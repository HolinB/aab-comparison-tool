from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from platformdirs import user_cache_path

from .config import AnalysisConfig


@dataclass(frozen=True)
class ToolSpec:
    name: str
    version: str
    url: str
    sha256: str
    archive_type: str
    executable_relative: str


# Checksums are populated from the exact release artifacts and intentionally never
# resolved through a "latest" URL.
DEFAULT_TOOL_SPECS: tuple[ToolSpec, ...] = (
    ToolSpec(
        name="jadx",
        version="1.5.6",
        url="https://github.com/skylot/jadx/releases/download/v1.5.6/jadx-1.5.6.zip",
        sha256="545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974",
        archive_type="zip",
        executable_relative="bin/jadx",
    ),
    ToolSpec(
        name="bundletool",
        version="1.18.3",
        url="https://github.com/google/bundletool/releases/download/1.18.3/bundletool-all-1.18.3.jar",
        sha256="a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29",
        archive_type="file",
        executable_relative="bundletool-all-1.18.3.jar",
    ),
)


class ToolInstallError(RuntimeError):
    pass


def default_tool_root() -> Path:
    return user_cache_path("aab-compare") / "tools"


class ToolManager:
    def __init__(
        self, root: Path | None = None, *, specs: tuple[ToolSpec, ...] | None = None
    ) -> None:
        self.root = (root or default_tool_root()).resolve()
        self.specs = DEFAULT_TOOL_SPECS if specs is None else specs

    def _spec(self, name: str) -> ToolSpec:
        try:
            return next(spec for spec in self.specs if spec.name == name)
        except StopIteration as error:
            raise ToolInstallError(f"unknown tool: {name}") from error

    def _directory(self, spec: ToolSpec) -> Path:
        return self.root / f"{spec.name}-{spec.version}"

    def executable(self, name: str) -> Path:
        spec = self._spec(name)
        return self._directory(spec) / spec.executable_relative

    @staticmethod
    def _marker_metadata(
        spec: ToolSpec, executable_sha256: str | None = None
    ) -> dict[str, str]:
        metadata = {"url": spec.url, "sha256": spec.sha256}
        if executable_sha256 is not None:
            metadata["executable_sha256"] = executable_sha256
        return metadata

    def _managed(self, spec: ToolSpec) -> bool:
        target = self._directory(spec)
        marker = target / ".artifact.json"
        if (
            target.is_symlink()
            or not target.is_dir()
            or marker.is_symlink()
            or not marker.is_file()
        ):
            return False
        try:
            metadata = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        if not isinstance(metadata, dict) or not set(metadata).issubset(
            {"url", "sha256", "executable_sha256"}
        ):
            return False
        return all(metadata.get(key) == value for key, value in self._marker_metadata(spec).items())

    def _recorded_executable_sha256(self, spec: ToolSpec) -> str | None:
        marker = self._directory(spec) / ".artifact.json"
        try:
            metadata = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(metadata, dict):
            return None
        value = metadata.get("executable_sha256")
        if not isinstance(value, str) or len(value) != 64:
            return None
        return value

    def _verified(self, spec: ToolSpec) -> bool:
        destination = self.executable(spec.name)
        if destination.is_symlink() or not destination.is_file() or not self._managed(spec):
            return False
        if spec.archive_type == "file":
            return _hash_file(destination) == spec.sha256
        recorded_sha256 = self._recorded_executable_sha256(spec)
        return recorded_sha256 is not None and _hash_file(destination) == recorded_sha256

    def status(self) -> dict[str, dict[str, object]]:
        return {
            spec.name: {
                "version": spec.version,
                "installed": self.executable(spec.name).is_file(),
                "verified": self._verified(spec),
                "path": str(self.executable(spec.name)),
            }
            for spec in self.specs
        }

    def install_all(self) -> dict[str, Path]:
        return {spec.name: self.install(spec.name) for spec in self.specs}

    def install(self, name: str) -> Path:
        spec = self._spec(name)
        if self._verified(spec):
            return self.executable(name)
        target = self._directory(spec)
        if (target.exists() or target.is_symlink()) and not self._managed(spec):
            raise ToolInstallError(f"tool directory is not managed by aab-compare: {target}")
        self.root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=f".{spec.name}-", dir=self.root) as temp_name:
            temp = Path(temp_name)
            artifact = temp / "artifact"
            try:
                with (
                    urllib.request.urlopen(spec.url, timeout=60) as response,
                    artifact.open("wb") as output,
                ):
                    shutil.copyfileobj(response, output)
            except OSError as error:
                raise ToolInstallError(f"failed to download {spec.name}: {error}") from error
            actual = _hash_file(artifact)
            if actual != spec.sha256:
                raise ToolInstallError(
                    f"checksum mismatch for {spec.name}: expected {spec.sha256}, got {actual}"
                )
            prepared = temp / "prepared"
            prepared.mkdir()
            if spec.archive_type == "file":
                destination = prepared / spec.executable_relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(artifact, destination)
            elif spec.archive_type == "zip":
                _extract_zip_safely(artifact, prepared)
            else:
                raise ToolInstallError(f"unsupported archive type: {spec.archive_type}")
            executable = prepared / spec.executable_relative
            if not executable.is_file():
                raise ToolInstallError(f"tool executable is missing after extraction: {executable}")
            executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
            (prepared / ".artifact.json").write_text(
                json.dumps(
                    self._marker_metadata(spec, _hash_file(executable)),
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            if (target.exists() or target.is_symlink()) and not self._managed(spec):
                raise ToolInstallError(f"tool directory is not managed by aab-compare: {target}")
            if target.exists():
                shutil.rmtree(target)
            os.replace(prepared, target)
        return self.executable(name)


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _extract_zip_safely(archive_path: Path, destination: Path) -> None:
    with zipfile.ZipFile(archive_path) as archive:
        for info in archive.infolist():
            pure = PurePosixPath(info.filename.replace("\\", "/"))
            mode = info.external_attr >> 16
            if pure.is_absolute() or ".." in pure.parts or stat.S_ISLNK(mode):
                raise ToolInstallError(f"unsafe path in tool archive: {info.filename}")
        archive.extractall(destination)


def normalize_manifest_xml(xml: str) -> list[str]:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        tokens = re.findall(r"[A-Za-z0-9_.$:/@+()<>?=-]{3,}", xml)
        return sorted(set(tokens))
    stable_name_tags = {
        "uses-permission",
        "uses-permission-sdk-23",
        "uses-feature",
        "action",
        "category",
        "meta-data",
        "uses-library",
    }
    component_tags = {"activity", "activity-alias", "service", "receiver", "provider"}
    features: set[str] = set()
    tag_counts: Counter[str] = Counter()
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        tag_counts[tag] += 1
        features.add(f"tag:{tag}")
        for raw_name, value in element.attrib.items():
            name = raw_name.rsplit("}", 1)[-1]
            features.add(f"{tag}:attr:{name}")
            if name == "name" and tag in stable_name_tags:
                features.add(f"{tag}:name={value}")
            elif name in {"exported", "enabled", "required", "grantUriPermissions"}:
                features.add(f"{tag}:{name}={value.lower()}")
            elif tag not in component_tags and name in {"minSdkVersion", "targetSdkVersion"}:
                features.add(f"{tag}:{name}={value}")
    features.update(f"count:{tag}:{count}" for tag, count in tag_counts.items())
    return sorted(features)


@dataclass(frozen=True)
class ManifestDetails:
    package_name: str | None
    components: tuple[tuple[str, str], ...]
    permissions: tuple[str, ...]
    actions: tuple[str, ...]
    features: tuple[str, ...]


def inspect_manifest_xml(xml: str) -> ManifestDetails:
    features = tuple(normalize_manifest_xml(xml))
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return ManifestDetails(None, (), (), (), features)
    package_name = root.attrib.get("package")
    android_name = "{http://schemas.android.com/apk/res/android}name"

    def qualified(value: str) -> str:
        if not package_name:
            return value
        if value.startswith("."):
            return package_name + value
        if "." not in value:
            return f"{package_name}.{value}"
        return value

    component_tags = {"activity", "activity-alias", "service", "receiver", "provider"}
    components: list[tuple[str, str]] = []
    permissions: list[str] = []
    actions: list[str] = []
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        name = element.attrib.get(android_name)
        if not name:
            continue
        if tag in component_tags:
            components.append((tag, qualified(name)))
        elif tag == "permission":
            permissions.append(name)
        elif tag == "action":
            actions.append(name)
    return ManifestDetails(
        package_name,
        tuple(components),
        tuple(permissions),
        tuple(actions),
        features,
    )


def _manifest_features(xml: str) -> list[str]:
    return normalize_manifest_xml(xml)


def decode_manifests(
    manager: ToolManager,
    bundle: Path,
    modules: list[str],
    config: AnalysisConfig,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> tuple[dict[str, list[str]], list[str]]:
    details, warnings = decode_manifest_details(
        manager,
        bundle,
        modules,
        config,
        runner=runner,
    )
    return {module: list(detail.features) for module, detail in details.items()}, warnings


def decode_manifest_details(
    manager: ToolManager,
    bundle: Path,
    modules: list[str],
    config: AnalysisConfig,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> tuple[dict[str, ManifestDetails], list[str]]:
    jar = manager.executable("bundletool")
    decoded: dict[str, ManifestDetails] = {}
    warnings: list[str] = []
    for module in modules:
        command = [
            "java",
            f"-Xmx{config.java_max_heap}",
            "-jar",
            str(jar),
            "dump",
            "manifest",
            f"--bundle={bundle.resolve()}",
            f"--module={module}",
        ]
        try:
            completed = runner(
                command,
                capture_output=True,
                text=True,
                timeout=config.subprocess_timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            warnings.append(f"Bundletool 无法解码 {module} Manifest: {error}")
            continue
        if completed.returncode != 0:
            message = completed.stderr.strip()[-1000:]
            warnings.append(f"Bundletool 解码 {module} Manifest 失败: {message}")
            continue
        decoded[module] = inspect_manifest_xml(completed.stdout)
    return decoded, warnings


_DUMP_RESOURCE = re.compile(
    r"^\s*0x[0-9a-fA-F]+\s+-\s+"
    r"(?P<type>[A-Za-z0-9_]+)/(?P<name>[A-Za-z0-9_.$-]+)\s*$"
)
_DUMP_VALUE = re.compile(
    r"^\s*(?P<config>.+?)\s+-\s+\[(?P<kind>[A-Z0-9_]+)\](?:\s+(?P<value>.*?))?\s*$"
)
_DUMP_CONFIG = re.compile(r"^\s*(?P<key>[a-z_]+):\s*(?P<value>.+?)\s*$")
_DENSITIES = {
    120: "ldpi",
    160: "mdpi",
    240: "hdpi",
    320: "xhdpi",
    480: "xxhdpi",
    640: "xxxhdpi",
    65534: "anydpi",
    65535: "nodpi",
}


def _locale_qualifier(locale: str) -> str:
    parts = locale.split("-")
    if len(parts) == 1:
        return parts[0]
    if len(parts) == 2 and len(parts[1]) == 2 and parts[1].isalpha():
        return f"{parts[0]}-r{parts[1].upper()}"
    return "b+" + "+".join(parts)


def _canonical_resource_qualifier(parts: list[str]) -> str | None:
    if parts == ["(default)"]:
        return ""
    tokens: list[tuple[int, str]] = []
    minimum_sdk = 0
    for part in parts:
        match = _DUMP_CONFIG.fullmatch(part)
        if match is None:
            return None
        key = match.group("key")
        value = match.group("value").strip()
        if key == "locale" and value.startswith('"') and value.endswith('"'):
            tokens.append((2, _locale_qualifier(value[1:-1])))
        elif key == "layout_direction":
            direction = {
                "LAYOUT_DIRECTION_LTR": "ldltr",
                "LAYOUT_DIRECTION_RTL": "ldrtl",
            }.get(value)
            if direction is None:
                return None
            tokens.append((5, direction))
            minimum_sdk = max(minimum_sdk, 17)
        elif key in {
            "smallest_screen_width_dp",
            "screen_width_dp",
            "screen_height_dp",
        }:
            prefix = {
                "smallest_screen_width_dp": "sw",
                "screen_width_dp": "w",
                "screen_height_dp": "h",
            }[key]
            tokens.append((6, f"{prefix}{int(value)}dp"))
            minimum_sdk = max(minimum_sdk, 13)
        elif key == "screen_layout_size":
            size = {
                "SCREEN_LAYOUT_SIZE_SMALL": "small",
                "SCREEN_LAYOUT_SIZE_NORMAL": "normal",
                "SCREEN_LAYOUT_SIZE_LARGE": "large",
                "SCREEN_LAYOUT_SIZE_XLARGE": "xlarge",
            }.get(value)
            if size is None:
                return None
            tokens.append((9, size))
            minimum_sdk = max(minimum_sdk, 4)
        elif key == "orientation":
            orientation = {
                "ORIENTATION_PORT": "port",
                "ORIENTATION_LAND": "land",
            }.get(value)
            if orientation is None:
                return None
            tokens.append((13, orientation))
        elif key == "ui_mode_type":
            mode = {"UI_MODE_TYPE_WATCH": "watch"}.get(value)
            if mode is None:
                return None
            tokens.append((14, mode))
            minimum_sdk = max(minimum_sdk, 20)
        elif key == "ui_mode_night":
            night = {
                "UI_MODE_NIGHT_NIGHT": "night",
                "UI_MODE_NIGHT_NOTNIGHT": "notnight",
            }.get(value)
            if night is None:
                return None
            tokens.append((15, night))
            minimum_sdk = max(minimum_sdk, 8)
        elif key == "density":
            density = _DENSITIES.get(int(value))
            if density is None:
                return None
            tokens.append((16, density))
            minimum_sdk = max(minimum_sdk, 21 if density == "anydpi" else 4)
        elif key == "sdk_version":
            minimum_sdk = max(minimum_sdk, int(value))
        else:
            return None
    ordered = [token for _, token in sorted(tokens)]
    if minimum_sdk:
        ordered.append(f"v{minimum_sdk}")
    return "-".join(ordered)


def _parse_resource_dump(output: str) -> tuple[dict[tuple[str, str, str], str], int]:
    inventory: dict[tuple[str, str, str], str] = {}
    current: tuple[str, str] | None = None
    pending_config: list[str] = []
    declarations = 0
    for line in output.splitlines():
        resource = _DUMP_RESOURCE.match(line)
        if resource:
            current = (resource.group("type"), resource.group("name"))
            pending_config = []
            declarations += 1
            continue
        value = _DUMP_VALUE.match(line)
        if current is not None and value is not None:
            qualifiers = _canonical_resource_qualifier(
                [*pending_config, value.group("config").strip()]
            )
            pending_config = []
            if qualifiers is None:
                continue
            resource_type, name = current
            raw_value = value.group("value") or f"[{value.group('kind')}]"
            canonical = " ".join(raw_value.split())
            inventory[(resource_type, qualifiers, name)] = canonical
            continue
        config = _DUMP_CONFIG.match(line)
        if current is not None and config is not None:
            pending_config.append(line.strip())
    return dict(sorted(inventory.items())), declarations


def parse_resource_dump(output: str) -> dict[tuple[str, str, str], str]:
    """Parse stable value records from Bundletool's human-readable resource dump."""
    return _parse_resource_dump(output)[0]


def dump_resource_inventory(
    manager: ToolManager,
    bundle: Path,
    config: AnalysisConfig,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> tuple[dict[tuple[str, str, str], str], list[str]]:
    jar = manager.executable("bundletool")
    command = [
        "java",
        f"-Xmx{config.java_max_heap}",
        "-jar",
        str(jar),
        "dump",
        "resources",
        f"--bundle={bundle.resolve()}",
        "--values",
    ]
    try:
        completed = runner(
            command,
            capture_output=True,
            text=True,
            timeout=config.subprocess_timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}, ["Bundletool 资源清单导出失败"]
    if completed.returncode != 0:
        return {}, [f"Bundletool 资源清单导出失败（退出码 {completed.returncode}）"]
    inventory, declarations = _parse_resource_dump(completed.stdout)
    if not inventory:
        return {}, ["Bundletool 资源清单未包含可验证值"]
    parsed_resources = {(resource_type, name) for resource_type, _, name in inventory}
    if len(parsed_resources) < declarations:
        return inventory, [
            f"Bundletool 资源清单部分无法解析（{len(parsed_resources)}/{declarations}）"
        ]
    return inventory, []


def run_jadx(
    manager: ToolManager,
    bundle: Path,
    output: Path,
    config: AnalysisConfig,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    diagnostics: list[str] | None = None,
) -> tuple[Path | None, list[str]]:
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    config_dir = output / ".jadx-config"
    cache_dir = output / ".jadx-cache"
    config_dir.mkdir()
    cache_dir.mkdir()
    environment = dict(os.environ)
    environment["JADX_CONFIG_DIR"] = str(config_dir)
    environment["JADX_CACHE_DIR"] = str(cache_dir)
    jobs = config.jobs or max(1, min(os.cpu_count() or 1, 16))
    command = [
        str(manager.executable("jadx")),
        "--no-res",
        "--threads-count",
        str(jobs),
        "-d",
        str(output),
        str(bundle.resolve()),
    ]
    try:
        completed = runner(
            command,
            capture_output=True,
            text=True,
            timeout=config.subprocess_timeout_seconds,
            check=False,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        if diagnostics is not None:
            diagnostics.append(str(error))
        return None, ["JADX 运行失败"]
    if completed.returncode != 0:
        message = (completed.stderr or completed.stdout).strip()[-2000:]
        if diagnostics is not None and message:
            diagnostics.append(message)
        sources_dir = output / "sources"
        if sources_dir.is_dir() and next(sources_dir.rglob("*.java"), None) is not None:
            return output, [f"JADX 部分反编译完成（退出码 {completed.returncode}），部分类不可读"]
        return None, [f"JADX 反编译失败（退出码 {completed.returncode}）"]
    return output, []
