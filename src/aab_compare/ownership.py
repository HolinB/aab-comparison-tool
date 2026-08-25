from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import tomllib
import zipfile
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager, suppress
from copy import deepcopy
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from .archive import ArchiveSecurityError, open_validated_aab
from .config import AnalysisConfig, ArchiveLimits
from .models import BundleProfile, FileFingerprint, ManifestFingerprint


class OriginKind(StrEnum):
    OWNED_SOURCE = "OWNED_SOURCE"
    OWNED_GENERATED = "OWNED_GENERATED"
    HEURISTIC_OWNED = "HEURISTIC_OWNED"
    PUBLIC_DEPENDENCY = "PUBLIC_DEPENDENCY"
    TOOL_GENERATED = "TOOL_GENERATED"
    UNRESOLVED = "UNRESOLVED"


@dataclass(frozen=True)
class OwnershipSideConfig:
    project_root: Path
    source_roots: tuple[Path, ...]
    variant: str
    artifact_output: Path
    prepare_task: str | None = None
    owned_generated_roots: tuple[Path, ...] = ()
    archive_limits: ArchiveLimits = field(default_factory=ArchiveLimits)


@dataclass(frozen=True)
class OwnershipConfig:
    left: OwnershipSideConfig
    right: OwnershipSideConfig
    schema_version: int = 1
    provenance_lock: Path | None = None


@dataclass(frozen=True)
class ProvenancePaths:
    r8_mapping: Path | None
    resource_merger: Path | None
    embedded_r8_mapping: dict[str, set[str]] = field(default_factory=dict)
    embedded_r8_mapping_entry: str | None = None
    embedded_r8_mapping_sha256: str | None = None


@dataclass(frozen=True)
class OwnershipEntry:
    identifier: str
    category: str
    origin: OriginKind
    source_path: str
    module: str
    aab_path: str | None = None
    original_identifier: str | None = None


@dataclass(frozen=True)
class _ConsumedSourceFile:
    path: Path
    origin: OriginKind
    category: str


ResourceIdentity = tuple[str, str, str, str]
ResourceProvenance = dict[ResourceIdentity, OwnershipEntry]
VerifiedResourceInventory = Mapping[tuple[str, str, str], str]


@dataclass(frozen=True)
class AttributionSummary:
    owned_source: int = 0
    owned_generated: int = 0
    heuristic_owned: int = 0
    public_dependency: int = 0
    tool_generated: int = 0
    unresolved: int = 0

    @classmethod
    def from_entries(cls, entries: Iterable[OwnershipEntry]) -> AttributionSummary:
        counts = {kind: 0 for kind in OriginKind}
        for entry in entries:
            counts[entry.origin] += 1
        return cls(
            owned_source=counts[OriginKind.OWNED_SOURCE],
            owned_generated=counts[OriginKind.OWNED_GENERATED],
            heuristic_owned=counts[OriginKind.HEURISTIC_OWNED],
            public_dependency=counts[OriginKind.PUBLIC_DEPENDENCY],
            tool_generated=counts[OriginKind.TOOL_GENERATED],
            unresolved=counts[OriginKind.UNRESOLVED],
        )


@dataclass(frozen=True)
class OwnedProjection:
    profile: BundleProfile
    attribution: AttributionSummary
    diagnostics: dict[str, Any]


@dataclass
class OwnershipManifest:
    entries: list[OwnershipEntry] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def owned_class_descriptors(self) -> set[str]:
        return {entry.identifier for entry in self.entries if entry.category == "code"}

    @property
    def summary(self) -> AttributionSummary:
        return AttributionSummary.from_entries(self.entries)


@dataclass(frozen=True)
class VerifiedProvenance:
    artifact_path: Path
    artifact_sha256: str
    paths: ProvenancePaths
    source: OwnershipManifest
    source_sha256: Mapping[str, str]
    manifest_contents: Mapping[str, bytes]
    r8_mapping: Mapping[str, frozenset[str]]
    mapping_source: str
    resource_provenance: Mapping[ResourceIdentity, OwnershipEntry]


_PACKAGE = re.compile(r"(?m)^\s*package\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*;?")
_KOTLIN_DECLARATION = re.compile(r"\b(?:class|object|interface)\s+([A-Za-z_]\w*)")
_KOTLIN_FILE_MEMBER = re.compile(r"\b(?:fun(?!\s+interface\b)|val|var|typealias)\b")
_JAVA_DECLARATION = re.compile(r"\b(?:class|interface|enum|record)\s+([A-Za-z_]\w*)")
_IMAGE_SUFFIXES = {".png", ".webp", ".jpg", ".jpeg", ".gif", ".bmp"}
_RESOURCE_DIRECTORIES = {
    "anim",
    "animator",
    "color",
    "drawable",
    "font",
    "interpolator",
    "layout",
    "menu",
    "mipmap",
    "navigation",
    "raw",
    "transition",
    "values",
    "xml",
}
_EXCLUDED_SOURCE_SETS = {"test", "androidtest", "testfixtures"}
_MAX_PROVENANCE_ARTIFACT_GAP_SECONDS = 6 * 60 * 60
_GRADLE_TASK = re.compile(r"(?::[A-Za-z][A-Za-z0-9_-]*)+")
_SIDE_KEYS = {
    "project_root",
    "source_roots",
    "variant",
    "artifact_output",
    "prepare_task",
    "owned_generated_roots",
}


def _inside(root: Path, value: Path, label: str) -> Path:
    resolved = value.resolve()
    if not resolved.is_relative_to(root):
        raise ValueError(f"{label} must be inside project_root: {value}")
    return resolved


def _side_config(raw: dict[str, Any], label: str) -> OwnershipSideConfig:
    unknown = set(raw) - _SIDE_KEYS
    if unknown:
        raise ValueError(f"unknown {label} ownership keys: {', '.join(sorted(unknown))}")
    required = {"project_root", "source_roots", "variant", "artifact_output"}
    missing = required - set(raw)
    if missing:
        raise ValueError(f"missing {label} ownership keys: {', '.join(sorted(missing))}")
    project_root = Path(str(raw["project_root"])).expanduser().resolve()
    if not project_root.is_dir():
        raise ValueError(f"{label}.project_root is not a directory: {project_root}")
    source_roots = tuple(
        _inside(project_root, project_root / str(value), f"{label}.source_roots")
        for value in raw["source_roots"]
    )
    generated = tuple(
        _inside(project_root, project_root / str(value), f"{label}.owned_generated_roots")
        for value in raw.get("owned_generated_roots", [])
    )
    artifact_raw = Path(str(raw["artifact_output"])).expanduser()
    artifact = (
        artifact_raw.resolve()
        if artifact_raw.is_absolute()
        else _inside(
            project_root,
            project_root / artifact_raw,
            f"{label}.artifact_output",
        )
    )
    variant = str(raw["variant"]).strip()
    if not variant or not variant[0].islower():
        raise ValueError(f"{label}.variant must be a lower camel-case Android variant")
    prepare_task = raw.get("prepare_task")
    if prepare_task is not None and _GRADLE_TASK.fullmatch(str(prepare_task)) is None:
        raise ValueError(f"{label}.prepare_task is unsafe or malformed: {prepare_task}")
    return OwnershipSideConfig(
        project_root=project_root,
        source_roots=source_roots,
        variant=variant,
        artifact_output=artifact,
        prepare_task=str(prepare_task) if prepare_task is not None else None,
        owned_generated_roots=generated,
    )


def _validated_provenance_lock_path(
    lock_path: Path,
    sides: Iterable[OwnershipSideConfig],
    *,
    ownership_config: Path | None = None,
) -> Path:
    expanded = lock_path.expanduser()
    if expanded.is_symlink():
        raise ValueError("provenance_lock must not be a symbolic link")
    resolved = expanded.resolve()
    side_configs = tuple(sides)
    if any(resolved.is_relative_to(side.project_root.resolve()) for side in side_configs):
        raise ValueError("provenance_lock must be outside Android project roots")
    if ownership_config is not None:
        config_path = ownership_config.resolve()
        if (
            resolved == config_path
            or resolved.is_relative_to(config_path)
            or config_path.is_relative_to(resolved)
        ):
            raise ValueError("provenance_lock must not overlap the ownership configuration")
    for side in side_configs:
        artifact = side.artifact_output.resolve()
        if (
            resolved == artifact
            or resolved.is_relative_to(artifact)
            or artifact.is_relative_to(resolved)
        ):
            raise ValueError("provenance_lock must not overlap an artifact path")
    return resolved


def load_ownership_config(path: Path) -> OwnershipConfig:
    with path.open("rb") as stream:
        raw = tomllib.load(stream)
    unknown = set(raw) - {"schema_version", "provenance_lock", "left", "right"}
    if unknown:
        raise ValueError(f"unknown ownership configuration keys: {', '.join(sorted(unknown))}")
    schema_version = int(raw.get("schema_version", 1))
    if schema_version not in {1, 2}:
        raise ValueError(f"unsupported ownership configuration schema: {schema_version}")
    lock_value = raw.get("provenance_lock")
    if schema_version == 2 and lock_value is None:
        raise ValueError("ownership configuration schema 2 requires provenance_lock")
    if not isinstance(raw.get("left"), dict) or not isinstance(raw.get("right"), dict):
        raise ValueError("ownership configuration requires [left] and [right]")
    left = _side_config(raw["left"], "left")
    right = _side_config(raw["right"], "right")
    lock_value_path = Path(str(lock_value)).expanduser() if lock_value is not None else None
    lock_path = (
        path.parent / lock_value_path
        if lock_value_path is not None and not lock_value_path.is_absolute()
        else lock_value_path
    )
    if lock_path is not None:
        lock_path = _validated_provenance_lock_path(
            lock_path,
            (left, right),
            ownership_config=path,
        )
    return OwnershipConfig(
        left=left,
        right=right,
        schema_version=schema_version,
        provenance_lock=lock_path,
    )


def _flavor_name(variant: str) -> str:
    for suffix in ("Release", "Debug"):
        if variant.endswith(suffix):
            return variant[: -len(suffix)]
    return variant


def _production_roots(side: OwnershipSideConfig) -> Iterable[Path]:
    active = {"main", "release", side.variant.lower(), _flavor_name(side.variant).lower()}
    for root in side.source_roots:
        if not root.is_dir():
            continue
        for child in sorted(root.iterdir()):
            if child.is_dir() and child.name.lower() in active - _EXCLUDED_SOURCE_SETS:
                yield child


def _module(side: OwnershipSideConfig, path: Path) -> str:
    return ":" + path.relative_to(side.project_root).parts[0]


def _descriptor(package: str, name: str) -> str:
    qualified = f"{package}.{name}" if package else name
    return "L" + qualified.replace(".", "/") + ";"


def _mask_comments_and_literals(text: str) -> str:
    masked = list(text)
    index = 0
    length = len(text)

    def blank(start: int, end: int) -> None:
        for position in range(start, end):
            if masked[position] != "\n":
                masked[position] = " "

    while index < length:
        if text.startswith("//", index):
            end = text.find("\n", index + 2)
            end = length if end < 0 else end
            blank(index, end)
            index = end
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            end = length if end < 0 else end + 2
            blank(index, end)
            index = end
        elif text.startswith('"""', index):
            end = text.find('"""', index + 3)
            end = length if end < 0 else end + 3
            blank(index, end)
            index = end
        elif text[index] in {'"', "'"}:
            quote = text[index]
            end = index + 1
            while end < length:
                if text[end] == "\\":
                    end += 2
                    continue
                end += 1
                if text[end - 1] == quote:
                    break
            blank(index, min(end, length))
            index = end
        else:
            index += 1
    return "".join(masked)


def _top_level_matches(text: str, pattern: re.Pattern[str]) -> list[re.Match[str]]:
    depths: list[int] = []
    depth = 0
    for character in text:
        depths.append(depth)
        if character in "({[":
            depth += 1
        elif character in ")}]":
            depth = max(0, depth - 1)
    return [match for match in pattern.finditer(text) if depths[match.start()] == 0]


def _code_entries(
    side: OwnershipSideConfig, path: Path, origin: OriginKind
) -> list[OwnershipEntry]:
    text = path.read_text(encoding="utf-8", errors="replace")
    return _code_entries_from_text(side, path, origin, text)


def _code_entries_from_text(
    side: OwnershipSideConfig,
    path: Path,
    origin: OriginKind,
    text: str,
) -> list[OwnershipEntry]:
    structural_text = _mask_comments_and_literals(text)
    package_match = _PACKAGE.search(structural_text)
    package = package_match.group(1) if package_match else ""
    names: set[str] = set()
    if path.suffix == ".java":
        names.update(
            match.group(1)
            for match in _top_level_matches(structural_text, _JAVA_DECLARATION)
        )
    else:
        names.update(
            match.group(1) for match in _top_level_matches(structural_text, _KOTLIN_DECLARATION)
        )
        if _top_level_matches(structural_text, _KOTLIN_FILE_MEMBER):
            names.add(path.stem + "Kt")
    return [
        OwnershipEntry(
            identifier=_descriptor(package, name),
            category="code",
            origin=origin,
            source_path=str(path),
            module=_module(side, path),
        )
        for name in sorted(names)
    ]


def _resource_directory(path: Path) -> str | None:
    for parent in path.parents:
        base = parent.name.split("-", 1)[0]
        if base in _RESOURCE_DIRECTORIES:
            return parent.name
    return None


def _file_entry(side: OwnershipSideConfig, path: Path, origin: OriginKind) -> OwnershipEntry | None:
    if path.name == "AndroidManifest.xml":
        category = "manifest"
        identifier = f"manifest:{path.relative_to(side.project_root).as_posix()}"
    elif "assets" in path.parts:
        category = "asset"
        assets_index = path.parts.index("assets")
        identifier = "asset:" + "/".join(path.parts[assets_index + 1 :])
    else:
        resource_directory = _resource_directory(path)
        if resource_directory is None:
            return None
        category = "image" if path.suffix.lower() in _IMAGE_SUFFIXES else "resource"
        name = path.name.removesuffix(".9.png").split(".", 1)[0]
        identifier = f"{resource_directory}:{name}"
    return OwnershipEntry(
        identifier=identifier,
        category=category,
        origin=origin,
        source_path=str(path),
        module=_module(side, path),
    )


def _consumed_files_under(
    side: OwnershipSideConfig,
    root: Path,
    origin: OriginKind,
) -> Iterable[_ConsumedSourceFile]:
    paths = [root] if root.is_file() else sorted(path for path in root.rglob("*") if path.is_file())
    for path in paths:
        if path.suffix.lower() in {".java", ".kt"}:
            yield _ConsumedSourceFile(path, origin, "code")
            continue
        entry = _file_entry(side, path, origin)
        if entry is not None:
            yield _ConsumedSourceFile(path, origin, entry.category)


def _consumed_source_files(side: OwnershipSideConfig) -> Iterable[_ConsumedSourceFile]:
    for root in _production_roots(side):
        yield from _consumed_files_under(side, root, OriginKind.OWNED_SOURCE)
    for root in side.owned_generated_roots:
        if root.exists():
            yield from _consumed_files_under(side, root, OriginKind.OWNED_GENERATED)


def _entries_under(
    side: OwnershipSideConfig, root: Path, origin: OriginKind
) -> Iterable[OwnershipEntry]:
    for source_file in _consumed_files_under(side, root, origin):
        if source_file.category == "code":
            yield from _code_entries(side, source_file.path, origin)
        else:
            entry = _file_entry(side, source_file.path, origin)
            if entry is not None:
                yield entry


def build_source_ownership(side: OwnershipSideConfig) -> OwnershipManifest:
    entries: list[OwnershipEntry] = []
    for root in _production_roots(side):
        entries.extend(_entries_under(side, root, OriginKind.OWNED_SOURCE))
    for root in side.owned_generated_roots:
        if root.exists():
            entries.extend(_entries_under(side, root, OriginKind.OWNED_GENERATED))
    entries.sort(key=lambda item: (item.category, item.identifier, item.source_path))
    return OwnershipManifest(entries=entries)


def _path_origin(
    path: Path, side: OwnershipSideConfig, *, from_dependency: bool = False
) -> OriginKind:
    resolved = path.resolve()
    if any(resolved.is_relative_to(root) for root in side.owned_generated_roots):
        return OriginKind.OWNED_GENERATED
    if any(resolved.is_relative_to(root) for root in _production_roots(side)):
        return OriginKind.OWNED_SOURCE
    selected_modules = {
        side.project_root / root.relative_to(side.project_root).parts[0]
        for root in side.source_roots
    }
    if from_dependency and any(
        resolved.is_relative_to(module / "build/intermediates/packaged_res")
        for module in selected_modules
    ):
        return OriginKind.UNRESOLVED
    if from_dependency or ".gradle/caches" in resolved.as_posix():
        return OriginKind.PUBLIC_DEPENDENCY
    generated_root = side.project_root / "build/generated"
    if resolved.is_relative_to(generated_root) or (
        resolved.is_relative_to(side.project_root) and "/build/generated/" in resolved.as_posix()
    ):
        return OriginKind.TOOL_GENERATED
    return OriginKind.UNRESOLVED


def _resource_items(file_element: ElementTree.Element) -> Iterable[tuple[str, str]]:
    resource_type = file_element.get("type")
    name = file_element.get("name")
    if resource_type and name:
        yield resource_type, name
        return
    for child in file_element:
        tag = child.tag.rsplit("}", 1)[-1]
        child_type = child.get("type") if tag == "item" else tag
        child_name = child.get("name")
        if child_type and child_name:
            yield child_type, child_name


def _parse_resource_merger_file(
    path: Path,
    side: OwnershipSideConfig,
    local_provenance: ResourceProvenance | None = None,
) -> ResourceProvenance:
    try:
        root = ElementTree.parse(path).getroot()
    except (OSError, ElementTree.ParseError) as error:
        raise ValueError(f"invalid resource merger provenance: {path}: {error}") from error
    return _parse_resource_merger_root(root, side, local_provenance)


def _parse_resource_merger_bytes(
    data: bytes,
    path: Path,
    side: OwnershipSideConfig,
    local_provenance: ResourceProvenance | None = None,
) -> ResourceProvenance:
    try:
        root = ElementTree.fromstring(data)
    except ElementTree.ParseError as error:
        raise ValueError(f"invalid resource merger provenance: {path}: {error}") from error
    return _parse_resource_merger_root(root, side, local_provenance)


def _parse_resource_merger_root(
    root: ElementTree.Element,
    side: OwnershipSideConfig,
    local_provenance: ResourceProvenance | None = None,
) -> ResourceProvenance:
    provenance: ResourceProvenance = {}
    for data_set in root.iter("dataSet"):
        from_dependency = data_set.get("from-dependency", "false").lower() == "true"
        for source in data_set.findall("source"):
            source_root = Path(source.get("path", ""))
            for file_element in source.findall("file"):
                source_path = Path(file_element.get("path", str(source_root)))
                origin = _path_origin(source_path, side, from_dependency=from_dependency)
                module = (
                    ":" + source_path.resolve().relative_to(side.project_root).parts[0]
                    if source_path.resolve().is_relative_to(side.project_root)
                    else ":external"
                )
                suffix = source_path.suffix.lower()
                qualifiers = file_element.get("qualifiers", "")
                for resource_type, name in _resource_items(file_element):
                    identity = (module, resource_type, qualifiers, name)
                    local_owner = (
                        local_provenance.get(identity)
                        if from_dependency and local_provenance is not None
                        else None
                    )
                    if local_owner is not None:
                        provenance.pop(identity, None)
                        provenance[identity] = local_owner
                        continue
                    category = (
                        "image"
                        if resource_type in {"drawable", "mipmap"} and suffix in _IMAGE_SUFFIXES
                        else "resource"
                    )
                    provenance.pop(identity, None)
                    provenance[identity] = OwnershipEntry(
                        identifier=f"{resource_type}:{name}",
                        category=category,
                        origin=origin,
                        source_path=str(source_path),
                        module=module,
                    )
    return provenance


def _consumed_resource_mergers(
    path: Path, side: OwnershipSideConfig
) -> tuple[tuple[str, Path], ...]:
    variant_title = side.variant[:1].upper() + side.variant[1:]
    mergers: list[tuple[str, Path]] = []
    for module in _module_roots(side):
        module_merger = (
            module
            / "build/intermediates/incremental"
            / side.variant
            / f"package{variant_title}Resources"
            / "merger.xml"
        )
        if module_merger.is_file() and module_merger.resolve() != path.resolve():
            mergers.append(("module-package", module_merger))
    mergers.append(("final", path))
    return tuple(mergers)


def parse_resource_merger(path: Path, side: OwnershipSideConfig) -> ResourceProvenance:
    local_provenance: ResourceProvenance = {}
    mergers = _consumed_resource_mergers(path, side)
    for _, module_merger in mergers[:-1]:
        local_provenance.update(_parse_resource_merger_file(module_merger, side))
    return _parse_resource_merger_file(path, side, local_provenance)


def _class_descriptor(value: str) -> str:
    return "L" + value.strip().replace(".", "/") + ";"


def parse_r8_mapping(text: str) -> dict[str, set[str]]:
    mappings: dict[str, set[str]] = {}
    for line in text.splitlines():
        if not line or line[0].isspace() or line.startswith("#") or " -> " not in line:
            continue
        original, output = line.split(" -> ", 1)
        output = output.removesuffix(":").strip()
        if not original.strip() or not output:
            continue
        mappings.setdefault(_class_descriptor(output), set()).add(
            _class_descriptor(original.strip())
        )
    return mappings


def _unique_owner(candidates: list[OwnershipEntry]) -> OwnershipEntry | None:
    identities = {(entry.origin, entry.source_path, entry.module) for entry in candidates}
    return candidates[0] if candidates and len(identities) == 1 else None


def _source_owner(
    original: str, source_by_descriptor: dict[str, list[OwnershipEntry]]
) -> OwnershipEntry | None:
    direct = source_by_descriptor.get(original)
    if direct is not None:
        return _unique_owner(direct)
    nested_candidates = [
        entry
        for descriptor, entries in source_by_descriptor.items()
        if original.startswith(descriptor.removesuffix(";") + "$")
        for entry in entries
    ]
    return _unique_owner(nested_candidates)


def _file_identifier(path: str) -> tuple[str, str] | None:
    parts = path.split("/")
    if len(parts) >= 3 and parts[1] == "assets":
        return "asset", "asset:" + "/".join(parts[2:])
    if len(parts) < 4 or parts[1] != "res":
        return None
    resource_type = parts[2].split("-", 1)[0]
    name = parts[-1].removesuffix(".9.png").split(".", 1)[0]
    category = "image" if Path(parts[-1]).suffix.lower() in _IMAGE_SUFFIXES else "resource"
    return category, f"{resource_type}:{name}"


def _resource_key(logical: tuple[str, str] | None) -> tuple[str, str, str] | None:
    if logical is None or logical[0] == "asset":
        return None
    resource_type, name = logical[1].split(":", 1)
    return resource_type, "", name


def _resource_key_for_path(path: str) -> tuple[str, str, str] | None:
    logical = _file_identifier(path)
    if logical is None or logical[0] == "asset":
        return None
    parts = path.split("/")
    resource_directory = parts[2]
    resource_type, _, qualifiers = resource_directory.partition("-")
    _, name = logical[1].split(":", 1)
    return resource_type, qualifiers, name


def _resource_owner(
    key: tuple[str, str, str] | None,
    provenance: Mapping[ResourceIdentity, OwnershipEntry],
) -> OwnershipEntry | None:
    if key is None:
        return None
    resource_type, qualifiers, name = key
    matches = [
        owner
        for (
            _,
            candidate_type,
            candidate_qualifiers,
            candidate_name,
        ), owner in provenance.items()
        if (candidate_type, candidate_qualifiers, candidate_name)
        == (resource_type, qualifiers, name)
    ]
    return matches[-1] if matches else None


def _owned_origin(origin: OriginKind) -> bool:
    return origin in {OriginKind.OWNED_SOURCE, OriginKind.OWNED_GENERATED}


def _apply_provenance(item: Any, owner: OwnershipEntry) -> Any:
    copied = deepcopy(item)
    copied.origin = owner.origin.value
    copied.source_path = owner.source_path
    return copied


def _asset_owner(
    item: FileFingerprint,
    source_entries: Iterable[OwnershipEntry],
    source_sha256: Mapping[str, str] | None = None,
) -> OwnershipEntry | None:
    logical = _file_identifier(item.path)
    if logical is None:
        return None
    candidates = [
        entry
        for entry in source_entries
        if entry.category == "asset" and entry.identifier == logical[1]
    ]
    matching = []
    for candidate in candidates:
        if source_sha256 is not None:
            matches_final_asset = source_sha256.get(candidate.source_path) == item.sha256
        else:
            try:
                matches_final_asset = _sha256(Path(candidate.source_path)) == item.sha256
            except OSError:
                matches_final_asset = False
        if matches_final_asset:
            matching.append(candidate)
    identities = {(entry.origin, entry.source_path, entry.module) for entry in matching}
    return matching[0] if len(identities) == 1 else None


def attribute_owned_profile(
    profile: BundleProfile,
    source: OwnershipManifest,
    r8_mapping: Mapping[str, set[str] | frozenset[str]],
    resource_provenance: Mapping[ResourceIdentity, OwnershipEntry] | None = None,
    source_sha256: Mapping[str, str] | None = None,
) -> tuple[BundleProfile, AttributionSummary]:
    owned = deepcopy(profile)
    source_classes: dict[str, list[OwnershipEntry]] = {}
    for entry in source.entries:
        if entry.category == "code":
            source_classes.setdefault(entry.identifier, []).append(entry)
    source_files = {
        (entry.category, entry.identifier): entry
        for entry in source.entries
        if entry.category in {"resource", "image"}
    }
    origin_counts = {kind: 0 for kind in OriginKind}

    kept_methods = []
    for method in profile.methods:
        originals = r8_mapping.get(method.class_name)
        if not originals:
            origin_counts[OriginKind.UNRESOLVED] += 1
            continue
        owners = [_source_owner(original, source_classes) for original in sorted(originals)]
        owner_identities = {
            (owner.origin, owner.source_path, owner.module) for owner in owners if owner is not None
        }
        if owners and all(owner is not None for owner in owners) and len(owner_identities) == 1:
            owner = owners[0]
            assert owner is not None
            method_copy = _apply_provenance(method, owner)
            method_copy.third_party = False
            kept_methods.append(method_copy)
            origin_counts[owner.origin] += 1
        else:
            origin_counts[OriginKind.UNRESOLVED] += 1

    kept_files = []
    for item in profile.files:
        logical = _file_identifier(item.path)
        if item.category == "asset":
            owner = (
                _asset_owner(item, source.entries, source_sha256)
                if logical is not None
                else None
            )
        else:
            owner = (
                _resource_owner(_resource_key_for_path(item.path), resource_provenance)
                if resource_provenance is not None
                else source_files.get(logical)
                if logical is not None
                else None
            )
        if owner is not None and _owned_origin(owner.origin):
            kept_files.append(_apply_provenance(item, owner))
            origin_counts[owner.origin] += 1
        elif owner is not None:
            origin_counts[owner.origin] += 1
        else:
            origin_counts[OriginKind.UNRESOLVED] += 1

    kept_images = []
    for image in profile.images:
        logical = _file_identifier(image.path)
        owner = (
            _resource_owner(_resource_key_for_path(image.path), resource_provenance)
            if resource_provenance is not None
            else source_files.get(logical)
            if logical is not None
            else None
        )
        if owner is not None and _owned_origin(owner.origin):
            kept_images.append(_apply_provenance(image, owner))

    owned.methods = sorted(kept_methods, key=lambda item: item.identifier)
    owned.files = sorted(kept_files, key=lambda item: item.path)
    owned.images = sorted(kept_images, key=lambda item: item.path)
    owned.counts = dict(owned.counts)
    owned.counts["candidate_methods"] = len(owned.methods)
    owned.counts["methods"] = len(owned.methods)
    owned.counts["business_methods"] = len(owned.methods)
    owned.counts["all_long_methods"] = sum(
        method.instruction_count >= 100 for method in owned.methods
    )
    owned.counts["long_methods"] = owned.counts["all_long_methods"]
    owned.counts["images"] = len(owned.images)
    owned.counts["owned_files"] = len(owned.files)
    summary = AttributionSummary(
        owned_source=origin_counts[OriginKind.OWNED_SOURCE],
        owned_generated=origin_counts[OriginKind.OWNED_GENERATED],
        heuristic_owned=origin_counts[OriginKind.HEURISTIC_OWNED],
        public_dependency=origin_counts[OriginKind.PUBLIC_DEPENDENCY],
        tool_generated=origin_counts[OriginKind.TOOL_GENERATED],
        unresolved=origin_counts[OriginKind.UNRESOLVED],
    )
    return owned, summary


def build_owned_manifest_entries(
    source: OwnershipManifest,
    contents: Mapping[str, bytes] | None = None,
) -> list[ManifestFingerprint]:
    features: list[ManifestFingerprint] = []
    for entry in sorted(source.entries, key=lambda item: (item.source_path, item.identifier)):
        if entry.category != "manifest" or not _owned_origin(entry.origin):
            continue
        try:
            root = (
                ElementTree.fromstring(contents[entry.source_path])
                if contents is not None and entry.source_path in contents
                else ElementTree.parse(entry.source_path).getroot()
            )
        except (OSError, ElementTree.ParseError):
            continue
        for element in root.iter():
            tag = element.tag.rsplit("}", 1)[-1]
            if tag in {"manifest", "application"}:
                continue
            attributes = []
            for raw_name, value in sorted(
                element.attrib.items(),
                key=lambda item: (item[0].rsplit("}", 1)[-1] != "name", item[0]),
            ):
                name = raw_name.rsplit("}", 1)[-1]
                attributes.append(f"{name}={value}")
            features.append(
                ManifestFingerprint(
                    f"{tag}:{'|'.join(attributes)}" if attributes else tag,
                    entry.origin.value,
                    entry.source_path,
                )
            )
    return features


def build_owned_manifest_features(source: OwnershipManifest) -> list[str]:
    return [entry.value for entry in build_owned_manifest_entries(source)]


def _compiled_resource_label(key: tuple[str, str, str]) -> str:
    resource_type, qualifiers, name = key
    directory = f"{resource_type}-{qualifiers}" if qualifiers else resource_type
    return f"{directory}:{name}"


def _values_backed(owner: OwnershipEntry) -> bool:
    return any(
        parent.name.split("-", 1)[0] == "values" for parent in Path(owner.source_path).parents
    )


def _inventory_owner(
    key: tuple[str, str, str],
    resource_provenance: Mapping[ResourceIdentity, OwnershipEntry],
) -> OwnershipEntry | None:
    resource_type, qualifiers, name = key
    matches = [
        owner
        for (
            _,
            candidate_type,
            candidate_qualifiers,
            candidate_name,
        ), owner in resource_provenance.items()
        if (candidate_type, candidate_qualifiers, candidate_name)
        == (resource_type, qualifiers, name)
        and _values_backed(owner)
    ]
    # Merger datasets are ordered from lower to higher priority; the final
    # matching entry is the resource that survives overlays.
    return matches[-1] if matches else None


def _summary_with_additions(
    summary: AttributionSummary, origins: Iterable[OriginKind]
) -> AttributionSummary:
    counts = {
        OriginKind.OWNED_SOURCE: summary.owned_source,
        OriginKind.OWNED_GENERATED: summary.owned_generated,
        OriginKind.HEURISTIC_OWNED: summary.heuristic_owned,
        OriginKind.PUBLIC_DEPENDENCY: summary.public_dependency,
        OriginKind.TOOL_GENERATED: summary.tool_generated,
        OriginKind.UNRESOLVED: summary.unresolved,
    }
    for origin in origins:
        counts[origin] += 1
    return AttributionSummary(
        owned_source=counts[OriginKind.OWNED_SOURCE],
        owned_generated=counts[OriginKind.OWNED_GENERATED],
        heuristic_owned=counts[OriginKind.HEURISTIC_OWNED],
        public_dependency=counts[OriginKind.PUBLIC_DEPENDENCY],
        tool_generated=counts[OriginKind.TOOL_GENERATED],
        unresolved=counts[OriginKind.UNRESOLVED],
    )


def build_owned_projection(
    raw_profile: BundleProfile,
    side: OwnershipSideConfig,
    config: AnalysisConfig,
    *,
    verified_resource_inventory: VerifiedResourceInventory | None = None,
    provenance_paths: ProvenancePaths | None = None,
    verified_provenance: VerifiedProvenance | None = None,
) -> OwnedProjection:
    """Build a deterministic, evidence-backed projection without writing project files."""
    artifact = (
        verified_provenance.artifact_path.resolve()
        if verified_provenance is not None
        else side.artifact_output.resolve()
    )
    artifact_sha256 = (
        verified_provenance.artifact_sha256
        if verified_provenance is not None
        else _sha256(artifact)
    )
    if (
        Path(raw_profile.source_path).resolve() != artifact
        or raw_profile.sha256.lower() != artifact_sha256.lower()
    ):
        raise ValueError("raw profile does not match target artifact")
    source = (
        verified_provenance.source
        if verified_provenance is not None
        else build_source_ownership(side)
    )
    paths = (
        verified_provenance.paths
        if verified_provenance is not None
        else provenance_paths or discover_provenance(side, config.archive_limits)
    )
    r8_mapping: Mapping[str, set[str] | frozenset[str]]
    if verified_provenance is not None:
        r8_mapping = verified_provenance.r8_mapping
        mapping_source = verified_provenance.mapping_source
        resource_provenance = verified_provenance.resource_provenance
        source_sha256 = verified_provenance.source_sha256
        manifest_contents = verified_provenance.manifest_contents
    elif provenance_paths is None:
        validate_provenance(paths, side)
        source_sha256 = None
        manifest_contents = None
    else:
        _require_provenance(paths, side)
        source_sha256 = None
        manifest_contents = None
    if verified_provenance is None:
        if paths.embedded_r8_mapping:
            r8_mapping = paths.embedded_r8_mapping
            mapping_source = "embedded"
        elif paths.r8_mapping is not None:
            mapping_text = paths.r8_mapping.read_text(encoding="utf-8", errors="replace")
            r8_mapping = parse_r8_mapping(mapping_text)
            if not r8_mapping:
                raise ValueError(f"unusable R8 mapping for {side.variant}: {paths.r8_mapping}")
            mapping_source = "disk"
        else:
            raise ValueError(f"missing usable R8 mapping for {side.variant}")
        assert paths.resource_merger is not None
        resource_provenance = parse_resource_merger(paths.resource_merger, side)
    owned, attribution = attribute_owned_profile(
        raw_profile,
        source,
        r8_mapping,
        resource_provenance,
        source_sha256,
    )
    compiled_keys = {
        (resource_type, qualifiers, name)
        for (_, resource_type, qualifiers, name), owner in resource_provenance.items()
        if owner.category == "resource" and _values_backed(owner)
    }
    compiled_owners = {
        key: owner
        for key in compiled_keys
        if (owner := _inventory_owner(key, resource_provenance)) is not None
    }
    expected_compiled = {
        key for key, owner in compiled_owners.items() if _owned_origin(owner.origin)
    }
    inventory = verified_resource_inventory or {}
    inventory_origins: list[OriginKind] = []
    unverified_compiled: list[str] = []
    covered_compiled = 0
    for key in sorted(expected_compiled):
        if key not in inventory:
            unverified_compiled.append(_compiled_resource_label(key))
            inventory_origins.append(OriginKind.UNRESOLVED)
            continue
        covered_compiled += 1
        owner = compiled_owners[key]
        inventory_origins.append(owner.origin)
        value = inventory[key]
        if _owned_origin(owner.origin):
            resource_type, qualifiers, name = key
            directory = f"{resource_type}-{qualifiers}" if qualifiers else resource_type
            item = FileFingerprint(
                path=f"verified-resources/{directory}/{name}",
                module=owner.module.removeprefix(":"),
                category="resource",
                size=len(value.encode("utf-8")),
                sha256=hashlib.sha256(value.encode("utf-8")).hexdigest(),
                semantic_hash=hashlib.sha256(value.encode("utf-8")).hexdigest(),
                features=[value],
                origin=owner.origin.value,
                source_path=owner.source_path,
            )
            owned.files.append(item)
    attribution = _summary_with_additions(attribution, inventory_origins)
    owned.files.sort(key=lambda item: item.path)
    owned.manifest_entries = build_owned_manifest_entries(source, manifest_contents)
    owned.manifests = {"owned": [entry.value for entry in owned.manifest_entries]}
    owned.counts = dict(owned.counts)
    owned.counts["methods"] = len(owned.methods)
    owned.counts["candidate_methods"] = len(owned.methods)
    owned.counts["business_methods"] = len(owned.methods)
    owned.counts["long_methods"] = sum(
        method.instruction_count >= config.long_method_min_instructions for method in owned.methods
    )
    owned.counts["all_long_methods"] = owned.counts["long_methods"]
    owned.counts["images"] = len(owned.images)
    owned.counts["resources"] = sum(item.category == "resource" for item in owned.files)
    owned.counts["assets"] = sum(item.category == "asset" for item in owned.files)
    owned.counts["owned_files"] = len(owned.files)
    if unverified_compiled:
        owned.warnings.append("unverified compiled resources: " + ", ".join(unverified_compiled))
    owned.warnings = sorted(set(owned.warnings))
    owned.duration_seconds = 0.0
    if verified_provenance is not None:
        owned.source_path = str(side.artifact_output.resolve())
    return OwnedProjection(
        profile=owned,
        attribution=attribution,
        diagnostics={
            "provenance": {
                "r8_mapping": mapping_source,
                "resource_merger": str(paths.resource_merger),
                "source_entries": len(source.entries),
            },
            "compiled_resources": {
                "expected": len(expected_compiled),
                "covered": covered_compiled,
                "complete": not unverified_compiled,
                "unverified": unverified_compiled,
            },
        },
    )


def _module_roots(side: OwnershipSideConfig) -> tuple[Path, ...]:
    modules = {
        side.project_root / root.relative_to(side.project_root).parts[0]
        for root in side.source_roots
    }
    return tuple(sorted(modules))


def _first_existing(candidates: Iterable[Path]) -> Path | None:
    return next((path for path in candidates if path.is_file()), None)


def _load_embedded_r8_mapping_details(
    artifact: Path,
    limits: ArchiveLimits | None = None,
) -> tuple[dict[str, set[str]], str | None, str | None]:
    try:
        with open_validated_aab(artifact, limits or ArchiveLimits()) as archive:
            canonical = "BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map"
            fallback_candidates = sorted(
                name
                for name in archive.namelist()
                if name.startswith("BUNDLE-METADATA/")
                and name.endswith(("proguard.map", "mapping.txt"))
                and name != canonical
            )
            candidates = (
                [canonical] if canonical in archive.namelist() else []
            ) + fallback_candidates
            for name in candidates:
                raw_mapping = archive.read(name)
                mapping = parse_r8_mapping(raw_mapping.decode("utf-8", errors="replace"))
                if mapping:
                    return mapping, name, hashlib.sha256(raw_mapping).hexdigest()
    except ArchiveSecurityError:
        raise
    except (OSError, zipfile.BadZipFile):
        return {}, None, None
    return {}, None, None


def load_embedded_r8_mapping(
    artifact: Path, limits: ArchiveLimits | None = None
) -> dict[str, set[str]]:
    mapping, _, _ = _load_embedded_r8_mapping_details(artifact, limits)
    return mapping


def discover_provenance(
    side: OwnershipSideConfig, limits: ArchiveLimits | None = None
) -> ProvenancePaths:
    variant_title = side.variant[:1].upper() + side.variant[1:]
    module_roots = _module_roots(side)
    mappings = (
        module / "build" / "outputs" / "mapping" / side.variant / "mapping.txt"
        for module in module_roots
    )
    mergers = (
        module
        / "build"
        / "intermediates"
        / "incremental"
        / side.variant
        / f"merge{variant_title}Resources"
        / "merger.xml"
        for module in module_roots
    )
    embedded_mapping, embedded_entry, embedded_sha256 = _load_embedded_r8_mapping_details(
        side.artifact_output, limits or side.archive_limits
    )
    return ProvenancePaths(
        r8_mapping=_first_existing(mappings),
        resource_merger=_first_existing(mergers),
        embedded_r8_mapping=embedded_mapping,
        embedded_r8_mapping_entry=embedded_entry,
        embedded_r8_mapping_sha256=embedded_sha256,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verified_hardening_report(side: OwnershipSideConfig) -> Path | None:
    if not side.artifact_output.is_file():
        return None
    artifact_hash = _sha256(side.artifact_output).lower()
    for module in _module_roots(side):
        report = (
            module / "build" / "reports" / "hardening" / side.variant / "bundle-verification.json"
        )
        try:
            values = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if (
            isinstance(values, dict)
            and values.get("variant") == side.variant
            and isinstance(values.get("hardenedAabSha256"), str)
            and values["hardenedAabSha256"].lower() == artifact_hash
        ):
            return report
    return None


def _latest_owned_input_mtimes_ns(side: OwnershipSideConfig) -> dict[str, int]:
    latest: dict[str, int] = {}
    for root in (*_production_roots(side), *side.owned_generated_roots):
        paths = [root] if root.is_file() else root.rglob("*") if root.is_dir() else []
        for path in paths:
            if not path.is_file():
                continue
            modified = path.stat().st_mtime_ns
            categories = ["all"]
            if path.suffix.lower() in {".java", ".kt"}:
                categories.append("code")
            else:
                entry = _file_entry(side, path, OriginKind.OWNED_SOURCE)
                if entry is not None and entry.category in {"resource", "image"}:
                    categories.append("resource")
            for category in categories:
                latest[category] = max(latest.get(category, 0), modified)
    return latest


def _require_provenance(paths: ProvenancePaths, side: OwnershipSideConfig) -> None:
    if not side.artifact_output.is_file():
        raise ValueError(f"target artifact does not exist: {side.artifact_output}")
    if paths.resource_merger is None:
        raise ValueError(f"missing resource merger provenance for {side.variant}")
    if paths.r8_mapping is None and not paths.embedded_r8_mapping:
        raise ValueError(f"missing usable R8 mapping for {side.variant}")


def validate_provenance(paths: ProvenancePaths, side: OwnershipSideConfig) -> None:
    _require_provenance(paths, side)
    artifact_mtime = side.artifact_output.stat().st_mtime_ns
    latest_inputs = _latest_owned_input_mtimes_ns(side)
    if latest_inputs.get("all", 0) > artifact_mtime:
        raise ValueError("stale target artifact relative to owned source inputs")
    def stale(path: Path | None, input_category: str) -> bool:
        if path is None:
            return False
        modified = path.stat().st_mtime_ns
        return (
            artifact_mtime - modified > _MAX_PROVENANCE_ARTIFACT_GAP_SECONDS * 1_000_000_000
            or modified < latest_inputs.get(input_category, 0)
        )

    assert paths.resource_merger is not None
    candidates = [(paths.resource_merger, "resource")]
    if not paths.embedded_r8_mapping and paths.r8_mapping is not None:
        candidates.append((paths.r8_mapping, "code"))
    stale_paths = [path for path, category in candidates if stale(path, category)]
    if stale_paths:
        raise ValueError(
            "stale provenance relative to target artifact: " + ", ".join(map(str, stale_paths))
        )


def _side_lock_payload(
    side: OwnershipSideConfig,
    paths: ProvenancePaths,
) -> dict[str, Any]:
    _require_provenance(paths, side)
    if paths.embedded_r8_mapping:
        if (
            paths.embedded_r8_mapping_entry is None
            or paths.embedded_r8_mapping_sha256 is None
        ):
            raise ValueError(f"missing embedded R8 mapping identity for {side.variant}")
        mapping: dict[str, Any] = {
            "kind": "embedded",
            "entry": paths.embedded_r8_mapping_entry,
            "sha256": paths.embedded_r8_mapping_sha256,
        }
    else:
        assert paths.r8_mapping is not None
        mapping = {
            "kind": "disk",
            "path": str(paths.r8_mapping.resolve()),
            "sha256": _sha256(paths.r8_mapping),
        }
    assert paths.resource_merger is not None
    mergers = [
        {
            "role": role,
            "path": str(merger.resolve()),
            "sha256": _sha256(merger),
        }
        for role, merger in _consumed_resource_mergers(paths.resource_merger, side)
    ]
    hardening_report = _verified_hardening_report(side)
    hardening = (
        {
            "path": str(hardening_report.resolve()),
            "sha256": _sha256(hardening_report),
        }
        if hardening_report is not None
        else None
    )
    source_files = [
        {
            "origin": source_file.origin.value,
            "category": source_file.category,
            "path": str(source_file.path.resolve()),
            "sha256": _sha256(source_file.path),
        }
        for source_file in sorted(
            _consumed_source_files(side),
            key=lambda item: (str(item.path.resolve()), item.origin.value, item.category),
        )
    ]
    return {
        "project_root": str(side.project_root.resolve()),
        "source_roots": [str(path.resolve()) for path in side.source_roots],
        "owned_generated_roots": [
            str(path.resolve()) for path in side.owned_generated_roots
        ],
        "variant": side.variant,
        "artifact": {
            "path": str(side.artifact_output.resolve()),
            "sha256": _sha256(side.artifact_output),
        },
        "mapping": mapping,
        "resource_mergers": mergers,
        "source_files": source_files,
        "hardening_report": hardening,
    }


def _current_lock_payload(
    ownership: OwnershipConfig,
    *,
    validate_freshness: bool,
) -> tuple[dict[str, Any], dict[str, ProvenancePaths]]:
    paths_by_side: dict[str, ProvenancePaths] = {}
    sides: dict[str, Any] = {}
    for label, side in (("left", ownership.left), ("right", ownership.right)):
        paths = discover_provenance(side)
        if validate_freshness:
            validate_provenance(paths, side)
        else:
            _require_provenance(paths, side)
        paths_by_side[label] = paths
        sides[label] = _side_lock_payload(side, paths)
    return {"schema_version": 1, "sides": sides}, paths_by_side


def _required_provenance_lock(ownership: OwnershipConfig) -> Path:
    if ownership.provenance_lock is None:
        raise ValueError("owned comparison requires a configured provenance_lock")
    return _validated_provenance_lock_path(
        ownership.provenance_lock,
        (ownership.left, ownership.right),
    )


def _is_provenance_lock_document(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != {"schema_version", "sides"}:
        return False
    sides = value.get("sides")
    if value.get("schema_version") != 1 or not isinstance(sides, dict):
        return False
    if set(sides) != {"left", "right"}:
        return False
    required_side_keys = {
        "project_root",
        "source_roots",
        "owned_generated_roots",
        "variant",
        "artifact",
        "mapping",
        "resource_mergers",
        "hardening_report",
    }
    return all(
        isinstance(side, dict) and required_side_keys.issubset(side)
        for side in sides.values()
    )


def _provenance_lock_matches_ownership(
    locked: Mapping[str, Any],
    ownership: OwnershipConfig,
) -> bool:
    locked_sides = locked.get("sides")
    if not isinstance(locked_sides, dict):
        return False
    for label, side in (("left", ownership.left), ("right", ownership.right)):
        locked_side = locked_sides.get(label)
        if not isinstance(locked_side, dict):
            return False
        artifact = locked_side.get("artifact")
        if not isinstance(artifact, dict):
            return False
        if locked_side.get("project_root") != str(side.project_root.resolve()):
            return False
        if locked_side.get("source_roots") != [
            str(path.resolve()) for path in side.source_roots
        ]:
            return False
        if locked_side.get("owned_generated_roots") != [
            str(path.resolve()) for path in side.owned_generated_roots
        ]:
            return False
        if locked_side.get("variant") != side.variant:
            return False
        if artifact.get("path") != str(side.artifact_output.resolve()):
            return False
    return True


@dataclass(frozen=True)
class _LockDestinationState:
    descriptor: int
    content: bytes


def _read_descriptor(descriptor: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while chunk := os.read(descriptor, 1024 * 1024):
        chunks.append(chunk)
    return b"".join(chunks)


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _safe_lock_destination_state(
    lock_path: Path,
    ownership: OwnershipConfig,
) -> _LockDestinationState | None:
    flags = (
        os.O_RDWR
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(lock_path, flags)
    except FileNotFoundError:
        if lock_path.is_symlink():
            raise ValueError(
                f"refusing to overwrite non-provenance-lock file: {lock_path}"
            ) from None
        return None
    except OSError as error:
        raise ValueError(
            f"refusing to overwrite non-provenance-lock file: {lock_path}"
        ) from error
    try:
        descriptor_state = os.fstat(descriptor)
        path_state = os.stat(lock_path, follow_symlinks=False)
        if (
            not stat.S_ISREG(descriptor_state.st_mode)
            or not stat.S_ISREG(path_state.st_mode)
            or descriptor_state.st_nlink != 1
            or path_state.st_nlink != 1
            or not _same_file_identity(descriptor_state, path_state)
        ):
            raise ValueError(
                f"refusing to overwrite non-provenance-lock file: {lock_path}"
            )
        existing_bytes = _read_descriptor(descriptor)
        existing = json.loads(existing_bytes.decode("utf-8"))
        if not _is_provenance_lock_document(existing):
            raise ValueError(
                f"refusing to overwrite non-provenance-lock file: {lock_path}"
            )
        if not _provenance_lock_matches_ownership(existing, ownership):
            raise ValueError(
                "refusing to overwrite provenance lock for a different "
                f"ownership configuration: {lock_path}"
            )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        os.close(descriptor)
        raise ValueError(
            f"refusing to overwrite non-provenance-lock file: {lock_path}"
        ) from error
    except Exception:
        os.close(descriptor)
        raise
    return _LockDestinationState(descriptor, existing_bytes)


def _require_unchanged_lock_destination(
    lock_path: Path,
    destination: _LockDestinationState,
    expected: bytes,
) -> None:
    try:
        descriptor_state = os.fstat(destination.descriptor)
        path_state = os.stat(lock_path, follow_symlinks=False)
        unchanged = (
            stat.S_ISREG(descriptor_state.st_mode)
            and stat.S_ISREG(path_state.st_mode)
            and descriptor_state.st_nlink == 1
            and path_state.st_nlink == 1
            and _same_file_identity(descriptor_state, path_state)
            and _read_descriptor(destination.descriptor) == expected
        )
    except OSError as error:
        raise ValueError(
            f"provenance_lock destination changed while preparing: {lock_path}"
        ) from error
    if not unchanged:
        raise ValueError(f"provenance_lock destination changed while preparing: {lock_path}")


def _write_descriptor(descriptor: int, content: bytes) -> None:
    os.lseek(descriptor, 0, os.SEEK_SET)
    remaining = memoryview(content)
    while remaining:
        written = os.write(descriptor, remaining)
        if written == 0:
            raise OSError("failed to write provenance lock")
        remaining = remaining[written:]
    os.ftruncate(descriptor, len(content))
    os.fsync(descriptor)


def write_provenance_lock(ownership: OwnershipConfig) -> Path:
    lock_path = _required_provenance_lock(ownership)
    destination_state = _safe_lock_destination_state(lock_path, ownership)
    try:
        payload, _ = _current_lock_payload(ownership, validate_freshness=True)
        serialized = (
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        if destination_state is not None:
            _require_unchanged_lock_destination(
                lock_path,
                destination_state,
                destination_state.content,
            )
            try:
                _write_descriptor(destination_state.descriptor, serialized)
                _require_unchanged_lock_destination(lock_path, destination_state, serialized)
            except Exception:
                with suppress(OSError):
                    _write_descriptor(
                        destination_state.descriptor,
                        destination_state.content,
                    )
                raise
        else:
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{lock_path.name}.", suffix=".tmp", dir=lock_path.parent
            )
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(serialized)
                    stream.flush()
                    os.fsync(stream.fileno())
                temporary = Path(temporary_name)
                try:
                    os.link(temporary, lock_path)
                except FileExistsError as error:
                    raise ValueError(
                        f"provenance_lock destination changed while preparing: {lock_path}"
                    ) from error
                temporary.unlink()
            except Exception:
                Path(temporary_name).unlink(missing_ok=True)
                raise
    finally:
        if destination_state is not None:
            os.close(destination_state.descriptor)
    return lock_path


def _verified_lock_state(
    ownership: OwnershipConfig,
) -> tuple[dict[str, Any], dict[str, ProvenancePaths]]:
    lock_path = _required_provenance_lock(ownership)
    if lock_path.is_symlink() or not lock_path.is_file():
        raise ValueError(f"provenance lock is missing or unsafe: {lock_path}")
    try:
        locked = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid provenance lock: {lock_path}") from error
    current, paths_by_side = _current_lock_payload(ownership, validate_freshness=False)
    if locked != current:
        raise ValueError(
            "provenance lock does not match the configured artifacts or provenance inputs"
        )
    assert isinstance(locked, dict)
    return locked, paths_by_side


def _snapshot_source_inputs(
    side: OwnershipSideConfig,
    expected_files: object,
) -> tuple[OwnershipManifest, dict[str, str], dict[str, bytes]]:
    records: list[dict[str, str]] = []
    entries: list[OwnershipEntry] = []
    source_sha256: dict[str, str] = {}
    manifest_contents: dict[str, bytes] = {}
    source_files = sorted(
        _consumed_source_files(side),
        key=lambda item: (str(item.path.resolve()), item.origin.value, item.category),
    )
    for source_file in source_files:
        try:
            data = source_file.path.read_bytes()
        except OSError as error:
            raise ValueError(
                f"provenance source changed while snapshotting: {source_file.path}"
            ) from error
        digest = hashlib.sha256(data).hexdigest()
        records.append(
            {
                "origin": source_file.origin.value,
                "category": source_file.category,
                "path": str(source_file.path.resolve()),
                "sha256": digest,
            }
        )
        source_path = str(source_file.path)
        source_sha256[source_path] = digest
        if source_file.category == "code":
            entries.extend(
                _code_entries_from_text(
                    side,
                    source_file.path,
                    source_file.origin,
                    data.decode("utf-8", errors="replace"),
                )
            )
            continue
        entry = _file_entry(side, source_file.path, source_file.origin)
        if entry is not None:
            entries.append(entry)
            if source_file.category == "manifest":
                manifest_contents[source_path] = data
    if records != expected_files:
        raise ValueError("provenance lock changed while snapshotting source inputs")
    entries.sort(key=lambda item: (item.category, item.identifier, item.source_path))
    return OwnershipManifest(entries=entries), source_sha256, manifest_contents


def _snapshot_mapping(
    side: OwnershipSideConfig,
    paths: ProvenancePaths,
    artifact_path: Path,
    expected_mapping: object,
) -> tuple[dict[str, frozenset[str]], str]:
    if not isinstance(expected_mapping, dict):
        raise ValueError("invalid mapping record in provenance lock")
    if expected_mapping.get("kind") == "embedded":
        mapping, entry, digest = _load_embedded_r8_mapping_details(
            artifact_path,
            side.archive_limits,
        )
        if (
            entry != expected_mapping.get("entry")
            or digest != expected_mapping.get("sha256")
            or not mapping
        ):
            raise ValueError("embedded R8 mapping changed while snapshotting")
        return {key: frozenset(values) for key, values in mapping.items()}, "embedded"
    if expected_mapping.get("kind") != "disk" or paths.r8_mapping is None:
        raise ValueError("invalid disk mapping record in provenance lock")
    try:
        data = paths.r8_mapping.read_bytes()
    except OSError as error:
        raise ValueError("disk R8 mapping changed while snapshotting") from error
    if (
        str(paths.r8_mapping.resolve()) != expected_mapping.get("path")
        or hashlib.sha256(data).hexdigest() != expected_mapping.get("sha256")
    ):
        raise ValueError("disk R8 mapping changed while snapshotting")
    mapping = parse_r8_mapping(data.decode("utf-8", errors="replace"))
    if not mapping:
        raise ValueError(f"unusable R8 mapping for {side.variant}: {paths.r8_mapping}")
    return {key: frozenset(values) for key, values in mapping.items()}, "disk"


def _snapshot_resource_provenance(
    side: OwnershipSideConfig,
    paths: ProvenancePaths,
    expected_mergers: object,
) -> ResourceProvenance:
    assert paths.resource_merger is not None
    merger_data: list[tuple[Path, bytes]] = []
    records: list[dict[str, str]] = []
    for role, merger in _consumed_resource_mergers(paths.resource_merger, side):
        try:
            data = merger.read_bytes()
        except OSError as error:
            raise ValueError(f"resource merger changed while snapshotting: {merger}") from error
        merger_data.append((merger, data))
        records.append(
            {
                "role": role,
                "path": str(merger.resolve()),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    if records != expected_mergers:
        raise ValueError("provenance lock changed while snapshotting resource mergers")
    local: ResourceProvenance = {}
    for merger, data in merger_data[:-1]:
        local.update(_parse_resource_merger_bytes(data, merger, side))
    final_merger, final_data = merger_data[-1]
    return _parse_resource_merger_bytes(final_data, final_merger, side, local)


def _copy_locked_artifact(source: Path, destination: Path, expected_sha256: str) -> None:
    digest = hashlib.sha256()
    try:
        with source.open("rb") as input_stream, destination.open("xb") as output_stream:
            for chunk in iter(lambda: input_stream.read(1024 * 1024), b""):
                digest.update(chunk)
                output_stream.write(chunk)
    except OSError as error:
        raise ValueError(f"target artifact changed while snapshotting: {source}") from error
    if digest.hexdigest().lower() != expected_sha256.lower():
        raise ValueError(f"target artifact changed while snapshotting: {source}")
    destination.chmod(0o400)


@contextmanager
def verified_provenance_snapshot(
    ownership: OwnershipConfig,
) -> Iterator[dict[str, VerifiedProvenance]]:
    locked, paths_by_side = _verified_lock_state(ownership)
    locked_sides = locked["sides"]
    assert isinstance(locked_sides, dict)
    with tempfile.TemporaryDirectory(prefix="aab-compare-provenance-") as temp_name:
        temp = Path(temp_name)
        snapshots: dict[str, VerifiedProvenance] = {}
        for label, side in (("left", ownership.left), ("right", ownership.right)):
            locked_side = locked_sides[label]
            assert isinstance(locked_side, dict)
            artifact_record = locked_side["artifact"]
            assert isinstance(artifact_record, dict)
            artifact_sha256 = str(artifact_record["sha256"])
            artifact_path = temp / f"{label}.aab"
            _copy_locked_artifact(side.artifact_output, artifact_path, artifact_sha256)
            paths = paths_by_side[label]
            source, source_sha256, manifest_contents = _snapshot_source_inputs(
                side,
                locked_side.get("source_files"),
            )
            r8_mapping, mapping_source = _snapshot_mapping(
                side,
                paths,
                artifact_path,
                locked_side.get("mapping"),
            )
            resource_provenance = _snapshot_resource_provenance(
                side,
                paths,
                locked_side.get("resource_mergers"),
            )
            snapshots[label] = VerifiedProvenance(
                artifact_path=artifact_path,
                artifact_sha256=artifact_sha256,
                paths=paths,
                source=source,
                source_sha256=source_sha256,
                manifest_contents=manifest_contents,
                r8_mapping=r8_mapping,
                mapping_source=mapping_source,
                resource_provenance=resource_provenance,
            )
        yield snapshots


def verify_provenance_lock(ownership: OwnershipConfig) -> dict[str, ProvenancePaths]:
    _, paths_by_side = _verified_lock_state(ownership)
    return paths_by_side
