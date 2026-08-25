from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from platformdirs import user_cache_path

from .ownership import OwnershipConfig


def default_registry_root() -> Path:
    return user_cache_path("aab-compare") / "provenance"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class RegistryLookup:
    status: str
    ownership_config: Path | None = None
    message: str = ""


class ProvenanceRegistry:
    def __init__(self, root: Path | None = None) -> None:
        self.root = (root or default_registry_root()).expanduser()

    @staticmethod
    def _pair_key(left: Path, right: Path) -> str:
        material = f"{left.resolve()}\0{right.resolve()}".encode()
        return hashlib.sha256(material).hexdigest()

    def record_path(self, left: Path, right: Path) -> Path:
        return self.root / f"{self._pair_key(left, right)}.json"

    def _validate_root(self) -> None:
        if self.root.is_symlink():
            raise ValueError(f"provenance registry must not be a symbolic link: {self.root}")
        if self.root.exists() and not self.root.is_dir():
            raise ValueError(f"provenance registry root is not a directory: {self.root}")

    def register(self, ownership_config: Path, ownership: OwnershipConfig) -> Path:
        self._validate_root()
        config_path = ownership_config.resolve()
        lock_path = ownership.provenance_lock
        if ownership_config.is_symlink() or not config_path.is_file():
            raise ValueError(f"ownership configuration is missing or unsafe: {ownership_config}")
        if lock_path is None or lock_path.is_symlink() or not lock_path.is_file():
            raise ValueError("provenance lock is missing or unsafe")
        left = ownership.left.artifact_output.resolve()
        right = ownership.right.artifact_output.resolve()
        if not left.is_file() or not right.is_file():
            raise ValueError("registered AAB pair must exist")
        record = self.record_path(left, right)
        if record.is_symlink():
            raise ValueError(f"registry record must not be a symbolic link: {record}")
        if record.exists() and not record.is_file():
            raise ValueError(f"registry record is not a regular file: {record}")
        payload = {
            "schema_version": 1,
            "ownership_config": str(config_path),
            "provenance_lock": str(lock_path.resolve()),
            "artifacts": {
                "left": {"path": str(left), "sha256": _sha256(left)},
                "right": {"path": str(right), "sha256": _sha256(right)},
            },
        }
        self.root.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{record.stem}.", suffix=".tmp", dir=self.root
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            if record.is_symlink():
                raise ValueError(f"registry record must not be a symbolic link: {record}")
            os.replace(temporary_name, record)
        except Exception:
            Path(temporary_name).unlink(missing_ok=True)
            raise
        return record

    @staticmethod
    def _valid_record(raw: Any) -> bool:
        if not isinstance(raw, dict) or set(raw) != {
            "schema_version",
            "ownership_config",
            "provenance_lock",
            "artifacts",
        }:
            return False
        artifacts = raw.get("artifacts")
        if raw.get("schema_version") != 1 or not isinstance(artifacts, dict):
            return False
        if set(artifacts) != {"left", "right"}:
            return False
        return all(
            isinstance(artifact, dict)
            and set(artifact) == {"path", "sha256"}
            and isinstance(artifact["path"], str)
            and isinstance(artifact["sha256"], str)
            for artifact in artifacts.values()
        )

    def lookup(self, left: Path, right: Path) -> RegistryLookup:
        self._validate_root()
        record = self.record_path(left, right)
        if not record.exists() and not record.is_symlink():
            return RegistryLookup("missing", message="未找到已登记的 provenance")
        if record.is_symlink() or not record.is_file():
            return RegistryLookup("invalid", message="provenance registry 记录不安全")
        try:
            raw = json.loads(record.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return RegistryLookup("invalid", message="provenance registry 记录损坏")
        if not self._valid_record(raw):
            return RegistryLookup("invalid", message="provenance registry 记录格式无效")
        artifacts = raw["artifacts"]
        resolved = {"left": left.resolve(), "right": right.resolve()}
        for side, path in resolved.items():
            if artifacts[side]["path"] != str(path):
                return RegistryLookup("invalid", message="provenance registry 路径不匹配")
            if not path.is_file() or artifacts[side]["sha256"] != _sha256(path):
                return RegistryLookup("stale", message=f"{side} AAB SHA-256 已变化")
        config_path = Path(raw["ownership_config"])
        lock_path = Path(raw["provenance_lock"])
        if (
            config_path.is_symlink()
            or not config_path.is_file()
            or lock_path.is_symlink()
            or not lock_path.is_file()
        ):
            return RegistryLookup("stale", message="ownership 配置或 provenance lock 已失效")
        return RegistryLookup("matched", config_path, "provenance registry 命中")


def register_provenance_pair(
    ownership_config: Path,
    ownership: OwnershipConfig,
    registry: ProvenanceRegistry | None = None,
) -> Path:
    return (registry or ProvenanceRegistry()).register(ownership_config, ownership)
