from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path

from .models import BundleProfile


class ProfileCache:
    def __init__(self, root: Path) -> None:
        self.root = root

    def load(self, key: str) -> BundleProfile | None:
        path = self.root / f"{key}.json"
        if not path.is_file():
            return None
        try:
            return BundleProfile.from_dict(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return None

    def save(self, key: str, profile: BundleProfile) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        destination = self.root / f"{key}.json"
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{key}.", suffix=".tmp", dir=self.root
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(profile.to_json())
                stream.flush()
                os.fsync(stream.fileno())
            Path(temporary_name).replace(destination)
        except Exception:
            Path(temporary_name).unlink(missing_ok=True)
            raise
        return destination


def cache_key(
    bundle_sha256: str,
    config_json: str,
    analyzer_version: str,
    *,
    capabilities: Mapping[str, bool] | None = None,
) -> str:
    capability_json = json.dumps(dict(capabilities or {}), sort_keys=True, separators=(",", ":"))
    material = (
        f"{bundle_sha256}\x00{config_json}\x00{analyzer_version}\x00{capability_json}"
    ).encode()
    return hashlib.sha256(material).hexdigest()
