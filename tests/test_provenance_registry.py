from __future__ import annotations

import json
from pathlib import Path

import pytest

from aab_compare.ownership import OwnershipConfig, OwnershipSideConfig
from aab_compare.provenance_registry import ProvenanceRegistry


def _ownership(tmp_path: Path) -> tuple[Path, OwnershipConfig]:
    left_root = tmp_path / "left-project"
    right_root = tmp_path / "right-project"
    left_root.mkdir()
    right_root.mkdir()
    left = left_root / "left.aab"
    right = right_root / "right.aab"
    left.write_bytes(b"left")
    right.write_bytes(b"right")
    lock = tmp_path / "provenance.lock.json"
    lock.write_text('{"schema_version": 1}\n', encoding="utf-8")
    config_path = tmp_path / "ownership.toml"
    config_path.write_text("schema_version = 2\n", encoding="utf-8")
    ownership = OwnershipConfig(
        left=OwnershipSideConfig(left_root, (), "release", left),
        right=OwnershipSideConfig(right_root, (), "release", right),
        schema_version=2,
        provenance_lock=lock,
    )
    return config_path, ownership


def test_registry_registers_and_matches_exact_ordered_aab_pair(tmp_path: Path) -> None:
    config_path, ownership = _ownership(tmp_path)
    registry = ProvenanceRegistry(tmp_path / "registry")

    record = registry.register(config_path, ownership)
    lookup = registry.lookup(ownership.left.artifact_output, ownership.right.artifact_output)

    assert record.is_file()
    assert lookup.status == "matched"
    assert lookup.ownership_config == config_path.resolve()
    assert registry.lookup(
        ownership.right.artifact_output, ownership.left.artifact_output
    ).status == "missing"


def test_registry_reports_stale_when_registered_aab_content_changes(tmp_path: Path) -> None:
    config_path, ownership = _ownership(tmp_path)
    registry = ProvenanceRegistry(tmp_path / "registry")
    registry.register(config_path, ownership)

    ownership.left.artifact_output.write_bytes(b"changed")
    lookup = registry.lookup(ownership.left.artifact_output, ownership.right.artifact_output)

    assert lookup.status == "stale"
    assert lookup.ownership_config is None
    assert "SHA-256" in lookup.message


def test_registry_treats_malformed_record_as_invalid(tmp_path: Path) -> None:
    config_path, ownership = _ownership(tmp_path)
    registry = ProvenanceRegistry(tmp_path / "registry")
    record = registry.register(config_path, ownership)
    record.write_text(json.dumps({"schema_version": 999}), encoding="utf-8")

    lookup = registry.lookup(ownership.left.artifact_output, ownership.right.artifact_output)

    assert lookup.status == "invalid"
    assert lookup.ownership_config is None


def test_registry_refuses_symlink_record_without_touching_referent(tmp_path: Path) -> None:
    config_path, ownership = _ownership(tmp_path)
    registry = ProvenanceRegistry(tmp_path / "registry")
    record = registry.record_path(
        ownership.left.artifact_output, ownership.right.artifact_output
    )
    record.parent.mkdir(parents=True)
    referent = tmp_path / "user.json"
    referent.write_text("keep", encoding="utf-8")
    record.symlink_to(referent)

    with pytest.raises(ValueError, match="symbolic link"):
        registry.register(config_path, ownership)

    assert referent.read_text(encoding="utf-8") == "keep"
    assert registry.lookup(
        ownership.left.artifact_output, ownership.right.artifact_output
    ).status == "invalid"
