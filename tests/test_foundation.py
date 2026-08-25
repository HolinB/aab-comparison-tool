from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from aab_compare.archive import ArchiveSecurityError, inspect_aab
from aab_compare.config import AnalysisConfig, load_config
from aab_compare.dex import canonicalize_instructions
from aab_compare.models import BundleProfile, DimensionResult
from aab_compare.scoring import aggregate_dimensions, similarity_level


def test_default_weights_sum_to_one_hundred() -> None:
    config = AnalysisConfig()
    assert sum(config.weights.values()) == 100
    assert config.long_method_min_instructions == 100
    assert "Lio/sentry/" in config.third_party_prefixes
    assert "Lretrofit2/" in config.third_party_prefixes
    assert "Lcoil/" in config.third_party_prefixes
    assert "Lcom/luck/picture/" in config.third_party_prefixes


def test_load_config_overrides_nested_values(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        """
long_method_min_instructions = 140
[weights]
business_code = 40
long_methods = 10
""".strip(),
        encoding="utf-8",
    )

    config = load_config(config_file)

    assert config.long_method_min_instructions == 140
    assert config.weights["business_code"] == 40
    assert sum(config.weights.values()) == 100


def test_bundle_profile_json_round_trip() -> None:
    profile = BundleProfile(
        source_path="/tmp/app.aab",
        sha256="abc",
        size=123,
        modules=["base"],
        counts={"dex": 2},
    )

    restored = BundleProfile.from_dict(json.loads(profile.to_json()))

    assert restored == profile


def test_safe_archive_rejects_path_traversal(tmp_path: Path) -> None:
    aab = tmp_path / "bad.aab"
    with zipfile.ZipFile(aab, "w") as archive:
        archive.writestr("base/manifest/AndroidManifest.xml", b"manifest")
        archive.writestr("../escape", b"bad")

    with pytest.raises(ArchiveSecurityError, match="unsafe path"):
        inspect_aab(aab, AnalysisConfig().archive_limits)


def test_safe_archive_counts_aab_dimensions(tmp_path: Path) -> None:
    aab = tmp_path / "valid.aab"
    with zipfile.ZipFile(aab, "w") as archive:
        archive.writestr("base/manifest/AndroidManifest.xml", b"manifest")
        archive.writestr("base/dex/classes.dex", b"dex\n035\x00")
        archive.writestr("base/lib/arm64-v8a/libx.so", b"elf")
        archive.writestr("base/assets/model.bin", b"asset")
        archive.writestr("base/res/drawable/logo.png", b"png")
        archive.writestr("BundleConfig.pb", b"config")

    inventory = inspect_aab(aab, AnalysisConfig().archive_limits)

    assert inventory.modules == ["base"]
    assert inventory.counts == {
        "entries": 6,
        "dex": 1,
        "native": 1,
        "assets": 1,
        "resources": 1,
        "manifests": 1,
    }


def test_safe_archive_rejects_symlinks_and_duplicate_entries(tmp_path: Path) -> None:
    symlink_aab = tmp_path / "symlink.aab"
    with zipfile.ZipFile(symlink_aab, "w") as archive:
        archive.writestr("base/manifest/AndroidManifest.xml", b"manifest")
        info = zipfile.ZipInfo("base/assets/link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, b"target")
    with pytest.raises(ArchiveSecurityError, match="symbolic link"):
        inspect_aab(symlink_aab, AnalysisConfig().archive_limits)

    duplicate_aab = tmp_path / "duplicate.aab"
    with zipfile.ZipFile(duplicate_aab, "w") as archive:
        archive.writestr("base/manifest/AndroidManifest.xml", b"manifest")
        archive.writestr("base/assets/value", b"one")
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("base/assets/value", b"two")
    with pytest.raises(ArchiveSecurityError, match="duplicate"):
        inspect_aab(duplicate_aab, AnalysisConfig().archive_limits)


@pytest.mark.skipif(
    os.name != "posix" or not hasattr(os, "mkfifo") or not hasattr(os, "O_NONBLOCK"),
    reason="requires POSIX FIFO support",
)
def test_safe_archive_rejects_fifo_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "blocked.aab"
    os.mkfifo(fifo)
    program = (
        "import sys\n"
        "from pathlib import Path\n"
        "from aab_compare.archive import ArchiveSecurityError, inspect_aab\n"
        "from aab_compare.config import AnalysisConfig\n"
        "try:\n"
        "    inspect_aab(Path(sys.argv[1]), AnalysisConfig().archive_limits)\n"
        "except (ArchiveSecurityError, FileNotFoundError):\n"
        "    raise SystemExit(0)\n"
        "raise SystemExit(1)\n"
    )

    try:
        completed = subprocess.run(
            [sys.executable, "-c", program, str(fifo)],
            capture_output=True,
            text=True,
            timeout=1,
            check=False,
        )
    except subprocess.TimeoutExpired:
        pytest.fail("FIFO AAB input blocked while opening")

    assert completed.returncode == 0, completed.stderr


def test_canonicalize_instructions_ignores_registers_and_symbol_names() -> None:
    left = [
        ("const/4", "v0, 0x1"),
        ("invoke-virtual", "{v0}, Ljava/lang/String;->length()I"),
        ("if-eqz", "v0, 0010"),
        ("return", "v0"),
    ]
    right = [
        ("const/16", "v7, 0x2"),
        ("invoke-virtual", "{v7}, Ljava/lang/String;->length()I"),
        ("if-eqz", "v7, 0020"),
        ("return", "v7"),
    ]

    assert (
        canonicalize_instructions(left).canonical_hash
        == canonicalize_instructions(right).canonical_hash
    )


def test_canonicalize_instructions_distinguishes_constant_categories() -> None:
    short_string = [("const-string", 'v0, "short"'), ("return", "v0")]
    long_string = [("const-string", 'v7, "a string longer than eight"'), ("return", "v7")]

    assert (
        canonicalize_instructions(short_string).canonical_hash
        != canonicalize_instructions(long_string).canonical_hash
    )


def test_aggregate_dimensions_uses_fixed_weights() -> None:
    config = AnalysisConfig()
    dimensions = {
        key: DimensionResult(key=key, score=80.0, left_coverage=1.0, right_coverage=1.0)
        for key in config.weights
    }

    aggregate = aggregate_dimensions(dimensions, config)

    assert aggregate.score == 80.0
    assert aggregate.minimum_score == 80.0
    assert aggregate.maximum_score == 80.0
    assert similarity_level(80.0, config.levels) == "极高"


def test_missing_dimension_produces_score_interval() -> None:
    config = AnalysisConfig()
    dimensions = {
        key: DimensionResult(
            key=key,
            score=None if key == "images" else 50.0,
            left_coverage=0.0 if key == "images" else 1.0,
            right_coverage=0.0 if key == "images" else 1.0,
        )
        for key in config.weights
    }

    aggregate = aggregate_dimensions(dimensions, config)

    assert aggregate.score is None
    assert aggregate.minimum_score == 46.0
    assert aggregate.maximum_score == 54.0
