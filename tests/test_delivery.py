from __future__ import annotations

import hashlib
import io
import json
import zipfile
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError
from PIL import Image

import aab_compare.report as report_module
from aab_compare.cache import ProfileCache
from aab_compare.config import AnalysisConfig
from aab_compare.models import (
    AggregateScore,
    BundleProfile,
    ComparisonResult,
    DimensionResult,
    Finding,
    ImageFingerprint,
)
from aab_compare.report import OutputDirectoryError, prepare_output_dir, render_report
from aab_compare.tools import ToolInstallError, ToolManager, ToolSpec


def _comparison() -> ComparisonResult:
    config = AnalysisConfig()
    left = BundleProfile("/tmp/left.aab", "left", 10, ["base"], {"dex": 1})
    right = BundleProfile("/tmp/right.aab", "right", 11, ["base"], {"dex": 1})
    dimensions = {
        key: DimensionResult(
            key,
            80.0,
            0.8,
            0.8,
            [Finding("匹配证据", 80.0, f"left-{key}", f"right-{key}")],
        )
        for key in config.weights
    }
    return ComparisonResult(
        left,
        right,
        dimensions,
        AggregateScore(80.0, 80.0, 80.0, 100, "极高"),
        config_snapshot=asdict(config),
    )


def test_profile_cache_round_trip(tmp_path: Path) -> None:
    cache = ProfileCache(tmp_path / "cache")
    profile = BundleProfile("/tmp/app.aab", "sha", 123, ["base"], {"dex": 1})

    cache.save("cache-key", profile)

    assert cache.load("cache-key") == profile


def test_tool_manager_downloads_and_verifies_locked_artifact(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.jar"
    artifact.write_bytes(b"locked-tool")
    spec = ToolSpec(
        name="demo",
        version="1.0",
        url=artifact.as_uri(),
        sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
        archive_type="file",
        executable_relative="demo.jar",
    )
    manager = ToolManager(tmp_path / "tools", specs=(spec,))

    installed = manager.install("demo")

    assert installed.read_bytes() == b"locked-tool"
    assert manager.status()["demo"]["installed"] is True
    assert manager.status()["demo"]["verified"] is True


def test_tool_manager_refuses_to_replace_unmanaged_version_directory(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.jar"
    artifact.write_bytes(b"locked-tool")
    spec = ToolSpec(
        name="demo",
        version="1.0",
        url=artifact.as_uri(),
        sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
        archive_type="file",
        executable_relative="demo.jar",
    )
    manager = ToolManager(tmp_path / "tools", specs=(spec,))
    unmanaged = tmp_path / "tools/demo-1.0"
    unmanaged.mkdir(parents=True)
    sentinel = unmanaged / "user-file.txt"
    sentinel.write_text("keep", encoding="utf-8")

    with pytest.raises(ToolInstallError, match="not managed"):
        manager.install("demo")

    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_tool_manager_repairs_managed_but_unverified_install(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.jar"
    artifact.write_bytes(b"locked-tool")
    spec = ToolSpec(
        name="demo",
        version="1.0",
        url=artifact.as_uri(),
        sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
        archive_type="file",
        executable_relative="demo.jar",
    )
    manager = ToolManager(tmp_path / "tools", specs=(spec,))
    executable = manager.install("demo")
    executable.write_bytes(b"corrupted")

    repaired = manager.install("demo")

    assert repaired.read_bytes() == b"locked-tool"
    assert manager.status()["demo"]["verified"] is True


def test_tool_manager_detects_and_repairs_tampered_zip_executable(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.zip"
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr("bin/demo", b"verified executable")
    spec = ToolSpec(
        name="demo",
        version="1.0",
        url=artifact.as_uri(),
        sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
        archive_type="zip",
        executable_relative="bin/demo",
    )
    manager = ToolManager(tmp_path / "tools", specs=(spec,))
    executable = manager.install("demo")
    executable.write_bytes(b"tampered executable")

    assert manager.status()["demo"]["verified"] is False

    repaired = manager.install("demo")

    assert repaired.read_bytes() == b"verified executable"
    assert manager.status()["demo"]["verified"] is True


def test_prepare_output_refuses_unmarked_directory(tmp_path: Path) -> None:
    output = tmp_path / "report"
    output.mkdir()
    (output / "user-file.txt").write_text("keep", encoding="utf-8")

    with pytest.raises(OutputDirectoryError, match="not managed"):
        prepare_output_dir(output, overwrite=True)

    assert (output / "user-file.txt").read_text(encoding="utf-8") == "keep"


def test_prepare_output_refuses_symlinked_root_and_preserves_target(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / ".aab-compare-output").write_text("schema=1\n", encoding="utf-8")
    (target / "data").mkdir()
    sentinel = target / "data/user.db"
    sentinel.write_text("keep", encoding="utf-8")
    output = tmp_path / "report"
    output.symlink_to(target, target_is_directory=True)

    with pytest.raises(OutputDirectoryError, match="symbolic link"):
        prepare_output_dir(output, overwrite=True)

    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_prepare_output_refuses_symlinked_marker_and_preserves_referent(tmp_path: Path) -> None:
    output = tmp_path / "report"
    output.mkdir()
    external_marker = tmp_path / "external-marker"
    external_marker.write_text("schema=1\n", encoding="utf-8")
    (output / ".aab-compare-output").symlink_to(external_marker)
    (output / "data").mkdir()
    sentinel = output / "data/user.db"
    sentinel.write_text("keep", encoding="utf-8")

    with pytest.raises(OutputDirectoryError, match="marker"):
        prepare_output_dir(output, overwrite=True)

    assert external_marker.read_text(encoding="utf-8") == "schema=1\n"
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_prepare_output_refuses_invalid_marker_content(tmp_path: Path) -> None:
    output = tmp_path / "report"
    output.mkdir()
    (output / ".aab-compare-output").write_text("not managed", encoding="utf-8")
    (output / "report.md").write_text("keep", encoding="utf-8")

    with pytest.raises(OutputDirectoryError, match="marker"):
        prepare_output_dir(output, overwrite=True)

    assert (output / "report.md").read_text(encoding="utf-8") == "keep"


def test_prepare_output_refuses_symlinked_known_output(tmp_path: Path) -> None:
    output = tmp_path / "report"
    output.mkdir()
    (output / ".aab-compare-output").write_text("schema=1\n", encoding="utf-8")
    external = tmp_path / "external-data"
    external.mkdir()
    sentinel = external / "user.db"
    sentinel.write_text("keep", encoding="utf-8")
    (output / "data").symlink_to(external, target_is_directory=True)

    with pytest.raises(OutputDirectoryError, match="symbolic link"):
        prepare_output_dir(output, overwrite=True)

    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_output_preflight_does_not_create_missing_directory(tmp_path: Path) -> None:
    output = tmp_path / "report"

    report_module.validate_output_dir(output)

    assert not output.exists()


def test_render_report_writes_markdown_json_and_evidence(tmp_path: Path) -> None:
    output = tmp_path / "report"

    report_path = render_report(_comparison(), output)

    assert report_path == output / "report.md"
    text = report_path.read_text(encoding="utf-8")
    assert "综合相似度：80.00 / 100（极高）" in text
    assert "业务代码" in text
    assert "置信度" in text
    assert (output / "data" / "analysis.json").is_file()
    schema = json.loads((output / "data" / "schema.json").read_text(encoding="utf-8"))
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert set(schema["required"]) >= {"schema_version", "aggregate", "dimensions", "left", "right"}
    evidence_links = [line for line in text.splitlines() if "evidence/" in line]
    assert evidence_links
    for line in evidence_links:
        relative = line.split("](", 1)[1].split(")", 1)[0]
        assert (output / relative).is_file()


def test_owned_report_has_six_independent_dimensions_and_separate_run_metadata(
    tmp_path: Path,
) -> None:
    profile = BundleProfile(
        "left.aab",
        "a" * 64,
        10,
        ["base"],
        {"dex": 1, "native": 2},
        agp_version="8.8.2",
        dependencies=["com.example:left:1"],
        build_features=["entry:META-INF/LEFT.RSA", "module:base"],
    )
    other = BundleProfile(
        "right.aab",
        "b" * 64,
        11,
        ["base"],
        {"dex": 1, "native": 3},
        agp_version="8.13.2",
        dependencies=["com.example:right:2"],
        build_features=["hardening:present", "module:base"],
    )
    keys = ("business_code", "long_methods", "images", "resources", "manifest", "assets")
    dimensions = {
        key: DimensionResult(
            key,
            None if key == "assets" else 80.0,
            0.5,
            0.75,
            metrics={
                "left_origins": {"OWNED_SOURCE": 2, "OWNED_GENERATED": 1},
                "right_origins": {"OWNED_SOURCE": 3, "OWNED_GENERATED": 2},
            },
        )
        for key in keys
    }
    result = ComparisonResult(
        profile,
        other,
        dimensions,
        None,
        mode="owned",
        ownership={
            "strategy": "strict_provenance",
            "left": {
                "owned_source": 4,
                "owned_generated": 2,
                "heuristic_owned": 0,
                "public_dependency": 3,
                "tool_generated": 1,
                "unresolved": 5,
            },
            "right": {
                "owned_source": 3,
                "owned_generated": 1,
                "heuristic_owned": 0,
                "public_dependency": 2,
                "tool_generated": 0,
                "unresolved": 4,
            },
        },
        diagnostics={
            "dependencies": {"left": [], "right": []},
            "native": {"left": 0, "right": 0},
            "build_structure": {"left": [], "right": []},
            "signing": {"left": [], "right": []},
            "hardening": {"left": [], "right": []},
            "agp": {"left": "8.8.2", "right": "8.13.2"},
            "projection": {"left": {}, "right": {}},
            "resource_inventory": {"left": {}, "right": {}},
            "selection": {
                "requested_mode": "auto",
                "registry_status": "matched",
                "message": "provenance registry 命中",
            },
        },
        warnings=["unresolved resource inventory"],
    )

    report_path = render_report(
        result,
        tmp_path / "owned",
        run_metadata={"cache": {"left": "hit"}, "duration_seconds": 1.25},
    )

    report = report_path.read_text(encoding="utf-8")
    analysis_text = (tmp_path / "owned/data/analysis.json").read_text(encoding="utf-8")
    run_text = (tmp_path / "owned/logs/run.json").read_text(encoding="utf-8")
    schema = json.loads((tmp_path / "owned/data/schema.json").read_text(encoding="utf-8"))
    analysis = json.loads(analysis_text)
    assert schema["properties"]["schema_version"] == {"const": 3}
    assert set(schema["required"]) <= set(analysis)
    owned_dimensions = schema["allOf"][0]["then"]["properties"]["dimensions"]
    assert set(owned_dimensions["required"]) == set(keys)
    owned_diagnostics = schema["$defs"]["owned_diagnostics"]
    assert "selection" in owned_diagnostics["required"]
    assert "严格自有代码与资源范围" in report
    assert "严格 provenance" in report
    assert "Assets" in report
    assert "N/A" in report
    assert "来源代码" in report and "自有生成" in report
    assert "2 / 1" in report and "3 / 2" in report
    assert "未解析" in report and "公共依赖" in report and "工具生成" in report
    assert "综合相似度" not in report
    assert "等级" not in report
    assert "权重" not in report
    assert "八维" not in report
    assert analysis["aggregate"] is None
    assert analysis["mode"] == "owned"
    for side in ("left", "right"):
        assert "dependencies" not in analysis[side]
        assert "build_features" not in analysis[side]
        assert "agp_version" not in analysis[side]
        assert "native" not in analysis[side]["counts"]
    assert "duration_seconds" not in analysis_text
    assert "duration_seconds\": 1.25" in run_text
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(analysis)
    invalid = deepcopy(analysis)
    del invalid["ownership"]["left"]["unresolved"]
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(invalid)

    heuristic = deepcopy(result)
    heuristic.ownership["strategy"] = "heuristic_aab"
    heuristic_path = render_report(heuristic, tmp_path / "heuristic")
    heuristic_report = heuristic_path.read_text(encoding="utf-8")
    heuristic_analysis = json.loads(
        (tmp_path / "heuristic/data/analysis.json").read_text(encoding="utf-8")
    )
    assert "AAB 启发式自有内容对比报告" in heuristic_report
    assert "不能证明完整源码归属" in heuristic_report
    assert "A 启发式候选" in heuristic_report
    Draft202012Validator(schema).validate(heuristic_analysis)


def test_legacy_analysis_and_report_do_not_embed_runtime_duration(tmp_path: Path) -> None:
    first = _comparison()
    second = _comparison()
    first.left.duration_seconds = 1.25
    first.right.duration_seconds = 2.5
    second.left.duration_seconds = 9.75
    second.right.duration_seconds = 10.5

    first_report = render_report(first, tmp_path / "first")
    second_report = render_report(second, tmp_path / "second")

    assert first_report.read_bytes() == second_report.read_bytes()
    assert (tmp_path / "first/data/analysis.json").read_bytes() == (
        tmp_path / "second/data/analysis.json"
    ).read_bytes()
    assert "分析耗时" not in first_report.read_text(encoding="utf-8")


def test_report_highlights_build_and_inventory_differences(tmp_path: Path) -> None:
    result = _comparison()
    result.left.agp_version = "8.8.2"
    result.right.agp_version = "8.13.2"
    result.left.counts.update(resources=2574, methods=7523, long_methods=492)
    result.right.counts.update(resources=2568, methods=7588, long_methods=490)
    result.left.build_features = ["entry:META-INF/ORIGINAL.RSA", "entry:META-INF/ORIGINAL.SF"]
    result.right.build_features = [
        "entry:META-INF/HARDEN.RSA",
        "entry:META-INF/HARDEN.SF",
        "entry:BUNDLE-METADATA/com.example.hardening/build.json",
        "hardening:present",
    ]
    result.dimensions["resources"].metrics["renamed_matches"] = 42

    report = render_report(result, tmp_path / "report").read_text(encoding="utf-8")

    assert "资源条目" in report
    assert "AGP 版本：`8.8.2` → `8.13.2`" in report
    assert "签名条目发生变化" in report
    assert "检测到 B 侧加固元数据" in report
    assert "资源内容相同但路径变化：42 项" in report


def test_render_report_creates_side_by_side_image_evidence(tmp_path: Path) -> None:
    def image_bytes(color: str) -> bytes:
        buffer = io.BytesIO()
        Image.new("RGB", (40, 30), color).save(buffer, "PNG")
        return buffer.getvalue()

    left_aab = tmp_path / "left.aab"
    right_aab = tmp_path / "right.aab"
    with zipfile.ZipFile(left_aab, "w") as archive:
        archive.writestr("base/res/drawable/a.png", image_bytes("red"))
    with zipfile.ZipFile(right_aab, "w") as archive:
        archive.writestr("base/res/drawable/b.png", image_bytes("red"))
    result = _comparison()
    result.left.source_path = str(tmp_path / "changed-left.aab")
    result.right.source_path = str(tmp_path / "changed-right.aab")
    result.left.images = [ImageFingerprint("base/res/drawable/a.png", "base", 1, "a", "00", 40, 30)]
    result.right.images = [
        ImageFingerprint("base/res/drawable/b.png", "base", 1, "b", "00", 40, 30)
    ]
    result.dimensions["images"].findings = [
        Finding(
            "图片视觉匹配",
            100.0,
            "base/res/drawable/a.png",
            "base/res/drawable/b.png",
        )
    ]

    render_report(
        result,
        tmp_path / "report",
        bundle_paths=(left_aab, right_aab),
    )

    thumbnail = tmp_path / "report" / "evidence" / "images" / "001.png"
    assert thumbnail.is_file()
    with Image.open(thumbnail) as image:
        assert image.width > image.height
