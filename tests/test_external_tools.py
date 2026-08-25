from __future__ import annotations

import hashlib
from dataclasses import asdict
from pathlib import Path
from subprocess import CompletedProcess

from aab_compare.config import AnalysisConfig
from aab_compare.models import (
    AggregateScore,
    BundleProfile,
    ComparisonResult,
    DimensionResult,
    Finding,
)
from aab_compare.report import render_report
from aab_compare.tools import (
    ToolManager,
    ToolSpec,
    decode_manifest_details,
    decode_manifests,
    dump_resource_inventory,
    normalize_manifest_xml,
    run_jadx,
)


def test_bundletool_resource_dump_runs_once_and_parses_values(tmp_path: Path) -> None:
    artifact = tmp_path / "bundletool.jar"
    artifact.write_bytes(b"jar")
    spec = ToolSpec(
        "bundletool",
        "test",
        artifact.as_uri(),
        hashlib.sha256(b"jar").hexdigest(),
        "file",
        "bundletool.jar",
    )
    manager = ToolManager(tmp_path / "tools", specs=(spec,))
    manager.install("bundletool")
    calls: list[list[str]] = []
    output = """Package 'com.example':
0x7f010001 - string/app_name
    (default) - [STR] "Example App"
    locale: "zh-CN" - [STR] "示例应用"
    locale: "sr-Latn" - [STR] "Primer"
    locale: "es-419" - [STR] "Ejemplo"
0x7f020001 - color/accent
    (default) - [COLOR_ARGB8] #ff102030
0x7f030001 - style/AppTheme
    (default) - [STYLE] [@color/accent]
0x7f040001 - bool/night_enabled
    ui_mode_night: UI_MODE_NIGHT_NIGHT
sdk_version: 33 - [BOOLEAN] true
"""

    def runner(command: list[str], **_: object) -> CompletedProcess[str]:
        calls.append(command)
        return CompletedProcess(command, 0, output, "")

    inventory, warnings = dump_resource_inventory(
        manager, tmp_path / "sample.aab", AnalysisConfig(), runner=runner
    )

    assert warnings == []
    assert inventory == {
        ("bool", "night-v33", "night_enabled"): "true",
        ("color", "", "accent"): "#ff102030",
        ("string", "", "app_name"): '"Example App"',
        ("string", "b+es+419", "app_name"): '"Ejemplo"',
        ("string", "b+sr+Latn", "app_name"): '"Primer"',
        ("string", "zh-rCN", "app_name"): '"示例应用"',
        ("style", "", "AppTheme"): "[@color/accent]",
    }
    assert len(calls) == 1
    assert calls[0][4:] == [
        "dump",
        "resources",
        f"--bundle={(tmp_path / 'sample.aab').resolve()}",
        "--values",
    ]


def test_bundletool_resource_dump_failure_admits_no_values(tmp_path: Path) -> None:
    artifact = tmp_path / "bundletool.jar"
    artifact.write_bytes(b"jar")
    spec = ToolSpec(
        "bundletool",
        "test",
        artifact.as_uri(),
        hashlib.sha256(b"jar").hexdigest(),
        "file",
        "bundletool.jar",
    )
    manager = ToolManager(tmp_path / "tools", specs=(spec,))
    manager.install("bundletool")

    def runner(command: list[str], **_: object) -> CompletedProcess[str]:
        return CompletedProcess(command, 1, "partial output that must be ignored", "bad bundle")

    inventory, warnings = dump_resource_inventory(
        manager, tmp_path / "sample.aab", AnalysisConfig(), runner=runner
    )

    assert inventory == {}
    assert warnings and "资源清单" in warnings[0]


def test_bundletool_resource_dump_supports_inherited_type_and_warns_on_partial_parse(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "bundletool.jar"
    artifact.write_bytes(b"jar")
    spec = ToolSpec(
        "bundletool",
        "test",
        artifact.as_uri(),
        hashlib.sha256(b"jar").hexdigest(),
        "file",
        "bundletool.jar",
    )
    manager = ToolManager(tmp_path / "tools", specs=(spec,))
    manager.install("bundletool")
    output = """Package 'com.example':
0x7f010001 - string/app_name
    (default) - [STR] "Example App"
0x7f010002 - string/unparsable_value
"""

    def runner(command: list[str], **_: object) -> CompletedProcess[str]:
        return CompletedProcess(command, 0, output, "")

    inventory, warnings = dump_resource_inventory(
        manager, tmp_path / "sample.aab", AnalysisConfig(), runner=runner
    )

    assert inventory == {("string", "", "app_name"): '"Example App"'}
    assert warnings and "部分" in warnings[0]


def test_bundletool_manifest_decoder_uses_each_module(tmp_path: Path) -> None:
    artifact = tmp_path / "bundletool.jar"
    artifact.write_bytes(b"jar")
    spec = ToolSpec(
        "bundletool",
        "test",
        artifact.as_uri(),
        hashlib.sha256(b"jar").hexdigest(),
        "file",
        "bundletool.jar",
    )
    manager = ToolManager(tmp_path / "tools", specs=(spec,))
    manager.install("bundletool")
    commands: list[list[str]] = []

    def fake_runner(command: list[str], **_: object) -> CompletedProcess[str]:
        commands.append(command)
        return CompletedProcess(
            command,
            0,
            '<manifest><uses-permission android:name="android.permission.INTERNET"/></manifest>',
            "",
        )

    decoded, warnings = decode_manifests(
        manager,
        tmp_path / "sample.aab",
        ["base", "feature"],
        AnalysisConfig(),
        runner=fake_runner,
    )

    assert warnings == []
    assert set(decoded) == {"base", "feature"}
    assert any("android.permission.INTERNET" in item for item in decoded["base"])
    assert commands[0][-1] == "--module=base"
    assert commands[1][-1] == "--module=feature"


def test_bundletool_manifest_details_preserve_package_and_component_names(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "bundletool.jar"
    artifact.write_bytes(b"jar")
    spec = ToolSpec(
        "bundletool",
        "test",
        artifact.as_uri(),
        hashlib.sha256(b"jar").hexdigest(),
        "file",
        "bundletool.jar",
    )
    manager = ToolManager(tmp_path / "tools", specs=(spec,))
    manager.install("bundletool")

    def fake_runner(command: list[str], **_: object) -> CompletedProcess[str]:
        return CompletedProcess(
            command,
            0,
            """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android"
                package="com.example.app">
              <permission android:name="com.example.app.INTERNAL" />
              <application><activity android:name=".MainActivity" /></application>
            </manifest>
            """,
            "",
        )

    details, warnings = decode_manifest_details(
        manager,
        tmp_path / "sample.aab",
        ["base"],
        AnalysisConfig(),
        runner=fake_runner,
    )

    assert warnings == []
    assert details["base"].package_name == "com.example.app"
    assert details["base"].components == (("activity", "com.example.app.MainActivity"),)
    assert details["base"].permissions == ("com.example.app.INTERNAL",)


def test_report_method_evidence_includes_jadx_source(tmp_path: Path) -> None:
    left_source = tmp_path / "jadx-left" / "sources" / "com" / "example" / "Feature.java"
    right_source = tmp_path / "jadx-right" / "sources" / "a" / "b.java"
    left_source.parent.mkdir(parents=True)
    right_source.parent.mkdir(parents=True)
    left_source.write_text("class Feature { int calculate() { return 7; } }", encoding="utf-8")
    right_source.write_text("class b { int a() { return 7; } }", encoding="utf-8")
    config = AnalysisConfig()
    dimensions = {key: DimensionResult(key, 100.0, 1.0, 1.0) for key in config.weights}
    dimensions["business_code"].findings.append(
        Finding(
            "方法实现匹配",
            100.0,
            "Lcom/example/Feature;->calculate()I",
            "La/b;->a()I",
        )
    )
    result = ComparisonResult(
        BundleProfile("/tmp/left.aab", "left", 1, ["base"], {}),
        BundleProfile("/tmp/right.aab", "right", 1, ["base"], {}),
        dimensions,
        AggregateScore(100.0, 100.0, 100.0, 100, "极高"),
        config_snapshot=asdict(config),
    )

    render_report(
        result,
        tmp_path / "report",
        source_roots=(left_source.parents[3], right_source.parents[2]),
    )

    evidence = tmp_path / "report" / "evidence" / "business_code" / "001.txt"
    text = evidence.read_text(encoding="utf-8")
    assert "SOURCE A" in text
    assert "int calculate()" in text
    assert "SOURCE B" in text
    assert "int a()" in text


def test_jadx_runner_builds_deterministic_command(tmp_path: Path) -> None:
    artifact = tmp_path / "jadx"
    artifact.write_bytes(b"executable")
    spec = ToolSpec(
        "jadx",
        "test",
        artifact.as_uri(),
        hashlib.sha256(b"executable").hexdigest(),
        "file",
        "bin/jadx",
    )
    manager = ToolManager(tmp_path / "tools", specs=(spec,))
    manager.install("jadx")
    commands: list[list[str]] = []
    environments: list[dict[str, str]] = []

    def fake_runner(command: list[str], **kwargs: object) -> CompletedProcess[str]:
        commands.append(command)
        environments.append(kwargs["env"])  # type: ignore[arg-type]
        return CompletedProcess(command, 0, "", "")

    output, warnings = run_jadx(
        manager,
        tmp_path / "app.aab",
        tmp_path / "jadx-output",
        AnalysisConfig(jobs=3),
        runner=fake_runner,
    )

    assert warnings == []
    assert output == tmp_path / "jadx-output"
    assert commands[0][1:6] == ["--no-res", "--threads-count", "3", "-d", str(output)]
    assert environments[0]["JADX_CONFIG_DIR"].startswith(str(output))
    assert environments[0]["JADX_CACHE_DIR"].startswith(str(output))


def test_manifest_normalization_ignores_component_class_names() -> None:
    left = """
    <manifest xmlns:android="http://schemas.android.com/apk/res/android">
      <uses-permission android:name="android.permission.INTERNET" />
      <application>
        <activity android:name="com.example.MainActivity" android:exported="true" />
      </application>
    </manifest>
    """
    right = left.replace("com.example.MainActivity", "a.b")

    assert normalize_manifest_xml(left) == normalize_manifest_xml(right)
    assert "uses-permission:name=android.permission.INTERNET" in normalize_manifest_xml(left)


def test_jadx_runner_keeps_partial_sources_when_cli_reports_decompile_errors(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "jadx"
    artifact.write_bytes(b"executable")
    spec = ToolSpec(
        "jadx",
        "test",
        artifact.as_uri(),
        hashlib.sha256(b"executable").hexdigest(),
        "file",
        "bin/jadx",
    )
    manager = ToolManager(tmp_path / "tools", specs=(spec,))
    manager.install("jadx")

    def partial_runner(command: list[str], **_: object) -> CompletedProcess[str]:
        output = Path(command[5])
        source = output / "sources" / "com" / "example" / "Feature.java"
        source.parent.mkdir(parents=True)
        source.write_text("class Feature {}", encoding="utf-8")
        return CompletedProcess(command, 3, "", "finished with errors, count: 2")

    output, warnings = run_jadx(
        manager,
        tmp_path / "app.aab",
        tmp_path / "jadx-output",
        AnalysisConfig(),
        runner=partial_runner,
    )

    assert output == tmp_path / "jadx-output"
    assert warnings and "部分反编译" in warnings[0]


def test_jadx_failure_separates_stable_warning_from_runtime_diagnostics(tmp_path: Path) -> None:
    artifact = tmp_path / "jadx"
    artifact.write_bytes(b"executable")
    spec = ToolSpec(
        "jadx",
        "test",
        artifact.as_uri(),
        hashlib.sha256(b"executable").hexdigest(),
        "file",
        "bin/jadx",
    )
    manager = ToolManager(tmp_path / "tools", specs=(spec,))
    manager.install("jadx")
    runtime_diagnostics: list[str] = []

    def failed_runner(command: list[str], **_: object) -> CompletedProcess[str]:
        return CompletedProcess(
            command,
            1,
            "",
            "failure in /tmp/aab-compare-jadx-random-123 at 12:34:56",
        )

    output, warnings = run_jadx(
        manager,
        tmp_path / "app.aab",
        tmp_path / "jadx-output",
        AnalysisConfig(),
        runner=failed_runner,
        diagnostics=runtime_diagnostics,
    )

    assert output is None
    assert warnings == ["JADX 反编译失败（退出码 1）"]
    assert runtime_diagnostics == [
        "failure in /tmp/aab-compare-jadx-random-123 at 12:34:56"
    ]
