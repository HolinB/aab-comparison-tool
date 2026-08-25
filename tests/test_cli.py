from __future__ import annotations

import hashlib
import json
import zipfile
from copy import deepcopy
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from aab_compare.cache import ProfileCache
from aab_compare.cli import (
    _core_analysis_incomplete,
    _load_or_analyze,
    execute_compare,
    main,
    run_prepare_tasks,
)
from aab_compare.config import AnalysisConfig
from aab_compare.models import BundleProfile
from aab_compare.ownership import (
    AttributionSummary,
    OwnedProjection,
    OwnershipConfig,
    OwnershipSideConfig,
)
from aab_compare.provenance_registry import RegistryLookup
from aab_compare.tools import DEFAULT_TOOL_SPECS


def _minimal_aab(path: Path, marker: bytes) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "base/manifest/AndroidManifest.xml", b"manifest activity android.permission.INTERNET"
        )
        archive.writestr("base/res/raw/payload.bin", marker)
        archive.writestr("BundleConfig.pb", b"bundle config")


def _ownership_config_file(
    path: Path,
    left_root: Path,
    right_root: Path,
    *,
    right_task: bool = False,
) -> Path:
    right_prepare = 'prepare_task = ":app:bundleRelease"' if right_task else ""
    path.write_text(
        f'''schema_version = 2
provenance_lock = "cache/provenance.lock.json"
[left]
project_root = "{left_root}"
source_roots = []
variant = "release"
artifact_output = "left.aab"
prepare_task = ":app:bundleRelease"
[right]
project_root = "{right_root}"
source_roots = []
variant = "release"
artifact_output = "right.aab"
{right_prepare}
''',
        encoding="utf-8",
    )
    return path


def test_default_tools_are_fixed_versions() -> None:
    versions = {spec.name: spec.version for spec in DEFAULT_TOOL_SPECS}
    assert versions == {"jadx": "1.5.6", "bundletool": "1.18.3"}
    assert all(len(spec.sha256) == 64 for spec in DEFAULT_TOOL_SPECS)


def test_profile_cache_separates_dex_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = tmp_path / "app.aab"
    artifact.write_bytes(b"same artifact")
    calls: list[bool] = []

    def fake_analyze(
        path: Path,
        config: AnalysisConfig,
        *,
        include_dex: bool,
        progress: object,
    ) -> BundleProfile:
        calls.append(include_dex)
        return BundleProfile(
            str(path.resolve()),
            "a" * 64,
            path.stat().st_size,
            ["base"],
            {"methods": int(include_dex)},
        )

    monkeypatch.setattr("aab_compare.cli.analyze_bundle", fake_analyze)
    cache = ProfileCache(tmp_path / "cache")

    skipped = _load_or_analyze(
        artifact,
        AnalysisConfig(),
        include_dex=False,
        use_cache=True,
        cache=cache,
        progress=False,
    )
    complete = _load_or_analyze(
        artifact,
        AnalysisConfig(),
        include_dex=True,
        use_cache=True,
        cache=cache,
        progress=False,
    )

    assert calls == [False, True]
    assert skipped.counts["methods"] == 0
    assert complete.counts["methods"] == 1


def test_load_or_analyze_enforces_locked_artifact_sha_before_cache_write(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "app.aab"
    _minimal_aab(artifact, b"artifact")
    cache = ProfileCache(tmp_path / "cache")

    with pytest.raises(ValueError, match="artifact does not match provenance lock"):
        _load_or_analyze(
            artifact,
            AnalysisConfig(),
            include_dex=False,
            use_cache=True,
            cache=cache,
            progress=False,
            expected_sha256="0" * 64,
        )

    assert not cache.root.exists()


def test_profile_cache_rebinds_source_path_for_identical_artifact_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    left = tmp_path / "left.aab"
    right = tmp_path / "right.aab"
    left.write_bytes(b"same artifact")
    right.write_bytes(left.read_bytes())
    calls: list[Path] = []

    def fake_analyze(
        path: Path,
        config: AnalysisConfig,
        *,
        include_dex: bool,
        progress: object,
    ) -> BundleProfile:
        calls.append(path)
        return BundleProfile(str(path.resolve()), "a" * 64, path.stat().st_size, ["base"], {})

    monkeypatch.setattr("aab_compare.cli.analyze_bundle", fake_analyze)
    cache = ProfileCache(tmp_path / "cache")

    _load_or_analyze(
        left,
        AnalysisConfig(),
        include_dex=False,
        use_cache=True,
        cache=cache,
        progress=False,
    )
    cached_copy = _load_or_analyze(
        right,
        AnalysisConfig(),
        include_dex=False,
        use_cache=True,
        cache=cache,
        progress=False,
    )

    assert calls == [left]
    assert cached_copy.source_path == str(right.resolve())


@pytest.mark.integration
def test_execute_compare_generates_report_without_external_tools(tmp_path: Path) -> None:
    left = tmp_path / "left.aab"
    right = tmp_path / "right.aab"
    output = tmp_path / "output"
    _minimal_aab(left, b"same-resource")
    _minimal_aab(right, b"same-resource")

    report = execute_compare(
        left,
        right,
        output,
        AnalysisConfig(),
        include_dex=False,
        ensure_tools=False,
        use_cache=False,
        mode="legacy",
    )

    assert report.is_file()
    assert "AAB 多维度查重报告" in report.read_text(encoding="utf-8")


@pytest.mark.integration
def test_execute_compare_heuristic_generates_six_owned_dimensions(tmp_path: Path) -> None:
    left = tmp_path / "left.aab"
    right = tmp_path / "right.aab"
    output = tmp_path / "output"
    _minimal_aab(left, b"same-resource")
    _minimal_aab(right, b"same-resource")

    report = execute_compare(
        left,
        right,
        output,
        AnalysisConfig(),
        include_dex=False,
        ensure_tools=False,
        use_cache=False,
        mode="heuristic",
    )
    payload = json.loads((output / "data/analysis.json").read_text(encoding="utf-8"))

    assert report.is_file()
    assert payload["mode"] == "owned"
    assert payload["aggregate"] is None
    assert payload["ownership"]["strategy"] == "heuristic_aab"
    assert payload["diagnostics"]["selection"]["registry_status"] == "not_provided"
    assert set(payload["dimensions"]) == {
        "business_code",
        "long_methods",
        "images",
        "resources",
        "manifest",
        "assets",
    }


def test_main_returns_input_error_for_missing_aab(tmp_path: Path, capsys: object) -> None:
    code = main(["compare", str(tmp_path / "missing.aab"), str(tmp_path / "other.aab")])
    assert code == 2


def test_root_command_compares_two_aabs_with_heuristic_fallback_and_default_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    left = tmp_path / "Left App.aab"
    right = tmp_path / "Right_App.aab"
    _minimal_aab(left, b"left")
    _minimal_aab(right, b"right")
    monkeypatch.chdir(tmp_path)
    captured: dict[str, object] = {}

    class MissingRegistry:
        def lookup(self, lookup_left: Path, lookup_right: Path) -> RegistryLookup:
            assert lookup_left == left
            assert lookup_right == right
            return RegistryLookup("missing", message="not registered")

    def fake_execute(
        left_path: Path,
        right_path: Path,
        output_dir: Path,
        _config: AnalysisConfig,
        **kwargs: object,
    ) -> Path:
        captured.update(
            left=left_path,
            right=right_path,
            output=output_dir,
            mode=kwargs["mode"],
            overwrite=kwargs["overwrite"],
        )
        output_dir.mkdir(parents=True)
        (output_dir / "data").mkdir()
        (output_dir / "data/analysis.json").write_text(
            json.dumps({"warnings": []}), encoding="utf-8"
        )
        report = output_dir / "report.md"
        report.write_text("report", encoding="utf-8")
        return report

    monkeypatch.setattr("aab_compare.cli.ProvenanceRegistry", MissingRegistry)
    monkeypatch.setattr("aab_compare.cli.execute_compare", fake_execute)

    code = main([str(left), str(right), "--skip-tools", "--skip-dex"])

    assert code == 0
    assert captured == {
        "left": left,
        "right": right,
        "output": Path("aab-compare-output/Left-App-vs-Right_App"),
        "mode": "heuristic",
        "overwrite": True,
    }


def test_auto_mode_uses_registered_ownership_when_paths_match(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    left = tmp_path / "left.aab"
    right = tmp_path / "right.aab"
    _minimal_aab(left, b"left")
    _minimal_aab(right, b"right")
    config_path = tmp_path / "ownership.toml"
    config_path.write_text("schema_version = 2\n", encoding="utf-8")
    ownership = OwnershipConfig(
        OwnershipSideConfig(tmp_path, (), "release", left),
        OwnershipSideConfig(tmp_path, (), "release", right),
        schema_version=2,
        provenance_lock=tmp_path / "lock.json",
    )
    captured: dict[str, object] = {}

    class MatchedRegistry:
        def lookup(self, _left: Path, _right: Path) -> RegistryLookup:
            return RegistryLookup("matched", config_path)

    def fake_execute(*_args: object, **kwargs: object) -> Path:
        captured.update(mode=kwargs["mode"], ownership=kwargs["ownership"])
        output = tmp_path / "report"
        output.mkdir()
        (output / "data").mkdir()
        (output / "data/analysis.json").write_text(
            json.dumps({"warnings": []}), encoding="utf-8"
        )
        (output / "report.md").write_text("report", encoding="utf-8")
        return output / "report.md"

    monkeypatch.setattr("aab_compare.cli.ProvenanceRegistry", MatchedRegistry)
    monkeypatch.setattr("aab_compare.cli.load_ownership_config", lambda _: ownership)
    monkeypatch.setattr("aab_compare.cli.execute_compare", fake_execute)

    assert main([str(left), str(right), "-o", str(tmp_path / "output")]) == 0
    assert captured == {"mode": "owned", "ownership": ownership}


def test_auto_mode_falls_back_when_registered_provenance_validation_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    left = tmp_path / "left.aab"
    right = tmp_path / "right.aab"
    _minimal_aab(left, b"left")
    _minimal_aab(right, b"right")
    config_path = tmp_path / "ownership.toml"
    config_path.write_text("schema_version = 2\n", encoding="utf-8")
    ownership = OwnershipConfig(
        OwnershipSideConfig(tmp_path, (), "release", left),
        OwnershipSideConfig(tmp_path, (), "release", right),
        schema_version=2,
        provenance_lock=tmp_path / "lock.json",
    )
    modes: list[str] = []

    class MatchedRegistry:
        def lookup(self, _left: Path, _right: Path) -> RegistryLookup:
            return RegistryLookup("matched", config_path)

    def fake_execute(*_args: object, **kwargs: object) -> Path:
        mode = str(kwargs["mode"])
        modes.append(mode)
        if mode == "owned":
            raise ValueError("provenance lock does not match")
        output = tmp_path / "report"
        output.mkdir()
        (output / "data").mkdir()
        (output / "data/analysis.json").write_text(
            json.dumps({"warnings": []}), encoding="utf-8"
        )
        (output / "report.md").write_text("report", encoding="utf-8")
        return output / "report.md"

    monkeypatch.setattr("aab_compare.cli.ProvenanceRegistry", MatchedRegistry)
    monkeypatch.setattr("aab_compare.cli.load_ownership_config", lambda _: ownership)
    monkeypatch.setattr("aab_compare.cli.execute_compare", fake_execute)

    assert main([str(left), str(right), "-o", str(tmp_path / "output")]) == 0
    assert modes == ["owned", "heuristic"]
    assert "转为启发式分析" in capsys.readouterr().err


def test_auto_mode_falls_back_when_registered_config_rebinds_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    left = tmp_path / "left.aab"
    right = tmp_path / "right.aab"
    _minimal_aab(left, b"left")
    _minimal_aab(right, b"right")
    config_path = tmp_path / "ownership.toml"
    config_path.write_text("schema_version = 2\n", encoding="utf-8")
    ownership = OwnershipConfig(
        OwnershipSideConfig(tmp_path, (), "release", tmp_path / "other-left.aab"),
        OwnershipSideConfig(tmp_path, (), "release", tmp_path / "other-right.aab"),
        schema_version=2,
        provenance_lock=tmp_path / "lock.json",
    )
    modes: list[str] = []

    class MatchedRegistry:
        def lookup(self, _left: Path, _right: Path) -> RegistryLookup:
            return RegistryLookup("matched", config_path)

    def fake_execute(*_args: object, **kwargs: object) -> Path:
        modes.append(str(kwargs["mode"]))
        output = tmp_path / "report"
        output.mkdir()
        (output / "data").mkdir()
        (output / "data/analysis.json").write_text(
            json.dumps({"warnings": []}), encoding="utf-8"
        )
        (output / "report.md").write_text("report", encoding="utf-8")
        return output / "report.md"

    monkeypatch.setattr("aab_compare.cli.ProvenanceRegistry", MatchedRegistry)
    monkeypatch.setattr("aab_compare.cli.load_ownership_config", lambda _: ownership)
    monkeypatch.setattr("aab_compare.cli.execute_compare", fake_execute)

    assert main([str(left), str(right), "-o", str(tmp_path / "output")]) == 0
    assert modes == ["heuristic"]


def test_legacy_owned_entry_remains_compatible_and_warns_about_deprecation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    left_root = tmp_path / "left-project"
    right_root = tmp_path / "right-project"
    left_root.mkdir()
    right_root.mkdir()
    left = left_root / "left.aab"
    right = right_root / "right.aab"
    _minimal_aab(left, b"left")
    _minimal_aab(right, b"right")
    ownership_path = _ownership_config_file(
        tmp_path / "ownership.toml", left_root, right_root
    )

    def fake_execute(*_args: object, **_kwargs: object) -> Path:
        output = tmp_path / "report"
        output.mkdir()
        (output / "data").mkdir()
        (output / "data/analysis.json").write_text(
            json.dumps({"warnings": []}), encoding="utf-8"
        )
        (output / "report.md").write_text("report", encoding="utf-8")
        return output / "report.md"

    monkeypatch.setattr("aab_compare.cli.execute_compare", fake_execute)

    assert (
        main(
            [
                "compare",
                str(left),
                str(right),
                "--ownership-config",
                str(ownership_path),
                "-o",
                str(tmp_path / "output"),
            ]
        )
        == 0
    )
    assert "已弃用" in capsys.readouterr().err


def test_explicit_legacy_checks_inputs_without_ownership_config(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(
        [
            "compare",
            str(tmp_path / "left.aab"),
            str(tmp_path / "right.aab"),
            "--mode",
            "legacy",
        ]
    )

    assert code == 2
    assert "--ownership-config" not in capsys.readouterr().err


def test_owned_execute_requires_provenance_lock_before_analysis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    left = tmp_path / "left.aab"
    right = tmp_path / "right.aab"
    _minimal_aab(left, b"left")
    _minimal_aab(right, b"right")
    left_root = tmp_path / "left-project"
    right_root = tmp_path / "right-project"
    left_root.mkdir()
    right_root.mkdir()
    ownership = OwnershipConfig(
        left=OwnershipSideConfig(left_root, (), "release", left),
        right=OwnershipSideConfig(right_root, (), "release", right),
    )

    def forbidden_analysis(*_: object, **__: object) -> BundleProfile:
        raise AssertionError("analysis must not run before provenance lock verification")

    monkeypatch.setattr("aab_compare.cli.analyze_bundle", forbidden_analysis)

    with pytest.raises(ValueError, match="provenance_lock"):
        execute_compare(
            left,
            right,
            tmp_path / "output",
            AnalysisConfig(),
            ensure_tools=False,
            use_cache=False,
            mode="owned",
            ownership=ownership,
        )


def test_prepare_runs_only_explicit_tasks_with_exact_argv(tmp_path: Path) -> None:
    left_root = tmp_path / "left"
    right_root = tmp_path / "right"
    left_root.mkdir()
    right_root.mkdir()
    (left_root / "gradlew").write_text("", encoding="utf-8")
    calls: list[tuple[list[str], Path]] = []

    def runner(command: list[str], **kwargs: object) -> CompletedProcess[str]:
        calls.append((command, kwargs["cwd"]))  # type: ignore[arg-type]
        return CompletedProcess(command, 0, "", "")

    config = OwnershipConfig(
        left=OwnershipSideConfig(
            left_root, (), "demoRelease", left_root / "left.aab", ":app:bundleDemoRelease"
        ),
        right=OwnershipSideConfig(right_root, (), "release", right_root / "right.aab"),
    )

    run_prepare_tasks(config, runner=runner)

    assert calls == [
        ([str((left_root / "gradlew").resolve()), ":app:bundleDemoRelease"], left_root.resolve())
    ]


@pytest.mark.parametrize(
    "task",
    [":app:bundleRelease --offline", ":app:bundleRelease;touch", "bundleRelease", ":", "::bad"],
)
def test_prepare_rejects_unsafe_or_malformed_task_names(tmp_path: Path, task: str) -> None:
    root = tmp_path / "project"
    root.mkdir()
    config = OwnershipConfig(
        left=OwnershipSideConfig(root, (), "release", root / "left.aab", task),
        right=OwnershipSideConfig(root, (), "release", root / "right.aab"),
    )

    with pytest.raises(ValueError, match="prepare_task"):
        run_prepare_tasks(config)


def test_prepare_validates_all_gradle_wrappers_before_running_any_task(tmp_path: Path) -> None:
    left_root = tmp_path / "left"
    right_root = tmp_path / "right"
    left_root.mkdir()
    right_root.mkdir()
    (left_root / "gradlew").write_text("", encoding="utf-8")
    calls: list[list[str]] = []
    config = OwnershipConfig(
        left=OwnershipSideConfig(
            left_root, (), "release", left_root / "left.aab", ":app:bundleRelease"
        ),
        right=OwnershipSideConfig(
            right_root, (), "release", right_root / "right.aab", ":app:bundleRelease"
        ),
    )

    def runner(command: list[str], **_: object) -> CompletedProcess[str]:
        calls.append(command)
        return CompletedProcess(command, 0, "", "")

    with pytest.raises(ValueError, match="gradlew"):
        run_prepare_tasks(config, runner=runner)

    assert calls == []


def test_prepare_command_refreshes_lock_and_registers_without_comparing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    left_root = tmp_path / "left-project"
    right_root = tmp_path / "right-project"
    left_root.mkdir()
    right_root.mkdir()
    ownership_path = _ownership_config_file(
        tmp_path / "ownership.toml", left_root, right_root
    )
    calls: list[str] = []

    monkeypatch.setattr("aab_compare.cli.run_prepare_tasks", lambda _: calls.append("prepare"))
    monkeypatch.setattr(
        "aab_compare.cli.write_provenance_lock",
        lambda _: calls.append("lock") or tmp_path / "cache/provenance.lock.json",
    )
    monkeypatch.setattr(
        "aab_compare.cli.register_provenance_pair",
        lambda *_: calls.append("register") or tmp_path / "registry/pair.json",
    )
    monkeypatch.setattr(
        "aab_compare.cli.execute_compare",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("prepare must not compare")
        ),
    )

    assert main(["prepare", str(ownership_path)]) == 0
    assert calls == ["prepare", "lock", "register"]


@pytest.mark.parametrize("invalid", ["binding", "jobs", "analysis-config"])
def test_main_validates_static_arguments_before_preparing_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invalid: str,
) -> None:
    left_root = tmp_path / "left-project"
    right_root = tmp_path / "right-project"
    left_root.mkdir()
    right_root.mkdir()
    left = left_root / "left.aab"
    right = right_root / "right.aab"
    _minimal_aab(left, b"left")
    _minimal_aab(right, b"right")
    ownership_path = _ownership_config_file(
        tmp_path / "ownership.toml", left_root, right_root
    )
    calls: list[str] = []
    monkeypatch.setattr("aab_compare.cli.run_prepare_tasks", lambda _: calls.append("prepare"))
    argv = [
        "compare",
        str(left),
        str(right),
        "--ownership-config",
        str(ownership_path),
        "--prepare-provenance",
        "--skip-tools",
    ]
    if invalid == "binding":
        argv[1] = str(tmp_path / "wrong.aab")
    elif invalid == "jobs":
        argv.extend(["--jobs", "0"])
    else:
        argv.extend(["--config", str(tmp_path / "missing-analysis.toml")])

    assert main(argv) == 2
    assert calls == []


def test_main_prepare_can_create_artifacts_then_freezes_before_compare(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    left_root = tmp_path / "left-project"
    right_root = tmp_path / "right-project"
    left_root.mkdir()
    right_root.mkdir()
    left = left_root / "left.aab"
    right = right_root / "right.aab"
    ownership_path = _ownership_config_file(
        tmp_path / "ownership.toml", left_root, right_root
    )
    output = tmp_path / "output"
    calls: list[str] = []

    def fake_prepare(_: OwnershipConfig) -> None:
        calls.append("prepare")
        _minimal_aab(left, b"left")
        _minimal_aab(right, b"right")

    def fake_lock(_: OwnershipConfig) -> Path:
        calls.append("lock")
        return tmp_path / "cache/provenance.lock.json"

    def fake_execute(*_: object, **__: object) -> Path:
        calls.append("compare")
        output.mkdir()
        (output / "data").mkdir()
        (output / "report.md").write_text("report", encoding="utf-8")
        (output / "data/analysis.json").write_text(
            json.dumps({"warnings": []}), encoding="utf-8"
        )
        return output / "report.md"

    monkeypatch.setattr("aab_compare.cli.run_prepare_tasks", fake_prepare)
    monkeypatch.setattr("aab_compare.cli.write_provenance_lock", fake_lock)
    monkeypatch.setattr("aab_compare.cli.execute_compare", fake_execute)

    assert (
        main(
            [
                "compare",
                str(left),
                str(right),
                "--ownership-config",
                str(ownership_path),
                "--prepare-provenance",
                "--skip-tools",
                "-o",
                str(output),
            ]
        )
        == 0
    )
    assert calls == ["prepare", "lock", "compare"]


def test_main_validates_output_before_preparing_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    left_root = tmp_path / "left-project"
    right_root = tmp_path / "right-project"
    left_root.mkdir()
    right_root.mkdir()
    left = left_root / "left.aab"
    right = right_root / "right.aab"
    _minimal_aab(left, b"left")
    _minimal_aab(right, b"right")
    ownership_path = _ownership_config_file(
        tmp_path / "ownership.toml", left_root, right_root
    )
    output = tmp_path / "output"
    output.mkdir()
    (output / "user.db").write_text("keep", encoding="utf-8")
    calls: list[str] = []
    monkeypatch.setattr("aab_compare.cli.run_prepare_tasks", lambda _: calls.append("prepare"))

    assert (
        main(
            [
                "compare",
                str(left),
                str(right),
                "--ownership-config",
                str(ownership_path),
                "--prepare-provenance",
                "--skip-tools",
                "--overwrite",
                "-o",
                str(output),
            ]
        )
        == 2
    )
    assert calls == []
    assert (output / "user.db").read_text(encoding="utf-8") == "keep"


def test_owned_execute_is_deterministic_and_empty_dimensions_are_not_core_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    left = tmp_path / "left.aab"
    right = tmp_path / "right.aab"
    _minimal_aab(left, b"left")
    _minimal_aab(right, b"right")
    left_root = tmp_path / "left-project"
    right_root = tmp_path / "right-project"
    left_root.mkdir()
    right_root.mkdir()
    ownership = OwnershipConfig(
        left=OwnershipSideConfig(left_root, (), "release", left),
        right=OwnershipSideConfig(right_root, (), "release", right),
    )

    def fake_projection(
        profile: BundleProfile, side: object, config: object, **_: object
    ) -> OwnedProjection:
        projected = deepcopy(profile)
        projected.duration_seconds = 0.0
        projected.methods = []
        projected.files = []
        projected.images = []
        projected.manifests = {}
        projected.manifest_entries = []
        return OwnedProjection(projected, AttributionSummary(), {"compiled_resources": {}})

    class FakeSnapshot:
        def __enter__(self) -> dict[str, object]:
            class Verified:
                def __init__(self, path: Path) -> None:
                    self.artifact_path = path
                    self.artifact_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()

            return {"left": Verified(left), "right": Verified(right)}

        def __exit__(self, *_: object) -> None:
            return None

    monkeypatch.setattr("aab_compare.cli.build_owned_projection", fake_projection)
    monkeypatch.setattr(
        "aab_compare.cli.verified_provenance_snapshot",
        lambda _: FakeSnapshot(),
    )
    profile_cache = ProfileCache(tmp_path / "cache")
    first = execute_compare(
        left,
        right,
        tmp_path / "first",
        AnalysisConfig(),
        include_dex=False,
        ensure_tools=False,
        use_cache=True,
        cache=profile_cache,
        mode="owned",
        ownership=ownership,
    )
    second = execute_compare(
        left,
        right,
        tmp_path / "second",
        AnalysisConfig(),
        include_dex=False,
        ensure_tools=False,
        offline=True,
        use_cache=False,
        cache=profile_cache,
        mode="owned",
        ownership=ownership,
    )

    first_analysis = (first.parent / "data/analysis.json").read_bytes()
    second_analysis = (second.parent / "data/analysis.json").read_bytes()
    first_run = json.loads((first.parent / "logs/run.json").read_text(encoding="utf-8"))
    assert first_analysis == second_analysis
    assert first.read_bytes() == second.read_bytes()
    analysis = json.loads(first_analysis)
    assert analysis["aggregate"] is None
    assert set(analysis["dimensions"]) == {
        "business_code",
        "long_methods",
        "images",
        "resources",
        "manifest",
        "assets",
    }
    assert all(item["score"] is None for item in analysis["dimensions"].values())
    assert first_run["cache_path"] == str(profile_cache.root.resolve())
    assert set(first_run["timings"]) == {"left_analysis_seconds", "right_analysis_seconds"}
    assert _core_analysis_incomplete(first) is False


def test_main_does_not_prepare_provenance_without_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    left_root = tmp_path / "left-project"
    right_root = tmp_path / "right-project"
    left_root.mkdir()
    right_root.mkdir()
    left = left_root / "left.aab"
    right = right_root / "right.aab"
    _minimal_aab(left, b"left")
    _minimal_aab(right, b"right")
    ownership_path = tmp_path / "ownership.toml"
    ownership_path.write_text(
        f'''schema_version = 2
provenance_lock = "cache/provenance.lock.json"
[left]
project_root = "{left_root}"
source_roots = []
variant = "release"
artifact_output = "left.aab"
prepare_task = ":app:bundleRelease"
[right]
project_root = "{right_root}"
source_roots = []
variant = "release"
artifact_output = "right.aab"
''',
        encoding="utf-8",
    )

    def forbidden_prepare(*_: object, **__: object) -> None:
        raise AssertionError("normal compare must not invoke Gradle")

    output = tmp_path / "output"

    def fake_execute(*_: object, **__: object) -> Path:
        output.mkdir()
        (output / "data").mkdir()
        (output / "report.md").write_text("report", encoding="utf-8")
        (output / "data/analysis.json").write_text(
            json.dumps({"warnings": []}), encoding="utf-8"
        )
        return output / "report.md"

    monkeypatch.setattr("aab_compare.cli.run_prepare_tasks", forbidden_prepare)
    monkeypatch.setattr("aab_compare.cli.execute_compare", fake_execute)

    assert main(
        [
            "compare",
            str(left),
            str(right),
            "--ownership-config",
            str(ownership_path),
            "-o",
            str(output),
        ]
    ) == 0


def test_main_returns_partial_code_when_dex_core_cannot_be_parsed(tmp_path: Path) -> None:
    left = tmp_path / "left.aab"
    right = tmp_path / "right.aab"
    for path in (left, right):
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("base/manifest/AndroidManifest.xml", b"manifest")
            archive.writestr("base/dex/classes.dex", b"not-a-dex")

    code = main(
        [
            "compare",
            str(left),
            str(right),
            "-o",
            str(tmp_path / "output"),
            "--skip-tools",
            "--no-cache",
            "--mode",
            "legacy",
        ]
    )

    assert code == 4
