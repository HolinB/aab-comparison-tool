from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, replace
from pathlib import Path

from platformdirs import user_cache_path

from . import __version__
from .analyzers import analyze_bundle, compare_owned_profiles, compare_profiles
from .archive import ArchiveSecurityError
from .cache import ProfileCache, cache_key
from .config import AnalysisConfig, load_config
from .heuristic import build_heuristic_projection
from .models import BundleProfile
from .ownership import (
    OwnershipConfig,
    VerifiedProvenance,
    build_owned_projection,
    load_ownership_config,
    verified_provenance_snapshot,
    write_provenance_lock,
)
from .provenance_registry import ProvenanceRegistry, register_provenance_pair
from .report import OutputDirectoryError, render_report, validate_output_dir
from .tools import (
    ToolInstallError,
    ToolManager,
    decode_manifest_details,
    decode_manifests,
    dump_resource_inventory,
    run_jadx,
)

_PROFILE_ANALYZER_REVISION = "profile-v6"
_GRADLE_TASK = re.compile(r"(?::[A-Za-z][A-Za-z0-9_-]*)+")
_COMMANDS = {"compare", "prepare", "tools"}


def _with_archive_limits(
    ownership: OwnershipConfig, config: AnalysisConfig
) -> OwnershipConfig:
    return replace(
        ownership,
        left=replace(ownership.left, archive_limits=config.archive_limits),
        right=replace(ownership.right, archive_limits=config.archive_limits),
    )


def run_prepare_tasks(
    ownership: OwnershipConfig,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    """Run only explicitly configured provenance preparation tasks."""
    commands: list[tuple[str, str, Path, Path]] = []
    for label, side in (("left", ownership.left), ("right", ownership.right)):
        task = side.prepare_task
        if task is None:
            continue
        if _GRADLE_TASK.fullmatch(task) is None:
            raise ValueError(f"{label}.prepare_task is unsafe or malformed: {task}")
        gradlew = (side.project_root / "gradlew").resolve()
        if not gradlew.is_file():
            raise ValueError(f"{label}.project_root has no gradlew")
        commands.append((label, task, gradlew, side.project_root.resolve()))
    for label, task, gradlew, project_root in commands:
        completed = runner(
            [str(gradlew), task],
            cwd=project_root,
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            raise ValueError(
                f"{label}.prepare_task failed with exit code {completed.returncode}: {task}"
            )


def _input_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _profile_cache_root() -> Path:
    return user_cache_path("aab-compare") / "profiles"


def _normalized_argv(argv: Sequence[str] | None) -> tuple[list[str], bool]:
    values = list(sys.argv[1:] if argv is None else argv)
    direct = bool(values and values[0] not in _COMMANDS and not values[0].startswith("-"))
    return (["compare", *values] if direct else values), direct


def _safe_output_stem(path: Path) -> str:
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", path.stem).strip("-._")
    return (stem or "aab")[:60]


def default_output_dir(left: Path, right: Path) -> Path:
    name = f"{_safe_output_stem(left)}-vs-{_safe_output_stem(right)}"
    return Path("aab-compare-output") / name


def _core_analysis_incomplete(report: Path) -> bool:
    try:
        result = json.loads((report.parent / "data" / "analysis.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, KeyError):
        return True
    warnings = result.get("warnings", [])
    return any(str(item).startswith("DEX 解析失败") for item in warnings)


def _resource_inventory_confidence(projection_diagnostics: dict[str, object]) -> float:
    compiled = projection_diagnostics.get("compiled_resources")
    if not isinstance(compiled, dict):
        return 1.0
    expected = compiled.get("expected", 0)
    covered = compiled.get("covered", 0)
    if not isinstance(expected, int) or not isinstance(covered, int) or expected <= 0:
        return 1.0
    return max(0.0, min(covered / expected, 1.0))


def _load_or_analyze(
    path: Path,
    config: AnalysisConfig,
    *,
    include_dex: bool,
    use_cache: bool,
    cache: ProfileCache,
    progress: bool,
    expected_sha256: str | None = None,
    run_metadata: dict[str, object] | None = None,
    side: str | None = None,
) -> BundleProfile:
    started = time.monotonic()

    def record_timing() -> None:
        if run_metadata is None or side is None:
            return
        timings = run_metadata.setdefault("timings", {})
        assert isinstance(timings, dict)
        timings[f"{side}_analysis_seconds"] = round(time.monotonic() - started, 6)

    input_sha256 = _input_sha256(path)
    if expected_sha256 is not None and input_sha256.lower() != expected_sha256.lower():
        raise ValueError(f"artifact does not match provenance lock: {path}")
    config_json = json.dumps(asdict(config), ensure_ascii=False, sort_keys=True)
    key = cache_key(
        input_sha256,
        config_json,
        f"{__version__}:{_PROFILE_ANALYZER_REVISION}",
        capabilities={"include_dex": include_dex},
    )
    if use_cache:
        cached = cache.load(key)
        if (
            cached is not None
            and expected_sha256 is not None
            and cached.sha256.lower() != expected_sha256.lower()
        ):
            cached = None
        if cached is not None:
            if run_metadata is not None and side is not None:
                cache_metadata = run_metadata.setdefault("cache", {})
                assert isinstance(cache_metadata, dict)
                cache_metadata[side] = "hit"
            if progress:
                print(f"使用缓存画像：{path.name}")
            record_timing()
            return replace(cached, source_path=str(path.resolve()))
    if run_metadata is not None and side is not None:
        cache_metadata = run_metadata.setdefault("cache", {})
        assert isinstance(cache_metadata, dict)
        cache_metadata[side] = "miss" if use_cache else "disabled"
    profile = analyze_bundle(
        path,
        config,
        include_dex=include_dex,
        progress=print if progress else None,
    )
    if expected_sha256 is not None and (
        profile.sha256.lower() != expected_sha256.lower()
        or _input_sha256(path).lower() != expected_sha256.lower()
    ):
        raise ValueError(f"artifact does not match provenance lock: {path}")
    if use_cache:
        cache.save(key, profile)
    record_timing()
    return profile


def execute_compare(
    left_path: Path,
    right_path: Path,
    output_dir: Path,
    config: AnalysisConfig,
    *,
    include_dex: bool = True,
    ensure_tools: bool = True,
    offline: bool = False,
    use_cache: bool = True,
    overwrite: bool = False,
    tool_manager: ToolManager | None = None,
    cache: ProfileCache | None = None,
    progress: bool = False,
    mode: str = "legacy",
    ownership: OwnershipConfig | None = None,
    selection_diagnostics: Mapping[str, object] | None = None,
    _verified_provenance: Mapping[str, VerifiedProvenance] | None = None,
) -> Path:
    left_path = left_path.resolve()
    right_path = right_path.resolve()
    if mode not in {"owned", "heuristic", "legacy"}:
        raise ValueError(f"unsupported comparison mode: {mode}")
    if mode == "owned":
        if ownership is None:
            raise ValueError("owned mode requires an ownership configuration")
        ownership = _with_archive_limits(ownership, config)
        expected = (
            ownership.left.artifact_output.resolve(),
            ownership.right.artifact_output.resolve(),
        )
        if (left_path, right_path) != expected:
            raise ValueError(
                "owned inputs must equal configured artifact_output paths "
                f"(expected {expected[0]} and {expected[1]})"
            )
    if mode == "owned":
        assert ownership is not None
        if _verified_provenance is None:
            for path in (left_path, right_path):
                if not path.is_file():
                    raise FileNotFoundError(path)
            with verified_provenance_snapshot(ownership) as snapshots:
                return execute_compare(
                    left_path,
                    right_path,
                    output_dir,
                    config,
                    include_dex=include_dex,
                    ensure_tools=ensure_tools,
                    offline=offline,
                    use_cache=use_cache,
                    overwrite=overwrite,
                    tool_manager=tool_manager,
                    cache=cache,
                    progress=progress,
                    mode=mode,
                    ownership=ownership,
                    selection_diagnostics=selection_diagnostics,
                    _verified_provenance=snapshots,
                )
        locked_provenance = _verified_provenance
        analysis_left_path = locked_provenance["left"].artifact_path
        analysis_right_path = locked_provenance["right"].artifact_path
    else:
        locked_provenance = {}
        analysis_left_path = left_path
        analysis_right_path = right_path
        for path in (left_path, right_path):
            if not path.is_file():
                raise FileNotFoundError(path)
    manager = tool_manager or ToolManager()
    run_metadata: dict[str, object] = {"mode": mode}
    if ensure_tools:
        statuses = manager.status()
        run_metadata["tools"] = statuses
        missing = [name for name, status in statuses.items() if not status["verified"]]
        if missing and offline:
            raise ToolInstallError(f"offline mode: missing tools: {', '.join(missing)}")
        for name in missing:
            if progress:
                print(f"安装并校验工具：{name}")
            manager.install(name)
        run_metadata["tools"] = manager.status()
    profile_cache = cache or ProfileCache(_profile_cache_root())
    run_metadata["cache_path"] = str(profile_cache.root.resolve())
    left = _load_or_analyze(
        analysis_left_path,
        config,
        include_dex=include_dex,
        use_cache=use_cache,
        cache=profile_cache,
        progress=progress,
        expected_sha256=(
            locked_provenance["left"].artifact_sha256 if mode == "owned" else None
        ),
        run_metadata=run_metadata,
        side="left",
    )
    right = _load_or_analyze(
        analysis_right_path,
        config,
        include_dex=include_dex,
        use_cache=use_cache,
        cache=profile_cache,
        progress=progress,
        expected_sha256=(
            locked_provenance["right"].artifact_sha256 if mode == "owned" else None
        ),
        run_metadata=run_metadata,
        side="right",
    )
    if mode == "owned":
        assert ownership is not None
        if ensure_tools:
            left_inventory, left_inventory_warnings = dump_resource_inventory(
                manager, analysis_left_path, config
            )
            right_inventory, right_inventory_warnings = dump_resource_inventory(
                manager, analysis_right_path, config
            )
        else:
            left_inventory = {}
            right_inventory = {}
            left_inventory_warnings = ["Bundletool 资源清单未运行"]
            right_inventory_warnings = ["Bundletool 资源清单未运行"]
        left_projection = build_owned_projection(
            left,
            ownership.left,
            config,
            verified_resource_inventory=left_inventory,
            verified_provenance=locked_provenance["left"],
        )
        right_projection = build_owned_projection(
            right,
            ownership.right,
            config,
            verified_resource_inventory=right_inventory,
            verified_provenance=locked_provenance["right"],
        )
        left_projection.profile.warnings.extend(left_inventory_warnings)
        right_projection.profile.warnings.extend(right_inventory_warnings)
        left_projection.profile.warnings = sorted(set(left_projection.profile.warnings))
        right_projection.profile.warnings = sorted(set(right_projection.profile.warnings))
        result = compare_owned_profiles(
            left_projection.profile,
            right_projection.profile,
            config,
            left_attribution=left_projection.attribution,
            right_attribution=right_projection.attribution,
            left_resource_confidence=_resource_inventory_confidence(
                left_projection.diagnostics
            ),
            right_resource_confidence=_resource_inventory_confidence(
                right_projection.diagnostics
            ),
        )
        result.diagnostics["projection"] = {
            "left": left_projection.diagnostics,
            "right": right_projection.diagnostics,
        }
        result.diagnostics["resource_inventory"] = {
            "left": {
                "values": len(left_inventory),
                "warnings": sorted(left_inventory_warnings),
            },
            "right": {
                "values": len(right_inventory),
                "warnings": sorted(right_inventory_warnings),
            },
        }
        result.ownership["strategy"] = "strict_provenance"
        result.warnings = sorted(set(result.warnings))
    elif mode == "heuristic":
        if ensure_tools:
            left_details, left_manifest_warnings = decode_manifest_details(
                manager, analysis_left_path, left.modules, config
            )
            right_details, right_manifest_warnings = decode_manifest_details(
                manager, analysis_right_path, right.modules, config
            )
        else:
            left_details = {}
            right_details = {}
            left_manifest_warnings = ["Bundletool Manifest 详情未运行"]
            right_manifest_warnings = ["Bundletool Manifest 详情未运行"]
        left_projection = build_heuristic_projection(
            left,
            config,
            manifest_details=left_details,
        )
        right_projection = build_heuristic_projection(
            right,
            config,
            manifest_details=right_details,
        )
        left_projection.profile.warnings.extend(left_manifest_warnings)
        right_projection.profile.warnings.extend(right_manifest_warnings)
        result = compare_owned_profiles(
            left_projection.profile,
            right_projection.profile,
            config,
            left_attribution=left_projection.attribution,
            right_attribution=right_projection.attribution,
        )
        result.ownership["strategy"] = "heuristic_aab"
        result.diagnostics["projection"] = {
            "left": left_projection.diagnostics,
            "right": right_projection.diagnostics,
        }
        result.diagnostics["resource_inventory"] = {
            "left": {"values": 0, "warnings": ["启发式模式不使用构建资源归属清单"]},
            "right": {"values": 0, "warnings": ["启发式模式不使用构建资源归属清单"]},
        }
        left_confidence = left_projection.diagnostics["dimension_confidence"]
        right_confidence = right_projection.diagnostics["dimension_confidence"]
        assert isinstance(left_confidence, dict)
        assert isinstance(right_confidence, dict)
        for key, dimension in result.dimensions.items():
            dimension.confidence = min(
                dimension.confidence,
                float(left_confidence.get(key, 0.0)),
                float(right_confidence.get(key, 0.0)),
            )
            if dimension.score is not None:
                dimension.warnings.append("该维度使用 AAB 启发式归属，不能证明完整源码归属")
        result.warnings = sorted(
            set(
                result.warnings
                + left_manifest_warnings
                + right_manifest_warnings
                + ["当前结果使用 AAB 启发式归属，公共内容过滤可能存在遗漏"]
            )
        )
    elif ensure_tools:
        for bundle_path, profile in ((left_path, left), (right_path, right)):
            decoded, manifest_warnings = decode_manifests(
                manager, bundle_path, profile.modules, config
            )
            if decoded:
                profile.manifests.update(decoded)
            profile.warnings.extend(manifest_warnings)
    if progress and mode == "legacy":
        print("正在执行八维匹配与评分")
    if mode == "legacy":
        result = compare_profiles(left, right, config)
    if mode in {"owned", "heuristic"}:
        result.diagnostics["selection"] = dict(
            selection_diagnostics
            or {
                "requested_mode": mode,
                "registry_status": "not_provided",
                "message": "execute_compare 直接调用",
            }
        )
    if not ensure_tools or not any(
        result.dimensions[key].findings for key in ("business_code", "long_methods")
    ):
        return render_report(
            result,
            output_dir,
            overwrite=overwrite,
            bundle_paths=(analysis_left_path, analysis_right_path)
            if mode in {"owned", "heuristic"}
            else None,
            run_metadata=run_metadata,
        )
    with tempfile.TemporaryDirectory(prefix="aab-compare-jadx-") as temp_name:
        temp = Path(temp_name)
        if progress:
            print("正在使用 JADX 生成可读源码证据")
        left_diagnostics: list[str] = []
        right_diagnostics: list[str] = []
        left_source, left_warnings = run_jadx(
            manager,
            analysis_left_path,
            temp / "left",
            config,
            diagnostics=left_diagnostics,
        )
        right_source, right_warnings = run_jadx(
            manager,
            analysis_right_path,
            temp / "right",
            config,
            diagnostics=right_diagnostics,
        )
        if left_diagnostics or right_diagnostics:
            run_metadata["jadx_diagnostics"] = {
                "left": left_diagnostics,
                "right": right_diagnostics,
            }
        result.warnings.extend(left_warnings + right_warnings)
        result.warnings = sorted(set(result.warnings))
        return render_report(
            result,
            output_dir,
            overwrite=overwrite,
            source_roots=(left_source, right_source),
            bundle_paths=(analysis_left_path, analysis_right_path)
            if mode in {"owned", "heuristic"}
            else None,
            run_metadata=run_metadata,
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aab-compare", description="AAB 多维度查重分析工具")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    tools_parser = subparsers.add_parser("tools", help="安装或检查外部分析工具")
    tools_parser.add_argument("action", choices=("install", "status"))
    tools_parser.add_argument("--tool-dir", type=Path)

    prepare_parser = subparsers.add_parser("prepare", help="准备并登记严格归属证据")
    prepare_parser.add_argument("ownership_config", type=Path)

    compare_parser = subparsers.add_parser("compare", help="比较两个 AAB")
    compare_parser.add_argument("left", type=Path)
    compare_parser.add_argument("right", type=Path)
    compare_parser.add_argument("-o", "--output", type=Path)
    compare_parser.add_argument("--config", type=Path)
    compare_parser.add_argument(
        "--mode", choices=("auto", "owned", "heuristic", "legacy"), default="auto"
    )
    compare_parser.add_argument("--ownership-config", type=Path)
    compare_parser.add_argument("--prepare-provenance", action="store_true")
    compare_parser.add_argument("--offline", action="store_true")
    compare_parser.add_argument("--jobs", type=int)
    compare_parser.add_argument("--no-cache", action="store_true")
    compare_parser.add_argument("--overwrite", action="store_true")
    compare_parser.add_argument("--cache-dir", type=Path)
    compare_parser.add_argument("--tool-dir", type=Path)
    compare_parser.add_argument("--skip-tools", action="store_true", help=argparse.SUPPRESS)
    compare_parser.add_argument("--skip-dex", action="store_true", help=argparse.SUPPRESS)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    try:
        normalized_argv, direct_entry = _normalized_argv(argv)
        args = parser.parse_args(normalized_argv)
        if args.command == "prepare":
            prepare_ownership = load_ownership_config(args.ownership_config)
            run_prepare_tasks(prepare_ownership)
            lock_path = write_provenance_lock(prepare_ownership)
            record_path = register_provenance_pair(
                args.ownership_config,
                prepare_ownership,
            )
            print(f"provenance lock 已生成：{lock_path}")
            print(f"AAB 对已登记：{record_path}")
            return 0

        manager = ToolManager(args.tool_dir) if args.tool_dir else ToolManager()
        if args.command == "tools":
            if args.action == "install":
                installed = manager.install_all()
                for name, path in installed.items():
                    print(f"{name}: {path}")
            else:
                print(json.dumps(manager.status(), ensure_ascii=False, indent=2, sort_keys=True))
            return 0

        if args.prepare_provenance:
            print(
                "已弃用：请使用 aab-compare prepare CONFIG 后直接比较两个 AAB",
                file=sys.stderr,
            )

        ownership = None
        execution_mode = args.mode
        auto_registered = False
        selection_diagnostics: dict[str, object] = {
            "requested_mode": args.mode,
            "registry_status": "not_provided",
            "message": "未使用 provenance registry",
        }
        if args.ownership_config is not None:
            if args.mode in {"heuristic", "legacy"}:
                print("输入或配置错误：当前模式不接受 --ownership-config", file=sys.stderr)
                return 2
            if not direct_entry:
                print(
                    "已弃用：请先运行 aab-compare prepare CONFIG，随后直接传入两个 AAB",
                    file=sys.stderr,
                )
            ownership = load_ownership_config(args.ownership_config)
            execution_mode = "owned"
            selection_diagnostics.update(
                registry_status="explicit_config",
                message="使用显式 ownership 配置",
            )
        elif args.mode == "owned":
            print("owned 模式必须提供 --ownership-config", file=sys.stderr)
            return 2
        elif args.mode == "auto":
            try:
                lookup = ProvenanceRegistry().lookup(args.left, args.right)
            except ValueError as error:
                lookup = None
                selection_diagnostics.update(
                    registry_status="invalid",
                    message=str(error),
                )
                print(f"provenance registry 不可用，转为启发式分析：{error}", file=sys.stderr)
            if lookup is not None:
                selection_diagnostics.update(
                    registry_status=lookup.status,
                    message=lookup.message,
                )
            if lookup is not None and lookup.status == "matched":
                assert lookup.ownership_config is not None
                try:
                    ownership = load_ownership_config(lookup.ownership_config)
                except (OSError, ValueError) as error:
                    print(f"严格归属证据无效，转为启发式分析：{error}", file=sys.stderr)
                else:
                    execution_mode = "owned"
                    auto_registered = True
            if ownership is None:
                execution_mode = "heuristic"

        if execution_mode == "owned":
            assert ownership is not None
            expected = (
                ownership.left.artifact_output.resolve(),
                ownership.right.artifact_output.resolve(),
            )
            actual = (args.left.resolve(), args.right.resolve())
            if actual != expected:
                if auto_registered:
                    message = "registry 中的 ownership 配置已重绑定其他 artifact"
                    print(f"严格归属证据无效，转为启发式分析：{message}", file=sys.stderr)
                    selection_diagnostics.update(
                        registry_status="stale",
                        message=message,
                    )
                    ownership = None
                    execution_mode = "heuristic"
                    auto_registered = False
                else:
                    print(
                        "输入或配置错误：owned 输入必须等于配置中的 artifact_output",
                        file=sys.stderr,
                    )
                    return 2
            if execution_mode == "owned":
                assert ownership is not None
                if ownership.provenance_lock is None:
                    print(
                        "输入或配置错误：owned 模式必须配置 provenance_lock",
                        file=sys.stderr,
                    )
                    return 2
        elif args.prepare_provenance:
            print("输入或配置错误：--prepare-provenance 仅适用于 owned 模式", file=sys.stderr)
            return 2
        config = load_config(args.config)
        if args.jobs is not None:
            if args.jobs < 1:
                print("--jobs 必须大于 0", file=sys.stderr)
                return 2
            config = replace(config, jobs=args.jobs)
        if ownership is not None:
            ownership = _with_archive_limits(ownership, config)
        output = args.output or default_output_dir(args.left, args.right)
        overwrite = args.overwrite or direct_entry
        validate_output_dir(output, overwrite=overwrite)
        if args.prepare_provenance:
            assert ownership is not None
            run_prepare_tasks(ownership)
            write_provenance_lock(ownership)
        for path in (args.left, args.right):
            if not path.is_file():
                print(f"输入文件不存在：{path}", file=sys.stderr)
                return 2
        cache = ProfileCache(args.cache_dir) if args.cache_dir else None
        try:
            report = execute_compare(
                args.left,
                args.right,
                output,
                config,
                include_dex=not args.skip_dex,
                ensure_tools=not args.skip_tools,
                offline=args.offline,
                use_cache=not args.no_cache,
                overwrite=overwrite,
                tool_manager=manager,
                cache=cache,
                progress=True,
                mode=execution_mode,
                ownership=ownership,
                selection_diagnostics=selection_diagnostics,
            )
        except ValueError as error:
            if not auto_registered:
                raise
            print(f"严格 provenance 校验失败，转为启发式分析：{error}", file=sys.stderr)
            selection_diagnostics.update(
                registry_status="stale",
                message=str(error),
            )
            report = execute_compare(
                args.left,
                args.right,
                output,
                config,
                include_dex=not args.skip_dex,
                ensure_tools=not args.skip_tools,
                offline=args.offline,
                use_cache=not args.no_cache,
                overwrite=overwrite,
                tool_manager=manager,
                cache=cache,
                progress=True,
                mode="heuristic",
                ownership=None,
                selection_diagnostics=selection_diagnostics,
            )
        print(f"报告已生成：{report}")
        if _core_analysis_incomplete(report):
            print("DEX 核心分析不完整，报告不包含确定的综合结论", file=sys.stderr)
            return 4
        return 0
    except (ValueError, FileNotFoundError, ArchiveSecurityError) as error:
        print(f"输入或配置错误：{error}", file=sys.stderr)
        return 2
    except ToolInstallError as error:
        print(f"工具错误：{error}", file=sys.stderr)
        return 3
    except OutputDirectoryError as error:
        print(f"输出错误：{error}", file=sys.stderr)
        return 2
    except Exception as error:
        print(f"分析失败：{error}", file=sys.stderr)
        return 5


if __name__ == "__main__":
    raise SystemExit(main())
