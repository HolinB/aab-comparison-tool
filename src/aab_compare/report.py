from __future__ import annotations

import io
import json
import shutil
import zipfile
from pathlib import Path

from PIL import Image, ImageOps

from .models import ComparisonResult
from .schema import ANALYSIS_JSON_SCHEMA

_MARKER = ".aab-compare-output"
_MARKER_CONTENT = "schema=1\n"
_KNOWN_OUTPUTS = ("report.md", "data", "evidence", "logs")
_DIMENSION_NAMES = {
    "business_code": "业务代码",
    "long_methods": "长方法",
    "manifest": "Manifest",
    "resources": "资源结构",
    "images": "图片",
    "dependencies": "依赖",
    "assets_native": "Assets / Native",
    "build_structure": "构建结构",
    "assets": "Assets",
}

_OWNED_DIMENSION_NAMES = {
    "business_code": "业务代码",
    "long_methods": "长方法",
    "images": "图片",
    "resources": "其他资源",
    "manifest": "Manifest",
    "assets": "Assets",
}


class OutputDirectoryError(ValueError):
    pass


def validate_output_dir(path: Path, *, overwrite: bool = False) -> Path:
    if path.is_symlink():
        raise OutputDirectoryError(f"output directory must not be a symbolic link: {path}")
    path = path.resolve()
    if path.exists() and not path.is_dir():
        raise OutputDirectoryError(f"output path is not a directory: {path}")
    if path.exists():
        entries = list(path.iterdir())
        marker = path / _MARKER
        if marker.is_symlink():
            raise OutputDirectoryError(f"output marker must not be a symbolic link: {marker}")
        marked = marker.is_file()
        if marker.exists() and not marked:
            raise OutputDirectoryError(f"output marker is not a regular file: {marker}")
        if marked:
            try:
                marker_content = marker.read_text(encoding="utf-8")
            except OSError as error:
                raise OutputDirectoryError(f"cannot read output marker: {marker}") from error
            if marker_content != _MARKER_CONTENT:
                raise OutputDirectoryError(f"invalid output marker content: {marker}")
        if entries and not marked:
            raise OutputDirectoryError(f"output directory is not managed by aab-compare: {path}")
        if marked and not overwrite:
            raise OutputDirectoryError(f"output directory already exists: {path}")
        if marked and overwrite:
            for name in _KNOWN_OUTPUTS:
                target = path / name
                if target.is_symlink():
                    raise OutputDirectoryError(
                        f"managed output must not contain symbolic links: {target}"
                    )
    return path


def prepare_output_dir(path: Path, *, overwrite: bool = False) -> Path:
    path = validate_output_dir(path, overwrite=overwrite)
    if path.exists():
        marker = path / _MARKER
        if marker.is_file() and overwrite:
            for name in _KNOWN_OUTPUTS:
                target = path / name
                if target.is_symlink():
                    raise OutputDirectoryError(
                        f"managed output must not contain symbolic links: {target}"
                    )
                if target.is_dir():
                    shutil.rmtree(target)
                else:
                    target.unlink(missing_ok=True)
    else:
        path.mkdir(parents=True)
    (path / _MARKER).write_text(_MARKER_CONTENT, encoding="utf-8")
    for child in ("data", "evidence", "logs"):
        (path / child).mkdir(parents=True, exist_ok=True)
    return path


def _escape(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _source_snippet(root: Path | None, identifier: str) -> str | None:
    if root is None or ";->" not in identifier or not identifier.startswith("L"):
        return None
    class_name, method_part = identifier.split(";->", 1)
    relative_class = class_name[1:].split("$", 1)[0] + ".java"
    source_path = root / "sources" / relative_class
    if not source_path.is_file():
        return None
    try:
        text = source_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    method_name = method_part.split("(", 1)[0]
    lines = text.splitlines()
    matched_line = next(
        (index for index, line in enumerate(lines) if method_name in line),
        0,
    )
    start = max(0, matched_line - 12)
    end = min(len(lines), matched_line + 40)
    return "\n".join(lines[start:end])[:12_000]


def _write_image_pair(
    result: ComparisonResult,
    left_member: str,
    right_member: str,
    destination: Path,
    bundle_paths: tuple[Path, Path] | None = None,
) -> bool:
    left_bundle, right_bundle = bundle_paths or (
        Path(result.left.source_path),
        Path(result.right.source_path),
    )
    try:
        with (
            zipfile.ZipFile(left_bundle) as left_archive,
            zipfile.ZipFile(right_bundle) as right_archive,
        ):
            left_data = left_archive.read(left_member)
            right_data = right_archive.read(right_member)
        images: list[Image.Image] = []
        for data in (left_data, right_data):
            with Image.open(io.BytesIO(data)) as raw:
                image = ImageOps.exif_transpose(raw).convert("RGBA")
                background = Image.new("RGBA", image.size, "white")
                background.alpha_composite(image)
                background.thumbnail((360, 300))
                images.append(background.convert("RGB"))
        gap = 20
        canvas = Image.new(
            "RGB",
            (images[0].width + gap + images[1].width, max(image.height for image in images)),
            "white",
        )
        canvas.paste(images[0], (0, 0))
        canvas.paste(images[1], (images[0].width + gap, 0))
        canvas.save(destination, "PNG", optimize=True)
        return True
    except (OSError, KeyError, ValueError):
        return False


def _write_evidence(
    result: ComparisonResult,
    output: Path,
    source_roots: tuple[Path | None, Path | None] | None,
    bundle_paths: tuple[Path, Path] | None,
) -> None:
    evidence_root = output / "evidence"
    source_limit = int(result.config_snapshot.get("max_source_evidence", 20))
    for key, dimension in result.dimensions.items():
        dimension_dir = evidence_root / key
        dimension_dir.mkdir(parents=True, exist_ok=True)
        for index, finding in enumerate(dimension.findings, start=1):
            evidence_path = dimension_dir / f"{index:03d}.txt"
            lines = [
                finding.title,
                f"similarity={finding.similarity:.2f}",
                f"left={finding.left}",
                f"right={finding.right}",
                "details=" + json.dumps(finding.details, ensure_ascii=False, sort_keys=True),
            ]
            if source_roots and index <= source_limit and key in {"business_code", "long_methods"}:
                left_source = _source_snippet(source_roots[0], finding.left)
                right_source = _source_snippet(source_roots[1], finding.right)
                if left_source:
                    lines.extend(["", "===== SOURCE A (JADX) =====", left_source])
                if right_source:
                    lines.extend(["", "===== SOURCE B (JADX) =====", right_source])
            evidence_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            if key == "images":
                image_path = dimension_dir / f"{index:03d}.png"
                if _write_image_pair(
                    result,
                    finding.left,
                    finding.right,
                    image_path,
                    bundle_paths,
                ):
                    finding.evidence_path = image_path.relative_to(output).as_posix()
                    continue
            finding.evidence_path = evidence_path.relative_to(output).as_posix()


def _score_text(result: ComparisonResult) -> str:
    aggregate = result.aggregate
    if aggregate is None:
        return "N/A"
    if aggregate.score is not None:
        return f"{aggregate.score:.2f} / 100（{aggregate.level}）"
    return f"不可确定，已证实区间 {aggregate.minimum_score:.2f}–{aggregate.maximum_score:.2f}"


def _signature_entries(result: ComparisonResult, side: str) -> list[str]:
    profile = result.left if side == "left" else result.right
    suffixes = (".RSA", ".DSA", ".EC", ".SF")
    return sorted(
        value.removeprefix("entry:")
        for value in profile.build_features
        if value.startswith("entry:META-INF/") and value.upper().endswith(suffixes)
    )


def _difference_summary(result: ComparisonResult) -> list[str]:
    differences: list[str] = []
    if result.left.agp_version != result.right.agp_version:
        differences.append(
            f"- AGP 版本：`{_escape(result.left.agp_version or '未知')}` → "
            f"`{_escape(result.right.agp_version or '未知')}`。"
        )
    left_signatures = _signature_entries(result, "left")
    right_signatures = _signature_entries(result, "right")
    if left_signatures != right_signatures:
        differences.append(
            "- 签名条目发生变化：A 为 "
            f"`{_escape(', '.join(left_signatures) or '无')}`，B 为 "
            f"`{_escape(', '.join(right_signatures) or '无')}`。"
        )
    right_hardening = [
        value for value in result.right.build_features if value.startswith("hardening:")
    ]
    if right_hardening:
        differences.append("- 检测到 B 侧加固元数据，A 侧未检测到同类标记。")
        original_sha = next(
            (
                value.rsplit(":", 1)[-1]
                for value in right_hardening
                if "originalaabsha256" in value.lower()
            ),
            None,
        )
        if original_sha:
            relation = "一致" if original_sha == result.left.sha256 else "不一致"
            differences.append(
                f"- 加固元数据记录的原始 AAB SHA-256 为 `{original_sha}`，与 A 输入哈希{relation}。"
            )
    resource_dimension = result.dimensions.get("resources")
    renamed_resources = int(
        resource_dimension.metrics.get("renamed_matches", 0) if resource_dimension else 0
    )
    if renamed_resources:
        differences.append(f"- 资源内容相同但路径变化：{renamed_resources} 项。")
    left_dex_bytes = result.left.counts.get("dex_bytes")
    right_dex_bytes = result.right.counts.get("dex_bytes")
    if (
        left_dex_bytes is not None
        and right_dex_bytes is not None
        and left_dex_bytes != right_dex_bytes
    ):
        differences.append(f"- DEX 总字节数：{left_dex_bytes} → {right_dex_bytes}。")
    if result.left.counts.get("methods") != result.right.counts.get("methods"):
        differences.append(
            "- 业务候选方法数："
            f"{result.left.counts.get('methods', 0)} → {result.right.counts.get('methods', 0)}。"
        )
    return differences or ["- 未发现需要单列的构建或结构差异。"]


def _markdown(result: ComparisonResult) -> str:
    if result.mode == "owned":
        return _owned_markdown(result)
    if result.aggregate is None:
        raise ValueError("legacy result requires an aggregate score")
    left_modules = _escape(", ".join(result.left.modules))
    right_modules = _escape(", ".join(result.right.modules))
    left_agp = _escape(result.left.agp_version or "未知")
    right_agp = _escape(result.right.agp_version or "未知")
    lines = [
        "# AAB 多维度查重报告",
        "",
        "## 总体结论",
        "",
        f"- 综合相似度：{_score_text(result)}",
        f"- 已分析权重：{result.aggregate.analyzed_weight}%",
        "- 说明：该结果为启发式技术分析，不能替代人工或法律鉴定。",
        "",
        "## 输入信息",
        "",
        "| 项目 | AAB A | AAB B |",
        "|---|---:|---:|",
        f"| 文件 | `{_escape(result.left.source_path)}` | `{_escape(result.right.source_path)}` |",
        f"| SHA-256 | `{result.left.sha256}` | `{result.right.sha256}` |",
        f"| 大小 | {result.left.size} | {result.right.size} |",
        f"| 模块 | {left_modules} | {right_modules} |",
        f"| DEX | {result.left.counts.get('dex', 0)} | {result.right.counts.get('dex', 0)} |",
        "| Native | "
        f"{result.left.counts.get('native', 0)} | {result.right.counts.get('native', 0)} |",
        "| Assets | "
        f"{result.left.counts.get('assets', 0)} | {result.right.counts.get('assets', 0)} |",
        "| 资源条目 | "
        f"{result.left.counts.get('resources', 0)} | "
        f"{result.right.counts.get('resources', 0)} |",
        "| 业务候选方法 | "
        f"{result.left.counts.get('methods', 0)} | {result.right.counts.get('methods', 0)} |",
        "| 长方法 | "
        f"{result.left.counts.get('long_methods', 0)} | "
        f"{result.right.counts.get('long_methods', 0)} |",
        f"| AGP | {left_agp} | {right_agp} |",
        "",
        "## 关键差异",
        "",
        *_difference_summary(result),
        "",
        "## 八维评分",
        "",
        "| 维度 | 权重 | 相似度 | A 被 B 覆盖 | B 被 A 覆盖 | 置信度 | 匹配证据 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    weights = result.config_snapshot.get("weights", {})
    for key, dimension in result.dimensions.items():
        score = "N/A" if dimension.score is None else f"{dimension.score:.2f}"
        lines.append(
            f"| {_DIMENSION_NAMES[key]} | {weights.get(key, 0)}% | {score} | "
            f"{dimension.left_coverage * 100:.2f}% | {dimension.right_coverage * 100:.2f}% | "
            f"{dimension.confidence * 100:.2f}% | "
            f"{len(dimension.findings)} |"
        )
    for key, dimension in result.dimensions.items():
        lines.extend(["", f"## {_DIMENSION_NAMES[key]}证据", ""])
        if not dimension.findings:
            lines.append("无可展示的匹配证据。")
        else:
            lines.extend(["| 相似度 | A | B | 详情 |", "|---:|---|---|---|"])
            for finding in dimension.findings:
                link = f"[证据]({finding.evidence_path})" if finding.evidence_path else "-"
                lines.append(
                    f"| {finding.similarity:.2f} | `{_escape(finding.left)}` | "
                    f"`{_escape(finding.right)}` | {link} |"
                )
        if dimension.warnings:
            lines.extend(["", "告警："] + [f"- {_escape(value)}" for value in dimension.warnings])
    lines.extend(["", "## 分析告警", ""])
    if result.warnings:
        lines.extend(f"- {_escape(value)}" for value in result.warnings)
    else:
        lines.append("无。")
    lines.extend(
        [
            "",
            "## 方法说明",
            "",
            "- 代码评分忽略混淆后的类名、方法名和寄存器号，"
            "主要比较操作码、控制流、API 调用和常量类别。",
            "- 第三方依赖与业务代码分开计分，无法确认的依赖会保留为推测项。",
            "- 缺失维度不会重新分配权重，而是展示综合分可能区间。",
            "",
        ]
    )
    return "\n".join(lines)


def _owned_markdown(result: ComparisonResult) -> str:
    strategy = result.ownership.get("strategy", "strict_provenance")
    heuristic = strategy == "heuristic_aab"
    lines = [
        "# AAB 启发式自有内容对比报告"
        if heuristic
        else "# AAB 严格自有代码与资源范围对比报告",
        "",
        "- 分析依据：AAB 启发式归属；该结果不能证明完整源码归属。"
        if heuristic
        else "- 分析依据：严格 provenance，所有评分内容均通过构建归属证据验证。",
        "",
        "## 六项独立结果",
        "",
        "| 维度 | 相似度 | A 被 B 覆盖 | B 被 A 覆盖 | 置信度 | "
        + (
            "A 启发式候选 | B 启发式候选 | Top 证据 |"
            if heuristic
            else "A 源码 / 生成 | B 源码 / 生成 | Top 证据 |"
        ),
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for key in _OWNED_DIMENSION_NAMES:
        dimension = result.dimensions[key]
        score = "N/A" if dimension.score is None else f"{dimension.score:.2f}"
        left_origins = dimension.metrics.get("left_origins", {})
        right_origins = dimension.metrics.get("right_origins", {})
        if not isinstance(left_origins, dict):
            left_origins = {}
        if not isinstance(right_origins, dict):
            right_origins = {}
        if heuristic:
            left_contribution = str(left_origins.get("HEURISTIC_OWNED", 0))
            right_contribution = str(right_origins.get("HEURISTIC_OWNED", 0))
        else:
            left_contribution = (
                f"{left_origins.get('OWNED_SOURCE', 0)} / "
                f"{left_origins.get('OWNED_GENERATED', 0)}"
            )
            right_contribution = (
                f"{right_origins.get('OWNED_SOURCE', 0)} / "
                f"{right_origins.get('OWNED_GENERATED', 0)}"
            )
        lines.append(
            f"| {_OWNED_DIMENSION_NAMES[key]} | {score} | "
            f"{dimension.left_coverage * 100:.2f}% | "
            f"{dimension.right_coverage * 100:.2f}% | "
            f"{dimension.confidence * 100:.2f}% | {left_contribution} | "
            f"{right_contribution} | {len(dimension.findings)} |"
        )

    lines.extend(
        [
            "",
            "## 所有权归因",
            "",
            "| 归因 | AAB A | AAB B |",
            "|---|---:|---:|",
        ]
    )
    attribution_names = {
        "owned_source": "来源代码",
        "owned_generated": "自有生成",
        "heuristic_owned": "启发式候选",
        "unresolved": "未解析",
        "public_dependency": "公共依赖",
        "tool_generated": "工具生成",
    }
    for key, name in attribution_names.items():
        lines.append(
            f"| {name} | {result.ownership.get('left', {}).get(key, 0)} | "
            f"{result.ownership.get('right', {}).get(key, 0)} |"
        )

    lines.extend(["", "## 诊断", ""])
    if result.diagnostics:
        lines.extend(
            [
                "```json",
                json.dumps(result.diagnostics, ensure_ascii=False, indent=2, sort_keys=True),
                "```",
            ]
        )
    else:
        lines.append("无。")

    for key in _OWNED_DIMENSION_NAMES:
        dimension = result.dimensions[key]
        lines.extend(["", f"## {_OWNED_DIMENSION_NAMES[key]} Top 证据", ""])
        if dimension.findings:
            lines.extend(["| 相似度 | A | B | 详情 |", "|---:|---|---|---|"])
            for finding in dimension.findings:
                link = f"[证据]({finding.evidence_path})" if finding.evidence_path else "-"
                lines.append(
                    f"| {finding.similarity:.2f} | `{_escape(finding.left)}` | "
                    f"`{_escape(finding.right)}` | {link} |"
                )
        else:
            lines.append("无可展示的匹配证据。")
        if dimension.warnings:
            lines.extend(["", "告警："])
            lines.extend(f"- {_escape(value)}" for value in sorted(set(dimension.warnings)))

    lines.extend(["", "## 分析告警", ""])
    if result.warnings:
        lines.extend(f"- {_escape(value)}" for value in sorted(set(result.warnings)))
    else:
        lines.append("无。")
    lines.extend(["", "## 方法说明", "", "- 六项结果彼此独立；没有输入时显示 N/A。"])
    if heuristic:
        lines.extend(
            [
                "- 公共依赖通过包前缀、依赖元数据及资源路径启发式过滤，可能存在遗漏。",
                "- Manifest、资源和 Assets 的归属置信度低于严格 provenance 模式。",
            ]
        )
    else:
        lines.append(
            "- Manifest 仅采用项目来源与显式自有生成来源，不采用完整反编译清单计分。"
        )
    lines.extend(["- DEX 指纹评分独立于 JADX；JADX 仅用于生成可读证据。", ""])
    return "\n".join(lines)


def render_report(
    result: ComparisonResult,
    output_dir: Path,
    *,
    overwrite: bool = False,
    source_roots: tuple[Path | None, Path | None] | None = None,
    bundle_paths: tuple[Path, Path] | None = None,
    run_metadata: dict[str, object] | None = None,
) -> Path:
    output = prepare_output_dir(output_dir, overwrite=overwrite)
    _write_evidence(result, output, source_roots, bundle_paths)
    (output / "data" / "analysis.json").write_text(result.to_json(), encoding="utf-8")
    (output / "data" / "schema.json").write_text(
        json.dumps(ANALYSIS_JSON_SCHEMA, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output / "logs" / "run.json").write_text(
        json.dumps(run_metadata or {}, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    report_path = output / "report.md"
    report_path.write_text(_markdown(result), encoding="utf-8")
    return report_path
