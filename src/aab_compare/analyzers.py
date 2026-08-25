from __future__ import annotations

import hashlib
import io
import json
import re
import time
import warnings
import zipfile
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from dataclasses import asdict
from pathlib import Path
from typing import TypeVar

import imagehash
from datasketch import MinHash, MinHashLSH  # type: ignore[import-untyped]
from PIL import Image, ImageOps

from .archive import inspect_aab
from .config import AnalysisConfig
from .dex import extract_methods_from_dex
from .models import (
    BundleProfile,
    ComparisonResult,
    DimensionResult,
    FileFingerprint,
    Finding,
    ImageFingerprint,
    ManifestFingerprint,
    MethodFingerprint,
)
from .ownership import AttributionSummary
from .scoring import aggregate_dimensions

_PRINTABLE = re.compile(rb"[A-Za-z0-9_.$:/@+()<>?=-]{3,}")
_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"}
_T = TypeVar("_T")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _as_text(value: str | bytes) -> str:
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else value


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _printable_features(data: bytes) -> list[str]:
    return sorted({value.decode("utf-8", "ignore") for value in _PRINTABLE.findall(data)})


def _semantic_hash(features: list[str], fallback: bytes) -> str:
    if not features:
        return _sha256(fallback)
    normalized = [
        feature for feature in features if not re.fullmatch(r"(?:0x)?[0-9a-fA-F]{6,}", feature)
    ]
    return _sha256("\n".join(normalized).encode("utf-8"))


def _chunk_features(data: bytes, chunk_size: int = 4096) -> list[str]:
    return [
        hashlib.sha1(data[offset : offset + chunk_size]).hexdigest()[:16]
        for offset in range(0, len(data), chunk_size)
    ]


def _category(path: str) -> str | None:
    parts = path.split("/")
    suffix = Path(path).suffix.lower()
    if len(parts) >= 3 and parts[1] == "res":
        return "image" if suffix in _IMAGE_EXTENSIONS else "resource"
    if len(parts) >= 3 and parts[1] == "assets":
        return "asset"
    if len(parts) >= 4 and parts[1] == "lib" and suffix == ".so":
        return "native"
    if path == "BundleConfig.pb" or path.startswith(("BUNDLE-METADATA/", "META-INF/")):
        return "build"
    return None


def _module(path: str) -> str:
    first = path.split("/", 1)[0]
    return first if first not in {"BundleConfig.pb", "BUNDLE-METADATA", "META-INF"} else "bundle"


def _image_fingerprint(path: str, module: str, data: bytes) -> ImageFingerprint:
    perceptual: str | None
    width: int | None
    height: int | None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with Image.open(io.BytesIO(data)) as raw:
                image = ImageOps.exif_transpose(raw).convert("RGBA").convert("RGB")
                perceptual = str(imagehash.phash(image))
                width, height = image.size
    except Exception:
        perceptual = None
        width = height = None
    return ImageFingerprint(path, module, len(data), _sha256(data), perceptual, width, height)


def _manifest_features(data: bytes) -> list[str]:
    features = _printable_features(data)
    return sorted(
        {
            feature
            for feature in features
            if any(
                marker in feature
                for marker in (
                    "manifest",
                    "permission",
                    "activity",
                    "service",
                    "receiver",
                    "provider",
                    "intent",
                    "feature",
                    "application",
                    "android.",
                    "com.",
                )
            )
        }
    )


def _dependency_features(data: bytes) -> list[str]:
    values = [
        value.decode("utf-8", "ignore").strip() for value in re.findall(rb"[\x20-\x7e]{3,}", data)
    ]
    group_pattern = re.compile(r"[A-Za-z][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]+)+")
    artifact_pattern = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
    version_pattern = re.compile(r"\d+(?:\.[0-9A-Za-z]+)+(?:[-+][0-9A-Za-z_.-]+)?")
    result: set[str] = set()
    for index, group in enumerate(values[:-1]):
        if group_pattern.fullmatch(group) is None:
            continue
        artifact_match = artifact_pattern.match(values[index + 1])
        if artifact_match is None:
            continue
        artifact = artifact_match.group(0)
        version_match = version_pattern.search(values[index + 1][artifact_match.end() :])
        if version_match is None and index + 2 < len(values):
            version_match = version_pattern.search(values[index + 2])
        if version_match:
            result.add(f"{group}:{artifact}:{version_match.group(0)}")
    return sorted(result)


def _native_features(data: bytes) -> list[str]:
    features = {"elf"} if data.startswith(b"\x7fELF") else {"binary"}
    features.update(value for value in _printable_features(data) if ".so" in value)
    features.update(f"chunk:{value}" for value in _chunk_features(data))
    if data.startswith(b"\x7fELF"):
        try:
            import lief

            lief.logging.disable()
            binary = lief.parse(list(data))
            if isinstance(binary, lief.ELF.Binary):
                features.add(f"arch:{binary.header.machine_type}")
                features.update(f"needed:{_as_text(library)}" for library in binary.libraries)
                features.update(f"export:{name}" for name in binary.exported_functions)
                features.update(f"import:{name}" for name in binary.imported_functions)
                text_section = binary.get_section(".text")
                if text_section is not None:
                    text_bytes = bytes(text_section.content)
                    features.add(f"text:{hashlib.sha256(text_bytes).hexdigest()}")
        except Exception:
            pass
    return sorted(features)


def classify_methods(profile: BundleProfile) -> None:
    dependency_prefixes = tuple(
        "L" + dependency.split(":", 1)[0].replace(".", "/") + "/"
        for dependency in profile.dependencies
        if ":" in dependency and "." in dependency.split(":", 1)[0]
    )
    generated_pattern = re.compile(
        r"(?:/R(?:\$[^;]+)?|/BR|/BuildConfig);$|/databinding/[^;]*Binding;$"
    )
    for method in profile.methods:
        if method.class_name.startswith(dependency_prefixes) or generated_pattern.search(
            method.class_name
        ):
            method.third_party = True


def analyze_bundle(
    path: Path,
    config: AnalysisConfig,
    *,
    include_dex: bool = True,
    progress: Callable[[str], None] | None = None,
) -> BundleProfile:
    started = time.monotonic()
    inventory = inspect_aab(path, config.archive_limits)
    profile = BundleProfile(
        source_path=str(inventory.path),
        sha256=_file_sha256(inventory.path),
        size=inventory.path.stat().st_size,
        modules=inventory.modules,
        counts=dict(inventory.counts),
    )
    image_count = 0
    dependency_values: set[str] = set()
    build_features: set[str] = {f"module:{module}" for module in inventory.modules}
    if progress:
        progress(f"正在读取 {inventory.path.name} 的 {len(inventory.entries)} 个条目")
    with zipfile.ZipFile(inventory.path) as archive:
        for entry in inventory.entries:
            path_name = entry.path
            if path_name.endswith("/"):
                continue
            if path_name.endswith("/manifest/AndroidManifest.xml"):
                module = path_name.split("/", 1)[0]
                profile.manifests[module] = _manifest_features(archive.read(path_name))
                continue
            if path_name.endswith(".dex") and "/dex/" in path_name:
                dex_data = archive.read(path_name)
                profile.counts["dex_bytes"] = profile.counts.get("dex_bytes", 0) + len(dex_data)
                build_features.add(f"dex-size:{path_name}:{len(dex_data)}")
                if include_dex:
                    try:
                        profile.methods.extend(
                            extract_methods_from_dex(
                                dex_data,
                                path_name,
                                third_party_prefixes=config.third_party_prefixes,
                                business_prefixes=config.business_prefixes,
                                minimum_instructions=config.min_method_instructions,
                                include_third_party=True,
                            )
                        )
                    except Exception as error:
                        profile.warnings.append(f"DEX 解析失败 {path_name}: {error}")
                continue
            category = _category(path_name)
            if category is None:
                continue
            data = archive.read(path_name)
            features = _printable_features(data)
            if category == "build":
                features = features[:200]
            if category in {"asset", "native"}:
                features = _native_features(data) if category == "native" else _chunk_features(data)
            fingerprint = FileFingerprint(
                path=path_name,
                module=_module(path_name),
                category=category,
                size=len(data),
                sha256=_sha256(data),
                semantic_hash=_semantic_hash(features, data),
                features=features,
            )
            profile.files.append(fingerprint)
            if category == "image":
                profile.images.append(_image_fingerprint(path_name, fingerprint.module, data))
                image_count += 1
            if path_name.endswith("app-metadata.properties"):
                match = re.search(rb"androidGradlePluginVersion=([^\r\n]+)", data)
                if match:
                    profile.agp_version = match.group(1).decode("utf-8", "replace")
            if path_name.endswith("dependencies.pb"):
                dependency_values.update(_dependency_features(data))
            if category == "build":
                build_features.add(f"entry:{path_name}")
                if "hardening" in path_name.lower():
                    build_features.add("hardening:present")
                    try:
                        metadata = json.loads(data)
                        if isinstance(metadata, dict):
                            for key, value in metadata.items():
                                if "sha256" in str(key).lower() and re.fullmatch(
                                    r"[0-9a-fA-F]{64}", str(value)
                                ):
                                    build_features.add(f"hardening:{key}:{str(value).lower()}")
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        pass
    dependency_values.update(
        prefix.removeprefix("L").removesuffix("/").replace("/", ".")
        for prefix in config.third_party_prefixes
        if any(method.class_name.startswith(prefix) for method in profile.methods)
    )
    profile.dependencies = sorted(dependency_values)
    classify_methods(profile)
    profile.counts["candidate_methods"] = len(profile.methods)
    profile.counts["methods"] = sum(not method.third_party for method in profile.methods)
    profile.counts["business_methods"] = profile.counts["methods"]
    profile.counts["all_long_methods"] = sum(
        method.instruction_count >= config.long_method_min_instructions
        for method in profile.methods
    )
    profile.counts["images"] = image_count
    profile.counts["long_methods"] = sum(
        not method.third_party and method.instruction_count >= config.long_method_min_instructions
        for method in profile.methods
    )
    if profile.agp_version:
        build_features.add(f"agp:{profile.agp_version}")
    for key in ("dex", "native", "assets", "resources", "manifests"):
        build_features.add(f"count:{key}:{profile.counts.get(key, 0)}")
    profile.build_features = sorted(build_features)
    profile.files.sort(key=lambda item: item.path)
    profile.methods.sort(key=lambda item: item.identifier)
    profile.images.sort(key=lambda item: item.path)
    profile.duration_seconds = round(time.monotonic() - started, 3)
    return profile


def _set_score(left: set[str], right: set[str]) -> tuple[float | None, float, float, set[str]]:
    if not left and not right:
        return 100.0, 1.0, 1.0, set()
    if not left or not right:
        return 0.0, 0.0 if left else 1.0, 0.0 if right else 1.0, set()
    common = left & right
    return (
        round(200 * len(common) / (len(left) + len(right)), 2),
        len(common) / len(left),
        len(common) / len(right),
        common,
    )


def _jaccard(left: set[str], right: set[str]) -> float:
    if not left and not right:
        return 1.0
    union = left | right
    return len(left & right) / len(union) if union else 1.0


def _shingles(values: list[str], width: int = 5) -> set[str]:
    if len(values) < width:
        return {"\x1f".join(values)} if values else set()
    return {"\x1f".join(values[index : index + width]) for index in range(len(values) - width + 1)}


def _method_similarity(left: MethodFingerprint, right: MethodFingerprint) -> float:
    opcode = _jaccard(_shingles(left.opcode_tokens), _shingles(right.opcode_tokens))
    blocks = _jaccard(set(left.block_signature), set(right.block_signature))
    apis = _jaccard(_shingles(left.api_calls, 2), _shingles(right.api_calls, 2))
    constants = _jaccard(set(left.constants), set(right.constants))
    return 0.45 * opcode + 0.25 * blocks + 0.20 * apis + 0.10 * constants


def _method_minhash(method: MethodFingerprint, permutations: int) -> MinHash:
    signature = MinHash(num_perm=permutations, seed=1)
    for shingle in sorted(_shingles(method.opcode_tokens)):
        signature.update(shingle.encode("utf-8"))
    return signature


def _match_methods(
    left: list[MethodFingerprint],
    right: list[MethodFingerprint],
    config: AnalysisConfig,
) -> DimensionResult:
    if not left or not right:
        if not left and not right:
            return DimensionResult("business_code", None, 0.0, 0.0, warnings=["没有可比较的方法"])
        return DimensionResult("business_code", 0.0, 0.0, 0.0)
    right_by_hash: dict[str, list[int]] = defaultdict(list)
    for index, method in enumerate(right):
        right_by_hash[method.canonical_hash].append(index)
    matched_right: set[int] = set()
    matches: list[tuple[float, MethodFingerprint, MethodFingerprint]] = []
    unmatched_left: list[MethodFingerprint] = []
    for method in left:
        candidates = right_by_hash.get(method.canonical_hash, [])
        available = [index for index in candidates if index not in matched_right]
        if available:
            index = min(
                available,
                key=lambda value: abs(right[value].instruction_count - method.instruction_count),
            )
            matched_right.add(index)
            matches.append((1.0, method, right[index]))
        else:
            unmatched_left.append(method)

    inverted: dict[str, set[int]] = defaultdict(set)
    lsh = MinHashLSH(
        threshold=config.lsh_threshold,
        num_perm=config.minhash_permutations,
    )
    for index, method in enumerate(right):
        if index in matched_right:
            continue
        for shingle in _shingles(method.opcode_tokens):
            inverted[shingle].add(index)
        signature = _method_minhash(method, config.minhash_permutations)
        lsh.insert(str(index), signature)
    for left_method in sorted(unmatched_left, key=lambda item: -item.instruction_count):
        candidate_counts: Counter[int] = Counter()
        for shingle in _shingles(left_method.opcode_tokens):
            indexes = inverted.get(shingle, set())
            if len(indexes) <= 200:
                candidate_counts.update(indexes)
        signature = _method_minhash(left_method, config.minhash_permutations)
        lsh_candidates = {
            int(index) for index in lsh.query(signature) if int(index) not in matched_right
        }
        candidate_order = sorted(
            lsh_candidates,
            key=lambda index: (-candidate_counts[index], index),
        )
        if not candidate_order:
            candidate_order = sorted(
                (index for index in candidate_counts if index not in matched_right),
                key=lambda index: (-candidate_counts[index], index),
            )
        best: tuple[float, int] | None = None
        for index in candidate_order[:30]:
            if index in matched_right:
                continue
            similarity = _method_similarity(left_method, right[index])
            if similarity >= config.min_method_similarity and (
                best is None or similarity > best[0]
            ):
                best = similarity, index
        if best:
            similarity, index = best
            matched_right.add(index)
            matches.append((similarity, left_method, right[index]))

    matched_mass = sum(
        min(left_method.instruction_count, right_method.instruction_count) * similarity
        for similarity, left_method, right_method in matches
    )
    left_mass = sum(method.instruction_count for method in left)
    right_mass = sum(method.instruction_count for method in right)
    score = 200 * matched_mass / (left_mass + right_mass) if left_mass + right_mass else 0.0
    findings = [
        Finding(
            title="方法实现匹配",
            similarity=round(similarity * 100, 2),
            left=left_method.identifier,
            right=right_method.identifier,
            details={
                "left_instructions": left_method.instruction_count,
                "right_instructions": right_method.instruction_count,
                "left_dex": left_method.dex_path,
                "right_dex": right_method.dex_path,
                "left_origin": left_method.origin,
                "right_origin": right_method.origin,
                "left_source_path": left_method.source_path,
                "right_source_path": right_method.source_path,
            },
        )
        for similarity, left_method, right_method in sorted(
            matches,
            key=lambda item: (
                -item[0] * min(item[1].instruction_count, item[2].instruction_count),
                item[1].identifier,
            ),
        )[: config.max_findings_per_dimension]
    ]
    return DimensionResult(
        "business_code",
        round(min(score, 100.0), 2),
        min(matched_mass / left_mass, 1.0) if left_mass else 0.0,
        min(matched_mass / right_mass, 1.0) if right_mass else 0.0,
        findings=findings,
        metrics={
            "left_methods": len(left),
            "right_methods": len(right),
            "matched_methods": len(matches),
            "matched_instruction_mass": round(matched_mass, 2),
        },
    )


def _compare_files(
    key: str,
    left: list[FileFingerprint],
    right: list[FileFingerprint],
    config: AnalysisConfig,
) -> DimensionResult:
    right_index: dict[str, list[FileFingerprint]] = defaultdict(list)
    for item in right:
        right_index[item.sha256].append(item)
        if item.semantic_hash:
            right_index[f"semantic:{item.semantic_hash}"].append(item)
    used: set[str] = set()
    matches: list[tuple[FileFingerprint, FileFingerprint]] = []
    for left_item in left:
        candidates = right_index.get(left_item.sha256, [])
        if not candidates and left_item.semantic_hash:
            candidates = right_index.get(f"semantic:{left_item.semantic_hash}", [])
        candidate = next((item for item in candidates if item.path not in used), None)
        if candidate:
            used.add(candidate.path)
            matches.append((left_item, candidate))
    matched_mass = sum(min(left_item.size, right_item.size) for left_item, right_item in matches)
    left_mass = sum(item.size for item in left)
    right_mass = sum(item.size for item in right)
    if not left and not right:
        score = 100.0
        left_coverage = right_coverage = 1.0
    else:
        score = 200 * matched_mass / (left_mass + right_mass) if left_mass + right_mass else 0.0
        left_coverage = matched_mass / left_mass if left_mass else 1.0
        right_coverage = matched_mass / right_mass if right_mass else 1.0
    findings = [
        Finding(
            "文件内容匹配",
            100.0,
            left_item.path,
            right_item.path,
            {
                "bytes": min(left_item.size, right_item.size),
                "left_origin": left_item.origin,
                "right_origin": right_item.origin,
                "left_source_path": left_item.source_path,
                "right_source_path": right_item.source_path,
            },
        )
        for left_item, right_item in sorted(
            matches, key=lambda pair: -min(pair[0].size, pair[1].size)
        )[: config.max_findings_per_dimension]
    ]
    return DimensionResult(
        key,
        round(min(score, 100.0), 2),
        min(left_coverage, 1.0),
        min(right_coverage, 1.0),
        findings=findings,
        metrics={
            "left_files": len(left),
            "right_files": len(right),
            "matched_files": len(matches),
            "renamed_matches": sum(a.path != b.path for a, b in matches),
        },
    )


def _phash_distance(left: str, right: str) -> int:
    return (int(left, 16) ^ int(right, 16)).bit_count()


def _compare_images(
    left: list[ImageFingerprint], right: list[ImageFingerprint], config: AnalysisConfig
) -> DimensionResult:
    used: set[int] = set()
    matches: list[tuple[float, ImageFingerprint, ImageFingerprint]] = []
    for left_image in left:
        best: tuple[float, int] | None = None
        for index, right_image in enumerate(right):
            if index in used:
                continue
            if left_image.sha256 == right_image.sha256:
                similarity = 1.0
            elif left_image.perceptual_hash and right_image.perceptual_hash:
                similarity = (
                    1.0
                    - _phash_distance(left_image.perceptual_hash, right_image.perceptual_hash) / 64
                )
            else:
                continue
            if similarity >= 0.84 and (best is None or similarity > best[0]):
                best = similarity, index
        if best:
            similarity, index = best
            used.add(index)
            matches.append((similarity, left_image, right[index]))
    matched_mass = sum(min(a.size, b.size) * similarity for similarity, a, b in matches)
    left_mass = sum(item.size for item in left)
    right_mass = sum(item.size for item in right)
    score = (
        100.0
        if not left and not right
        else (200 * matched_mass / (left_mass + right_mass) if left_mass + right_mass else 0.0)
    )
    findings = [
        Finding(
            "图片视觉匹配",
            round(similarity * 100, 2),
            a.path,
            b.path,
            {
                "left_size": [a.width, a.height],
                "right_size": [b.width, b.height],
                "left_origin": a.origin,
                "right_origin": b.origin,
                "left_source_path": a.source_path,
                "right_source_path": b.source_path,
            },
        )
        for similarity, a, b in sorted(matches, key=lambda item: -item[0])[
            : config.max_findings_per_dimension
        ]
    ]
    return DimensionResult(
        "images",
        round(min(score, 100.0), 2),
        min(matched_mass / left_mass, 1.0) if left_mass else 1.0,
        min(matched_mass / right_mass, 1.0) if right_mass else 1.0,
        findings,
        metrics={
            "left_images": len(left),
            "right_images": len(right),
            "matched_images": len(matches),
            "renamed_matches": sum(a.path != b.path for _, a, b in matches),
        },
    )


def _simple_set_dimension(
    key: str, left_values: list[str], right_values: list[str], title: str, limit: int
) -> DimensionResult:
    score, left_coverage, right_coverage, common = _set_score(set(left_values), set(right_values))
    findings = [Finding(title, 100.0, value, value) for value in sorted(common)[:limit]]
    return DimensionResult(
        key,
        score,
        left_coverage,
        right_coverage,
        findings,
        metrics={
            "left_items": len(set(left_values)),
            "right_items": len(set(right_values)),
            "matched_items": len(common),
        },
    )


def compare_profiles(
    left: BundleProfile, right: BundleProfile, config: AnalysisConfig
) -> ComparisonResult:
    business_left = [
        method
        for method in left.methods
        if not method.third_party and method.instruction_count >= config.min_method_instructions
    ]
    business_right = [
        method
        for method in right.methods
        if not method.third_party and method.instruction_count >= config.min_method_instructions
    ]
    business = _match_methods(business_left, business_right, config)
    business.key = "business_code"
    long_left = [
        method
        for method in business_left
        if method.instruction_count >= config.long_method_min_instructions
    ]
    long_right = [
        method
        for method in business_right
        if method.instruction_count >= config.long_method_min_instructions
    ]
    long_methods = _match_methods(long_left, long_right, config)
    long_methods.key = "long_methods"

    left_manifest = [
        f"{module}:{value}" for module, values in left.manifests.items() for value in values
    ]
    right_manifest = [
        f"{module}:{value}" for module, values in right.manifests.items() for value in values
    ]
    dimensions = {
        "business_code": business,
        "long_methods": long_methods,
        "manifest": _simple_set_dimension(
            "manifest",
            left_manifest,
            right_manifest,
            "Manifest 特征匹配",
            config.max_findings_per_dimension,
        ),
        "resources": _compare_files(
            "resources",
            [item for item in left.files if item.category == "resource"],
            [item for item in right.files if item.category == "resource"],
            config,
        ),
        "images": _compare_images(left.images, right.images, config),
        "dependencies": _simple_set_dimension(
            "dependencies",
            left.dependencies,
            right.dependencies,
            "依赖匹配",
            config.max_findings_per_dimension,
        ),
        "assets_native": _compare_files(
            "assets_native",
            [item for item in left.files if item.category in {"asset", "native"}],
            [item for item in right.files if item.category in {"asset", "native"}],
            config,
        ),
        "build_structure": _simple_set_dimension(
            "build_structure",
            left.build_features,
            right.build_features,
            "构建特征匹配",
            config.max_findings_per_dimension,
        ),
    }
    aggregate = aggregate_dimensions(dimensions, config)
    return ComparisonResult(
        left=left,
        right=right,
        dimensions=dimensions,
        aggregate=aggregate,
        warnings=left.warnings + right.warnings,
        config_snapshot=asdict(config),
    )


def _origin_counts(items: Iterable[object]) -> dict[str, int]:
    counts = Counter(str(getattr(item, "origin", None) or "UNRESOLVED") for item in items)
    return dict(sorted(counts.items()))


def _source_path_counts(items: Iterable[object]) -> dict[str, int]:
    counts = Counter(
        str(source_path)
        for item in items
        if (source_path := getattr(item, "source_path", None)) is not None
    )
    return dict(sorted(counts.items()))


def _owned_empty(
    result: DimensionResult, left_items: list[object], right_items: list[object]
) -> DimensionResult:
    if not left_items or not right_items:
        result.score = None
        result.left_coverage = 0.0
        result.right_coverage = 0.0
        result.confidence = 0.0
        if not left_items and not right_items:
            result.warnings.append("双方均没有可证明归属的自有内容")
        elif not left_items:
            result.warnings.append("A 侧没有可证明归属的自有内容")
        else:
            result.warnings.append("B 侧没有可证明归属的自有内容")
    result.metrics["left_origins"] = _origin_counts(left_items)
    result.metrics["right_origins"] = _origin_counts(right_items)
    result.metrics["left_source_paths"] = _source_path_counts(left_items)
    result.metrics["right_source_paths"] = _source_path_counts(right_items)
    return result


def _compare_manifest_multiset(
    left_values: list[ManifestFingerprint],
    right_values: list[ManifestFingerprint],
    config: AnalysisConfig,
) -> DimensionResult:
    if not left_values and not right_values:
        return DimensionResult(
            "manifest",
            None,
            0.0,
            0.0,
            warnings=["没有可证明归属的自有内容"],
            confidence=0.0,
            metrics={"left_items": 0, "right_items": 0, "matched_items": 0},
        )
    left_counter = Counter(item.value for item in left_values)
    right_counter = Counter(item.value for item in right_values)
    matched = left_counter & right_counter
    matched_count = sum(matched.values())
    left_count = sum(left_counter.values())
    right_count = sum(right_counter.values())
    score = 200 * matched_count / (left_count + right_count)
    findings = [
        Finding(
            "Manifest 自有节点匹配",
            100.0,
            value,
            value,
            {
                "occurrences": count,
                "left_source_paths": sorted(
                    {
                        item.source_path
                        for item in left_values
                        if item.value == value and item.source_path is not None
                    }
                ),
                "right_source_paths": sorted(
                    {
                        item.source_path
                        for item in right_values
                        if item.value == value and item.source_path is not None
                    }
                ),
            },
        )
        for value, count in sorted(matched.items())[: config.max_findings_per_dimension]
    ]
    return DimensionResult(
        "manifest",
        round(score, 2),
        matched_count / left_count if left_count else 0.0,
        matched_count / right_count if right_count else 0.0,
        findings=findings,
        metrics={
            "left_items": left_count,
            "right_items": right_count,
            "matched_items": matched_count,
        },
    )


def compare_owned_profiles(
    left: BundleProfile,
    right: BundleProfile,
    config: AnalysisConfig,
    *,
    left_attribution: AttributionSummary | None = None,
    right_attribution: AttributionSummary | None = None,
    left_resource_confidence: float = 1.0,
    right_resource_confidence: float = 1.0,
) -> ComparisonResult:
    business_left = [
        method
        for method in left.methods
        if method.instruction_count >= config.min_method_instructions
    ]
    business_right = [
        method
        for method in right.methods
        if method.instruction_count >= config.min_method_instructions
    ]
    business = _owned_empty(
        _match_methods(business_left, business_right, config),
        list(business_left),
        list(business_right),
    )
    business.key = "business_code"
    long_left = [
        method
        for method in business_left
        if method.instruction_count >= config.long_method_min_instructions
    ]
    long_right = [
        method
        for method in business_right
        if method.instruction_count >= config.long_method_min_instructions
    ]
    long_methods = _owned_empty(
        _match_methods(long_left, long_right, config), list(long_left), list(long_right)
    )
    long_methods.key = "long_methods"
    left_resources = [item for item in left.files if item.category == "resource"]
    right_resources = [item for item in right.files if item.category == "resource"]
    resources = _owned_empty(
        _compare_files("resources", left_resources, right_resources, config),
        list(left_resources),
        list(right_resources),
    )
    if resources.score is not None:
        resources.confidence = round(
            max(0.0, min(1.0, left_resource_confidence, right_resource_confidence)), 6
        )
        if resources.confidence < 1.0:
            resources.warnings.append("Bundletool 资源清单覆盖不完整，资源维度置信度已降低")
    images = _owned_empty(
        _compare_images(left.images, right.images, config),
        list(left.images),
        list(right.images),
    )
    left_assets = [item for item in left.files if item.category == "asset"]
    right_assets = [item for item in right.files if item.category == "asset"]
    assets = _owned_empty(
        _compare_files("assets", left_assets, right_assets, config),
        list(left_assets),
        list(right_assets),
    )
    left_manifest = left.manifest_entries or [
        ManifestFingerprint(value)
        for values in left.manifests.values()
        for value in values
    ]
    right_manifest = right.manifest_entries or [
        ManifestFingerprint(value)
        for values in right.manifests.values()
        for value in values
    ]
    manifest = _owned_empty(
        _compare_manifest_multiset(left_manifest, right_manifest, config),
        list(left_manifest),
        list(right_manifest),
    )
    dimensions = {
        "business_code": business,
        "long_methods": long_methods,
        "images": images,
        "resources": resources,
        "manifest": manifest,
        "assets": assets,
    }
    left_summary = left_attribution or AttributionSummary()
    right_summary = right_attribution or AttributionSummary()
    return ComparisonResult(
        left=left,
        right=right,
        dimensions=dimensions,
        aggregate=None,
        mode="owned",
        warnings=sorted(set(left.warnings + right.warnings)),
        config_snapshot=asdict(config),
        ownership={
            "strategy": "strict_provenance",
            "left": asdict(left_summary),
            "right": asdict(right_summary),
        },
        diagnostics={
            "dependencies": {"left": left.dependencies, "right": right.dependencies},
            "native": {
                "left": left.counts.get("native", 0),
                "right": right.counts.get("native", 0),
            },
            "build_structure": {
                "left": left.build_features,
                "right": right.build_features,
            },
            "signing": {
                "left": [item for item in left.build_features if "META-INF" in item],
                "right": [item for item in right.build_features if "META-INF" in item],
            },
            "hardening": {
                "left": [item for item in left.build_features if item.startswith("hardening:")],
                "right": [item for item in right.build_features if item.startswith("hardening:")],
            },
            "agp": {"left": left.agp_version, "right": right.agp_version},
        },
    )
