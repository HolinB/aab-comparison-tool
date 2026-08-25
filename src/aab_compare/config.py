from __future__ import annotations

import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

DIMENSION_WEIGHTS: dict[str, int] = {
    "business_code": 35,
    "long_methods": 15,
    "manifest": 10,
    "resources": 10,
    "images": 8,
    "dependencies": 5,
    "assets_native": 10,
    "build_structure": 7,
}


@dataclass(frozen=True)
class ArchiveLimits:
    max_input_size: int = 4 * 1024**3
    max_uncompressed_size: int = 16 * 1024**3
    max_entry_size: int = 2 * 1024**3
    max_entries: int = 200_000
    max_compression_ratio: float = 200.0


@dataclass(frozen=True)
class AnalysisConfig:
    weights: dict[str, int] = field(default_factory=lambda: dict(DIMENSION_WEIGHTS))
    levels: dict[str, int] = field(
        default_factory=lambda: {"低": 0, "中": 30, "高": 55, "极高": 75}
    )
    long_method_min_instructions: int = 100
    min_method_instructions: int = 12
    min_method_similarity: float = 0.70
    lsh_threshold: float = 0.55
    minhash_permutations: int = 128
    max_findings_per_dimension: int = 50
    max_source_evidence: int = 20
    jobs: int = 0
    subprocess_timeout_seconds: int = 1800
    java_max_heap: str = "4g"
    archive_limits: ArchiveLimits = field(default_factory=ArchiveLimits)
    third_party_prefixes: tuple[str, ...] = (
        "Landroid/",
        "Landroidx/",
        "Lcom/android/",
        "Lcom/airbnb/",
        "Lcom/appsflyer/",
        "Lcom/bumptech/",
        "Lcom/chad/",
        "Lcom/coremedia/",
        "Lcom/daimajia/",
        "Lcom/google/",
        "Lcom/facebook/",
        "Lcom/github/",
        "Lcom/hjq/",
        "Lcom/kyleduo/",
        "Lcom/luck/picture/",
        "Lcom/netease/",
        "Lcom/rousetime/android_startup/",
        "Lcom/scwang/",
        "Lcom/squareup/",
        "Lcom/tencent/",
        "Lcom/yalantis/",
        "Lcom/gyf/immersionbar/",
        "Lcn/thinkingdata/",
        "Lcoil/",
        "Lio/objectbox/",
        "Lio/reactivex/",
        "Lio/sentry/",
        "Lkotlin/",
        "Lkotlinx/",
        "Lokhttp3/",
        "Lokio/",
        "Lorg/jetbrains/",
        "Lorg/extra/relinker/",
        "Lorg/greenrobot/",
        "Lretrofit2/",
        "Lszcom/",
        "Ltop/zibin/luban/",
    )
    business_prefixes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if set(self.weights) != set(DIMENSION_WEIGHTS):
            raise ValueError("weights must contain exactly the eight supported dimensions")
        if sum(self.weights.values()) != 100:
            raise ValueError("dimension weights must sum to 100")
        if self.long_method_min_instructions < 1:
            raise ValueError("long_method_min_instructions must be positive")
        if not 0 <= self.min_method_similarity <= 1:
            raise ValueError("min_method_similarity must be between 0 and 1")


def load_config(path: Path | None) -> AnalysisConfig:
    if path is None:
        return AnalysisConfig()
    with path.open("rb") as stream:
        raw = tomllib.load(stream)
    defaults = AnalysisConfig()
    allowed = {field.name for field in defaults.__dataclass_fields__.values()}
    unknown = set(raw) - allowed
    if unknown:
        raise ValueError(f"unknown configuration keys: {', '.join(sorted(unknown))}")
    changes: dict[str, Any] = dict(raw)
    if "weights" in changes:
        merged_weights = dict(defaults.weights)
        merged_weights.update(changes["weights"])
        changes["weights"] = merged_weights
    if "levels" in changes:
        merged_levels = dict(defaults.levels)
        merged_levels.update(changes["levels"])
        changes["levels"] = merged_levels
    if "archive_limits" in changes:
        changes["archive_limits"] = replace(defaults.archive_limits, **changes["archive_limits"])
    for key in ("third_party_prefixes", "business_prefixes"):
        if key in changes:
            changes[key] = tuple(changes[key])
    return replace(defaults, **changes)
