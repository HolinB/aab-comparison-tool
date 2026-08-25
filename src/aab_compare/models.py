from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class FileFingerprint:
    path: str
    module: str
    category: str
    size: int
    sha256: str
    semantic_hash: str | None = None
    features: list[str] = field(default_factory=list)
    origin: str | None = None
    source_path: str | None = None


@dataclass
class MethodFingerprint:
    identifier: str
    module: str
    dex_path: str
    class_name: str
    method_name: str
    descriptor: str
    instruction_count: int
    canonical_hash: str
    opcode_tokens: list[str]
    api_calls: list[str]
    constants: list[str]
    block_signature: list[str]
    third_party: bool = False
    origin: str | None = None
    source_path: str | None = None


@dataclass
class ImageFingerprint:
    path: str
    module: str
    size: int
    sha256: str
    perceptual_hash: str | None
    width: int | None
    height: int | None
    origin: str | None = None
    source_path: str | None = None


@dataclass
class ManifestFingerprint:
    value: str
    origin: str | None = None
    source_path: str | None = None


@dataclass
class BundleProfile:
    source_path: str
    sha256: str
    size: int
    modules: list[str]
    counts: dict[str, int]
    schema_version: int = 1
    agp_version: str | None = None
    files: list[FileFingerprint] = field(default_factory=list)
    methods: list[MethodFingerprint] = field(default_factory=list)
    images: list[ImageFingerprint] = field(default_factory=list)
    manifests: dict[str, list[str]] = field(default_factory=dict)
    manifest_entries: list[ManifestFingerprint] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    build_features: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> BundleProfile:
        data = dict(raw)
        data["files"] = [FileFingerprint(**item) for item in data.get("files", [])]
        data["methods"] = [MethodFingerprint(**item) for item in data.get("methods", [])]
        data["images"] = [ImageFingerprint(**item) for item in data.get("images", [])]
        data["manifest_entries"] = [
            ManifestFingerprint(**item) for item in data.get("manifest_entries", [])
        ]
        return cls(**data)


@dataclass
class Finding:
    title: str
    similarity: float
    left: str
    right: str
    details: dict[str, Any] = field(default_factory=dict)
    evidence_path: str | None = None


@dataclass
class DimensionResult:
    key: str
    score: float | None
    left_coverage: float
    right_coverage: float
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0


@dataclass
class AggregateScore:
    score: float | None
    minimum_score: float
    maximum_score: float
    analyzed_weight: int
    level: str | None


@dataclass
class ComparisonResult:
    left: BundleProfile
    right: BundleProfile
    dimensions: dict[str, DimensionResult]
    aggregate: AggregateScore | None
    schema_version: int = 3
    mode: str = "legacy"
    warnings: list[str] = field(default_factory=list)
    config_snapshot: dict[str, Any] = field(default_factory=dict)
    ownership: dict[str, Any] = field(default_factory=dict)
    diagnostics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        for side in ("left", "right"):
            profile = result[side]
            profile.pop("duration_seconds", None)
            if self.mode == "owned":
                profile.pop("dependencies", None)
                profile.pop("build_features", None)
                profile.pop("agp_version", None)
                profile["counts"].pop("native", None)
        return result

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)


@dataclass(frozen=True)
class CanonicalMethod:
    tokens: tuple[str, ...]
    api_calls: tuple[str, ...]
    constants: tuple[str, ...]
    block_signature: tuple[str, ...]
    canonical_hash: str
