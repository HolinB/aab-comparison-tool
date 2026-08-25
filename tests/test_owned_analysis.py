from __future__ import annotations

from aab_compare.analyzers import compare_owned_profiles
from aab_compare.config import AnalysisConfig
from aab_compare.models import (
    BundleProfile,
    FileFingerprint,
    ImageFingerprint,
    ManifestFingerprint,
    MethodFingerprint,
)
from aab_compare.ownership import AttributionSummary, OriginKind


def _method(identifier: str, origin: OriginKind, instructions: int = 120) -> MethodFingerprint:
    class_name, method = identifier.split("->", 1)
    return MethodFingerprint(
        identifier=identifier,
        module="base",
        dex_path="base/dex/classes.dex",
        class_name=class_name,
        method_name=method.split("(", 1)[0],
        descriptor="()V",
        instruction_count=instructions,
        canonical_hash="same",
        opcode_tokens=["invoke", "return"] * (instructions // 2),
        api_calls=[],
        constants=[],
        block_signature=["return"],
        origin=origin.value,
        source_path=f"/src/{identifier}",
    )


def test_owned_comparison_has_six_independent_dimensions_and_no_aggregate() -> None:
    left = BundleProfile("/tmp/left.aab", "left", 1, ["base"], {})
    right = BundleProfile("/tmp/right.aab", "right", 1, ["base"], {})
    left.counts["native"] = 2
    right.counts["native"] = 3
    left.dependencies = ["com.example:left:1"]
    right.dependencies = ["com.example:right:2"]
    left.agp_version = "8.8.2"
    right.agp_version = "8.13.2"
    left.build_features = ["entry:META-INF/LEFT.RSA", "module:base"]
    right.build_features = ["hardening:present", "module:base"]
    left.methods = [
        _method("Lleft/Feature;->run()V", OriginKind.OWNED_SOURCE),
        _method("Lleft/Junk;->run()V", OriginKind.OWNED_GENERATED),
    ]
    right.methods = [_method("Lright/Feature;->run()V", OriginKind.OWNED_SOURCE)]
    left.files = [
        FileFingerprint(
            "base/res/layout/screen.xml",
            "base",
            "resource",
            10,
            "resource",
            origin=OriginKind.OWNED_SOURCE.value,
            source_path="/src/main/res/layout/screen.xml",
        )
    ]
    right.files = [
        FileFingerprint(
            "base/res/layout/renamed.xml",
            "base",
            "resource",
            10,
            "resource",
            origin=OriginKind.OWNED_SOURCE.value,
            source_path="/right/main/res/layout/renamed.xml",
        )
    ]
    left.manifests = {"owned": ["activity:left.Feature", "activity:left.Junk"]}
    right.manifests = {"owned": ["activity:right.Feature"]}

    result = compare_owned_profiles(
        left,
        right,
        AnalysisConfig(),
        left_attribution=AttributionSummary(owned_source=2, owned_generated=1),
        right_attribution=AttributionSummary(owned_source=2),
    )

    assert result.mode == "owned"
    assert result.schema_version == 3
    assert result.aggregate is None
    assert set(result.dimensions) == {
        "business_code",
        "long_methods",
        "images",
        "resources",
        "manifest",
        "assets",
    }
    assert result.dimensions["assets"].score is None
    assert result.dimensions["business_code"].metrics["left_origins"] == {
        "OWNED_GENERATED": 1,
        "OWNED_SOURCE": 1,
    }
    assert result.dimensions["business_code"].metrics["left_source_paths"] == {
        "/src/Lleft/Feature;->run()V": 1,
        "/src/Lleft/Junk;->run()V": 1,
    }
    business_evidence = result.dimensions["business_code"].findings[0].details
    assert business_evidence["left_origin"] in {
        OriginKind.OWNED_SOURCE.value,
        OriginKind.OWNED_GENERATED.value,
    }
    assert business_evidence["left_source_path"].startswith("/src/")
    resource_evidence = result.dimensions["resources"].findings[0].details
    assert resource_evidence["left_origin"] == OriginKind.OWNED_SOURCE.value
    assert resource_evidence["left_source_path"] == "/src/main/res/layout/screen.xml"
    assert result.ownership["left"]["owned_generated"] == 1
    assert "dependencies" in result.diagnostics
    assert "native" in result.diagnostics
    assert "signing" in result.diagnostics
    assert "hardening" in result.diagnostics
    assert result.diagnostics["agp"] == {"left": "8.8.2", "right": "8.13.2"}


def test_owned_json_keeps_build_dependency_and_native_data_only_in_diagnostics() -> None:
    left = BundleProfile(
        "/tmp/left.aab",
        "left",
        1,
        ["base"],
        {"dex": 1, "native": 2, "assets": 3, "owned_files": 4},
        agp_version="8.8.2",
        dependencies=["com.example:left:1"],
        build_features=["entry:META-INF/LEFT.RSA", "module:base"],
    )
    right = BundleProfile(
        "/tmp/right.aab",
        "right",
        1,
        ["base"],
        {"dex": 1, "native": 3, "assets": 4, "owned_files": 5},
        agp_version="8.13.2",
        dependencies=["com.example:right:2"],
        build_features=["hardening:present", "module:base"],
    )

    payload = compare_owned_profiles(left, right, AnalysisConfig()).to_dict()

    for side in ("left", "right"):
        assert "dependencies" not in payload[side]
        assert "build_features" not in payload[side]
        assert "agp_version" not in payload[side]
        assert "native" not in payload[side]["counts"]
    assert payload["diagnostics"]["dependencies"] == {
        "left": ["com.example:left:1"],
        "right": ["com.example:right:2"],
    }
    assert payload["diagnostics"]["native"] == {"left": 2, "right": 3}
    assert payload["diagnostics"]["agp"] == {"left": "8.8.2", "right": "8.13.2"}


def test_owned_empty_both_sides_is_not_perfect_similarity() -> None:
    empty_left = BundleProfile("/tmp/left.aab", "left", 1, ["base"], {})
    empty_right = BundleProfile("/tmp/right.aab", "right", 1, ["base"], {})

    result = compare_owned_profiles(empty_left, empty_right, AnalysisConfig())

    assert all(dimension.score is None for dimension in result.dimensions.values())
    assert all(dimension.confidence == 0.0 for dimension in result.dimensions.values())


def test_owned_one_sided_content_is_na_instead_of_zero_or_vacuous_coverage() -> None:
    left = BundleProfile("/tmp/left.aab", "left", 1, ["base"], {})
    right = BundleProfile("/tmp/right.aab", "right", 1, ["base"], {})
    left.methods = [_method("Lleft/Only;->run()V", OriginKind.OWNED_SOURCE)]

    result = compare_owned_profiles(left, right, AnalysisConfig())

    for key in ("business_code", "long_methods"):
        dimension = result.dimensions[key]
        assert dimension.score is None
        assert dimension.left_coverage == 0.0
        assert dimension.right_coverage == 0.0
        assert dimension.confidence == 0.0


def test_owned_resource_inventory_coverage_reduces_dimension_confidence() -> None:
    left = BundleProfile("/tmp/left.aab", "left", 1, ["base"], {})
    right = BundleProfile("/tmp/right.aab", "right", 1, ["base"], {})
    left.files = [
        FileFingerprint(
            "base/res/layout/a.xml",
            "base",
            "resource",
            10,
            "same",
            origin=OriginKind.OWNED_SOURCE.value,
            source_path="/left/a.xml",
        )
    ]
    right.files = [
        FileFingerprint(
            "base/res/layout/b.xml",
            "base",
            "resource",
            10,
            "same",
            origin=OriginKind.OWNED_SOURCE.value,
            source_path="/right/b.xml",
        )
    ]

    result = compare_owned_profiles(
        left,
        right,
        AnalysisConfig(),
        left_resource_confidence=0.5,
        right_resource_confidence=0.75,
    )

    resources = result.dimensions["resources"]
    assert resources.confidence == 0.5
    assert any("资源清单" in warning for warning in resources.warnings)


def test_owned_image_evidence_includes_origin_and_source_paths() -> None:
    left = BundleProfile("/tmp/left.aab", "left", 1, ["base"], {})
    right = BundleProfile("/tmp/right.aab", "right", 1, ["base"], {})
    left.images = [
        ImageFingerprint(
            "base/res/drawable/a.png",
            "base",
            10,
            "same",
            "00" * 8,
            10,
            10,
            OriginKind.OWNED_GENERATED.value,
            "/left/generated/a.png",
        )
    ]
    right.images = [
        ImageFingerprint(
            "base/res/drawable/b.png",
            "base",
            10,
            "same",
            "00" * 8,
            10,
            10,
            OriginKind.OWNED_SOURCE.value,
            "/right/src/b.png",
        )
    ]

    finding = compare_owned_profiles(left, right, AnalysisConfig()).dimensions["images"].findings[0]

    assert finding.details["left_origin"] == OriginKind.OWNED_GENERATED.value
    assert finding.details["left_source_path"] == "/left/generated/a.png"
    assert finding.details["right_origin"] == OriginKind.OWNED_SOURCE.value
    assert finding.details["right_source_path"] == "/right/src/b.png"


def test_owned_manifest_dimension_preserves_origin_and_source_path_evidence() -> None:
    left = BundleProfile("/tmp/left.aab", "left", 1, ["base"], {})
    right = BundleProfile("/tmp/right.aab", "right", 1, ["base"], {})
    feature = "activity:name=a.b.Random"
    left.manifests = {"owned": [feature, feature]}
    right.manifests = {"owned": [feature]}
    left.manifest_entries = [
        ManifestFingerprint(
            feature, OriginKind.OWNED_SOURCE.value, "/src/main/AndroidManifest.xml"
        ),
        ManifestFingerprint(
            feature, OriginKind.OWNED_GENERATED.value, "/build/junk/AndroidManifest.xml"
        ),
    ]
    right.manifest_entries = [
        ManifestFingerprint(feature, OriginKind.OWNED_SOURCE.value, "/right/AndroidManifest.xml")
    ]

    result = compare_owned_profiles(left, right, AnalysisConfig())

    manifest = result.dimensions["manifest"]
    assert manifest.metrics["left_origins"] == {"OWNED_GENERATED": 1, "OWNED_SOURCE": 1}
    assert manifest.metrics["left_source_paths"] == {
        "/build/junk/AndroidManifest.xml": 1,
        "/src/main/AndroidManifest.xml": 1,
    }
    assert manifest.findings[0].details["left_source_paths"] == [
        "/build/junk/AndroidManifest.xml",
        "/src/main/AndroidManifest.xml",
    ]
