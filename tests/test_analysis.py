from __future__ import annotations

import io
import zipfile
from pathlib import Path

from PIL import Image

import aab_compare.analyzers as analyzers
from aab_compare.analyzers import analyze_bundle, classify_methods, compare_profiles
from aab_compare.config import AnalysisConfig
from aab_compare.dex import build_method_fingerprint, should_retain_method
from aab_compare.models import BundleProfile, MethodFingerprint


def _png_bytes(color: tuple[int, int, int]) -> bytes:
    output = io.BytesIO()
    Image.new("RGB", (32, 32), color).save(output, format="PNG")
    return output.getvalue()


def _write_synthetic_aab(path: Path, *, renamed: bool = False) -> None:
    layout_name = "screen_obfuscated.xml" if renamed else "activity_main.xml"
    image_name = "x1.png" if renamed else "logo.png"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "base/manifest/AndroidManifest.xml",
            b'<manifest package="com.example">'
            b'<uses-permission android:name="android.permission.INTERNET"/>'
            b'<application><activity android:name=".MainActivity"/>'
            b"</application></manifest>",
        )
        archive.writestr(
            "BUNDLE-METADATA/com.android.tools.build.gradle/app-metadata.properties",
            b"appMetadataVersion=1.1\nandroidGradlePluginVersion=8.8.2\n",
        )
        archive.writestr(
            "BUNDLE-METADATA/com.android.tools.build.libraries/dependencies.pb",
            b"com.squareup.okhttp3\x00okhttp\x004.12.0\x00androidx.core\x00core-ktx\x001.15.0",
        )
        archive.writestr(
            f"base/res/layout/{layout_name}",
            b'<LinearLayout android:orientation="vertical">'
            b'<TextView android:text="hello"/></LinearLayout>',
        )
        archive.writestr(f"base/res/drawable/{image_name}", _png_bytes((20, 100, 220)))
        archive.writestr("base/assets/model.bin", b"model-data" * 100)
        archive.writestr("base/lib/arm64-v8a/libdemo.so", b"\x7fELF" + b"native" * 100)
        archive.writestr("BundleConfig.pb", b"splitDimension\x00ABI\x00LANGUAGE")


def test_analyze_bundle_builds_multidimensional_profile(tmp_path: Path) -> None:
    aab = tmp_path / "sample.aab"
    _write_synthetic_aab(aab)

    profile = analyze_bundle(aab, AnalysisConfig(), include_dex=False)

    assert profile.agp_version == "8.8.2"
    assert profile.counts["images"] == 1
    assert any("android.permission.INTERNET" in feature for feature in profile.manifests["base"])
    assert profile.dependencies == [
        "androidx.core:core-ktx:1.15.0",
        "com.squareup.okhttp3:okhttp:4.12.0",
    ]
    assert {file.category for file in profile.files} >= {
        "resource",
        "image",
        "asset",
        "native",
        "build",
    }
    assert profile.images[0].perceptual_hash is not None


def test_compare_profiles_matches_renamed_resources_and_images(tmp_path: Path) -> None:
    left_path = tmp_path / "left.aab"
    right_path = tmp_path / "right.aab"
    _write_synthetic_aab(left_path)
    _write_synthetic_aab(right_path, renamed=True)
    config = AnalysisConfig()
    left = analyze_bundle(left_path, config, include_dex=False)
    right = analyze_bundle(right_path, config, include_dex=False)

    result = compare_profiles(left, right, config)

    assert set(result.dimensions) == set(config.weights)
    assert result.dimensions["resources"].score == 100.0
    assert result.dimensions["images"].score == 100.0
    assert result.dimensions["dependencies"].score == 100.0
    assert result.dimensions["assets_native"].score == 100.0
    assert result.dimensions["resources"].metrics["renamed_matches"] == 1
    assert result.dimensions["images"].metrics["renamed_matches"] == 1


def test_build_profile_keeps_structural_metadata_without_dumping_payload(tmp_path: Path) -> None:
    aab = tmp_path / "hardened.aab"
    large_metadata = b"secret-token-" * 10_000
    with zipfile.ZipFile(aab, "w") as archive:
        archive.writestr("base/manifest/AndroidManifest.xml", b"manifest")
        archive.writestr("META-INF/HARDEN.SF", b"signature")
        archive.writestr("META-INF/HARDEN.RSA", b"certificate")
        archive.writestr(
            "BUNDLE-METADATA/com.example.android.hardening/build.json",
            b'{"sourceSha256":"abc","tool":"harden"}',
        )
        archive.writestr("BUNDLE-METADATA/example/large.txt", large_metadata)

    profile = analyze_bundle(aab, AnalysisConfig(), include_dex=False)

    assert "entry:META-INF/HARDEN.SF" in profile.build_features
    assert "entry:META-INF/HARDEN.RSA" in profile.build_features
    assert "hardening:present" in profile.build_features
    build_files = [item for item in profile.files if item.category == "build"]
    assert all(len(item.features) <= 200 for item in build_files)


def test_code_matching_ignores_method_and_class_names() -> None:
    instructions = (
        [
            ("const-string", 'v0, "hello"'),
            ("invoke-virtual", "{v0}, Ljava/lang/String;->length()I"),
        ]
        + [("add-int", "v0, v0, v1")] * 110
        + [("return", "v0")]
    )
    left_method = build_method_fingerprint(
        "base/dex/classes.dex", "Lcom/example/Feature;", "calculate", "()I", instructions
    )
    right_method = build_method_fingerprint(
        "base/dex/classes.dex", "La/b;", "a", "()I", instructions
    )
    config = AnalysisConfig()
    left_path = Path("/tmp/left.aab")
    right_path = Path("/tmp/right.aab")
    result = compare_profiles(
        BundleProfile(str(left_path), "l", 1, ["base"], {}, methods=[left_method]),
        BundleProfile(str(right_path), "r", 1, ["base"], {}, methods=[right_method]),
        config,
    )

    assert result.dimensions["business_code"].score == 100.0
    assert result.dimensions["long_methods"].score == 100.0
    finding = result.dimensions["long_methods"].findings[0]
    assert finding.left.endswith("Feature;->calculate()I")
    assert finding.right.endswith("a/b;->a()I")


def test_method_match_fallback_orders_tied_candidates_by_index(
    monkeypatch: object,
) -> None:
    class EmptyLsh:
        def __init__(self, **_: object) -> None:
            pass

        def insert(self, _: str, __: object) -> None:
            pass

        def query(self, _: object) -> list[str]:
            return []

    class ReverseIterationSet(set[str]):
        def __iter__(self):  # type: ignore[no-untyped-def]
            return iter(sorted(super().__iter__(), reverse=True))

    def fingerprint(identifier: str, token: str) -> MethodFingerprint:
        return MethodFingerprint(
            identifier=identifier,
            module="base",
            dex_path="base/dex/classes.dex",
            class_name="Lexample/Test;",
            method_name=identifier,
            descriptor="()V",
            instruction_count=100,
            canonical_hash=identifier,
            opcode_tokens=[token],
            api_calls=[],
            constants=[],
            block_signature=[],
        )

    def shingles(values: list[str], width: int = 5) -> set[str]:
        del width
        if values[0] == "left":
            return ReverseIterationSet(f"token-{index:02}" for index in range(31))
        return {values[0]}

    left = fingerprint("left", "left")
    right = [fingerprint(f"right-{index}", f"token-{index:02}") for index in range(31)]
    monkeypatch.setattr(analyzers, "MinHashLSH", EmptyLsh)
    monkeypatch.setattr(analyzers, "_method_minhash", lambda *_: object())
    monkeypatch.setattr(analyzers, "_shingles", shingles)
    monkeypatch.setattr(
        analyzers,
        "_method_similarity",
        lambda _, method: 1.0 if method.identifier == "right-0" else 0.0,
    )

    result = analyzers._match_methods([left], right, AnalysisConfig())

    assert result.metrics["matched_methods"] == 1
    assert result.findings[0].right == "right-0"


def test_method_match_fallback_excludes_already_matched_candidates_before_cap(
    monkeypatch: object,
) -> None:
    class EmptyLsh:
        def __init__(self, **_: object) -> None:
            pass

        def insert(self, _: str, __: object) -> None:
            pass

        def query(self, _: object) -> list[str]:
            return []

    def fingerprint(
        identifier: str, canonical_hash: str, opcode_tokens: list[str]
    ) -> MethodFingerprint:
        return MethodFingerprint(
            identifier=identifier,
            module="base",
            dex_path="base/dex/classes.dex",
            class_name="Lexample/Test;",
            method_name=identifier,
            descriptor="()V",
            instruction_count=100,
            canonical_hash=canonical_hash,
            opcode_tokens=opcode_tokens,
            api_calls=[],
            constants=[],
            block_signature=[],
        )

    def shingles(values: list[str], width: int = 5) -> set[str]:
        del width
        if values[0] == "fallback":
            return {f"token-{index:02}" for index in range(31)}
        return set(values)

    staged_left = [
        fingerprint(f"left-{index}", f"left-hash-{index}", [f"stage-{index:02}"])
        for index in range(30)
    ]
    fallback_left = fingerprint("fallback-left", "fallback", ["fallback"])
    right = [
        fingerprint(
            f"right-{index}",
            f"right-hash-{index}",
            [f"token-{index:02}", f"stage-{index:02}"],
        )
        for index in range(31)
    ]
    monkeypatch.setattr(analyzers, "MinHashLSH", EmptyLsh)
    monkeypatch.setattr(analyzers, "_method_minhash", lambda *_: object())
    monkeypatch.setattr(analyzers, "_shingles", shingles)
    monkeypatch.setattr(
        analyzers,
        "_method_similarity",
        lambda left_method, right_method: 1.0
        if (
            left_method.identifier == f"left-{right_method.identifier.removeprefix('right-')}"
            or (
                left_method.identifier == "fallback-left"
                and right_method.identifier == "right-30"
            )
        )
        else 0.0,
    )

    result = analyzers._match_methods(staged_left + [fallback_left], right, AnalysisConfig())

    assert result.metrics["matched_methods"] == 31
    assert any(finding.right == "right-30" for finding in result.findings)


def test_dex_profile_can_drop_short_and_known_third_party_methods() -> None:
    short_business = build_method_fingerprint(
        "base/dex/classes.dex", "La/b;", "a", "()V", [("return-void", "")]
    )
    third_party = build_method_fingerprint(
        "base/dex/classes.dex",
        "Landroidx/core/Foo;",
        "work",
        "()V",
        [("add-int", "v0, v1, v2")] * 20,
        third_party_prefixes=("Landroidx/",),
    )
    business = build_method_fingerprint(
        "base/dex/classes.dex",
        "La/b;",
        "work",
        "()V",
        [("add-int", "v0, v1, v2")] * 20,
    )

    assert should_retain_method(short_business, minimum_instructions=12) is False
    assert should_retain_method(third_party, minimum_instructions=12) is False
    assert should_retain_method(business, minimum_instructions=12) is True


def test_dependency_metadata_and_generated_classes_are_removed_from_business_code() -> None:
    dependency_method = build_method_fingerprint(
        "base/dex/classes.dex",
        "Lio/sentry/Client;",
        "send",
        "()V",
        [("add-int", "v0, v1, v2")] * 20,
    )
    generated_method = build_method_fingerprint(
        "base/dex/classes.dex",
        "Lcom/exampleapp/R$styleable;",
        "<clinit>",
        "()V",
        [("const", "v0, 1")] * 20,
    )
    business_method = build_method_fingerprint(
        "base/dex/classes.dex",
        "Lcom/exampleapp/Feature;",
        "work",
        "()V",
        [("add-int", "v0, v1, v2")] * 20,
    )
    profile = BundleProfile(
        "/tmp/app.aab",
        "sha",
        1,
        ["base"],
        {},
        methods=[dependency_method, generated_method, business_method],
        dependencies=["io.sentry:sentry-android:8.0.0"],
    )

    classify_methods(profile)

    assert dependency_method.third_party is True
    assert generated_method.third_party is True
    assert business_method.third_party is False


def test_analyze_bundle_retains_classified_methods_and_legacy_comparison_filters_them(
    tmp_path: Path, monkeypatch: object
) -> None:
    aab = tmp_path / "methods.aab"
    with zipfile.ZipFile(aab, "w") as archive:
        archive.writestr("base/manifest/AndroidManifest.xml", b"<manifest />")
        archive.writestr("base/dex/classes.dex", b"dex")

    third_party = build_method_fingerprint(
        "base/dex/classes.dex",
        "Lcom/example/R$styleable;",
        "run",
        "()V",
        [("add-int", "v0, v1, v2")] * 20,
    )
    business = build_method_fingerprint(
        "base/dex/classes.dex",
        "Lcom/example/Feature;",
        "run",
        "()V",
        [("add-int", "v0, v1, v2")] * 20,
    )
    calls: list[bool] = []

    def extract(*_: object, include_third_party: bool, **__: object) -> list[object]:
        calls.append(include_third_party)
        return [third_party, business]

    monkeypatch.setattr("aab_compare.analyzers.extract_methods_from_dex", extract)

    profile = analyze_bundle(aab, AnalysisConfig())
    comparison = compare_profiles(profile, profile, AnalysisConfig())

    assert calls == [True]
    assert {method.class_name for method in profile.methods} == {
        "Lcom/example/R$styleable;",
        "Lcom/example/Feature;",
    }
    assert next(
        method for method in profile.methods if "R$styleable" in method.class_name
    ).third_party
    assert profile.counts["candidate_methods"] == 2
    assert profile.counts["methods"] == 1
    assert profile.counts["business_methods"] == 1
    assert profile.counts["all_long_methods"] == 0
    assert profile.counts["long_methods"] == 0
    assert comparison.dimensions["business_code"].metrics["left_methods"] == 1
