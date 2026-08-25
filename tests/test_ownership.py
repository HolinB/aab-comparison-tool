from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

import aab_compare.archive as archive_module
import aab_compare.ownership as ownership
from aab_compare.analyzers import compare_owned_profiles
from aab_compare.archive import ArchiveSecurityError
from aab_compare.config import ArchiveLimits
from aab_compare.models import BundleProfile, FileFingerprint, ImageFingerprint, MethodFingerprint
from aab_compare.ownership import (
    OriginKind,
    OwnershipEntry,
    OwnershipSideConfig,
    attribute_owned_profile,
    build_owned_projection,
    build_source_ownership,
    load_ownership_config,
    parse_r8_mapping,
    parse_resource_merger,
)


def _write(path: Path, content: str = "x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _write_minimal_aab(path: Path, entries: dict[str, str], *, compression: int = 0) -> Path:
    import zipfile

    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=compression) as archive:
        archive.writestr("base/manifest/AndroidManifest.xml", "manifest")
        for name, content in entries.items():
            archive.writestr(name, content)
    return path


def test_load_ownership_config_resolves_project_relative_paths(tmp_path: Path) -> None:
    left = tmp_path / "left"
    right = tmp_path / "right"
    for root in (left, right):
        (root / "app/src").mkdir(parents=True)
        (root / "app/build/generated/java/junk").mkdir(parents=True)
    config_path = tmp_path / "ownership.toml"
    config_path.write_text(
        f"""
    schema_version = 2
    provenance_lock = "cache/provenance.lock.json"

[left]
project_root = "{left}"
source_roots = ["app/src"]
variant = "demoRelease"
artifact_output = "app/build/outputs/bundle/demoRelease/app.aab"
prepare_task = ":app:bundleDemoRelease"
owned_generated_roots = ["app/build/generated/java/junk"]

[right]
project_root = "{right}"
source_roots = ["app/src"]
variant = "sampleRelease"
artifact_output = "app/build/outputs/bundle/sampleRelease/app.aab"
owned_generated_roots = ["app/build/generated/java/junk"]
""".strip(),
        encoding="utf-8",
    )

    config = load_ownership_config(config_path)

    assert config.schema_version == 2
    assert config.provenance_lock == (tmp_path / "cache/provenance.lock.json").resolve()
    assert config.left.project_root == left.resolve()
    assert config.left.source_roots == ((left / "app/src").resolve(),)
    assert config.left.prepare_task == ":app:bundleDemoRelease"
    assert config.right.prepare_task is None
    assert config.right.variant == "sampleRelease"


def test_load_ownership_config_rejects_paths_outside_project(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    config_path = tmp_path / "ownership.toml"
    config_path.write_text(
        f"""
[left]
project_root = "{project}"
source_roots = ["../outside"]
variant = "demoRelease"
artifact_output = "app.aab"

[right]
project_root = "{project}"
source_roots = ["app/src"]
variant = "demoRelease"
artifact_output = "app.aab"
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="inside project_root"):
        load_ownership_config(config_path)


def test_load_ownership_config_allows_an_absolute_artifact_outside_project(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    artifact = tmp_path / "artifacts" / "release.aab"
    config_path = tmp_path / "ownership.toml"
    config_path.write_text(
        f"""
[left]
project_root = "{project}"
source_roots = ["app/src"]
variant = "demoRelease"
artifact_output = "{artifact}"

[right]
project_root = "{project}"
source_roots = ["app/src"]
variant = "demoRelease"
artifact_output = "{artifact}"
""".strip(),
        encoding="utf-8",
    )

    assert load_ownership_config(config_path).right.artifact_output == artifact.resolve()


def test_load_ownership_config_rejects_provenance_lock_that_overlaps_artifact(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    artifact = tmp_path / "artifacts" / "release.aab"
    config_path = tmp_path / "ownership.toml"
    config_path.write_text(
        f"""
schema_version = 2
provenance_lock = "{artifact}"

[left]
project_root = "{project}"
source_roots = ["app/src"]
variant = "demoRelease"
artifact_output = "app/build/outputs/bundle/demoRelease/app.aab"

[right]
project_root = "{project}"
source_roots = ["app/src"]
variant = "demoRelease"
artifact_output = "{artifact}"
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="provenance_lock must not overlap an artifact"):
        load_ownership_config(config_path)


def test_load_ownership_config_rejects_provenance_lock_that_overlaps_config(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    config_path = tmp_path / "ownership.toml"
    config_path.write_text(
        f"""
schema_version = 2
provenance_lock = "{config_path}"

[left]
project_root = "{project}"
source_roots = ["app/src"]
variant = "demoRelease"
artifact_output = "app.aab"

[right]
project_root = "{project}"
source_roots = ["app/src"]
variant = "demoRelease"
artifact_output = "app.aab"
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="provenance_lock must not overlap the ownership configuration",
    ):
        load_ownership_config(config_path)


def test_load_ownership_config_rejects_provenance_lock_symlink(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    target = _write(tmp_path / "existing-lock.json", "{}")
    lock_link = tmp_path / "provenance-lock.json"
    lock_link.symlink_to(target)
    config_path = tmp_path / "ownership.toml"
    config_path.write_text(
        f"""
schema_version = 2
provenance_lock = "{lock_link}"

[left]
project_root = "{project}"
source_roots = ["app/src"]
variant = "demoRelease"
artifact_output = "app.aab"

[right]
project_root = "{project}"
source_roots = ["app/src"]
variant = "demoRelease"
artifact_output = "app.aab"
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="provenance_lock must not be a symbolic link"):
        load_ownership_config(config_path)


def test_load_ownership_config_rejects_malformed_prepare_task(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    config_path = tmp_path / "ownership.toml"
    config_path.write_text(
        f"""
[left]
project_root = "{project}"
source_roots = ["app/src"]
variant = "demoRelease"
artifact_output = "app.aab"
prepare_task = ":app:bundleDemoRelease --offline"

[right]
project_root = "{project}"
source_roots = ["app/src"]
variant = "demoRelease"
artifact_output = "app.aab"
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unsafe or malformed"):
        load_ownership_config(config_path)


def test_source_ownership_includes_selected_sources_and_junkcode_only(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write(
        project / "app/src/main/java/com/example/Feature.kt",
        "package com.example\nclass Feature\nfun topLevel() = 1\n",
    )
    _write(
        project / "app/src/demo/java/com/example/FlavorOnly.java",
        "package com.example; public class FlavorOnly {}",
    )
    _write(
        project / "app/src/hush/java/com/example/OtherFlavor.java",
        "package com.example; public class OtherFlavor {}",
    )
    _write(
        project / "app/src/test/java/com/example/TestOnly.java",
        "package com.example; public class TestOnly {}",
    )
    _write(project / "app/src/main/res-im/drawable/logo.webp", "image")
    _write(
        project / "selector/src/main/java/com/luck/picture/lib/LocalCopy.java",
        "package com.luck.picture.lib; public class LocalCopy {}",
    )
    _write(
        project / "app/build/generated/java/generateDemoReleaseJunkCode/com/example/Junk.java",
        "package com.example; public class Junk {}",
    )
    _write(
        project / "app/build/generated/res/generateDemoReleaseJunkCode/layout/random.xml",
        "<LinearLayout />",
    )
    _write(
        project / "app/build/generated/source/junk/demoRelease/AndroidManifest.xml",
        (
            '<manifest><application><activity android:name="com.example.Junk" />'
            "</application></manifest>"
        ),
    )
    _write(
        project / "app/build/generated/res/processDemoReleaseGoogleServices/values/values.xml",
        "<resources />",
    )
    config_path = tmp_path / "ownership.toml"
    side = f"""
project_root = "{project}"
source_roots = ["app/src", "selector/src"]
variant = "demoRelease"
artifact_output = "app/build/outputs/bundle/demoRelease/app.aab"
owned_generated_roots = [
  "app/build/generated/java/generateDemoReleaseJunkCode",
  "app/build/generated/res/generateDemoReleaseJunkCode",
  "app/build/generated/source/junk/demoRelease/AndroidManifest.xml",
]
"""
    config_path.write_text(f"[left]\n{side}\n[right]\n{side}", encoding="utf-8")
    config = load_ownership_config(config_path)

    manifest = build_source_ownership(config.left)

    descriptors = manifest.owned_class_descriptors
    assert "Lcom/example/Feature;" in descriptors
    assert "Lcom/example/FeatureKt;" in descriptors
    assert "Lcom/example/FlavorOnly;" in descriptors
    assert "Lcom/luck/picture/lib/LocalCopy;" in descriptors
    assert "Lcom/example/Junk;" in descriptors
    assert "Lcom/example/OtherFlavor;" not in descriptors
    assert "Lcom/example/TestOnly;" not in descriptors
    assert manifest.summary.owned_source > 0
    assert manifest.summary.owned_generated == 3
    assert all("GoogleServices" not in entry.source_path for entry in manifest.entries)
    assert any(
        entry.category == "image" and entry.origin is OriginKind.OWNED_SOURCE
        for entry in manifest.entries
    )
    assert any(
        entry.category == "manifest" and entry.origin is OriginKind.OWNED_GENERATED
        for entry in manifest.entries
    )


def test_source_ownership_does_not_emit_kotlin_nested_class_as_package_level(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    _write(
        project / "app/src/main/java/com/example/Outer.kt",
        "package com.example\nclass Outer {\n    class Nested\n}\n",
    )
    side = OwnershipSideConfig(
        project,
        (project / "app/src",),
        "release",
        project / "app.aab",
    )

    descriptors = build_source_ownership(side).owned_class_descriptors

    assert "Lcom/example/Outer;" in descriptors
    assert "Lcom/example/Nested;" not in descriptors


def test_source_ownership_includes_kotlin_fun_interface(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write(
        project / "app/src/main/java/com/example/Listener.kt",
        "package com.example\nfun interface Listener { fun invoke() }\n",
    )
    side = OwnershipSideConfig(
        project,
        (project / "app/src",),
        "release",
        project / "app.aab",
    )

    descriptors = build_source_ownership(side).owned_class_descriptors

    assert "Lcom/example/Listener;" in descriptors


def test_source_ownership_does_not_invent_file_facade_for_constructor_property(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    _write(
        project / "app/src/main/java/com/example/Model.kt",
        "package com.example\nclass Model(val identifier: String)\n",
    )
    side = OwnershipSideConfig(
        project,
        (project / "app/src",),
        "release",
        project / "app.aab",
    )

    descriptors = build_source_ownership(side).owned_class_descriptors

    assert "Lcom/example/Model;" in descriptors
    assert "Lcom/example/ModelKt;" not in descriptors


def test_source_ownership_includes_java_secondary_top_level_declarations(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    _write(
        project / "app/src/main/java/com/example/Primary.java",
        (
            "package com.example;\n"
            "public class Primary { class Nested {} }\n"
            "class Secondary {}\n"
            "interface Contract {}\n"
        ),
    )
    side = OwnershipSideConfig(
        project,
        (project / "app/src",),
        "release",
        project / "app.aab",
    )

    descriptors = build_source_ownership(side).owned_class_descriptors

    assert {"Lcom/example/Primary;", "Lcom/example/Secondary;", "Lcom/example/Contract;"} <= (
        descriptors
    )
    assert "Lcom/example/Nested;" not in descriptors


def _method(class_name: str, *, third_party: bool = False) -> MethodFingerprint:
    return MethodFingerprint(
        identifier=f"{class_name}->run()V",
        module="base",
        dex_path="base/dex/classes.dex",
        class_name=class_name,
        method_name="run",
        descriptor="()V",
        instruction_count=20,
        canonical_hash=class_name,
        opcode_tokens=["return"] * 20,
        api_calls=[],
        constants=[],
        block_signature=["return"],
        third_party=third_party,
    )


def test_attribute_profile_uses_r8_and_source_allowlist_not_package_blacklist(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    _write(
        project / "selector/src/main/java/com/luck/picture/lib/LocalCopy.java",
        "package com.luck.picture.lib; public class LocalCopy {}",
    )
    _write(project / "app/src/main/res-im/drawable/logo.webp", "image")
    _write(project / "app/src/main/assets/models/matcher.bin", "asset")
    config_path = tmp_path / "ownership.toml"
    side = f"""
project_root = "{project}"
source_roots = ["app/src", "selector/src"]
variant = "demoRelease"
artifact_output = "app/build/outputs/bundle/demoRelease/app.aab"
"""
    config_path.write_text(f"[left]\n{side}\n[right]\n{side}", encoding="utf-8")
    source = build_source_ownership(load_ownership_config(config_path).left)
    mapping = parse_r8_mapping(
        """
com.luck.picture.lib.LocalCopy -> a.b:
androidx.core.External -> c.d:
"""
    )
    logo = ImageFingerprint("base/res/drawable-xhdpi-v4/logo.webp", "base", 5, "img", "0", 1, 1)
    profile = BundleProfile(
        source_path="/tmp/app.aab",
        sha256="sha",
        size=1,
        modules=["base"],
        counts={},
        methods=[_method("La/b;", third_party=True), _method("Lc/d;", third_party=False)],
        files=[
            FileFingerprint("base/res/drawable-xhdpi-v4/logo.webp", "base", "image", 5, "img"),
            FileFingerprint(
                "base/assets/models/matcher.bin",
                "base",
                "asset",
                5,
                hashlib.sha256(b"asset").hexdigest(),
            ),
            FileFingerprint("base/res/drawable/google_logo.webp", "base", "image", 5, "google"),
        ],
        images=[
            logo,
            ImageFingerprint("base/res/drawable/google_logo.webp", "base", 5, "g", "0", 1, 1),
        ],
    )

    owned, attribution = attribute_owned_profile(profile, source, mapping)

    assert [method.class_name for method in owned.methods] == ["La/b;"]
    assert owned.methods[0].third_party is False
    assert [item.path for item in owned.files] == [
        "base/assets/models/matcher.bin",
        "base/res/drawable-xhdpi-v4/logo.webp",
    ]
    assert [item.path for item in owned.images] == ["base/res/drawable-xhdpi-v4/logo.webp"]
    assert attribution.owned_source == 3
    assert attribution.unresolved == 2


def test_resource_merger_distinguishes_owned_junk_public_and_tool_generated(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    local = _write(project / "app/src/main/res/drawable/logo.xml", "<shape />")
    junk = _write(
        project / "app/build/generated/res/generateDemoReleaseJunkCode/layout/random.xml",
        "<LinearLayout />",
    )
    google = _write(
        project / "app/build/generated/res/processDemoReleaseGoogleServices/values/values.xml",
        "<resources />",
    )
    dependency = tmp_path / ".gradle/caches/library/res/drawable/library.xml"
    _write(dependency, "<shape />")
    merger = tmp_path / "merger.xml"
    merger.write_text(
        f"""
<merger version="3">
  <dataSet config="dependency" from-dependency="true">
    <source path="{dependency.parents[1]}">
      <file path="{dependency}" qualifiers="" type="drawable" name="library" />
    </source>
  </dataSet>
  <dataSet config="main">
    <source path="{local.parents[1]}">
      <file path="{local}" qualifiers="" type="drawable" name="logo" />
    </source>
    <source path="{google.parents[1]}">
      <file path="{google}" qualifiers=""><string name="google_app_id">x</string></file>
    </source>
    <source path="{junk.parents[1]}">
      <file path="{junk}" qualifiers="" type="layout" name="random" />
    </source>
  </dataSet>
</merger>
""".strip(),
        encoding="utf-8",
    )
    config_path = tmp_path / "ownership.toml"
    side = f"""
project_root = "{project}"
source_roots = ["app/src"]
variant = "demoRelease"
artifact_output = "app.aab"
owned_generated_roots = ["app/build/generated/res/generateDemoReleaseJunkCode"]
"""
    config_path.write_text(f"[left]\n{side}\n[right]\n{side}", encoding="utf-8")
    side_config = load_ownership_config(config_path).left

    provenance = parse_resource_merger(merger, side_config)

    assert provenance[(":app", "drawable", "", "logo")].origin is OriginKind.OWNED_SOURCE
    assert provenance[(":app", "layout", "", "random")].origin is OriginKind.OWNED_GENERATED
    assert (
        provenance[(":external", "drawable", "", "library")].origin is OriginKind.PUBLIC_DEPENDENCY
    )
    assert provenance[(":app", "string", "", "google_app_id")].origin is OriginKind.TOOL_GENERATED


def test_resource_merger_retraces_selected_local_module_packaged_resources(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    original = _write(
        project / "base/src/main/res/values-sw480dp/dimens.xml",
        "<resources><dimen name=\"spacing\">16dp</dimen></resources>",
    )
    packaged = _write(
        project
        / "base/build/intermediates/packaged_res/demoRelease/packageDemoReleaseResources"
        / "values-sw480dp-v13/values-sw480dp-v13.xml",
        "<resources><dimen name=\"spacing\">16dp</dimen></resources>",
    )
    module_merger = (
        project
        / "base/build/intermediates/incremental/demoRelease/packageDemoReleaseResources"
        / "merger.xml"
    )
    _write(
        module_merger,
        f'''<merger version="3"><dataSet config="main"><source path="{original.parent}">
        <file path="{original}" qualifiers="sw480dp-v13">
        <dimen name="spacing">16dp</dimen></file></source></dataSet></merger>''',
    )
    app_merger = _write(
        project / "app-merger.xml",
        f'''<merger version="3"><dataSet config=":base" from-dependency="true">
        <source path="{packaged.parent.parent}"><file path="{packaged}"
        qualifiers="sw480dp-v13"><dimen name="spacing">16dp</dimen></file>
        </source></dataSet></merger>''',
    )
    side = OwnershipSideConfig(
        project_root=project,
        source_roots=(project / "app/src", project / "base/src"),
        variant="demoRelease",
        artifact_output=project / "app.aab",
    )

    owner = parse_resource_merger(app_merger, side)[
        (":base", "dimen", "sw480dp-v13", "spacing")
    ]

    assert owner.origin is OriginKind.OWNED_SOURCE
    assert owner.source_path == str(original)
    assert owner.module == ":base"


def test_resource_merger_uses_final_overlay_across_repeated_modules(tmp_path: Path) -> None:
    project = tmp_path / "project"
    external_a = tmp_path / "external-a"
    external_b = tmp_path / "external-b"
    local_values = _write(project / "base/src/main/res/values/strings.xml", "<resources />")
    local_drawable = _write(project / "base/src/main/res/drawable/logo.xml", "<shape />")
    external_a_values = _write(external_a / "values/strings.xml", "<resources />")
    external_a_drawable = _write(external_a / "drawable/logo.xml", "<shape />")
    external_b_values = _write(external_b / "values/strings.xml", "<resources />")
    external_b_drawable = _write(external_b / "drawable/logo.xml", "<shape />")
    merger = _write(
        project / "merger.xml",
        f'''<merger version="3">
        <dataSet config="external-a" from-dependency="true"><source path="{external_a}">
        <file path="{external_a_values}" qualifiers=""><string name="title">A</string></file>
        <file path="{external_a_drawable}" qualifiers="" type="drawable" name="logo" />
        </source></dataSet>
        <dataSet config="base"><source path="{local_values.parent}">
        <file path="{local_values}" qualifiers=""><string name="title">Local</string></file>
        </source><source path="{local_drawable.parent}">
        <file path="{local_drawable}" qualifiers="" type="drawable" name="logo" />
        </source></dataSet>
        <dataSet config="external-b" from-dependency="true"><source path="{external_b}">
        <file path="{external_b_values}" qualifiers=""><string name="title">B</string></file>
        <file path="{external_b_drawable}" qualifiers="" type="drawable" name="logo" />
        </source></dataSet></merger>''',
    )
    side = OwnershipSideConfig(
        project_root=project,
        source_roots=(project / "base/src",),
        variant="demoRelease",
        artifact_output=project / "app.aab",
    )

    provenance = parse_resource_merger(merger, side)
    values_owner = ownership._inventory_owner(("string", "", "title"), provenance)
    raw = BundleProfile(
        "/tmp/app.aab",
        "sha",
        1,
        ["base"],
        {},
        files=[
            FileFingerprint("base/res/drawable/logo.xml", "base", "resource", 1, "logo")
        ],
    )
    owned, _ = attribute_owned_profile(raw, ownership.OwnershipManifest(), {}, provenance)

    assert values_owner is not None
    assert values_owner.origin is OriginKind.PUBLIC_DEPENDENCY
    assert values_owner.source_path == str(external_b_values)
    assert owned.files == []


def test_attribute_profile_excludes_asset_when_final_aab_content_differs_from_owned_source(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    _write(project / "app/src/main/assets/models/matcher.bin", "owned")
    side = OwnershipSideConfig(
        project_root=project,
        source_roots=(project / "app/src",),
        variant="demoRelease",
        artifact_output=project / "app.aab",
    )
    profile = BundleProfile(
        "/tmp/app.aab",
        "sha",
        1,
        ["base"],
        {},
        files=[
            FileFingerprint(
                "base/assets/models/matcher.bin",
                "base",
                "asset",
                10,
                hashlib.sha256(b"dependency").hexdigest(),
            )
        ],
    )

    owned, attribution = attribute_owned_profile(profile, build_source_ownership(side), {})

    assert owned.files == []
    assert attribution.unresolved == 1


def test_attribute_profile_requires_r8_and_resource_merger_provenance(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write(
        project / "app/src/main/java/com/example/Feature.kt", "package com.example\nclass Feature"
    )
    _write(project / "app/src/main/res/drawable/logo.webp", "image")
    config_path = tmp_path / "ownership.toml"
    side = f'''project_root = "{project}"
source_roots = ["app/src"]
variant = "demoRelease"
artifact_output = "app.aab"'''
    config_path.write_text(f"[left]\n{side}\n[right]\n{side}", encoding="utf-8")
    source = build_source_ownership(load_ownership_config(config_path).left)
    resource_provenance = {
        (":app", "drawable", "", "logo"): source.entries[-1],
        (":external", "drawable", "", "library"): OwnershipEntry(
            "drawable:library",
            "image",
            OriginKind.PUBLIC_DEPENDENCY,
            "/deps/library.webp",
            ":external",
        ),
        (":app", "drawable", "", "generated"): OwnershipEntry(
            "drawable:generated",
            "image",
            OriginKind.TOOL_GENERATED,
            "/build/generated.webp",
            ":app",
        ),
    }
    profile = BundleProfile(
        "/tmp/app.aab",
        "sha",
        1,
        ["base"],
        {},
        methods=[_method("La/b;"), _method("Lcom/example/Feature;")],
        files=[
            FileFingerprint("base/res/drawable/logo.webp", "base", "image", 1, "logo"),
            FileFingerprint("base/res/drawable/library.webp", "base", "image", 1, "library"),
            FileFingerprint("base/res/drawable/generated.webp", "base", "image", 1, "generated"),
            FileFingerprint("base/res/drawable/unknown.webp", "base", "image", 1, "unknown"),
        ],
        images=[
            ImageFingerprint("base/res/drawable/logo.webp", "base", 1, "logo", None, None, None),
            ImageFingerprint(
                "base/res/drawable/library.webp", "base", 1, "library", None, None, None
            ),
        ],
    )

    owned, attribution = attribute_owned_profile(
        profile,
        source,
        parse_r8_mapping("com.example.Feature -> a.b:"),
        resource_provenance,
    )

    assert [method.class_name for method in owned.methods] == ["La/b;"]
    assert owned.methods[0].origin == OriginKind.OWNED_SOURCE.value
    assert owned.methods[0].source_path.endswith("Feature.kt")
    assert [item.path for item in owned.files] == ["base/res/drawable/logo.webp"]
    assert owned.files[0].origin == OriginKind.OWNED_SOURCE.value
    assert owned.files[0].source_path.endswith("logo.webp")
    assert [image.path for image in owned.images] == ["base/res/drawable/logo.webp"]
    assert owned.images[0].origin == OriginKind.OWNED_SOURCE.value
    assert attribution.public_dependency == 1
    assert attribution.tool_generated == 1
    assert attribution.unresolved == 2


def test_attribute_profile_excludes_mixed_r8_ownership(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write(
        project / "app/src/main/java/com/example/Feature.java",
        "package com.example; class Feature {}",
    )
    config_path = tmp_path / "ownership.toml"
    side = f'''project_root = "{project}"
source_roots = ["app/src"]
variant = "demoRelease"
artifact_output = "app.aab"'''
    config_path.write_text(f"[left]\n{side}\n[right]\n{side}", encoding="utf-8")

    owned, attribution = attribute_owned_profile(
        BundleProfile("/tmp/app.aab", "sha", 1, ["base"], {}, methods=[_method("La/b;")]),
        build_source_ownership(load_ownership_config(config_path).left),
        {"La/b;": {"Lcom/example/Feature;", "Lthird/Party;"}},
    )

    assert owned.methods == []
    assert attribution.unresolved == 1


@pytest.mark.parametrize(
    ("left_origin", "right_origin"),
    [
        (OriginKind.OWNED_SOURCE, OriginKind.OWNED_SOURCE),
        (OriginKind.OWNED_SOURCE, OriginKind.OWNED_GENERATED),
    ],
)
def test_attribute_profile_excludes_descriptor_with_non_unique_provenance_identity(
    left_origin: OriginKind,
    right_origin: OriginKind,
) -> None:
    descriptor = "Lcom/example/Duplicate;"
    source = ownership.OwnershipManifest(
        entries=[
            OwnershipEntry(descriptor, "code", left_origin, "/src/first.kt", ":app"),
            OwnershipEntry(descriptor, "code", right_origin, "/src/second.kt", ":app"),
        ]
    )
    profile = BundleProfile(
        "/tmp/app.aab",
        "sha",
        1,
        ["base"],
        {},
        methods=[_method("La/b;")],
    )

    owned, attribution = attribute_owned_profile(profile, source, {"La/b;": {descriptor}})

    assert owned.methods == []
    assert attribution.unresolved == 1


def test_source_ownership_scans_release_variant_and_res_im_but_not_other_generated(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    _write(
        project / "app/src/release/java/com/example/Release.java",
        "package com.example; class Release {}",
    )
    _write(
        project / "app/src/demoRelease/java/com/example/Variant.java",
        "package com.example; class Variant {}",
    )
    _write(project / "app/src/main/res-im/drawable/icon.webp", "image")
    _write(project / "app/build/generated/res/not-owned/drawable/generated.webp", "image")
    config_path = tmp_path / "ownership.toml"
    side = f'''project_root = "{project}"
source_roots = ["app/src"]
variant = "demoRelease"
artifact_output = "app.aab"'''
    config_path.write_text(f"[left]\n{side}\n[right]\n{side}", encoding="utf-8")

    manifest = build_source_ownership(load_ownership_config(config_path).left)

    assert {"Lcom/example/Release;", "Lcom/example/Variant;"} <= manifest.owned_class_descriptors
    assert any(entry.identifier == "drawable:icon" for entry in manifest.entries)
    assert all("not-owned" not in entry.source_path for entry in manifest.entries)


def test_owned_manifest_features_keep_duplicate_source_nodes_and_randomized_names(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    _write(
        project / "app/src/main/AndroidManifest.xml",
        """<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application>
        <activity android:name="a.b.C" android:exported="true" />
        <activity android:name="a.b.C" android:exported="true" />
        </application></manifest>""",
    )
    config_path = tmp_path / "ownership.toml"
    side = f'''project_root = "{project}"
source_roots = ["app/src"]
variant = "demoRelease"
artifact_output = "app.aab"'''
    config_path.write_text(f"[left]\n{side}\n[right]\n{side}", encoding="utf-8")

    features = ownership.build_owned_manifest_features(
        build_source_ownership(load_ownership_config(config_path).left)
    )

    assert features == ["activity:name=a.b.C|exported=true", "activity:name=a.b.C|exported=true"]


def test_discover_validate_and_read_embedded_provenance_without_writing(tmp_path: Path) -> None:
    import zipfile

    project = tmp_path / "project"
    artifact = _write(project / "app/build/outputs/bundle/demoRelease/app.aab", "artifact")
    mapping = _write(
        project / "app/build/outputs/mapping/demoRelease/mapping.txt", "com.example.Feature -> a.b:"
    )
    merger = _write(
        project
        / "app/build/intermediates/incremental/demoRelease/mergeDemoReleaseResources/merger.xml",
        "<merger />",
    )
    config_path = tmp_path / "ownership.toml"
    side = f'''project_root = "{project}"
source_roots = ["app/src"]
variant = "demoRelease"
artifact_output = "{artifact}"'''
    config_path.write_text(f"[left]\n{side}\n[right]\n{side}", encoding="utf-8")
    side_config = load_ownership_config(config_path).left

    paths = ownership.discover_provenance(side_config)
    ownership.validate_provenance(paths, side_config)
    assert paths.r8_mapping == mapping
    assert paths.resource_merger == merger

    embedded = tmp_path / "embedded.aab"
    with zipfile.ZipFile(embedded, "w") as archive:
        archive.writestr(
            "BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map",
            "com.example.Feature -> a.b:",
        )
    assert ownership.load_embedded_r8_mapping(embedded) == parse_r8_mapping(
        "com.example.Feature -> a.b:"
    )


def test_embedded_mapping_prefers_canonical_agp_metadata_entry(tmp_path: Path) -> None:
    artifact = _write_minimal_aab(
        tmp_path / "embedded.aab",
        {
            "BUNDLE-METADATA/a-fallback/proguard.map": "com.example.Fallback -> z.y:",
            "BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map": (
                "com.example.Canonical -> a.b:"
            ),
        },
    )

    assert ownership.load_embedded_r8_mapping(artifact) == parse_r8_mapping(
        "com.example.Canonical -> a.b:"
    )


def test_embedded_mapping_falls_back_when_canonical_entry_is_unusable(tmp_path: Path) -> None:
    artifact = _write_minimal_aab(
        tmp_path / "embedded.aab",
        {
            "BUNDLE-METADATA/a-fallback/proguard.map": "com.example.Fallback -> z.y:",
            "BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map": "# empty",
        },
    )

    assert ownership.load_embedded_r8_mapping(artifact) == parse_r8_mapping(
        "com.example.Fallback -> z.y:"
    )


def test_embedded_mapping_rejects_oversized_member_before_reading(tmp_path: Path) -> None:
    artifact = _write_minimal_aab(
        tmp_path / "oversized.aab",
        {
            "BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map": (
                "com.example.Feature -> a.b:\n" * 100
            ),
        },
        compression=8,
    )

    with pytest.raises(ArchiveSecurityError, match="entry exceeds size limit"):
        ownership.load_embedded_r8_mapping(artifact, ArchiveLimits(max_entry_size=16))


def test_embedded_mapping_rejects_unsafe_compression_ratio_before_reading(
    tmp_path: Path,
) -> None:
    artifact = _write_minimal_aab(
        tmp_path / "compressed.aab",
        {
            "BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map": (
                "com.example.Feature -> a.b:\n" * 100
            ),
        },
        compression=8,
    )

    with pytest.raises(ArchiveSecurityError, match="compression ratio is unsafe"):
        ownership.load_embedded_r8_mapping(
            artifact, ArchiveLimits(max_compression_ratio=2.0)
        )


@pytest.mark.skipif(os.name != "posix", reason="requires replacing an open archive")
def test_embedded_mapping_reads_from_the_same_archive_identity_it_validates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canonical = "BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map"
    safe_mapping = "com.example.Safe -> a.b:"
    replacement_mapping = "com.example.Replacement -> z.y:\n" * 100
    artifact = _write_minimal_aab(
        tmp_path / "embedded.aab",
        {canonical: safe_mapping},
    )
    replacement = _write_minimal_aab(
        tmp_path / "replacement.aab",
        {canonical: replacement_mapping},
    )
    validate_member = archive_module._validate_member
    swapped = False

    def replace_archive_after_member_validation(
        info: object,
        limits: ArchiveLimits,
    ) -> None:
        nonlocal swapped
        validate_member(info, limits)  # type: ignore[arg-type]
        if not swapped and getattr(info, "filename", None) == canonical:
            swapped = True
            replacement.replace(artifact)

    monkeypatch.setattr(
        archive_module,
        "_validate_member",
        replace_archive_after_member_validation,
    )

    mapping = ownership.load_embedded_r8_mapping(
        artifact,
        ArchiveLimits(max_entry_size=64),
    )

    assert swapped
    assert mapping == parse_r8_mapping(safe_mapping)


def test_provenance_lock_is_deterministic_and_binds_all_consumed_mergers(
    tmp_path: Path,
) -> None:
    import os
    import time
    import zipfile

    project = tmp_path / "project"
    _write(
        project / "app/src/main/java/com/example/Feature.java",
        "package com.example; class Feature {}",
    )
    package_merger = _write(
        project
        / "app/build/intermediates/incremental/demoRelease/packageDemoReleaseResources/merger.xml",
        "<merger />",
    )
    final_merger = _write(
        project
        / "app/build/intermediates/incremental/demoRelease/mergeDemoReleaseResources/merger.xml",
        "<merger />",
    )
    artifact = project / "app/build/outputs/bundle/demoRelease/app.aab"
    artifact.parent.mkdir(parents=True)
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr(
            "BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map",
            "com.example.Feature -> a.b:",
        )
    hardening_report = _write(
        project / "app/build/reports/hardening/demoRelease/bundle-verification.json",
        json.dumps(
            {
                "variant": "demoRelease",
                "hardenedAabSha256": ownership._sha256(artifact),
            }
        ),
    )
    side = OwnershipSideConfig(
        project_root=project,
        source_roots=(project / "app/src",),
        variant="demoRelease",
        artifact_output=artifact,
    )
    lock_path = tmp_path / "cache/provenance.lock.json"
    config = ownership.OwnershipConfig(
        left=side,
        right=side,
        schema_version=2,
        provenance_lock=lock_path,
    )
    old = time.time() - 10 * 24 * 60 * 60
    os.utime(package_merger, (old, old))

    ownership.write_provenance_lock(config)
    first = lock_path.read_bytes()
    ownership.write_provenance_lock(config)

    assert lock_path.read_bytes() == first
    locked = json.loads(first)
    assert locked["schema_version"] == 1
    assert locked["sides"]["left"]["mapping"]["kind"] == "embedded"
    assert locked["sides"]["left"]["mapping"]["entry"].endswith("proguard.map")
    assert {
        item["path"] for item in locked["sides"]["left"]["resource_mergers"]
    } == {str(package_merger.resolve()), str(final_merger.resolve())}
    assert locked["sides"]["left"]["hardening_report"]["path"] == str(
        hardening_report.resolve()
    )
    assert locked["sides"]["right"] == locked["sides"]["left"]
    lock_mtime = lock_path.stat().st_mtime_ns
    verified = ownership.verify_provenance_lock(config)
    assert verified["left"].resource_merger == final_merger
    assert lock_path.read_bytes() == first
    assert lock_path.stat().st_mtime_ns == lock_mtime

    package_merger.write_text("<merger version=\"changed\" />", encoding="utf-8")
    with pytest.raises(ValueError, match="provenance lock"):
        ownership.verify_provenance_lock(config)


def test_provenance_lock_binds_disk_mapping_and_artifact(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write(project / "app/src/main/java/com/example/Feature.java", "class Feature {}")
    mapping = _write(
        project / "app/build/outputs/mapping/demoRelease/mapping.txt",
        "com.example.Feature -> a.b:",
    )
    _write(
        project
        / "app/build/intermediates/incremental/demoRelease/mergeDemoReleaseResources/merger.xml",
        "<merger />",
    )
    artifact = _write(project / "app/build/outputs/bundle/demoRelease/app.aab", "artifact")
    side = OwnershipSideConfig(
        project_root=project,
        source_roots=(project / "app/src",),
        variant="demoRelease",
        artifact_output=artifact,
    )
    config = ownership.OwnershipConfig(
        left=side,
        right=side,
        schema_version=2,
        provenance_lock=tmp_path / "cache/provenance.lock.json",
    )
    ownership.write_provenance_lock(config)

    mapping.write_text("com.example.Other -> c.d:", encoding="utf-8")

    with pytest.raises(ValueError, match="provenance lock"):
        ownership.verify_provenance_lock(config)

    mapping.write_text("com.example.Feature -> a.b:", encoding="utf-8")
    ownership.verify_provenance_lock(config)
    artifact.write_text("changed artifact", encoding="utf-8")
    with pytest.raises(ValueError, match="provenance lock"):
        ownership.verify_provenance_lock(config)


def test_write_provenance_lock_rejects_artifact_destination_without_modifying_it(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    _write(project / "app/src/main/java/com/example/Feature.java", "class Feature {}")
    _write(
        project / "app/build/outputs/mapping/demoRelease/mapping.txt",
        "com.example.Feature -> a.b:",
    )
    _write(
        project
        / "app/build/intermediates/incremental/demoRelease/mergeDemoReleaseResources/merger.xml",
        "<merger />",
    )
    artifact = _write(tmp_path / "artifacts/release.aab", "original artifact")
    side = OwnershipSideConfig(
        project_root=project,
        source_roots=(project / "app/src",),
        variant="demoRelease",
        artifact_output=artifact,
    )
    config = ownership.OwnershipConfig(
        left=side,
        right=side,
        schema_version=2,
        provenance_lock=artifact,
    )
    original = artifact.read_bytes()

    try:
        with pytest.raises(ValueError, match="provenance_lock must not overlap an artifact"):
            ownership.write_provenance_lock(config)
    finally:
        assert artifact.read_bytes() == original


def _source_bound_provenance_config(
    tmp_path: Path,
) -> tuple[ownership.OwnershipConfig, Path, dict[str, Path]]:
    project = tmp_path / "project"
    source_files = {
        "code": _write(
            project / "app/src/main/java/com/example/Feature.java",
            "package com.example; class Feature {}",
        ),
        "manifest": _write(
            project / "app/src/main/AndroidManifest.xml",
            "<manifest><application><activity name=\"com.example.Feature\" />"
            "</application></manifest>",
        ),
        "resource": _write(
            project / "app/src/main/res/values/strings.xml",
            "<resources><string name=\"app_name\">Demo</string></resources>",
        ),
        "asset": _write(project / "app/src/main/assets/data.txt", "asset"),
        "generated": _write(
            project / "app/build/generated/owned/com/example/Generated.kt",
            "package com.example\nclass Generated",
        ),
    }
    _write(
        project / "app/build/outputs/mapping/demoRelease/mapping.txt",
        "com.example.Feature -> a.b:",
    )
    _write(
        project
        / "app/build/intermediates/incremental/demoRelease/mergeDemoReleaseResources/merger.xml",
        "<merger />",
    )
    artifact = _write(project / "app/build/outputs/bundle/demoRelease/app.aab", "artifact")
    side = OwnershipSideConfig(
        project_root=project,
        source_roots=(project / "app/src",),
        variant="demoRelease",
        artifact_output=artifact,
        owned_generated_roots=(project / "app/build/generated/owned",),
    )
    return (
        ownership.OwnershipConfig(
            left=side,
            right=side,
            schema_version=2,
            provenance_lock=tmp_path / "cache/provenance.lock.json",
        ),
        project,
        source_files,
    )


def test_provenance_lock_binds_consumed_source_inventory(tmp_path: Path) -> None:
    config, project, source_files = _source_bound_provenance_config(tmp_path)

    lock_path = ownership.write_provenance_lock(config)

    locked = json.loads(lock_path.read_text(encoding="utf-8"))
    assert {
        (item["origin"], item["category"], item["path"], item["sha256"])
        for item in locked["sides"]["left"]["source_files"]
    } == {
        (
            OriginKind.OWNED_GENERATED.value
            if label == "generated"
            else OriginKind.OWNED_SOURCE.value,
            "code" if label in {"code", "generated"} else label,
            str(path.resolve()),
            ownership._sha256(path),
        )
        for label, path in source_files.items()
    }
    assert locked["sides"]["right"]["source_files"] == locked["sides"]["left"][
        "source_files"
    ]

    _write(
        project / "app/src/main/java/com/example/Injected.java",
        "package com.example; class Injected {}",
    )
    with pytest.raises(ValueError, match="provenance lock"):
        ownership.verify_provenance_lock(config)


def test_write_provenance_lock_does_not_replace_an_unrelated_file(tmp_path: Path) -> None:
    config, _, _ = _source_bound_provenance_config(tmp_path)
    assert config.provenance_lock is not None
    unrelated = _write(config.provenance_lock, "user data")
    original = unrelated.read_bytes()

    try:
        with pytest.raises(ValueError, match="refusing to overwrite non-provenance-lock file"):
            ownership.write_provenance_lock(config)
    finally:
        assert unrelated.read_bytes() == original


def test_write_provenance_lock_does_not_replace_another_projects_valid_lock(
    tmp_path: Path,
) -> None:
    first, _, _ = _source_bound_provenance_config(tmp_path / "first")
    second, _, _ = _source_bound_provenance_config(tmp_path / "second")
    assert first.provenance_lock is not None
    ownership.write_provenance_lock(first)
    original_lock = first.provenance_lock.read_bytes()
    foreign_destination = ownership.OwnershipConfig(
        left=second.left,
        right=second.right,
        schema_version=2,
        provenance_lock=first.provenance_lock,
    )

    with pytest.raises(ValueError, match="different ownership configuration"):
        ownership.write_provenance_lock(foreign_destination)

    assert first.provenance_lock.read_bytes() == original_lock


def test_write_provenance_lock_does_not_modify_a_hard_link_alias(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _, _ = _source_bound_provenance_config(tmp_path)
    assert config.provenance_lock is not None
    ownership.write_provenance_lock(config)
    original_lock = config.provenance_lock.read_bytes()
    alias = tmp_path / "other-project-provenance.lock.json"
    try:
        os.link(config.provenance_lock, alias)
    except OSError as error:
        pytest.skip(f"hard links are unavailable: {error}")
    current_payload = ownership._current_lock_payload

    def change_payload(*args: object, **kwargs: object) -> object:
        payload, paths = current_payload(*args, **kwargs)  # type: ignore[arg-type]
        payload["sides"]["left"]["variant"] += "-changed"
        return payload, paths

    monkeypatch.setattr(ownership, "_current_lock_payload", change_payload)

    with pytest.raises(ValueError, match="refusing to overwrite non-provenance-lock file"):
        ownership.write_provenance_lock(config)

    assert config.provenance_lock.read_bytes() == original_lock
    assert alias.read_bytes() == original_lock


def test_write_provenance_lock_does_not_replace_file_created_during_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _, _ = _source_bound_provenance_config(tmp_path)
    assert config.provenance_lock is not None
    current_payload = ownership._current_lock_payload

    def create_destination_during_payload(*args: object, **kwargs: object) -> object:
        result = current_payload(*args, **kwargs)  # type: ignore[arg-type]
        _write(config.provenance_lock, "late user data")
        return result

    monkeypatch.setattr(ownership, "_current_lock_payload", create_destination_during_payload)

    with pytest.raises(ValueError, match="provenance_lock destination changed"):
        ownership.write_provenance_lock(config)

    assert config.provenance_lock.read_text(encoding="utf-8") == "late user data"


@pytest.mark.skipif(os.name != "posix", reason="requires replacing an open lock file")
def test_write_provenance_lock_does_not_replace_file_swapped_after_refresh_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _, _ = _source_bound_provenance_config(tmp_path)
    assert config.provenance_lock is not None
    ownership.write_provenance_lock(config)
    original_lock = config.provenance_lock.read_bytes()
    displaced_lock = tmp_path / "displaced-provenance.lock.json"
    current_payload = ownership._current_lock_payload
    require_unchanged = ownership._require_unchanged_lock_destination
    swapped = False

    def change_payload(*args: object, **kwargs: object) -> object:
        payload, paths = current_payload(*args, **kwargs)  # type: ignore[arg-type]
        payload["sides"]["left"]["variant"] += "-changed"
        return payload, paths

    def swap_destination_after_check(*args: object, **kwargs: object) -> None:
        nonlocal swapped
        require_unchanged(*args, **kwargs)  # type: ignore[arg-type]
        if not swapped:
            swapped = True
            config.provenance_lock.replace(displaced_lock)
            _write(config.provenance_lock, "late user data")

    monkeypatch.setattr(ownership, "_current_lock_payload", change_payload)
    monkeypatch.setattr(
        ownership, "_require_unchanged_lock_destination", swap_destination_after_check
    )

    with pytest.raises(ValueError, match="provenance_lock destination changed"):
        ownership.write_provenance_lock(config)

    assert swapped
    assert config.provenance_lock.read_text(encoding="utf-8") == "late user data"
    assert displaced_lock.read_bytes() == original_lock


@pytest.mark.parametrize("source_label", ["code", "manifest", "resource", "asset", "generated"])
def test_provenance_lock_binds_consumed_source_content(
    tmp_path: Path,
    source_label: str,
) -> None:
    config, _, source_files = _source_bound_provenance_config(tmp_path)
    ownership.write_provenance_lock(config)

    source_files[source_label].write_text("changed", encoding="utf-8")

    with pytest.raises(ValueError, match="provenance lock"):
        ownership.verify_provenance_lock(config)


def test_verified_provenance_snapshot_is_immutable_after_live_inputs_change(
    tmp_path: Path,
) -> None:
    config, project, source_files = _source_bound_provenance_config(tmp_path)
    ownership.write_provenance_lock(config)
    side = config.left
    mapping = project / "app/build/outputs/mapping/demoRelease/mapping.txt"
    merger = (
        project
        / "app/build/intermediates/incremental/demoRelease/mergeDemoReleaseResources/merger.xml"
    )

    with ownership.verified_provenance_snapshot(config) as snapshots:
        verified = snapshots["left"]
        source_files["code"].write_text("package com.example; class Other {}", encoding="utf-8")
        source_files["manifest"].write_text(
            "<manifest><application><service name=\"changed\" /></application></manifest>",
            encoding="utf-8",
        )
        source_files["asset"].write_text("changed asset", encoding="utf-8")
        mapping.write_text("com.example.Other -> a.b:", encoding="utf-8")
        merger.write_text("not xml", encoding="utf-8")
        side.artifact_output.write_text("changed artifact", encoding="utf-8")
        raw = BundleProfile(
            str(verified.artifact_path),
            verified.artifact_sha256,
            verified.artifact_path.stat().st_size,
            ["base"],
            {},
            files=[
                FileFingerprint(
                    "base/assets/data.txt",
                    "base",
                    "asset",
                    len(b"asset"),
                    hashlib.sha256(b"asset").hexdigest(),
                )
            ],
            methods=[_method("La/b;")],
        )

        projection = build_owned_projection(
            raw,
            side,
            ownership.AnalysisConfig(),
            verified_provenance=verified,
        )

        assert [method.class_name for method in projection.profile.methods] == ["La/b;"]
        assert [item.path for item in projection.profile.files] == ["base/assets/data.txt"]
        assert projection.profile.manifests == {
            "owned": ["activity:name=com.example.Feature"]
        }
        assert projection.profile.source_path == str(side.artifact_output.resolve())
        assert verified.artifact_path.read_text(encoding="utf-8") == "artifact"


def test_owned_projection_prefers_exact_embedded_mapping_and_keeps_owned_junkcode(
    tmp_path: Path,
) -> None:
    import os
    import time
    import zipfile

    project = tmp_path / "project"
    _write(
        project / "selector/src/main/java/com/luck/picture/lib/LocalCopy.java",
        "package com.luck.picture.lib; public class LocalCopy {}",
    )
    _write(
        project / "app/build/generated/junk/com/example/Junk.java",
        "package com.example; public class Junk {}",
    )
    _write(
        project / "app/src/main/AndroidManifest.xml",
        "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\"><application>"
        "<activity android:name=\"com.example.Local\" /></application></manifest>",
    )
    _write(
        project / "app/build/generated/junk/AndroidManifest.xml",
        "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\"><application>"
        "<service android:name=\"com.example.Junk\" /></application></manifest>",
    )
    artifact = project / "app/build/outputs/bundle/demoRelease/app.aab"
    artifact.parent.mkdir(parents=True)
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr(
            "BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map",
            "com.luck.picture.lib.LocalCopy -> a.b:\ncom.example.Junk -> c.d:",
        )
    disk_mapping = _write(
        project / "app/build/outputs/mapping/demoRelease/mapping.txt",
        "third.party.Stale -> a.b:",
    )
    merger = _write(
        project
        / "app/build/intermediates/incremental/demoRelease/mergeDemoReleaseResources/merger.xml",
        "<merger />",
    )
    old = time.time() - 10 * 24 * 60 * 60
    os.utime(disk_mapping, (old, old))
    os.utime(merger, None)
    os.utime(artifact, None)
    side = OwnershipSideConfig(
        project_root=project,
        source_roots=(project / "app/src", project / "selector/src"),
        variant="demoRelease",
        artifact_output=artifact,
        owned_generated_roots=(project / "app/build/generated/junk",),
    )
    raw = BundleProfile(
        str(artifact.resolve()),
        hashlib.sha256(artifact.read_bytes()).hexdigest(),
        1,
        ["base"],
        {},
        methods=[
            _method("La/b;", third_party=True),
            _method("Lc/d;"),
            _method("Le/f;"),
        ],
    )

    before = sorted(
        (path.relative_to(project).as_posix(), path.read_bytes(), path.stat().st_mtime_ns)
        for path in project.rglob("*")
        if path.is_file()
    )
    projection = build_owned_projection(raw, side, ownership.AnalysisConfig())
    after = sorted(
        (path.relative_to(project).as_posix(), path.read_bytes(), path.stat().st_mtime_ns)
        for path in project.rglob("*")
        if path.is_file()
    )

    assert [method.class_name for method in projection.profile.methods] == ["La/b;", "Lc/d;"]
    assert projection.profile.methods[0].origin == OriginKind.OWNED_SOURCE.value
    assert projection.profile.methods[1].origin == OriginKind.OWNED_GENERATED.value
    assert projection.profile.counts["methods"] == 2
    assert projection.profile.counts["long_methods"] == 0
    assert projection.profile.manifests == {
        "owned": ["service:name=com.example.Junk", "activity:name=com.example.Local"]
    }
    assert [entry.origin for entry in projection.profile.manifest_entries] == [
        OriginKind.OWNED_GENERATED.value,
        OriginKind.OWNED_SOURCE.value,
    ]
    manifest_names = [
        Path(entry.source_path or "").name for entry in projection.profile.manifest_entries
    ]
    assert manifest_names == [
        "AndroidManifest.xml",
        "AndroidManifest.xml",
    ]
    assert projection.attribution.owned_generated == 1
    assert projection.diagnostics["provenance"]["r8_mapping"] == "embedded"
    manifest_metrics = compare_owned_profiles(
        projection.profile, projection.profile, ownership.AnalysisConfig()
    ).dimensions["manifest"].metrics
    assert manifest_metrics["left_origins"] == {
        "OWNED_GENERATED": 1,
        "OWNED_SOURCE": 1,
    }
    assert after == before


def test_owned_projection_rejects_missing_or_stale_required_provenance(tmp_path: Path) -> None:
    import os
    import time
    import zipfile

    project = tmp_path / "project"
    _write(
        project / "app/src/main/java/com/example/Feature.java",
        "package com.example; class Feature {}",
    )
    artifact = project / "app/build/outputs/bundle/demoRelease/app.aab"
    artifact.parent.mkdir(parents=True)
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr(
            "BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map",
            "com.example.Feature -> a.b:",
        )
    side = OwnershipSideConfig(
        project_root=project,
        source_roots=(project / "app/src",),
        variant="demoRelease",
        artifact_output=artifact,
    )
    raw = BundleProfile(
        str(artifact.resolve()), hashlib.sha256(artifact.read_bytes()).hexdigest(), 1, ["base"], {}
    )

    with pytest.raises(ValueError, match="missing resource merger"):
        build_owned_projection(raw, side, ownership.AnalysisConfig())

    merger = _write(
        project
        / "app/build/intermediates/incremental/demoRelease/mergeDemoReleaseResources/merger.xml",
        "<merger />",
    )
    old = time.time() - 10 * 24 * 60 * 60
    os.utime(merger, (old, old))

    with pytest.raises(ValueError, match="stale provenance"):
        build_owned_projection(raw, side, ownership.AnalysisConfig())


def test_owned_projection_includes_verified_values_and_excludes_tool_generated_resvalue(
    tmp_path: Path,
) -> None:
    import zipfile

    project = tmp_path / "project"
    values = _write(project / "app/src/main/res/values/strings.xml", "<resources />")
    generated = _write(
        project / "app/build/generated/res/google/values/values.xml", "<resources />"
    )
    artifact = project / "app/build/outputs/bundle/demoRelease/app.aab"
    artifact.parent.mkdir(parents=True)
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr(
            "BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map",
            "com.example.Feature -> a.b:",
        )
    _write(
        project
        / "app/build/intermediates/incremental/demoRelease/mergeDemoReleaseResources/merger.xml",
        f'''<merger><dataSet config="main"><source path="{values.parent}">
        <file path="{values}" qualifiers=""><string name="app_name">Local</string></file>
        </source><source path="{generated.parent}">
        <file path="{generated}" qualifiers=""><string name="google_app_id">external</string></file>
        </source></dataSet></merger>''',
    )
    side = OwnershipSideConfig(
        project_root=project,
        source_roots=(project / "app/src",),
        variant="demoRelease",
        artifact_output=artifact,
    )

    projection = build_owned_projection(
        BundleProfile(
            str(artifact.resolve()),
            hashlib.sha256(artifact.read_bytes()).hexdigest(),
            1,
            ["base"],
            {},
        ),
        side,
        ownership.AnalysisConfig(),
        verified_resource_inventory={
            ("string", "", "app_name"): "Local",
            ("string", "", "google_app_id"): "external",
        },
    )

    assert [item.path for item in projection.profile.files] == [
        "verified-resources/string/app_name"
    ]
    assert projection.profile.files[0].origin == OriginKind.OWNED_SOURCE.value
    assert projection.diagnostics["compiled_resources"]["unverified"] == []
    assert projection.diagnostics["compiled_resources"] == {
        "expected": 1,
        "covered": 1,
        "complete": True,
        "unverified": [],
    }
    assert projection.profile.counts["owned_files"] == len(projection.profile.files)


def test_owned_projection_tracks_partial_inventory_and_skips_file_backed_resources(
    tmp_path: Path,
) -> None:
    import zipfile

    project = tmp_path / "project"
    values = _write(project / "app/src/main/res/values/strings.xml", "<resources />")
    drawable = _write(project / "app/src/main/res/drawable/logo.xml", "<shape />")
    layout = _write(project / "app/src/main/res/layout/screen.xml", "<LinearLayout />")
    generated = _write(
        project / "app/build/generated/res/google/values/values.xml", "<resources />"
    )
    artifact = project / "app/build/outputs/bundle/demoRelease/app.aab"
    artifact.parent.mkdir(parents=True)
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr(
            "BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map",
            "com.example.Feature -> a.b:",
        )
    _write(
        project
        / "app/build/intermediates/incremental/demoRelease/mergeDemoReleaseResources/merger.xml",
        f'''<merger><dataSet config="main"><source path="{values.parent}">
        <file path="{values}" qualifiers=""><string name="app_name">Local</string></file>
        </source><source path="{generated.parent}">
        <file path="{generated}" qualifiers=""><string name="google_app_id">external</string></file>
        </source><source path="{drawable.parent}">
        <file path="{drawable}" qualifiers="" type="drawable" name="logo" />
        </source><source path="{layout.parent}">
        <file path="{layout}" qualifiers="" type="layout" name="screen" />
        </source></dataSet></merger>''',
    )
    side = OwnershipSideConfig(
        project_root=project,
        source_roots=(project / "app/src",),
        variant="demoRelease",
        artifact_output=artifact,
    )
    raw = BundleProfile(
        str(artifact.resolve()),
        hashlib.sha256(artifact.read_bytes()).hexdigest(),
        1,
        ["base"],
        {},
        files=[
            FileFingerprint("base/res/drawable/logo.xml", "base", "resource", 1, "logo"),
            FileFingerprint("base/res/layout/screen.xml", "base", "resource", 1, "screen"),
        ],
    )

    partial = build_owned_projection(
        raw,
        side,
        ownership.AnalysisConfig(),
        verified_resource_inventory={("string", "", "app_name"): "Local"},
    )
    empty = build_owned_projection(
        raw,
        side,
        ownership.AnalysisConfig(),
        verified_resource_inventory={},
    )

    assert [item.path for item in partial.profile.files] == [
        "base/res/drawable/logo.xml",
        "base/res/layout/screen.xml",
        "verified-resources/string/app_name",
    ]
    assert partial.diagnostics["compiled_resources"]["unverified"] == []
    assert partial.diagnostics["compiled_resources"]["covered"] == 1
    assert partial.diagnostics["compiled_resources"]["complete"] is True
    assert empty.diagnostics["compiled_resources"]["unverified"] == ["string:app_name"]
    assert empty.attribution.unresolved == 1
    assert empty.diagnostics["compiled_resources"]["covered"] == 0


def test_owned_projection_rejects_profile_not_bound_to_target_artifact(tmp_path: Path) -> None:
    import zipfile

    project = tmp_path / "project"
    (project / "app/src").mkdir(parents=True)
    artifact = project / "app/build/outputs/bundle/demoRelease/app.aab"
    artifact.parent.mkdir(parents=True)
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr(
            "BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map",
            "com.example.Feature -> a.b:",
        )
    _write(
        project
        / "app/build/intermediates/incremental/demoRelease/mergeDemoReleaseResources/merger.xml",
        "<merger />",
    )
    other = _write(tmp_path / "other.aab", "other")
    side = OwnershipSideConfig(
        project_root=project,
        source_roots=(project / "app/src",),
        variant="demoRelease",
        artifact_output=artifact,
    )
    raw = BundleProfile(str(other), hashlib.sha256(b"other").hexdigest(), 5, ["base"], {})

    with pytest.raises(ValueError, match="does not match target artifact"):
        build_owned_projection(raw, side, ownership.AnalysisConfig())


def test_owned_projection_rejects_stale_hash_for_target_artifact_path(tmp_path: Path) -> None:
    import zipfile

    project = tmp_path / "project"
    (project / "app/src").mkdir(parents=True)
    artifact = project / "app/build/outputs/bundle/demoRelease/app.aab"
    artifact.parent.mkdir(parents=True)
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr(
            "BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map",
            "com.example.Feature -> a.b:",
        )
    _write(
        project
        / "app/build/intermediates/incremental/demoRelease/mergeDemoReleaseResources/merger.xml",
        "<merger />",
    )
    side = OwnershipSideConfig(
        project_root=project,
        source_roots=(project / "app/src",),
        variant="demoRelease",
        artifact_output=artifact,
    )
    raw = BundleProfile(str(artifact), "stale-sha256", 1, ["base"], {})

    with pytest.raises(ValueError, match="does not match target artifact"):
        build_owned_projection(raw, side, ownership.AnalysisConfig())


def test_attribute_profile_counts_images_once_as_file_views(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write(project / "app/src/main/res/drawable/logo.webp", "logo")
    side = OwnershipSideConfig(
        project_root=project,
        source_roots=(project / "app/src",),
        variant="demoRelease",
        artifact_output=project / "app.aab",
    )
    source = build_source_ownership(side)
    logo = "base/res/drawable/logo.webp"
    public = "base/res/drawable/public.webp"
    unknown = "base/res/drawable/unknown.webp"
    profile = BundleProfile(
        "/tmp/app.aab",
        "sha",
        1,
        ["base"],
        {},
        files=[
            FileFingerprint(logo, "base", "image", 1, "logo"),
            FileFingerprint(public, "base", "image", 1, "public"),
            FileFingerprint(unknown, "base", "image", 1, "unknown"),
        ],
        images=[
            ImageFingerprint(logo, "base", 1, "logo", None, None, None),
            ImageFingerprint(public, "base", 1, "public", None, None, None),
            ImageFingerprint(unknown, "base", 1, "unknown", None, None, None),
        ],
    )
    provenance = {
        (":app", "drawable", "", "logo"): next(
            entry for entry in source.entries if entry.identifier == "drawable:logo"
        ),
        (":external", "drawable", "", "public"): OwnershipEntry(
            "drawable:public",
            "image",
            OriginKind.PUBLIC_DEPENDENCY,
            "/deps/public.webp",
            ":external",
        ),
    }

    owned, attribution = attribute_owned_profile(profile, source, {}, provenance)

    assert [image.path for image in owned.images] == [logo]
    assert attribution.owned_source == 1
    assert attribution.public_dependency == 1
    assert attribution.unresolved == 1


def test_asset_identical_bytes_from_distinct_owned_candidates_are_unresolved(
    tmp_path: Path,
) -> None:
    owned = _write(tmp_path / "source/assets/models/matcher.bin", "same")
    generated = _write(tmp_path / "generated/assets/models/matcher.bin", "same")
    source = ownership.OwnershipManifest(
        entries=[
            OwnershipEntry(
                "asset:models/matcher.bin",
                "asset",
                OriginKind.OWNED_SOURCE,
                str(owned),
                ":app",
            ),
            OwnershipEntry(
                "asset:models/matcher.bin",
                "asset",
                OriginKind.OWNED_GENERATED,
                str(generated),
                ":app",
            ),
        ]
    )
    profile = BundleProfile(
        "/tmp/app.aab",
        "sha",
        1,
        ["base"],
        {},
        files=[
            FileFingerprint(
                "base/assets/models/matcher.bin",
                "base",
                "asset",
                4,
                hashlib.sha256(b"same").hexdigest(),
            )
        ],
    )

    projected, attribution = attribute_owned_profile(profile, source, {})

    assert projected.files == []
    assert attribution.unresolved == 1


def test_validate_provenance_rejects_inputs_older_than_the_target_artifact(tmp_path: Path) -> None:
    import os
    import time

    project = tmp_path / "project"
    mapping = _write(project / "app/build/outputs/mapping/demoRelease/mapping.txt", "a.A -> b:")
    merger = _write(
        project
        / "app/build/intermediates/incremental/demoRelease/mergeDemoReleaseResources/merger.xml",
        "<merger />",
    )
    artifact = _write(project / "app/build/outputs/bundle/demoRelease/app.aab", "artifact")
    old = time.time() - 10 * 24 * 60 * 60
    os.utime(mapping, (old, old))
    os.utime(merger, (old, old))
    config_path = tmp_path / "ownership.toml"
    side = f'''project_root = "{project}"
source_roots = ["app/src"]
variant = "demoRelease"
artifact_output = "{artifact}"'''
    config_path.write_text(f"[left]\n{side}\n[right]\n{side}", encoding="utf-8")

    with pytest.raises(ValueError, match="stale"):
        ownership.validate_provenance(
            ownership.discover_provenance(load_ownership_config(config_path).left),
            load_ownership_config(config_path).left,
        )


def test_validate_provenance_allows_normal_pre_artifact_build_window(tmp_path: Path) -> None:
    import os
    import time

    project = tmp_path / "project"
    mapping = _write(project / "app/build/outputs/mapping/demoRelease/mapping.txt", "a.A -> b:")
    merger = _write(
        project
        / "app/build/intermediates/incremental/demoRelease/mergeDemoReleaseResources/merger.xml",
        "<merger />",
    )
    artifact = _write(project / "app/build/outputs/bundle/demoRelease/app.aab", "artifact")
    now = time.time()
    os.utime(mapping, (now - 120, now - 120))
    os.utime(merger, (now - 120, now - 120))
    os.utime(artifact, (now, now))
    config_path = tmp_path / "ownership.toml"
    side = f'''project_root = "{project}"
source_roots = ["app/src"]
variant = "demoRelease"
artifact_output = "{artifact}"'''
    config_path.write_text(f"[left]\n{side}\n[right]\n{side}", encoding="utf-8")
    side_config = load_ownership_config(config_path).left

    ownership.validate_provenance(ownership.discover_provenance(side_config), side_config)


def test_validate_provenance_rejects_files_older_than_owned_inputs(tmp_path: Path) -> None:
    import os
    import time

    project = tmp_path / "project"
    mapping = _write(project / "app/build/outputs/mapping/demoRelease/mapping.txt", "a.A -> b:")
    merger = _write(
        project
        / "app/build/intermediates/incremental/demoRelease/mergeDemoReleaseResources/merger.xml",
        "<merger />",
    )
    source = _write(project / "app/src/main/java/com/example/Feature.java", "class Feature {}")
    artifact = _write(project / "app/build/outputs/bundle/demoRelease/app.aab", "artifact")
    now = time.time()
    os.utime(mapping, (now - 120, now - 120))
    os.utime(merger, (now - 120, now - 120))
    os.utime(source, (now - 60, now - 60))
    os.utime(artifact, (now, now))
    config_path = tmp_path / "ownership.toml"
    side = f'''project_root = "{project}"
source_roots = ["app/src"]
variant = "demoRelease"
artifact_output = "{artifact}"'''
    config_path.write_text(f"[left]\n{side}\n[right]\n{side}", encoding="utf-8")
    side_config = load_ownership_config(config_path).left

    with pytest.raises(ValueError, match="stale"):
        ownership.validate_provenance(ownership.discover_provenance(side_config), side_config)


def test_resource_provenance_distinguishes_qualifiers_and_compiled_directory_versions(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    _write(project / "app/src/main/res/drawable/logo.webp", "image")
    config_path = tmp_path / "ownership.toml"
    side = f'''project_root = "{project}"
source_roots = ["app/src"]
variant = "demoRelease"
artifact_output = "app.aab"'''
    config_path.write_text(f"[left]\n{side}\n[right]\n{side}", encoding="utf-8")
    source = build_source_ownership(load_ownership_config(config_path).left)
    owned_logo = next(entry for entry in source.entries if entry.identifier == "drawable:logo")
    dependency_logo = OwnershipEntry(
        "drawable:logo",
        "image",
        OriginKind.PUBLIC_DEPENDENCY,
        "/deps/drawable-night/logo.webp",
        ":external",
    )
    profile = BundleProfile(
        "/tmp/app.aab",
        "sha",
        1,
        ["base"],
        {},
        files=[
            FileFingerprint("base/res/drawable/logo.webp", "base", "image", 1, "owned"),
            FileFingerprint(
                "base/res/drawable-night-v8/logo.webp", "base", "image", 1, "dependency"
            ),
        ],
    )

    owned, attribution = attribute_owned_profile(
        profile,
        source,
        {},
        {
            (":app", "drawable", "", "logo"): owned_logo,
            (":external", "drawable", "night-v8", "logo"): dependency_logo,
        },
    )

    assert [item.path for item in owned.files] == ["base/res/drawable/logo.webp"]
    assert attribution.owned_source == 1
    assert attribution.public_dependency == 1


def test_resource_provenance_excludes_ambiguous_cross_module_identity(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write(project / "app/src/main/res/drawable/logo.webp", "image")
    config_path = tmp_path / "ownership.toml"
    side = f'''project_root = "{project}"
source_roots = ["app/src"]
variant = "demoRelease"
artifact_output = "app.aab"'''
    config_path.write_text(f"[left]\n{side}\n[right]\n{side}", encoding="utf-8")
    source = build_source_ownership(load_ownership_config(config_path).left)
    owner = next(entry for entry in source.entries if entry.identifier == "drawable:logo")
    profile = BundleProfile(
        "/tmp/app.aab",
        "sha",
        1,
        ["base"],
        {},
        files=[FileFingerprint("base/res/drawable-night-v8/logo.webp", "base", "image", 1, "x")],
    )

    owned, attribution = attribute_owned_profile(
        profile,
        source,
        {},
        {
            (":app", "drawable", "night", "logo"): owner,
            (":feature", "drawable", "night", "logo"): owner,
        },
    )

    assert owned.files == []
    assert attribution.unresolved == 1


@pytest.mark.parametrize(
    ("sources", "generated"),
    [
        (["Feature", "OtherFeature"], False),
        (["Feature", "Junk"], True),
    ],
)
def test_attribute_profile_excludes_r8_mappings_with_distinct_owned_provenance(
    tmp_path: Path,
    sources: list[str],
    generated: bool,
) -> None:
    project = tmp_path / "project"
    _write(
        project / "app/src/main/java/com/example/Feature.java",
        "package com.example; class Feature {}",
    )
    if generated:
        _write(
            project / "app/build/generated/junk/com/example/Junk.java",
            "package com.example; class Junk {}",
        )
    else:
        _write(
            project / "app/src/main/java/com/example/OtherFeature.java",
            "package com.example; class OtherFeature {}",
        )
    generated_roots = 'owned_generated_roots = ["app/build/generated/junk"]' if generated else ""
    config_path = tmp_path / "ownership.toml"
    side = f'''project_root = "{project}"
source_roots = ["app/src"]
variant = "demoRelease"
artifact_output = "app.aab"
{generated_roots}'''
    config_path.write_text(f"[left]\n{side}\n[right]\n{side}", encoding="utf-8")

    owned, attribution = attribute_owned_profile(
        BundleProfile("/tmp/app.aab", "sha", 1, ["base"], {}, methods=[_method("La/b;")]),
        build_source_ownership(load_ownership_config(config_path).left),
        {"La/b;": {*(f"Lcom/example/{name};" for name in sources)}},
    )

    assert owned.methods == []
    assert attribution.unresolved == 1


def test_attribute_profile_allows_r8_inner_classes_from_one_owner(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write(
        project / "app/src/main/java/com/example/Feature.java",
        "package com.example; class Feature {}",
    )
    config_path = tmp_path / "ownership.toml"
    side = f'''project_root = "{project}"
source_roots = ["app/src"]
variant = "demoRelease"
artifact_output = "app.aab"'''
    config_path.write_text(f"[left]\n{side}\n[right]\n{side}", encoding="utf-8")

    owned, attribution = attribute_owned_profile(
        BundleProfile("/tmp/app.aab", "sha", 1, ["base"], {}, methods=[_method("La/b;")]),
        build_source_ownership(load_ownership_config(config_path).left),
        {"La/b;": {"Lcom/example/Feature$One;", "Lcom/example/Feature$Two;"}},
    )

    assert [method.class_name for method in owned.methods] == ["La/b;"]
    assert attribution.owned_source == 1


def test_hardening_history_hash_does_not_validate_stale_provenance(tmp_path: Path) -> None:
    import os
    import time

    project = tmp_path / "project"
    mapping = _write(project / "app/build/outputs/mapping/demoRelease/mapping.txt", "a.A -> b:")
    merger = _write(
        project
        / "app/build/intermediates/incremental/demoRelease/mergeDemoReleaseResources/merger.xml",
        "<merger />",
    )
    artifact = _write(project / "app/build/outputs/bundle/demoRelease/app.aab", "artifact")
    report = project / "app/build/reports/hardening/demoRelease/bundle-verification.json"
    _write(
        report,
        json.dumps(
            {
                "variant": "demoRelease",
                "history": {"hardenedAabSha256": ownership._sha256(artifact)},
            }
        ),
    )
    old = time.time() - 10 * 24 * 60 * 60
    os.utime(mapping, (old, old))
    os.utime(merger, (old, old))
    config_path = tmp_path / "ownership.toml"
    side = f'''project_root = "{project}"
source_roots = ["app/src"]
variant = "demoRelease"
artifact_output = "{artifact}"'''
    config_path.write_text(f"[left]\n{side}\n[right]\n{side}", encoding="utf-8")
    side_config = load_ownership_config(config_path).left

    with pytest.raises(ValueError, match="stale"):
        ownership.validate_provenance(ownership.discover_provenance(side_config), side_config)


def test_exact_hardening_record_does_not_validate_stale_provenance(tmp_path: Path) -> None:
    import os
    import time

    project = tmp_path / "project"
    mapping = _write(project / "app/build/outputs/mapping/demoRelease/mapping.txt", "a.A -> b:")
    merger = _write(
        project
        / "app/build/intermediates/incremental/demoRelease/mergeDemoReleaseResources/merger.xml",
        "<merger />",
    )
    artifact = _write(project / "app/build/outputs/bundle/demoRelease/app.aab", "artifact")
    _write(
        project / "app/build/reports/hardening/demoRelease/bundle-verification.json",
        f'{{"variant": "demoRelease", "hardenedAabSha256": "{ownership._sha256(artifact)}"}}',
    )
    old = time.time() - 10 * 24 * 60 * 60
    os.utime(mapping, (old, old))
    os.utime(merger, (old, old))
    config_path = tmp_path / "ownership.toml"
    side = f'''project_root = "{project}"
source_roots = ["app/src"]
variant = "demoRelease"
artifact_output = "{artifact}"'''
    config_path.write_text(f"[left]\n{side}\n[right]\n{side}", encoding="utf-8")
    side_config = load_ownership_config(config_path).left

    with pytest.raises(ValueError, match="stale"):
        ownership.validate_provenance(ownership.discover_provenance(side_config), side_config)


def test_validate_provenance_does_not_require_merger_to_follow_java_input(tmp_path: Path) -> None:
    import os
    import time

    project = tmp_path / "project"
    mapping = _write(project / "app/build/outputs/mapping/demoRelease/mapping.txt", "a.A -> b:")
    merger = _write(
        project
        / "app/build/intermediates/incremental/demoRelease/mergeDemoReleaseResources/merger.xml",
        "<merger />",
    )
    source = _write(project / "app/src/main/java/com/example/Feature.java", "class Feature {}")
    artifact = _write(project / "app/build/outputs/bundle/demoRelease/app.aab", "artifact")
    now = time.time()
    os.utime(merger, (now - 180, now - 180))
    os.utime(source, (now - 120, now - 120))
    os.utime(mapping, (now - 60, now - 60))
    os.utime(artifact, (now, now))
    config_path = tmp_path / "ownership.toml"
    side = f'''project_root = "{project}"
source_roots = ["app/src"]
variant = "demoRelease"
artifact_output = "{artifact}"'''
    config_path.write_text(f"[left]\n{side}\n[right]\n{side}", encoding="utf-8")
    side_config = load_ownership_config(config_path).left

    ownership.validate_provenance(ownership.discover_provenance(side_config), side_config)


def test_validate_provenance_does_not_require_mapping_to_follow_resource_input(
    tmp_path: Path,
) -> None:
    import os
    import time

    project = tmp_path / "project"
    mapping = _write(project / "app/build/outputs/mapping/demoRelease/mapping.txt", "a.A -> b:")
    merger = _write(
        project
        / "app/build/intermediates/incremental/demoRelease/mergeDemoReleaseResources/merger.xml",
        "<merger />",
    )
    resource = _write(project / "app/src/main/res/drawable/logo.xml", "<shape />")
    artifact = _write(project / "app/build/outputs/bundle/demoRelease/app.aab", "artifact")
    now = time.time()
    os.utime(mapping, (now - 180, now - 180))
    os.utime(resource, (now - 120, now - 120))
    os.utime(merger, (now - 60, now - 60))
    os.utime(artifact, (now, now))
    config_path = tmp_path / "ownership.toml"
    side = f'''project_root = "{project}"
source_roots = ["app/src"]
variant = "demoRelease"
artifact_output = "{artifact}"'''
    config_path.write_text(f"[left]\n{side}\n[right]\n{side}", encoding="utf-8")
    side_config = load_ownership_config(config_path).left

    ownership.validate_provenance(ownership.discover_provenance(side_config), side_config)


def test_exact_hardening_record_rejects_source_newer_than_artifact(tmp_path: Path) -> None:
    import os
    import time

    project = tmp_path / "project"
    mapping = _write(project / "app/build/outputs/mapping/demoRelease/mapping.txt", "a.A -> b:")
    merger = _write(
        project
        / "app/build/intermediates/incremental/demoRelease/mergeDemoReleaseResources/merger.xml",
        "<merger />",
    )
    artifact = _write(project / "app/build/outputs/bundle/demoRelease/app.aab", "artifact")
    source = _write(project / "app/src/main/java/com/example/Feature.java", "class Feature {}")
    _write(
        project / "app/build/reports/hardening/demoRelease/bundle-verification.json",
        f'{{"variant": "demoRelease", "hardenedAabSha256": "{ownership._sha256(artifact)}"}}',
    )
    now = time.time()
    os.utime(mapping, (now - 180, now - 180))
    os.utime(merger, (now - 180, now - 180))
    os.utime(artifact, (now - 120, now - 120))
    os.utime(source, (now - 60, now - 60))
    config_path = tmp_path / "ownership.toml"
    side = f'''project_root = "{project}"
source_roots = ["app/src"]
variant = "demoRelease"
artifact_output = "{artifact}"'''
    config_path.write_text(f"[left]\n{side}\n[right]\n{side}", encoding="utf-8")
    side_config = load_ownership_config(config_path).left

    with pytest.raises(ValueError, match="stale"):
        ownership.validate_provenance(ownership.discover_provenance(side_config), side_config)
