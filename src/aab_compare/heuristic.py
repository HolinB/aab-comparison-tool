from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
from typing import TypeVar
from urllib.parse import urlsplit

from .config import AnalysisConfig
from .models import (
    BundleProfile,
    FileFingerprint,
    ImageFingerprint,
    ManifestFingerprint,
    MethodFingerprint,
)
from .ownership import AttributionSummary, OriginKind, OwnedProjection
from .tools import ManifestDetails

_GENERATED_CLASS = re.compile(
    r"(?:/R(?:\$[^;]+)?|/BR|/BuildConfig|/Manifest);$|"
    r"/(?:data|view)binding/[^;]*Binding;$|"
    r"/(?:Dagger|Hilt_|_Factory|_MembersInjector)[^;]*;$"
)
_PUBLIC_RESOURCE_PREFIXES = (
    "$m3_",
    "abc_",
    "activity_browse",
    "alert_dialog_",
    "avatar_view_",
    "avd_",
    "back_title_bar_",
    "blue_noise",
    "bottom_choice_dialog_",
    "browser_actions_",
    "brvah_",
    "btn_checkbox_",
    "btn_radio_",
    "choice_dialog_",
    "clearable_edit_",
    "com_facebook_",
    "common_act_",
    "common_confirm_dialog_",
    "common_crop_image_",
    "common_dialog_photo_choice",
    "common_full_open_on_phone",
    "common_google_",
    "common_title_bar_",
    "compat_splash_screen",
    "confirm_dialog_",
    "content_pop_list_",
    "custom_dialog",
    "design_",
    "dialog_date_picker",
    "exo_",
    "facebook_",
    "fingerprint_",
    "firebase_",
    "fragment_close_",
    "fragment_open_",
    "googleg_",
    "ic_call_",
    "ic_back",
    "ic_clear_black_",
    "ic_clock_black_",
    "ic_keyboard_black_",
    "ic_list_empty",
    "ic_m3_",
    "ic_mtrl_",
    "ic_other_sign_in",
    "ic_passkey",
    "ic_password",
    "ic_search_black",
    "ic_yunxin",
    "ime_secondary_split_test_",
    "icon_exo_",
    "ksw_",
    "list_alert_dialog_",
    "loading",
    "loading_dialog_",
    "m3_",
    "material_",
    "media3_",
    "messenger_",
    "mtrl_",
    "notify_panel_",
    "notification_",
    "pager_navigator_",
    "picture_",
    "ps_",
    "roboto_",
    "sentry_",
    "select_dialog_",
    "splash_screen_",
    "indeterminate_",
    "srl_",
    "ucrop_",
)
_TOOL_RESOURCE_PREFIXES = (
    "crashlytics_",
    "databinding_",
    "google_services",
)
_PUBLIC_ASSET_PREFIXES = (
    "appsflyer/",
    "chatkit/",
    "com/appsflyer/",
    "com.google/",
    "facebook/",
    "firebase/",
    "nim/",
    "notocoloremojicompat.ttf",
    "sentry/",
)
_PUBLIC_MANIFEST_HOST_LABELS = frozenset(
    {
        "airbnb",
        "appsflyer",
        "facebook",
        "firebase",
        "google",
        "netease",
        "objectbox",
        "sentry",
        "squareup",
        "tencent",
        "yalantis",
        "yunxin",
    }
)
_Fingerprint = TypeVar("_Fingerprint", MethodFingerprint, FileFingerprint, ImageFingerprint)


def _dependency_prefixes(profile: BundleProfile) -> tuple[str, ...]:
    prefixes = {
        "L" + dependency.split(":", 1)[0].replace(".", "/") + "/"
        for dependency in profile.dependencies
        if ":" in dependency and "." in dependency.split(":", 1)[0]
    }
    return tuple(sorted(prefixes))


def _descriptor_prefix(package_name: str) -> str:
    return "L" + package_name.replace(".", "/").rstrip("/") + "/"


def _inferred_prefixes(details: Mapping[str, ManifestDetails]) -> tuple[str, ...]:
    packages = {
        item.package_name
        for item in details.values()
        if item.package_name
    }
    return tuple(sorted(_descriptor_prefix(package) for package in packages))


def _copy_with_origin(item: _Fingerprint) -> _Fingerprint:
    copied = deepcopy(item)
    copied.origin = OriginKind.HEURISTIC_OWNED.value
    path = copied.dex_path if isinstance(copied, MethodFingerprint) else copied.path
    copied.source_path = f"aab://{path}"
    return copied


def _resource_name(path: str) -> str:
    name = Path(path).name.removesuffix(".9.png").split(".", 1)[0].lower()
    return re.sub(r"__\d+$", "", name.lstrip("$"))


def _file_origin(path: str, category: str) -> OriginKind:
    lowered = path.lower()
    name = _resource_name(path)
    if category == "native":
        return OriginKind.PUBLIC_DEPENDENCY
    if category == "asset":
        asset_path = lowered.split("/assets/", 1)[-1]
        if asset_path.startswith(_PUBLIC_ASSET_PREFIXES):
            return OriginKind.PUBLIC_DEPENDENCY
        return OriginKind.HEURISTIC_OWNED
    if name.startswith(_TOOL_RESOURCE_PREFIXES):
        return OriginKind.TOOL_GENERATED
    if name.startswith(_PUBLIC_RESOURCE_PREFIXES):
        return OriginKind.PUBLIC_DEPENDENCY
    return OriginKind.HEURISTIC_OWNED


def _is_public_dotted(value: str, public_prefixes: tuple[str, ...]) -> bool:
    if "://" in value:
        hostname = urlsplit(value).hostname or ""
        if set(hostname.lower().split(".")) & _PUBLIC_MANIFEST_HOST_LABELS:
            return True
    descriptor = "L" + value.replace(".", "/")
    return descriptor.startswith(public_prefixes)


def _manifest_entries(
    details: Mapping[str, ManifestDetails],
    public_prefixes: tuple[str, ...],
) -> tuple[list[ManifestFingerprint], int]:
    entries: list[tuple[int, ManifestFingerprint]] = []
    public_count = 0
    for module, manifest in sorted(details.items()):
        source = f"aab://{module}/manifest/AndroidManifest.xml"
        for tag, name in manifest.components:
            if _is_public_dotted(name, public_prefixes):
                public_count += 1
                continue
            entries.append(
                (
                    0,
                    ManifestFingerprint(
                        f"{tag}:name={name}",
                        OriginKind.HEURISTIC_OWNED.value,
                        source,
                    ),
                )
            )
        for action in manifest.actions:
            if action.startswith("android."):
                continue
            if _is_public_dotted(action, public_prefixes):
                public_count += 1
            else:
                entries.append(
                    (
                        1,
                        ManifestFingerprint(
                            f"action:name={action}",
                            OriginKind.HEURISTIC_OWNED.value,
                            source,
                        ),
                    )
                )
        for permission in manifest.permissions:
            if permission.startswith("android."):
                continue
            if _is_public_dotted(permission, public_prefixes):
                public_count += 1
            else:
                entries.append(
                    (
                        2,
                        ManifestFingerprint(
                            f"permission:name={permission}",
                            OriginKind.HEURISTIC_OWNED.value,
                            source,
                        ),
                    )
                )
    ordered = [entry for _, entry in sorted(entries, key=lambda item: (item[0], item[1].value))]
    return ordered, public_count


def build_heuristic_projection(
    raw_profile: BundleProfile,
    config: AnalysisConfig,
    *,
    manifest_details: Mapping[str, ManifestDetails] | None = None,
) -> OwnedProjection:
    details = manifest_details or {}
    inferred = _inferred_prefixes(details)
    public_prefixes = tuple(
        sorted(set(config.third_party_prefixes) | set(_dependency_prefixes(raw_profile)))
    )
    business_prefixes = tuple(config.business_prefixes) + inferred
    counts: Counter[OriginKind] = Counter()
    kept_methods = []
    code_confidences: list[float] = []
    for method in raw_profile.methods:
        class_name = method.class_name
        if _GENERATED_CLASS.search(class_name):
            counts[OriginKind.TOOL_GENERATED] += 1
            continue
        if class_name.startswith(business_prefixes):
            confidence = 0.75
        elif class_name.startswith(public_prefixes) or method.third_party:
            counts[OriginKind.PUBLIC_DEPENDENCY] += 1
            continue
        else:
            confidence = 0.45
        method_copy = _copy_with_origin(method)
        method_copy.third_party = False
        kept_methods.append(method_copy)
        code_confidences.append(confidence)
        counts[OriginKind.HEURISTIC_OWNED] += 1

    kept_files = []
    kept_paths: set[str] = set()
    for item in raw_profile.files:
        origin = _file_origin(item.path, item.category)
        counts[origin] += 1
        if origin is OriginKind.HEURISTIC_OWNED:
            file_copy = _copy_with_origin(item)
            kept_files.append(file_copy)
            kept_paths.add(item.path)
    kept_images = [
        _copy_with_origin(image) for image in raw_profile.images if image.path in kept_paths
    ]
    manifest_entries, public_manifest_count = _manifest_entries(details, public_prefixes)
    counts[OriginKind.HEURISTIC_OWNED] += len(manifest_entries)
    counts[OriginKind.PUBLIC_DEPENDENCY] += public_manifest_count

    profile = deepcopy(raw_profile)
    profile.methods = sorted(kept_methods, key=lambda item: item.identifier)
    profile.files = sorted(kept_files, key=lambda item: item.path)
    profile.images = sorted(kept_images, key=lambda item: item.path)
    profile.manifest_entries = manifest_entries
    profile.manifests = {"heuristic": [entry.value for entry in manifest_entries]}
    profile.counts = dict(profile.counts)
    profile.counts.update(
        candidate_methods=len(profile.methods),
        methods=len(profile.methods),
        business_methods=len(profile.methods),
        long_methods=sum(
            method.instruction_count >= config.long_method_min_instructions
            for method in profile.methods
        ),
        images=len(profile.images),
        owned_files=len(profile.files),
    )
    attribution = AttributionSummary(
        heuristic_owned=counts[OriginKind.HEURISTIC_OWNED],
        public_dependency=counts[OriginKind.PUBLIC_DEPENDENCY],
        tool_generated=counts[OriginKind.TOOL_GENERATED],
        unresolved=counts[OriginKind.UNRESOLVED],
    )
    code_confidence = (
        sum(code_confidences) / len(code_confidences) if code_confidences else 0.0
    )
    diagnostics = {
        "strategy": "heuristic_aab",
        "inferred_business_prefixes": list(inferred),
        "attribution": asdict(attribution),
        "dimension_confidence": {
            "business_code": code_confidence,
            "long_methods": code_confidence,
            "images": 0.45 if profile.images else 0.0,
            "resources": 0.45 if any(
                item.category == "resource" for item in profile.files
            ) else 0.0,
            "manifest": 0.6 if manifest_entries else 0.0,
            "assets": 0.4 if any(item.category == "asset" for item in profile.files) else 0.0,
        },
    }
    return OwnedProjection(profile, attribution, diagnostics)
