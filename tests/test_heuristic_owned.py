from __future__ import annotations

import pytest

from aab_compare.config import AnalysisConfig
from aab_compare.heuristic import build_heuristic_projection
from aab_compare.models import BundleProfile, FileFingerprint, ImageFingerprint, MethodFingerprint
from aab_compare.ownership import OriginKind
from aab_compare.tools import inspect_manifest_xml


def _method(class_name: str, *, instructions: int = 120) -> MethodFingerprint:
    return MethodFingerprint(
        identifier=f"{class_name}->run()V",
        module="base",
        dex_path="base/dex/classes.dex",
        class_name=class_name,
        method_name="run",
        descriptor="()V",
        instruction_count=instructions,
        canonical_hash=class_name,
        opcode_tokens=["invoke", "return"] * (instructions // 2),
        api_calls=[],
        constants=[],
        block_signature=["return"],
    )


def test_heuristic_projection_filters_public_dependency_and_generated_code() -> None:
    profile = BundleProfile("/tmp/app.aab", "a" * 64, 1, ["base"], {})
    profile.dependencies = ["com.vendor.sdk:analytics:1.0"]
    profile.methods = [
        _method("Lcom/example/app/Feature;"),
        _method("Lother/private/Feature;"),
        _method("Landroidx/core/ViewKt;"),
        _method("Lcom/google/firebase/App;"),
        _method("Lkotlin/collections/CollectionsKt;"),
        _method("Lorg/jetbrains/annotations/NotNull;"),
        _method("Lcom/facebook/FacebookSdk;"),
        _method("Lcom/vendor/sdk/Tracker;"),
        _method("Lcom/example/app/BuildConfig;"),
    ]

    projection = build_heuristic_projection(
        profile,
        AnalysisConfig(business_prefixes=("Lcom/example/app/",)),
    )

    assert [method.class_name for method in projection.profile.methods] == [
        "Lcom/example/app/Feature;",
        "Lother/private/Feature;",
    ]
    assert all(
        method.origin == OriginKind.HEURISTIC_OWNED.value
        for method in projection.profile.methods
    )
    assert projection.attribution.heuristic_owned == 2
    assert projection.attribution.public_dependency == 6
    assert projection.attribution.tool_generated == 1


def test_explicit_business_prefix_overrides_curated_public_prefix() -> None:
    profile = BundleProfile("/tmp/app.aab", "a" * 64, 1, ["base"], {})
    profile.methods = [_method("Lcom/google/myapp/Feature;")]

    projection = build_heuristic_projection(
        profile,
        AnalysisConfig(business_prefixes=("Lcom/google/myapp/",)),
    )

    assert [method.class_name for method in projection.profile.methods] == [
        "Lcom/google/myapp/Feature;"
    ]


def test_heuristic_projection_filters_public_resources_and_sdk_assets() -> None:
    profile = BundleProfile("/tmp/app.aab", "a" * 64, 1, ["base"], {})
    profile.files = [
        FileFingerprint(
            "base/res/drawable/abc_btn.png", "base", "image", 10, "public-image"
        ),
        FileFingerprint(
            "base/res/drawable/com_facebook_close.png",
            "base",
            "image",
            10,
            "facebook-image",
        ),
        FileFingerprint("base/res/drawable/hero.png", "base", "image", 20, "hero"),
        FileFingerprint(
            "base/res/color/m3_button_ripple.xml", "base", "resource", 10, "material"
        ),
        FileFingerprint(
            "base/res/values/google_services.xml",
            "base",
            "resource",
            10,
            "generated",
        ),
        FileFingerprint("base/res/layout/home.xml", "base", "resource", 20, "home"),
        FileFingerprint("base/assets/facebook/sdk.json", "base", "asset", 10, "sdk"),
        FileFingerprint("base/assets/content/data.json", "base", "asset", 20, "data"),
    ]
    profile.images = [
        ImageFingerprint(
            "base/res/drawable/abc_btn.png", "base", 10, "public-image", "0" * 16, 10, 10
        ),
        ImageFingerprint(
            "base/res/drawable/com_facebook_close.png",
            "base",
            10,
            "facebook-image",
            "2" * 16,
            10,
            10,
        ),
        ImageFingerprint("base/res/drawable/hero.png", "base", 20, "hero", "1" * 16, 10, 10),
    ]

    projection = build_heuristic_projection(profile, AnalysisConfig())

    assert [item.path for item in projection.profile.files] == [
        "base/assets/content/data.json",
        "base/res/drawable/hero.png",
        "base/res/layout/home.xml",
    ]
    assert [item.path for item in projection.profile.images] == [
        "base/res/drawable/hero.png"
    ]
    assert projection.attribution.heuristic_owned == 3
    assert projection.attribution.public_dependency == 4
    assert projection.attribution.tool_generated == 1


@pytest.mark.parametrize(
    "name",
    [
        "$m3_avd_hide_password__0.xml",
        "$avd_hide_password__0.xml",
        "$ic_yunxin__2.xml",
        "$mtrl_checkbox_button_icon_checked__0.xml",
        "activity_browse.xml",
        "alert_dialog_layout.xml",
        "avatar_view_layout.xml",
        "back_title_bar_layout.xml",
        "blue_noise.webp",
        "bottom_choice_dialog_layout.xml",
        "browser_actions_context_menu_page.xml",
        "brvah_trailing_load_more.xml",
        "btn_checkbox_to_checked.xml",
        "btn_radio_to_on.xml",
        "choice_dialog_layout.xml",
        "clearable_edit_layout.xml",
        "com_facebook_close.png",
        "common_act_layout.xml",
        "common_confirm_dialog_layout.xml",
        "common_crop_image_activity.xml",
        "common_dialog_photo_choice.xml",
        "common_full_open_on_phone.png",
        "common_title_bar_layout.xml",
        "compat_splash_screen.xml",
        "confirm_dialog_layout.xml",
        "content_pop_list_view_with_shadow.xml",
        "custom_dialog.xml",
        "dialog_date_picker.xml",
        "fingerprint_dialog_error.png",
        "fragment_open_enter.xml",
        "ic_back.xml",
        "ic_call_answer.xml",
        "ic_clear_black_24.xml",
        "ic_clock_black_24dp.xml",
        "ic_keyboard_black_24dp.xml",
        "ic_list_empty.png",
        "ic_m3_chip_checked_circle.xml",
        "ic_mtrl_chip_checked_circle.xml",
        "ic_other_sign_in.xml",
        "ic_passkey.xml",
        "ic_password.xml",
        "ic_search_black.xml",
        "ic_search_black_24.xml",
        "ic_yunxin.png",
        "ime_secondary_split_test_activity.xml",
        "icon_exo_controls_play.webp",
        "ksw_md_thumb.xml",
        "list_alert_dialog_item.xml",
        "loading.json",
        "loading_dialog_layout.xml",
        "m3_alert_dialog.xml",
        "media3_notification_template.xml",
        "messenger_bubble_large_blue.png",
        "notify_panel_notification_icon_bg.png",
        "pager_navigator_layout.xml",
        "picture_selector.xml",
        "ps_click_music.wav",
        "roboto_medium_numbers.ttf",
        "sentry_dialog_user_feedback.xml",
        "srl_classics_header.xml",
        "select_dialog_item_material.xml",
        "splash_screen_view.xml",
        "indeterminate_static.xml",
        "ucrop_ic_done.png",
    ],
)
def test_heuristic_projection_filters_known_public_resource_prefixes(name: str) -> None:
    profile = BundleProfile("/tmp/app.aab", "a" * 64, 1, ["base"], {})
    profile.files = [
        FileFingerprint(f"base/res/drawable/{name}", "base", "resource", 10, name)
    ]

    projection = build_heuristic_projection(profile, AnalysisConfig())

    assert projection.profile.files == []
    assert projection.attribution.public_dependency == 1


@pytest.mark.parametrize(
    "path",
    [
        "base/assets/NotoColorEmojiCompat.ttf",
        "base/assets/chatkit/emoji/default/emoji_00.png",
        "base/assets/com/appsflyer/internal/identifier",
        "base/assets/nim/cacert",
    ],
)
def test_heuristic_projection_filters_known_sdk_assets(path: str) -> None:
    profile = BundleProfile("/tmp/app.aab", "a" * 64, 1, ["base"], {})
    profile.files = [FileFingerprint(path, "base", "asset", 10, path)]

    projection = build_heuristic_projection(profile, AnalysisConfig())

    assert projection.profile.files == []
    assert projection.attribution.public_dependency == 1


def test_heuristic_manifest_keeps_app_declarations_and_excludes_public_components() -> None:
    details = inspect_manifest_xml(
        """
        <manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="com.example.app">
          <uses-permission android:name="android.permission.INTERNET" />
          <permission android:name="com.example.app.permission.INTERNAL" />
          <application>
            <activity android:name=".MainActivity">
              <intent-filter>
                <action android:name="com.example.app.OPEN" />
                <action android:name="https://netease.yunxin.browser" />
              </intent-filter>
            </activity>
            <provider android:name="com.facebook.FacebookContentProvider" />
            <activity android:name="com.yalantis.ucrop.UCropActivity" />
          </application>
        </manifest>
        """
    )
    profile = BundleProfile("/tmp/app.aab", "a" * 64, 1, ["base"], {})

    projection = build_heuristic_projection(
        profile,
        AnalysisConfig(),
        manifest_details={"base": details},
    )

    values = [entry.value for entry in projection.profile.manifest_entries]
    assert values == [
        "activity:name=com.example.app.MainActivity",
        "action:name=com.example.app.OPEN",
        "permission:name=com.example.app.permission.INTERNAL",
    ]
    assert projection.attribution.public_dependency == 3
    assert projection.diagnostics["inferred_business_prefixes"] == ["Lcom/example/app/"]
