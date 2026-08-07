"""Unit tests for the pure Android triage report builder.

The hostile APK is parsed only inside the sandbox pod by androguard; the report
assembly is pure over a duck-typed ``ApkView`` and is exercised here (and by the
in-pod script) so the JSON contract has a single, tested source of truth.
"""

from __future__ import annotations

from reverse_engineering.tools.android.report import (
    DANGEROUS_PERMISSIONS,
    ApkView,
    build_report,
)


def test_build_report_shape_and_packer_delegation():
    view = ApkView(
        package="com.x",
        permissions=("android.permission.SEND_SMS", "android.permission.INTERNET"),
        receivers=(("com.x.Boot", True),),
        native_libs=("lib/arm64-v8a/libjiagu.so",),
    )
    rep = build_report(view)

    assert rep["success"] is True
    assert rep["package"] == "com.x"
    assert "android.permission.SEND_SMS" in rep["permissions"]["dangerous"]
    # INTERNET is a normal permission -> requested but not dangerous.
    assert "android.permission.INTERNET" in rep["permissions"]["requested"]
    assert "android.permission.INTERNET" not in rep["permissions"]["dangerous"]
    # Packer detection is delegated to the shared pure signature table.
    assert rep["packer"]["detected"] is True
    assert rep["packer"]["name"] == "jiagu"


def test_report_carries_the_full_contract_keys():
    rep = build_report(ApkView(package="com.y"))

    assert set(rep) == {
        "success",
        "package",
        "permissions",
        "components",
        "flags",
        "sdk",
        "certificate",
        "dex",
        "native_libs",
        "url_candidates",
        "packer",
    }
    assert set(rep["permissions"]) == {"requested", "dangerous"}
    assert set(rep["components"]) == {
        "activities",
        "services",
        "receivers",
        "providers",
        "exported",
    }
    assert set(rep["flags"]) == {"debuggable", "uses_cleartext_traffic"}
    assert set(rep["sdk"]) == {"min", "target"}
    assert set(rep["certificate"]) == {"sha256", "subject"}
    assert set(rep["dex"]) == {"count", "classes", "methods"}
    assert set(rep["packer"]) == {"detected", "name", "signals"}


def test_exported_components_are_collected_across_kinds():
    view = ApkView(
        package="com.z",
        activities=(("com.z.Main", True), ("com.z.Hidden", False)),
        services=(("com.z.Svc", True),),
        receivers=(("com.z.Boot", False),),
        providers=(("com.z.Prov", True),),
    )
    rep = build_report(view)

    assert rep["components"]["activities"] == ["com.z.Main", "com.z.Hidden"]
    assert rep["components"]["services"] == ["com.z.Svc"]
    assert set(rep["components"]["exported"]) == {"com.z.Main", "com.z.Svc", "com.z.Prov"}


def test_dangerous_set_is_a_frozenset_of_known_permissions():
    assert isinstance(DANGEROUS_PERMISSIONS, frozenset)
    assert "android.permission.SEND_SMS" in DANGEROUS_PERMISSIONS
    assert "android.permission.RECORD_AUDIO" in DANGEROUS_PERMISSIONS
    # A normal permission must never be classified dangerous.
    assert "android.permission.INTERNET" not in DANGEROUS_PERMISSIONS


def test_flags_and_sdk_and_certificate_pass_through():
    view = ApkView(
        package="com.f",
        debuggable=True,
        uses_cleartext_traffic=True,
        min_sdk=21,
        target_sdk=33,
        certificate_sha256="ab" * 32,
        certificate_subject="CN=Test",
        dex_count=2,
        dex_classes=100,
        dex_methods=500,
        url_candidates=("https://evil.example/c2",),
    )
    rep = build_report(view)

    assert rep["flags"] == {"debuggable": True, "uses_cleartext_traffic": True}
    assert rep["sdk"] == {"min": 21, "target": 33}
    assert rep["certificate"] == {"sha256": "ab" * 32, "subject": "CN=Test"}
    assert rep["dex"] == {"count": 2, "classes": 100, "methods": 500}
    assert rep["url_candidates"] == ["https://evil.example/c2"]


def test_clean_app_reports_no_packer_and_no_dangerous_perms():
    view = ApkView(
        package="com.clean",
        permissions=("android.permission.INTERNET",),
        native_libs=("lib/arm64-v8a/libnative-lib.so",),
    )
    rep = build_report(view)

    assert rep["permissions"]["dangerous"] == []
    assert rep["packer"] == {"detected": False, "name": None, "signals": []}
