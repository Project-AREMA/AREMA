"""Pure Android triage report builder over a duck-typed APK view.

Single source of truth for the Android triage JSON contract. The in-pod
androguard script (``images/deobfuscation-tools/androguard_triage.py``) parses
the hostile APK/DEX/JAR in isolation, adapts it into an :class:`ApkView`, and
prints ``build_report(view)`` as JSON; the unit tests exercise ``build_report``
directly. No androguard import lives here, so the report/packer logic is fully
testable inside the AREMA process while the untrusted sample is only ever parsed
inside the sandbox pod.

The module is imported both as ``reverse_engineering.tools.android.report`` (in
tree / tests) and, vendored onto the image ``PYTHONPATH`` via a build-context,
by the in-pod script. It therefore uses a package-relative import for the packer
signatures so it is relocatable and carries no drift between the two.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .packer_signatures import detect_packer

if TYPE_CHECKING:
    from collections.abc import Sequence

# Android runtime permissions whose protection level is ``dangerous`` (the ones
# that gate access to sensitive user data or device capabilities). A requested
# permission is surfaced as dangerous only when it appears here; everything else
# is reported under ``requested`` but not flagged.
DANGEROUS_PERMISSIONS: frozenset[str] = frozenset(
    {
        # Calendar
        "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR",
        # Call log
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS",
        # Camera
        "android.permission.CAMERA",
        # Contacts
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.GET_ACCOUNTS",
        # Location
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        # Microphone
        "android.permission.RECORD_AUDIO",
        # Phone
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_PHONE_NUMBERS",
        "android.permission.CALL_PHONE",
        "android.permission.ANSWER_PHONE_CALLS",
        "android.permission.ADD_VOICEMAIL",
        "android.permission.USE_SIP",
        "android.permission.ACCEPT_HANDOVER",
        # Sensors
        "android.permission.BODY_SENSORS",
        "android.permission.BODY_SENSORS_BACKGROUND",
        "android.permission.ACTIVITY_RECOGNITION",
        # SMS
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_WAP_PUSH",
        "android.permission.RECEIVE_MMS",
        # Storage
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.ACCESS_MEDIA_LOCATION",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_MEDIA_AUDIO",
    }
)

# A component is expressed as ``(class_name, exported)``.
_Component = tuple[str, bool]


@dataclass(frozen=True)
class ApkView:
    """Duck-typed, parse-independent view of a triaged APK/DEX/JAR.

    The in-pod androguard adapter populates this from a parsed sample; the unit
    tests construct it directly. Every field defaults to an empty/absent value so
    a bare ``dex`` (only ``dex``/``url_candidates``) or a ``jar`` (class-level
    only) can populate the subset that applies and leave manifest-derived fields
    empty, matching the triage contract's degradation rules.
    """

    package: str = ""
    permissions: Sequence[str] = ()
    activities: Sequence[_Component] = ()
    services: Sequence[_Component] = ()
    receivers: Sequence[_Component] = ()
    providers: Sequence[_Component] = ()
    debuggable: bool = False
    uses_cleartext_traffic: bool = False
    min_sdk: int | None = None
    target_sdk: int | None = None
    certificate_sha256: str | None = None
    certificate_subject: str | None = None
    dex_count: int = 0
    dex_classes: int = 0
    dex_methods: int = 0
    native_libs: Sequence[str] = ()
    url_candidates: Sequence[str] = ()
    asset_names: Sequence[str] = ()
    app_class: str | None = None


def _names(components: Sequence[_Component]) -> list[str]:
    return [name for name, _ in components]


def build_report(view: ApkView) -> dict[str, object]:
    """Assemble the Android triage JSON contract from a parsed sample view.

    Args:
        view: the parse-independent :class:`ApkView` produced in the sandbox pod.

    Returns:
        The triage report dict (see the module docstring / spec §D for the key
        contract). ``success`` is always ``True`` here: an unparseable sample is
        handled by the in-pod script, which emits its own error object instead of
        calling ``build_report``.
    """

    requested = list(view.permissions)
    dangerous = [perm for perm in requested if perm in DANGEROUS_PERMISSIONS]

    all_components = (
        *view.activities,
        *view.services,
        *view.receivers,
        *view.providers,
    )
    exported = [name for name, is_exported in all_components if is_exported]

    packer = detect_packer(list(view.native_libs), list(view.asset_names), view.app_class)

    return {
        "success": True,
        "package": view.package,
        "permissions": {"requested": requested, "dangerous": dangerous},
        "components": {
            "activities": _names(view.activities),
            "services": _names(view.services),
            "receivers": _names(view.receivers),
            "providers": _names(view.providers),
            "exported": exported,
        },
        "flags": {
            "debuggable": view.debuggable,
            "uses_cleartext_traffic": view.uses_cleartext_traffic,
        },
        "sdk": {"min": view.min_sdk, "target": view.target_sdk},
        "certificate": {
            "sha256": view.certificate_sha256,
            "subject": view.certificate_subject,
        },
        "dex": {
            "count": view.dex_count,
            "classes": view.dex_classes,
            "methods": view.dex_methods,
        },
        "native_libs": list(view.native_libs),
        "url_candidates": list(view.url_candidates),
        "packer": packer,
    }
