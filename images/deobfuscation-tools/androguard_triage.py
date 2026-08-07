#!/usr/bin/env python3
"""In-pod androguard triage -> the Android triage JSON contract on stdout.

This script runs ONLY inside the ``deobfuscation-tools`` sandbox pod. androguard
parses the (hostile) APK/DEX/JAR in isolation, this module adapts the parsed
sample into the shared :class:`ApkView`, and prints ``build_report(view)`` as a
single JSON object. On any parse/IO failure it prints ``{"success": false,
"error": ...}`` and exits non-zero -- it never propagates a traceback, so the
staging tool always reads a well-formed JSON object.

The pure report/packer logic is the very module the AREMA unit tests exercise
(``reverse_engineering.tools.android``), vendored onto this image's ``PYTHONPATH``
under the package name ``androguard_pure`` via a Docker build-context. There is
one source of truth for the contract; nothing about the report shape is
re-implemented here.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys

from androguard_pure.report import ApkView, build_report

# Bounded, deduplicated URL harvesting from raw DEX/resource bytes. Kept small so
# a hostile sample cannot blow up the report.
_URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}")
_MAX_URLS = 200
_MAX_DEX_SCAN_BYTES = 32 * 1024 * 1024

# Manifest component tags keyed by androguard's ``get_<plural>()`` accessor.
_COMPONENT_ACCESSORS: tuple[tuple[str, str], ...] = (
    ("activities", "activity"),
    ("services", "service"),
    ("receivers", "receiver"),
    ("providers", "provider"),
)


def _safe_int(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _is_true(value: object) -> bool:
    return str(value).lower() == "true"


def _element(apk: object, tag: str, attribute: str, **filters: str) -> object:
    getter = getattr(apk, "get_element", None)
    if not callable(getter):
        return None
    try:
        return getter(tag, attribute, **filters)
    except Exception:  # noqa: BLE001 - manifest lookups are best-effort per field
        return None


def _components(apk: object, accessor: str, tag: str) -> list[tuple[str, bool]]:
    getter = getattr(apk, f"get_{accessor}", None)
    if not callable(getter):
        return []
    try:
        names = list(getter())
    except Exception:  # noqa: BLE001 - one missing accessor must not sink the report
        return []
    out: list[tuple[str, bool]] = []
    for name in names:
        exported = _is_true(_element(apk, tag, "exported", name=name))
        out.append((str(name), exported))
    return out


def _certificate(apk: object) -> tuple[str | None, str | None]:
    getter = getattr(apk, "get_certificates_der_v2", None) or getattr(
        apk, "get_certificates_der", None
    )
    ders: list[bytes] = []
    if callable(getter):
        try:
            ders = [d for d in getter() if d]
        except Exception:  # noqa: BLE001 - unsigned/malformed cert -> empty
            ders = []
    if not ders:
        return None, None
    sha256 = hashlib.sha256(ders[0]).hexdigest()
    subject: str | None = None
    x509_getter = getattr(apk, "get_certificates", None)
    if callable(x509_getter):
        try:
            certs = list(x509_getter())
            if certs:
                # certs[0].subject is an asn1crypto x509.Name; str() on it yields an
                # object repr, so use its .human_friendly DN string instead.
                human = getattr(getattr(certs[0], "subject", None), "human_friendly", None)
                subject = human if isinstance(human, str) and human else None
        except Exception:  # noqa: BLE001 - subject is best-effort
            subject = None
    return sha256, subject


def _dex_stats(dex_blobs: list[bytes]) -> tuple[int, int, int]:
    classes = 0
    methods = 0
    try:
        from androguard.core.dex import DEX
    except Exception:  # noqa: BLE001 - class/method counts degrade to 0
        return len(dex_blobs), 0, 0
    for blob in dex_blobs:
        try:
            parsed = DEX(blob)
            class_defs = list(parsed.get_classes())
            classes += len(class_defs)
            for klass in class_defs:
                methods += len(list(klass.get_methods()))
        except Exception:  # noqa: BLE001 - a malformed dex contributes nothing
            continue
    return len(dex_blobs), classes, methods


def _url_candidates(blobs: list[bytes]) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for blob in blobs:
        for match in _URL_RE.findall(blob[:_MAX_DEX_SCAN_BYTES]):
            url = match.decode("ascii", "ignore")
            if url and url not in seen:
                seen.add(url)
                found.append(url)
                if len(found) >= _MAX_URLS:
                    return found
    return found


def _dex_blobs(apk: object) -> list[bytes]:
    getter = getattr(apk, "get_all_dex", None)
    if not callable(getter):
        return []
    try:
        return [blob for blob in getter() if blob]
    except Exception:  # noqa: BLE001 - no readable dex -> empty inventory
        return []


def _files(apk: object) -> list[str]:
    getter = getattr(apk, "get_files", None)
    if not callable(getter):
        return []
    try:
        return [str(name) for name in getter()]
    except Exception:  # noqa: BLE001 - file listing is best-effort
        return []


def _load_apk(path: str) -> ApkView:
    """Adapt a parsed APK into the pure :class:`ApkView` (in-pod only)."""

    from androguard.core.apk import APK

    apk = APK(path)

    files = _files(apk)
    native_libs = [f for f in files if f.startswith("lib/") and f.endswith(".so")]
    asset_names = [f for f in files if f.startswith("assets/")]

    dex_blobs = _dex_blobs(apk)
    dex_count, dex_classes, dex_methods = _dex_stats(dex_blobs)
    urls = _url_candidates(dex_blobs)

    permissions_getter = getattr(apk, "get_permissions", None)
    permissions = list(permissions_getter()) if callable(permissions_getter) else []

    activities, services, receivers, providers = (
        _components(apk, accessor, tag) for accessor, tag in _COMPONENT_ACCESSORS
    )

    cert_sha256, cert_subject = _certificate(apk)

    return ApkView(
        package=str(getattr(apk, "get_package", lambda: "")() or ""),
        permissions=permissions,
        activities=activities,
        services=services,
        receivers=receivers,
        providers=providers,
        debuggable=_is_true(_element(apk, "application", "debuggable")),
        uses_cleartext_traffic=_is_true(_element(apk, "application", "usesCleartextTraffic")),
        min_sdk=_safe_int(apk.get_min_sdk_version()),
        target_sdk=_safe_int(apk.get_target_sdk_version()),
        certificate_sha256=cert_sha256,
        certificate_subject=cert_subject,
        dex_count=dex_count,
        dex_classes=dex_classes,
        dex_methods=dex_methods,
        native_libs=native_libs,
        url_candidates=urls,
        asset_names=asset_names,
        app_class=(str(_element(apk, "application", "name") or "") or None),
    )


def _load_dex(path: str) -> ApkView:
    """Adapt a bare ``.dex`` into an :class:`ApkView` (dex/url fields only)."""

    with open(path, "rb") as handle:
        blob = handle.read()
    dex_count, dex_classes, dex_methods = _dex_stats([blob])
    return ApkView(
        dex_count=dex_count or 1,
        dex_classes=dex_classes,
        dex_methods=dex_methods,
        url_candidates=_url_candidates([blob]),
    )


def _load(path: str) -> ApkView:
    with open(path, "rb") as handle:
        magic = handle.read(8)
    # A bare Dalvik executable starts with ``dex\n0"``; anything else (ZIP-based
    # apk/jar) is handled by androguard's APK reader.
    if magic.startswith(b"dex\n"):
        return _load_dex(path)
    return _load_apk(path)


def _silence_logging() -> None:
    """Keep pod stderr bounded so it can never smother a valid stdout report.

    androguard logs freely through the shared ``loguru`` logger (and a few
    transitive deps through the stdlib ``logging`` module) while parsing a
    hostile sample. This script's only contract is the JSON object on *stdout*;
    stderr is pure diagnostic noise. Left unbounded it can exceed the sandbox
    output cap -- historically enough to trip the staging tool's truncation flag
    and throw away a report the pass actually produced. Silence both logging
    paths up front: ``logger.remove()`` drops loguru's default stderr sink and
    ``logger.disable("androguard")`` suppresses androguard's records even if it
    re-adds a sink on its (lazy) import, while ``logging.disable`` covers the
    stdlib path.

    Called from ``__main__`` only -- never at import -- so importing this module
    in-process for unit tests carries no global logging side effect.
    """

    import logging

    logging.disable(logging.CRITICAL)
    try:
        from loguru import logger
    except Exception:  # noqa: BLE001 - loguru absent (in-process unit import): nothing to silence
        return
    logger.remove()
    logger.disable("androguard")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        json.dump({"success": False, "error": "usage: androguard_triage.py <sample>"}, sys.stdout)
        return 2
    try:
        report = build_report(_load(argv[1]))
    except Exception as exc:  # noqa: BLE001 - fail open: emit an error object, never crash
        json.dump({"success": False, "error": f"{type(exc).__name__}: {exc}"}, sys.stdout)
        return 1
    json.dump(report, sys.stdout)
    return 0


if __name__ == "__main__":
    _silence_logging()
    raise SystemExit(main(sys.argv))
