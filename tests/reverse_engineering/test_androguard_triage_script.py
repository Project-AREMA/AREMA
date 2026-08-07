"""In-process coverage for the in-pod androguard triage entrypoint.

``images/deobfuscation-tools/androguard_triage.py`` runs only inside the
deobfuscation-tools pod, but its fail-open ``main`` contract and its
androguard-free code paths (magic-byte ``_load`` dispatch, the ``_load_dex``
degrade path, bounded ``_url_candidates``) are the guarantee the whole "a hostile
sample never crashes the run" property rests on -- and they are trivially
exercisable in the AREMA process. androguard is imported lazily by the script and
is NOT installed here, so importing it by path and driving these paths verifies
the JSON contract without a live cluster.

The script's only non-stdlib top-level import is ``androguard_pure.report`` -- the
SAME module the tree ships as ``reverse_engineering.tools.android.report`` and the
image vendors via a build-context. We alias that package so there is one source of
truth, exactly as the pod's PYTHONPATH does.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from types import ModuleType

_SCRIPT_PATH = (
    Path(__file__).resolve().parents[2] / "images" / "deobfuscation-tools" / "androguard_triage.py"
)


def _load_script_module() -> ModuleType:
    """Import the in-pod script in-process with ``androguard_pure`` aliased."""
    import reverse_engineering.tools.android as android_pkg
    import reverse_engineering.tools.android.report as android_report

    sys.modules.setdefault("androguard_pure", android_pkg)
    sys.modules.setdefault("androguard_pure.report", android_report)
    spec = importlib.util.spec_from_file_location("androguard_triage_in_pod", _SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def script() -> ModuleType:
    return _load_script_module()


def test_main_fails_open_on_missing_file(
    script: ModuleType, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    # The documented fail-open contract: a parse/IO failure never propagates a
    # traceback; main converts it to a {"success": false, "error": ...} object on
    # stdout and exits non-zero, so the staging tool always reads valid JSON.
    rc = script.main(["androguard_triage.py", str(tmp_path / "does-not-exist.apk")])
    obj = json.loads(capsys.readouterr().out)

    assert rc != 0
    assert obj["success"] is False
    assert obj["error"]
    assert "FileNotFoundError" in obj["error"]


def test_main_rejects_wrong_arg_count(
    script: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = script.main(["androguard_triage.py"])
    obj = json.loads(capsys.readouterr().out)

    assert rc == 2
    assert obj["success"] is False
    assert "usage" in obj["error"]


def test_load_routes_dex_magic_without_androguard(script: ModuleType, tmp_path: Path) -> None:
    # A ``dex\n``-magic file must route to _load_dex, which degrades cleanly with
    # no androguard installed (class/method counts collapse to 0) yet still yields
    # a valid report carrying the dex count and any harvested URLs.
    dex = tmp_path / "classes.dex"
    dex.write_bytes(b"dex\n035\x00 https://evil.example/c2 payload")

    report = script.build_report(script._load(str(dex)))

    assert report["success"] is True
    assert report["dex"]["count"] == 1
    assert report["dex"]["classes"] == 0
    assert "https://evil.example/c2" in report["url_candidates"]


def test_url_candidates_dedup_and_cap(script: ModuleType) -> None:
    duplicated = b" https://a.example/pathA https://a.example/pathA https://b.example/pathB "
    assert script._url_candidates([duplicated]) == [
        "https://a.example/pathA",
        "https://b.example/pathB",
    ]

    many = b" ".join(
        f"https://evil.example/{index:05d}".encode() for index in range(script._MAX_URLS + 25)
    )
    assert len(script._url_candidates([many])) == script._MAX_URLS


def test_certificate_subject_is_human_readable_not_object_repr(script: ModuleType) -> None:
    # Regression (found by the in-cluster smoke test): _certificate rendered
    # certs[0].subject via str(), yielding an asn1crypto object repr like
    # "<asn1crypto.x509.Name 0x... b'0\\x81...'>". It must use the .human_friendly
    # DN string instead.
    import hashlib

    class _Name:
        human_friendly = "Country: US, Organization: Android, Common Name: Android"

    class _Cert:
        subject = _Name()

    class _Apk:
        def get_certificates_der_v2(self) -> list[bytes]:
            return [b"\x30\x82fake-der-bytes"]

        def get_certificates(self) -> list[_Cert]:
            return [_Cert()]

    sha256, subject = script._certificate(_Apk())

    assert sha256 == hashlib.sha256(b"\x30\x82fake-der-bytes").hexdigest()
    assert subject == "Country: US, Organization: Android, Common Name: Android"
    assert subject is not None
    assert "asn1crypto" not in subject and "object at 0x" not in subject
