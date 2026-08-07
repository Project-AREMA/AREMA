"""Reputation enrichment: the gate that keeps it off, and the hashlookup parser.

Every fixture below is a verbatim body measured against the live
``hashlookup.circl.lu`` service, so the parser is tested against CIRCL's real
contract rather than an assumed one. Two of them exist specifically because the
documentation does not predict them: a malicious file carrying
``hashlookup:trust`` 100, and a ``FileName`` that has nothing to do with the
sample because the digest is of four bytes that many files contain.
"""

from __future__ import annotations

import json

import httpx
import pytest
from pydantic import SecretStr

from reverse_engineering.intel import hashlookup
from reverse_engineering.intel.config import IntelSettings
from reverse_engineering.intel.hashlookup import lookup_hashlookup, parse_hashlookup
from reverse_engineering.intel.models import (
    HASHLOOKUP_SOURCE,
    MALWAREBAZAAR_SOURCE,
    MAX_SUMMARY_CHARS,
    VIRUSTOTAL_SOURCE,
    IntelResult,
    IntelStatus,
    sanitize_summary,
)

AID = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# Measured: GET /lookup/sha256/e3b0c442...b855 (the empty file), HTTP 200.
KNOWN_GOOD_BODY: dict[str, object] = {
    "CRC32": "00000000",
    "FileName": "./usr/lib/python3/dist-packages/zzzeeksphinx-1.0.20.egg-info/requires.txt",
    "FileSize": "0",
    "MD5": "D41D8CD98F00B204E9800998ECF8427E",
    "RDS:package_id": "304062",
    "SHA-1": "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
    "SHA-256": AID.upper(),
    "SSDEEP": "3::",
    "TLSH": "",
    "db": "nsrl_legacy",
    "insert-timestamp": "1646977909.0909765",
    "source": "snap:drNKnccj3BjVCUKrE8sexEX8zULMyPmi_2",
    "hashlookup:parent-total": 655925,
    "hashlookup:trust": 100,
}

# Measured: GET /lookup/sha256/9f86d081...0a08 (the four bytes "test"), HTTP 200.
# Catalogued AND flagged malicious, with trust 100 all the same.
KNOWN_BAD_BODY: dict[str, object] = {
    "FileName": "./usr/share/cargo/registry/fs_extra-1.1.0/tests/temp/dir/sub/test.txt",
    "FileSize": "4",
    "KnownMalicious": "malshare.com",
    "MD5": "098F6BCD4621D373CADE4E832627B4F6",
    "db": "nsrl_legacy",
    "source": "RDS_2025.03.1_android.db",
    "hashlookup:parent-total": 167,
    "hashlookup:trust": 100,
}

# Measured: GET /lookup/sha256/<any absent digest>, HTTP 404.
NOT_FOUND_BODY: dict[str, object] = {"message": "Non existing SHA-256", "query": AID}


class _Response:
    """Minimal httpx.Response stand-in: only what the lookup actually reads."""

    def __init__(self, status_code: int, body: object = None, *, text: str = "") -> None:
        self.status_code = status_code
        self._body = body
        self._text = text

    def json(self) -> object:
        if self._text:
            return json.loads(self._text)
        return self._body


# --- the gate: no credential means no request ---------------------------------


def test_no_credential_configured_queries_nothing() -> None:
    """The whole feature switch. An unconfigured checkout must not reach the
    network, including for the keyless source."""
    assert IntelSettings(virustotal_api_key=None, malwarebazaar_api_key=None).active_sources == ()


def test_a_placeholder_key_does_not_switch_enrichment_on() -> None:
    """.env.example ships the keys present and empty; whitespace is the same
    thing as absent."""
    settings = IntelSettings(virustotal_api_key=SecretStr("  "), malwarebazaar_api_key=None)

    assert settings.active_sources == ()


def test_one_key_switches_on_that_source_and_the_keyless_one() -> None:
    settings = IntelSettings(virustotal_api_key=SecretStr("k"), malwarebazaar_api_key=None)

    assert settings.active_sources == (HASHLOOKUP_SOURCE, VIRUSTOTAL_SOURCE)


def test_every_key_switches_on_every_source() -> None:
    settings = IntelSettings(
        virustotal_api_key=SecretStr("k"), malwarebazaar_api_key=SecretStr("j")
    )

    assert settings.active_sources == (
        HASHLOOKUP_SOURCE,
        VIRUSTOTAL_SOURCE,
        MALWAREBAZAAR_SOURCE,
    )


def test_a_key_is_read_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AREMA_MALWAREBAZAAR_API_KEY", "from-env")

    settings = IntelSettings()

    assert settings.active_sources == (HASHLOOKUP_SOURCE, MALWAREBAZAAR_SOURCE)
    assert settings.malwarebazaar_api_key is not None


def test_a_key_never_appears_in_a_repr() -> None:
    settings = IntelSettings(virustotal_api_key=SecretStr("super-secret-value"))

    assert "super-secret-value" not in repr(settings)
    assert "super-secret-value" not in str(settings.virustotal_api_key)


# --- the parser, against measured bodies --------------------------------------


def test_a_catalogued_digest_is_known_good() -> None:
    result = parse_hashlookup(KNOWN_GOOD_BODY)

    assert result.status is IntelStatus.KNOWN_GOOD
    assert result.source == HASHLOOKUP_SOURCE
    assert result.is_hit


def test_a_flagged_digest_is_known_bad_even_though_it_is_catalogued() -> None:
    """Being in a known-file corpus and being safe are different claims."""
    result = parse_hashlookup(KNOWN_BAD_BODY)

    assert result.status is IntelStatus.KNOWN_BAD
    assert "malshare.com" in result.summary


def test_trust_is_never_carried_into_the_summary() -> None:
    """Measured: a KnownMalicious entry returns hashlookup:trust 100, identical
    to a clean one. Printing it next to a malicious file would mislead."""
    for body in (KNOWN_GOOD_BODY, KNOWN_BAD_BODY):
        assert "trust" not in parse_hashlookup(body).summary.lower()
        assert "100" not in parse_hashlookup(body).summary


def test_the_filename_is_labelled_as_an_example() -> None:
    """Digests collide on content, so the name is one arbitrary member of the
    set of files with those bytes, not the sample's identity."""
    result = parse_hashlookup(KNOWN_GOOD_BODY)

    assert "example name" in result.summary


def test_the_corpus_is_named() -> None:
    assert "snap:drNKnccj3BjVCUKrE8sexEX8zULMyPmi_2" in parse_hashlookup(KNOWN_GOOD_BODY).summary


def test_the_db_field_is_used_when_source_is_missing() -> None:
    body = {key: value for key, value in KNOWN_GOOD_BODY.items() if key != "source"}

    assert "nsrl_legacy" in parse_hashlookup(body).summary


@pytest.mark.parametrize("payload", [None, "", [], 7, b"bytes"])
def test_an_unusable_body_is_not_a_hit(payload: object) -> None:
    result = parse_hashlookup(payload)

    assert result.status is IntelStatus.NOT_PRESENT
    assert not result.is_hit


def test_a_bare_two_hundred_still_reports_presence_and_nothing_more() -> None:
    result = parse_hashlookup({})

    assert result.status is IntelStatus.KNOWN_GOOD
    assert result.summary == "present, no descriptive fields returned"


def test_a_summary_stays_bounded_for_a_maximal_body() -> None:
    body = {"FileName": "n" * 5_000, "source": "s" * 5_000, "KnownMalicious": "m" * 5_000}

    assert len(parse_hashlookup(body).summary) <= MAX_SUMMARY_CHARS


# --- hostile third-party text -------------------------------------------------


def test_a_filename_cannot_smuggle_an_instruction_placeholder() -> None:
    """A filename is chosen by whoever submitted the sample, and the summary is
    injected into an ADK instruction template where a brace is a placeholder."""
    result = parse_hashlookup({"FileName": "evil{validated_evidence_json?}.exe"})

    assert "{" not in result.summary
    assert "}" not in result.summary


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("line one\nline two", "line one line two"),
        ("tabs\tand   spaces", "tabs and spaces"),
        ("stock ls 你好 utility", "stock ls utility"),
        ("back`tick", "back tick"),
        ("\x00\x07control", "control"),
        (None, ""),
        (12345, ""),
    ],
)
def test_summary_sanitization(raw: object, expected: str) -> None:
    assert sanitize_summary(raw) == expected


# --- the fetch, fail-open in every direction ----------------------------------


def test_a_hit_round_trips_through_the_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hashlookup.httpx, "get", lambda *_a, **_k: _Response(200, KNOWN_GOOD_BODY))

    assert lookup_hashlookup(AID, timeout=5.0).status is IntelStatus.KNOWN_GOOD


def test_a_404_is_absence_not_a_clean_bill_of_health(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hashlookup.httpx, "get", lambda *_a, **_k: _Response(404, NOT_FOUND_BODY))

    result = lookup_hashlookup(AID, timeout=5.0)

    assert result.status is IntelStatus.NOT_PRESENT
    assert result.status is not IntelStatus.KNOWN_GOOD
    assert not result.is_hit


@pytest.mark.parametrize("status_code", [400, 429, 500, 502, 503])
def test_an_error_status_is_unavailable_not_absence(
    monkeypatch: pytest.MonkeyPatch, status_code: int
) -> None:
    """A source that failed has told us nothing; a source that said 'absent' has
    told us something small but real. Collapsing them lets an outage read as
    evidence."""
    monkeypatch.setattr(hashlookup.httpx, "get", lambda *_a, **_k: _Response(status_code))

    assert lookup_hashlookup(AID, timeout=5.0).status is IntelStatus.UNAVAILABLE


@pytest.mark.parametrize(
    "error",
    [
        httpx.ConnectTimeout("timed out"),
        httpx.ReadTimeout("timed out"),
        httpx.ConnectError("refused"),
        OSError("network unreachable"),
        RuntimeError("something else entirely"),
    ],
)
def test_any_transport_failure_degrades_rather_than_raising(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    def _raise(*_args: object, **_kwargs: object) -> object:
        raise error

    monkeypatch.setattr(hashlookup.httpx, "get", _raise)

    assert lookup_hashlookup(AID, timeout=5.0).status is IntelStatus.UNAVAILABLE


def test_a_non_json_body_degrades(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        hashlookup.httpx, "get", lambda *_a, **_k: _Response(200, text="<html>nope</html>")
    )

    assert lookup_hashlookup(AID, timeout=5.0).status is IntelStatus.UNAVAILABLE


def test_only_the_digest_is_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    """The privacy contract: no filename, no path, no bytes leave the host."""
    seen: dict[str, object] = {}

    def _capture(url: str, **kwargs: object) -> _Response:
        seen["url"] = url
        seen["kwargs"] = kwargs
        return _Response(200, KNOWN_GOOD_BODY)

    monkeypatch.setattr(hashlookup.httpx, "get", _capture)
    lookup_hashlookup(AID, timeout=5.0)

    assert seen["url"] == f"https://hashlookup.circl.lu/lookup/sha256/{AID}"
    assert seen["kwargs"] == {"timeout": 5.0}


def test_the_timeout_is_always_passed(monkeypatch: pytest.MonkeyPatch) -> None:
    """A lookup on the intake critical path must never wait indefinitely."""
    seen: dict[str, object] = {}
    monkeypatch.setattr(
        hashlookup.httpx,
        "get",
        lambda _url, **kwargs: seen.update(kwargs) or _Response(404),
    )

    lookup_hashlookup(AID, timeout=0.25)

    assert seen["timeout"] == 0.25


def test_the_result_model_is_frozen_and_bounded() -> None:
    result = IntelResult(source=HASHLOOKUP_SOURCE, status=IntelStatus.NOT_PRESENT)

    with pytest.raises(ValueError, match="frozen"):
        result.summary = "mutated"  # type: ignore[misc]

    with pytest.raises(ValueError, match="at most"):
        IntelResult(source=HASHLOOKUP_SOURCE, status=IntelStatus.KNOWN_GOOD, summary="x" * 5_000)


def test_a_cut_example_name_is_marked_as_cut() -> None:
    """Measured live: NSRL paths exceed the cap, and a silent trim turned
    requires.txt into requires.tx, which reads as a real filename. The field is
    an example, so an abbreviated one must be distinguishable from an exact one."""
    body = {"FileName": "./usr/lib/python3/dist-packages/" + "d" * 80 + "/requires.txt"}

    summary = parse_hashlookup(body).summary

    assert summary.endswith("...")
    assert "requires.txt" not in summary


def test_a_short_example_name_is_left_alone() -> None:
    assert parse_hashlookup({"FileName": "ls"}).summary == "example name ls"
