"""Indicators a third party associates with a digest.

Every body below was measured against the live VirusTotal API with a premium key
on the QuasarRAT sample `1595d92f…`, so the parser is tested against the real
contract. Two things the documentation did not predict shape it: a URL object's
``id`` is a hash while the URL itself lives in ``attributes.url``, and a file
object's ``id`` *is* its SHA-256 — so reading ``id`` uniformly would put opaque
hashes in the report where URLs belong.

The measurement also produced the rule that matters most. `itw_urls` returned a
live distribution URL at **16/49 malicious** while `contacted_ips` returned five
Microsoft Teams endpoints at **0/91**. Without the ratio a report presents those
as the same kind of fact.
"""

from __future__ import annotations

import pytest
from pydantic import SecretStr

from malware_analyst.prompts.loader import load_malware_prompt
from reverse_engineering.intel import relations as relations_module
from reverse_engineering.intel.config import IntelSettings
from reverse_engineering.intel.lookup import (
    MAX_RELATIONS_LINE_CHARS,
    gather_relations,
    render_relations_block,
)
from reverse_engineering.intel.models import (
    MAX_RELATION_VALUE_CHARS,
    VIRUSTOTAL_SOURCE,
    IntelRelation,
)
from reverse_engineering.intel.relations import (
    MAX_ITEMS_PER_RELATION,
    RELATIONS,
    fetch_relations,
    parse_relation,
)
from reverse_engineering.prompts.loader import load_domain_prompt
from reverse_engineering.tools.acquire_sample import SAMPLE_RELATIONS_PROMPT_KEY

AID = "1595d92fb580ab1264b533c3504863062bf47d8ce61e838c64179b904f2a6d23"
C2 = (
    "http://floneimf.ydns.eu/webcontents/drsgtsrhydtesrtshtigushdfhsdufhuhdsfrgsthfxh/"
    "ibKUVSEfbgrnsrkgtsdzthsftgzhthsthsfg/contents.exe"
)

# Measured: GET /files/{id}/itw_urls. The id is a hash; the URL is an attribute.
ITW_URLS: dict[str, object] = {
    "data": [
        {
            "type": "url",
            "id": "945852b0f0054e1cf09683853a269fb3b87419a490dd57f2d29c13d7ae890b36",
            "attributes": {
                "url": C2,
                "reputation": -58,
                "last_analysis_stats": {
                    "malicious": 16,
                    "suspicious": 1,
                    "undetected": 29,
                    "harmless": 49,
                    "timeout": 0,
                },
            },
        }
    ],
    "links": {},
    "meta": {},
}

# Measured: GET /files/{id}/dropped_files. Here the id IS the sha256.
DROPPED_FILES: dict[str, object] = {
    "data": [
        {
            "type": "file",
            "id": "e2980ccd6345d55c608ef790e4f95bc2fb53dbaebdd63c24b605ae62653655af",
            "attributes": {
                "meaningful_name": "encrypted.exe.log",
                "type_description": "Text",
                "size": 1024,
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 62,
                    "harmless": 0,
                    "timeout": 0,
                    "confirmed-timeout": 0,
                    "failure": 1,
                    "type-unsupported": 14,
                },
            },
        }
    ]
}

EMPTY: dict[str, object] = {"data": [], "links": {}, "meta": {}}


class _Response:
    def __init__(self, status_code: int, body: object = None) -> None:
        self.status_code = status_code
        self._body = body

    def json(self) -> object:
        if self._body is None:
            raise ValueError("not json")
        return self._body


def _keyed() -> IntelSettings:
    return IntelSettings(virustotal_api_key=SecretStr("k"), malwarebazaar_api_key=None)


def _unkeyed() -> IntelSettings:
    return IntelSettings(virustotal_api_key=None, malwarebazaar_api_key=None)


# --- the parser, against measured bodies --------------------------------------


def test_a_url_object_yields_its_url_not_its_id() -> None:
    """The id is a hash of the URL. Reading it uniformly would put an opaque
    64-character string in the report where the indicator belongs."""
    (found,) = parse_relation(ITW_URLS, kind="in-the-wild URL")

    assert found.value == C2
    assert found.source == VIRUSTOTAL_SOURCE
    assert found.kind == "in-the-wild URL"


def test_a_url_carries_its_detection_ratio() -> None:
    """16 of 95 buckets summed. The denominator is what the API returned, so the
    ratio is reproducible from the response alone."""
    (found,) = parse_relation(ITW_URLS, kind="in-the-wild URL")

    assert found.malicious == 16
    assert found.total == 95
    assert found.ratio == "16/95"


def test_a_file_object_yields_its_digest_and_its_name() -> None:
    """Here the id IS the sha256, and a dropped filename is a real host
    indicator worth carrying."""
    (found,) = parse_relation(DROPPED_FILES, kind="dropped file")

    assert found.value.startswith("e2980ccd6345")
    assert found.name == "encrypted.exe.log"


def test_a_zero_detection_indicator_is_kept_not_dropped() -> None:
    """0/77 is a fact, and the analyst decides what it means. Filtering by
    detection count here would hide a C2 nobody has flagged yet."""
    (found,) = parse_relation(DROPPED_FILES, kind="dropped file")

    assert found.malicious == 0
    assert found.total == 77
    assert found.ratio == "0/77"


def test_an_indicator_with_no_engine_results_has_an_empty_ratio() -> None:
    payload = {"data": [{"type": "domain", "id": "evil.invalid", "attributes": {}}]}
    (found,) = parse_relation(payload, kind="embedded domain")

    assert found.value == "evil.invalid"
    assert found.ratio == ""


@pytest.mark.parametrize("payload", [None, "", [], {}, {"data": None}, {"data": "x"}, 7])
def test_an_unusable_body_yields_nothing_rather_than_raising(payload: object) -> None:
    assert parse_relation(payload, kind="dropped file") == ()


def test_items_without_a_value_are_skipped() -> None:
    payload = {"data": [{"type": "url", "id": "h", "attributes": {}}, None, "junk"]}

    assert parse_relation(payload, kind="in-the-wild URL") == ()


def test_the_item_count_is_bounded() -> None:
    """A sample with hundreds of bundled files is a container, and listing them
    all tells an analyst nothing the count does not."""
    payload = {
        "data": [
            {"type": "file", "id": f"{i:064x}", "attributes": {}}
            for i in range(MAX_ITEMS_PER_RELATION * 5)
        ]
    }

    assert len(parse_relation(payload, kind="bundled file")) == MAX_ITEMS_PER_RELATION


def test_a_value_is_bounded_and_template_safe() -> None:
    """These are attacker-controlled strings arriving through a trusted-looking
    API, and they end up in an ADK instruction template."""
    payload = {
        "data": [
            {
                "type": "url",
                "id": "h",
                "attributes": {"url": "http://evil.invalid/{sample_intel?}/" + "a" * 500},
            }
        ]
    }
    (found,) = parse_relation(payload, kind="in-the-wild URL")

    assert "{" not in found.value
    assert "}" not in found.value
    assert len(found.value) <= MAX_RELATION_VALUE_CHARS


def test_a_dropped_filename_cannot_smuggle_a_placeholder() -> None:
    payload = {
        "data": [
            {"type": "file", "id": "a" * 64, "attributes": {"meaningful_name": "`{evil?}`.exe"}}
        ]
    }
    (found,) = parse_relation(payload, kind="dropped file")

    assert "{" not in found.name
    assert "`" not in found.name


# --- which relationships are asked, and which are not -------------------------


def test_contacted_relationships_are_not_requested() -> None:
    """Measured: every contacted_ip on a real sample was a Microsoft Teams
    endpoint. They are observations of a whole sandbox detonation, not
    indicators of the sample."""
    asked = {relation for relation, _label in RELATIONS}

    assert not any(name.startswith("contacted_") for name in asked)


def test_the_high_signal_relationships_are_requested() -> None:
    asked = {relation for relation, _label in RELATIONS}

    assert {"itw_urls", "embedded_urls", "dropped_files", "bundled_files"} <= asked


# --- the fetch ----------------------------------------------------------------


def test_no_key_means_no_request(monkeypatch: pytest.MonkeyPatch) -> None:
    def _explode(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("relations must not be fetched without a credential")

    monkeypatch.setattr(relations_module.httpx, "get", _explode)

    assert fetch_relations(AID, settings=_unkeyed(), timeout=5.0) == ()
    assert gather_relations(AID, settings=_unkeyed()) == ()


def test_only_the_digest_and_the_key_are_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[dict[str, object]] = []

    def _capture(url: str, **kwargs: object) -> _Response:
        seen.append({"url": url, **kwargs})
        return _Response(200, EMPTY)

    monkeypatch.setattr(relations_module.httpx, "get", _capture)
    fetch_relations(AID, settings=_keyed(), timeout=5.0)

    assert len(seen) == len(RELATIONS)
    for call in seen:
        assert AID in str(call["url"])
        assert call["headers"] == {"x-apikey": "k"}
        assert "files" not in call
        assert "data" not in call


def test_one_failing_relationship_does_not_suppress_the_others(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"n": 0}

    def _flaky(_url: str, **_kwargs: object) -> _Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return _Response(500)
        return _Response(200, ITW_URLS)

    monkeypatch.setattr(relations_module.httpx, "get", _flaky)
    found = fetch_relations(AID, settings=_keyed(), timeout=5.0)

    assert len(found) == len(RELATIONS) - 1


def test_a_transport_failure_degrades(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(*_args: object, **_kwargs: object) -> object:
        raise OSError("network unreachable")

    monkeypatch.setattr(relations_module.httpx, "get", _raise)

    assert fetch_relations(AID, settings=_keyed(), timeout=5.0) == ()


def test_a_non_json_body_degrades(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(relations_module.httpx, "get", lambda *_a, **_k: _Response(200))

    assert fetch_relations(AID, settings=_keyed(), timeout=5.0) == ()


# --- the rendered block -------------------------------------------------------


def _relation(**overrides: object) -> IntelRelation:
    payload: dict[str, object] = {
        "source": VIRUSTOTAL_SOURCE,
        "kind": "in-the-wild URL",
        "value": C2,
        "malicious": 16,
        "total": 49,
    }
    payload.update(overrides)
    return IntelRelation(**payload)  # type: ignore[arg-type]


def test_the_block_carries_the_ratio_beside_every_value() -> None:
    """Without it a live C2 and an analysis VM's Office traffic read the same."""
    block = render_relations_block(
        [
            _relation(),
            _relation(kind="embedded URL", value="https://discord.gg/x", malicious=0, total=91),
        ]
    )

    assert "[16/49]" in block
    assert "[0/91]" in block


def test_the_block_names_the_kind_of_each_indicator() -> None:
    block = render_relations_block([_relation(kind="dropped file", value="a" * 64)])

    assert "dropped file:" in block


def test_a_filename_is_carried_when_present() -> None:
    block = render_relations_block(
        [_relation(kind="dropped file", value="a" * 64, name="encrypted.exe.log")]
    )

    assert "(encrypted.exe.log)" in block


def test_an_empty_set_renders_nothing() -> None:
    assert render_relations_block([]) == ""


def test_the_block_is_bounded_and_template_safe() -> None:
    block = render_relations_block([_relation(value="http://x.invalid/" + "a" * 150)] * 40)

    assert len(block) <= MAX_RELATIONS_LINE_CHARS
    assert "{" not in block
    assert "\n" not in block


# --- the prompts that consume it ----------------------------------------------


def _triage() -> str:
    return load_domain_prompt("triage_recon")


def _report() -> str:
    return load_malware_prompt("malware_report_generator")


def test_triage_reads_the_alias_intake_writes() -> None:
    assert f"{{{SAMPLE_RELATIONS_PROMPT_KEY}?}}" in _triage()
    assert SAMPLE_RELATIONS_PROMPT_KEY.isidentifier()


def test_the_relations_placeholder_appears_exactly_once() -> None:
    """ADK substitutes every occurrence; a duplicate pastes the whole list twice."""
    assert _triage().count(f"{{{SAMPLE_RELATIONS_PROMPT_KEY}?}}") == 1


def test_triage_forbids_turning_an_association_into_an_observation() -> None:
    """VirusTotal links a URL to a digest. Nothing here executed the sample, so
    nobody saw it contact anything."""
    prompt = _triage()

    assert "These are associations, not observations." in prompt
    assert "never" in prompt and "the sample contacts" in prompt


def test_triage_keeps_relations_out_of_the_ioc_kinds() -> None:
    """host_ioc and network_ioc are for indicators the analysis found in the
    bytes. Merging destroys the distinction in strength."""
    prompt = _triage()

    assert "never `network_ioc` or `host_ioc`" in prompt


def test_triage_requires_the_ratio_to_travel_with_the_indicator() -> None:
    prompt = _triage()

    assert "The bracketed ratio is the point." in prompt
    assert "[16/49]" in prompt


def test_report_table_carries_type_and_detections() -> None:
    report = _report()

    assert "`Source | Type | Value | Detections`" in report
    assert "The detection ratio is load-bearing" in report


def test_report_forbids_asserting_contact() -> None:
    report = _report()

    assert "VirusTotal associates this URL with the sample" in report
    assert "no contact was observed by anyone here" in report
