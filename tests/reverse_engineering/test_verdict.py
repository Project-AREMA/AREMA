"""The sample's disposition is a validated value, not a sentence.

Run against UPX-packed GNU coreutils ``ls``, the pipeline mapped T1027.002 (the
container is packed) and T1083 (``ls`` calls ``readdir``) and listed "indicators
of compromise" for a stock system utility. Both mappings were true and both were
meaningless: ATT&CK techniques describe what code *can* do, never intent, and
nothing in the pipeline could say "this is fine".
"""

from __future__ import annotations

import json

import pytest

from reverse_engineering.agents.evidence_output import (
    EXECUTION_FLOW_MERMAID_KEY,
    SAMPLE_VERDICT_KEY,
    SAMPLE_VERDICT_RATIONALE_KEY,
)
from reverse_engineering.evidence_envelope import (
    parse_evidence_envelope,
    rebind_evidence_envelope,
    salvage_evidence_envelope,
)
from reverse_engineering.verdict import (
    MAX_RATIONALE_CHARS,
    SampleVerdict,
    VerdictClass,
    sanitize_verdict,
    verdict_label,
)

AID = "a" * 64
RATIONALE = "Unmodified GNU coreutils ls; no execution, network, or write sink reachable."


def _verdict(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {"classification": "benign", "rationale": RATIONALE}
    payload.update(overrides)
    return payload


def _envelope(verdict: object) -> dict[str, object]:
    return {
        "artifact_id": AID,
        "coverage": {"status": "complete", "surfaces": ["ghidra_metadata"], "limitations": []},
        "findings": [
            {
                "artifact_id": AID,
                "claim": "Stock coreutils ls, no dangerous sinks.",
                "tool": "ghidra_search_decompiled",
                "confidence": 0.9,
                "detail": "zero matches for execve/socket/unlink across 191 functions",
                "kind": "behavior",
            }
        ],
        "verdict": verdict,
    }


# --- the model's disposition ---------------------------------------------------


@pytest.mark.parametrize("name", ["benign", "grayware", "malicious"])
def test_each_declarable_disposition_is_accepted(name: str) -> None:
    verdict = sanitize_verdict(_verdict(classification=name))

    assert verdict is not None
    assert verdict.classification is VerdictClass(name)


@pytest.mark.parametrize("spelling", ["BENIGN", "  Benign ", "MaLiCiOuS"])
def test_casing_and_padding_are_normalized(spelling: str) -> None:
    verdict = sanitize_verdict(_verdict(classification=spelling))

    assert verdict is not None
    assert verdict.classification.value == spelling.strip().lower()


def test_a_model_may_not_claim_undetermined() -> None:
    """UNDETERMINED is the pipeline's own marker for "nobody decided". Letting a
    model claim it would be a way to dodge the question while looking answered."""
    assert sanitize_verdict(_verdict(classification="undetermined")) is None


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "benign",
        [],
        {},
        _verdict(classification="suspicious"),
        _verdict(classification="clean"),
        _verdict(classification=7),
        _verdict(rationale=""),
        _verdict(rationale="   "),
        _verdict(rationale=None),
        {"classification": "benign"},
        {"rationale": RATIONALE},
    ],
)
def test_unusable_input_yields_no_verdict_rather_than_an_error(raw: object) -> None:
    assert sanitize_verdict(raw) is None


def test_a_rationale_is_bounded_and_single_line() -> None:
    verdict = sanitize_verdict(
        _verdict(rationale="line one\n\tline two   " + "x" * (MAX_RATIONALE_CHARS + 50))
    )

    assert verdict is not None
    assert "\n" not in verdict.rationale
    assert len(verdict.rationale) <= MAX_RATIONALE_CHARS


def test_a_rationale_cannot_smuggle_an_instruction_placeholder() -> None:
    """It is injected into an ADK instruction template, where a brace would be
    resolved as a state placeholder."""
    verdict = sanitize_verdict(_verdict(rationale="benign but {validated_evidence_json?}"))

    assert verdict is not None
    assert "{" not in verdict.rationale
    assert "}" not in verdict.rationale


def test_non_ascii_is_reduced_rather_than_carried() -> None:
    verdict = sanitize_verdict(_verdict(rationale="stock ls 你好 utility"))

    assert verdict is not None
    assert verdict.rationale == "stock ls utility"


def test_the_default_label_is_undetermined() -> None:
    assert verdict_label(None) == "UNDETERMINED"
    assert verdict_label(SampleVerdict(classification=VerdictClass.BENIGN, rationale="x")) == (
        "BENIGN"
    )


# --- carried on the envelope, unable to harm it -------------------------------


def test_a_verdict_rides_the_envelope_and_round_trips() -> None:
    envelope = parse_evidence_envelope(json.dumps(_envelope(_verdict())), artifact_id=AID)

    assert envelope.verdict is not None
    assert envelope.verdict.classification is VerdictClass.BENIGN

    reparsed = parse_evidence_envelope(envelope.model_dump(mode="json"), artifact_id=AID)
    assert reparsed.verdict == envelope.verdict


@pytest.mark.parametrize(
    "verdict",
    [
        None,
        "benign",
        {"classification": "suspicious", "rationale": RATIONALE},
        {"classification": "benign", "rationale": "", "extra": True},
        {"nodes": []},
    ],
)
def test_a_malformed_verdict_never_costs_the_stage_its_findings(verdict: object) -> None:
    """The same guarantee the diagram has: a judgement the model got wrong in
    shape must not discard the evidence it got right."""
    envelope = parse_evidence_envelope(json.dumps(_envelope(verdict)), artifact_id=AID)

    assert len(envelope.findings) == 1
    assert envelope.verdict is None


def test_a_salvaged_envelope_keeps_a_good_verdict() -> None:
    payload = {**_envelope(_verdict(classification="malicious")), "summary": "stray key"}
    envelope, _dropped, _rebound = salvage_evidence_envelope(json.dumps(payload), artifact_id=AID)

    assert envelope.verdict is not None
    assert envelope.verdict.classification is VerdictClass.MALICIOUS


def test_rebinding_carries_the_verdict_across_the_new_anchor() -> None:
    envelope = parse_evidence_envelope(json.dumps(_envelope(_verdict())), artifact_id=AID)
    rebound = rebind_evidence_envelope(envelope, artifact_id="b" * 64)

    assert rebound.verdict == envelope.verdict


def test_the_state_keys_stay_identifier_safe() -> None:
    """ADK instruction templating resolves ``{name?}`` by exact key, so a colon
    would silently never resolve."""
    for key in (SAMPLE_VERDICT_KEY, SAMPLE_VERDICT_RATIONALE_KEY, EXECUTION_FLOW_MERMAID_KEY):
        assert key.isidentifier()
