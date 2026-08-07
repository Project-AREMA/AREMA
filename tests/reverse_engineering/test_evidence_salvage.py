"""Salvage of a strictly-invalid evidence envelope.

A live ``malware_analyst`` run lost every Ghidra finding to
``deep:evidence_envelope_invalid``. The strict ``EvidenceEnvelope`` is
all-or-nothing, so one malformed finding costs a whole stage its evidence.
These tests pin the recovery: well-formed findings survive, malformed ones are
dropped and counted, and nothing is ever invented to fill the gap.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from types import SimpleNamespace

import pytest

from reverse_engineering.agents.evidence_output import normalize_evidence_output
from reverse_engineering.evidence_envelope import (
    MAX_CLAIM_CHARS,
    MAX_FINDINGS,
    MAX_RAW_EVIDENCE_JSON_CHARS,
    MAX_SURFACE_CHARS,
    CoverageStatus,
    FindingKind,
    parse_evidence_envelope,
    salvage_evidence_envelope,
)
from reverse_engineering.tools.deobfuscation.state import CURRENT_ARTIFACT_KEY

ARTIFACT_ID = "a" * 64
OTHER_ARTIFACT_ID = "b" * 64
OUTPUT_KEY = "deep_evidence_json"


def _finding(**overrides: object) -> dict[str, object]:
    finding: dict[str, object] = {
        "artifact_id": ARTIFACT_ID,
        "claim": "Decompiled sub_401200 writes to /etc/profile.",
        "tool": "ghidra_decompile",
        "confidence": 0.8,
        "detail": 'fopen("/etc/profile", "a")',
        "kind": "behavior",
    }
    finding.update(overrides)
    return finding


def _omit(finding: dict[str, object], key: str) -> dict[str, object]:
    return {name: value for name, value in finding.items() if name != key}


def _payload(*findings: dict[str, object], **overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "artifact_id": ARTIFACT_ID,
        "coverage": {
            "status": "complete",
            "surfaces": ["ghidra_decompile"],
            "limitations": [],
        },
        "findings": list(findings) or [_finding()],
    }
    payload.update(overrides)
    return payload


# --- the defects that cost a whole stage today --------------------------------


@pytest.mark.parametrize(
    ("name", "payload"),
    [
        # Measured against the strict model, not assumed. Each of these costs a
        # stage every one of its findings today.
        ("omitted detail", _payload(_omit(_finding(), "detail"))),
        ("string confidence", _payload(_finding(confidence="0.8"))),
        ("extra key on a finding", _payload(_finding(source="ghidra", severity="high"))),
        ("null detail", _payload(_finding(detail=None))),
        ("extra key on the envelope", _payload(summary="analysis complete")),
        (
            "extra key on coverage",
            _payload(coverage={"status": "complete", "surfaces": [], "limitations": [], "n": 1}),
        ),
        ("unknown coverage status", _payload(coverage={"status": "done", "surfaces": []})),
    ],
)
def test_defects_that_cost_a_whole_stage_today_are_salvaged(
    name: str, payload: dict[str, object]
) -> None:
    with pytest.raises(ValueError):
        parse_evidence_envelope(json.dumps(payload), artifact_id=ARTIFACT_ID)

    envelope, _dropped, rebound = salvage_evidence_envelope(
        json.dumps(payload), artifact_id=ARTIFACT_ID
    )
    assert rebound is False, name
    assert envelope.findings, name
    assert envelope.findings[0].tool == "ghidra_decompile", name


@pytest.mark.parametrize("finding", [_omit(_finding(), "detail"), _finding(detail=None)])
def test_a_missing_detail_survives_as_empty_never_as_invented_text(
    finding: dict[str, object],
) -> None:
    """Omitted and explicitly null must mean the same thing, and neither may be
    filled in with text the model did not produce."""
    envelope, dropped, _ = salvage_evidence_envelope(
        json.dumps(_payload(finding)), artifact_id=ARTIFACT_ID
    )
    assert dropped == 0
    assert envelope.findings[0].detail == ""


def test_one_bad_kind_drops_only_that_finding() -> None:
    payload = _payload(
        _finding(claim="First real finding."),
        _finding(claim="Bad kind.", kind="string"),
        _finding(claim="Third real finding."),
    )
    envelope, dropped, _ = salvage_evidence_envelope(json.dumps(payload), artifact_id=ARTIFACT_ID)

    assert dropped == 1
    assert [f.claim for f in envelope.findings] == ["First real finding.", "Third real finding."]


def test_dropping_a_finding_downgrades_a_complete_coverage_claim() -> None:
    """A salvaged envelope may never keep claiming it covered everything."""
    payload = _payload(_finding(), _finding(claim="Bad.", kind="nonsense"))
    envelope, dropped, _ = salvage_evidence_envelope(json.dumps(payload), artifact_id=ARTIFACT_ID)

    assert dropped == 1
    assert envelope.coverage.status is CoverageStatus.PARTIAL


def test_clean_salvage_keeps_the_stage_own_coverage_status() -> None:
    envelope, dropped, _ = salvage_evidence_envelope(
        json.dumps(_payload(_finding(source="ghidra"))), artifact_id=ARTIFACT_ID
    )
    assert dropped == 0
    assert envelope.coverage.status is CoverageStatus.COMPLETE
    assert envelope.coverage.surfaces == ("ghidra_decompile",)


# --- artifact identity --------------------------------------------------------


def test_envelope_bound_to_another_artifact_is_rebound_not_discarded() -> None:
    payload = _payload(
        _finding(artifact_id=OTHER_ARTIFACT_ID),
        artifact_id=OTHER_ARTIFACT_ID,
    )
    envelope, dropped, rebound = salvage_evidence_envelope(
        json.dumps(payload), artifact_id=ARTIFACT_ID
    )

    assert rebound is True
    assert dropped == 0
    assert envelope.artifact_id == ARTIFACT_ID
    assert all(finding.artifact_id == ARTIFACT_ID for finding in envelope.findings)


def test_a_missing_envelope_anchor_defaults_without_counting_as_a_rebind() -> None:
    payload = _payload()
    del payload["artifact_id"]
    envelope, _dropped, rebound = salvage_evidence_envelope(
        json.dumps(payload), artifact_id=ARTIFACT_ID
    )

    assert rebound is False
    assert envelope.artifact_id == ARTIFACT_ID


def test_a_finding_naming_a_third_artifact_is_dropped_never_relabelled() -> None:
    """Relabelling would silently reattribute another binary's evidence."""
    payload = _payload(_finding(), _finding(claim="Foreign.", artifact_id=OTHER_ARTIFACT_ID))
    envelope, dropped, _ = salvage_evidence_envelope(json.dumps(payload), artifact_id=ARTIFACT_ID)

    assert dropped == 1
    assert [f.claim for f in envelope.findings] == ["Decompiled sub_401200 writes to /etc/profile."]


# --- nothing recoverable: today's behaviour is preserved ----------------------


def test_prose_is_still_unrecoverable() -> None:
    with pytest.raises(ValueError):
        salvage_evidence_envelope(
            "I analyzed the binary and found a persistence mechanism.", artifact_id=ARTIFACT_ID
        )


def test_a_bare_list_is_still_unrecoverable() -> None:
    with pytest.raises(ValueError):
        salvage_evidence_envelope(json.dumps([1, 2, 3]), artifact_id=ARTIFACT_ID)


def test_every_finding_malformed_is_still_unrecoverable() -> None:
    payload = _payload(_finding(kind="bogus"), _finding(kind="also_bogus"))
    with pytest.raises(ValueError):
        salvage_evidence_envelope(json.dumps(payload), artifact_id=ARTIFACT_ID)


def test_an_envelope_with_no_findings_is_left_to_the_strict_path() -> None:
    """It already parses strictly, so salvage must not invent a reason to keep it."""
    payload = _payload(findings=[])
    assert parse_evidence_envelope(json.dumps(payload), artifact_id=ARTIFACT_ID).findings == ()
    with pytest.raises(ValueError):
        salvage_evidence_envelope(json.dumps(payload), artifact_id=ARTIFACT_ID)


def test_salvage_rejects_a_non_canonical_session_artifact() -> None:
    with pytest.raises(ValueError):
        salvage_evidence_envelope(json.dumps(_payload()), artifact_id="not-a-sha")


# --- bounds still hold after coercion -----------------------------------------


def test_an_over_long_claim_is_dropped_not_truncated_into_a_survivor() -> None:
    payload = _payload(_finding(), _finding(claim="x" * (MAX_CLAIM_CHARS + 1)))
    envelope, dropped, _ = salvage_evidence_envelope(json.dumps(payload), artifact_id=ARTIFACT_ID)

    assert dropped == 1
    assert len(envelope.findings) == 1
    assert len(envelope.findings[0].claim) <= MAX_CLAIM_CHARS


def test_an_empty_claim_or_tool_is_dropped() -> None:
    payload = _payload(_finding(), _finding(claim=""), _finding(tool=""))
    envelope, dropped, _ = salvage_evidence_envelope(json.dumps(payload), artifact_id=ARTIFACT_ID)

    assert dropped == 2
    assert len(envelope.findings) == 1


def test_findings_beyond_the_cap_are_counted_as_dropped() -> None:
    payload = _payload(*[_finding(claim=f"Finding {i}.") for i in range(MAX_FINDINGS + 3)])
    envelope, dropped, _ = salvage_evidence_envelope(json.dumps(payload), artifact_id=ARTIFACT_ID)

    assert len(envelope.findings) == MAX_FINDINGS
    assert dropped == 3
    assert envelope.coverage.status is CoverageStatus.PARTIAL


def test_out_of_range_surfaces_and_limitations_are_filtered_individually() -> None:
    payload = _payload(
        coverage={
            "status": "partial",
            "surfaces": ["ghidra_decompile", "", "y" * (MAX_SURFACE_CHARS + 1), 7],
            "limitations": ["deep:analysis_incomplete", ""],
        }
    )
    envelope, _dropped, _rebound = salvage_evidence_envelope(
        json.dumps(payload), artifact_id=ARTIFACT_ID
    )

    assert envelope.coverage.surfaces == ("ghidra_decompile",)
    assert envelope.coverage.limitations == ("deep:analysis_incomplete",)


def test_an_unusable_coverage_block_falls_back_to_partial_and_keeps_findings() -> None:
    envelope, _dropped, _rebound = salvage_evidence_envelope(
        json.dumps(_payload(coverage="complete")), artifact_id=ARTIFACT_ID
    )

    assert envelope.coverage.status is CoverageStatus.PARTIAL
    assert envelope.coverage.surfaces == ()
    assert len(envelope.findings) == 1


def test_oversized_raw_json_is_rejected_before_any_parsing() -> None:
    with pytest.raises(ValueError):
        salvage_evidence_envelope("x" * (MAX_RAW_EVIDENCE_JSON_CHARS + 1), artifact_id=ARTIFACT_ID)


# --- the boundary still does its normal work ----------------------------------


def test_salvage_sees_through_a_code_fence() -> None:
    fenced = f"```json\n{json.dumps(_payload(_finding(source='ghidra')))}\n```"
    envelope, dropped, _ = salvage_evidence_envelope(fenced, artifact_id=ARTIFACT_ID)

    assert dropped == 0
    assert envelope.findings[0].kind is FindingKind.BEHAVIOR


def test_salvage_recovers_the_sole_envelope_from_a_multi_object_turn() -> None:
    raw = json.dumps({"note": "done"}) + "\n" + json.dumps(_payload(_finding(source="ghidra")))
    envelope, dropped, _ = salvage_evidence_envelope(raw, artifact_id=ARTIFACT_ID)

    assert dropped == 0
    assert len(envelope.findings) == 1


def test_salvage_accepts_an_already_decoded_mapping() -> None:
    envelope, dropped, _ = salvage_evidence_envelope(
        _payload(_finding(source="ghidra")), artifact_id=ARTIFACT_ID
    )

    assert dropped == 0
    assert envelope.artifact_id == ARTIFACT_ID


# --- wired into the after-agent normalizer ------------------------------------


def _normalized(raw: object, *, stage: str = "deep", accumulate: bool = False) -> dict[str, object]:
    state: dict[str, object] = {CURRENT_ARTIFACT_KEY: ARTIFACT_ID, OUTPUT_KEY: raw}
    normalize_evidence_output(
        SimpleNamespace(state=state), output_key=OUTPUT_KEY, stage=stage, accumulate=accumulate
    )
    stored = state[OUTPUT_KEY]
    assert isinstance(stored, dict)
    return stored


def test_the_incident_shape_keeps_its_findings_instead_of_failing_the_stage() -> None:
    """The regression: one malformed finding used to cost the deep stage all of
    them and leave only ``deep:evidence_envelope_invalid`` for the reader."""
    stored = _normalized(
        json.dumps(
            _payload(
                _finding(claim="Ghidra decompiled the OEP."),
                _finding(claim="Broken.", kind="observation"),
            )
        )
    )

    assert [f["claim"] for f in stored["findings"]] == ["Ghidra decompiled the OEP."]
    assert "deep:evidence_envelope_invalid" not in stored["coverage"]["limitations"]
    assert "deep:findings_dropped:1" in stored["coverage"]["limitations"]


def test_a_clean_salvage_adds_no_limitation_at_all() -> None:
    stored = _normalized(json.dumps(_payload(_finding(source="ghidra"))))

    assert stored["coverage"]["limitations"] == []
    assert len(stored["findings"]) == 1


def test_a_rebound_envelope_says_so_in_its_coverage() -> None:
    payload = _payload(_finding(artifact_id=OTHER_ARTIFACT_ID), artifact_id=OTHER_ARTIFACT_ID)
    stored = _normalized(json.dumps(payload))

    assert stored["artifact_id"] == ARTIFACT_ID
    assert "deep:evidence_rebound" in stored["coverage"]["limitations"]


def test_the_stage_own_limitations_survive_salvage() -> None:
    payload = _payload(
        _finding(source="ghidra"),
        coverage={
            "status": "partial",
            "surfaces": ["ghidra_decompile"],
            "limitations": ["deep:analysis_incomplete"],
        },
    )
    stored = _normalized(json.dumps(payload))

    assert "deep:analysis_incomplete" in stored["coverage"]["limitations"]


def test_unrecoverable_output_still_fails_the_stage_exactly_as_before() -> None:
    stored = _normalized("Ghidra could not load the binary.")

    assert stored == {
        "artifact_id": ARTIFACT_ID,
        "coverage": {
            "status": "failed",
            "surfaces": [],
            "limitations": ["deep:evidence_envelope_invalid"],
        },
        "findings": [],
        "flow": None,
        "verdict": None,
    }


def test_the_salvage_log_names_field_paths_and_counts_never_model_content(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """structlog prints to stdout, so the diagnostic is read from there."""
    secret = "c2.attacker.example/beacon-do-not-log"
    payload = _payload(_finding(detail=secret), _finding(claim=secret, kind="observation"))

    stored = _normalized(json.dumps(payload))
    logged = capsys.readouterr().out

    assert stored["findings"][0]["detail"] == secret  # kept as evidence
    assert secret not in logged  # never as a diagnostic
    # The field path and failure kind identify what the model got wrong without
    # quoting it. Asserted on the payload only -- the renderer is JSON or console
    # depending on which test configured logging first, so key/value spelling is
    # not stable, while the substrings below are.
    assert "findings.1.kind:enum" in logged
    assert "salvaged after strict rejection" in logged


def test_a_salvaged_envelope_merges_into_the_loop_running_best() -> None:
    """A salvaged pass must be treated as valid by the accumulator, or the deep
    loop would keep dropping it on every later iteration."""
    state: dict[str, object] = {
        CURRENT_ARTIFACT_KEY: ARTIFACT_ID,
        OUTPUT_KEY: json.dumps(_payload(_finding(claim="Pass one.", source="ghidra"))),
    }
    normalize_evidence_output(
        SimpleNamespace(state=state), output_key=OUTPUT_KEY, stage="deep", accumulate=True
    )
    state[OUTPUT_KEY] = json.dumps(_payload(_finding(claim="Pass two.", source="ghidra")))
    normalize_evidence_output(
        SimpleNamespace(state=state), output_key=OUTPUT_KEY, stage="deep", accumulate=True
    )

    stored = state[OUTPUT_KEY]
    assert isinstance(stored, dict)
    assert [f["claim"] for f in stored["findings"]] == ["Pass one.", "Pass two."]


def test_a_hostile_mapping_that_raises_while_read_still_fails_closed() -> None:
    class _Hostile(Mapping[str, object]):
        def __getitem__(self, _key: str) -> object:
            raise RuntimeError("boom")

        def __iter__(self) -> Iterator[str]:
            raise RuntimeError("boom")

        def __len__(self) -> int:
            return 1

    stored = _normalized(_Hostile())

    assert stored["coverage"]["limitations"] == ["deep:evidence_envelope_invalid"]
    assert stored["findings"] == []
