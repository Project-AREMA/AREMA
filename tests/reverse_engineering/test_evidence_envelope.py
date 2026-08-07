"""Tests for bounded artifact-bound evidence state."""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from reverse_engineering import evidence_envelope as evidence_envelope_module
from reverse_engineering.agents.evidence_output import normalize_evidence_output
from reverse_engineering.evidence_envelope import (
    MAX_CLAIM_CHARS,
    MAX_DETAIL_CHARS,
    MAX_FINDINGS,
    MAX_LIMITATION_CHARS,
    MAX_LIMITATIONS,
    MAX_RAW_EVIDENCE_JSON_CHARS,
    MAX_SURFACE_CHARS,
    MAX_SURFACES,
    MAX_TOOL_CHARS,
    CoverageStatus,
    EvidenceCoverage,
    EvidenceEnvelope,
    EvidenceFinding,
    FindingKind,
    failed_evidence_envelope,
    parse_evidence_envelope,
    rebind_evidence_envelope,
)
from reverse_engineering.tools.deobfuscation.state import CURRENT_ARTIFACT_KEY

ARTIFACT_ID = "a" * 64
OTHER_ARTIFACT_ID = "b" * 64
OUTPUT_KEY = "analysis:evidence"


def _payload(*, artifact_id: str = ARTIFACT_ID) -> dict[str, object]:
    return {
        "artifact_id": artifact_id,
        "coverage": {
            "status": "partial",
            "surfaces": ["imports"],
            "limitations": ["network:unavailable"],
        },
        "findings": [
            {
                "artifact_id": artifact_id,
                "claim": "Imports include a suspicious API.",
                "tool": "radare2",
                "confidence": 0.9,
                "detail": "Observed import table entry.",
                "kind": "host_ioc",
            }
        ],
    }


def _stored(payload: dict[str, object]) -> dict[str, object]:
    """The payload as a dumped envelope: the optional judgement keys (execution
    flow, verdict) are always present in the dump, and absent by default."""
    return {**payload, "flow": None, "verdict": None}


def test_parse_accepts_exact_artifact_bound_json_and_preserves_enums() -> None:
    envelope = parse_evidence_envelope(json.dumps(_payload()), artifact_id=ARTIFACT_ID)

    assert isinstance(envelope, EvidenceEnvelope)
    assert envelope.artifact_id == ARTIFACT_ID
    assert envelope.coverage.status is CoverageStatus.PARTIAL
    assert envelope.findings[0].kind is FindingKind.HOST_IOC


def test_parse_accepts_mapping_input() -> None:
    envelope = parse_evidence_envelope(_payload(), artifact_id=ARTIFACT_ID)

    assert envelope.model_dump(mode="json") == _stored(_payload())


def test_rebind_re_anchors_envelope_and_every_finding() -> None:
    envelope = parse_evidence_envelope(
        _payload(artifact_id=OTHER_ARTIFACT_ID), artifact_id=OTHER_ARTIFACT_ID
    )

    rebound = rebind_evidence_envelope(envelope, artifact_id=ARTIFACT_ID)

    assert rebound.artifact_id == ARTIFACT_ID
    assert all(finding.artifact_id == ARTIFACT_ID for finding in rebound.findings)
    # Only the anchor id changes -- claim/tool/detail/coverage are preserved verbatim.
    assert [f.claim for f in rebound.findings] == [f.claim for f in envelope.findings]
    assert rebound.coverage == envelope.coverage


def test_rebind_to_the_same_artifact_is_a_noop() -> None:
    envelope = parse_evidence_envelope(_payload(), artifact_id=ARTIFACT_ID)

    assert rebind_evidence_envelope(envelope, artifact_id=ARTIFACT_ID) is envelope


def test_parse_rejects_raw_json_over_size_ceiling_without_parsing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_parse(*_args: object, **_kwargs: object) -> object:
        pytest.fail("over-cap raw JSON must be rejected before parsing")

    monkeypatch.setattr(evidence_envelope_module.json, "loads", unexpected_parse)

    with pytest.raises(ValueError, match="maximum"):
        parse_evidence_envelope(
            "x" * (MAX_RAW_EVIDENCE_JSON_CHARS + 1),
            artifact_id=ARTIFACT_ID,
        )


def test_parse_accepts_maximum_sized_astral_escaped_envelope() -> None:
    astral = "\U00010000"
    finding = {
        "artifact_id": ARTIFACT_ID,
        "claim": astral * MAX_CLAIM_CHARS,
        "tool": astral * MAX_TOOL_CHARS,
        "confidence": 1.0,
        "detail": astral * MAX_DETAIL_CHARS,
        "kind": "network_ioc",
    }
    payload = {
        "artifact_id": ARTIFACT_ID,
        "coverage": {
            "status": "complete",
            "surfaces": [astral * MAX_SURFACE_CHARS] * MAX_SURFACES,
            "limitations": [astral * MAX_LIMITATION_CHARS] * MAX_LIMITATIONS,
        },
        "findings": [finding] * MAX_FINDINGS,
    }
    raw = json.dumps(payload, ensure_ascii=True)

    assert len(raw) <= MAX_RAW_EVIDENCE_JSON_CHARS
    envelope = parse_evidence_envelope(raw, artifact_id=ARTIFACT_ID)

    assert len(envelope.findings) == MAX_FINDINGS
    assert envelope.findings[-1].detail == astral * MAX_DETAIL_CHARS


def test_models_use_immutable_collections_and_dump_json_arrays() -> None:
    envelope = parse_evidence_envelope(_payload(), artifact_id=ARTIFACT_ID)

    assert isinstance(envelope.coverage.surfaces, tuple)
    assert isinstance(envelope.coverage.limitations, tuple)
    assert isinstance(envelope.findings, tuple)
    with pytest.raises(AttributeError):
        envelope.coverage.surfaces.append("functions")
    with pytest.raises(AttributeError):
        envelope.findings.append(envelope.findings[0])
    assert envelope.model_dump(mode="json") == _stored(_payload())


def test_parse_revalidates_constructed_model_instances() -> None:
    finding = EvidenceFinding.model_validate(_payload()["findings"][0])  # type: ignore[arg-type,index]
    malformed_models = (
        EvidenceEnvelope.model_construct(
            artifact_id=ARTIFACT_ID,
            coverage=EvidenceCoverage.model_construct(
                status=CoverageStatus.PARTIAL,
                surfaces=("x" * 129,),
                limitations=(),
            ),
            findings=(),
        ),
        EvidenceEnvelope.model_construct(
            artifact_id=ARTIFACT_ID,
            coverage=EvidenceCoverage.model_construct(
                status=CoverageStatus.PARTIAL,
                surfaces=(),
                limitations=(),
            ),
            findings=(finding,) * (MAX_FINDINGS + 1),
        ),
        EvidenceEnvelope.model_construct(
            artifact_id=ARTIFACT_ID,
            coverage=EvidenceCoverage.model_construct(
                status=CoverageStatus.PARTIAL,
                surfaces=(),
                limitations=(),
            ),
            findings=(
                EvidenceFinding.model_construct(
                    artifact_id=OTHER_ARTIFACT_ID,
                    claim="cross-artifact",
                    tool="tool",
                    confidence=0.5,
                    detail="",
                    kind=FindingKind.METADATA,
                ),
            ),
        ),
    )

    for malformed in malformed_models:
        with pytest.raises(ValidationError):
            parse_evidence_envelope(malformed, artifact_id=ARTIFACT_ID)


@pytest.mark.parametrize(
    "payload, artifact_id",
    [
        (_payload(artifact_id="A" * 64), "A" * 64),
        (_payload(artifact_id=OTHER_ARTIFACT_ID), ARTIFACT_ID),
        (
            {
                **_payload(),
                "findings": [{**_payload()["findings"][0], "artifact_id": OTHER_ARTIFACT_ID}],
            },
            ARTIFACT_ID,
        ),
    ],
)
def test_parse_rejects_invalid_or_cross_artifact_identity(
    payload: dict[str, object], artifact_id: str
) -> None:
    with pytest.raises((ValidationError, ValueError)):
        parse_evidence_envelope(payload, artifact_id=artifact_id)


@pytest.mark.parametrize(
    "payload",
    [
        {**_payload(), "unexpected": True},
        {**_payload(), "coverage": {**_payload()["coverage"], "unexpected": True}},
        {
            **_payload(),
            "findings": [{**_payload()["findings"][0], "unexpected": True}],
        },
    ],
)
def test_parse_rejects_unknown_keys_at_every_level(payload: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        parse_evidence_envelope(payload, artifact_id=ARTIFACT_ID)


@pytest.mark.parametrize(
    "payload",
    [
        {**_payload(), "coverage": {**_payload()["coverage"], "status": "unknown"}},
        {
            **_payload(),
            "findings": [{**_payload()["findings"][0], "kind": "unknown"}],
        },
        {
            **_payload(),
            "findings": [{**_payload()["findings"][0], "confidence": 1.1}],
        },
    ],
)
def test_parse_rejects_invalid_enum_and_confidence_values(payload: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        parse_evidence_envelope(payload, artifact_id=ARTIFACT_ID)


@pytest.mark.parametrize(
    ("field", "limit", "container"),
    [
        ("surfaces", MAX_SURFACES, "coverage"),
        ("limitations", MAX_LIMITATIONS, "coverage"),
        ("findings", MAX_FINDINGS, "envelope"),
    ],
)
def test_parse_enforces_collection_boundaries(field: str, limit: int, container: str) -> None:
    accepted = _payload()
    values: list[object]
    if container == "coverage":
        values = ["x"] * limit
        accepted["coverage"] = {**accepted["coverage"], field: values}  # type: ignore[arg-type]
    else:
        values = [accepted["findings"][0]] * limit  # type: ignore[index]
        accepted[field] = values
    assert parse_evidence_envelope(accepted, artifact_id=ARTIFACT_ID)

    rejected = _payload()
    if container == "coverage":
        rejected["coverage"] = {**rejected["coverage"], field: ["x"] * (limit + 1)}  # type: ignore[arg-type]
    else:
        rejected[field] = [rejected["findings"][0]] * (limit + 1)  # type: ignore[index]
    with pytest.raises(ValidationError):
        parse_evidence_envelope(rejected, artifact_id=ARTIFACT_ID)


@pytest.mark.parametrize(
    ("path", "limit"),
    [
        ("surface", 128),
        ("limitation", 500),
        ("claim", MAX_CLAIM_CHARS),
        ("tool", 128),
        ("detail", MAX_DETAIL_CHARS),
    ],
)
def test_parse_enforces_string_boundaries(path: str, limit: int) -> None:
    def with_value(value: str) -> dict[str, object]:
        payload = _payload()
        if path == "surface":
            payload["coverage"] = {**payload["coverage"], "surfaces": [value]}  # type: ignore[arg-type]
        elif path == "limitation":
            payload["coverage"] = {**payload["coverage"], "limitations": [value]}  # type: ignore[arg-type]
        else:
            payload["findings"] = [{**payload["findings"][0], path: value}]  # type: ignore[index]
        return payload

    assert parse_evidence_envelope(with_value("x" * limit), artifact_id=ARTIFACT_ID)
    with pytest.raises(ValidationError):
        parse_evidence_envelope(with_value("x" * (limit + 1)), artifact_id=ARTIFACT_ID)


def test_parse_rejects_nonfinite_json_extensions() -> None:
    with pytest.raises(ValueError):
        parse_evidence_envelope('{"artifact_id": NaN}', artifact_id=ARTIFACT_ID)


def test_parse_rejects_artifact_values_that_only_contain_a_sha_substring() -> None:
    payload = _payload(artifact_id=f"{ARTIFACT_ID}0")

    with pytest.raises(ValidationError):
        parse_evidence_envelope(payload, artifact_id=ARTIFACT_ID)


def test_failed_envelope_is_bounded_artifact_bound_failed_coverage() -> None:
    envelope = failed_evidence_envelope(
        artifact_id=ARTIFACT_ID,
        stage="triage",
        code="evidence_envelope_invalid",
    )

    assert envelope.coverage.status is CoverageStatus.FAILED
    assert envelope.coverage.surfaces == ()
    assert envelope.coverage.limitations == ("triage:evidence_envelope_invalid",)
    assert envelope.findings == ()


def test_normalizer_replaces_invalid_output_without_logging_raw_value(
    caplog: pytest.LogCaptureFixture,
) -> None:
    raw_value = "do-not-log-this-model-detail"
    state = {CURRENT_ARTIFACT_KEY: ARTIFACT_ID, OUTPUT_KEY: raw_value}

    normalize_evidence_output(SimpleNamespace(state=state), output_key=OUTPUT_KEY, stage="triage")

    assert state[OUTPUT_KEY] == {
        "artifact_id": ARTIFACT_ID,
        "coverage": {
            "status": "failed",
            "surfaces": [],
            "limitations": ["triage:evidence_envelope_invalid"],
        },
        "findings": [],
        "flow": None,
        "verdict": None,
    }
    assert raw_value not in caplog.text


def test_normalizer_stores_valid_output_as_json_safe_dict() -> None:
    state = {CURRENT_ARTIFACT_KEY: ARTIFACT_ID, OUTPUT_KEY: json.dumps(_payload())}

    normalize_evidence_output(SimpleNamespace(state=state), output_key=OUTPUT_KEY, stage="triage")

    assert state[OUTPUT_KEY] == _stored(_payload())


def test_accumulate_preserves_finding_when_later_iteration_emits_empty() -> None:
    """A looped deep worker that emits a valid finding, then an empty envelope on
    a later iteration, must not lose the finding. ADK overwrites ``output_key``
    last-write-wins each loop pass; ``accumulate=True`` unions findings/surfaces
    across passes so the ghidra evidence survives a worker that "forgets" it."""
    state = {CURRENT_ARTIFACT_KEY: ARTIFACT_ID, OUTPUT_KEY: json.dumps(_payload())}
    # iteration 1: valid envelope carrying one finding, surface "imports"
    normalize_evidence_output(
        SimpleNamespace(state=state), output_key=OUTPUT_KEY, stage="deep", accumulate=True
    )
    assert len(state[OUTPUT_KEY]["findings"]) == 1

    # iteration 2: ADK overwrites output_key with an EMPTY (but valid) envelope
    empty = {
        "artifact_id": ARTIFACT_ID,
        "coverage": {
            "status": "complete",
            "surfaces": ["ghidra_search_decompiled"],
            "limitations": [],
        },
        "findings": [],
    }
    state[OUTPUT_KEY] = json.dumps(empty)
    normalize_evidence_output(
        SimpleNamespace(state=state), output_key=OUTPUT_KEY, stage="deep", accumulate=True
    )

    stored = state[OUTPUT_KEY]
    assert len(stored["findings"]) == 1  # preserved across the empty emission
    assert stored["findings"][0]["claim"] == "Imports include a suspicious API."
    assert "imports" in stored["coverage"]["surfaces"]  # both iterations' surfaces unioned
    assert "ghidra_search_decompiled" in stored["coverage"]["surfaces"]


def test_accumulate_preserves_finding_when_later_iteration_is_prose() -> None:
    """The exact native-run failure: the worker emits a valid finding, then prose
    ("Deep-decompile pass complete") on the final loop pass. The prose must not
    overwrite the finding with a failed ``evidence_envelope_invalid`` envelope."""
    state = {CURRENT_ARTIFACT_KEY: ARTIFACT_ID, OUTPUT_KEY: json.dumps(_payload())}
    normalize_evidence_output(
        SimpleNamespace(state=state), output_key=OUTPUT_KEY, stage="deep", accumulate=True
    )

    # iteration 2: ADK overwrites output_key with unparseable prose
    state[OUTPUT_KEY] = "Deep-decompile pass complete. No further surfaces required."
    normalize_evidence_output(
        SimpleNamespace(state=state), output_key=OUTPUT_KEY, stage="deep", accumulate=True
    )

    stored = state[OUTPUT_KEY]
    assert len(stored["findings"]) == 1  # prose did NOT erase the finding
    assert stored["coverage"]["status"] != "failed"
    assert "deep:evidence_envelope_invalid" not in stored["coverage"]["limitations"]


def test_accumulate_first_invalid_then_valid_does_not_poison_with_stale_limitation() -> None:
    """A first-pass prose emission (failed envelope) must not poison the
    accumulator: a later valid pass carries its finding without inheriting the
    stale ``deep:evidence_envelope_invalid`` limitation from the failed pass."""
    state = {CURRENT_ARTIFACT_KEY: ARTIFACT_ID, OUTPUT_KEY: "not an envelope at all"}
    normalize_evidence_output(
        SimpleNamespace(state=state), output_key=OUTPUT_KEY, stage="deep", accumulate=True
    )
    assert state[OUTPUT_KEY]["coverage"]["status"] == "failed"  # nothing better yet

    state[OUTPUT_KEY] = json.dumps(_payload())
    normalize_evidence_output(
        SimpleNamespace(state=state), output_key=OUTPUT_KEY, stage="deep", accumulate=True
    )

    stored = state[OUTPUT_KEY]
    assert len(stored["findings"]) == 1
    assert "deep:evidence_envelope_invalid" not in stored["coverage"]["limitations"]


def test_without_accumulate_later_empty_iteration_overwrites() -> None:
    """Default (``accumulate=False``) stays last-write-wins: the single-shot
    stage normalizers (triage, native, host, attack, behavior, ILSpy, jadx) keep
    their existing behavior; only the looped ghidra worker opts into merging."""
    state = {CURRENT_ARTIFACT_KEY: ARTIFACT_ID, OUTPUT_KEY: json.dumps(_payload())}
    normalize_evidence_output(SimpleNamespace(state=state), output_key=OUTPUT_KEY, stage="deep")
    empty = {
        "artifact_id": ARTIFACT_ID,
        "coverage": {"status": "complete", "surfaces": [], "limitations": []},
        "findings": [],
    }
    state[OUTPUT_KEY] = json.dumps(empty)
    normalize_evidence_output(SimpleNamespace(state=state), output_key=OUTPUT_KEY, stage="deep")

    assert state[OUTPUT_KEY]["findings"] == []  # last-write-wins, no accumulation


def test_normalizer_parses_fenced_json_end_to_end() -> None:
    """Regression guard for the path these tool-using agents depend on entirely
    now that output_schema is gone: on a tool-using turn the model commonly emits
    a ```json-fenced envelope rather than bare JSON, and the after-agent
    normalizer -- not schema coercion -- is what must turn that fenced text into
    a real envelope. Prove fenced text survives end-to-end through
    normalize_evidence_output, landing as a complete envelope with its finding
    intact rather than as the raw fenced string or a failed_evidence_envelope."""
    payload = {**_payload(), "coverage": {**_payload()["coverage"], "status": "complete"}}
    fenced = "```json\n" + json.dumps(payload) + "\n```"
    state = {CURRENT_ARTIFACT_KEY: ARTIFACT_ID, OUTPUT_KEY: fenced}

    normalize_evidence_output(SimpleNamespace(state=state), output_key=OUTPUT_KEY, stage="deep")

    stored = state[OUTPUT_KEY]
    assert stored == _stored(payload)
    assert stored != fenced
    assert stored["coverage"]["status"] == "complete"
    assert stored["findings"] == payload["findings"]
    assert stored != failed_evidence_envelope(
        artifact_id=ARTIFACT_ID, stage="deep", code="evidence_envelope_invalid"
    ).model_dump(mode="json")


def test_normalizer_returns_none_after_state_update() -> None:
    state = {CURRENT_ARTIFACT_KEY: ARTIFACT_ID, OUTPUT_KEY: json.dumps(_payload())}

    result = normalize_evidence_output(
        SimpleNamespace(state=state),
        output_key=OUTPUT_KEY,
        stage="triage",
    )

    assert result is None


def test_normalizer_replaces_hostile_mapping_without_logging_raw_value(
    caplog: pytest.LogCaptureFixture,
) -> None:
    raw_value = "do-not-log-this-hostile-mapping-detail"

    class _HostileMapping(Mapping[str, object]):
        def __getitem__(self, _key: str) -> object:
            raise RuntimeError(raw_value)

        def __iter__(self) -> Iterator[str]:
            raise RuntimeError(raw_value)

        def __len__(self) -> int:
            return 1

    state = {CURRENT_ARTIFACT_KEY: ARTIFACT_ID, OUTPUT_KEY: _HostileMapping()}

    normalize_evidence_output(SimpleNamespace(state=state), output_key=OUTPUT_KEY, stage="triage")

    assert state[OUTPUT_KEY] == failed_evidence_envelope(
        artifact_id=ARTIFACT_ID,
        stage="triage",
        code="evidence_envelope_invalid",
    ).model_dump(mode="json")
    assert raw_value not in caplog.text


def test_normalizer_replaces_malformed_model_instance() -> None:
    malformed = EvidenceEnvelope.model_construct(
        artifact_id=ARTIFACT_ID,
        coverage=object(),
        findings=(),
    )
    state = {CURRENT_ARTIFACT_KEY: ARTIFACT_ID, OUTPUT_KEY: malformed}

    normalize_evidence_output(SimpleNamespace(state=state), output_key=OUTPUT_KEY, stage="triage")

    assert state[OUTPUT_KEY] == failed_evidence_envelope(
        artifact_id=ARTIFACT_ID,
        stage="triage",
        code="evidence_envelope_invalid",
    ).model_dump(mode="json")


@pytest.mark.parametrize("interrupt", [KeyboardInterrupt, SystemExit])
def test_normalizer_propagates_process_control_exceptions_from_model_output(
    interrupt: type[BaseException],
) -> None:
    class _InterruptingMapping(Mapping[str, object]):
        def __getitem__(self, _key: str) -> object:
            raise interrupt

        def __iter__(self) -> Iterator[str]:
            raise interrupt

        def __len__(self) -> int:
            return 1

    state = {CURRENT_ARTIFACT_KEY: ARTIFACT_ID, OUTPUT_KEY: _InterruptingMapping()}

    with pytest.raises(interrupt):
        normalize_evidence_output(
            SimpleNamespace(state=state), output_key=OUTPUT_KEY, stage="triage"
        )


def test_normalizer_fails_closed_when_artifact_authority_is_invalid(
    caplog: pytest.LogCaptureFixture,
) -> None:
    raw_value = "do-not-log-this-model-detail"
    state = {CURRENT_ARTIFACT_KEY: "not-a-sha", OUTPUT_KEY: raw_value}

    normalize_evidence_output(SimpleNamespace(state=state), output_key=OUTPUT_KEY, stage="triage")

    assert state[OUTPUT_KEY] == raw_value
    assert raw_value not in caplog.text


def test_normalizer_fails_closed_when_state_access_raises(caplog: pytest.LogCaptureFixture) -> None:
    raw_value = "do-not-log-this-model-detail"

    class _UnreadableState:
        def get(self, _key: str) -> object:
            raise RuntimeError(raw_value)

        def __setitem__(self, _key: str, _value: object) -> None:
            raise AssertionError("state must not be written without artifact authority")

    normalize_evidence_output(
        SimpleNamespace(state=_UnreadableState()),
        output_key=OUTPUT_KEY,
        stage="triage",
    )

    assert raw_value not in caplog.text


def test_rejected_fields_names_the_path_and_kind_never_the_value(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A schema rejection must say WHICH field and WHY, without echoing the value.

    Live runs lost triage and deep evidence to a bare
    ``error_type=ValidationError``, which cannot distinguish an invented enum
    member from a missing field. The path and failure kind are facts about our own
    schema and are safe; the offending value is model-controlled and is not.
    """
    secret = "do-not-log-this-model-detail"
    state = {
        CURRENT_ARTIFACT_KEY: ARTIFACT_ID,
        OUTPUT_KEY: {
            "artifact_id": ARTIFACT_ID,
            "coverage": {"status": "complete", "surfaces": [], "limitations": []},
            "findings": [
                {
                    "artifact_id": ARTIFACT_ID,
                    "claim": "c",
                    "tool": "t",
                    "confidence": 0.5,
                    "detail": "d",
                    "kind": secret,
                }
            ],
        },
    }

    normalize_evidence_output(SimpleNamespace(state=state), output_key=OUTPUT_KEY, stage="triage")

    out = capsys.readouterr().out
    assert secret not in out, "the model-controlled value must never be logged"
    assert "findings.0.kind" in out, "the rejected field path must be logged"
    assert "enum" in out, "the kind of failure must be logged"


# --- multi-value model turns --------------------------------------------------
#
# A model turn does not always carry exactly one JSON value. json_repair recovers
# every value it finds and returns a list, which validated against an object model
# fails at the ROOT -- so an entire stage's findings were discarded while a good
# envelope sat in the list. Observed live as payload_type=list with
# rejected_fields=[':model_type'].


def _envelope_json(*, findings: int = 1) -> str:
    finding = (
        f'{{"artifact_id": "{ARTIFACT_ID}", "claim": "c", "tool": "t", '
        '"confidence": 0.5, "detail": "d", "kind": "behavior"}'
    )
    body = ", ".join([finding] * findings)
    return (
        f'{{"artifact_id": "{ARTIFACT_ID}", '
        '"coverage": {"status": "complete", "surfaces": ["s"], "limitations": []}, '
        f'"findings": [{body}]}}'
    )


def test_envelope_is_recovered_when_the_turn_carries_a_trailing_object() -> None:
    raw = _envelope_json() + '\n{"note": "a second value the model tacked on"}'

    envelope = parse_evidence_envelope(raw, artifact_id=ARTIFACT_ID)

    assert envelope.coverage.status.value == "complete"
    assert len(envelope.findings) == 1


def test_envelope_is_recovered_when_preceded_by_another_object() -> None:
    """Selection is by shape, not position: the envelope need not come first."""
    raw = '{"note": "preamble object"}\n' + _envelope_json()

    assert len(parse_evidence_envelope(raw, artifact_id=ARTIFACT_ID).findings) == 1


def test_two_envelopes_are_refused_rather_than_guessed_between() -> None:
    """Picking the wrong one is silently wrong evidence; failing is honest."""
    raw = _envelope_json(findings=1) + "\n" + _envelope_json(findings=2)

    with pytest.raises((ValueError, ValidationError)):
        parse_evidence_envelope(raw, artifact_id=ARTIFACT_ID)


def test_a_bare_list_with_no_envelope_still_fails() -> None:
    with pytest.raises((ValueError, ValidationError)):
        parse_evidence_envelope('[{"note": "x"}, {"note": "y"}]', artifact_id=ARTIFACT_ID)


# --- third-party intelligence is a kind, not a wording convention -------------


def _intel_payload() -> dict[str, object]:
    payload = _payload()
    findings = payload["findings"]
    assert isinstance(findings, list)
    payload["findings"] = [{**findings[0], "kind": "intel", "tool": "hashlookup"}]
    return payload


def test_intel_is_a_valid_kind_and_survives_strict_parsing() -> None:
    """An intel finding records what somebody else already had on file about the
    digest. Every other kind describes the sample's own bytes."""
    envelope = parse_evidence_envelope(json.dumps(_intel_payload()), artifact_id=ARTIFACT_ID)

    assert envelope.findings[0].kind is FindingKind.INTEL


def test_intel_round_trips_through_a_json_dump() -> None:
    envelope = parse_evidence_envelope(json.dumps(_intel_payload()), artifact_id=ARTIFACT_ID)

    reparsed = parse_evidence_envelope(envelope.model_dump(mode="json"), artifact_id=ARTIFACT_ID)

    assert reparsed.findings[0].kind is FindingKind.INTEL


def test_adding_intel_did_not_widen_the_kind_enum_by_accident() -> None:
    """The taxonomy is closed on purpose: an unrecognized kind invalidates a
    whole envelope, so a typo must stay a typo rather than becoming a category."""
    assert {kind.value for kind in FindingKind} == {
        "metadata",
        "host_ioc",
        "network_ioc",
        "behavior",
        "attack",
        "limitation",
        "intel",
    }
