"""Deterministic escalation rule for the bounded deobfuscation loop."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import partial
from typing import TYPE_CHECKING, Literal, TypedDict, cast

from arema.registry.descriptors import AgentDescriptor, AgentKind
from arema.runtime.agent_factory import EscalationDecision, build_escalation_gate
from reverse_engineering.evidence_envelope import (
    MAX_FINDINGS,
    MAX_LIMITATIONS,
    CoverageStatus,
    EvidenceCoverage,
    EvidenceEnvelope,
    EvidenceFinding,
    FindingKind,
    parse_evidence_envelope,
    rebind_evidence_envelope,
)
from reverse_engineering.model_json import loads_model_json
from reverse_engineering.tools.deobfuscation.dotnet import (
    _valid_cached_result as _valid_de4dot_result,
)
from reverse_engineering.tools.deobfuscation.floss import (
    _valid_cached_result as _valid_floss_result,
)
from reverse_engineering.tools.deobfuscation.state import (
    DE4DOT_CALLED_KEY,
    DE4DOT_RESULT_KEY,
    DEEP_DECOMPILE_TARGETS_PROMPT_KEY,
    DEOBF_BASELINE_PROMPT_KEY,
    DEOBF_ITERATION_KEY,
    DEOBF_MAX_ITERATIONS,
    DNLIB_ROUNDTRIP_CALLED_KEY,
    DNLIB_ROUNDTRIP_RESULT_KEY,
    FLOSS_CALLED_KEY,
    FLOSS_COUNT_KEY,
    FLOSS_DEGRADED_KEY,
    FLOSS_RESULT_KEY,
    PCODE_PREFERRED_PROMPT_KEY,
    PREVIOUS_SNAPSHOT_KEY,
    RECOVERY_EVIDENCE_KEY,
    RECOVERY_SUMMARY_KEY,
    RETRIAGE_SNAPSHOT_KEY,
    SCRIPTED_ATTEMPTED_KEY,
    SCRIPTED_RESULT_KEY,
    UPX_CALLED_KEY,
    UPX_CHANGED_KEY,
    UPX_DEGRADED_KEY,
    UPX_RESULT_KEY,
    parse_current_classification,
)
from reverse_engineering.tools.deobfuscation.upx import _valid_cached_result as _valid_upx_result

if TYPE_CHECKING:
    from collections.abc import Mapping

SNAPSHOT_FIELDS = (
    "size",
    "function_count",
    "import_count",
    "string_count",
    "section_count",
)
_GATE_ERROR_KEY = "deobf:gate_error"
_INVALID_STATE_ERROR = "invalid_state"
_RECOVERY_NOT_CALLED_ERROR = "recovery_not_called"
_ARTIFACT_ID_PATTERN = re.compile(r"[0-9a-f]{64}")
_HEX_ADDRESS_PATTERN = re.compile(r"0x[0-9a-fA-F]+")
_MAX_DECOMPILE_TARGETS = 8
_TOOL_STATUS = Literal["success", "non_applicable", "degraded"]

__all__ = ["DEOBF_GATE_DESCRIPTOR", "SNAPSHOT_FIELDS", "evaluate_deobf_gate"]


@dataclass(frozen=True, slots=True)
class _ToolOutcome:
    status: _TOOL_STATUS
    error_code: str
    changed: bool = False
    new_count: int = 0
    records: tuple[dict[str, object], ...] = ()


class _UpxSummary(TypedDict):
    status: str
    changed: bool
    error_code: str


class _FlossSummary(TypedDict):
    status: str
    new_count: int
    error_code: str


class RecoverySummary(TypedDict):
    """Terminal, JSON-serializable summary of one deobfuscation loop's outcome."""

    artifact_id: str
    exit_reason: str
    upx: _UpxSummary
    floss: _FlossSummary
    limitations: list[str]


def evaluate_deobf_gate(state: Mapping[str, object]) -> EscalationDecision:
    """Decide whether the deobfuscation loop should exit, failing closed on bad state."""
    try:
        plan = parse_current_classification(state)
    except ValueError:
        return _fail_closed("", _INVALID_STATE_ERROR)

    pcode_alias = "true" if plan.pcode_preferred else "false"
    try:
        iteration = _iteration(state)
        if not _recovery_called(state):
            raise _RecoveryNotCalled
        raw_previous = state.get(PREVIOUS_SNAPSHOT_KEY)
        previous = None if raw_previous is None else _parse_snapshot(raw_previous)
        upx_changed = _state_bool(state, UPX_CHANGED_KEY)
        upx_degraded = _state_bool(state, UPX_DEGRADED_KEY)
        floss_degraded = _state_bool(state, FLOSS_DEGRADED_KEY)
        floss_count = _floss_count(state)
        previous_summary = _parse_summary(state.get(RECOVERY_SUMMARY_KEY), plan.artifact_id)
        previous_evidence = _parse_previous_evidence(
            state.get(RECOVERY_EVIDENCE_KEY), plan.artifact_id
        )
    except _RecoveryNotCalled:
        return _fail_closed(pcode_alias, _RECOVERY_NOT_CALLED_ERROR)
    except ValueError:
        return _fail_closed(pcode_alias, _INVALID_STATE_ERROR)

    # The retriage snapshot is model-authored (the retriage agent has no
    # output_schema); a bad snapshot only loses the loop's progress signal and must
    # never fail closed and discard the deterministic FLOSS/UPX recovery evidence.
    try:
        current: dict[str, int] | None = _parse_current_snapshot(
            state.get(RETRIAGE_SNAPSHOT_KEY), plan.artifact_id
        )
        snapshot_invalid = False
    except ValueError:
        current = None
        snapshot_invalid = True

    iteration += 1
    upx = _upx_outcome(state.get(UPX_RESULT_KEY), plan.upx, upx_changed, upx_degraded)
    # FLOSS eligibility is deterministic (PE-only), decided by the tool, not the
    # classifier's `floss` flag: build its evidence whenever the recorded result
    # is applicable, so a flaky floss=false plan can never discard recovered
    # strings.
    floss_result = state.get(FLOSS_RESULT_KEY)
    floss_applicable = isinstance(floss_result, dict) and floss_result.get("applicable") is True
    floss = _floss_outcome(
        floss_result, plan.floss or floss_applicable, floss_degraded, plan.artifact_id
    )
    scripted = _scripted_outcome(state.get(SCRIPTED_RESULT_KEY), plan.artifact_id)
    de4dot = _de4dot_outcome(state.get(DE4DOT_RESULT_KEY), plan.artifact_id)
    evidence = _build_evidence(
        plan.artifact_id, previous_evidence, previous_summary, upx, floss, scripted, de4dot
    )

    baseline = previous if previous is not None else plan.pre_snapshot
    if snapshot_invalid:
        evidence = _add_limitation(evidence, "deobfuscation:retriage_snapshot_invalid")
    # Without a snapshot the loop cannot measure growth; treat it as no growth.
    grew = current is not None and any(
        current[key] > baseline.get(key, 0) for key in SNAPSHOT_FIELDS
    )
    # A "clean" plan disabled the cheap tools *because the sample needs none* — not
    # because a still-packed class (packed-other/cff/vm/...) simply has no cheap
    # tool. Treat only obf_class in {none, unknown} as genuinely clean.
    clean_plan = not plan.upx and not plan.floss and plan.obf_class in {"none", "unknown"}
    enabled_degraded = (
        (not plan.upx or upx_degraded)
        and (not plan.floss or floss_degraded)
        and (plan.upx or plan.floss)
    )
    no_progress = not upx_changed and floss_count == 0 and not grew
    exit_loop = (
        clean_plan
        or plan.pcode_preferred
        or enabled_degraded
        or snapshot_invalid
        or no_progress
        or iteration >= DEOBF_MAX_ITERATIONS
    )
    # A missing snapshot cannot be persisted as the next iteration's baseline;
    # fall back to the current baseline so the delta stays well-formed.
    delta = _iteration_delta(
        current if current is not None else baseline, pcode_alias, iteration, evidence
    )
    # Give the deep worker concrete FLOSS-derived decompile targets so targeted
    # coverage does not hinge on the model re-deriving them from a long context.
    delta[DEEP_DECOMPILE_TARGETS_PROMPT_KEY] = _floss_decompile_targets(floss)
    if not exit_loop:
        return EscalationDecision(escalate=False, state_delta=delta)

    if clean_plan:
        reason = "complete"
    elif plan.pcode_preferred:
        reason = "pcode_handoff"
    elif enabled_degraded:
        reason = "degraded"
    elif snapshot_invalid:
        reason = "retriage_snapshot_invalid"
    elif no_progress:
        reason = "no_progress"
    else:
        reason = "iteration_cap"
        evidence = _add_limitation(evidence, "deobfuscation:iteration_cap")
        delta[RECOVERY_EVIDENCE_KEY] = evidence.model_dump(mode="json")
    scripted_attempted = _state_bool(state, SCRIPTED_ATTEMPTED_KEY)
    if scripted_attempted and scripted.status != "success" and reason == "no_progress":
        evidence = _add_limitation(evidence, "recovery:scripted_unavailable")
        delta[RECOVERY_EVIDENCE_KEY] = evidence.model_dump(mode="json")
    limitations = _summary_limitations(previous_summary, evidence)
    if reason == "iteration_cap":
        limitations = _stable_append(limitations, "deobfuscation:iteration_cap", MAX_LIMITATIONS)
    delta[RECOVERY_SUMMARY_KEY] = _summary(plan.artifact_id, reason, upx, floss, limitations)
    return EscalationDecision(escalate=True, state_delta=delta)


class _RecoveryNotCalled(ValueError):
    pass


def _fail_closed(pcode_alias: str, code: str) -> EscalationDecision:
    """Fail closed on malformed state without leaking it into durable evidence.

    Terminal recovery keys are never touched here, so any trustworthy evidence
    from a prior iteration survives unchanged while untrusted state is discarded.
    """
    return EscalationDecision(
        escalate=True,
        state_delta={_GATE_ERROR_KEY: code, PCODE_PREFERRED_PROMPT_KEY: pcode_alias},
    )


def _iteration_delta(
    current: dict[str, int], pcode_alias: str, iteration: int, evidence: EvidenceEnvelope
) -> dict[str, object]:
    return {
        PREVIOUS_SNAPSHOT_KEY: current,
        DEOBF_BASELINE_PROMPT_KEY: json.dumps(current, separators=(",", ":")),
        PCODE_PREFERRED_PROMPT_KEY: pcode_alias,
        DEOBF_ITERATION_KEY: iteration,
        RECOVERY_EVIDENCE_KEY: evidence.model_dump(mode="json"),
        UPX_CALLED_KEY: False,
        FLOSS_CALLED_KEY: False,
        UPX_RESULT_KEY: None,
        FLOSS_RESULT_KEY: None,
        UPX_CHANGED_KEY: False,
        UPX_DEGRADED_KEY: False,
        FLOSS_COUNT_KEY: 0,
        FLOSS_DEGRADED_KEY: False,
        SCRIPTED_RESULT_KEY: None,
        SCRIPTED_ATTEMPTED_KEY: False,
        DE4DOT_RESULT_KEY: None,
        DE4DOT_CALLED_KEY: False,
        DNLIB_ROUNDTRIP_RESULT_KEY: None,
        DNLIB_ROUNDTRIP_CALLED_KEY: False,
    }


def _iteration(state: Mapping[str, object]) -> int:
    value = state.get(DEOBF_ITERATION_KEY, 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("iteration must be a nonnegative integer")
    return value


def _upx_outcome(
    raw: object, enabled: bool, changed_state: bool, degraded_state: bool
) -> _ToolOutcome:
    if not enabled:
        return _ToolOutcome("non_applicable", "")
    if not isinstance(raw, dict) or not _valid_upx_result(raw):
        return _ToolOutcome("degraded", "result_invalid")
    if degraded_state != raw["degraded"] or changed_state != raw["changed"]:
        return _ToolOutcome("degraded", "result_invalid")
    if raw["success"] is True and raw["applicable"] is False:
        return _ToolOutcome("non_applicable", "")
    if raw["success"] is True and raw["applicable"] is True and raw["degraded"] is False:
        return _ToolOutcome("success", "", changed=raw["changed"])
    error_code = raw.get("error_code")
    return _ToolOutcome("degraded", error_code if isinstance(error_code, str) else "result_invalid")


def _floss_outcome(
    raw: object, enabled: bool, degraded_state: bool, artifact_id: str
) -> _ToolOutcome:
    if not enabled:
        return _ToolOutcome("non_applicable", "")
    if not isinstance(raw, dict) or not _valid_floss_result(raw):
        return _ToolOutcome("degraded", "result_invalid")
    if degraded_state != raw["degraded"]:
        return _ToolOutcome("degraded", "result_invalid")
    if raw["success"] is True and raw["applicable"] is False:
        return _ToolOutcome("non_applicable", "")
    if raw["success"] is True and raw["applicable"] is True and raw["degraded"] is False:
        if raw.get("source_artifact_id") != artifact_id:
            return _ToolOutcome("degraded", "result_invalid")
        records = tuple(record for record in raw["records"] if isinstance(record, dict))
        return _ToolOutcome("success", "", new_count=raw["new_count"], records=records)
    error_code = raw.get("error_code")
    return _ToolOutcome("degraded", error_code if isinstance(error_code, str) else "result_invalid")


def _scripted_outcome(raw: object, artifact_id: str) -> _ToolOutcome:
    """Build the scripted-recovery evidence outcome from ``SCRIPTED_RESULT_KEY``.

    Success requires a result whose recovered ``artifact_id`` matches the current
    plan artifact (``register`` advanced the classification before the gate runs);
    anything else yields no finding. The ``method`` label is already bounded by
    ``register`` (≤200 chars).
    """
    if not isinstance(raw, dict) or raw.get("artifact_id") != artifact_id:
        return _ToolOutcome("non_applicable", "")
    record = {
        "method": str(raw.get("method", "")),
        "format": str(raw.get("format", "")),
        "entropy_before": raw.get("entropy_before"),
        "entropy_after": raw.get("entropy_after"),
    }
    return _ToolOutcome("success", "", records=(record,))


def _de4dot_outcome(raw: object, artifact_id: str) -> _ToolOutcome:
    """Build the de4dot evidence outcome from ``DE4DOT_RESULT_KEY`` (a mechanism
    finding). Success only when de4dot deobfuscated the artifact into the current
    one (``changed`` + recovered id matches the advanced plan artifact)."""
    if not isinstance(raw, dict) or not _valid_de4dot_result(raw):
        return _ToolOutcome("non_applicable", "")
    if (
        raw["success"] is True
        and raw["applicable"] is True
        and raw["degraded"] is False
        and raw["changed"] is True
    ):
        if raw.get("recovered_artifact_id") != artifact_id:
            return _ToolOutcome("non_applicable", "")
        record: dict[str, object] = {"obfuscator": str(raw.get("obfuscator_name", "unknown"))}
        return _ToolOutcome("success", "", records=(record,))
    if raw["degraded"] is True:
        code = raw.get("error_code")
        return _ToolOutcome("degraded", code if isinstance(code, str) else "result_invalid")
    return _ToolOutcome("non_applicable", "")


def _floss_decompile_targets(floss: _ToolOutcome) -> str:
    """FLOSS-cited function addresses, deduped and ranked by decoded-string
    density, as a bounded comma-separated list of decompile targets."""
    if floss.status != "success":
        return ""
    counts: dict[str, int] = {}
    for record in floss.records:
        address = record.get("function")
        if (
            isinstance(address, str)
            and _HEX_ADDRESS_PATTERN.fullmatch(address)
            and int(address, 16) != 0
        ):
            counts[address] = counts.get(address, 0) + 1
    ranked = sorted(counts, key=lambda address: (-counts[address], int(address, 16)))
    return ",".join(ranked[:_MAX_DECOMPILE_TARGETS])


def _build_evidence(
    artifact_id: str,
    previous: EvidenceEnvelope | None,
    summary: RecoverySummary | None,
    upx: _ToolOutcome,
    floss: _ToolOutcome,
    scripted: _ToolOutcome,
    de4dot: _ToolOutcome,
) -> EvidenceEnvelope:
    prior_findings = () if previous is None else previous.findings
    prior_surfaces = () if previous is None else previous.coverage.surfaces
    limitations: list[str] = []
    if summary is not None:
        for limitation in summary["limitations"]:
            limitations = _stable_append(limitations, limitation, MAX_LIMITATIONS)
    if previous is not None:
        for limitation in previous.coverage.limitations:
            limitations = _stable_append(limitations, limitation, MAX_LIMITATIONS)
    for prefix, outcome in (("upx", upx), ("floss", floss), ("de4dot", de4dot)):
        if outcome.status == "degraded":
            limitations = _stable_append(
                limitations, f"{prefix}:{outcome.error_code}", MAX_LIMITATIONS
            )
    surfaces = list(prior_surfaces)
    if floss.status == "success":
        surfaces = _stable_append(surfaces, "floss_decode", 64)
    findings = list(prior_findings)
    identities = {(finding.tool, finding.detail) for finding in findings}
    if floss.status == "success":
        for record in floss.records:
            detail = json.dumps(record, sort_keys=True, separators=(",", ":"))
            identity = ("floss_decode", detail)
            if identity in identities or len(findings) >= MAX_FINDINGS:
                continue
            identities.add(identity)
            findings.append(
                EvidenceFinding(
                    artifact_id=artifact_id,
                    claim=f"FLOSS recovered a {record['type']} string.",
                    tool="floss_decode",
                    confidence=1.0,
                    detail=detail,
                    kind=FindingKind.METADATA,
                )
            )
    if scripted.status == "success":
        surfaces = _stable_append(surfaces, "scripted_recover", 64)
        for record in scripted.records:
            detail = json.dumps(record, sort_keys=True, separators=(",", ":"))
            identity = ("scripted_recover", detail)
            if identity in identities or len(findings) >= MAX_FINDINGS:
                continue
            identities.add(identity)
            findings.append(
                EvidenceFinding(
                    artifact_id=artifact_id,
                    claim=f"Recovered the packed payload via {record['format']} static unpacking.",
                    tool="scripted_recover",
                    confidence=1.0,
                    detail=detail,
                    kind=FindingKind.METADATA,
                )
            )
    if de4dot.status == "success":
        surfaces = _stable_append(surfaces, "de4dot", 64)
        for record in de4dot.records:
            detail = json.dumps(record, sort_keys=True, separators=(",", ":"))
            identity = ("de4dot", detail)
            if identity in identities or len(findings) >= MAX_FINDINGS:
                continue
            identities.add(identity)
            findings.append(
                EvidenceFinding(
                    artifact_id=artifact_id,
                    claim=f"de4dot deobfuscated a {record['obfuscator']}-protected .NET assembly.",
                    tool="de4dot",
                    confidence=1.0,
                    detail=detail,
                    kind=FindingKind.METADATA,
                )
            )
    usable = bool(findings or surfaces)
    status = (
        CoverageStatus.PARTIAL
        if limitations and usable
        else CoverageStatus.FAILED
        if limitations
        else CoverageStatus.COMPLETE
    )
    return EvidenceEnvelope(
        artifact_id=artifact_id,
        coverage=EvidenceCoverage(
            status=status, surfaces=tuple(surfaces), limitations=tuple(limitations)
        ),
        findings=tuple(findings),
    )


def _add_limitation(envelope: EvidenceEnvelope, limitation: str) -> EvidenceEnvelope:
    limitations = _stable_append(list(envelope.coverage.limitations), limitation, MAX_LIMITATIONS)
    status = (
        CoverageStatus.PARTIAL
        if envelope.findings or envelope.coverage.surfaces
        else CoverageStatus.FAILED
    )
    return EvidenceEnvelope(
        artifact_id=envelope.artifact_id,
        coverage=EvidenceCoverage(
            status=status,
            surfaces=envelope.coverage.surfaces,
            limitations=tuple(limitations),
        ),
        findings=envelope.findings,
    )


def _summary(
    artifact_id: str,
    reason: str,
    upx: _ToolOutcome,
    floss: _ToolOutcome,
    limitations: list[str],
) -> RecoverySummary:
    return {
        "artifact_id": artifact_id,
        "exit_reason": reason,
        "upx": {"status": upx.status, "changed": upx.changed, "error_code": upx.error_code},
        "floss": {
            "status": floss.status,
            "new_count": floss.new_count,
            "error_code": floss.error_code,
        },
        "limitations": limitations,
    }


def _summary_limitations(summary: RecoverySummary | None, evidence: EvidenceEnvelope) -> list[str]:
    limitations: list[str] = []
    if summary is not None:
        for limitation in summary["limitations"]:
            limitations = _stable_append(limitations, limitation, MAX_LIMITATIONS)
    for limitation in evidence.coverage.limitations:
        limitations = _stable_append(limitations, limitation, MAX_LIMITATIONS)
    return limitations


def _stable_append(items: list[str], value: str, maximum: int) -> list[str]:
    if value not in items and len(items) < maximum:
        items.append(value)
    return items


def _parse_previous_evidence(raw: object, artifact_id: str) -> EvidenceEnvelope | None:
    """Read the loop's own cumulative evidence, re-anchoring it to the CURRENT
    artifact when a recovering round advanced ``CURRENT_ARTIFACT_KEY`` since it was
    written. ``RECOVERY_EVIDENCE_KEY`` is gate-authored (never model input), so
    re-anchoring it is safe and is what lets multi-layer recovery accumulate
    evidence across rounds instead of fail-closing on the id mismatch.
    """
    if raw is None:
        return None
    # Validate the persisted envelope against its OWN embedded authority (integrity),
    # then re-anchor it to the current artifact.
    envelope = parse_evidence_envelope(raw, artifact_id=_evidence_artifact_id(raw))
    return rebind_evidence_envelope(envelope, artifact_id=artifact_id)


def _evidence_artifact_id(raw: object) -> str:
    """The artifact id a persisted evidence envelope is bound to -- read so it can be
    parsed against its own authority before being re-anchored to the current one.

    ``raw`` is decoded through the same ``loads_model_json`` boundary that
    ``parse_evidence_envelope`` uses on this same value immediately afterward
    (see ``_parse_previous_evidence``): a single canonical decode boundary for
    one payload, tolerant of a code-fenced or minor-malformed re-serialization
    rather than only the strict subset a bare ``json.loads`` accepts.
    """
    data = loads_model_json(raw)
    if isinstance(data, dict):
        candidate = data.get("artifact_id")
        if isinstance(candidate, str):
            return candidate
    raise ValueError("evidence envelope missing artifact_id")


def _parse_summary(raw: object, artifact_id: str) -> RecoverySummary | None:
    if raw is None:
        return None
    raw = loads_model_json(raw)
    if not isinstance(raw, dict) or set(raw) != {
        "artifact_id",
        "exit_reason",
        "upx",
        "floss",
        "limitations",
    }:
        raise ValueError("invalid recovery summary")
    if raw["artifact_id"] != artifact_id or raw["exit_reason"] not in {
        "complete",
        "no_progress",
        "degraded",
        "pcode_handoff",
        "iteration_cap",
    }:
        raise ValueError("invalid recovery summary")
    upx = raw["upx"]
    floss = raw["floss"]
    limitations = raw["limitations"]
    if (
        not isinstance(upx, dict)
        or set(upx) != {"status", "changed", "error_code"}
        or upx.get("status") not in {"success", "non_applicable", "degraded"}
        or not isinstance(upx.get("changed"), bool)
        or not isinstance(upx.get("error_code"), str)
        or not isinstance(floss, dict)
        or set(floss) != {"status", "new_count", "error_code"}
        or floss.get("status") not in {"success", "non_applicable", "degraded"}
        or isinstance(floss.get("new_count"), bool)
        or not isinstance(floss.get("new_count"), int)
        or floss["new_count"] < 0
        or not isinstance(floss.get("error_code"), str)
        or not isinstance(limitations, list)
        or len(limitations) > MAX_LIMITATIONS
        or any(not isinstance(item, str) for item in limitations)
    ):
        raise ValueError("invalid recovery summary")
    return cast("RecoverySummary", raw)


def _recovery_called(state: Mapping[str, object]) -> bool:
    """Require both fixed sequential recovery children to run once this iteration."""
    for key in (UPX_CALLED_KEY, FLOSS_CALLED_KEY):
        if key not in state or state[key] is False:
            return False
        if state[key] is not True:
            raise ValueError("recovery call markers must be booleans")
    return True


def _parse_snapshot(raw: object) -> dict[str, int]:
    """Normalize a strict retriage snapshot from a mapping or JSON object string."""
    if isinstance(raw, str):
        try:
            raw = loads_model_json(raw)
        except ValueError as exc:
            raise ValueError("invalid snapshot JSON") from exc
    if not isinstance(raw, dict):
        raise ValueError("snapshot must be an object")
    snapshot: dict[str, int] = {}
    for field in SNAPSHOT_FIELDS:
        value = raw.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("snapshot metrics must be nonnegative integers")
        snapshot[field] = value
    return snapshot


def _parse_current_snapshot(raw: object, artifact_id: str) -> dict[str, int]:
    """Bind model-authored retriage metrics to the strict canonical plan."""
    if isinstance(raw, str):
        try:
            decoded = loads_model_json(raw)
        except ValueError as exc:
            raise ValueError("invalid snapshot JSON") from exc
    else:
        decoded = raw
    if not isinstance(decoded, dict):
        raise ValueError("snapshot must be an object")
    snapshot_artifact_id = decoded.get("artifact_id")
    if (
        not isinstance(snapshot_artifact_id, str)
        or _ARTIFACT_ID_PATTERN.fullmatch(snapshot_artifact_id) is None
        or snapshot_artifact_id != artifact_id
    ):
        raise ValueError("snapshot artifact_id must equal the canonical plan")
    return _parse_snapshot(decoded)


def _state_bool(state: Mapping[str, object], key: str) -> bool:
    value = state.get(key, False)
    if not isinstance(value, bool):
        raise ValueError("recovery facts must be booleans")
    return value


def _floss_count(state: Mapping[str, object]) -> int:
    value = state.get(FLOSS_COUNT_KEY, 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("FLOSS count must be a nonnegative integer")
    return value


DEOBF_GATE_DESCRIPTOR = AgentDescriptor(
    id="deobf_gate",
    name="deobf_gate",
    description="Deterministically exits the deobfuscation loop when recovery cannot progress.",
    prompt_id=None,
    factory=partial(build_escalation_gate, evaluator=evaluate_deobf_gate),
    kind=AgentKind.DETERMINISTIC,
)
