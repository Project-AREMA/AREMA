"""Deterministic completion gate for the bounded deep-analysis loop.

Deep analysis is complete only when the loaded binary was prepared, a semantic
decompiled-search surface succeeded, and a targeted decompile/p-code surface
succeeded. Metadata alone can never terminate the loop. On the third pass the
gate exits regardless, preserving any valid findings and recording a durable
``deep:analysis_incomplete`` limitation so downstream stages cannot mistake an
incomplete pass for an exhaustive one.
"""

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

from arema.registry.descriptors import AgentDescriptor, AgentKind
from arema.runtime.agent_factory import EscalationDecision, build_escalation_gate
from reverse_engineering.evidence_envelope import (
    CoverageStatus,
    EvidenceCoverage,
    failed_evidence_envelope,
    parse_evidence_envelope,
)
from reverse_engineering.tools.deobfuscation.state import CURRENT_ARTIFACT_KEY
from reverse_engineering.tools.ghidra.coverage import (
    DEEP_EVIDENCE_KEY,
    DEEP_ITERATION_KEY,
    DEEP_MISSING_PROMPT_KEY,
    read_deep_coverage,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

MAX_DEEP_ITERATIONS = 3
_GATE_ERROR_KEY = "deep:gate_error"

__all__ = [
    "DEEP_ANALYSIS_GATE_DESCRIPTOR",
    "MAX_DEEP_ITERATIONS",
    "evaluate_deep_analysis_gate",
]


def evaluate_deep_analysis_gate(state: Mapping[str, object]) -> EscalationDecision:
    """Decide whether the deep-analysis loop is complete, failing closed on bad state."""
    artifact_id = state.get(CURRENT_ARTIFACT_KEY)
    if not isinstance(artifact_id, str):
        return EscalationDecision(
            escalate=True,
            state_delta={
                DEEP_MISSING_PROMPT_KEY: "",
                _GATE_ERROR_KEY: "canonical_artifact_invalid",
            },
        )

    raw_iteration = state.get(DEEP_ITERATION_KEY, 0)
    iteration = (
        raw_iteration + 1
        if isinstance(raw_iteration, int) and not isinstance(raw_iteration, bool)
        else MAX_DEEP_ITERATIONS
    )
    coverage = None
    try:
        coverage = read_deep_coverage(state, artifact_id)
        missing: list[str] = []
        if not coverage.prepared:
            missing.append("prepared")
        if not coverage.semantic_search_succeeded:
            missing.append("semantic_search")
        if not coverage.target_analysis_succeeded:
            missing.append("target_decompile_or_pcode")
    except (TypeError, ValueError):
        coverage = None
        missing = ["prepared", "semantic_search", "target_decompile_or_pcode"]

    complete = not missing
    exhausted = iteration >= MAX_DEEP_ITERATIONS
    state_delta: dict[str, object] = {
        DEEP_ITERATION_KEY: iteration,
        DEEP_MISSING_PROMPT_KEY: ",".join(missing),
    }
    if complete or exhausted:
        try:
            envelope = parse_evidence_envelope(
                state.get(DEEP_EVIDENCE_KEY), artifact_id=artifact_id
            )
        except (TypeError, ValueError):
            envelope = failed_evidence_envelope(
                artifact_id=artifact_id, stage="deep", code="evidence_envelope_invalid"
            )
        limitations = list(envelope.coverage.limitations)
        if not complete and "deep:analysis_incomplete" not in limitations:
            limitations.append("deep:analysis_incomplete")
        status = (
            CoverageStatus.COMPLETE
            if complete
            else CoverageStatus.PARTIAL
            if envelope.findings
            else CoverageStatus.FAILED
        )
        surfaces = list(coverage.surfaces) if coverage is not None else []
        state_delta[DEEP_EVIDENCE_KEY] = envelope.model_copy(
            update={
                "coverage": EvidenceCoverage(
                    status=status,
                    surfaces=tuple(surfaces),
                    limitations=tuple(limitations),
                )
            }
        ).model_dump(mode="json")
    return EscalationDecision(escalate=complete or exhausted, state_delta=state_delta)


DEEP_ANALYSIS_GATE_DESCRIPTOR = AgentDescriptor(
    id="deep_analysis_gate",
    name="deep_analysis_gate",
    description="Enforce bounded semantic and targeted Ghidra coverage.",
    prompt_id=None,
    factory=partial(build_escalation_gate, evaluator=evaluate_deep_analysis_gate),
    kind=AgentKind.DETERMINISTIC,
)
