"""Tests for the deterministic deep-analysis completion gate."""

from __future__ import annotations

from reverse_engineering.agents.deep_analysis_gate import evaluate_deep_analysis_gate
from reverse_engineering.tools.deobfuscation.state import CURRENT_ARTIFACT_KEY
from reverse_engineering.tools.ghidra.coverage import (
    DEEP_COVERAGE_KEY,
    DEEP_EVIDENCE_KEY,
    DEEP_ITERATION_KEY,
    DEEP_MISSING_PROMPT_KEY,
)

ARTIFACT = "a" * 64


def _state(*, prepared: bool, search: bool, target: bool, iteration: int = 0) -> dict[str, object]:
    return {
        CURRENT_ARTIFACT_KEY: ARTIFACT,
        DEEP_ITERATION_KEY: iteration,
        DEEP_COVERAGE_KEY: {
            "artifact_id": ARTIFACT,
            "prepared": prepared,
            "semantic_search_succeeded": search,
            "target_analysis_succeeded": target,
            "surfaces": [],
        },
        DEEP_EVIDENCE_KEY: {
            "artifact_id": ARTIFACT,
            "coverage": {"status": "partial", "surfaces": [], "limitations": []},
            "findings": [],
        },
    }


def test_metadata_only_deep_analysis_continues() -> None:
    decision = evaluate_deep_analysis_gate(_state(prepared=True, search=False, target=False))
    assert decision.escalate is False
    assert decision.state_delta[DEEP_MISSING_PROMPT_KEY] == (
        "semantic_search,target_decompile_or_pcode"
    )


def test_search_and_target_analysis_complete_the_loop() -> None:
    decision = evaluate_deep_analysis_gate(_state(prepared=True, search=True, target=True))
    assert decision.escalate is True
    assert decision.state_delta[DEEP_EVIDENCE_KEY]["coverage"]["status"] == "complete"  # type: ignore[index,call-overload]


def test_cap_exhaustion_preserves_findings_and_adds_limitation() -> None:
    state = _state(prepared=True, search=True, target=False, iteration=2)
    state[DEEP_EVIDENCE_KEY]["findings"] = [  # type: ignore[index]
        {
            "artifact_id": ARTIFACT,
            "claim": "The binary is PE32+.",
            "tool": "ghidra_metadata",
            "confidence": 0.9,
            "detail": "format pe64",
            "kind": "metadata",
        }
    ]

    decision = evaluate_deep_analysis_gate(state)

    assert decision.escalate is True
    envelope = decision.state_delta[DEEP_EVIDENCE_KEY]
    assert envelope["findings"]  # type: ignore[index,call-overload]
    assert "deep:analysis_incomplete" in envelope["coverage"]["limitations"]  # type: ignore[index,call-overload]
