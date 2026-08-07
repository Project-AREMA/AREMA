"""Tests for artifact-bound deep (Ghidra) coverage facts."""

from __future__ import annotations

from reverse_engineering.tools.deobfuscation.state import CURRENT_ARTIFACT_KEY
from reverse_engineering.tools.ghidra.coverage import (
    DEEP_COVERAGE_KEY,
    read_deep_coverage,
    record_ghidra_result,
    record_prepared,
)

ARTIFACT = "a" * 64


def test_metadata_cannot_complete_deep_coverage() -> None:
    state: dict[str, object] = {CURRENT_ARTIFACT_KEY: ARTIFACT}
    record_prepared(state, ARTIFACT)
    record_ghidra_result(
        state,
        artifact_id=ARTIFACT,
        tool_name="ghidra_metadata",
        response={"success": True, "output": '{"result":{"format":"pe"}}'},
    )

    coverage = read_deep_coverage(state, ARTIFACT)
    assert coverage.prepared is True
    assert coverage.semantic_search_succeeded is False
    assert coverage.target_analysis_succeeded is False


def test_nonempty_search_and_decompile_complete_deep_coverage() -> None:
    state: dict[str, object] = {CURRENT_ARTIFACT_KEY: ARTIFACT}
    record_prepared(state, ARTIFACT)
    record_ghidra_result(
        state,
        artifact_id=ARTIFACT,
        tool_name="ghidra_search_decompiled",
        response={"success": True, "output": '{"result":[{"function":"main"}]}'},
    )
    record_ghidra_result(
        state,
        artifact_id=ARTIFACT,
        tool_name="ghidra_decompile",
        response={"success": True, "output": '{"result":{"c_code":"return 0;"}}'},
    )

    coverage = read_deep_coverage(state, ARTIFACT)
    assert coverage.semantic_search_succeeded is True
    assert coverage.target_analysis_succeeded is True
    assert coverage.surfaces == [
        "ghidra_search_decompiled",
        "ghidra_decompile",
    ]


def test_empty_or_stale_result_does_not_count() -> None:
    state: dict[str, object] = {CURRENT_ARTIFACT_KEY: ARTIFACT}
    record_prepared(state, ARTIFACT)
    record_ghidra_result(
        state,
        artifact_id="b" * 64,
        tool_name="ghidra_pcode",
        response={"success": True, "output": '{"result":{"ops":["COPY"]}}'},
    )
    record_ghidra_result(
        state,
        artifact_id=ARTIFACT,
        tool_name="ghidra_search_decompiled",
        response={"success": True, "output": '{"result":[]}'},
    )

    coverage = read_deep_coverage(state, ARTIFACT)
    assert coverage.semantic_search_succeeded is False
    assert coverage.target_analysis_succeeded is False
    assert state[DEEP_COVERAGE_KEY]["artifact_id"] == ARTIFACT  # type: ignore[index]
