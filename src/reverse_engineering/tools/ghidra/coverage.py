"""Artifact-bound deep-analysis (Ghidra) coverage facts.

Deep analysis is only complete when the loaded binary was actually prepared,
a semantic decompiled-search surface returned a non-empty result, and a
targeted decompile/p-code surface returned a non-empty result. Metadata,
imports, strings, and function inventories never satisfy that contract.

Coverage is recorded deterministically from the tool wrappers (never inferred
from conversation history) and is bound to the canonical artifact so a stale
or cross-artifact result can never advance it.
"""

from __future__ import annotations

import json

from pydantic import BaseModel, ConfigDict

from reverse_engineering.tools.deobfuscation.state import CURRENT_ARTIFACT_KEY

DEEP_COVERAGE_KEY = "deep:coverage"
DEEP_MISSING_PROMPT_KEY = "deep_missing_surfaces"
DEEP_ITERATION_KEY = "deep:iteration"
DEEP_EVIDENCE_KEY = "deep_evidence_json"
# Native (.so) analysis is a separate evidence stage from deep binary analysis:
# `android_native_analysis` runs Ghidra over the APK's extracted native libraries
# and writes its own envelope, which the critic unions alongside `deep`.
NATIVE_EVIDENCE_KEY = "native_evidence_json"

_SEMANTIC_TOOLS = frozenset({"ghidra_search_decompiled"})
_TARGET_TOOLS = frozenset({"ghidra_decompile", "ghidra_pcode"})

__all__ = [
    "DEEP_COVERAGE_KEY",
    "DEEP_EVIDENCE_KEY",
    "DEEP_ITERATION_KEY",
    "DEEP_MISSING_PROMPT_KEY",
    "NATIVE_EVIDENCE_KEY",
    "DeepCoverage",
    "read_deep_coverage",
    "record_ghidra_result",
    "record_prepared",
    "reset_deep_analysis_state",
]


class DeepCoverage(BaseModel):
    """Immutable, artifact-bound record of which deep surfaces have succeeded."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact_id: str
    prepared: bool
    semantic_search_succeeded: bool
    target_analysis_succeeded: bool
    surfaces: list[str]


def _empty_coverage(artifact_id: str) -> DeepCoverage:
    return DeepCoverage(
        artifact_id=artifact_id,
        prepared=False,
        semantic_search_succeeded=False,
        target_analysis_succeeded=False,
        surfaces=[],
    )


def read_deep_coverage(state: object, artifact_id: str) -> DeepCoverage:
    """Read the strict coverage model, rejecting a cross-artifact record."""
    getter = getattr(state, "get", None)
    raw = getter(DEEP_COVERAGE_KEY) if callable(getter) else None
    coverage = DeepCoverage.model_validate(raw)
    if coverage.artifact_id != artifact_id:
        raise ValueError("deep coverage artifact mismatch")
    return coverage


def record_prepared(state: object, artifact_id: str) -> None:
    """Mark deep preparation for the canonical artifact, preserving prior surfaces."""
    getter = getattr(state, "get", None)
    setter = getattr(state, "__setitem__", None)
    if not callable(getter) or not callable(setter) or getter(CURRENT_ARTIFACT_KEY) != artifact_id:
        return
    try:
        current = read_deep_coverage(state, artifact_id)
    except (TypeError, ValueError):
        current = _empty_coverage(artifact_id)
    setter(
        DEEP_COVERAGE_KEY,
        current.model_copy(update={"prepared": True}).model_dump(mode="json"),
    )


def _nonempty_result(output: object) -> bool:
    """True when ghidra-rpc output carries a usable, non-empty ``result``."""
    if not isinstance(output, str) or not output.strip():
        return False
    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        return True
    if not isinstance(payload, dict) or payload.get("ok") is False:
        return False
    result = payload.get("result")
    if isinstance(result, dict):
        return any(value not in (None, "", [], {}) for value in result.values())
    return result not in (None, "", [], {})


def record_ghidra_result(
    state: object,
    *,
    artifact_id: str,
    tool_name: str,
    response: object,
) -> None:
    """Record one successful, non-empty, artifact-bound Ghidra surface.

    Degraded, empty, mismatched, or exception responses are ignored so coverage
    only ever reflects surfaces that produced usable output for this artifact.
    """
    getter = getattr(state, "get", None)
    setter = getattr(state, "__setitem__", None)
    if (
        not callable(getter)
        or not callable(setter)
        or getter(CURRENT_ARTIFACT_KEY) != artifact_id
        or not isinstance(response, dict)
        or response.get("success") is not True
        or not _nonempty_result(response.get("output"))
    ):
        return
    try:
        current = read_deep_coverage(state, artifact_id)
    except (TypeError, ValueError):
        return
    surfaces = list(current.surfaces)
    if tool_name not in surfaces:
        surfaces.append(tool_name)
    setter(
        DEEP_COVERAGE_KEY,
        current.model_copy(
            update={
                "semantic_search_succeeded": (
                    current.semantic_search_succeeded or tool_name in _SEMANTIC_TOOLS
                ),
                "target_analysis_succeeded": (
                    current.target_analysis_succeeded or tool_name in _TARGET_TOOLS
                ),
                "surfaces": surfaces,
            }
        ).model_dump(mode="json"),
    )


def reset_deep_analysis_state(state: object) -> None:
    """Clear all deep-analysis state so a new sample starts from zero coverage."""
    setter = getattr(state, "__setitem__", None)
    if not callable(setter):
        return
    setter(DEEP_COVERAGE_KEY, None)
    setter(DEEP_MISSING_PROMPT_KEY, "")
    setter(DEEP_ITERATION_KEY, 0)
    setter(DEEP_EVIDENCE_KEY, None)
