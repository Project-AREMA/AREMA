"""Shared state contracts for the deobfuscation loop."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from reverse_engineering.model_json import loads_model_json
from reverse_engineering.tools.workbench.state import (
    THRASH_ARTIFACT_KEY,
    THRASH_REPEAT_COUNT_KEY,
    THRASH_SIGNATURE_KEY,
)

CLASSIFICATION_KEY = "deobf:classification"
CURRENT_ARTIFACT_KEY = "deobf:current_artifact_id"
CURRENT_ARTIFACT_PROMPT_KEY = "deobf_current_artifact_id"
DEOBF_BASELINE_PROMPT_KEY = "deobf_previous_snapshot_json"
PCODE_PREFERRED_PROMPT_KEY = "deobf_pcode_preferred"
UPX_PROVENANCE_PROMPT_KEY = "deobf_upx_provenance"
# Concrete, FLOSS-derived function addresses handed to the deep-decompile worker
# as mandatory targeted-decompilation targets (see deobf_gate + deep_decompile).
DEEP_DECOMPILE_TARGETS_PROMPT_KEY = "deep_decompile_targets"
UPX_CHANGED_KEY = "deobf:upx_changed"
UPX_DEGRADED_KEY = "deobf:upx_degraded"
UPX_CALLED_KEY = "deobf:upx_called"
UPX_RESULT_KEY = "deobf:upx_result"
DE4DOT_CALLED_KEY = "deobf:de4dot_called"
DE4DOT_RESULT_KEY = "deobf:de4dot_result"
# Deterministic dnlib metadata-roundtrip first-pass (runs after de4dot in the
# recover chain). Its OWN outcome lives here so the agentic dotnet_scripted_recover
# gate can tell whether the deterministic pass already recovered; on success it
# also writes the shared SCRIPTED_RESULT_KEY rail (same shape as register), so the
# gate/evidence/critic need no dnlib-specific handling.
DNLIB_ROUNDTRIP_CALLED_KEY = "deobf:dnlib_roundtrip_called"
DNLIB_ROUNDTRIP_RESULT_KEY = "deobf:dnlib_roundtrip_result"
# Per-artifact marker holding the CURRENT_ARTIFACT id the agentic dotnet_analyst
# deep pass last ran on (NOT reset per loop iteration). The deep pass runs once per
# LAYER: when it registers a recovered inner layer, CURRENT_ARTIFACT advances and
# the pass re-runs on the new layer, so a multi-layer sample is peeled layer by
# layer (bounded by the global run_python budget + the loop's iteration cap). The
# metadata round-trip only makes the assembly loadable, so a successful round-trip
# must NOT skip the deep pass.
DOTNET_DEEP_ATTEMPTED_KEY = "deobf:dotnet_deep_attempted"
FLOSS_COUNT_KEY = "deobf:floss_count"
FLOSS_DEGRADED_KEY = "deobf:floss_degraded"
FLOSS_CALLED_KEY = "deobf:floss_called"
FLOSS_RESULT_KEY = "deobf:floss_result"
FLOSS_SEEN_FINGERPRINTS_KEY = "deobf:floss_seen_fingerprints"
RETRIAGE_SNAPSHOT_KEY = "deobf:retriage_snapshot"
PREVIOUS_SNAPSHOT_KEY = "deobf:previous_snapshot"
RECOVERY_SUMMARY_KEY = "recovery_summary_json"
RECOVERY_EVIDENCE_KEY = "recovery_evidence_json"
DEOBF_ITERATION_KEY = "deobf:iteration"
SCRIPTED_RESULT_KEY = "deobf:scripted_result"
SCRIPTED_ATTEMPTED_KEY = "deobf:scripted_attempted"
# Single source of truth for the deobfuscation loop's iteration cap, imported by
# both the LoopAgent descriptor (metadata['max_iterations']) and deobf_gate's
# independent exit check. Six gives headroom for nested packer->loader->core
# layers; the global run_python budget still bounds total executions across rounds.
DEOBF_MAX_ITERATIONS = 6
_GATE_ERROR_KEY = "deobf:gate_error"

_ARTIFACT_ID_PATTERN = re.compile(r"[0-9a-f]{64}")
_TOP_LEVEL_KEYS = frozenset(
    {"artifact_id", "deobf_plan", "pcode_preferred", "obf_class", "pre_snapshot"}
)
_PLAN_KEYS = frozenset({"upx", "floss"})
_SNAPSHOT_KEYS = frozenset(
    {"size", "function_count", "import_count", "string_count", "section_count"}
)
_OBF_CLASSES = frozenset(
    {"none", "upx", "packed-other", "cff", "vm", "opaque-predicate", "unknown"}
)


@dataclass(frozen=True, slots=True)
class DeobfPlan:
    """Normalized decision inputs written by the classification stage."""

    artifact_id: str
    upx: bool
    floss: bool
    pcode_preferred: bool
    obf_class: str
    pre_snapshot: dict[str, int]


def reset_deobfuscation_state(state: object, artifact_id: str) -> None:
    """Start a new sample analysis without retaining prior loop authority.

    ADK's state proxy has no deletion operation, so neutral values deliberately
    clear all per-analysis aliases, caches, snapshots, and gate facts. The new
    canonical artifact id is the only authority retained.
    """
    if not isinstance(artifact_id, str) or _ARTIFACT_ID_PATTERN.fullmatch(artifact_id) is None:
        raise ValueError("artifact_id must be a lowercase SHA-256")
    setter = getattr(state, "__setitem__", None)
    if not callable(setter):
        return
    cleared: dict[str, object] = {
        CLASSIFICATION_KEY: None,
        CURRENT_ARTIFACT_PROMPT_KEY: "",
        DEOBF_BASELINE_PROMPT_KEY: "",
        PCODE_PREFERRED_PROMPT_KEY: "",
        UPX_PROVENANCE_PROMPT_KEY: "",
        DEEP_DECOMPILE_TARGETS_PROMPT_KEY: "",
        UPX_CHANGED_KEY: False,
        UPX_DEGRADED_KEY: False,
        UPX_CALLED_KEY: False,
        UPX_RESULT_KEY: None,
        DE4DOT_CALLED_KEY: False,
        DE4DOT_RESULT_KEY: None,
        FLOSS_COUNT_KEY: 0,
        FLOSS_DEGRADED_KEY: False,
        FLOSS_CALLED_KEY: False,
        FLOSS_RESULT_KEY: None,
        FLOSS_SEEN_FINGERPRINTS_KEY: [],
        RETRIAGE_SNAPSHOT_KEY: None,
        PREVIOUS_SNAPSHOT_KEY: None,
        RECOVERY_SUMMARY_KEY: None,
        RECOVERY_EVIDENCE_KEY: None,
        DEOBF_ITERATION_KEY: 0,
        SCRIPTED_RESULT_KEY: None,
        SCRIPTED_ATTEMPTED_KEY: False,
        _GATE_ERROR_KEY: None,
        THRASH_SIGNATURE_KEY: "",
        THRASH_REPEAT_COUNT_KEY: 0,
        THRASH_ARTIFACT_KEY: "",
        CURRENT_ARTIFACT_KEY: artifact_id,
    }
    for key, value in cleared.items():
        setter(key, value)


def parse_classification(state: object) -> DeobfPlan:
    """Read and strictly normalize the classification payload from ADK state."""
    getter = getattr(state, "get", None)
    raw = getter(CLASSIFICATION_KEY) if callable(getter) else None
    if isinstance(raw, str):
        # deobf_classify is a composed agent with no output_schema, so its
        # classification arrives as free-form model text -- routinely wrapped in a
        # ```json code fence. Route through the single model->JSON boundary
        # (fence-tolerant, constant-rejecting) instead of a bare json.loads.
        try:
            data = loads_model_json(raw)
        except ValueError as exc:
            raise ValueError("invalid deobfuscation classification JSON") from exc
    else:
        data = raw
    if not isinstance(data, dict):
        raise ValueError("missing deobfuscation classification")
    _require_exact_keys(data, _TOP_LEVEL_KEYS, "classification top-level")
    artifact_id = data.get("artifact_id")
    if not isinstance(artifact_id, str) or _ARTIFACT_ID_PATTERN.fullmatch(artifact_id) is None:
        raise ValueError("classification.artifact_id must be a lowercase SHA-256")
    plan = data.get("deobf_plan")
    if not isinstance(plan, dict):
        raise ValueError("classification.deobf_plan must be an object")
    _require_exact_keys(plan, _PLAN_KEYS, "classification.deobf_plan")
    upx = _required_bool(plan, "upx", "classification.deobf_plan.upx")
    floss = _required_bool(plan, "floss", "classification.deobf_plan.floss")
    pcode_preferred = _required_bool(data, "pcode_preferred", "classification.pcode_preferred")
    obf_class = data.get("obf_class")
    if not isinstance(obf_class, str) or obf_class not in _OBF_CLASSES:
        raise ValueError("classification.obf_class is invalid")
    pre_snapshot = data.get("pre_snapshot")
    if not isinstance(pre_snapshot, dict):
        raise ValueError("classification.pre_snapshot must be an object")
    _require_exact_keys(pre_snapshot, _SNAPSHOT_KEYS, "classification.pre_snapshot")
    normalized_snapshot: dict[str, int] = {}
    for key in _SNAPSHOT_KEYS:
        value = pre_snapshot[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("classification.pre_snapshot values must be nonnegative integers")
        normalized_snapshot[key] = value
    return DeobfPlan(
        artifact_id=artifact_id,
        upx=upx,
        floss=floss,
        pcode_preferred=pcode_preferred,
        obf_class=obf_class,
        pre_snapshot=normalized_snapshot,
    )


def parse_current_classification(state: object) -> DeobfPlan:
    """Parse classification and require it to match canonical artifact authority."""
    plan = parse_classification(state)
    validate_current_classification(state, plan)
    return plan


def validate_current_classification(state: object, plan: DeobfPlan) -> None:
    """Reject missing, malformed, or mismatched canonical artifact state."""
    getter = getattr(state, "get", None)
    current = getter(CURRENT_ARTIFACT_KEY) if callable(getter) else None
    if not isinstance(current, str) or _ARTIFACT_ID_PATTERN.fullmatch(current) is None:
        raise ValueError("current artifact must be a lowercase SHA-256")
    if current != plan.artifact_id:
        raise ValueError("classification artifact does not match current artifact")


def advance_classification_artifact(state: object, plan: DeobfPlan, artifact_id: str) -> None:
    """Advance strict classification authority after admitted artifact recovery."""
    if _ARTIFACT_ID_PATTERN.fullmatch(artifact_id) is None:
        raise ValueError("artifact_id must be a lowercase SHA-256")
    setter = getattr(state, "__setitem__", None)
    if not callable(setter):
        raise ValueError("state is not writable")
    setter(
        CLASSIFICATION_KEY,
        json.dumps(
            {
                "artifact_id": artifact_id,
                "deobf_plan": {"upx": plan.upx, "floss": plan.floss},
                "pcode_preferred": plan.pcode_preferred,
                "obf_class": plan.obf_class,
                "pre_snapshot": plan.pre_snapshot,
            },
            separators=(",", ":"),
        ),
    )


def _required_bool(data: dict[object, object], key: str, label: str) -> bool:
    """Return one required bool without accepting truthy/falsy coercions."""
    value = data.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a boolean")
    return value


def _require_exact_keys(data: dict[object, object], expected: frozenset[str], label: str) -> None:
    if set(data) != expected:
        raise ValueError(f"{label} keys must be exactly {sorted(expected)}")
