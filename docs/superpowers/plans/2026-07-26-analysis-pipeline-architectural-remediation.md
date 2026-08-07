# Analysis Pipeline Architectural Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every AREMA entry point share one sandbox identity and produce a complete, coverage-aware malware report from explicit, validated, sandbox-derived evidence.

**Architecture:** A neutral invocation-scoped resolver supplies the case identity used by Radare2, Ghidra, UPX, and FLOSS. Evidence-producing agents write bounded JSON to named state keys; deterministic callbacks normalize those outputs, recovery and deep-analysis gates preserve limitations and enforce completion, and isolated evidence consumers read only named aliases. The malware spine runs all local evidence producers before IOC synthesis and validates every stage before rendering.

**Tech Stack:** Python 3.12, Google ADK, Pydantic v2, pytest, Radare2 MCP, ghidra-rpc, Mandiant FLOSS, UPX, Kubernetes sandbox claims

---

## Scope and sequencing

This is one integrated plan because each invariant depends on the preceding
one: evidence consumers cannot be corrected before evidence has a validated
transport, deep evidence cannot participate in IOC extraction until completion
is enforced, and no sandbox-backed producer is reliable until case identity is
entry-point independent.

The branch already contains the reviewed Ghidra timeout fix in commit
`de14f03`. Task 4 builds on its changes in:

- `src/reverse_engineering/tools/ghidra/prepare_ghidra.py`
- `tests/reverse_engineering/test_ghidra_toolset.py`

Preserve the 600/660-second deadlines. Each task stages only the paths named in
its commit step.

## File map

| Path | Responsibility |
|---|---|
| `src/arema/runtime/sessions.py` | Single sandbox case identity resolver |
| `src/arema/registry/descriptors.py` | Declarative after-agent callback extension |
| `src/arema/runtime/agent_factory.py` | Callback ordering: normalization before checkpointing |
| `src/reverse_engineering/evidence_envelope.py` | Bounded evidence and critic schemas, parsing, failure envelopes |
| `src/reverse_engineering/agents/evidence_output.py` | Deterministic state-output normalization callbacks |
| `src/reverse_engineering/tools/deobfuscation/state.py` | Iteration and terminal recovery state keys |
| `src/reverse_engineering/agents/deobf_gate.py` | Durable recovery summary/evidence and bounded terminal reason |
| `src/reverse_engineering/tools/ghidra/coverage.py` | Artifact-bound Ghidra coverage facts |
| `src/reverse_engineering/tools/ghidra/prepare_ghidra.py` | Shared identity, preparation coverage, idempotent reuse |
| `src/reverse_engineering/tools/ghidra/toolset.py` | Shared identity and successful semantic/target coverage recording |
| `src/reverse_engineering/agents/deep_analysis_gate.py` | Deterministic deep completion gate |
| `src/reverse_engineering/agents/deep_analysis.py` | Capped deep worker/gate loop |
| Evidence producer descriptors | Named output keys and deterministic normalizers |
| Evidence consumer prompts | Explicit aliases and JSON-only contracts |
| `src/malware_analyst/agents/malware_analyst.py` | Correct producer-before-consumer pipeline order |
| `src/malware_analyst/evidence.py` | Network coverage and critic/report contract enforcement |
| Architecture documentation | Durable lifecycle, evidence-flow, and tool-authoring rules |

### Task 1: Centralize invocation-scoped sandbox identity

**Files:**

- Modify: `src/arema/runtime/sessions.py`
- Modify: `src/reverse_engineering/tools/prepare_sandbox.py`
- Modify: `src/reverse_engineering/tools/ghidra/prepare_ghidra.py`
- Modify: `src/reverse_engineering/tools/ghidra/toolset.py`
- Modify: `src/reverse_engineering/tools/deobfuscation/runtime.py`
- Create: `tests/unit/runtime/test_sessions.py`
- Modify: `tests/reverse_engineering/test_prepare_sandbox.py`
- Modify: `tests/reverse_engineering/test_ghidra_toolset.py`
- Modify: `tests/reverse_engineering/test_deobfuscation_runtime.py`

- [ ] **Step 1: Write resolver unit tests**

Add `tests/unit/runtime/test_sessions.py`:

```python
from __future__ import annotations

from types import SimpleNamespace

import pytest

from arema.runtime.sessions import (
    SandboxIdentityError,
    SessionKeys,
    resolve_sandbox_case_id,
)


class _State:
    def __init__(self, values: dict[object, object] | None = None) -> None:
        self.values = dict(values or {})

    def get(self, key: object, default: object = None) -> object:
        return self.values.get(key, default)

    def __setitem__(self, key: object, value: object) -> None:
        self.values[key] = value


def test_explicit_sandbox_case_id_is_preserved_exactly() -> None:
    state = _State({SessionKeys.SANDBOX_CASE_ID: "cli-case-42"})
    context = SimpleNamespace(state=state, invocation_id="invocation-ignored")

    assert resolve_sandbox_case_id(context) == "cli-case-42"
    assert state.values[SessionKeys.SANDBOX_CASE_ID] == "cli-case-42"


def test_invocation_id_derives_and_persists_one_case_id() -> None:
    state = _State()
    context = SimpleNamespace(state=state, invocation_id="dev-ui-invocation")

    first = resolve_sandbox_case_id(context)
    second = resolve_sandbox_case_id(context)

    assert first == second
    assert first.startswith("inv-")
    assert state.values[SessionKeys.SANDBOX_CASE_ID] == first


def test_distinct_invocations_have_distinct_case_ids() -> None:
    first = resolve_sandbox_case_id(
        SimpleNamespace(state=_State(), invocation_id="invocation-a")
    )
    second = resolve_sandbox_case_id(
        SimpleNamespace(state=_State(), invocation_id="invocation-b")
    )

    assert first != second


@pytest.mark.parametrize(
    "context",
    [
        SimpleNamespace(state=_State(), invocation_id=""),
        SimpleNamespace(state=_State(), invocation_id=None),
        SimpleNamespace(state=object(), invocation_id="invocation-a"),
        object(),
    ],
)
def test_missing_writable_state_or_identity_is_rejected(context: object) -> None:
    with pytest.raises(SandboxIdentityError):
        resolve_sandbox_case_id(context)
```

- [ ] **Step 2: Run the resolver test and verify red**

Run:

```bash
rtk uv run pytest tests/unit/runtime/test_sessions.py -q
```

Expected: collection fails because `SandboxIdentityError` and
`resolve_sandbox_case_id` do not exist.

- [ ] **Step 3: Implement the neutral resolver**

Add to `src/arema/runtime/sessions.py`:

```python
import hashlib


class SandboxIdentityError(RuntimeError):
    """Raised when an ADK context cannot identify a sandbox lifecycle."""


def resolve_sandbox_case_id(context: object) -> str:
    """Resolve and persist the stable sandbox key for one ADK invocation."""
    state = getattr(context, "state", None)
    getter = getattr(state, "get", None)
    setter = getattr(state, "__setitem__", None)
    if not callable(getter) or not callable(setter):
        raise SandboxIdentityError("sandbox state is unavailable")

    explicit = getter(SessionKeys.SANDBOX_CASE_ID, None)
    if isinstance(explicit, str) and explicit.strip():
        return explicit

    invocation_id = getattr(context, "invocation_id", None)
    if not isinstance(invocation_id, str) or not invocation_id.strip():
        raise SandboxIdentityError("sandbox invocation identity is unavailable")

    digest = hashlib.sha256(invocation_id.encode("utf-8")).hexdigest()[:32]
    resolved = f"inv-{digest}"
    setter(SessionKeys.SANDBOX_CASE_ID, resolved)
    return resolved
```

- [ ] **Step 4: Replace every private sandbox default**

Delete `_DEFAULT_CASE_KEY = "re-mvp"` and each private `_resolve_case_id`.
Import and call the neutral resolver:

```python
from arema.runtime.sessions import (
    SandboxIdentityError,
    resolve_sandbox_case_id,
)
```

In `prepare_sandbox`, resolve before claiming and return a stable public code:

```python
try:
    case_id = resolve_sandbox_case_id(tool_context)
except SandboxIdentityError:
    return {
        "pod": "",
        "ready": False,
        "error_code": "sandbox_identity_unavailable",
        "error": "The sandbox identity is unavailable.",
    }
```

Use the same block in `prepare_ghidra`, retaining its `binary` and
`artifact_id` response fields. In the Ghidra command wrapper return:

```python
try:
    case_id = resolve_sandbox_case_id(tool_context)
except SandboxIdentityError:
    return {
        "success": False,
        "error_code": "sandbox_identity_unavailable",
        "error": "The sandbox identity is unavailable.",
        "tool": spec.name,
    }
```

In `deobfuscation/runtime.py`, translate the neutral error without weakening
the Kubernetes-only guard:

```python
try:
    case_id = resolve_sandbox_case_id(tool_context)
except SandboxIdentityError as exc:
    raise DeobfuscationUnavailable("sandbox identity unavailable") from exc
```

- [ ] **Step 5: Replace fallback tests with invocation and cross-tool tests**

Update the fake tool contexts to carry a writable state and
`invocation_id`. Replace fallback assertions with:

```python
def test_dev_ui_context_persists_case_id_before_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _FakeToolContext(invocation_id="dev-ui-run")
    tool = prepare_sandbox.build_prepare_sandbox(_build_context(executor=FakeExecutor()))
    monkeypatch.setattr(prepare_sandbox, "default_artifacts_root", lambda: tmp_path)
    monkeypatch.setattr(prepare_sandbox, "kubectl_cp", lambda *_args: None)
    monkeypatch.setattr(prepare_sandbox, "default_registry", lambda: _RecordingRegistry())

    tool("a" * 64, context)

    resolved = context.state.get(SessionKeys.SANDBOX_CASE_ID)
    assert isinstance(resolved, str)
    assert resolved.startswith("inv-")
```

Add one cross-tool assertion proving every module exposes the same resolver:

```python
from reverse_engineering.tools import prepare_sandbox
from reverse_engineering.tools.deobfuscation import runtime as deobfuscation_runtime
from reverse_engineering.tools.ghidra import prepare_ghidra
from reverse_engineering.tools.ghidra import toolset as ghidra_toolset


def test_all_sandbox_tool_families_share_one_resolved_case() -> None:
    context = _FakeToolContext(invocation_id="shared-dev-ui-run")

    resolved = [
        prepare_sandbox.resolve_sandbox_case_id(context),
        prepare_ghidra.resolve_sandbox_case_id(context),
        ghidra_toolset.resolve_sandbox_case_id(context),
        deobfuscation_runtime.resolve_sandbox_case_id(context),
    ]

    assert len(set(resolved)) == 1
    assert context.state.get(SessionKeys.SANDBOX_CASE_ID) == resolved[0]
```

- [ ] **Step 6: Run focused sandbox tests**

Run:

```bash
rtk uv run pytest tests/unit/runtime/test_sessions.py tests/reverse_engineering/test_prepare_sandbox.py tests/reverse_engineering/test_ghidra_toolset.py tests/reverse_engineering/test_deobfuscation_runtime.py -q
```

Expected: all tests pass and no assertion references `re-mvp`.

- [ ] **Step 7: Commit the identity contract**

```bash
rtk git add src/arema/runtime/sessions.py src/reverse_engineering/tools/prepare_sandbox.py src/reverse_engineering/tools/ghidra/prepare_ghidra.py src/reverse_engineering/tools/ghidra/toolset.py src/reverse_engineering/tools/deobfuscation/runtime.py tests/unit/runtime/test_sessions.py tests/reverse_engineering/test_prepare_sandbox.py tests/reverse_engineering/test_ghidra_toolset.py tests/reverse_engineering/test_deobfuscation_runtime.py
rtk git commit -m "fix: unify sandbox identity across analysis tools"
```

### Task 2: Add bounded evidence schemas and deterministic output normalization

**Files:**

- Modify: `src/arema/registry/descriptors.py`
- Modify: `src/arema/runtime/agent_factory.py`
- Create: `src/reverse_engineering/evidence_envelope.py`
- Create: `src/reverse_engineering/agents/evidence_output.py`
- Create: `tests/reverse_engineering/test_evidence_envelope.py`
- Modify: `tests/unit/registry/test_catalog.py`
- Modify: `tests/unit/runtime/test_agent_factory.py`

- [ ] **Step 1: Write schema and normalization tests**

Create `tests/reverse_engineering/test_evidence_envelope.py` with:

```python
from __future__ import annotations

from types import SimpleNamespace

from reverse_engineering.agents.evidence_output import normalize_evidence_output
from reverse_engineering.evidence_envelope import (
    EvidenceEnvelope,
    FindingKind,
    parse_evidence_envelope,
)


ARTIFACT = "a" * 64


def _valid_payload() -> dict[str, object]:
    return {
        "artifact_id": ARTIFACT,
        "coverage": {
            "status": "complete",
            "surfaces": ["show_info"],
            "limitations": [],
        },
        "findings": [
            {
                "artifact_id": ARTIFACT,
                "claim": "The sample is PE32+.",
                "tool": "show_info",
                "confidence": 0.95,
                "detail": "format pe64",
                "kind": "metadata",
            }
        ],
    }


def test_parser_accepts_exact_artifact_bound_envelope() -> None:
    envelope = parse_evidence_envelope(_valid_payload(), artifact_id=ARTIFACT)
    assert envelope.findings[0].kind is FindingKind.METADATA


def test_parser_rejects_cross_artifact_finding() -> None:
    payload = _valid_payload()
    payload["findings"][0]["artifact_id"] = "b" * 64  # type: ignore[index]
    try:
        parse_evidence_envelope(payload, artifact_id=ARTIFACT)
    except ValueError as error:
        assert "artifact" in str(error)
    else:
        raise AssertionError("cross-artifact evidence was accepted")


def test_invalid_model_output_becomes_failed_coverage() -> None:
    state = {"deobf:current_artifact_id": ARTIFACT, "triage_evidence_json": "not json"}
    callback_context = SimpleNamespace(state=state)

    normalize_evidence_output(
        callback_context,
        output_key="triage_evidence_json",
        stage="triage",
    )

    normalized = EvidenceEnvelope.model_validate(state["triage_evidence_json"])
    assert normalized.coverage.status == "failed"
    assert normalized.coverage.limitations == ["triage:evidence_envelope_invalid"]
    assert normalized.findings == []
```

- [ ] **Step 2: Run the schema test and verify red**

Run:

```bash
rtk uv run pytest tests/reverse_engineering/test_evidence_envelope.py -q
```

Expected: collection fails because the evidence-envelope modules do not exist.

- [ ] **Step 3: Implement strict bounded schemas**

Create `src/reverse_engineering/evidence_envelope.py`:

```python
from __future__ import annotations

import json
import re
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

MAX_FINDINGS = 200
MAX_SURFACES = 64
MAX_LIMITATIONS = 64
MAX_CLAIM_CHARS = 1_000
MAX_DETAIL_CHARS = 8_000
_ARTIFACT_ID = re.compile(r"[0-9a-f]{64}")
SurfaceName = Annotated[str, StringConstraints(min_length=1, max_length=128)]
Limitation = Annotated[str, StringConstraints(min_length=1, max_length=500)]


class CoverageStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class FindingKind(StrEnum):
    METADATA = "metadata"
    HOST_IOC = "host_ioc"
    NETWORK_IOC = "network_ioc"
    BEHAVIOR = "behavior"
    ATTACK = "attack"
    LIMITATION = "limitation"


class EvidenceCoverage(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    status: CoverageStatus
    surfaces: list[SurfaceName] = Field(max_length=MAX_SURFACES)
    limitations: list[Limitation] = Field(max_length=MAX_LIMITATIONS)


class EvidenceFinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact_id: str
    claim: str = Field(min_length=1, max_length=MAX_CLAIM_CHARS)
    tool: str = Field(min_length=1, max_length=128)
    confidence: float = Field(ge=0.0, le=1.0)
    detail: str = Field(max_length=MAX_DETAIL_CHARS)
    kind: FindingKind


class EvidenceEnvelope(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact_id: str
    coverage: EvidenceCoverage
    findings: list[EvidenceFinding] = Field(max_length=MAX_FINDINGS)

    @model_validator(mode="after")
    def validate_artifact_authority(self) -> EvidenceEnvelope:
        if _ARTIFACT_ID.fullmatch(self.artifact_id) is None:
            raise ValueError("artifact_id must be a lowercase SHA-256")
        if any(finding.artifact_id != self.artifact_id for finding in self.findings):
            raise ValueError("finding artifact does not match envelope artifact")
        return self


def parse_evidence_envelope(raw: object, *, artifact_id: str) -> EvidenceEnvelope:
    if isinstance(raw, str):
        raw = json.loads(raw)
    envelope = EvidenceEnvelope.model_validate(raw)
    if envelope.artifact_id != artifact_id:
        raise ValueError("envelope artifact does not match canonical artifact")
    return envelope


def failed_evidence_envelope(*, artifact_id: str, stage: str, code: str) -> EvidenceEnvelope:
    return EvidenceEnvelope(
        artifact_id=artifact_id,
        coverage=EvidenceCoverage(
            status=CoverageStatus.FAILED,
            surfaces=[],
            limitations=[f"{stage}:{code}"],
        ),
        findings=[],
    )
```

- [ ] **Step 4: Add declarative after-agent callbacks**

In `AgentDescriptor`, add:

```python
after_agent_callbacks: tuple[Callable[[CallbackContext], object], ...] = ()
```

Copy it to an immutable tuple in `__post_init__`. In
`arema/runtime/agent_factory.py`, construct callback order as:

```python
checkpoint_callbacks = (
    (make_checkpoint_recorder(checkpoint_sink),) if profile.record_memory else ()
)
after_agent = descriptor.after_agent_callbacks + checkpoint_callbacks
```

This ordering is part of the contract: normalization runs before a memory
checkpoint observes the stage output.

- [ ] **Step 5: Implement the normalizer callback**

Create `src/reverse_engineering/agents/evidence_output.py`:

```python
from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

from arema.core.logging import get_logger
from reverse_engineering.evidence_envelope import (
    failed_evidence_envelope,
    parse_evidence_envelope,
)
from reverse_engineering.tools.deobfuscation.state import CURRENT_ARTIFACT_KEY

if TYPE_CHECKING:
    from google.adk.agents.callback_context import CallbackContext

logger = get_logger(__name__)


def normalize_evidence_output(
    callback_context: CallbackContext,
    *,
    output_key: str,
    stage: str,
) -> None:
    state = callback_context.state
    artifact_id = state.get(CURRENT_ARTIFACT_KEY)
    if not isinstance(artifact_id, str):
        return
    try:
        envelope = parse_evidence_envelope(state.get(output_key), artifact_id=artifact_id)
    except (TypeError, ValueError) as error:
        logger.warning(
            "evidence envelope invalid",
            stage=stage,
            error_type=type(error).__name__,
        )
        envelope = failed_evidence_envelope(
            artifact_id=artifact_id,
            stage=stage,
            code="evidence_envelope_invalid",
        )
    state[output_key] = envelope.model_dump(mode="json")


def evidence_output_callback(*, output_key: str, stage: str):
    return partial(normalize_evidence_output, output_key=output_key, stage=stage)
```

- [ ] **Step 6: Test callback ordering**

Add a factory test with two callbacks that append `"normalize"` and
`"checkpoint"` to a list, then assert the built agent exposes them in that
order. Add catalog tests proving caller-owned callback lists are copied and
text values are rejected.

- [ ] **Step 7: Run focused schema and factory tests**

Run:

```bash
rtk uv run pytest tests/reverse_engineering/test_evidence_envelope.py tests/unit/registry/test_catalog.py tests/unit/runtime/test_agent_factory.py -q
```

Expected: all tests pass.

- [ ] **Step 8: Commit the evidence transport**

```bash
rtk git add src/arema/registry/descriptors.py src/arema/runtime/agent_factory.py src/reverse_engineering/evidence_envelope.py src/reverse_engineering/agents/evidence_output.py tests/reverse_engineering/test_evidence_envelope.py tests/unit/registry/test_catalog.py tests/unit/runtime/test_agent_factory.py
rtk git commit -m "feat: add validated state evidence envelopes"
```

### Task 3: Preserve recovery outcomes and FLOSS evidence

**Files:**

- Modify: `src/reverse_engineering/tools/deobfuscation/state.py`
- Modify: `src/reverse_engineering/agents/deobf_gate.py`
- Modify: `src/reverse_engineering/tools/acquire_sample.py`
- Modify: `tests/reverse_engineering/test_deobfuscation_agents.py`
- Modify: `tests/reverse_engineering/test_acquire_sample.py`

- [ ] **Step 1: Write failing durable-state tests**

Add constants and assertions for:

```python
RECOVERY_SUMMARY_KEY = "recovery_summary_json"
RECOVERY_EVIDENCE_KEY = "recovery_evidence_json"
DEOBF_ITERATION_KEY = "deobf:iteration"
```

Add these tests:

```python
def test_degraded_floss_survives_gate_iteration_cleanup() -> None:
    state = _state(floss=True, floss_degraded=True)
    state[FLOSS_RESULT_KEY] = {
        "success": False,
        "applicable": True,
        "degraded": True,
        "error_code": "sandbox_unavailable",
        "error": "The deobfuscation sandbox is unavailable.",
        "format": "pe",
        "tool_version": "3.1.1",
        "new_count": 0,
        "counts": {"decoded": 0, "stack": 0, "tight": 0},
        "records": [],
        "truncated": False,
        "source_artifact_id": "a" * 64,
    }

    decision = evaluate_deobf_gate(state)

    summary = decision.state_delta[RECOVERY_SUMMARY_KEY]
    assert summary["exit_reason"] == "degraded"
    assert summary["floss"]["error_code"] == "sandbox_unavailable"
    assert "floss:sandbox_unavailable" in summary["limitations"]
    assert decision.state_delta[FLOSS_RESULT_KEY] is None


def test_floss_records_become_durable_recovery_evidence() -> None:
    state = _state(floss=True, floss_count=1)
    state[FLOSS_RESULT_KEY] = {
        "success": True,
        "applicable": True,
        "degraded": False,
        "source_artifact_id": "a" * 64,
        "source_size": 12,
        "format": "pe",
        "tool_version": "3.1.1",
        "new_count": 1,
        "counts": {"decoded": 1, "stack": 0, "tight": 0},
        "records": [{
            "type": "decoded",
            "string": "https://example.test/a",
            "encoding": "ASCII",
            "function": "0x401000",
            "location": "0x401020",
        }],
        "truncated": False,
    }

    decision = evaluate_deobf_gate(state)

    evidence = decision.state_delta[RECOVERY_EVIDENCE_KEY]
    assert evidence["findings"][0]["tool"] == "floss_decode"
    assert "https://example.test/a" in evidence["findings"][0]["detail"]


def test_third_progressing_iteration_exits_with_cap_limitation() -> None:
    state = _state(upx_changed=True)
    state[DEOBF_ITERATION_KEY] = 2

    decision = evaluate_deobf_gate(state)

    assert decision.escalate is True
    assert decision.state_delta[RECOVERY_SUMMARY_KEY]["exit_reason"] == "iteration_cap"
```

- [ ] **Step 2: Run the recovery tests and verify red**

Run:

```bash
rtk uv run pytest tests/reverse_engineering/test_deobfuscation_agents.py -q
```

Expected: failures show the terminal keys and iteration counter are missing.

- [ ] **Step 3: Split resettable and terminal state**

In `state.py`, add the three constants. In
`reset_deobfuscation_state`, initialize:

```python
DEOBF_ITERATION_KEY: 0,
RECOVERY_SUMMARY_KEY: None,
RECOVERY_EVIDENCE_KEY: None,
```

Only `acquire_sample` calls this full reset. The gate must never clear the two
terminal keys.

- [ ] **Step 4: Build a terminal recovery envelope in the gate**

Add pure helpers that:

1. Validate cached UPX/FLOSS result mappings.
2. Classify each tool as `success`, `non_applicable`, or `degraded`.
3. Merge prior limitations without duplicates.
4. Convert each bounded FLOSS record into an `EvidenceFinding` with
   `tool="floss_decode"` and `kind` selected by content only at the later IOC
   stage; recovery records use `kind="metadata"` because they are decoded
   artifacts, not yet classified IOCs.
5. Merge records by the tuple `(tool, detail)` so later loop iterations do not
   duplicate strings.

Use these status and evidence helpers:

```python
def _recovery_status(
    result: object,
    *,
    enabled: bool,
) -> tuple[str, str]:
    if not enabled:
        return "non_applicable", ""
    if not isinstance(result, dict):
        return "degraded", "result_invalid"
    if result.get("degraded") is True or result.get("success") is False:
        code = result.get("error_code")
        return "degraded", code if isinstance(code, str) else "result_invalid"
    if result.get("applicable") is False:
        return "non_applicable", ""
    if result.get("success") is True and result.get("applicable") is True:
        return "success", ""
    return "degraded", "result_invalid"


def _floss_findings(artifact_id: str, result: object) -> list[EvidenceFinding]:
    if not isinstance(result, dict) or result.get("success") is not True:
        return []
    records = result.get("records")
    if not isinstance(records, list):
        return []
    findings: list[EvidenceFinding] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        detail = json.dumps(record, sort_keys=True, separators=(",", ":"))
        findings.append(
            EvidenceFinding(
                artifact_id=artifact_id,
                claim=f"FLOSS recovered a {record.get('type', 'decoded')} string.",
                tool="floss_decode",
                confidence=1.0,
                detail=detail,
                kind=FindingKind.METADATA,
            )
        )
    return findings


def _merge_recovery_evidence(
    state: Mapping[str, object],
    *,
    artifact_id: str,
    result: object,
    degraded: bool,
) -> EvidenceEnvelope:
    try:
        previous = parse_evidence_envelope(
            state.get(RECOVERY_EVIDENCE_KEY),
            artifact_id=artifact_id,
        )
    except (TypeError, ValueError):
        previous = EvidenceEnvelope(
            artifact_id=artifact_id,
            coverage=EvidenceCoverage(
                status=CoverageStatus.COMPLETE,
                surfaces=[],
                limitations=[],
            ),
            findings=[],
        )
    merged = [*previous.findings, *_floss_findings(artifact_id, result)]
    unique = {
        (finding.tool, finding.detail): finding
        for finding in merged
    }
    limitations = list(previous.coverage.limitations)
    error_code = result.get("error_code") if isinstance(result, dict) else None
    limitation = (
        f"floss:{error_code}"
        if isinstance(error_code, str)
        else "floss:result_invalid"
    )
    if degraded and limitation not in limitations:
        limitations.append(limitation)
    return EvidenceEnvelope(
        artifact_id=artifact_id,
        coverage=EvidenceCoverage(
            status=(
                CoverageStatus.PARTIAL
                if limitations
                else CoverageStatus.COMPLETE
            ),
            surfaces=(
                ["floss_decode"]
                if isinstance(result, dict) and result.get("success") is True
                else []
            ),
            limitations=limitations,
        ),
        findings=list(unique.values())[:MAX_FINDINGS],
    )
```

The gate always writes the merged recovery evidence and iteration count. It
writes the terminal summary only when `exit_loop` is true:

```python
state_delta = {
    RECOVERY_EVIDENCE_KEY: recovery_envelope.model_dump(mode="json"),
    DEOBF_ITERATION_KEY: iteration,
}
if exit_loop:
    state_delta[RECOVERY_SUMMARY_KEY] = {
        "artifact_id": plan.artifact_id,
        "exit_reason": exit_reason,
        "upx": {
            "status": upx_status,
            "changed": upx_changed,
            "error_code": upx_error_code,
        },
        "floss": {
            "status": floss_status,
            "new_count": floss_count,
            "error_code": floss_error_code,
        },
        "limitations": limitations,
    }
```

Use this exact exit precedence:

```python
exit_loop = (
    clean_plan
    or plan.pcode_preferred
    or enabled_degraded
    or no_progress
    or iteration >= 3
)
if not exit_loop:
    exit_reason = ""
elif clean_plan:
    exit_reason = "complete"
elif plan.pcode_preferred:
    exit_reason = "pcode_handoff"
elif enabled_degraded:
    exit_reason = "degraded"
elif no_progress:
    exit_reason = "no_progress"
elif iteration >= 3:
    exit_reason = "iteration_cap"
else:
    raise AssertionError("terminal recovery reason was not classified")
```

Return `EscalationDecision(escalate=exit_loop, state_delta=state_delta)`.

- [ ] **Step 5: Prove a new sample clears terminal authority**

Extend `test_acquire_sample.py` so a fake state begins with both terminal keys,
then assert `acquire_sample` resets them to `None` and resets the iteration to
zero while setting the new canonical artifact.

- [ ] **Step 6: Run recovery and acquisition tests**

Run:

```bash
rtk uv run pytest tests/reverse_engineering/test_deobfuscation_agents.py tests/reverse_engineering/test_acquire_sample.py tests/reverse_engineering/test_floss_deobfuscation_tool.py tests/reverse_engineering/test_upx_deobfuscation_tool.py -q
```

Expected: all tests pass; existing per-iteration cache assertions remain true.

- [ ] **Step 7: Commit durable recovery**

```bash
rtk git add src/reverse_engineering/tools/deobfuscation/state.py src/reverse_engineering/agents/deobf_gate.py src/reverse_engineering/tools/acquire_sample.py tests/reverse_engineering/test_deobfuscation_agents.py tests/reverse_engineering/test_acquire_sample.py
rtk git commit -m "feat: preserve deobfuscation outcomes and evidence"
```

### Task 4: Record artifact-bound Ghidra coverage and reuse preparation

**Files:**

- Create: `src/reverse_engineering/tools/ghidra/coverage.py`
- Modify: `src/reverse_engineering/tools/ghidra/prepare_ghidra.py`
- Modify: `src/reverse_engineering/tools/ghidra/toolset.py`
- Modify: `src/reverse_engineering/tools/acquire_sample.py`
- Modify: `tests/reverse_engineering/test_ghidra_toolset.py`
- Create: `tests/reverse_engineering/test_ghidra_coverage.py`
- Modify: `tests/reverse_engineering/test_acquire_sample.py`

- [ ] **Step 1: Write coverage-state tests**

Create `tests/reverse_engineering/test_ghidra_coverage.py`:

```python
from reverse_engineering.tools.ghidra.coverage import (
    DEEP_COVERAGE_KEY,
    read_deep_coverage,
    record_ghidra_result,
    record_prepared,
)
from reverse_engineering.tools.deobfuscation.state import CURRENT_ARTIFACT_KEY


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
    assert state[DEEP_COVERAGE_KEY]["artifact_id"] == ARTIFACT
```

- [ ] **Step 2: Run coverage tests and verify red**

Run:

```bash
rtk uv run pytest tests/reverse_engineering/test_ghidra_coverage.py -q
```

Expected: collection fails because `ghidra.coverage` does not exist.

- [ ] **Step 3: Implement coverage facts**

Create `coverage.py` with a frozen `DeepCoverage` Pydantic model and these
rules:

```python
from __future__ import annotations

import json

from pydantic import BaseModel, ConfigDict

from reverse_engineering.tools.deobfuscation.state import CURRENT_ARTIFACT_KEY

DEEP_COVERAGE_KEY = "deep:coverage"
DEEP_MISSING_PROMPT_KEY = "deep_missing_surfaces"
DEEP_ITERATION_KEY = "deep:iteration"
DEEP_EVIDENCE_KEY = "deep_evidence_json"

_SEMANTIC_TOOLS = frozenset({"ghidra_search_decompiled"})
_TARGET_TOOLS = frozenset({"ghidra_decompile", "ghidra_pcode"})


class DeepCoverage(BaseModel):
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
    getter = getattr(state, "get", None)
    raw = getter(DEEP_COVERAGE_KEY) if callable(getter) else None
    coverage = DeepCoverage.model_validate(raw)
    if coverage.artifact_id != artifact_id:
        raise ValueError("deep coverage artifact mismatch")
    return coverage


def record_prepared(state: object, artifact_id: str) -> None:
    getter = getattr(state, "get", None)
    setter = getattr(state, "__setitem__", None)
    if (
        not callable(getter)
        or not callable(setter)
        or getter(CURRENT_ARTIFACT_KEY) != artifact_id
    ):
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
                    current.semantic_search_succeeded
                    or tool_name in _SEMANTIC_TOOLS
                ),
                "target_analysis_succeeded": (
                    current.target_analysis_succeeded
                    or tool_name in _TARGET_TOOLS
                ),
                "surfaces": surfaces,
            }
        ).model_dump(mode="json"),
    )
```

- [ ] **Step 4: Make Ghidra preparation idempotent**

After resolving `case_id` and canonical artifact, check:

```python
existing = _GHIDRA_CASE_STATE.get(case_id)
if (
    existing is not None
    and existing.get("artifact_id") == artifact_id
    and existing.get("pod")
    and existing.get("binary")
):
    record_prepared(tool_context.state, artifact_id)
    return {
        "pod": existing["pod"],
        "binary": existing["binary"],
        "ready": True,
        "artifact_id": artifact_id,
        "reused": True,
    }
```

Store `"artifact_id": artifact_id` in `_GHIDRA_CASE_STATE` after a successful
load and call `record_prepared`. The first successful response includes
`"reused": False`.

- [ ] **Step 5: Record every successful Ghidra result**

After the wrapper constructs its public response:

```python
response = {"success": True, "output": stdout}
record_ghidra_result(
    tool_context.state,
    artifact_id=case_state["artifact_id"],
    tool_name=spec.name,
    response=response,
)
return response
```

Do not record degraded, empty, mismatched, or exception responses.

- [ ] **Step 6: Give deep analysis its own sample-reset contract**

Add this function to `ghidra/coverage.py`:

```python
def reset_deep_analysis_state(state: object) -> None:
    setter = getattr(state, "__setitem__", None)
    if not callable(setter):
        return
    setter(DEEP_COVERAGE_KEY, None)
    setter(DEEP_MISSING_PROMPT_KEY, "")
    setter(DEEP_ITERATION_KEY, 0)
    setter(DEEP_EVIDENCE_KEY, None)
```

In `acquire_sample`, call `reset_deep_analysis_state` immediately after
`reset_deobfuscation_state`. Extend `test_acquire_sample.py` to seed all four
keys and assert acquisition clears them. Deobfuscation does not import or own
Ghidra state.

- [ ] **Step 7: Add preparation reuse tests**

Call `prepare_ghidra` twice with the same context/artifact and assert:

```python
assert first["reused"] is False
assert second["reused"] is True
assert len(executor.claimed) == 1
assert sum(call[1] == "load" for call in exec_calls) == 1
```

Also assert a different canonical artifact does not reuse the cached project.

- [ ] **Step 8: Run focused Ghidra tests**

Run:

```bash
rtk uv run pytest tests/reverse_engineering/test_ghidra_coverage.py tests/reverse_engineering/test_ghidra_toolset.py tests/reverse_engineering/test_acquire_sample.py -q
```

Expected: all tests pass, including the pre-existing 600/660-second timeout
contract.

- [ ] **Step 9: Commit Ghidra coverage**

```bash
rtk git add src/reverse_engineering/tools/ghidra/coverage.py src/reverse_engineering/tools/ghidra/prepare_ghidra.py src/reverse_engineering/tools/ghidra/toolset.py src/reverse_engineering/tools/acquire_sample.py tests/reverse_engineering/test_ghidra_coverage.py tests/reverse_engineering/test_ghidra_toolset.py tests/reverse_engineering/test_acquire_sample.py
rtk git commit -m "feat: enforce artifact-bound Ghidra coverage"
```

### Task 5: Replace prompt-only deep decompilation with a bounded worker/gate loop

**Files:**

- Modify: `src/reverse_engineering/agents/deep_decompile.py`
- Create: `src/reverse_engineering/agents/deep_analysis_gate.py`
- Create: `src/reverse_engineering/agents/deep_analysis.py`
- Modify: `src/reverse_engineering/__init__.py`
- Modify: `src/malware_analyst/composition.py`
- Modify: `tests/reverse_engineering/test_deep_decompile.py`
- Create: `tests/reverse_engineering/test_deep_analysis_gate.py`
- Modify: `tests/malware_analyst/test_malware_analyst_composition.py`

- [ ] **Step 1: Write deep-gate tests**

Create `tests/reverse_engineering/test_deep_analysis_gate.py`:

```python
from reverse_engineering.agents.deep_analysis_gate import evaluate_deep_analysis_gate
from reverse_engineering.tools.ghidra.coverage import (
    DEEP_COVERAGE_KEY,
    DEEP_EVIDENCE_KEY,
    DEEP_ITERATION_KEY,
    DEEP_MISSING_PROMPT_KEY,
)
from reverse_engineering.tools.deobfuscation.state import CURRENT_ARTIFACT_KEY


ARTIFACT = "a" * 64


def _state(*, prepared: bool, search: bool, target: bool, iteration: int = 0):
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
    decision = evaluate_deep_analysis_gate(
        _state(prepared=True, search=False, target=False)
    )
    assert decision.escalate is False
    assert decision.state_delta[DEEP_MISSING_PROMPT_KEY] == (
        "semantic_search,target_decompile_or_pcode"
    )


def test_search_and_target_analysis_complete_the_loop() -> None:
    decision = evaluate_deep_analysis_gate(
        _state(prepared=True, search=True, target=True)
    )
    assert decision.escalate is True
    assert decision.state_delta[DEEP_EVIDENCE_KEY]["coverage"]["status"] == "complete"


def test_cap_exhaustion_preserves_findings_and_adds_limitation() -> None:
    state = _state(prepared=True, search=True, target=False, iteration=2)
    state[DEEP_EVIDENCE_KEY]["findings"] = [{
        "artifact_id": ARTIFACT,
        "claim": "The binary is PE32+.",
        "tool": "ghidra_metadata",
        "confidence": 0.9,
        "detail": "format pe64",
        "kind": "metadata",
    }]

    decision = evaluate_deep_analysis_gate(state)

    assert decision.escalate is True
    envelope = decision.state_delta[DEEP_EVIDENCE_KEY]
    assert envelope["findings"]
    assert "deep:analysis_incomplete" in envelope["coverage"]["limitations"]
```

- [ ] **Step 2: Run gate tests and verify red**

Run:

```bash
rtk uv run pytest tests/reverse_engineering/test_deep_analysis_gate.py -q
```

Expected: collection fails because the gate module does not exist.

- [ ] **Step 3: Implement the deterministic gate**

Create `deep_analysis_gate.py`. `evaluate_deep_analysis_gate`:

1. Reads the canonical artifact and strict coverage model.
2. Increments `DEEP_ITERATION_KEY`.
3. Computes missing predicates in the fixed order
   `prepared`, `semantic_search`, `target_decompile_or_pcode`.
4. Completes only when none are missing.
5. At iteration three, preserves valid findings, changes coverage to
   `partial` or `failed`, and appends `deep:analysis_incomplete`.
6. On malformed or stale coverage, emits failed coverage with
   `deep:coverage_invalid`.

Implement the decision body as:

```python
MAX_DEEP_ITERATIONS = 3


def evaluate_deep_analysis_gate(state: Mapping[str, object]) -> EscalationDecision:
    artifact_id = state.get(CURRENT_ARTIFACT_KEY)
    if not isinstance(artifact_id, str):
        return EscalationDecision(
            escalate=True,
            state_delta={
                DEEP_MISSING_PROMPT_KEY: "",
                "deep:gate_error": "canonical_artifact_invalid",
            },
        )

    raw_iteration = state.get(DEEP_ITERATION_KEY, 0)
    iteration = (
        raw_iteration + 1
        if isinstance(raw_iteration, int) and not isinstance(raw_iteration, bool)
        else MAX_DEEP_ITERATIONS
    )
    try:
        coverage = read_deep_coverage(state, artifact_id)
        missing = []
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
                state.get(DEEP_EVIDENCE_KEY),
                artifact_id=artifact_id,
            )
        except (TypeError, ValueError):
            envelope = failed_evidence_envelope(
                artifact_id=artifact_id,
                stage="deep",
                code="evidence_envelope_invalid",
            )
        limitations = list(envelope.coverage.limitations)
        if not complete and "deep:analysis_incomplete" not in limitations:
            limitations.append("deep:analysis_incomplete")
        status = (
            CoverageStatus.COMPLETE
            if complete
            else (
                CoverageStatus.PARTIAL
                if envelope.findings
                else CoverageStatus.FAILED
            )
        )
        surfaces = coverage.surfaces if coverage is not None else []
        state_delta[DEEP_EVIDENCE_KEY] = envelope.model_copy(
            update={
                "coverage": EvidenceCoverage(
                    status=status,
                    surfaces=surfaces,
                    limitations=limitations,
                )
            }
        ).model_dump(mode="json")
    return EscalationDecision(
        escalate=complete or exhausted,
        state_delta=state_delta,
    )
```

Expose:

```python
DEEP_ANALYSIS_GATE_DESCRIPTOR = AgentDescriptor(
    id="deep_analysis_gate",
    name="deep_analysis_gate",
    description="Enforce bounded semantic and targeted Ghidra coverage.",
    prompt_id=None,
    factory=partial(build_escalation_gate, evaluator=evaluate_deep_analysis_gate),
    kind=AgentKind.DETERMINISTIC,
)
```

- [ ] **Step 4: Convert the existing leaf into the worker**

Rename the descriptor identity while retaining its file:

```python
DEEP_DECOMPILE_WORKER_DESCRIPTOR = AgentDescriptor(
    id="deep_decompile_worker",
    name="deep_decompile_worker",
    description="Model-directed Ghidra worker inside the bounded deep-analysis loop.",
    prompt_id="deep_decompile",
    factory=build_llm_agent,
    runtime_profile_id="re_guarded",
    prompt_loader=load_domain_prompt,
    tool_ids=(
        "prepare_ghidra",
        "ghidra_metadata",
        "ghidra_list_functions",
        "ghidra_decompile",
        "ghidra_search_decompiled",
        "ghidra_basic_blocks",
        "ghidra_xrefs_to",
        "ghidra_imports",
        "ghidra_strings",
        "ghidra_pcode",
    ),
    output_key=DEEP_EVIDENCE_KEY,
    after_agent_callbacks=(
        evidence_output_callback(output_key=DEEP_EVIDENCE_KEY, stage="deep"),
    ),
)
```

- [ ] **Step 5: Add the capped deep-analysis shell**

Create `deep_analysis.py`:

```python
from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_loop_agent

DEEP_ANALYSIS_DESCRIPTOR = AgentDescriptor(
    id="deep_analysis",
    name="deep_analysis",
    description="Bounded Ghidra worker and deterministic completion gate.",
    prompt_id=None,
    factory=build_loop_agent,
    sub_agent_ids=("deep_decompile_worker", "deep_analysis_gate"),
    metadata={"max_iterations": 3},
)
```

Register and export the shell, worker, and gate. The malware root references
only `deep_analysis`.

- [ ] **Step 6: Update the worker prompt**

Add near the top of `deep_decompile.md`:

```text
Read `{deep_missing_surfaces?}` before selecting tools. An empty value means
this is the first bounded pass. Otherwise it is the exact deterministic list
of unsatisfied coverage surfaces. You must attempt every named missing surface
in this pass. Metadata, imports, strings, and function inventories never
satisfy semantic-search or targeted-code coverage.
```

Replace free-form `FINDING` output instructions with the exact
`EvidenceEnvelope` JSON shape from the design and require JSON only.

- [ ] **Step 7: Lock the composition shape**

Update composition tests:

```python
deep = next(agent for agent in root.sub_agents if agent.name == "deep_analysis")
assert isinstance(deep, LoopAgent)
assert deep.max_iterations == 3
assert [agent.name for agent in deep.sub_agents] == [
    "deep_decompile_worker",
    "deep_analysis_gate",
]
assert not isinstance(deep.sub_agents[1], LlmAgent)
```

- [ ] **Step 8: Run deep-analysis tests**

Run:

```bash
rtk uv run pytest tests/reverse_engineering/test_deep_analysis_gate.py tests/reverse_engineering/test_deep_decompile.py tests/malware_analyst/test_malware_analyst_composition.py -q
```

Expected: all tests pass and metadata-only state cannot terminate the loop.

- [ ] **Step 9: Commit the bounded deep stage**

```bash
rtk git add src/reverse_engineering/agents/deep_decompile.py src/reverse_engineering/agents/deep_analysis_gate.py src/reverse_engineering/agents/deep_analysis.py src/reverse_engineering/prompts/deep_decompile.md src/reverse_engineering/__init__.py src/malware_analyst/composition.py tests/reverse_engineering/test_deep_decompile.py tests/reverse_engineering/test_deep_analysis_gate.py tests/malware_analyst/test_malware_analyst_composition.py
rtk git commit -m "feat: enforce bounded deep analysis completion"
```

### Task 6: Give every evidence stage an explicit validated output

**Files:**

- Modify: `src/reverse_engineering/profiles.py`
- Modify: `src/reverse_engineering/composition.py`
- Modify: `src/reverse_engineering/agents/triage_recon.py`
- Modify: `src/malware_analyst/agents/host_indicators.py`
- Modify: `src/malware_analyst/agents/network_indicators.py`
- Modify: `src/malware_analyst/agents/behavior_characterization.py`
- Modify: `src/malware_analyst/agents/attack_mapper.py`
- Modify: `src/reverse_engineering/prompts/triage_recon.md`
- Modify: `src/malware_analyst/prompts/host_indicators.md`
- Modify: `src/malware_analyst/prompts/network_indicators.md`
- Modify: `src/malware_analyst/prompts/behavior_characterization.md`
- Modify: `src/malware_analyst/prompts/attack_mapper.md`
- Create: `tests/malware_analyst/test_evidence_handoff.py`
- Modify: `tests/reverse_engineering/test_re_guarded_profile.py`

- [ ] **Step 1: Write descriptor and prompt-contract tests**

Create `test_evidence_handoff.py`:

```python
from malware_analyst.agents.attack_mapper import ATTACK_MAPPER_DESCRIPTOR
from malware_analyst.agents.behavior_characterization import (
    BEHAVIOR_CHARACTERIZATION_DESCRIPTOR,
)
from malware_analyst.agents.host_indicators import HOST_INDICATORS_DESCRIPTOR
from malware_analyst.agents.network_indicators import NETWORK_INDICATORS_DESCRIPTOR
from malware_analyst.prompts.loader import load_malware_prompt
from reverse_engineering.agents.triage_recon import TRIAGE_RECON_DESCRIPTOR


def test_every_evidence_producer_has_a_named_output() -> None:
    assert TRIAGE_RECON_DESCRIPTOR.output_key == "triage_evidence_json"
    assert HOST_INDICATORS_DESCRIPTOR.output_key == "host_ioc_evidence_json"
    assert NETWORK_INDICATORS_DESCRIPTOR.output_key == "network_ioc_evidence_json"
    assert BEHAVIOR_CHARACTERIZATION_DESCRIPTOR.output_key == "behavior_evidence_json"
    assert ATTACK_MAPPER_DESCRIPTOR.output_key == "attack_evidence_json"


def test_ioc_prompts_name_all_authoritative_inputs() -> None:
    for prompt_id in ("host_indicators", "network_indicators"):
        text = load_malware_prompt(prompt_id)
        assert "{triage_evidence_json?}" in text
        assert "{recovery_summary_json?}" in text
        assert "{recovery_evidence_json?}" in text
        assert "{deep_evidence_json?}" in text


def test_behavior_and_attack_prompts_use_only_named_inputs() -> None:
    behavior = load_malware_prompt("behavior_characterization")
    assert "{deep_evidence_json?}" in behavior
    assert "{host_ioc_evidence_json?}" in behavior
    assert "{network_ioc_evidence_json?}" in behavior
    attack = load_malware_prompt("attack_mapper")
    assert "{behavior_evidence_json?}" in attack
```

- [ ] **Step 2: Run handoff tests and verify red**

Run:

```bash
rtk uv run pytest tests/malware_analyst/test_evidence_handoff.py -q
```

Expected: descriptor output-key and prompt-alias assertions fail.

- [ ] **Step 3: Add an isolated evidence-consumer profile**

In `profiles.py`:

```python
from arema.registry.descriptors import ContextMode

EVIDENCE_ISOLATED_PROFILE = replace(
    RuntimeProfile.safe_default(),
    id="evidence_isolated",
    context_mode=ContextMode.ISOLATED,
)
```

Register it in `register_re_infrastructure`. Host, network, behavior, ATT&CK,
critic, and report agents use this profile, guaranteeing conversation history
cannot become authoritative evidence.

- [ ] **Step 4: Assign output keys and normalizers**

Use these exact keys:

```python
TRIAGE_EVIDENCE_KEY = "triage_evidence_json"
HOST_IOC_EVIDENCE_KEY = "host_ioc_evidence_json"
NETWORK_IOC_EVIDENCE_KEY = "network_ioc_evidence_json"
BEHAVIOR_EVIDENCE_KEY = "behavior_evidence_json"
ATTACK_EVIDENCE_KEY = "attack_evidence_json"
```

Each descriptor sets its key and one stage-specific
`evidence_output_callback`. Triage keeps `re_guarded`; the four no-tool
consumers use `evidence_isolated`.

- [ ] **Step 5: Replace ambient-history prompt contracts**

Each producer must return only:

```json
{
  "artifact_id": "<canonical lowercase sha256>",
  "coverage": {
    "status": "complete",
    "surfaces": ["exact upstream tool or stage names examined"],
    "limitations": []
  },
  "findings": [
    {
      "artifact_id": "<same sha256>",
      "claim": "bounded evidence-backed claim",
      "tool": "original analysis tool",
      "confidence": 0.8,
      "detail": "bounded supporting excerpt",
      "kind": "metadata"
    }
  ]
}
```

Add the exact state aliases tested in Step 1. State that prior messages are
non-authoritative and that an unavailable or invalid input lowers coverage and
adds a limitation rather than being reconstructed from history.

For triage, encode the exact deobfuscation baseline as one metadata finding:

```json
{
  "claim": "Exact deobfuscation baseline",
  "tool": "show_info",
  "confidence": 1.0,
  "detail": "{\"size\":225792,\"function_count\":725,\"import_count\":41,\"string_count\":167,\"section_count\":8}",
  "kind": "metadata"
}
```

The classifier prompt reads that canonical triage alias and requires all five
integer fields; it fails closed if the finding is missing or malformed.

- [ ] **Step 6: Enforce behavior and ATT&CK evidence semantics**

Add these exact rules:

```text
A behavior finding requires a source-to-sink path in its own detail. Imports
alone may produce a lower-confidence capability primitive, but the claim must
say "capability primitive" and must not say the behavior was observed.

ATT&CK consumes only `{behavior_evidence_json?}`. Skip a mapping when the
behavior detail does not support the technique. A capability primitive may be
mapped only when the technique is discovery of that same primitive.
```

- [ ] **Step 7: Run profile, descriptor, and prompt tests**

Run:

```bash
rtk uv run pytest tests/malware_analyst/test_evidence_handoff.py tests/reverse_engineering/test_re_guarded_profile.py tests/reverse_engineering/test_domain_prompt_loader.py tests/malware_analyst/test_malware_prompt_loader.py -q
```

Expected: all tests pass.

- [ ] **Step 8: Commit explicit producer outputs**

```bash
rtk git add src/reverse_engineering/profiles.py src/reverse_engineering/composition.py src/reverse_engineering/agents/triage_recon.py src/reverse_engineering/prompts/triage_recon.md src/reverse_engineering/prompts/deobf_classify.md src/malware_analyst/agents/host_indicators.py src/malware_analyst/agents/network_indicators.py src/malware_analyst/agents/behavior_characterization.py src/malware_analyst/agents/attack_mapper.py src/malware_analyst/prompts/host_indicators.md src/malware_analyst/prompts/network_indicators.md src/malware_analyst/prompts/behavior_characterization.md src/malware_analyst/prompts/attack_mapper.md tests/malware_analyst/test_evidence_handoff.py tests/reverse_engineering/test_re_guarded_profile.py
rtk git commit -m "feat: make stage evidence handoff explicit"
```

### Task 7: Reorder synthesis and enforce network coverage

**Files:**

- Create: `src/malware_analyst/evidence.py`
- Modify: `src/malware_analyst/agents/network_indicators.py`
- Modify: `src/malware_analyst/agents/malware_analyst.py`
- Modify: `tests/malware_analyst/test_ioc_lenses.py`
- Modify: `tests/malware_analyst/test_malware_analyst_composition.py`

- [ ] **Step 1: Write order and negative-coverage tests**

Lock the root order:

```python
assert [agent.name for agent in root.sub_agents] == [
    "sample_intake",
    "triage_recon",
    "deobfuscation",
    "deep_analysis",
    "ioc_extraction",
    "behavior_characterization",
    "attack_mapper",
    "evidence_critic",
    "malware_report_generator",
]
```

Add network normalization tests:

```python
from types import SimpleNamespace

from malware_analyst.evidence import enforce_network_coverage
from reverse_engineering.evidence_envelope import EvidenceEnvelope


ARTIFACT = "a" * 64


def _network_state(
    *,
    recovery_status: str,
    deep_status: str,
    network_findings: list[dict[str, object]],
) -> dict[str, object]:
    recovery_surfaces = ["floss_decode"] if recovery_status == "success" else []
    deep_surfaces = (
        ["ghidra_search_decompiled", "ghidra_decompile"]
        if deep_status == "complete"
        else []
    )
    return {
        "deobf:current_artifact_id": ARTIFACT,
        "recovery_summary_json": {
            "artifact_id": ARTIFACT,
            "exit_reason": "complete" if recovery_status == "success" else "degraded",
            "upx": {"status": "non_applicable", "changed": False, "error_code": ""},
            "floss": {
                "status": recovery_status,
                "new_count": 0,
                "error_code": "" if recovery_status == "success" else "sandbox_unavailable",
            },
            "limitations": (
                [] if recovery_status == "success" else ["floss:sandbox_unavailable"]
            ),
        },
        "recovery_evidence_json": {
            "artifact_id": ARTIFACT,
            "coverage": {
                "status": "complete" if recovery_status == "success" else "failed",
                "surfaces": recovery_surfaces,
                "limitations": [],
            },
            "findings": [],
        },
        "deep_evidence_json": {
            "artifact_id": ARTIFACT,
            "coverage": {
                "status": deep_status,
                "surfaces": deep_surfaces,
                "limitations": [] if deep_status == "complete" else ["deep:analysis_incomplete"],
            },
            "findings": [],
        },
        "network_ioc_evidence_json": {
            "artifact_id": ARTIFACT,
            "coverage": {
                "status": "complete",
                "surfaces": [],
                "limitations": [],
            },
            "findings": network_findings,
        },
    }


def test_failed_floss_and_incomplete_deep_analysis_cannot_mean_no_iocs() -> None:
    state = _network_state(
        recovery_status="degraded",
        deep_status="partial",
        network_findings=[],
    )

    enforce_network_coverage(SimpleNamespace(state=state))

    envelope = EvidenceEnvelope.model_validate(state["network_ioc_evidence_json"])
    assert envelope.coverage.status == "partial"
    assert "network:not_determined" in envelope.coverage.limitations


def test_completed_network_surface_allows_zero_match_conclusion() -> None:
    state = _network_state(
        recovery_status="success",
        deep_status="complete",
        network_findings=[],
    )

    enforce_network_coverage(SimpleNamespace(state=state))

    envelope = EvidenceEnvelope.model_validate(state["network_ioc_evidence_json"])
    assert envelope.coverage.status == "complete"
    assert "network:not_determined" not in envelope.coverage.limitations
```

- [ ] **Step 2: Run the tests and verify red**

Run:

```bash
rtk uv run pytest tests/malware_analyst/test_ioc_lenses.py tests/malware_analyst/test_malware_analyst_composition.py -q
```

Expected: order assertion and network enforcement imports fail.

- [ ] **Step 3: Implement deterministic network coverage**

Create `malware_analyst/evidence.py`. Completed network coverage is true when
at least one of these is present:

```python
NETWORK_RELEVANT_SURFACES = frozenset(
    {
        "floss_decode",
        "ghidra_strings",
        "ghidra_search_decompiled",
        "ghidra_decompile",
        "ghidra_pcode",
    }
)
```

`enforce_network_coverage(callback_context)` first normalizes the model output,
then checks recovery and deep envelopes. When no network finding exists and no
completed relevant surface exists, replace the network coverage with:

```python
EvidenceCoverage(
    status=CoverageStatus.PARTIAL,
    surfaces=sorted(observed_surfaces),
    limitations=sorted({*limitations, "network:not_determined"}),
)
```

When a network IOC exists, retain it even under partial coverage. Never change
the exact IOC value, tool, artifact ID, or detail.

Use this implementation:

```python
def enforce_network_coverage(callback_context: CallbackContext) -> None:
    normalize_evidence_output(
        callback_context,
        output_key=NETWORK_IOC_EVIDENCE_KEY,
        stage="network",
    )
    state = callback_context.state
    artifact_id = state.get(CURRENT_ARTIFACT_KEY)
    if not isinstance(artifact_id, str):
        return
    network = parse_evidence_envelope(
        state.get(NETWORK_IOC_EVIDENCE_KEY),
        artifact_id=artifact_id,
    )
    upstream = []
    for key in (RECOVERY_EVIDENCE_KEY, DEEP_EVIDENCE_KEY):
        try:
            upstream.append(
                parse_evidence_envelope(state.get(key), artifact_id=artifact_id)
            )
        except (TypeError, ValueError):
            continue
    observed_surfaces = {
        surface
        for envelope in upstream
        for surface in envelope.coverage.surfaces
        if surface in NETWORK_RELEVANT_SURFACES
    }
    completed_surface = any(
        envelope.coverage.status is CoverageStatus.COMPLETE
        and any(
            surface in NETWORK_RELEVANT_SURFACES
            for surface in envelope.coverage.surfaces
        )
        for envelope in upstream
    )
    has_network_ioc = any(
        finding.kind is FindingKind.NETWORK_IOC
        for finding in network.findings
    )
    if has_network_ioc or completed_surface:
        return
    limitations = sorted(
        {
            *network.coverage.limitations,
            *(limitation for envelope in upstream for limitation in envelope.coverage.limitations),
            "network:not_determined",
        }
    )
    state[NETWORK_IOC_EVIDENCE_KEY] = network.model_copy(
        update={
            "coverage": EvidenceCoverage(
                status=CoverageStatus.PARTIAL,
                surfaces=sorted(observed_surfaces)[:MAX_SURFACES],
                limitations=limitations[:MAX_LIMITATIONS],
            )
        }
    ).model_dump(mode="json")
```

- [ ] **Step 4: Attach the specialized callback**

The network descriptor uses:

```python
after_agent_callbacks=(normalize_and_enforce_network_output,)
```

The callback performs generic envelope normalization first and coverage
enforcement second, before checkpointing.

- [ ] **Step 5: Reorder the malware spine**

Move `deep_analysis` before `ioc_extraction`. Update the module description to
say nine stages and name the producer-before-consumer invariant.

- [ ] **Step 6: Run IOC and composition tests**

Run:

```bash
rtk uv run pytest tests/malware_analyst/test_ioc_lenses.py tests/malware_analyst/test_malware_analyst_composition.py tests/malware_analyst/test_behavior_lenses.py -q
```

Expected: all tests pass and the no-IOC result is coverage-sensitive.

- [ ] **Step 7: Commit ordering and coverage**

```bash
rtk git add src/malware_analyst/evidence.py src/malware_analyst/agents/network_indicators.py src/malware_analyst/agents/malware_analyst.py tests/malware_analyst/test_ioc_lenses.py tests/malware_analyst/test_malware_analyst_composition.py
rtk git commit -m "fix: run IOC synthesis after deep evidence"
```

### Task 8: Expand critic scope and make report language coverage-aware

**Files:**

- Modify: `src/reverse_engineering/evidence_envelope.py`
- Modify: `src/reverse_engineering/agents/evidence_output.py`
- Modify: `src/reverse_engineering/agents/evidence_critic.py`
- Modify: `src/reverse_engineering/prompts/evidence_critic.md`
- Modify: `src/malware_analyst/agents/malware_report_generator.py`
- Modify: `src/malware_analyst/prompts/malware_report_generator.md`
- Modify: `tests/reverse_engineering/test_evidence_critic.py`
- Modify: `tests/malware_analyst/test_report_lens.py`

- [ ] **Step 1: Write critic-schema and report-language tests**

Add a strict critic result:

```python
class RejectedFinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    source_stage: str = Field(min_length=1, max_length=64)
    source_index: int = Field(ge=0, le=MAX_FINDINGS - 1)
    reason: str = Field(min_length=1, max_length=500)


class CriticEnvelope(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    artifact_id: str
    coverage: EvidenceCoverage
    accepted: list[EvidenceFinding] = Field(max_length=MAX_FINDINGS)
    qualified: list[EvidenceFinding] = Field(max_length=MAX_FINDINGS)
    rejected: list[RejectedFinding] = Field(max_length=MAX_FINDINGS)

    @model_validator(mode="after")
    def validate_artifact_authority(self) -> CriticEnvelope:
        if _ARTIFACT_ID.fullmatch(self.artifact_id) is None:
            raise ValueError("artifact_id must be a lowercase SHA-256")
        findings = [*self.accepted, *self.qualified]
        if any(finding.artifact_id != self.artifact_id for finding in findings):
            raise ValueError("critic finding artifact mismatch")
        return self
```

Test that cross-artifact accepted/qualified findings are rejected, upstream
limitations are retained, and invalid critic output becomes a failed critic
envelope rather than disappearing.

Add prompt tests:

```python
def test_critic_names_every_upstream_envelope() -> None:
    text = load_domain_prompt("evidence_critic")
    for alias in (
        "{triage_evidence_json?}",
        "{recovery_summary_json?}",
        "{recovery_evidence_json?}",
        "{deep_evidence_json?}",
        "{host_ioc_evidence_json?}",
        "{network_ioc_evidence_json?}",
        "{behavior_evidence_json?}",
        "{attack_evidence_json?}",
    ):
        assert alias in text


def test_report_distinguishes_absence_from_incomplete_coverage() -> None:
    text = load_malware_prompt("malware_report_generator")
    assert "No indicators were found by the completed static-analysis surfaces." in text
    assert "Indicators were not determined because" in text
    assert "{validated_evidence_json?}" in text
```

- [ ] **Step 2: Run critic/report tests and verify red**

Run:

```bash
rtk uv run pytest tests/reverse_engineering/test_evidence_critic.py tests/malware_analyst/test_report_lens.py -q
```

Expected: missing schema, aliases, and coverage-language assertions fail.

- [ ] **Step 3: Implement critic parsing and normalization**

Add `parse_critic_envelope` and `failed_critic_envelope` beside the evidence
parser. Enforce one canonical artifact across accepted and qualified findings.
The failure form is:

```python
def parse_critic_envelope(raw: object, *, artifact_id: str) -> CriticEnvelope:
    if isinstance(raw, str):
        raw = json.loads(raw)
    envelope = CriticEnvelope.model_validate(raw)
    if envelope.artifact_id != artifact_id:
        raise ValueError("critic artifact does not match canonical artifact")
    return envelope


def failed_critic_envelope(*, artifact_id: str) -> CriticEnvelope:
    return CriticEnvelope(
        artifact_id=artifact_id,
        coverage=EvidenceCoverage(
            status=CoverageStatus.FAILED,
            surfaces=[],
            limitations=["critic:evidence_envelope_invalid"],
        ),
        accepted=[],
        qualified=[],
        rejected=[],
    )
```

Add a critic-specific after-agent callback that parses
`validated_evidence_json` and deterministically merges upstream coverage:

```python
UPSTREAM_EVIDENCE_KEYS = (
    "triage_evidence_json",
    "recovery_evidence_json",
    "deep_evidence_json",
    "host_ioc_evidence_json",
    "network_ioc_evidence_json",
    "behavior_evidence_json",
    "attack_evidence_json",
)


def normalize_critic_output(callback_context: CallbackContext) -> None:
    state = callback_context.state
    artifact_id = state.get(CURRENT_ARTIFACT_KEY)
    if not isinstance(artifact_id, str):
        return
    try:
        critic = parse_critic_envelope(
            state.get(VALIDATED_EVIDENCE_KEY),
            artifact_id=artifact_id,
        )
    except (TypeError, ValueError):
        critic = failed_critic_envelope(artifact_id=artifact_id)

    limitations = set(critic.coverage.limitations)
    surfaces = set(critic.coverage.surfaces)
    upstream_failed = False
    for key in UPSTREAM_EVIDENCE_KEYS:
        try:
            envelope = parse_evidence_envelope(
                state.get(key),
                artifact_id=artifact_id,
            )
        except (TypeError, ValueError):
            limitations.add(f"critic:{key}:invalid")
            upstream_failed = True
            continue
        limitations.update(envelope.coverage.limitations)
        surfaces.update(envelope.coverage.surfaces)
        upstream_failed = (
            upstream_failed
            or envelope.coverage.status is not CoverageStatus.COMPLETE
        )
    recovery_summary = state.get(RECOVERY_SUMMARY_KEY)
    if isinstance(recovery_summary, dict):
        recovery_limitations = recovery_summary.get("limitations", [])
        if isinstance(recovery_limitations, list):
            limitations.update(
                item for item in recovery_limitations if isinstance(item, str)
            )

    findings = [*critic.accepted, *critic.qualified]
    status = critic.coverage.status
    if upstream_failed or limitations:
        status = CoverageStatus.PARTIAL if findings else CoverageStatus.FAILED
    state[VALIDATED_EVIDENCE_KEY] = critic.model_copy(
        update={
            "coverage": EvidenceCoverage(
                status=status,
                surfaces=sorted(surfaces)[:MAX_SURFACES],
                limitations=sorted(limitations)[:MAX_LIMITATIONS],
            )
        }
    ).model_dump(mode="json")
```

- [ ] **Step 4: Update the critic contract**

The critic descriptor uses `output_key="validated_evidence_json"`,
`evidence_isolated`, and the critic normalizer.

Replace the prompt input section with all eight aliases from Step 1. Require
JSON-only `CriticEnvelope` output. Require:

- supported findings in `accepted`;
- overstatements that still have a supported primitive in `qualified`, with
  reduced confidence and explicit wording;
- unsupported entries in `rejected` using source stage and zero-based index;
- every upstream limitation merged into coverage;
- no inference from conversation history.

- [ ] **Step 5: Make the report consume only validated state**

Set the report profile to `evidence_isolated`. Add:

```text
The sole authoritative input is `{validated_evidence_json?}`. Ignore all
conversation history. Render accepted and qualified findings, preserving the
original tool citation and marking qualified claims as qualified.

When network coverage is complete and contains no network IOC, write:
"No indicators were found by the completed static-analysis surfaces."

When network coverage is partial or failed, write:
"Indicators were not determined because <validated limitations>."
```

- [ ] **Step 6: Run critic/report tests**

Run:

```bash
rtk uv run pytest tests/reverse_engineering/test_evidence_critic.py tests/malware_analyst/test_report_lens.py tests/malware_analyst/test_evidence_handoff.py -q
```

Expected: all tests pass.

- [ ] **Step 7: Commit the final evidence contract**

```bash
rtk git add src/reverse_engineering/evidence_envelope.py src/reverse_engineering/agents/evidence_output.py src/reverse_engineering/agents/evidence_critic.py src/reverse_engineering/prompts/evidence_critic.md src/malware_analyst/agents/malware_report_generator.py src/malware_analyst/prompts/malware_report_generator.md tests/reverse_engineering/test_evidence_critic.py tests/malware_analyst/test_report_lens.py
rtk git commit -m "feat: validate complete evidence before reporting"
```

### Task 9: Add the incident regression and architecture documentation

**Files:**

- Create: `tests/malware_analyst/test_analysis_pipeline_regression.py`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/AGENTS_AND_DISCOVERY.md`
- Modify: `docs/CREATING_TOOLS.md`
- Modify: `docs/ARCHITECTURAL_ISSUES.md`

- [ ] **Step 1: Add a hermetic Dev UI-shaped regression**

The test uses a writable fake context with an invocation ID but no pre-seeded
case ID. It runs the identity resolver, recovery-output helper, deep gate,
network coverage enforcement, critic parser, and report input contract against
the known incident-shaped evidence:

```python
from types import SimpleNamespace

from arema.runtime.sessions import SessionKeys, resolve_sandbox_case_id
from malware_analyst.evidence import enforce_network_coverage
from reverse_engineering.agents.deep_analysis_gate import evaluate_deep_analysis_gate
from reverse_engineering.agents.deobf_gate import evaluate_deobf_gate
from reverse_engineering.evidence_envelope import EvidenceEnvelope
from reverse_engineering.tools.deobfuscation.state import (
    CLASSIFICATION_KEY,
    CURRENT_ARTIFACT_KEY,
    FLOSS_CALLED_KEY,
    FLOSS_COUNT_KEY,
    FLOSS_DEGRADED_KEY,
    FLOSS_RESULT_KEY,
    RETRIAGE_SNAPSHOT_KEY,
    UPX_CALLED_KEY,
    UPX_CHANGED_KEY,
    UPX_DEGRADED_KEY,
)
from reverse_engineering.tools.ghidra.coverage import (
    DEEP_COVERAGE_KEY,
    DEEP_EVIDENCE_KEY,
    DEEP_ITERATION_KEY,
    DEEP_MISSING_PROMPT_KEY,
)


ARTIFACT = "a" * 64


def _incident_state() -> dict[str, object]:
    snapshot = {
        "size": 225_792,
        "function_count": 725,
        "import_count": 41,
        "string_count": 167,
        "section_count": 8,
    }
    return {
        CURRENT_ARTIFACT_KEY: ARTIFACT,
        CLASSIFICATION_KEY: {
            "artifact_id": ARTIFACT,
            "deobf_plan": {"upx": False, "floss": True},
            "pcode_preferred": False,
            "obf_class": "unknown",
            "pre_snapshot": snapshot,
        },
        RETRIAGE_SNAPSHOT_KEY: {"artifact_id": ARTIFACT, **snapshot},
        UPX_CALLED_KEY: True,
        UPX_CHANGED_KEY: False,
        UPX_DEGRADED_KEY: False,
        FLOSS_CALLED_KEY: True,
        FLOSS_COUNT_KEY: 0,
        FLOSS_DEGRADED_KEY: False,
        FLOSS_RESULT_KEY: {
            "success": True,
            "applicable": True,
            "degraded": False,
            "source_artifact_id": ARTIFACT,
            "source_size": 225_792,
            "format": "pe",
            "tool_version": "3.1.1",
            "new_count": 0,
            "counts": {"decoded": 1, "stack": 0, "tight": 0},
            "records": [{
                "type": "decoded",
                "string": "https://ethereum-rpc.publicnode.com",
                "encoding": "ASCII",
                "function": "0x140001000",
                "location": "0x140001020",
            }],
            "truncated": False,
        },
        DEEP_ITERATION_KEY: 0,
        DEEP_COVERAGE_KEY: {
            "artifact_id": ARTIFACT,
            "prepared": True,
            "semantic_search_succeeded": True,
            "target_analysis_succeeded": False,
            "surfaces": ["ghidra_search_decompiled"],
        },
        DEEP_EVIDENCE_KEY: {
            "artifact_id": ARTIFACT,
            "coverage": {
                "status": "partial",
                "surfaces": ["ghidra_search_decompiled"],
                "limitations": [],
            },
            "findings": [],
        },
    }


def _network_envelope(value: str) -> dict[str, object]:
    return {
        "artifact_id": ARTIFACT,
        "coverage": {
            "status": "complete",
            "surfaces": ["floss_decode"],
            "limitations": [],
        },
        "findings": [{
            "artifact_id": ARTIFACT,
            "claim": f"Decoded network URL: {value}",
            "tool": "floss_decode",
            "confidence": 0.95,
            "detail": value,
            "kind": "network_ioc",
        }],
    }


def test_dev_ui_shaped_run_preserves_url_and_limitations() -> None:
    context = SimpleNamespace(state=_incident_state(), invocation_id="dev-ui-regression")
    case_id = resolve_sandbox_case_id(context)

    assert case_id == context.state[SessionKeys.SANDBOX_CASE_ID]
    recovery = evaluate_deobf_gate(context.state)
    context.state.update(recovery.state_delta)

    deep = evaluate_deep_analysis_gate(context.state)
    assert deep.escalate is False
    assert "target_decompile_or_pcode" in deep.state_delta[DEEP_MISSING_PROMPT_KEY]

    context.state["network_ioc_evidence_json"] = _network_envelope(
        "https://ethereum-rpc.publicnode.com"
    )
    enforce_network_coverage(context)

    network = EvidenceEnvelope.model_validate(
        context.state["network_ioc_evidence_json"]
    )
    assert network.findings[0].tool == "floss_decode"
    assert "https://ethereum-rpc.publicnode.com" in network.findings[0].detail
    assert context.state["recovery_summary_json"]["limitations"] == []


def test_failed_surfaces_produce_not_determined_instead_of_no_iocs() -> None:
    context = SimpleNamespace(state=_incident_state(), invocation_id="failed-run")
    context.state[FLOSS_COUNT_KEY] = 0
    context.state[FLOSS_DEGRADED_KEY] = True
    context.state[FLOSS_RESULT_KEY] = {
        "success": False,
        "applicable": True,
        "degraded": True,
        "error_code": "sandbox_unavailable",
        "error": "The deobfuscation sandbox is unavailable.",
        "format": "pe",
        "tool_version": "3.1.1",
        "new_count": 0,
        "counts": {"decoded": 0, "stack": 0, "tight": 0},
        "records": [],
        "truncated": False,
        "source_artifact_id": ARTIFACT,
    }
    context.state[DEEP_ITERATION_KEY] = 2
    context.state[DEEP_COVERAGE_KEY] = {
        "artifact_id": ARTIFACT,
        "prepared": True,
        "semantic_search_succeeded": False,
        "target_analysis_succeeded": False,
        "surfaces": ["ghidra_metadata"],
    }
    context.state["network_ioc_evidence_json"] = {
        "artifact_id": ARTIFACT,
        "coverage": {"status": "complete", "surfaces": [], "limitations": []},
        "findings": [],
    }

    recovery = evaluate_deobf_gate(context.state)
    context.state.update(recovery.state_delta)
    deep = evaluate_deep_analysis_gate(context.state)
    context.state.update(deep.state_delta)
    enforce_network_coverage(context)

    network = EvidenceEnvelope.model_validate(
        context.state["network_ioc_evidence_json"]
    )
    assert network.coverage.status == "partial"
    assert "network:not_determined" in network.coverage.limitations
    assert all("no network" not in finding.claim.lower() for finding in network.findings)
```

- [ ] **Step 2: Run the incident regression and verify green**

Run:

```bash
rtk uv run pytest tests/malware_analyst/test_analysis_pipeline_regression.py -q
```

Expected: both incident-shaped paths pass without Kubernetes or a model.

- [ ] **Step 3: Update architecture documentation**

Document these exact invariants:

1. Explicit case ID wins; otherwise invocation ID is hashed and persisted.
2. Every sandbox-backed tool calls the neutral resolver; private production
   defaults are prohibited.
3. Binary execution remains Kubernetes-only.
4. Session state, not conversation history, is the evidence bus.
5. Deep analysis requires preparation, semantic search, and targeted
   decompile/p-code.
6. Negative report language requires completed relevant coverage.
7. Threat-intelligence enrichment remains the next independent,
   out-of-scope slice.

Mark AI-001 through AI-007 as `Implemented` only after their associated test
commands pass. Add the implementing commit hashes beside each status.

- [ ] **Step 4: Run documentation and architecture checks**

Run:

```bash
rtk rg -n "re-mvp" src tests docs/ARCHITECTURE.md docs/AGENTS_AND_DISCOVERY.md docs/CREATING_TOOLS.md
rtk rg -n "conversation history.*authoritative|state.*evidence bus|invocation.*sandbox" docs/ARCHITECTURE.md docs/AGENTS_AND_DISCOVERY.md docs/CREATING_TOOLS.md
rtk git diff --check
```

Expected: the first command finds no production fallback; documentation
commands find the new invariants; diff check is silent.

- [ ] **Step 5: Commit regression and documentation**

```bash
rtk git add tests/malware_analyst/test_analysis_pipeline_regression.py docs/ARCHITECTURE.md docs/AGENTS_AND_DISCOVERY.md docs/CREATING_TOOLS.md docs/ARCHITECTURAL_ISSUES.md
rtk git commit -m "test: lock analysis pipeline incident regression"
```

### Task 10: Verify the full repository and repeat the real-sample smoke test

**Files:**

- Modify only if a verification failure identifies a root defect in a file
  already owned by Tasks 1–9.

- [ ] **Step 1: Run focused architectural suites**

```bash
rtk uv run pytest tests/unit/runtime/test_sessions.py tests/reverse_engineering tests/malware_analyst -q
```

Expected: all tests pass.

- [ ] **Step 2: Run the complete quality gate**

```bash
rtk make check
```

Expected: Ruff, formatting, mypy, architecture tests, and the full pytest suite
all pass.

- [ ] **Step 3: Validate sandbox pools before handling the real sample**

```bash
rtk kubectl get sandboxpool,sandboxclaim,pods -n agent-sandbox-demo
rtk make sandbox-deobfuscation-smoke
```

Expected: Radare2, Ghidra, and deobfuscation pools are ready; UPX and FLOSS
image smoke checks pass. Do not execute, decompress, or inspect malware bytes
on the host.

- [ ] **Step 4: Start ADK Web and run the known sample**

```bash
rtk make adk-web
```

In the Dev UI, analyze the already-ingested artifact
`e440f3fbbd33d569432ddbc45ee7de8a19b1648de898c01329d5f3a404bde96d`.
Keep every binary-analysis operation inside claimed Kubernetes pods.

The run is accepted only when the session evidence shows:

- one invocation-derived case ID shared by all three sandbox pools;
- FLOSS executed or returned a truthful non-applicable result;
- Ghidra performed semantic search and decompile/p-code, or reported a durable
  incomplete limitation;
- `https://ethereum-rpc.publicnode.com` reaches network evidence and the critic
  when recovered by FLOSS or Ghidra;
- recovery/deep limitations survive to the report; and
- the report never says “no network IOCs” under partial or failed coverage.

- [ ] **Step 5: Inspect the session database without executing sample content**

Use the existing session database reader or SQLite query path to confirm the
named state keys are present:

```bash
rtk sqlite3 src/.adk/session.db ".tables"
rtk sqlite3 src/.adk/session.db "select id, app_name, user_id from sessions order by update_time desc limit 5;"
```

Then inspect only the selected session's serialized state/events for:

```text
arema:sandbox_case_id
recovery_summary_json
recovery_evidence_json
deep_evidence_json
host_ioc_evidence_json
network_ioc_evidence_json
behavior_evidence_json
attack_evidence_json
validated_evidence_json
```

Expected: each key is artifact-bound and bounded; no backend diagnostics or raw
malware bytes are present.

- [ ] **Step 6: Review commit scope and working tree**

```bash
rtk git status --short
rtk git log --oneline -10
rtk git diff --check
```

Expected: no accidental files, no generated sandbox output, and only intentional
user edits remain uncommitted.
