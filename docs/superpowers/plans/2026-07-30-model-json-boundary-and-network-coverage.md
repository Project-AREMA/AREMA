# Model→JSON Boundary + Network-Coverage Correctness — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Permanently close the recurring "```json-fenced model output breaks a strict JSON parser" class of bug by establishing a single robust model→JSON boundary and making the misconfiguration that produces it unbuildable; and fix the two independent bugs that suppressed network IOCs (the native-only network-coverage model and the un-rebound triage envelope).

**Architecture:** Untrusted model text becomes structured data through exactly ONE hardened decoder (`loads_model_json`) that tolerates code fences / surrounding prose and repairs minor malformation. Every model-output parse routes through it. The unreliable `output_schema`+tools combination (ADK's documented anti-pattern — the source of fenced, coercion-dropped output) is removed from the three tool-using agents and forbidden at descriptor construction so it can never return. Two separate correctness fixes make the network-coverage verdict honest for .NET samples.

**Tech Stack:** Python 3.14, Google ADK, `json_repair` (already a dependency), Pydantic, pytest.

## Global Constraints

- **No bare `typing.Any` as a function parameter annotation** — use `object`; `dict[str, Any]` is fine.
- **Never `isinstance(state, dict)`** on ADK `CallbackContext.state`/`ToolContext.state` — duck-type on `.get`/`.__setitem__`.
- **Model output is untrusted.** Never log raw model text. The decoder rejects the JSON constants `NaN`/`Infinity`/`-Infinity` (preserve the existing `parse_constant` rejection).
- **`src/arema` must stay domain-neutral** (`tests/architecture/test_neutral_boundaries.py`): do not name a concrete domain tool (`radare2`, `ghidra`, `ilspycmd`, …) in any `src/arema` module. The decoder therefore lives under `src/reverse_engineering`, not `src/arema`.
- **Fail-open evidence:** a parse that still fails after robust decoding must degrade to the existing `failed_evidence_envelope`/coverage-limitation path, never raise into the pipeline.
- **Commit messages** end with: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/reverse_engineering/model_json.py` (create) | The single robust model→JSON boundary: `loads_model_json()` (fence/prose strip → strict `json.loads` w/ constant rejection → `json_repair` fallback). |
| `src/reverse_engineering/evidence_envelope.py` (modify) | `parse_evidence_envelope` / `parse_critic_envelope` (and the third parser at :334) decode via `loads_model_json` instead of bare `json.loads`. |
| `src/reverse_engineering/agents/deobf_gate.py` (modify) | `_parse_snapshot` / `_parse_current_snapshot` decode via `loads_model_json`. |
| `src/reverse_engineering/agents/dotnet_decompile.py`, `deep_decompile.py`, `triage_recon.py` (modify) | Drop `output_schema` (they use tools; keep `output_key` + after-agent normalizer). |
| `src/arema/registry/descriptors.py` (modify) | `AgentDescriptor.__post_init__` forbids `output_schema` together with `tool_ids`/`mcp_server_ids`. |
| `src/malware_analyst/evidence.py` (modify) | `enforce_network_coverage`: add .NET decompile surfaces to `NETWORK_RELEVANT_SURFACES`; credit the network envelope's OWN completed coverage, not only upstream. |
| `src/reverse_engineering/agents/evidence_output.py` (modify) | Critic aggregation rebinds a prior-artifact envelope (triage) to the current artifact instead of rejecting it as `:invalid`. |
| `tests/reverse_engineering/test_model_json.py` (create) | Decoder unit tests + the architecture guard test. |
| `tests/…` (modify/create) | Regression tests: fenced envelope/snapshot parse; descriptor invariant; network coverage; triage rebind. |

**Task dependency order is strict:** 1 → 2 → 3 → 4 → 5 → 6, then 7 and 8 (independent of each other, depend on 2). Task 4 (drop `output_schema`) must land before Task 5 (the invariant) or the composition freeze would break.

---

### Task 1: The robust model→JSON boundary decoder

**Files:**
- Create: `src/reverse_engineering/model_json.py`
- Test: `tests/reverse_engineering/test_model_json.py`

**Interfaces:**
- Produces: `loads_model_json(raw: object) -> object` — returns `raw` unchanged if not a `str`; otherwise strips a Markdown code fence / surrounding prose and returns the decoded JSON value. Raises `ValueError` only when the text is unrecoverable even after `json_repair`.

- [ ] **Step 1: Write the failing tests**

Create `tests/reverse_engineering/test_model_json.py`:

```python
"""Unit tests for the single robust model->JSON boundary."""

from __future__ import annotations

import pytest

from reverse_engineering.model_json import loads_model_json


def test_plain_json_object():
    assert loads_model_json('{"a": 1}') == {"a": 1}


def test_strips_json_code_fence():
    assert loads_model_json('```json\n{"a": 1}\n```') == {"a": 1}


def test_strips_bare_code_fence():
    assert loads_model_json('```\n{"a": 1}\n```') == {"a": 1}


def test_strips_fence_with_trailing_prose_whitespace():
    assert loads_model_json('  ```json\n{"a": [1, 2]}\n```  ') == {"a": [1, 2]}


def test_passes_through_already_parsed_mapping():
    obj = {"a": 1}
    assert loads_model_json(obj) is obj


def test_rejects_nan_infinity_constants():
    with pytest.raises(ValueError):
        loads_model_json('{"a": NaN}')
    with pytest.raises(ValueError):
        loads_model_json('```json\n{"a": Infinity}\n```')


def test_repairs_trailing_comma_via_json_repair():
    assert loads_model_json('{"a": 1,}') == {"a": 1}


def test_repairs_fenced_trailing_comma():
    assert loads_model_json('```json\n{"a": 1, "b": 2,}\n```') == {"a": 1, "b": 2}


def test_unrecoverable_text_raises():
    with pytest.raises(ValueError):
        loads_model_json("this is not json at all ~~~")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `rtk uv run pytest tests/reverse_engineering/test_model_json.py -q`
Expected: FAIL — `ModuleNotFoundError: reverse_engineering.model_json`.

- [ ] **Step 3: Implement the decoder**

Create `src/reverse_engineering/model_json.py`:

```python
"""The single robust boundary for turning model-produced text into JSON.

LLMs routinely wrap JSON in Markdown code fences (```json ... ```), add leading
or trailing prose, or emit minor malformations (trailing commas). A strict
``json.loads`` fails on all of these, and because several agents combine tool use
with structured output, their final turn is free-form text -- so fenced output is
the norm, not the exception. This module is the ONE place that knows how model
output actually arrives: strip a code fence, then decode strictly (rejecting the
``NaN``/``Infinity`` JSON constants), and only if that fails fall back to
``json_repair``. Every site that decodes model output MUST use this function;
raw ``json.loads`` on model text is forbidden (enforced by test).
"""

from __future__ import annotations

import json
import re

from json_repair import repair_json

# Matches a whole-string Markdown code fence with an optional ```json info string.
_FENCE_RE = re.compile(r"\A\s*```[^\n`]*\n(?P<body>.*)\n```\s*\Z", re.DOTALL)


def _reject_json_constant(value: str) -> object:
    """Reject ``NaN``/``Infinity``/``-Infinity`` -- never valid, DoS-adjacent."""
    raise ValueError(f"JSON constant {value!r} is not permitted")


def _strip_code_fence(text: str) -> str:
    match = _FENCE_RE.match(text)
    return match.group("body").strip() if match else text.strip()


def loads_model_json(raw: object) -> object:
    """Decode JSON from untrusted model text, tolerating fences and minor malformation.

    Returns ``raw`` unchanged when it is not a ``str`` (an earlier stage already
    parsed it). Strips a Markdown code fence, decodes strictly with constant
    rejection, and only on failure repairs via ``json_repair`` -- re-decoding the
    repaired string so constant rejection still applies. Raises ``ValueError`` when
    the text is unrecoverable.
    """
    if not isinstance(raw, str):
        return raw
    text = _strip_code_fence(raw)
    try:
        return json.loads(text, parse_constant=_reject_json_constant)
    except ValueError:
        repaired = repair_json(text)
        if not repaired or repaired == '""':
            raise
        return json.loads(repaired, parse_constant=_reject_json_constant)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `rtk uv run pytest tests/reverse_engineering/test_model_json.py -q`
Expected: PASS (9 tests). If `test_unrecoverable_text_raises` fails because `json_repair` coerces the prose into `""` or a truthy scalar, adjust the guard: the intent is that non-JSON prose raises — confirm `repair_json("this is not json at all ~~~")` returns falsy/`'""'`; if it returns a bare string scalar, tighten the check to also reject a non-container repair (`if not isinstance(json.loads(repaired,...), (dict, list)): raise`). Keep the fix minimal and re-run.

- [ ] **Step 5: Commit**

```bash
rtk git add src/reverse_engineering/model_json.py tests/reverse_engineering/test_model_json.py
rtk git commit -m "feat(re): single robust model->JSON boundary (loads_model_json)"
```

---

### Task 2: Route the evidence/critic envelope parsers through the boundary

**Files:**
- Modify: `src/reverse_engineering/evidence_envelope.py`
- Test: `tests/reverse_engineering/` (new regression test)

**Interfaces:**
- Consumes: `loads_model_json` (Task 1).
- The public parse signatures are unchanged (`parse_evidence_envelope`, `parse_critic_envelope`); only their internal decode step changes.

- [ ] **Step 1: Write the failing regression test**

Create `tests/reverse_engineering/test_evidence_envelope_fenced.py`:

```python
"""A fenced (```json) envelope must parse into real findings, not fail-close."""

from __future__ import annotations

from reverse_engineering.evidence_envelope import parse_evidence_envelope

_AID = "9d23916206a4749f6d69876e9e9dad4cbe8e6b9a26d0d5a14b7ac964a6e5c43b"


def test_fenced_evidence_envelope_parses():
    raw = (
        "```json\n"
        '{"artifact_id": "' + _AID + '",'
        ' "coverage": {"status": "complete", "surfaces": ["dotnet_decompile"], "limitations": []},'
        ' "findings": []}\n'
        "```"
    )
    env = parse_evidence_envelope(raw, artifact_id=_AID)
    assert env.artifact_id == _AID
    assert env.coverage.status.value == "complete"
```

- [ ] **Step 2: Run it to verify it fails**

Run: `rtk uv run pytest tests/reverse_engineering/test_evidence_envelope_fenced.py -q`
Expected: FAIL — `json.loads` chokes on the fence (`JSONDecodeError`/`ValueError`).

- [ ] **Step 3: Replace the bare decode calls**

In `src/reverse_engineering/evidence_envelope.py`, add the import near the top:

```python
from reverse_engineering.model_json import loads_model_json
```

Then in each of the three parsers (`parse_evidence_envelope` ~line 269, `parse_critic_envelope` ~line 321, and the parser at ~line 334) replace the decode line. Currently each reads like:

```python
        raw = json.loads(raw, parse_constant=_reject_json_constant)
```

Replace each with:

```python
        raw = loads_model_json(raw)
```

Keep the surrounding `if isinstance(raw, str):` size-guard (`len(raw) > MAX_RAW_…`) exactly as-is. If `_reject_json_constant` in `evidence_envelope.py` becomes unused after all three replacements, delete it (the decoder now owns constant rejection).

- [ ] **Step 4: Run the regression test + the module's existing tests**

Run: `rtk uv run pytest tests/reverse_engineering/test_evidence_envelope_fenced.py tests/ -q -k evidence_envelope`
Expected: PASS — the fenced envelope now parses, and existing envelope tests still pass.

- [ ] **Step 5: Full gate + commit**

Run: `rtk make check`
Expected: green. Then:

```bash
rtk git add src/reverse_engineering/evidence_envelope.py tests/reverse_engineering/test_evidence_envelope_fenced.py
rtk git commit -m "fix(re): evidence/critic envelope parsing tolerates model code fences"
```

---

### Task 3: Route the retriage snapshot parsers through the boundary

**Files:**
- Modify: `src/reverse_engineering/agents/deobf_gate.py`
- Test: `tests/reverse_engineering/` (new regression test)

**Interfaces:**
- Consumes: `loads_model_json` (Task 1).

- [ ] **Step 1: Write the failing regression test**

Create `tests/reverse_engineering/test_snapshot_fenced.py`:

```python
"""A fenced (```json) retriage snapshot must parse, not read as invalid."""

from __future__ import annotations

from reverse_engineering.agents.deobf_gate import _parse_snapshot


def test_fenced_snapshot_parses():
    raw = (
        "```json\n"
        '{"size": 1627136, "function_count": 0, "import_count": 1,'
        ' "string_count": 452, "section_count": 7}\n'
        "```"
    )
    snap = _parse_snapshot(raw)
    assert snap["size"] == 1627136
    assert snap["section_count"] == 7
```

(If `_parse_snapshot` requires additional `SNAPSHOT_FIELDS` beyond those five, read the constant and include them in the test's JSON verbatim so it exercises a real snapshot.)

- [ ] **Step 2: Run it to verify it fails**

Run: `rtk uv run pytest tests/reverse_engineering/test_snapshot_fenced.py -q`
Expected: FAIL — `_parse_snapshot`'s `json.loads` raises `ValueError("invalid snapshot JSON")` on the fence.

- [ ] **Step 3: Replace the bare decode calls**

In `src/reverse_engineering/agents/deobf_gate.py`, add the import near the top:

```python
from reverse_engineering.model_json import loads_model_json
```

In `_parse_snapshot` (~line 605-611), replace:

```python
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("invalid snapshot JSON") from exc
```
with:
```python
    if isinstance(raw, str):
        try:
            raw = loads_model_json(raw)
        except ValueError as exc:
            raise ValueError("invalid snapshot JSON") from exc
```

Apply the identical replacement in `_parse_current_snapshot` (~line 625-629, the `decoded = json.loads(raw)` block). Leave the other `json.loads` calls in `deobf_gate.py` (542, 554, 609-context already covered) that parse **non-model** data unchanged — but verify: lines 542/554 parse model-authored evidence too; if `_evidence_artifact_id`/the previous-evidence path (534-542, 554) decodes model text, route those through `loads_model_json` as well. Confirm by reading each site: any `raw` that originates from an agent's `output_key` or a model-authored state value is model output and must use `loads_model_json`.

- [ ] **Step 4: Run the regression test + gate**

Run: `rtk uv run pytest tests/reverse_engineering/test_snapshot_fenced.py -q && rtk make check`
Expected: PASS then green.

- [ ] **Step 5: Commit**

```bash
rtk git add src/reverse_engineering/agents/deobf_gate.py tests/reverse_engineering/test_snapshot_fenced.py
rtk git commit -m "fix(re): retriage snapshot + prior-evidence parsing tolerates model code fences"
```

---

### Task 4: Drop `output_schema` from the three tool-using agents

**Why:** `output_schema` + tools is ADK's documented unreliable combination; on a tool-using turn the model emits free-form (fenced) text that the coercion rejects, silently dropping the stage's findings. These three agents have tools AND an after-agent evidence normalizer, so removing `output_schema` lets their raw text land in `output_key` and be parsed by the now-robust normalizer (Task 2) instead of coerced-away.

**Files:**
- Modify: `src/reverse_engineering/agents/dotnet_decompile.py`, `src/reverse_engineering/agents/deep_decompile.py`, `src/reverse_engineering/agents/triage_recon.py`
- Test: existing agent/descriptor tests (adjust assertions)

**Interfaces:**
- These descriptors keep `output_key` and their `after_agent_callbacks`; they lose `output_schema`.

- [ ] **Step 1: Find tests asserting `output_schema` on these three**

Run: `rtk grep -rn "output_schema" tests/ | rtk grep -i "dotnet_decompile\|deep_decompile\|triage_recon"`
Note each; they will need updating to assert `output_schema is None` (or to drop the assertion).

- [ ] **Step 2: Remove `output_schema` from each descriptor**

In `dotnet_decompile.py` delete the line `output_schema=EvidenceEnvelopeInput,` (line ~43). Do the same in `deep_decompile.py` (~46) and `triage_recon.py` (~32). Remove the now-unused `EvidenceEnvelopeInput` import from each file **only if** nothing else in that file references it (check each). Leave `output_key`, `tool_ids`/`mcp_server_ids`, and `after_agent_callbacks` untouched.

- [ ] **Step 3: Update the tests found in Step 1**

For each test asserting these agents carry `output_schema`, change it to assert the descriptor now has `output_schema is None` and still has its `output_key` + `after_agent_callbacks`. If a test asserted schema-coercion behavior end-to-end, re-point it at the normalizer path (the after-agent callback produces the envelope).

- [ ] **Step 4: Verify + gate**

Run: `rtk make check`
Expected: green — including the composition freeze (these agents build without `output_schema`) and the malware_analyst pipeline tests.

- [ ] **Step 5: Commit**

```bash
rtk git add src/reverse_engineering/agents/dotnet_decompile.py src/reverse_engineering/agents/deep_decompile.py src/reverse_engineering/agents/triage_recon.py tests/
rtk git commit -m "fix(agents): drop output_schema from tool-using agents (ADK schema+tools is unreliable)"
```

---

### Task 5: Forbid `output_schema` + tools at descriptor construction

**Files:**
- Modify: `src/arema/registry/descriptors.py`
- Test: `tests/` (descriptor validation test — colocate with existing descriptor tests)

**Interfaces:**
- `AgentDescriptor.__post_init__` gains a new invariant that raises `InvalidCapabilityDescriptorError`.

- [ ] **Step 1: Write the failing test**

Find the existing descriptor-validation test file (`rtk grep -rln "output_schema but no output_key\|InvalidCapabilityDescriptorError" tests/`). Add:

```python
import pytest
from pydantic import BaseModel

from arema.registry.descriptors import AgentDescriptor
from arema.registry.errors import InvalidCapabilityDescriptorError


class _Schema(BaseModel):
    x: int


def test_output_schema_with_tools_is_rejected():
    with pytest.raises(InvalidCapabilityDescriptorError, match="output_schema"):
        AgentDescriptor(
            id="bad", name="bad", description="d", prompt_id="bad",
            factory=lambda ctx: ctx, runtime_profile_id="safe_default",
            output_key="k", output_schema=_Schema, tool_ids=("some_tool",),
        )


def test_output_schema_with_mcp_is_rejected():
    with pytest.raises(InvalidCapabilityDescriptorError, match="output_schema"):
        AgentDescriptor(
            id="bad", name="bad", description="d", prompt_id="bad",
            factory=lambda ctx: ctx, runtime_profile_id="safe_default",
            output_key="k", output_schema=_Schema, mcp_server_ids=("some_mcp",),
        )
```

(Match the constructor's required fields to the real `AgentDescriptor` signature — copy the field set from a passing descriptor test in the same file.)

- [ ] **Step 2: Run it to verify it fails**

Run: `rtk uv run pytest <that test file> -q -k "output_schema_with"`
Expected: FAIL — no error is raised (the combination is currently allowed).

- [ ] **Step 3: Add the invariant**

In `src/arema/registry/descriptors.py`, `AgentDescriptor.__post_init__`, immediately after the existing `output_schema`/`output_key` check (~line 445), add:

```python
        if self.output_schema is not None and (self.tool_ids or self.mcp_server_ids):
            raise InvalidCapabilityDescriptorError(
                f"agent '{self.id}' combines output_schema with tools/MCP servers; "
                "ADK's schema coercion is unreliable on a tool-using turn (the model "
                "emits free-form, often code-fenced, text), so a tool-using agent must "
                "emit a normal text envelope parsed by its after-agent normalizer "
                "instead of declaring output_schema."
            )
```

- [ ] **Step 4: Run the test + full gate**

Run: `rtk uv run pytest <that test file> -q -k "output_schema" && rtk make check`
Expected: PASS then green. `make check` proves no shipped descriptor violates the new invariant (Task 4 already cleared the three offenders).

- [ ] **Step 5: Commit**

```bash
rtk git add src/arema/registry/descriptors.py tests/
rtk git commit -m "feat(registry): forbid output_schema + tools on one agent (unbuildable misconfig)"
```

---

### Task 6: Architecture guard — the decoder is the only model-JSON boundary

**Files:**
- Modify: `tests/reverse_engineering/test_model_json.py` (add the guard test)

**Interfaces:** none (test-only).

- [ ] **Step 1: Write the guard test**

Append to `tests/reverse_engineering/test_model_json.py`:

```python
import ast
from pathlib import Path

# Modules that legitimately parse MODEL-authored text into JSON. Each must go
# through loads_model_json, never a bare json.loads -- that is what let the
# ```json bug recur. Non-model json.loads (sqlite rows, tool stdout) is fine and
# lives in other modules, which this guard does not touch.
_MODEL_JSON_PARSERS = (
    "src/reverse_engineering/evidence_envelope.py",
    "src/reverse_engineering/agents/deobf_gate.py",
)


def test_model_output_parsers_do_not_call_bare_json_loads():
    offenders = []
    for rel in _MODEL_JSON_PARSERS:
        tree = ast.parse(Path(rel).read_text())
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "loads"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "json"
            ):
                offenders.append(f"{rel}:{node.lineno}")
    assert not offenders, (
        "bare json.loads on model output found; route through loads_model_json: "
        + ", ".join(offenders)
    )
```

- [ ] **Step 2: Run it**

Run: `rtk uv run pytest tests/reverse_engineering/test_model_json.py -q -k bare_json_loads`
Expected: PASS (Tasks 2 and 3 already removed every `json.loads` from those two files). If it FAILS, a bare `json.loads` remains in a listed file that decodes model text — replace it with `loads_model_json` (do NOT weaken the test). If a listed file has a `json.loads` on genuinely non-model data that cannot be removed, that is a signal the model-parsing code should move to its own module; note it and consult before exempting.

- [ ] **Step 3: Commit**

```bash
rtk git add tests/reverse_engineering/test_model_json.py
rtk git commit -m "test(re): architecture guard — model-JSON parsers must use the robust boundary"
```

---

### Task 7: Honest network coverage for .NET samples

**Why:** `enforce_network_coverage` only credits a completed network-relevant surface from **upstream** (recovery/deep) envelopes, and `NETWORK_RELEVANT_SURFACES` lists only **native** surfaces (`floss`, `ghidra_*`). So a network agent that fully examined the .NET decompilation (`status: complete, surfaces: [dotnet_decompile]`) with zero IOCs is wrongly downgraded to `network:not_determined`. Fix both: recognize the managed surfaces, and credit the network envelope's own completed coverage.

**Files:**
- Modify: `src/malware_analyst/evidence.py`
- Test: `tests/` (malware_analyst network-coverage tests)

- [ ] **Step 1: Write the failing test**

Add to the network-coverage test module (find via `rtk grep -rln "enforce_network_coverage\|NETWORK_IOC_EVIDENCE_KEY" tests/`):

```python
def test_complete_dotnet_network_examination_is_not_downgraded(...):
    # Arrange a callback_context whose network envelope is COMPLETE over
    # ["dotnet_decompile"] with zero findings, and upstream recovery/deep that are
    # partial/failed (as in a real .NET run). Follow the existing tests' fixture
    # style in this file for constructing the context + state.
    enforce_network_coverage(ctx)
    net = <parse NETWORK_IOC_EVIDENCE_KEY from state>
    assert "network:not_determined" not in net["coverage"]["limitations"]
    assert net["coverage"]["status"] == "complete"
```

Write it concretely using the fixtures already in that test file (mirror an existing `enforce_network_coverage` test's setup exactly; only the network envelope's surface/status differ).

- [ ] **Step 2: Run it to verify it fails**

Expected: FAIL — the current code downgrades to `partial` + `network:not_determined`.

- [ ] **Step 3: Fix `evidence.py`**

Add the managed decompilation surfaces to `NETWORK_RELEVANT_SURFACES` (these are what `dotnet_decompile`/`network_indicators` actually report):

```python
NETWORK_RELEVANT_SURFACES = frozenset(
    {
        # native
        "floss_decode",
        "ghidra_strings",
        "ghidra_search_decompiled",
        "ghidra_decompile",
        "ghidra_pcode",
        # managed (.NET / CIL) — ILSpy decompilation is where a C2 host/port surfaces
        "dotnet_decompile",
        "decompile_method",
        "analyze_assembly",
        "search_strings",
    }
)
```

Then credit the network envelope's OWN coverage. Change `completed_surface` to consider the network envelope alongside upstream:

```python
    completed_surface = any(
        envelope.coverage.status is CoverageStatus.COMPLETE
        and any(surface in NETWORK_RELEVANT_SURFACES for surface in envelope.coverage.surfaces)
        for envelope in (network, *upstream)
    )
```

(Change the iterable from `upstream` to `(network, *upstream)`. Leave the `observed_surfaces`/limitation-merge logic as-is — it still only fires when `not has_network_ioc and not completed_surface`.)

- [ ] **Step 4: Run the test + gate**

Run: `rtk make check`
Expected: green; the new test passes and existing network-coverage tests (including the native-surface and genuinely-degraded cases that SHOULD still mark `not_determined`) stay green.

- [ ] **Step 5: Commit**

```bash
rtk git add src/malware_analyst/evidence.py tests/
rtk git commit -m "fix(malware): credit .NET decompilation + own coverage in network determination"
```

---

### Task 8: Rebind prior-artifact (triage) evidence in the critic aggregation

**Why:** `triage_evidence_json` is legitimately bound to the **original** pre-recovery artifact; the critic aggregation parses every stage against the **current recovered** artifact, so triage fails the artifact-id match and is recorded as `critic:triage_evidence_json:invalid` — discarding valid triage context. The codebase already has `rebind_evidence_envelope` for exactly this (the deobf loop uses the parse-then-rebind pattern at `deobf_gate.py:535-536`).

**Files:**
- Modify: `src/reverse_engineering/agents/evidence_output.py`
- Test: `tests/reverse_engineering/`

- [ ] **Step 1: Write the failing test**

Add a test that the critic aggregation accepts a triage envelope bound to a *different* (prior) artifact by rebinding it, rather than emitting `critic:triage_evidence_json:invalid`. Construct state with `triage_evidence_json` bound to artifact A (original) and `CURRENT_ARTIFACT_KEY` = artifact B (recovered), plus at least one triage finding; assert the resulting `VALIDATED_EVIDENCE_KEY` envelope does NOT contain `critic:triage_evidence_json:invalid` and DOES carry the triage finding (re-anchored to B). Mirror the existing critic-aggregation test fixtures in the file.

- [ ] **Step 2: Run it to verify it fails**

Expected: FAIL — the current loop adds `critic:triage_evidence_json:invalid`.

- [ ] **Step 3: Fix the aggregation loop**

In `src/reverse_engineering/agents/evidence_output.py`, add the import:

```python
from reverse_engineering.evidence_envelope import (
    parse_evidence_envelope,
    rebind_evidence_envelope,
)
```
(add `rebind_evidence_envelope` to the existing import).

Replace the parse at ~line 176 so a prior-artifact envelope is rebound instead of rejected. Currently:

```python
        try:
            envelope = parse_evidence_envelope(getter(key), artifact_id=artifact_id)
        except (TypeError, ValueError):
            limitations.add(f"critic:{key}:invalid")
            upstream_failed = True
            continue
```
Change to parse against the envelope's OWN id, then rebind to the current artifact — matching `deobf_gate`'s established pattern. Add a small module-level helper (or reuse `_evidence_artifact_id` if importable) that extracts the raw envelope's `artifact_id`:

```python
        raw = getter(key)
        try:
            own_id = _raw_artifact_id(raw)  # extract artifact_id from the raw envelope
            envelope = rebind_evidence_envelope(
                parse_evidence_envelope(raw, artifact_id=own_id),
                artifact_id=artifact_id,
            )
        except (TypeError, ValueError, KeyError):
            limitations.add(f"critic:{key}:invalid")
            upstream_failed = True
            continue
```

Where `_raw_artifact_id` decodes the raw via `loads_model_json` and returns its `artifact_id` string (raising if absent/malformed). Implement it in this module (or import the existing `_evidence_artifact_id` from `deobf_gate` if it is public enough; prefer a small local helper to avoid a cross-agent import). This makes a genuinely-malformed envelope still fail-close to `:invalid`, while a valid envelope bound to a prior artifact is correctly rebound — the same authority model the recovery loop already uses.

- [ ] **Step 4: Run the test + gate**

Run: `rtk make check`
Expected: green; the triage envelope is rebound (no false `:invalid`), and a genuinely malformed envelope still yields `:invalid`.

- [ ] **Step 5: Commit**

```bash
rtk git add src/reverse_engineering/agents/evidence_output.py tests/
rtk git commit -m "fix(re): rebind prior-artifact triage evidence in critic aggregation"
```

---

## Self-Review

**1. Spec coverage.**
- Recurring ```json class of bug → Tasks 1 (decoder), 2 (envelopes), 3 (snapshots), 6 (guard). ✓
- Remove the misconfiguration that produces fenced-then-dropped output → Task 4 (drop `output_schema`). ✓
- Make it unbuildable / never recur → Task 5 (descriptor invariant) + Task 6 (architecture guard). ✓
- Network `not_determined` bug → Task 7. ✓
- `critic:triage_evidence_json:invalid` bug → Task 8. ✓
- `de4dot_failed` / `floss:result_invalid` are documented in the diagnosis as genuine/benign (native tools on ConfuserEx/.NET) — no code change, correctly out of scope.

**2. Placeholder scan.** Tasks 1–6 carry exact code. Tasks 7–8's test bodies say "mirror the existing fixtures in this file" rather than inventing a fake context shape — this is deliberate: the real `CallbackContext`/state fixtures live in those test modules and must be matched exactly, not guessed. The implementer reads the neighbouring test and copies its setup. Every production-code edit is exact.

**3. Type consistency.** `loads_model_json(raw: object) -> object` is used identically in Tasks 2, 3, 8. `NETWORK_RELEVANT_SURFACES` stays a `frozenset[str]`. `rebind_evidence_envelope(envelope, *, artifact_id)` matches its definition in `evidence_envelope.py:276`. The descriptor invariant raises the same `InvalidCapabilityDescriptorError` the neighbouring checks use.

## Known limitations (out of scope, documented)
- A tool-using agent that fully decompiles a still-string-encrypted inner assembly may honestly need to report `coverage.status = partial` (not `complete`) so Task 7's "credit own coverage" can't over-claim "no C2". That is an agent-prompt concern (teach the decompile/network prompts to mark coverage partial when string encryption remains unpeeled), tracked separately — it is orthogonal to the coverage-callback bug fixed here.
- The `de4dot_failed` genuine limit (ConfuserEx `ProxyCallFixer` crash) is unaffected; recovering the inner Quasar C2 likely still requires a further string-decryption pass, which is existing pipeline depth, not this plan's scope.
