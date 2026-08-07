# Thrash-Detector (Slice-1 harness improvement) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the `dotnet_analyst` deep-agentic loop a harness-level thrash detector that spots when the model re-runs the *same* `run_python` approach against the *same* failure and injects a one-time "pivot, don't retry" directive — so a weaker/differently-shaped model (e.g. GLM-5.2) stops burning its execution budget varying a dead approach, the way Claude's decisive-pivot reasoning does on its own.

**Architecture:** Deterministic scaffolding around a non-deterministic core (the ADK "deterministic skeleton, autonomous flesh" philosophy). Two self-scoped callbacks — an `after_tool` **Monitor** that classifies each `run_python` outcome into a stable `(approach|failure)` signature and tracks consecutive repeats in session state, and a `before_model` **Advisor** that fires a pivot directive once the streak reaches a strike threshold. Both are wired onto a new `re_deep_agentic` runtime profile (a `replace()` of `re_guarded`) used *only* by `dotnet_analyst`, so the other 11 RE agents on `re_guarded` are untouched. No prose is added to the loop's reasoning; the discipline is enforced structurally.

**Tech Stack:** Python 3.14, Google ADK (`LlmAgent`, `before_model_callback`, `after_tool_callback`, `RuntimeProfile`), pytest.

## Global Constraints

- **No bare `typing.Any` as a function parameter annotation.** Use `object` for a generic single param; `dict[str, object]` is fine. (ADK calls `isinstance(default, annotation)` at import; Python 3.14 removed `isinstance` support for `Any`.)
- **Never `isinstance(state, dict)`** on ADK `CallbackContext.state` / `ToolContext.state`. ADK's `State` is a proxy — duck-type on `.get` / `.__setitem__`, exactly as `workbench/budget.py` and `dotnet_scripted_recover.py` already do.
- **Callback ordering invariants (enforced by `validate_callback_chain`):** the registered-tool guard is first in `before_tool`; the output compactor is the single last step in `after_tool`. New `extra_after_tool` steps sit *between* the metrics recorder and the compactor — the Monitor must precede the SanitizationMembrane so it reads raw `stderr`.
- **Every callback is fail-open.** Wrap the body in `try/except`, log the failure, and return `None` (proceed) — mirror `enforce_turn_limit` and `run_python_budget_guard`.
- **Prompts/harness must generalize, never overfit the test sample.** The advisory names the *observed* approach + failure at runtime and points to technique classes; it must contain **zero** sample-specific identifiers, hashes, protector banners, or C2 (per `prompts-must-generalize-not-overfit-samples`).
- **Commit messages** end with: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/reverse_engineering/tools/workbench/state.py` (modify) | Add 3 thrash session-state keys + `THRASH_STRIKE_THRESHOLD` beside the existing workbench constants (single source of truth). |
| `src/reverse_engineering/tools/workbench/thrash.py` (create) | Pure classifiers (`classify_approach`, `classify_failure`, `thrash_signature`) + the two callbacks (`record_run_python_thrash`, `advise_on_thrash`). |
| `src/arema/runtime/callbacks/_llm_request.py` (create) | Shared `append_to_system_instruction(llm_request, text)` helper, extracted from `turn_limit.py` so it isn't duplicated. |
| `src/arema/runtime/callbacks/turn_limit.py` (modify) | Import the shared helper instead of its private copy (pure refactor, behavior identical). |
| `src/reverse_engineering/profiles.py` (modify) | Add `RE_DEEP_AGENTIC_PROFILE` = `replace(RE_GUARDED_PROFILE, …)` with the Monitor (before the sanitizer) + Advisor. |
| `src/reverse_engineering/agents/dotnet_analyst.py` (modify) | Point the descriptor at `re_deep_agentic`. |
| `src/reverse_engineering/composition.py` (modify) | Register `RE_DEEP_AGENTIC_PROFILE`. |
| `src/reverse_engineering/prompts/dotnet_analyst.md` (modify) | One sentence telling the agent a repeated-failure advisory is authoritative. |
| `tests/reverse_engineering/test_workbench_thrash.py` (create) | Unit tests for classifiers + both callbacks (incl. the false-positive guard). |
| `tests/reverse_engineering/test_re_deep_agentic_profile.py` (create) | Assert profile wiring + ordering + descriptor rewire. |

---

### Task 1: State keys + pure classifiers

The signature is the whole design. Keying on `(approach|failure)` means a strike accrues **only** when both the approach *and* the failure are unchanged — which is exactly "varied nothing that matters." A second `de4dot` attempt with different flags that produces a *different* error resets the streak (real progress); one that produces the *same* crash strikes (genuine thrash). This is the false-positive guard, baked into the data model rather than special-cased.

**Files:**
- Modify: `src/reverse_engineering/tools/workbench/state.py`
- Create: `src/reverse_engineering/tools/workbench/thrash.py`
- Test: `tests/reverse_engineering/test_workbench_thrash.py`

**Interfaces:**
- Produces: `classify_approach(code: str) -> str`, `classify_failure(exit_code: object, stderr: str) -> str`, `thrash_signature(code: str, exit_code: object, stderr: str) -> str`; state keys `THRASH_SIGNATURE_KEY`, `THRASH_REPEAT_COUNT_KEY`, `THRASH_ARTIFACT_KEY` (all `str`), and `THRASH_STRIKE_THRESHOLD: int = 3`.

- [ ] **Step 1: Write the failing test**

Create `tests/reverse_engineering/test_workbench_thrash.py`:

```python
"""Unit tests for the run_python thrash detector."""

from __future__ import annotations

from reverse_engineering.tools.workbench.thrash import (
    classify_approach,
    classify_failure,
    thrash_signature,
)


def test_classify_approach_names_the_heaviest_tool():
    assert classify_approach('subprocess.run(["de4dot", "-r", "/in"])') == "de4dot"
    assert classify_approach('subprocess.run(["mono", exe])') == "mono"
    assert classify_approach('subprocess.run(["dotnet-script", csx])') == "dotnet-script"
    assert classify_approach('subprocess.run(["ilspycmd", dll])') == "ilspycmd"
    assert classify_approach("import pefile; pefile.PE(inp)") == "python"


def test_classify_failure_extracts_exception_class():
    assert classify_failure(1, "System.InvalidCastException: bad cast\n at X") == "InvalidCastException"
    assert classify_failure(1, "Traceback...\nValueError: nope") == "ValueError"


def test_classify_failure_empty_on_success():
    assert classify_failure(0, "anything") == ""


def test_classify_failure_falls_back_to_first_line():
    assert classify_failure(1, "  boom happened  \nmore") == "boom happened"
    assert classify_failure(2, "") == "nonzero_exit"


def test_signature_is_empty_on_success_and_stable_on_same_failure():
    assert thrash_signature("de4dot ...", 0, "") == ""
    sig_a = thrash_signature('run(["de4dot"])', 1, "System.InvalidCastException: x")
    sig_b = thrash_signature('run(["de4dot", "--other-flag"])', 1, "System.InvalidCastException: y")
    assert sig_a == sig_b == "de4dot|InvalidCastException"  # flags differ, failure identical -> same sig


def test_signature_differs_when_failure_changes():
    sig_a = thrash_signature('run(["de4dot"])', 1, "System.InvalidCastException: x")
    sig_b = thrash_signature('run(["de4dot"])', 1, "System.BadImageFormatException: y")
    assert sig_a != sig_b  # progress -> streak will reset
```

- [ ] **Step 2: Run test to verify it fails**

Run: `rtk uv run pytest tests/reverse_engineering/test_workbench_thrash.py -q`
Expected: FAIL — `ModuleNotFoundError: reverse_engineering.tools.workbench.thrash`.

- [ ] **Step 3: Add the state keys**

In `src/reverse_engineering/tools/workbench/state.py`, append after the existing tool-name constants:

```python
# --- Thrash detector (run_python loop) ---------------------------------------
# A run is a "strike" only when BOTH the approach and the failure class repeat
# unchanged; success or a new artifact/layer resets the streak. Keys are global
# session state (like WORKBENCH_EXEC_COUNT_KEY) so they span deobfuscation-loop
# rounds; THRASH_ARTIFACT_KEY scopes the streak to one layer.
THRASH_SIGNATURE_KEY = "workbench:thrash_signature"
THRASH_REPEAT_COUNT_KEY = "workbench:thrash_repeats"
THRASH_ARTIFACT_KEY = "workbench:thrash_artifact"
# Consecutive identical failures before the before-model advisor fires.
THRASH_STRIKE_THRESHOLD = 3
```

- [ ] **Step 4: Write the classifiers**

Create `src/reverse_engineering/tools/workbench/thrash.py` with **only** the classifiers for now (callbacks come in Tasks 2–3):

```python
"""Thrash detector for the run_python deep-agentic loop.

A weaker model tends to re-run the SAME dead approach (same tool, same error)
instead of pivoting, burning the per-case execution budget. This module turns
each run_python outcome into a stable ``approach|failure`` signature; a Monitor
(after_tool) counts consecutive repeats and an Advisor (before_model) injects a
one-time pivot directive once the streak reaches the strike threshold. A strike
accrues only when BOTH halves repeat, so varying flags that still hit the same
crash strikes (real thrash) while a genuinely different failure resets (progress).
"""

from __future__ import annotations

import re

# Ordered most-specific/heaviest first: a script that shells out to several tools
# is labeled by the one that most defines the attempt. Word-boundary anchored so
# a comment mentioning "mono" in prose does not misclassify a pure-python run.
_APPROACH_PATTERNS: tuple[tuple[str, str], ...] = (
    ("de4dot", r"\bde4dot\b"),
    ("ilspycmd", r"\bilspycmd\b"),
    ("dotnet-script", r"dotnet[-_ ]script"),
    ("mono", r"\bmono\b"),
    ("radare2", r"\b(?:radare2|r2pipe|r2)\b"),
)

# A .NET/CLR or Python exception class: a capitalized name ending Error/Exception.
_EXCEPTION_RE = re.compile(r"\b([A-Z][A-Za-z0-9_]*(?:Error|Exception))\b")


def classify_approach(code: str) -> str:
    """Return a coarse label for the dominant tool the script invokes."""
    for label, pattern in _APPROACH_PATTERNS:
        if re.search(pattern, code):
            return label
    return "python"


def classify_failure(exit_code: object, stderr: str) -> str:
    """Return a stable failure token, or "" when the run succeeded.

    A zero exit is progress (no failure). Otherwise prefer the named exception
    class (the LAST match: Python tracebacks put it last, and .NET stderr stacks
    name no other Error/Exception token below the header line), falling back to a
    trimmed first non-empty stderr line, then a generic nonzero-exit marker.
    """
    code = exit_code if isinstance(exit_code, int) and not isinstance(exit_code, bool) else 1
    if code == 0:
        return ""
    matches = _EXCEPTION_RE.findall(stderr or "")
    if matches:
        return matches[-1]
    first_line = next((line.strip() for line in (stderr or "").splitlines() if line.strip()), "")
    return first_line[:80] if first_line else "nonzero_exit"


def thrash_signature(code: str, exit_code: object, stderr: str) -> str:
    """Return the ``approach|failure`` signature, or "" for a successful run."""
    failure = classify_failure(exit_code, stderr)
    if not failure:
        return ""
    return f"{classify_approach(code)}|{failure}"
```

- [ ] **Step 5: Run test to verify it passes**

Run: `rtk uv run pytest tests/reverse_engineering/test_workbench_thrash.py -q`
Expected: PASS (7 tests).

- [ ] **Step 6: Commit**

```bash
rtk git add src/reverse_engineering/tools/workbench/state.py src/reverse_engineering/tools/workbench/thrash.py tests/reverse_engineering/test_workbench_thrash.py
rtk git commit -m "feat(deobf): thrash signature + state keys for the run_python loop"
```

---

### Task 2: The after_tool Monitor

**Files:**
- Modify: `src/reverse_engineering/tools/workbench/thrash.py`
- Test: `tests/reverse_engineering/test_workbench_thrash.py`

**Interfaces:**
- Consumes: Task 1 classifiers + keys; `RUN_PYTHON_TOOL_NAME` (workbench state); `CURRENT_ARTIFACT_KEY` (deobfuscation state).
- Produces: `record_run_python_thrash(*, tool, args, tool_context, tool_response) -> dict[str, object] | None` — an `after_tool` callback that returns `None` (never transforms the response) and mutates the streak counters in `tool_context.state`.

- [ ] **Step 1: Write the failing test**

Append to `tests/reverse_engineering/test_workbench_thrash.py`:

```python
from types import SimpleNamespace

from reverse_engineering.tools.deobfuscation.state import CURRENT_ARTIFACT_KEY
from reverse_engineering.tools.workbench.state import (
    RUN_PYTHON_TOOL_NAME,
    THRASH_REPEAT_COUNT_KEY,
    THRASH_SIGNATURE_KEY,
)
from reverse_engineering.tools.workbench.thrash import record_run_python_thrash


def _run(state, code, exit_code, stderr, *, tool_name=RUN_PYTHON_TOOL_NAME):
    # A plain dict satisfies ADK's .get/.__setitem__ duck-typing used by the callback.
    record_run_python_thrash(
        tool=SimpleNamespace(name=tool_name),
        args={"code": code},
        tool_context=SimpleNamespace(state=state),
        tool_response={"exit_code": exit_code, "stderr": stderr},
    )


def test_repeated_identical_failure_accrues_strikes():
    state = {CURRENT_ARTIFACT_KEY: "a1"}
    for _ in range(3):
        _run(state, 'run(["de4dot"])', 1, "System.InvalidCastException: x")
    assert state[THRASH_REPEAT_COUNT_KEY] == 3
    assert state[THRASH_SIGNATURE_KEY] == "de4dot|InvalidCastException"


def test_different_failure_resets_the_streak():
    state = {CURRENT_ARTIFACT_KEY: "a1"}
    _run(state, 'run(["de4dot"])', 1, "System.InvalidCastException: x")
    _run(state, 'run(["de4dot"])', 1, "System.InvalidCastException: x")
    _run(state, 'run(["de4dot"])', 1, "System.BadImageFormatException: y")  # progress
    assert state[THRASH_REPEAT_COUNT_KEY] == 1
    assert state[THRASH_SIGNATURE_KEY] == "de4dot|BadImageFormatException"


def test_success_resets_the_streak():
    state = {CURRENT_ARTIFACT_KEY: "a1"}
    _run(state, 'run(["de4dot"])', 1, "InvalidCastException: x")
    _run(state, "print(ok)", 0, "")
    assert state[THRASH_REPEAT_COUNT_KEY] == 0
    assert state[THRASH_SIGNATURE_KEY] == ""


def test_new_artifact_layer_resets_the_streak():
    state = {CURRENT_ARTIFACT_KEY: "a1"}
    _run(state, 'run(["de4dot"])', 1, "InvalidCastException: x")
    _run(state, 'run(["de4dot"])', 1, "InvalidCastException: x")
    state[CURRENT_ARTIFACT_KEY] = "a2"  # loop banked a layer and advanced
    _run(state, 'run(["de4dot"])', 1, "InvalidCastException: x")
    assert state[THRASH_REPEAT_COUNT_KEY] == 1


def test_non_run_python_tool_is_ignored():
    state = {CURRENT_ARTIFACT_KEY: "a1"}
    _run(state, "whatever", 1, "SomeError: x", tool_name="register_unpacked_artifact")
    assert THRASH_REPEAT_COUNT_KEY not in state
```

- [ ] **Step 2: Run test to verify it fails**

Run: `rtk uv run pytest tests/reverse_engineering/test_workbench_thrash.py -q`
Expected: FAIL — `ImportError: cannot import name 'record_run_python_thrash'`.

- [ ] **Step 3: Implement the Monitor**

Add to `src/reverse_engineering/tools/workbench/thrash.py` (imports at top, function below the classifiers):

```python
from typing import TYPE_CHECKING

from arema.core.logging import get_logger
from reverse_engineering.tools.deobfuscation.state import CURRENT_ARTIFACT_KEY
from reverse_engineering.tools.workbench.state import (
    RUN_PYTHON_TOOL_NAME,
    THRASH_ARTIFACT_KEY,
    THRASH_REPEAT_COUNT_KEY,
    THRASH_SIGNATURE_KEY,
    THRASH_STRIKE_THRESHOLD,
)

if TYPE_CHECKING:
    from google.adk.agents.callback_context import CallbackContext
    from google.adk.models.llm_request import LlmRequest
    from google.adk.models.llm_response import LlmResponse
    from google.adk.tools.base_tool import BaseTool
    from google.adk.tools.tool_context import ToolContext

logger = get_logger(__name__)


def _int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _str(value: object) -> str:
    return value if isinstance(value, str) else ""


def record_run_python_thrash(
    *,
    tool: BaseTool,
    args: dict[str, object],
    tool_context: ToolContext,
    tool_response: dict[str, object],
) -> dict[str, object] | None:
    """after_tool Monitor: track consecutive identical run_python failures.

    Self-scoped to run_python; returns ``None`` (never transforms the response).
    Resets on progress (a successful run, or the loop advancing to a new layer).
    Fail-open.
    """
    try:
        if getattr(tool, "name", "") != RUN_PYTHON_TOOL_NAME:
            return None
        state = tool_context.state
        getter = getattr(state, "get", None)
        setter = getattr(state, "__setitem__", None)
        if not callable(getter) or not callable(setter):
            return None
        # A new artifact means the loop peeled a layer; the old streak is stale.
        current_artifact = _str(getter(CURRENT_ARTIFACT_KEY))
        if current_artifact != _str(getter(THRASH_ARTIFACT_KEY)):
            setter(THRASH_ARTIFACT_KEY, current_artifact)
            setter(THRASH_SIGNATURE_KEY, "")
            setter(THRASH_REPEAT_COUNT_KEY, 0)
        code = args.get("code", "") if isinstance(args, dict) else ""
        response = tool_response if isinstance(tool_response, dict) else {}
        signature = thrash_signature(_str(code), response.get("exit_code"), _str(response.get("stderr")))
        if not signature:  # success -> progress, clear the streak
            setter(THRASH_SIGNATURE_KEY, "")
            setter(THRASH_REPEAT_COUNT_KEY, 0)
            return None
        if signature == _str(getter(THRASH_SIGNATURE_KEY)):
            setter(THRASH_REPEAT_COUNT_KEY, _int(getter(THRASH_REPEAT_COUNT_KEY)) + 1)
        else:
            setter(THRASH_SIGNATURE_KEY, signature)
            setter(THRASH_REPEAT_COUNT_KEY, 1)
        return None
    except Exception:
        logger.warning("record_run_python_thrash failed - continuing", exc_info=True)
        return None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `rtk uv run pytest tests/reverse_engineering/test_workbench_thrash.py -q`
Expected: PASS (12 tests).

- [ ] **Step 5: Commit**

```bash
rtk git add src/reverse_engineering/tools/workbench/thrash.py tests/reverse_engineering/test_workbench_thrash.py
rtk git commit -m "feat(deobf): after_tool Monitor tracking run_python thrash streaks"
```

---

### Task 3: Shared injection helper + the before_model Advisor

**Files:**
- Create: `src/arema/runtime/callbacks/_llm_request.py`
- Modify: `src/arema/runtime/callbacks/turn_limit.py`
- Modify: `src/reverse_engineering/tools/workbench/thrash.py`
- Test: `tests/reverse_engineering/test_workbench_thrash.py`

**Interfaces:**
- Produces: `append_to_system_instruction(llm_request: LlmRequest, text: str) -> None` (shared); `advise_on_thrash(callback_context, llm_request) -> LlmResponse | None` — a `before_model` callback that returns `None` (never short-circuits the model) and appends a pivot directive when the streak ≥ `THRASH_STRIKE_THRESHOLD`.

- [ ] **Step 1: Write the failing test**

Append to `tests/reverse_engineering/test_workbench_thrash.py`:

```python
from reverse_engineering.tools.workbench.state import THRASH_STRIKE_THRESHOLD
from reverse_engineering.tools.workbench.thrash import advise_on_thrash


def _req(base="BASE"):
    return SimpleNamespace(config=SimpleNamespace(system_instruction=base))


def test_advisor_fires_at_threshold():
    state = {
        THRASH_REPEAT_COUNT_KEY: THRASH_STRIKE_THRESHOLD,
        THRASH_SIGNATURE_KEY: "de4dot|InvalidCastException",
    }
    req = _req()
    result = advise_on_thrash(SimpleNamespace(state=state), req)
    assert result is None  # never short-circuits the model
    text = req.config.system_instruction
    assert text.startswith("BASE")  # KV-cache: appended, not replaced
    assert "de4dot" in text and "InvalidCastException" in text
    assert "REPEATED FAILURE" in text


def test_advisor_silent_below_threshold():
    state = {THRASH_REPEAT_COUNT_KEY: THRASH_STRIKE_THRESHOLD - 1, THRASH_SIGNATURE_KEY: "de4dot|X"}
    req = _req()
    advise_on_thrash(SimpleNamespace(state=state), req)
    assert req.config.system_instruction == "BASE"


def test_advisor_names_no_sample_specifics():
    # Generalization guard: the directive must not hardcode a technique/name; it
    # only echoes the observed approach/failure and points to technique classes.
    state = {THRASH_REPEAT_COUNT_KEY: THRASH_STRIKE_THRESHOLD, THRASH_SIGNATURE_KEY: "de4dot|X"}
    req = _req("")
    advise_on_thrash(SimpleNamespace(state=state), req)
    lowered = req.config.system_instruction.lower()
    assert "confuser" not in lowered and "skidzex" not in lowered and "1595d92f" not in lowered
```

- [ ] **Step 2: Run test to verify it fails**

Run: `rtk uv run pytest tests/reverse_engineering/test_workbench_thrash.py -q`
Expected: FAIL — `ImportError: cannot import name 'advise_on_thrash'`.

- [ ] **Step 3: Extract the shared injection helper**

Create `src/arema/runtime/callbacks/_llm_request.py`:

```python
"""Shared helpers for mutating an ADK ``LlmRequest`` from a before-model callback."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from google.adk.models.llm_request import LlmRequest


def append_to_system_instruction(llm_request: LlmRequest, text: str) -> None:
    """Append *text* to the request's system instruction, handling both forms.

    No-ops silently when the request has no config. Handles a plain-string
    instruction and a ``Content``-style instruction with parts.
    """
    config = getattr(llm_request, "config", None)
    if config is None:
        return

    existing = getattr(config, "system_instruction", "") or ""
    if isinstance(existing, str):
        config.system_instruction = existing + text
        return

    parts = getattr(existing, "parts", None) or []
    if parts and hasattr(parts[0], "text"):
        parts[0].text = (parts[0].text or "") + text
```

- [ ] **Step 4: Point turn_limit at the shared helper**

In `src/arema/runtime/callbacks/turn_limit.py`: delete the local `_append_to_system_instruction` def (lines 37–54) and add the import near the other callback imports:

```python
from arema.runtime.callbacks._llm_request import append_to_system_instruction
```

Then update the one call site inside `enforce_turn_limit` from `_append_to_system_instruction(` to `append_to_system_instruction(`.

- [ ] **Step 5: Verify the refactor is behavior-preserving**

Run: `rtk uv run pytest tests/ -q -k turn_limit`
Expected: PASS — the existing turn-limit tests are unchanged and green.

- [ ] **Step 6: Implement the Advisor**

Add to `src/reverse_engineering/tools/workbench/thrash.py` (import the shared helper at top; function at the bottom):

```python
from arema.runtime.callbacks._llm_request import append_to_system_instruction
```

```python
def advise_on_thrash(
    callback_context: CallbackContext,
    llm_request: LlmRequest,
) -> LlmResponse | None:
    """before_model Advisor: inject a pivot directive on a repeated dead approach.

    Fires once the same-approach/same-failure streak reaches the strike threshold.
    Names only what recon OBSERVED (approach + failure) and points to technique
    CLASSES, never a sample-specific answer. Returns ``None`` (never short-circuits
    the model). Fail-open. Follows the turn_limit precedent of appending to the
    system instruction; this happens only during active thrashing, so KV-cache
    churn is rare.
    """
    try:
        state = callback_context.state
        getter = getattr(state, "get", None)
        if not callable(getter):
            return None
        count = _int(getter(THRASH_REPEAT_COUNT_KEY))
        if count < THRASH_STRIKE_THRESHOLD:
            return None
        approach, _, failure = _str(getter(THRASH_SIGNATURE_KEY)).partition("|")
        append_to_system_instruction(
            llm_request,
            (
                f"\n\n[STOP — REPEATED FAILURE: '{approach or 'this approach'}' has "
                f"failed {count}x in a row with the same error "
                f"({failure or 'no progress'}).]\n"
                f"That approach is exhausted for the current artifact. Do NOT run "
                f"'{approach or 'it'}' again. Pivot to a DIFFERENT technique: attack "
                "a different layer, use a different tool, or attack at a different "
                "abstraction (e.g. run the sample's own loader end-to-end instead of "
                "invoking a low-level routine directly). If you have genuinely "
                "exhausted your options, register the deepest valid artifact you "
                "recovered and stop.\n"
            ),
        )
        logger.info("thrash advisory injected", approach=approach, failure=failure, count=count)
        return None
    except Exception:
        logger.warning("advise_on_thrash failed - continuing", exc_info=True)
        return None
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `rtk uv run pytest tests/reverse_engineering/test_workbench_thrash.py -q`
Expected: PASS (15 tests).

- [ ] **Step 8: Commit**

```bash
rtk git add src/arema/runtime/callbacks/_llm_request.py src/arema/runtime/callbacks/turn_limit.py src/reverse_engineering/tools/workbench/thrash.py tests/reverse_engineering/test_workbench_thrash.py
rtk git commit -m "feat(deobf): before_model pivot advisory + shared system-instruction helper"
```

---

### Task 4: Wire the profile, rewire the agent, register, gate

**Files:**
- Modify: `src/reverse_engineering/profiles.py`
- Modify: `src/reverse_engineering/agents/dotnet_analyst.py`
- Modify: `src/reverse_engineering/composition.py`
- Modify: `src/reverse_engineering/prompts/dotnet_analyst.md`
- Test: `tests/reverse_engineering/test_re_deep_agentic_profile.py`

**Interfaces:**
- Consumes: `record_run_python_thrash`, `advise_on_thrash` (Task 2–3); `RE_GUARDED_PROFILE` (existing).
- Produces: `RE_DEEP_AGENTIC_PROFILE: RuntimeProfile` (id `"re_deep_agentic"`); `dotnet_analyst` now runs under it.

- [ ] **Step 1: Write the failing test**

Create `tests/reverse_engineering/test_re_deep_agentic_profile.py`:

```python
"""The re_deep_agentic profile wires the thrash detector and only dotnet_analyst uses it."""

from __future__ import annotations

from reverse_engineering.agents.dotnet_analyst import DOTNET_ANALYST_DESCRIPTOR
from reverse_engineering.profiles import RE_DEEP_AGENTIC_PROFILE, RE_GUARDED_PROFILE
from reverse_engineering.tools.workbench.thrash import (
    advise_on_thrash,
    record_run_python_thrash,
)


def test_monitor_precedes_the_sanitizer():
    after = RE_DEEP_AGENTIC_PROFILE.extra_after_tool
    assert after[0] is record_run_python_thrash  # reads raw stderr before sanitization
    # the re_guarded sanitizer(s) are preserved, after the monitor
    assert after[1:] == RE_GUARDED_PROFILE.extra_after_tool


def test_advisor_is_in_before_model():
    assert advise_on_thrash in RE_DEEP_AGENTIC_PROFILE.extra_before_model


def test_profile_id_is_distinct():
    assert RE_DEEP_AGENTIC_PROFILE.id == "re_deep_agentic"
    assert RE_GUARDED_PROFILE.id == "re_guarded"  # unchanged


def test_dotnet_analyst_uses_the_deep_profile():
    assert DOTNET_ANALYST_DESCRIPTOR.runtime_profile_id == "re_deep_agentic"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `rtk uv run pytest tests/reverse_engineering/test_re_deep_agentic_profile.py -q`
Expected: FAIL — `ImportError: cannot import name 'RE_DEEP_AGENTIC_PROFILE'`.

- [ ] **Step 3: Add the profile**

In `src/reverse_engineering/profiles.py`, add the imports and the profile after `RE_GUARDED_PROFILE`:

```python
from reverse_engineering.tools.workbench.thrash import (
    advise_on_thrash,
    record_run_python_thrash,
)
```

```python
# Deep-agentic analyst profile: re_guarded PLUS the thrash detector. The Monitor
# is placed BEFORE the SanitizationMembrane so it classifies run_python's raw
# stderr; the sanitizer (which frames binary-origin output) still runs after it
# and stays inside the always-last compactor. Scoped to dotnet_analyst so the
# other re_guarded agents are unaffected.
RE_DEEP_AGENTIC_PROFILE: RuntimeProfile = replace(
    RE_GUARDED_PROFILE,
    id="re_deep_agentic",
    extra_after_tool=(record_run_python_thrash, *RE_GUARDED_PROFILE.extra_after_tool),
    extra_before_model=(advise_on_thrash,),
)
```

- [ ] **Step 4: Rewire the agent descriptor**

In `src/reverse_engineering/agents/dotnet_analyst.py`, change:

```python
    runtime_profile_id="re_guarded",
```
to
```python
    runtime_profile_id="re_deep_agentic",
```

- [ ] **Step 5: Register the profile**

In `src/reverse_engineering/composition.py`: extend the import on line 21 and add the registration beside the others (after `RE_GUARDED_PROFILE`):

```python
from reverse_engineering.profiles import (
    EVIDENCE_ISOLATED_PROFILE,
    RE_DEEP_AGENTIC_PROFILE,
    RE_GUARDED_PROFILE,
)
```
```python
    builder.add_runtime_profile(RE_DEEP_AGENTIC_PROFILE)
```

- [ ] **Step 6: Add the one-line prompt note**

In `src/reverse_engineering/prompts/dotnet_analyst.md`, under the `Rules:` list, add:

```markdown
- If the system notes a **repeated failure** (the same approach failing with the
  same error several times), treat it as authoritative: stop retrying that
  approach and pivot to a different technique or layer.
```

- [ ] **Step 7: Run the profile test to verify it passes**

Run: `rtk uv run pytest tests/reverse_engineering/test_re_deep_agentic_profile.py -q`
Expected: PASS (4 tests).

- [ ] **Step 8: Full gate**

Run: `rtk make check`
Expected: lint + format-check + type-check clean; full suite green (prior 1386 + the new thrash/profile tests). The catalog freeze in `composition.py` must still validate (the new profile is referenced by `dotnet_analyst`, so it is reachable; `re_guarded` remains referenced by the other agents). Fix any finding inline (`rtk uv run --extra dev ruff format <files>`).

- [ ] **Step 9: Commit**

```bash
rtk git add src/reverse_engineering/profiles.py src/reverse_engineering/agents/dotnet_analyst.py src/reverse_engineering/composition.py src/reverse_engineering/prompts/dotnet_analyst.md tests/reverse_engineering/test_re_deep_agentic_profile.py
rtk git commit -m "feat(deobf): re_deep_agentic profile wires the thrash detector onto dotnet_analyst"
```

---

## Self-Review

**1. Spec coverage** (against the slice-1 design in the session analysis):
- Detect repeated same-approach/same-failure `run_python` calls → Task 1 signature + Task 2 Monitor. ✓
- Inject a decisive "pivot, don't retry" directive on the 3rd strike → Task 3 Advisor. ✓
- Scope to the deep-agentic analyst without touching the 11 shared-profile agents → Task 4 dedicated `re_deep_agentic` profile. ✓
- Respect the enforced ordering invariants (Monitor before sanitizer; compactor last) → Task 4 test + `make check`. ✓
- False-positive guard (flag-varying that still hits the same crash strikes; genuinely different failures reset) → Task 1 `test_signature_*` + Task 2 `test_different_failure_resets_the_streak`. ✓
- Generalization (no sample specifics in the advisory) → Task 3 `test_advisor_names_no_sample_specifics`. ✓

**2. Placeholder scan:** no TBD/TODO; every step ships real code, exact edits, and runnable commands. ✓

**3. Type consistency:** `classify_approach`/`classify_failure`/`thrash_signature` signatures match between Task 1 def and Task 2 use; `record_run_python_thrash` keyword-only params match the `compose_after_tool` call convention (`tool=`, `args=`, `tool_context=`, `tool_response=`); `advise_on_thrash(callback_context, llm_request)` matches ADK's before-model positional call; state-key names identical across state.py, thrash.py, and both test modules. ✓

## Known limitations (out of scope for slice-1, by design)
- Approach classification is coarse (dominant tool token), not a full AST parse — sufficient for equality-based streak detection and cheap; revisit only if a real run log shows a misclassification.
- The advisory re-appends each turn while the streak stays ≥ threshold (escalating pressure), following the `turn_limit` precedent. If a live run shows context bloat, add a "advised-for-signature" latch so it fires once per exhausted approach.
- Priority ranking of this mechanism vs. the objective-restatement advisor (slice-1 mechanism #2) is reasoned, not measured — the three GLM run logs would confirm it. Bring them into the session to re-rank before building slice-2.
