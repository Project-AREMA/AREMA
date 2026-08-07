# Per-Model Token Accounting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Capture LLM token usage per model across a run and emit a deterministic **Token Usage & Cost** section as a separate final message right after the pipeline's report.

**Architecture:** A new core-managed `after_model` callback seam captures `usage_metadata` for every `LlmAgent` (gated on the existing `record_metrics` profile flag — transparent, zero per-agent code). Pure core functions fold, price, and render the usage. A deterministic `_TokenUsageReporter` BaseAgent, appended once as the last sub-agent of a pipeline, emits the section and writes a structured record to state.

**Tech Stack:** Python 3.12+, Google ADK (`LlmAgent`/`SequentialAgent`/`BaseAgent`, callback chain), `google.genai.types` usage metadata, Pydantic `Settings`, pytest.

**Spec:** `docs/superpowers/specs/2026-07-31-per-model-token-accounting-design.md`

## Global Constraints

- **Deterministic, code-computed** — numbers never come from an LLM.
- **Semantic columns (per model):** `Input`, `Cached`, `Output`, `Thinking`, `Total`, `Est. cost`.
- **Field mapping** from `google.genai.types.GenerateContentResponseUsageMetadata` (read by `getattr`, missing → `0`):
  - `Input = prompt_token_count − cached_content_token_count`
  - `Cached = cached_content_token_count`
  - `Output = candidates_token_count`
  - `Thinking = thoughts_token_count`
  - `Total = Input + Cached + Output + Thinking`; **tested invariant:** equals `total_token_count` for a fixture sample.
  - `usage_metadata` absent → skip the whole sample (accumulate nothing).
- **Cost formula** (rates per **1,000,000** tokens): `cost = (Input·in + Cached·cached + (Output+Thinking)·out) / 1e6`. Thinking billed at output rate.
- **Unpriced model:** cost cell `?`, excluded from the cost total, section notes `(excludes N unpriced model(s): <ids>)`.
- **Run-scoping:** accumulator is `{"run_id": …, "by_model": {…}}`; a sample whose current `run_id` differs re-initializes it.
- **State keys** (in `SessionKeys`): `CURRENT_MODEL = "_runtime:current_model"`, `MODEL_USAGE = "_runtime:model_usage"`, `TOKEN_USAGE_RECORD = "token_usage_json"`.
- **Reporter placement:** last entry of a pipeline's `sub_agent_ids`; emits a **separate** message (own `Event` with content), never merged into the report agent's text.
- **Price override:** env `AREMA_MODEL_PRICE_OVERRIDES` (JSON `{model: {input, cached, output}}`, per-1M), merged over bundled defaults; malformed → logged + ignored (fail-open to defaults).
- **Fail-open everywhere** — capture/pricing failures log and swallow; never abort a run.
- **Neutrality:** all capture/accounting/reporter code under `src/arema/`; only the malware domain references the reporter (registration + one `sub_agent_ids` line). `composition.py` stays neutral.
- **ADK annotation rule:** never bare `typing.Any` as a tool/callback param annotation; never `isinstance(state, dict)` on ADK `State` (duck-type `.get`/`__setitem__`).
- **Commits:** plain `git commit` (local `commit.gpgsign=false` already set).

---

## File Structure

**Create (core, neutral):**
- `src/arema/runtime/token_pricing.py` — `ModelPrice`, `DEFAULT_MODEL_PRICES`, `PriceTable`.
- `src/arema/runtime/token_usage.py` — `UsageSample`, `usage_sample_from_metadata`, `accumulate_usage`, `render_usage_markdown`, `build_usage_record`.
- `tests/unit/runtime/test_token_pricing.py`
- `tests/unit/runtime/test_token_usage.py`
- `tests/unit/runtime/test_after_model_seam.py`
- `tests/unit/runtime/test_token_usage_reporter.py`

**Create (domain):**
- `src/malware_analyst/agents/token_usage_reporter.py` — reporter `AgentDescriptor`.
- `tests/malware_analyst/test_token_usage_wiring.py`

**Modify (core):**
- `src/arema/registry/descriptors.py` — add `AfterModelCallback` Protocol.
- `src/arema/runtime/callbacks/chain.py` — `CallbackChain.after_model` (+`empty()`); append token recorder in `build_callback_chain`.
- `src/arema/runtime/agent_factory.py` — wire `after_model_callback`; add `_TokenUsageReporter` + `build_token_usage_reporter`.
- `src/arema/runtime/callbacks/metrics.py` — before-model model stash + `make_model_usage_token_recorder`.
- `src/arema/runtime/callbacks/roles.py` — `ROLE_RECORD_MODEL_TOKENS`.
- `src/arema/runtime/sessions.py` — three new `SessionKeys`.
- `src/arema/core/config.py` — `model_price_overrides` setting (env `AREMA_MODEL_PRICE_OVERRIDES`).

**Modify (domain):**
- `src/malware_analyst/composition.py` — register the reporter descriptor.
- `src/malware_analyst/agents/malware_analyst.py` — append `"token_usage_reporter"` to `sub_agent_ids`.

Execution order T1→T7 satisfies all dependencies.

---

### Task 1: `after_model` chain seam (descriptors + chain + factory)

Establishes the seam that lets any callback observe an `LlmResponse`. No recorder yet — the seam ships empty and is exercised structurally.

**Files:**
- Modify: `src/arema/registry/descriptors.py` (add `AfterModelCallback` Protocol near the other callback Protocols, ~line 105-206)
- Modify: `src/arema/runtime/callbacks/chain.py` (`CallbackChain` dataclass ~108-133; `build_callback_chain` ~187-263)
- Modify: `src/arema/runtime/agent_factory.py` (`build_llm_agent` ~197-235; add ADK `AfterModelCallback` type import under `TYPE_CHECKING`)
- Test: `tests/unit/runtime/test_after_model_seam.py`

**Interfaces:**
- Consumes: existing `CallbackChain`, `build_callback_chain`, `build_llm_agent`.
- Produces:
  - `descriptors.AfterModelCallback` — Protocol, keyword-invoked `(callback_context: CallbackContext, llm_response: LlmResponse) -> Awaitable[LlmResponse | None] | LlmResponse | None`.
  - `CallbackChain.after_model: tuple[AfterModelCallback, ...]` (required field; `empty()` sets `()`).
  - `build_llm_agent` wires `after_model_callback=list(chain.after_model)`.

- [ ] **Step 1: Write the failing test**

`tests/unit/runtime/test_after_model_seam.py`:
```python
from __future__ import annotations

from arema.runtime.callbacks.chain import CallbackChain, build_callback_chain
from arema.runtime.services import RuntimeServices


def test_empty_chain_has_after_model() -> None:
    chain = CallbackChain.empty()
    assert chain.after_model == ()


def test_build_chain_after_model_is_tuple() -> None:
    # A profile with metrics off still yields a valid (empty) after_model tuple.
    from arema.registry.descriptors import RuntimeProfile

    profile = RuntimeProfile(id="p", record_metrics=False)
    chain = build_callback_chain(profile, services=RuntimeServices.default(), tools={})
    assert isinstance(chain.after_model, tuple)


def test_llm_agent_wires_after_model_callback() -> None:
    from arema.registry.descriptors import RuntimeProfile
    from arema.runtime.agent_factory import AgentBuildContext, build_llm_agent

    profile = RuntimeProfile(id="p")
    chain = build_callback_chain(profile, services=RuntimeServices.default(), tools={})
    # Minimal build context with a string model (no provider call at construction).
    from arema.registry.descriptors import AgentDescriptor

    descriptor = AgentDescriptor(
        id="a", name="a", description="d", prompt_id="a",
        factory=build_llm_agent, runtime_profile_id="p",
    )
    ctx = AgentBuildContext(
        descriptor=descriptor, profile=profile, model="gemini-2.0-flash",
        instruction="hi", tools=(), sub_agents=(), chain=chain,
    )
    agent = build_llm_agent(ctx)
    # ADK stores the list under after_model_callback.
    assert list(agent.after_model_callback or []) == list(chain.after_model)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/runtime/test_after_model_seam.py -v`
Expected: FAIL — `CallbackChain` has no attribute `after_model`.

- [ ] **Step 3: Add the `AfterModelCallback` Protocol**

In `descriptors.py`, after `BeforeModelCallback` (mirror its shape; ADK invokes by keyword `callback_context=`, `llm_response=`):
```python
class AfterModelCallback(Protocol):
    """One ADK after-model callback, synchronous or asynchronous.

    ADK invokes after-model callbacks by keyword (``callback_context=...``,
    ``llm_response=...``), so the parameter names below are part of the
    contract and must not be positional-only.
    """

    def __call__(
        self,
        callback_context: CallbackContext,
        llm_response: LlmResponse,
    ) -> Awaitable[LlmResponse | None] | LlmResponse | None:
        """Optionally replace a completed model response."""
        ...
```
Ensure `LlmResponse` is importable under `TYPE_CHECKING` (it already is in this module for `BeforeModelCallback`).

- [ ] **Step 4: Add `after_model` to `CallbackChain`**

In `chain.py`: add the field to the frozen dataclass and to `empty()`; import the type under `TYPE_CHECKING`.
```python
# in the TYPE_CHECKING import block of chain.py, add AfterModelCallback:
from arema.registry.descriptors import (
    AfterModelCallback,
    AfterToolCallback,
    BeforeModelCallback,
    BeforeToolCallback,
    RuntimeProfile,
    ToolDescriptor,
    ToolErrorCallback,
)

@dataclass(frozen=True, slots=True)
class CallbackChain:
    before_model: tuple[BeforeModelCallback, ...]
    after_model: tuple[AfterModelCallback, ...]
    before_tool: tuple[BeforeToolCallback, ...]
    after_tool: tuple[AfterToolCallback, ...]
    on_tool_error: tuple[ToolErrorCallback, ...]
    on_model_error: tuple[ModelErrorCallback, ...]

    @classmethod
    def empty(cls) -> CallbackChain:
        return cls(
            before_model=(),
            after_model=(),
            before_tool=(),
            after_tool=(),
            on_tool_error=(),
            on_model_error=(),
        )
```
In `build_callback_chain`, construct the returned `CallbackChain(...)` with `after_model=()` (recorder is added in Task 5). Place the `after_model=` argument right after `before_model=`.

- [ ] **Step 5: Wire `after_model_callback` in `build_llm_agent`**

In `agent_factory.py` `TYPE_CHECKING` block, add the ADK alias:
```python
from google.adk.agents.llm_agent import (
    AfterModelCallback as AdkAfterModelCallback,
)
```
In `build_llm_agent`, add to the `_CoercedLlmAgent(...)` construction (right after `before_model_callback=`):
```python
        after_model_callback=cast("AdkAfterModelCallback", list(chain.after_model)),
```

- [ ] **Step 6: Update every other `CallbackChain(...)` construction site**

Run: `rtk grep -rn "CallbackChain(" src/ tests/`
For each direct constructor call (outside `empty()` and `build_callback_chain`, which are done), add `after_model=()`. This is a required field with no default (no backward-compat shims).

- [ ] **Step 7: Run tests to verify they pass**

Run: `uv run pytest tests/unit/runtime/test_after_model_seam.py tests/unit/runtime/ -v`
Expected: PASS. Then `rtk make type-check` to confirm the Protocol + casts type-check.

- [ ] **Step 8: Commit**

```bash
git add src/arema/registry/descriptors.py src/arema/runtime/callbacks/chain.py src/arema/runtime/agent_factory.py tests/unit/runtime/test_after_model_seam.py
git commit -m "feat(runtime): add after_model callback seam to the chain and LlmAgent"
```

---

### Task 2: Pricing (`token_pricing.py`) + Settings override

**Files:**
- Create: `src/arema/runtime/token_pricing.py`
- Modify: `src/arema/core/config.py` (add `model_price_overrides`)
- Test: `tests/unit/runtime/test_token_pricing.py`

**Interfaces:**
- Consumes: `arema.core.config.Settings`.
- Produces:
  - `ModelPrice(input: float, cached: float, output: float)` — per 1M tokens (frozen).
  - `DEFAULT_MODEL_PRICES: dict[str, ModelPrice]` — bundled, keyed by **unqualified** model id.
  - `PriceTable` with `.cost_for(model: str, *, input: int, cached: int, output: int, thinking: int) -> float | None` (None = unpriced) and constructor `PriceTable.from_settings(settings) -> PriceTable`.
  - `Settings.model_price_overrides: dict[str, dict[str, float]]` (env `AREMA_MODEL_PRICE_OVERRIDES`, JSON).

- [ ] **Step 1: Write the failing test**

`tests/unit/runtime/test_token_pricing.py`:
```python
from __future__ import annotations

from arema.runtime.token_pricing import DEFAULT_MODEL_PRICES, ModelPrice, PriceTable


def test_cost_for_known_model() -> None:
    table = PriceTable(DEFAULT_MODEL_PRICES)
    price = DEFAULT_MODEL_PRICES["claude-opus-4-8"]
    cost = table.cost_for("claude-opus-4-8", input=1_000_000, cached=0, output=0, thinking=0)
    assert cost == price.input  # 1M input tokens == exactly one input-rate unit


def test_cost_folds_thinking_into_output_rate() -> None:
    table = PriceTable({"m": ModelPrice(input=10.0, cached=1.0, output=20.0)})
    cost = table.cost_for("m", input=0, cached=0, output=500_000, thinking=500_000)
    assert cost == 20.0  # (500k + 500k) * 20/1e6


def test_provider_prefixed_model_normalizes_to_unqualified() -> None:
    table = PriceTable({"claude-opus-4-8": ModelPrice(15.0, 1.5, 75.0)})
    assert table.cost_for("anthropic/claude-opus-4-8", input=1_000_000, cached=0, output=0, thinking=0) == 15.0


def test_unpriced_model_returns_none() -> None:
    table = PriceTable({})
    assert table.cost_for("mystery-model", input=100, cached=0, output=0, thinking=0) is None


def test_override_merges_over_defaults() -> None:
    from arema.core.config import Settings

    settings = Settings(model_price_overrides={"claude-opus-4-8": {"input": 1.0, "cached": 0.5, "output": 2.0}})
    table = PriceTable.from_settings(settings)
    assert table.cost_for("claude-opus-4-8", input=1_000_000, cached=0, output=0, thinking=0) == 1.0


def test_malformed_override_is_ignored() -> None:
    from arema.core.config import Settings

    settings = Settings(model_price_overrides={"claude-opus-4-8": {"input": "not-a-number"}})  # type: ignore[dict-item]
    table = PriceTable.from_settings(settings)  # must not raise
    # falls back to the bundled default for that model
    assert table.cost_for("claude-opus-4-8", input=1_000_000, cached=0, output=0, thinking=0) == DEFAULT_MODEL_PRICES["claude-opus-4-8"].input
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/runtime/test_token_pricing.py -v`
Expected: FAIL — module `arema.runtime.token_pricing` does not exist.

- [ ] **Step 3: Add the `model_price_overrides` setting**

In `core/config.py` `Settings`, add (follow the existing field/env pattern in that file; AREMA uses an env prefix — match it so the env var is `AREMA_MODEL_PRICE_OVERRIDES`):
```python
    model_price_overrides: dict[str, dict[str, float]] = Field(
        default_factory=dict,
        description="Per-model price overrides (per 1M tokens): {model: {input, cached, output}}.",
    )
```
Pydantic parses a JSON object from the env var into this dict automatically. Confirm the existing `Field`/import is already present in the file.

- [ ] **Step 4: Write `token_pricing.py`**

```python
"""Neutral per-model token pricing.

Rates are expressed per 1,000,000 tokens. Thinking tokens are billed at the
output rate. A model absent from the table is *unpriced*: ``cost_for`` returns
``None`` and callers must exclude it from any cost total rather than assume zero.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from arema.core.logging import get_logger

if TYPE_CHECKING:
    from arema.core.config import Settings

logger = get_logger(__name__)

_PER_MILLION = 1_000_000


@dataclass(frozen=True, slots=True)
class ModelPrice:
    """USD rates per 1,000,000 tokens."""

    input: float
    cached: float
    output: float


# Bundled defaults (USD per 1M tokens). Override per model via
# AREMA_MODEL_PRICE_OVERRIDES. Keyed by the unqualified model id.
DEFAULT_MODEL_PRICES: dict[str, ModelPrice] = {
    "claude-opus-4-8": ModelPrice(input=15.0, cached=1.5, output=75.0),
    "claude-sonnet-5": ModelPrice(input=3.0, cached=0.3, output=15.0),
    "claude-haiku-4-5": ModelPrice(input=1.0, cached=0.1, output=5.0),
}


def _unqualified(model: str) -> str:
    """Strip a provider prefix: ``anthropic/claude-opus-4-8`` -> ``claude-opus-4-8``."""
    return model.rsplit("/", 1)[-1]


class PriceTable:
    """An immutable price lookup with provider-prefix normalization."""

    def __init__(self, prices: Mapping[str, ModelPrice]) -> None:
        self._prices = dict(prices)

    @classmethod
    def from_settings(cls, settings: Settings) -> PriceTable:
        prices = dict(DEFAULT_MODEL_PRICES)
        for model, raw in (settings.model_price_overrides or {}).items():
            try:
                prices[model] = ModelPrice(
                    input=float(raw["input"]),
                    cached=float(raw["cached"]),
                    output=float(raw["output"]),
                )
            except (KeyError, TypeError, ValueError):
                logger.warning("ignoring malformed price override", model=model)
        return cls(prices)

    def _lookup(self, model: str) -> ModelPrice | None:
        return self._prices.get(model) or self._prices.get(_unqualified(model))

    def cost_for(
        self, model: str, *, input: int, cached: int, output: int, thinking: int
    ) -> float | None:
        """Return USD cost for the counts, or ``None`` when the model is unpriced."""
        price = self._lookup(model)
        if price is None:
            return None
        return (
            input * price.input
            + cached * price.cached
            + (output + thinking) * price.output
        ) / _PER_MILLION
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/unit/runtime/test_token_pricing.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/arema/runtime/token_pricing.py src/arema/core/config.py tests/unit/runtime/test_token_pricing.py
git commit -m "feat(runtime): bundled per-model price table with env overrides"
```

---

### Task 3: Usage sample + accumulator (`token_usage.py` part 1) + SessionKeys

**Files:**
- Create: `src/arema/runtime/token_usage.py` (types + `usage_sample_from_metadata` + `accumulate_usage`)
- Modify: `src/arema/runtime/sessions.py` (three keys)
- Test: `tests/unit/runtime/test_token_usage.py` (sample + accumulator sections)

**Interfaces:**
- Consumes: `SessionKeys`.
- Produces:
  - `UsageSample(input, cached, output, thinking)` frozen; `.total` property.
  - `usage_sample_from_metadata(metadata: object) -> UsageSample | None` (None when metadata is falsy/unreadable; missing counts → 0).
  - `accumulate_usage(state: object, model: str, sample: UsageSample, run_id: str | None) -> None` — reads/writes `SessionKeys.MODEL_USAGE`, run-scoped reset.
  - `SessionKeys.CURRENT_MODEL`, `SessionKeys.MODEL_USAGE`, `SessionKeys.TOKEN_USAGE_RECORD`.

- [ ] **Step 1: Write the failing test**

`tests/unit/runtime/test_token_usage.py`:
```python
from __future__ import annotations

from types import SimpleNamespace

from arema.runtime.sessions import SessionKeys
from arema.runtime.token_usage import (
    UsageSample,
    accumulate_usage,
    usage_sample_from_metadata,
)


def _meta(prompt: int, cached: int, candidates: int, thoughts: int, total: int) -> object:
    return SimpleNamespace(
        prompt_token_count=prompt,
        cached_content_token_count=cached,
        candidates_token_count=candidates,
        thoughts_token_count=thoughts,
        total_token_count=total,
    )


def test_sample_maps_fields_and_total_matches_provider() -> None:
    meta = _meta(prompt=812004, cached=640110, candidates=41220, thoughts=12880, total=866104)
    sample = usage_sample_from_metadata(meta)
    assert sample == UsageSample(input=171894, cached=640110, output=41220, thinking=12880)
    # invariant: computed total equals the provider's total_token_count
    assert sample.total == meta.total_token_count


def test_sample_missing_fields_default_to_zero() -> None:
    sample = usage_sample_from_metadata(SimpleNamespace(prompt_token_count=10, candidates_token_count=5))
    assert sample == UsageSample(input=10, cached=0, output=5, thinking=0)


def test_sample_none_when_metadata_absent() -> None:
    assert usage_sample_from_metadata(None) is None


class _State:
    """Minimal dict-backed stand-in for ADK State (duck-typed .get/__setitem__)."""

    def __init__(self) -> None:
        self._d: dict[str, object] = {}

    def get(self, key: str, default: object = None) -> object:
        return self._d.get(key, default)

    def __setitem__(self, key: str, value: object) -> None:
        self._d[key] = value


def test_accumulate_merges_same_model() -> None:
    state = _State()
    accumulate_usage(state, "opus", UsageSample(1, 2, 3, 4), run_id="r1")
    accumulate_usage(state, "opus", UsageSample(10, 20, 30, 40), run_id="r1")
    acc = state.get(SessionKeys.MODEL_USAGE)
    assert acc["run_id"] == "r1"
    assert acc["by_model"]["opus"] == {"input": 11, "cached": 22, "output": 33, "thinking": 44}


def test_accumulate_resets_on_new_run() -> None:
    state = _State()
    accumulate_usage(state, "opus", UsageSample(1, 1, 1, 1), run_id="r1")
    accumulate_usage(state, "opus", UsageSample(5, 5, 5, 5), run_id="r2")
    acc = state.get(SessionKeys.MODEL_USAGE)
    assert acc["run_id"] == "r2"
    assert acc["by_model"] == {"opus": {"input": 5, "cached": 5, "output": 5, "thinking": 5}}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/runtime/test_token_usage.py -v`
Expected: FAIL — module/keys do not exist.

- [ ] **Step 3: Add SessionKeys**

In `sessions.py` `SessionKeys(StrEnum)`, alongside the existing `_runtime:` keys:
```python
    CURRENT_MODEL = "_runtime:current_model"
    MODEL_USAGE = "_runtime:model_usage"
    TOKEN_USAGE_RECORD = "token_usage_json"
```

- [ ] **Step 4: Write `token_usage.py` (sample + accumulator)**

```python
"""Neutral per-model token accounting: sampling, accumulation, rendering.

All numbers are computed from provider usage metadata; nothing here asks an LLM
to count anything. State access duck-types ``.get``/``__setitem__`` because ADK's
``State`` is a proxy, not a ``dict``.
"""

from __future__ import annotations

from dataclasses import dataclass

from arema.core.logging import get_logger
from arema.runtime.sessions import SessionKeys

logger = get_logger(__name__)

_COUNTERS = ("input", "cached", "output", "thinking")


@dataclass(frozen=True, slots=True)
class UsageSample:
    """One model call's token counts (semantic columns)."""

    input: int
    cached: int
    output: int
    thinking: int

    @property
    def total(self) -> int:
        return self.input + self.cached + self.output + self.thinking


def _count(metadata: object, name: str) -> int:
    value = getattr(metadata, name, 0) or 0
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def usage_sample_from_metadata(metadata: object) -> UsageSample | None:
    """Map a ``GenerateContentResponseUsageMetadata`` to a :class:`UsageSample`.

    Returns ``None`` when ``metadata`` is falsy. Missing counts default to 0.
    ``Input`` is the *uncached* prompt (``prompt − cached``), clamped at 0.
    """
    if not metadata:
        return None
    cached = _count(metadata, "cached_content_token_count")
    prompt = _count(metadata, "prompt_token_count")
    return UsageSample(
        input=max(0, prompt - cached),
        cached=cached,
        output=_count(metadata, "candidates_token_count"),
        thinking=_count(metadata, "thoughts_token_count"),
    )


def accumulate_usage(
    state: object, model: str, sample: UsageSample, run_id: str | None
) -> None:
    """Fold ``sample`` into ``state[MODEL_USAGE]`` under ``model``.

    The accumulator is ``{"run_id": run_id, "by_model": {model: {counters}}}``.
    A sample whose ``run_id`` differs from the stored one re-initializes it, so a
    reused session running a second analysis never double-counts.
    """
    getter = getattr(state, "get", None)
    setter = getattr(state, "__setitem__", None)
    if not callable(getter) or not callable(setter):
        return
    acc = getter(SessionKeys.MODEL_USAGE, None)
    if not isinstance(acc, dict) or acc.get("run_id") != run_id:
        acc = {"run_id": run_id, "by_model": {}}
    by_model = acc["by_model"]
    row = by_model.get(model) or dict.fromkeys(_COUNTERS, 0)
    for name in _COUNTERS:
        row[name] += getattr(sample, name)
    by_model[model] = row
    setter(SessionKeys.MODEL_USAGE, acc)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/unit/runtime/test_token_usage.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/arema/runtime/token_usage.py src/arema/runtime/sessions.py tests/unit/runtime/test_token_usage.py
git commit -m "feat(runtime): usage sampling + run-scoped per-model accumulator"
```

---

### Task 4: Renderers (`token_usage.py` part 2)

**Files:**
- Modify: `src/arema/runtime/token_usage.py` (add `render_usage_markdown`, `build_usage_record`)
- Modify: `tests/unit/runtime/test_token_usage.py` (add render/record tests)

**Interfaces:**
- Consumes: `UsageSample` counters shape, `PriceTable` (Task 2).
- Produces:
  - `render_usage_markdown(by_model: Mapping[str, Mapping[str, int]], prices: PriceTable) -> str`
  - `build_usage_record(by_model: Mapping[str, Mapping[str, int]], prices: PriceTable, run_id: str | None) -> dict`
  - Both accept the accumulator's `by_model` mapping (`{model: {input,cached,output,thinking}}`).

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/runtime/test_token_usage.py`:
```python
from arema.runtime.token_pricing import ModelPrice, PriceTable
from arema.runtime.token_usage import build_usage_record, render_usage_markdown

_BY_MODEL = {
    "claude-opus-4-8": {"input": 171894, "cached": 640110, "output": 41220, "thinking": 12880},
    "claude-sonnet-5": {"input": 120300, "cached": 0, "output": 9880, "thinking": 0},
}
_PRICES = PriceTable({
    "claude-opus-4-8": ModelPrice(15.0, 1.5, 75.0),
    "claude-sonnet-5": ModelPrice(3.0, 0.3, 15.0),
})


def test_render_has_header_rows_and_bold_total() -> None:
    md = render_usage_markdown(_BY_MODEL, _PRICES)
    assert md.startswith("## Token Usage & Cost")
    assert "| claude-opus-4-8 |" in md
    assert "171,894" in md  # thousands separators
    assert "**Total**" in md


def test_render_flags_unpriced_and_excludes_from_total() -> None:
    by_model = {"mystery": {"input": 100, "cached": 0, "output": 10, "thinking": 0}}
    md = render_usage_markdown(by_model, PriceTable({}))
    assert "?" in md
    assert "excludes 1 unpriced model" in md
    assert "mystery" in md


def test_render_empty_accumulator_is_neutral_line() -> None:
    md = render_usage_markdown({}, _PRICES)
    assert "## Token Usage & Cost" in md
    assert "No model usage was recorded" in md


def test_build_record_shape_and_grand_total() -> None:
    rec = build_usage_record(_BY_MODEL, _PRICES, run_id="r1")
    assert rec["run_id"] == "r1"
    assert rec["by_model"]["claude-opus-4-8"]["total"] == 866104
    assert rec["grand_total"]["total"] == 996284
    assert rec["unpriced_models"] == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/runtime/test_token_usage.py -k "render or record" -v`
Expected: FAIL — functions undefined.

- [ ] **Step 3: Implement the renderers**

Append to `token_usage.py` (import `PriceTable` under `TYPE_CHECKING`, `Mapping` from `collections.abc`):
```python
def _row_total(row: Mapping[str, int]) -> int:
    return sum(row.get(c, 0) for c in _COUNTERS)


def _fmt(n: int) -> str:
    return f"{n:,}"


def _priced(by_model, prices):
    """Yield (model, row, total, cost|None) sorted by model id."""
    for model in sorted(by_model):
        row = by_model[model]
        cost = prices.cost_for(
            model,
            input=row.get("input", 0),
            cached=row.get("cached", 0),
            output=row.get("output", 0),
            thinking=row.get("thinking", 0),
        )
        yield model, row, _row_total(row), cost


def render_usage_markdown(by_model, prices) -> str:
    header = "## Token Usage & Cost"
    if not by_model:
        return f"{header}\n\n_No model usage was recorded for this run._"
    lines = [
        header,
        "",
        "| Model | Input | Cached | Output | Thinking | Total | Est. cost |",
        "|-------|-------|--------|--------|----------|-------|-----------|",
    ]
    totals = dict.fromkeys(_COUNTERS, 0)
    cost_total = 0.0
    unpriced: list[str] = []
    for model, row, total, cost in _priced(by_model, prices):
        for c in _COUNTERS:
            totals[c] += row.get(c, 0)
        cost_cell = "?" if cost is None else f"${cost:,.2f}"
        if cost is None:
            unpriced.append(model)
        else:
            cost_total += cost
        lines.append(
            f"| {model} | {_fmt(row.get('input', 0))} | {_fmt(row.get('cached', 0))} "
            f"| {_fmt(row.get('output', 0))} | {_fmt(row.get('thinking', 0))} "
            f"| {_fmt(total)} | {cost_cell} |"
        )
    grand_total = sum(totals.values())
    lines.append(
        f"| **Total** | {_fmt(totals['input'])} | {_fmt(totals['cached'])} "
        f"| {_fmt(totals['output'])} | {_fmt(totals['thinking'])} "
        f"| {_fmt(grand_total)} | **${cost_total:,.2f}** |"
    )
    if unpriced:
        lines.append("")
        lines.append(f"_(excludes {len(unpriced)} unpriced model(s): {', '.join(unpriced)})_")
    return "\n".join(lines)


def build_usage_record(by_model, prices, run_id: str | None) -> dict:
    out_models: dict[str, dict] = {}
    totals = dict.fromkeys(_COUNTERS, 0)
    cost_total = 0.0
    unpriced: list[str] = []
    for model, row, total, cost in _priced(by_model, prices):
        for c in _COUNTERS:
            totals[c] += row.get(c, 0)
        entry = {c: row.get(c, 0) for c in _COUNTERS}
        entry["total"] = total
        if cost is None:
            entry["cost_usd"] = None
            unpriced.append(model)
        else:
            entry["cost_usd"] = round(cost, 2)
            cost_total += cost
        out_models[model] = entry
    grand = {c: totals[c] for c in _COUNTERS}
    grand["total"] = sum(totals.values())
    grand["cost_usd"] = round(cost_total, 2)
    return {"run_id": run_id, "by_model": out_models, "grand_total": grand, "unpriced_models": unpriced}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/runtime/test_token_usage.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/arema/runtime/token_usage.py tests/unit/runtime/test_token_usage.py
git commit -m "feat(runtime): render per-model token usage table + structured record"
```

---

### Task 5: Metrics callbacks — before-model stash + after-model recorder + chain wiring

**Files:**
- Modify: `src/arema/runtime/callbacks/metrics.py` (stash `CURRENT_MODEL`; add `make_model_usage_token_recorder`)
- Modify: `src/arema/runtime/callbacks/roles.py` (add `ROLE_RECORD_MODEL_TOKENS`)
- Modify: `src/arema/runtime/callbacks/chain.py` (`build_callback_chain` appends the recorder to `after_model` when `record_metrics`)
- Test: extend `tests/unit/runtime/test_after_model_seam.py`

**Interfaces:**
- Consumes: `accumulate_usage`, `usage_sample_from_metadata` (T3), `SessionKeys.CURRENT_MODEL`, after_model seam (T1).
- Produces: `make_model_usage_token_recorder(services: RuntimeServices) -> AfterModelCallback`.

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/runtime/test_after_model_seam.py`:
```python
import asyncio
from types import SimpleNamespace

from arema.runtime.callbacks.metrics import make_model_usage_token_recorder
from arema.runtime.sessions import SessionKeys
from arema.runtime.token_usage import UsageSample  # noqa: F401


class _RecState:
    def __init__(self, initial=None):
        self._d = dict(initial or {})

    def get(self, key, default=None):
        return self._d.get(key, default)

    def __setitem__(self, key, value):
        self._d[key] = value


def _ctx(state):
    return SimpleNamespace(state=state, agent_name="a")


def test_after_model_recorder_accumulates() -> None:
    state = _RecState({SessionKeys.CURRENT_MODEL: "opus", SessionKeys.RUN_ID: "r1"})
    recorder = make_model_usage_token_recorder(RuntimeServices.default())
    resp = SimpleNamespace(usage_metadata=SimpleNamespace(
        prompt_token_count=100, cached_content_token_count=40,
        candidates_token_count=10, thoughts_token_count=0, total_token_count=110))
    asyncio.run(recorder(callback_context=_ctx(state), llm_response=resp))
    acc = state.get(SessionKeys.MODEL_USAGE)
    assert acc["by_model"]["opus"] == {"input": 60, "cached": 40, "output": 10, "thinking": 0}


def test_after_model_recorder_fail_open_no_usage() -> None:
    state = _RecState({SessionKeys.CURRENT_MODEL: "opus"})
    recorder = make_model_usage_token_recorder(RuntimeServices.default())
    resp = SimpleNamespace(usage_metadata=None)
    asyncio.run(recorder(callback_context=_ctx(state), llm_response=resp))  # no raise
    assert state.get(SessionKeys.MODEL_USAGE) is None


def test_after_model_recorder_fail_open_no_model() -> None:
    state = _RecState({SessionKeys.RUN_ID: "r1"})  # no CURRENT_MODEL
    recorder = make_model_usage_token_recorder(RuntimeServices.default())
    resp = SimpleNamespace(usage_metadata=SimpleNamespace(
        prompt_token_count=1, candidates_token_count=1, total_token_count=2))
    asyncio.run(recorder(callback_context=_ctx(state), llm_response=resp))
    assert state.get(SessionKeys.MODEL_USAGE) is None


def test_chain_includes_token_recorder_when_metrics_on() -> None:
    from arema.registry.descriptors import RuntimeProfile
    from arema.runtime.callbacks.roles import ROLE_RECORD_MODEL_TOKENS, callback_role

    profile = RuntimeProfile(id="p", record_metrics=True)
    chain = build_callback_chain(profile, services=RuntimeServices.default(), tools={})
    roles = [callback_role(cb) for cb in chain.after_model]
    assert ROLE_RECORD_MODEL_TOKENS in roles


def test_chain_excludes_token_recorder_when_metrics_off() -> None:
    from arema.registry.descriptors import RuntimeProfile

    profile = RuntimeProfile(id="p", record_metrics=False)
    chain = build_callback_chain(profile, services=RuntimeServices.default(), tools={})
    assert chain.after_model == ()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/runtime/test_after_model_seam.py -v`
Expected: FAIL — `make_model_usage_token_recorder` / `ROLE_RECORD_MODEL_TOKENS` undefined.

- [ ] **Step 3: Add the role marker**

In `roles.py`, add alongside the existing `ROLE_RECORD_MODEL_USAGE`:
```python
ROLE_RECORD_MODEL_TOKENS = "record_model_tokens"
```

- [ ] **Step 4: Stash the model in the before-model recorder**

In `metrics.py` `make_model_usage_recorder`'s `record_model_usage`, replace `del llm_request` with a stash (keep the existing call-count logic):
```python
        try:
            state = callback_context.state
            if state is None:
                return None
            model = getattr(llm_request, "model", None)
            if isinstance(model, str) and model:
                state[SessionKeys.CURRENT_MODEL] = model
            count = int(state.get(SessionKeys.MODEL_CALLS, 0)) + 1
            # ... unchanged ...
```

- [ ] **Step 5: Add the after-model token recorder**

In `metrics.py` (import `accumulate_usage`, `usage_sample_from_metadata`, `ROLE_RECORD_MODEL_TOKENS`, `with_role`):
```python
def make_model_usage_token_recorder(services: RuntimeServices) -> AfterModelCallback:
    """Build an after-model callback that folds token usage into the accumulator."""
    del services  # accumulation is state-only; sink emission is a future extension

    @with_role(ROLE_RECORD_MODEL_TOKENS)
    async def record_model_tokens(
        callback_context: CallbackContext,
        llm_response: LlmResponse,
    ) -> LlmResponse | None:
        try:
            state = getattr(callback_context, "state", None)
            if state is None:
                return None
            sample = usage_sample_from_metadata(getattr(llm_response, "usage_metadata", None))
            model = _state_str(state, SessionKeys.CURRENT_MODEL)
            if sample is None or model is None:
                return None
            accumulate_usage(state, model, sample, _state_str(state, SessionKeys.RUN_ID))
        except Exception:
            logger.warning("record_model_tokens failed - continuing", exc_info=True)
        return None

    return record_model_tokens
```
Add `AfterModelCallback` to the `TYPE_CHECKING` import from `arema.registry.descriptors`.

- [ ] **Step 6: Wire the recorder into `build_callback_chain`**

In `chain.py`, import `make_model_usage_token_recorder`, build an `after_model` list, and pass it to `CallbackChain(...)`:
```python
    after_model: list[AfterModelCallback] = []
    if profile.record_metrics:
        after_model.append(make_model_usage_token_recorder(services))
    # ... in the CallbackChain(...) construction:
        after_model=tuple(after_model),
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `uv run pytest tests/unit/runtime/test_after_model_seam.py -v && rtk make type-check`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/arema/runtime/callbacks/metrics.py src/arema/runtime/callbacks/roles.py src/arema/runtime/callbacks/chain.py tests/unit/runtime/test_after_model_seam.py
git commit -m "feat(runtime): capture per-model token usage via after_model recorder"
```

---

### Task 6: Deterministic reporter agent (`_TokenUsageReporter` + factory)

**Files:**
- Modify: `src/arema/runtime/agent_factory.py` (`_TokenUsageReporter` BaseAgent + `build_token_usage_reporter`)
- Test: `tests/unit/runtime/test_token_usage_reporter.py`

**Interfaces:**
- Consumes: `render_usage_markdown`, `build_usage_record` (T4), `PriceTable.from_settings` (T2), `SessionKeys.MODEL_USAGE`/`TOKEN_USAGE_RECORD`, `AgentBuildContext`.
- Produces: `build_token_usage_reporter(context: AgentBuildContext) -> BaseAgent` (registered via a domain descriptor in T7).

- [ ] **Step 1: Write the failing test**

`tests/unit/runtime/test_token_usage_reporter.py`:
```python
from __future__ import annotations

import asyncio
from types import SimpleNamespace

from arema.registry.descriptors import AgentDescriptor, RuntimeProfile
from arema.runtime.agent_factory import AgentBuildContext, build_token_usage_reporter
from arema.runtime.callbacks.chain import CallbackChain
from arema.runtime.sessions import SessionKeys


def _reporter():
    descriptor = AgentDescriptor(
        id="token_usage_reporter", name="token_usage_reporter",
        description="Renders per-model token usage.", prompt_id=None,
        factory=build_token_usage_reporter, runtime_profile_id="p",
    )
    ctx = AgentBuildContext(
        descriptor=descriptor, profile=RuntimeProfile(id="p"), model=None,
        instruction="", tools=(), sub_agents=(), chain=CallbackChain.empty(),
    )
    return build_token_usage_reporter(ctx)


def _run(agent, state):
    ctx = SimpleNamespace(session=SimpleNamespace(state=state), invocation_id="i", branch=None)

    async def collect():
        return [ev async for ev in agent._run_async_impl(ctx)]

    return asyncio.run(collect())


def test_reporter_emits_table_and_record() -> None:
    state = {SessionKeys.MODEL_USAGE: {"run_id": "r1", "by_model": {
        "claude-opus-4-8": {"input": 171894, "cached": 640110, "output": 41220, "thinking": 12880}}}}
    events = _run(_reporter(), state)
    assert len(events) == 1
    text = events[0].content.parts[0].text
    assert "## Token Usage & Cost" in text and "claude-opus-4-8" in text
    delta = events[0].actions.state_delta
    assert SessionKeys.TOKEN_USAGE_RECORD in delta
    assert delta[SessionKeys.TOKEN_USAGE_RECORD]["grand_total"]["total"] == 866104


def test_reporter_empty_accumulator_neutral_line() -> None:
    events = _run(_reporter(), {})
    assert len(events) == 1
    assert "No model usage was recorded" in events[0].content.parts[0].text
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/runtime/test_token_usage_reporter.py -v`
Expected: FAIL — `build_token_usage_reporter` undefined.

- [ ] **Step 3: Implement the reporter**

In `agent_factory.py` (near `_EscalationGate`; import `get_settings`, `PriceTable`, `render_usage_markdown`, `build_usage_record`, `SessionKeys`, `Content`/`Part` from `google.genai.types`):
```python
class _TokenUsageReporter(BaseAgent):
    """Deterministic final stage: render per-model token usage as one message."""

    async def _run_async_impl(self, ctx: InvocationContext) -> AsyncGenerator[Event, None]:
        state = ctx.session.state
        getter = getattr(state, "get", None)
        acc = getter(SessionKeys.MODEL_USAGE, None) if callable(getter) else None
        by_model = acc.get("by_model", {}) if isinstance(acc, dict) else {}
        run_id = acc.get("run_id") if isinstance(acc, dict) else None
        prices = PriceTable.from_settings(get_settings())
        markdown = render_usage_markdown(by_model, prices)
        record = build_usage_record(by_model, prices, run_id)
        yield Event(
            author=self.name,
            invocation_id=ctx.invocation_id,
            branch=ctx.branch,
            content=Content(role="model", parts=[Part(text=markdown)]),
            actions=EventActions(state_delta={SessionKeys.TOKEN_USAGE_RECORD: record}),
        )


def build_token_usage_reporter(context: AgentBuildContext) -> BaseAgent:
    """Construct the deterministic per-model token-usage reporter."""
    return _TokenUsageReporter(
        name=context.descriptor.name,
        description=context.descriptor.description,
        after_agent_callback=list(context.after_agent),
    )
```
Add `build_token_usage_reporter` to `__all__`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/runtime/test_token_usage_reporter.py -v && rtk make type-check`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/arema/runtime/agent_factory.py tests/unit/runtime/test_token_usage_reporter.py
git commit -m "feat(runtime): deterministic token-usage reporter agent"
```

---

### Task 7: Malware domain wiring

**Files:**
- Create: `src/malware_analyst/agents/token_usage_reporter.py`
- Modify: `src/malware_analyst/composition.py` (register the descriptor)
- Modify: `src/malware_analyst/agents/malware_analyst.py` (append to `sub_agent_ids`)
- Test: `tests/malware_analyst/test_token_usage_wiring.py`

**Interfaces:**
- Consumes: `build_token_usage_reporter` (T6), the malware composition builder.
- Produces: a registered `token_usage_reporter` agent that is the last stage of the malware pipeline.

- [ ] **Step 1: Write the failing test**

`tests/malware_analyst/test_token_usage_wiring.py`:
```python
from __future__ import annotations

from malware_analyst.agents.malware_analyst import MALWARE_ANALYST_DESCRIPTOR
from malware_analyst.agents.token_usage_reporter import TOKEN_USAGE_REPORTER_DESCRIPTOR


def test_reporter_is_last_pipeline_stage() -> None:
    assert MALWARE_ANALYST_DESCRIPTOR.sub_agent_ids[-1] == "token_usage_reporter"


def test_reporter_descriptor_is_deterministic_leaf() -> None:
    d = TOKEN_USAGE_REPORTER_DESCRIPTOR
    assert d.id == "token_usage_reporter"
    assert d.prompt_id is None
    assert d.factory.__name__ == "build_token_usage_reporter"


def test_reporter_registered_and_reachable_in_built_pipeline() -> None:
    # The package's autouse conftest pins a credential-free provider
    # (AREMA_LLM_PROVIDER=ollama) so the composition builds hermetically.
    from malware_analyst.composition import get_malware_analyst_composition

    root = get_malware_analyst_composition().root_agent
    assert [a.name for a in root.sub_agents][-1] == "token_usage_reporter"
    assert "token_usage_reporter" in get_malware_analyst_composition().catalog.agents
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/malware_analyst/test_token_usage_wiring.py -v`
Expected: FAIL — module/descriptor absent.

- [ ] **Step 3: Create the reporter descriptor**

`src/malware_analyst/agents/token_usage_reporter.py`:
```python
"""The token_usage_reporter descriptor: the malware pipeline's final stage.

Deterministic, prompt-less leaf that renders per-model token usage. The
rendering logic is domain-neutral (arema core); this descriptor only names the
stage and points at the neutral factory.
"""

from __future__ import annotations

from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_token_usage_reporter

TOKEN_USAGE_REPORTER_DESCRIPTOR = AgentDescriptor(
    id="token_usage_reporter",
    name="token_usage_reporter",
    description="Renders per-model token usage and cost as the final report section.",
    prompt_id=None,
    factory=build_token_usage_reporter,
    runtime_profile_id="safe_default",
)
```
(`safe_default` is confirmed present — `MALWARE_ANALYST_DESCRIPTOR` itself uses it. As a prompt-less leaf, the reporter gets `CallbackChain.empty()` regardless of the profile; the profile id only needs to resolve in the catalog.)

- [ ] **Step 4: Register + append + update the existing order test**

In `src/malware_analyst/composition.py`, add the import next to the other agent imports:
```python
from malware_analyst.agents.token_usage_reporter import TOKEN_USAGE_REPORTER_DESCRIPTOR
```
and register it immediately after the `MALWARE_REPORT_GENERATOR_DESCRIPTOR` line (line ~88):
```python
    builder.add_agent(MALWARE_REPORT_GENERATOR_DESCRIPTOR)
    builder.add_agent(TOKEN_USAGE_REPORTER_DESCRIPTOR)
```
In `src/malware_analyst/agents/malware_analyst.py`, append `"token_usage_reporter"` as the final `sub_agent_ids` entry (after `"malware_report_generator"`), and update the module docstring so it notes the pipeline ends with a deterministic token-usage reporter after the nine analysis stages (the reporter is an appendix, not a tenth analysis stage).

**Update the existing pipeline-order test** — `tests/malware_analyst/test_malware_analyst_composition.py::test_root_runs_nine_stages_in_order` asserts the sub-agent name list ends at `malware_report_generator`; add `"token_usage_reporter"` as the final entry of its expected list (rename the test to `..._runs_pipeline_stages_in_order` if you like). Without this, an existing test fails.

- [ ] **Step 5: Run tests + full domain suite**

Run: `uv run pytest tests/malware_analyst/ -v`
Expected: PASS (freeze validation accepts the new reachable leaf; the updated order test passes).

- [ ] **Step 6: End-to-end fixture (reporter over seeded pipeline state)**

Add to `tests/malware_analyst/test_token_usage_wiring.py` a test that builds the malware composition, resolves the built `token_usage_reporter` agent, runs it against a session state seeded with a two-model accumulator, and asserts the emitted event carries the table + `TOKEN_USAGE_RECORD`. (Reuse the `_run` helper pattern from `test_token_usage_reporter.py`.)

- [ ] **Step 7: Full gate**

Run: `rtk make check`
Expected: exit 0 — lint, format, type-check, and the whole suite (incl. neutrality/architecture guards) green.

- [ ] **Step 8: Commit**

```bash
git add src/malware_analyst/agents/token_usage_reporter.py src/malware_analyst/composition.py src/malware_analyst/agents/malware_analyst.py tests/malware_analyst/test_token_usage_wiring.py
git commit -m "feat(malware): append per-model token-usage reporter as the final pipeline stage"
```

---

## Self-Review Notes

- **Spec coverage:** capture seam (T1, T5), pricing + override (T2), sampling + run-scoped accumulator (T3), renderers + structured record (T4), deterministic separate-message reporter (T6), domain wiring/last-stage/neutrality/e2e (T7). Transparency (core-managed capture, one-line-per-pipeline render) is realized by gating on `record_metrics` in `build_callback_chain` (T5) and appending one `sub_agent_ids` entry (T7). All spec sections map to a task.
- **Type consistency:** `UsageSample` counters `(input, cached, output, thinking)` are the single source of column names, reused by `accumulate_usage`, renderers, and `cost_for`'s keyword args. `PriceTable.cost_for` signature is identical across producer (T2) and consumers (T4, `_priced`). `SessionKeys` names are fixed in T3 and consumed unchanged in T5/T6.
- **Composition entry points (verified during planning, now concrete in T7):** builder is `build_malware_analyst_composition` / `get_malware_analyst_composition`; register via `builder.add_agent(...)` after `MALWARE_REPORT_GENERATOR_DESCRIPTOR`; hermetic build in tests via `get_malware_analyst_composition().root_agent` (autouse conftest pins `AREMA_LLM_PROVIDER=ollama`); catalog via `.catalog.agents`; `safe_default` profile confirmed present. T7 updates the existing `test_root_runs_nine_stages_in_order` so appending the reporter doesn't break it.
- **Pinned by test, not guessed:** the `usage_metadata` provider field names (T3) are fixed by the fixture test and the `Total == total_token_count` invariant. If a provider populates `cached`/`thinking` differently, the fixture is updated and the invariant still guards the arithmetic.
