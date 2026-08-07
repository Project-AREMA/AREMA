# Per-Model Token Accounting Attached to the Final Report — Design

**Date:** 2026-07-31
**Status:** Approved for planning
**Author:** brainstorming session (Opus 4.8)

## Goal

Track LLM token consumption across an analysis run and emit a per-model
**Token Usage & Cost** summary as a separate, deterministic final message right
after the pipeline's report. Numbers are computed by code from provider usage
metadata — **never authored by the LLM**.

## Non-negotiable principles

1. **Deterministic, code-computed.** A model cannot count its own tokens, and
   AREMA prompts must generalize (never hardcode numbers). All counters, costs,
   and the rendered table come from `usage_metadata`, folded by pure functions.
   The report LLM is never asked to produce or echo any number.
2. **Architecturally transparent — capture is core-managed.** Token capture is
   appended inside `build_callback_chain`, gated on the existing
   `RuntimeProfile.record_metrics` flag (default `True`). Every `LlmAgent` is
   built through one path (`compose_agents → _build_agent → build_callback_chain`),
   so **any new agent is counted automatically**: no per-agent callback, no
   mixin, no base class, no prompt change. Nobody ever "adds the usage tracker"
   to an agent again.
3. **Render is opt-in per pipeline, once.** A rendered "final report section"
   only exists at the end of a *specific* pipeline, so the deterministic
   `token_usage_reporter` is appended as the **last sub-agent of a pipeline** —
   one line in `sub_agent_ids`, per pipeline, not per agent. New stages inside
   the pipeline need nothing.
4. **Fail-open.** Missing `usage_metadata`, missing model, or a pricing gap
   never raises and never aborts a run — consistent with every existing metrics
   callback.

## Global Constraints (exact values — bind every task)

- **Semantic columns (per model):** `Input`, `Cached`, `Output`, `Thinking`,
  `Total`, `Est. cost`.
- **Field mapping** from `google.genai.types.GenerateContentResponseUsageMetadata`:
  - `Input`  = `prompt_token_count − cached_content_token_count` (uncached prompt)
  - `Cached` = `cached_content_token_count`
  - `Output` = `candidates_token_count`
  - `Thinking` = `thoughts_token_count` **plus** the reconciliation residual
    `max(0, total_token_count − (Input + Cached + Output + thoughts_token_count))`.
    Reasoning models (e.g. `grok-4`) report generated reasoning tokens only
    inside `total_token_count` — not in `candidates_token_count`, with no
    `thoughts_token_count` field — so folding that residual into `Thinking`
    (billed at the output rate, correct for reasoning tokens) keeps the sample
    reconciled to the provider total. The residual is 0 for providers whose
    sub-fields already sum to the total (e.g. Gemini).
  - `Total`  = `Input + Cached + Output + Thinking`, which **equals** the
    provider's `total_token_count` **by construction** (the residual absorbs any
    difference).
  - **Invariant (tested):** `Total == total_token_count` holds by construction —
    a fixture test covers both a Gemini-shaped sample (residual 0) and a
    grok-shaped sample (reasoning residual folded into `Thinking`). A negative or
    absent `total_token_count` is never folded, so it can only leave `Thinking`
    at `thoughts_token_count`, never below it. (Field names verified against real
    LiteLLM/xAI + Gemini responses.)
  - Any of these counts absent on a sample → treated as `0`. If `usage_metadata`
    itself is absent, the whole sample is skipped (nothing accumulated).
- **Cost formula** (rates expressed **per 1,000,000 tokens**):
  `cost = Input·in_rate + Cached·cached_rate + (Output + Thinking)·out_rate`,
  each term divided by 1e6. Thinking is billed at the output rate.
- **Unpriced model:** cost cell renders `?`, the model is **excluded from the
  cost total**, and the section carries `(excludes N unpriced model(s): <ids>)`.
  A stale/missing price never produces a silently-wrong total.
- **Run-scoping:** the accumulator stores `{"run_id": …, "by_model": {…}}`; on a
  sample whose current `run_id` differs from the stored one, the accumulator
  re-initializes — a reused adk-web session running two analyses never
  double-counts. The scope id is `SessionKeys.RUN_ID` when the neutral-core
  runner (`run_single_query`) seeded it; on the `adk run` / `adk web` path
  (which never sets `RUN_ID`) the recorder falls back to ADK's
  `invocation_id` — a fresh value per user turn, constant across all stages of
  one pipeline invocation. Without that fallback the scope would be `None` on
  every turn, the reset would never fire, and the primary entry point would
  double-count.
- **State keys** (added to `SessionKeys`, `_runtime:` prefix for internal,
  unprefixed for the durable record consumed at render time):
  - `CURRENT_MODEL = "_runtime:current_model"` (prefix for the temp before→after
    handoff; the live slot is per-agent: `f"{CURRENT_MODEL}:{agent_name}"`)
  - `MODEL_USAGE   = "_runtime:model_usage"` (the accumulator)
  - `TOKEN_USAGE_RECORD = "token_usage_json"` (structured record, written by the
    reporter's `state_delta`)
- **Reporter placement:** `token_usage_reporter` is the **last** entry of a
  pipeline's `sub_agent_ids`, and emits a **separate** message (its own `Event`
  with content), not merged into the report agent's text.
- **Price override:** env-driven `AREMA_MODEL_PRICE_OVERRIDES` (JSON mapping
  model id → `{"input": r, "cached": r, "output": r}`, per-1M rates) merged over
  the bundled defaults at settings load; a per-model override replaces that
  model's default entry wholesale.
- **Neutrality:** all capture/accounting/reporter code is domain-neutral and
  lives under `src/arema/`. Only the malware domain's registration + one
  `sub_agent_ids` line reference the reporter. `composition.py` stays neutral.

## Architecture & data flow

```
①  after_model callback   →  reads llm_response.usage_metadata, resolves the
   (every LlmAgent turn)       model from CURRENT_MODEL, folds the sample into
        │                      the MODEL_USAGE accumulator (run-scoped)
        │
②  accounting (pure)      →  price per-model dict; render markdown; build record
   (arema core, no ADK)
        │
③  token_usage_reporter   →  deterministic BaseAgent (last pipeline sub-agent):
   (final pipeline stage)     yields ONE Event whose content is the markdown
                              section AND whose actions.state_delta carries
                              TOKEN_USAGE_RECORD
```

Capture (①), accounting (②), and the reporter (③) are all in `arema` core.
Only the wiring — registering the reporter descriptor and appending it to the
malware pipeline — is domain-side.

## Components

### B. Capture — a new `after_model` seam

Today `CallbackChain` has `before_model` but **no `after_model`**, and
`usage_metadata` exists only on the response. Changes:

- `registry/descriptors.py`: add an `AfterModelCallback` Protocol mirroring
  `BeforeModelCallback`, invoked by keyword
  `(callback_context, llm_response) -> Awaitable[LlmResponse | None] | LlmResponse | None`.
- `runtime/callbacks/chain.py`: `CallbackChain` gains
  `after_model: tuple[AfterModelCallback, ...]`; `empty()` sets it `()`;
  `build_callback_chain` appends the token recorder when `profile.record_metrics`
  (same gate as the before-model counter). No ordering invariant applies to
  `after_model`; `validate_callback_chain` is unchanged beyond the new field.
- `runtime/agent_factory.py`: `build_llm_agent` wires
  `after_model_callback=cast(..., list(chain.after_model))`.
- `runtime/callbacks/metrics.py`:
  - Extend the existing before-model recorder to stash the request model under a
    **per-agent** key `f"{CURRENT_MODEL}:{agent_name}"` (it already holds
    `llm_request` and `callback_context`).
  - Add `make_model_usage_token_recorder(services) -> AfterModelCallback`
    (role-tagged). It reads `llm_response.usage_metadata` and the same per-agent
    model key, calls `accumulate_usage(...)`, and returns `None`. Fail-open
    (logs, swallows).

Pairing must be **per agent, not global**. Within one agent, ADK runs
before-model → model call → after-model in sequence, so its own slot is stable
across the await. But a `ParallelAgent` (e.g. `ioc_extraction`) runs its
branches concurrently over one shared `session.state`, and `State.__setitem__`
writes straight into that shared dict — a single global `CURRENT_MODEL` slot
would let a sibling branch overwrite this branch's model during its model-call
await, mis-attributing the returned usage (and, under per-agent model overrides,
pricing it at the wrong rate). Keying the slot by `agent_name` gives each
concurrent branch its own slot, so the handoff is race-free.

### C. Accounting — pure core (`runtime/token_usage.py`)

```python
@dataclass(frozen=True, slots=True)
class UsageSample:
    input: int
    cached: int
    output: int
    thinking: int

    @property
    def total(self) -> int: ...

def usage_sample_from_metadata(metadata: object) -> UsageSample | None:
    """Map a GenerateContentResponseUsageMetadata to a UsageSample.
    Returns None when metadata is absent/unreadable. Missing counts -> 0."""

def accumulate_usage(state: object, model: str, sample: UsageSample, run_id: str | None) -> None:
    """Fold `sample` into state[MODEL_USAGE], keyed by `model`. Re-initializes
    the accumulator when run_id changes. Duck-types state.get / __setitem__."""

def render_usage_markdown(by_model: Mapping[str, UsageSample], prices: PriceTable) -> str:
    """Return the '## Token Usage & Cost' section: one row per model (sorted),
    a bold Total row, and the unpriced-models note when any model is unpriced."""

def build_usage_record(by_model: Mapping[str, UsageSample], prices: PriceTable, run_id: str | None) -> dict:
    """Return the structured record (by_model, grand_total, unpriced_models)."""
```

### C2. Pricing — pure core (`runtime/token_pricing.py`)

```python
@dataclass(frozen=True, slots=True)
class ModelPrice:      # per 1,000,000 tokens
    input: float
    cached: float
    output: float

DEFAULT_MODEL_PRICES: Mapping[str, ModelPrice]  # bundled table (Opus/Sonnet/Haiku/…)

class PriceTable:
    """Bundled defaults merged with AREMA_MODEL_PRICE_OVERRIDES.
    cost_for(model, sample) -> float | None  (None == unpriced)."""
```

Overrides load via `Settings` (env `AREMA_MODEL_PRICE_OVERRIDES`, JSON). A
malformed override is logged and ignored (fail-open to bundled defaults).

### D. Render — deterministic reporter

`runtime/agent_factory.py` gains `_TokenUsageReporter(BaseAgent)` (mirrors the
existing `_EscalationGate`) and `build_token_usage_reporter(context) -> BaseAgent`.
`_run_async_impl` reads `MODEL_USAGE` from `ctx.session.state`, prices it, and
yields ONE `Event` with:
- `content` = `render_usage_markdown(...)` (a text Part), so
  `run_single_query`'s existing per-event text collection appends it after the
  report; and
- `actions = EventActions(state_delta={TOKEN_USAGE_RECORD: build_usage_record(...)})`.

Empty accumulator → renders a single neutral line (e.g. "_No model usage was
recorded for this run._"). The reporter makes no model call, so it never
self-counts, and the empty callback chain (`prompt_id=None`) applies.

Exact section shape:

```markdown
## Token Usage & Cost

| Model           | Input   | Cached  | Output | Thinking | Total   | Est. cost |
|-----------------|---------|---------|--------|----------|---------|-----------|
| claude-opus-4-8 | 171,894 | 640,110 | 41,220 |   12,880 | 866,104 | $12.40    |
| claude-sonnet-5 | 120,300 |       0 |  9,880 |        0 | 130,180 | $0.72     |
| **Total**       | 292,194 | 640,110 | 51,100 |   12,880 | 996,284 | **$13.12** |
```

Structured record (`TOKEN_USAGE_RECORD`):

```json
{"run_id":"…",
 "by_model":{"claude-opus-4-8":{"input":171894,"cached":640110,"output":41220,
   "thinking":12880,"total":866104,"cost_usd":12.40}},
 "grand_total":{"input":292194,"cached":640110,"output":51100,"thinking":12880,
   "total":996284,"cost_usd":13.12},
 "unpriced_models":[]}
```

### E. Domain wiring (malware)

- `src/malware_analyst/agents/token_usage_reporter.py`: an `AgentDescriptor`
  (`id="token_usage_reporter"`, `prompt_id=None`, `factory=build_token_usage_reporter`,
  a neutral `runtime_profile_id`).
- `src/malware_analyst/composition.py`: register the descriptor.
- `src/malware_analyst/agents/malware_analyst.py`: append
  `"token_usage_reporter"` as the last `sub_agent_ids` entry.

## Module layout

**Core (neutral):**
- `runtime/token_usage.py` — samples, accumulator, renderers (new)
- `runtime/token_pricing.py` — `ModelPrice`, defaults, `PriceTable` (new)
- `runtime/callbacks/metrics.py` — before-model model stash + after-model recorder
- `runtime/callbacks/chain.py` — `after_model` in `CallbackChain` + wiring
- `runtime/callbacks/roles.py` — `ROLE_RECORD_MODEL_TOKENS`
- `runtime/agent_factory.py` — `after_model_callback` wiring + `_TokenUsageReporter`
- `registry/descriptors.py` — `AfterModelCallback` Protocol
- `runtime/sessions.py` — `CURRENT_MODEL`, `MODEL_USAGE`, `TOKEN_USAGE_RECORD`
- `core/config.py` — `model_price_overrides` (env `AREMA_MODEL_PRICE_OVERRIDES`)

**Domain (malware):** the three files in §E.

## Testing

- **Unit (pure):** `usage_sample_from_metadata` mapping incl. the
  `Total == provider total_token_count` invariant and missing-field defaults;
  `accumulate_usage` merge + run-id reset; `PriceTable.cost_for` incl. override
  merge and unpriced → `None`; `render_usage_markdown` (row format, thousands
  separators, bold Total, unpriced note); `build_usage_record` shape.
- **Unit (callbacks):** after-model recorder accumulates from a fake response;
  fail-open on absent `usage_metadata` and absent `CURRENT_MODEL`; before-model
  stash writes `CURRENT_MODEL`.
- **Chain:** `after_model` populated when `record_metrics`, empty otherwise;
  `CallbackChain.empty().after_model == ()`; existing invariants still pass.
- **Component:** `_TokenUsageReporter` yields exactly one `Event` whose content
  contains the table and whose `state_delta` carries `TOKEN_USAGE_RECORD`;
  empty-accumulator path yields the neutral line.
- **Wiring/architecture:** malware `sub_agent_ids` ends with
  `token_usage_reporter`; the descriptor is registered; neutrality tests stay
  green.
- **End-to-end (fixture):** a session state seeded with a two-model accumulator
  renders the exact expected section + record.

## Confirmed decisions

- Full split per model (Input/Cached/Output/Thinking/Total). ✅
- Tokens **and** cost, always, from a bundled table; unpriced excluded + noted. ✅
- Markdown section **and** structured record in state. ✅
- Usage as a **separate final message right after the report**. ✅
- Price **overrides** via env (`AREMA_MODEL_PRICE_OVERRIDES`). ✅
- Capture is **core-managed / transparent**; render is **one line per pipeline**. ✅

## Open item (resolved during implementation, not blocking)

- Exact `usage_metadata` field names differ slightly across providers
  (Gemini vs LiteLLM/Anthropic). The mapping in Global Constraints is the
  intent; a fixture test against a real captured response pins the arithmetic
  and the `Total == total_token_count` invariant.
