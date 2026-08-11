# Context Management & Resilience

AREMA keeps long autonomous runs inside a provider's context window and keeps
transient infrastructure failures from aborting a run. Four domain-neutral
mechanisms cooperate (none of them knows the name or shape of any concrete tool):
per-tool output compaction, context-budget enforcement, resilient MCP
degradation, and fail-open memory. A fifth neutral layer (`runtime/callbacks/
sanitization/`) structurally neutralizes prompt-injection text in
untrusted-origin tool output, and one domain-level mechanism keeps a stage's
evidence from being lost at the model boundary.

## Two layers of context management

### Layer 1: descriptor-driven output compaction (`runtime/context/compactor.py`)

Every completed tool response is bounded *before* it enters the conversation
history. The rules come entirely from the tool's `OutputPolicy`. There is no
hardcoded table of tool names.

`make_output_compactor(policy_by_tool_id)` builds the after-tool callback that
the callback chain always places **last**. For each completed tool it looks up
the tool's policy (falling back to a safe `OutputPolicy()` default) and applies
`compact_response` in three stages, without mutating the original response:

1. **Recursive field dropping**: every key in `policy.drop_fields` is removed
   wherever it appears, unless also listed in `policy.preserve_fields`.
2. **Bounded list truncation**: every list in the tree is capped at
   `policy.max_list_items` (preserved fields are exempt).
3. **Largest-value-first deep truncation**: if the result still serialises
   larger than `policy.max_chars`, the single largest reachable value is
   shortened repeatedly (leaving a `[truncated]` hint) until it fits or no
   further shrinking is possible.

`OutputPolicy` defaults: `max_chars=15_000`, `max_list_items=30`, empty
`drop_fields`/`preserve_fields`. The compactor is fail-open: if compaction
raises it logs and returns `None`, leaving the original response intact.

### Layer 2/3: context-budget enforcement (`runtime/context/budget.py`)

`enforce_context_budget` is a before-model callback. Before each model call it
estimates the pending request's token footprint (`estimate_tokens`: JSON length
÷ 4, a deterministic, dependency-free proxy) and classifies occupancy against the
configured budget into a `ContextPressure` tier.

#### `ContextPressure` tiers

| Tier       | Trigger ratio                | Preservation behavior |
|------------|------------------------------|-----------------------|
| `NORMAL`   | below `CONTEXT_WARNING_RATIO` (0.60) | nothing done; request proceeds |
| `WARNING`  | ≥ `CONTEXT_WARNING_RATIO`    | compact old tool results using the configured recent-preservation counts |
| `HARD`     | ≥ `CONTEXT_HARD_RATIO` (0.75) | halve both preservation counts (floored at 1) |
| `CRITICAL` | ≥ `CONTEXT_CRITICAL_RATIO` (0.85) | preserve only the single most recent tool result and model turn; halve both text-truncation floors (`text_min_length` 500→250 floored at 200, `text_prefix_chars` 200→100 floored at 100) |

The settings validator enforces `warning < hard < critical`.

Within a pressure tier the pass runs in two stages:

- **Layer 2**: `_compact_old_tool_results` replaces old function-response
  payloads (older than the tier's `tool_preserve` count) with a short,
  tool-agnostic summary marked `[Compacted]`. Already-compacted results are
  skipped, so repeated passes are idempotent.
- **Layer 3**: if compacting tool results is not enough to drop back under the
  warning ratio, `_compact_old_model_text` truncates old plain-text *model*
  output (verbose reasoning) beyond the tier's `model_turns_preserve` count. User
  messages and tool activity are never touched; truncated parts carry an
  idempotence suffix.

If, after the most aggressive compaction, occupancy is still `CRITICAL`, the run
has no safe way to continue. Rather than submit an oversized request, the
callback records a bounded checkpoint under session-state key
`context_budget:checkpoint` (`{tokens, budget, ratio}`) and returns an
explanatory `LlmResponse` that stops the run cleanly.

All thresholds and preservation counts are `Settings` fields
(`CONTEXT_BUDGET_TOKENS`, the three ratios, `CONTEXT_PRESERVE_RECENT_TOOLS`,
`CONTEXT_PRESERVE_RECENT_MODEL_TURNS`, `CONTEXT_MAX_LIST_ITEMS`).

## Resilient MCP degradation (`registry/mcp.py`)

`ResilientMcpToolset` subclasses ADK's `McpToolset` to add required/optional
failure semantics. `get_tools()` wraps the base resolution:

- On success it records `McpStatus.AVAILABLE` and returns the tools.
- On an ordinary failure (an unreachable or misbehaving server) it records
  `McpStatus.UNAVAILABLE` with the error type. If the descriptor is `required`,
  the error re-raises; if it is optional, it logs a warning and returns `[]`, so
  a flaky optional server degrades to "no tools this turn" instead of crashing
  the run.
- Cancellation is never treated as an availability signal.
  `_is_cancellation` walks the `__cause__`/`__context__` chain and any
  `ExceptionGroup` so an `asyncio.CancelledError` disguised as a `ConnectionError`
  during shutdown is re-raised untouched, leaving the availability snapshot intact.

`build_mcp_toolset(descriptor)` resolves `${VAR}` placeholders in transport
headers/env from a one-shot snapshot of `os.environ` (never a live reference), so
later environment mutation cannot retroactively change resolved values. Resolved
secrets are confined to the ADK connection parameters and never placed in logs or
exception text by this layer.

Each resolved tool is wrapped in a `_SerializedTool` that holds one `asyncio.Lock`
per toolset. ADK dispatches every function call in a single model turn
concurrently (`asyncio.gather`), but an MCP server that fronts one stateful
backend (one subprocess, one session cursor) cannot serve concurrent in-flight
requests over its one session — a call that sets server-side state can interleave
with a later call that depends on it. The per-toolset lock makes the calls run one
at a time against that session, exactly as if the model had issued them
sequentially, without changing the tool's name or declaration.

> MCP toolsets **are** wired onto agents: the agent factory resolves an agent's
> `mcp_server_ids` into `ResilientMcpToolset`s (via `build_mcp_toolset`) and
> appends them to the agent's `tools`. MCP tools flow through the same callback
> chain as function tools (the registered-tool guard stays first in `before_tool`,
> the output compactor last in `after_tool`).

## Fail-open memory (`memory/service.py`)

Working memory is a convenience for continuity, never a hard dependency of a run.
Every lifecycle write degrades open:

- `safe_append_event` catches `MemoryStoreError`, logs it with only the error
  *type* (no payload), sets an internal degraded flag, and returns `False`; the
  run continues.
- `record_tool_event` records only neutral lifecycle metadata (tool id, outcome
  flag, elapsed time, output size, run id) and drops events that have no scope to
  attribute to. It never persists tool arguments or output.
- `make_checkpoint_recorder` (an after-agent hook) writes a bounded
  `CheckpointRecord` when session state carries a scope and a checkpoint value;
  any failure is logged and swallowed so an after-agent hook never aborts a run.
- `health()` returns `degraded` after any write failure, so a supervisor or the
  CLI `/status` command can observe the condition without reaching into backend
  internals.

The neutral core registers four codec payloads at schema version 1 under
namespace `arema.core` (`default_core_codec_registry`): `event`, `checkpoint`,
`note`, and `artifact`. Only these typed, neutral records ever cross the store
boundary.

Retrieval is equally conservative: `retrieve_bounded` admits records in the
store's deterministic order until either the record cap (`memory_retrieval_max_records`,
default 20) or the estimated-token cap (`memory_retrieval_token_limit`, default
4_000) would be exceeded, and flags `truncated` when anything was left out.
Nothing retrieved is ever injected into an agent instruction implicitly; a caller
always decides what to do with it.

## Fail-open evidence (`reverse_engineering/evidence_envelope.py`)

`EvidenceEnvelope` is deliberately strict (`extra="forbid"`, a closed `kind`
enum, bounded strings, an exact artifact match) because it is what the report is
rendered from. Strictness at the model boundary is all-or-nothing, though: a
single malformed finding used to replace an entire stage's evidence with a failed
envelope, and a live run lost every Ghidra finding that way while the report
carried nothing but `deep:evidence_envelope_invalid`.

`salvage_evidence_envelope` is the fail-open reconstruction. `normalize_evidence_output`
tries the strict parse first and salvages only on rejection; a payload nothing can
be recovered from still takes the failed-envelope path unchanged.

Every step it takes is a **subtraction or a normalization**, never an addition:

- a finding that cannot be coerced is dropped and counted, never repaired;
- an unknown key is ignored, an explicitly-null `detail` read as omitted;
- a finding naming a different artifact than its own envelope is dropped rather
  than relabelled, which would reattribute another binary's evidence;
- every survivor is re-validated against the strict model before it is stored.

Nothing is absorbed silently. Dropped findings become
`<stage>:findings_dropped:<n>` and a moved anchor becomes
`<stage>:evidence_rebound`, both of which reach the report's limitations. A
salvaged envelope may never keep claiming `complete` coverage.

The optional execution diagram (`reverse_engineering/execution_flow.py`) rides on
the same envelope, because a stage has exactly one `output_key`. It is popped and
sanitized *before* strict validation, so a malformed diagram can never cost a
stage its findings, and sanitation itself never raises. The diagram is rendered
by code from structured nodes and edges (a model never writes mermaid), and the
critic drops any node whose tool no surviving finding cites, so the picture can
never show a step the report does not carry.

## Output sanitization (`runtime/callbacks/sanitization/`)

The neutral core ships a pluggable sanitization framework that structurally
neutralizes prompt-injection text in untrusted-origin tool output (e.g.
decompiled code from a binary under analysis). It is wired via a domain-specific
`RuntimeProfile` whose `extra_after_tool` carries the sanitizer callback; it
runs **before** memory-recording and the output compactor (which stays last).

- **`OutputSanitizer`**: a `Protocol` (`sanitize(tool_name, response) -> dict`).
  The default backend is `StructuralSanitizer` (data-frame wrapping + a curated
  case-insensitive prompt-injection regex denylist); `PassthroughSanitizer` is
  the no-op backend used in tests and as the "disabled" sentinel. A future
  `GuardrailsSanitizer` would implement the same protocol so Guardrails AI drops
  in without a rewrite.
- **`make_sanitizing_after_tool(sanitizer, binary_origin_tools)`**: builds the
  `after_tool` callback. It sanitizes only tools whose names are in the
  `binary_origin_tools` set (e.g. the r2mcp, ghidra, and jadx/androguard tool
  names); all others pass through untouched. Fail-open: a sanitizer exception is
  swallowed and the original response passes through.
- **Lossless for genuine tool output**: real decompiled code contains no
  injection signatures, so only the framing wrapper is added.

A domain configures it by deriving a profile from `safe_default` and supplying
its set of untrusted-origin tool names:

```python
RE_GUARDED = replace(RuntimeProfile.safe_default(), id="re_guarded",
    extra_after_tool=(make_sanitizing_after_tool(StructuralSanitizer(), binary_origin_tools),))
```

## Where the pieces attach

The runtime profile decides which of these run for a given agent. In the guarded
`safe_default` profile they are all enabled, and `build_callback_chain`
(`runtime/callbacks/chain.py`) assembles them in one approved order, then
re-validates the result.

### Ordering invariants (`validate_callback_chain`)

Two invariants are enforced, and crucially they are checked with **identity role
markers** (`runtime/callbacks/roles.py`), never `__name__` comparisons — so
wrapping, decorating, or renaming a callback cannot silently defeat them:

1. The registered-tool guard (`ROLE_REGISTERED_TOOL_GUARD`), when present, is
   **first** in `before_tool`, so an unknown tool is rejected before any other
   callback invests work in it.
2. Output compaction (`ROLE_COMPACT_TOOL_OUTPUT`), when present, is the **single
   last** step in `after_tool`, so metrics, memory, and sanitization all observe
   the untruncated response before it is bounded for context.

### Why the after-tool list is folded into one callback (`compose_after_tool`)

ADK walks its after-tool list and **stops at the first callback returning a
truthy value** (`flows/llm_flows/functions.py`: `if altered_function_response:
break`). That short-circuit is fatal to the "compactor last" invariant: a
callback that *transforms* the response — the sanitization membrane, for one —
returns a value by construction, so every later step was being skipped,
including compaction. The effect was exactly inverted: compaction died for
precisely the binary-origin tools it exists to bound.

`compose_after_tool` restores the documented semantics by folding the entire
validated after-tool list into **one** callback. That callback runs every step in
order, threads each step's result into the next, and returns `None` only when no
step altered the response. The chain itself stays an ordered, validated tuple
(ordered by `build_callback_chain`, re-checked by `validate_callback_chain`), so
the role markers and the "compactor last" invariant keep holding on the real
list — ADK simply never gets the chance to short-circuit between steps.

This is why **output compaction is always the last after-tool step in practice**:
metrics, memory, and sanitization observe full output before it is bounded for
context, and no transforming callback can accidentally skip the compactor.
