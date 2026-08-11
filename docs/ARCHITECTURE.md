# AREMA Architecture

AREMA is a domain-neutral shell for building autonomous agents on the Google
Agent Development Kit (ADK). The neutral core (`src/arema/`) ships one no-tools
**smoke agent** in its default composition to prove the runtime is wired end to
end, but it is also the reusable infrastructure layer that domain packages
consume: the **sandbox subsystem** (`runtime/sandbox/`), the **sanitization
framework** (`runtime/callbacks/sanitization/`), **token pricing/usage**
accounting (`runtime/token_pricing.py`, `runtime/token_usage.py`), the
**sessions** key registry (`runtime/sessions.py`), and the **composite-agent
factories** (`build_sequential_agent`, `build_parallel_agent`,
`build_loop_agent`, `build_escalation_gate`, `build_token_usage_reporter`).
Concrete capabilities live in **domain packages** — the live domain is
`src/malware_analyst/`, built on the shared capability library
`src/reverse_engineering/` — fronted by a **welcome router**
(`src/greeter_agent/`). See [`AGENTS_AND_DISCOVERY.md`](./AGENTS_AND_DISCOVERY.md)
for the multi-agent layout, the `src/`-based ADK discovery model, and the
add-a-domain recipe.

The design goal is a strict, testable seam between *declaration* (immutable
capability descriptors) and *construction* (ADK agents and callbacks). Nothing
in `src/arema` hardcodes a concrete tool name, a domain, or a provider: the
sandbox, sanitization, and accounting subsystems are pool-name- and
tool-name-agnostic, so domains supply configuration while the core supplies
mechanism.

## Layering

Dependencies point strictly downward. A higher layer may import a lower one; the
reverse never happens (enforced structurally with `Protocol` seams, not just by
convention).

```
 cli.py / agent.py            entry points (interactive, --query, --web; ADK root_agent)
        │
 runner.py                    run_single_query: one turn, one memory scope
        │
 composition.py               build_default_composition → ApplicationComposition
        │                     (catalog + root_agent + memory_service + sandbox)
        │
 registry/  (catalog)         CatalogBuilder → frozen, validated CapabilityCatalog
        │                     descriptors: RuntimeProfile, AgentKind, Agent/Tool/McpServer,
        │                     OutputPolicy, transports
        │
 runtime/   (construction)    agent_factory.compose_agents → ADK agents
        │                     factories: build_llm_agent + composite (sequential/parallel/loop)
        │                       + escalation_gate + token_usage_reporter
        │                     callbacks/chain.build_callback_chain → validated CallbackChain
        │                     callbacks/sanitization/ → OutputSanitizer membrane (neutral core)
        │                     context/ (budget + compactor), services (injected collaborators),
        │                     sessions (SessionKeys + resolve_sandbox_case_id),
        │                     token_pricing + token_usage (cost accounting),
        │                     sandbox/ (SandboxExecutor port: Local | K8s)
        │
 memory/    (persistence)     MemoryService over a MemoryStore port (InMemory | SQLite)
        │                     codecs, models, migrations
        │
 core/                        config (Settings), logging, model_factory (LiteLLM)
```

`memory/` never imports `runtime/`; the runtime's `RuntimeServices` and
checkpoint sinks are satisfied *structurally* by `MemoryService` (via
`runtime_checkable` protocols), so neither side imports the other's concrete
type. This keeps the memory subsystem a self-contained hexagonal adapter.

## Composition root (`composition.py`)

`build_default_composition(settings)` is the single wiring point. In order it:

1. Builds the core codec registry (`default_core_codec_registry()`).
2. Registers the guarded runtime profile (`RuntimeProfile.safe_default()`) and the
   root agent descriptor (`SMOKE_AGENT_DESCRIPTOR`) on a `CatalogBuilder`, then
   calls `freeze(root_agent_id)`, which produces an immutable, fully validated
   `CapabilityCatalog`.
3. Wires the configured `MemoryService` (SQLite or in-memory per `Settings`).
4. Validates that every registered tool's declared `memory_codec_ids` resolve
   against the codec registry (fails composition otherwise).
5. Builds the sandbox executor via `build_sandbox_executor(settings)`, which
   returns `None` when `settings.sandbox_enabled` is False and otherwise selects
   `LocalSandboxExecutor` or `K8sSandboxExecutor` from `sandbox_backend`
   (k8s/auto falls back to local when the optional `sandbox` extra is absent).
6. Bundles the memory service and sandbox into `RuntimeServices` and calls
   `compose_agents(...)` to build the ADK agent graph in dependency order.

The result is a frozen `ApplicationComposition(catalog, root_agent,
memory_service, sandbox)` — the `sandbox: SandboxExecutor | None` field is the
process-wide handle domain compositions reuse. `get_default_composition()`
memoizes one instance per process (`functools.lru_cache`) so the ADK entry
point resolves exactly one root.

The composition root creates the memory *service*; it does **not** open a run
scope. Scope lifetime belongs to the runner (see below).

## Catalog (`registry/`)

The catalog is the typed, immutable source of truth for what an application
contains. Descriptors (`registry/descriptors.py`) are frozen dataclasses that
copy every caller-owned collection into read-only storage on construction:

- `RuntimeProfile`: declarative feature switches (context mode plus per-concern
  booleans: capture request, throttle, retry, turn limit, context budget,
  metrics, tool guard, memory, compaction) and optional `extra_*` callback tuples.
- `AgentDescriptor`: id, name, description, `prompt_id` (optional), a
  `prompt_loader` (optional override of the packaged loader), a `factory`, a
  `runtime_profile_id`, an `AgentKind` (`AUTO` | `LLM` | `COMPOSITE` |
  `DETERMINISTIC`), reference tuples (`tool_ids`, `mcp_server_ids`,
  `sub_agent_ids`), an optional `output_key`, an optional `output_schema`, and
  free-form `metadata`.
- `ToolDescriptor`: exactly one of a concrete `tool` or a deferred `factory`, an
  `OutputPolicy`, `memory_codec_ids`, and `ToolLifecycleCallbacks`.
- `McpServerDescriptor`: a transport (`StdioTransport` | `SseTransport` |
  `StreamableHttpTransport`), a `required` flag, an optional `tool_allowlist`,
  an optional `tool_name_prefix`, and an optional header provider.

`CatalogBuilder.freeze(root_agent_id)` runs `_validate_catalog`, which checks
registry-key/id agreement, per-descriptor field validity, transport safety
(URL scheme, header/env sanitation, no embedded credentials), reference
resolution, **acyclicity** of the sub-agent graph, and **reachability** of every
agent from the root. Agent kind is resolved by `_effective_agent_kind`:
`AUTO` becomes `LLM` when `prompt_id` is set, else `COMPOSITE`. Each kind then
carries its own invariants — `LLM` requires a non-empty `prompt_id`; `COMPOSITE`
requires `prompt_id is None`, forbids `tool_ids`/`mcp_server_ids`/`output_key`,
and requires at least one `sub_agent_id`; `DETERMINISTIC` forbids
`prompt_id`/`prompt_loader`/`tool_ids`/`mcp_server_ids`/`sub_agent_ids`/
`output_key`. A catalog that survives `freeze` is guaranteed safe to build.

## Runtime profiles and the callback chain (`runtime/`)

`build_callback_chain(profile, services, tools)` translates a `RuntimeProfile`
plus injected `RuntimeServices` and the agent's tool descriptors into an
immutable `CallbackChain` (before-model, before-tool, after-tool, tool-error,
model-error). Callbacks are emitted in one approved order and the chain is
re-validated before return. Two invariants are enforced by identity-based *role
markers* (not fragile name comparisons):

- the registered-tool guard, when present, is **first** in `before_tool`;
- output compaction, when present, is the **single last** step in `after_tool`,
  so every metric, capability, and memory callback runs before output is bounded.

Because ordering is validated structurally, wrapping or renaming a callback can
never silently defeat it. One ADK-specific wrinkle: `compose_after_tool` folds
the whole `after_tool` list into a **single** callback before handing it to the
`LlmAgent`, because ADK short-circuits the after-tool chain on the first truthy
return — folding restores the "all steps run" semantics the chain promises.

### Sanitization membrane (`runtime/callbacks/sanitization/`)

A neutral-core defense layer for untrusted-origin tool output. It exposes an
`OutputSanitizer` `Protocol`, a default `StructuralSanitizer` that wraps output
in `=== BEGIN/END UNTRUSTED TOOL-DERIVED DATA ===` framing, a prompt-injection
denylist (`signatures.py`, seven patterns) with `redact_signatures`, and
`make_sanitizing_after_tool(sanitizer, binary_origin_tools)`. Domains supply
only the *configuration* (which tool names are untrusted-origin); the framing,
redaction, and pluggable protocol live in the core. The reverse-engineering
domain wires this as its `SanitizationMembrane` over all binary-origin tools.

## Agent factory (`runtime/agent_factory.py`)

`compose_agents(catalog, ...)` walks the catalog post-order from the root
(sub-agents first) so each agent's children exist before it is built. For each
agent, `_build_agent`:

- resolves the runtime profile and each referenced `ToolDescriptor` (building
  deferred tools lazily via a `ToolBuildContext`);
- resolves MCP servers per `mcp_server_id` into `ResilientMcpToolset`s via
  `build_mcp_toolset` (with `${VAR}` env substitution) and appends them to the
  agent's `tools`, so MCP tools flow through the same `tools` list as function
  tools;
- builds and validates the callback chain (for LLM-kind agents);
- loads the instruction prompt — `descriptor.prompt_loader(prompt_id)` when the
  descriptor supplies one, else the packaged `load_prompt(prompt_id)`;
- resolves the model (`get_agent_model`, honoring per-agent overrides and
  retries);
- assembles an `AgentBuildContext` and delegates to the descriptor's `factory`.

The factory set is: `build_llm_agent` (LLM kind), `build_sequential_agent`,
`build_parallel_agent`, `build_loop_agent` (COMPOSITE kind, mapping to ADK's
`SequentialAgent` / `ParallelAgent` / `LoopAgent`), plus `build_escalation_gate`
and the DETERMINISTIC `build_token_usage_reporter`. An `_CoercedLlmAgent`
wrapper overrides ADK's output-save hook (skip empty chunks, salvage reasoning
text, swallow `output_schema` `ValidationError`).

`build_llm_agent` maps the profile's context mode onto ADK's `include_contents`
(`isolated → "none"`, `history → "default"`) and wires every callback list from
the validated chain (the after-tool list passed through `compose_after_tool`).
The registered-tool guard stays first in `before_tool` and the output compactor
last in `after_tool`.

## Memory subsystem (`memory/`)

`MemoryService` is the seam between callers and a raw `MemoryStore`. It encodes
typed Pydantic records into content-addressed `MemoryEnvelope`s on the way in,
decodes them on the way out, bounds what may enter model context
(`retrieve_bounded`), and **degrades open**: a failed lifecycle write is caught,
logged without sensitive detail, and surfaced through `health()` rather than
aborting the run.

- `MemoryStore` (`store.py`) is a `runtime_checkable` `Protocol`: the single
  port. `InMemoryStore` (reference/test backend) and `SQLiteStore` (durable,
  WAL-journalled, migration-managed) are interchangeable adapters proven by one
  shared contract test.
- `RecordCodecRegistry` binds `(namespace, kind, schema_version)` triples to
  payload models and applies forward-only upgrade chains on decode. Unknown
  envelopes pass through unchanged.
- Only neutral lifecycle metadata is ever persisted: identities, an outcome
  flag, timings, counts, and bounded checkpoint state. Prompts, tool
  arguments, model text, and tool output are never persisted.

## Runner and CLI

`run_single_query(query, ...)` drives one turn. It opens a fresh `MemoryScope`,
seeds `RUN_ID` and `MEMORY_SCOPE_ID` (and `SANDBOX_CASE_ID` when a case id is
given) into ADK session state, runs the root agent through an ADK
`InMemoryRunner`, and **always** closes both the runner and the scope in a
`finally` block, even when runner construction itself raises. The runner and
its memory service are injected together through one `RunnerFactory` boundary so
a run's execution and its memory scope always come from the same place; tests
inject a fake and never touch a live provider or the SQLite-backed default.

`cli.py` wraps the runner in an `argparse` front end with three modes: one-shot
`--query`, the ADK developer web UI (`--web`), and an interactive Rich session
(`/help`, `/status`, `/clear`, `/exit`). `--web` points ADK's `agents_dir` at
`src/` (`Path(arema.__file__).resolve().parent.parent`), so the neutral CLI
discovers every domain package that ships an `agent.py` (today:
`greeter_agent`, `malware_analyst`). Interactive `/reset`, `/exit`, and Ctrl+C
release the sandbox session for the run; `atexit` releases any leftover handles.
`--help` and `--version` never import the runner, composition, or agent modules,
so neither requires provider credentials. Domain packages (e.g.
`src/malware_analyst/`) expose their own `agent.py` with a module-level
`root_agent` for ADK discovery; the neutral core (`src/arema`) is a library with
no `agent.py`. See [`AGENTS_AND_DISCOVERY.md`](./AGENTS_AND_DISCOVERY.md) for the
multi-agent layout.

## Data flow of one run

```
cli/main → runner.run_single_query
    → memory_service.create_scope(run)          # scope opened
    → seed RUN_ID / MEMORY_SCOPE_ID into state
    → InMemoryRunner(root_agent).run_async(...)
        → before_model chain (capture, throttle, turn limit, context budget)
        → model call (LiteLLM; retry on JSON error)
        → [tools would run here: guard → timer → after → memory → compact]
        → after_agent: bounded context checkpoint (fail-open)
    → collect response text
    finally: runner.close(); memory_service.close_scope(...)   # always
```

## Analysis pipeline invariants

The multi-stage analysis pipeline (reverse-engineering + malware domains) holds
these durable invariants. They are enforced deterministically (resolvers, gates,
callbacks), not by prompt discipline, and are locked by
`tests/malware_analyst/test_analysis_pipeline_regression.py`. See
`docs/ARCHITECTURAL_ISSUES.md` (AI-001..AI-007) for the failures they close.

1. **Sandbox identity.** An explicit case ID wins; otherwise the ADK invocation
   ID is hashed into the persisted sandbox case ID
   (`SessionKeys.SANDBOX_CASE_ID` = `"arema:sandbox_case_id"`, fallback
   `inv-<sha256[:32]>`).
2. **One resolver.** Every sandbox-backed tool calls the neutral
   `resolve_sandbox_case_id` (`runtime/sessions.py`); private production
   defaults are prohibited, so one invocation shares one sandbox identity
   across Radare2, Ghidra, UPX, FLOSS, jadx, and androguard.
3. **Execution boundary.** Binary execution remains Kubernetes-only.
4. **Evidence bus.** Session state (not conversation history) is the evidence
   bus. Every producer writes a bounded, artifact-bound `EvidenceEnvelope`
   (`reverse_engineering.evidence_envelope`) to a named key
   (`EvidenceEnvelope`, `EvidenceCoverage`, `EvidenceFinding`, `CoverageStatus`,
   `FindingKind`, `CriticEnvelope`, `CriticJudgment`; caps 200 findings / 64
   surfaces / 64 limitations), and conversation history is never authoritative
   evidence.
5. **Deep completion.** Deep analysis completes only with preparation, a
   cross-function semantic search, and a targeted decompile/p-code result;
   metadata alone can never complete it.
6. **No false negatives.** Negative report language requires completed relevant
   coverage; otherwise the stage reports "not determined" with the blocking
   limitation.
7. **Out of scope.** Threat-intelligence enrichment remains the next
   independent, out-of-scope slice; all findings derive from tools operating on
   the supplied artifact inside AREMA's Kubernetes sandboxes.
