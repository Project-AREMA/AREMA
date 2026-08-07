# AREMA Architecture

AREMA is a domain-neutral shell for building autonomous agents on the Google
Agent Development Kit (ADK). The shell itself ships one no-tools smoke agent that
proves the runtime is wired end to end; concrete capabilities live in **domain
packages** (e.g. `src/reverse_engineer/`) fronted by a **welcome router**
(`src/greeter_agent/`). See [`AGENTS_AND_DISCOVERY.md`](./AGENTS_AND_DISCOVERY.md)
for the multi-agent layout, the `src/`-based ADK discovery model, and the
add-a-domain recipe.

The design goal is a strict, testable seam between *declaration* (immutable
capability descriptors) and *construction* (ADK agents and callbacks). Nothing
in `src/arema` hardcodes a tool name, a domain, or a provider.

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
        │
 registry/  (catalog)         CatalogBuilder → frozen, validated CapabilityCatalog
        │                     descriptors: RuntimeProfile, Agent/Tool/McpServer, OutputPolicy
        │
 runtime/   (construction)    agent_factory.compose_agents → ADK LlmAgent(s)
        │                     callbacks/chain.build_callback_chain → validated CallbackChain
        │                     context/ (budget + compactor), services (injected collaborators)
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
5. Bundles the memory service into `RuntimeServices` and calls
   `compose_agents(...)` to build the ADK agent graph in dependency order.

The result is a frozen `ApplicationComposition(catalog, root_agent,
memory_service)`. `get_default_composition()` memoizes one instance per process
(`functools.lru_cache`) so the ADK entry point resolves exactly one root.

The composition root creates the memory *service*; it does **not** open a run
scope. Scope lifetime belongs to the runner (see below).

## Catalog (`registry/`)

The catalog is the typed, immutable source of truth for what an application
contains. Descriptors (`registry/descriptors.py`) are frozen dataclasses that
copy every caller-owned collection into read-only storage on construction:

- `RuntimeProfile`: declarative feature switches (context mode plus per-concern
  booleans: capture request, throttle, retry, turn limit, context budget,
  metrics, tool guard, memory, compaction) and optional `extra_*` callback tuples.
- `AgentDescriptor`: id, name, description, `prompt_id`, a `factory`, a
  `runtime_profile_id`, and reference tuples (`tool_ids`, `mcp_server_ids`,
  `sub_agent_ids`), plus an optional `output_key`.
- `ToolDescriptor`: exactly one of a concrete `tool` or a deferred `factory`, an
  `OutputPolicy`, `memory_codec_ids`, and `ToolLifecycleCallbacks`.
- `McpServerDescriptor`: a transport (`StdioTransport` | `SseTransport` |
  `StreamableHttpTransport`), a `required` flag, an optional `tool_allowlist`,
  and an optional `tool_name_prefix`.

`CatalogBuilder.freeze(root_agent_id)` runs `_validate_catalog`, which checks
registry-key/id agreement, per-descriptor field validity, transport safety
(URL scheme, header/env sanitation, no embedded credentials), reference
resolution, **acyclicity** of the sub-agent graph, and **reachability** of every
agent from the root. A catalog that survives `freeze` is guaranteed safe to
build.

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
never silently defeat it.

## Agent factory (`runtime/agent_factory.py`)

`compose_agents(catalog, ...)` walks the catalog post-order from the root
(sub-agents first) so each agent's children exist before it is built. For each
agent, `_build_agent`:

- resolves the runtime profile and each referenced `ToolDescriptor` (building
  deferred tools lazily via a `ToolBuildContext`);
- builds and validates the callback chain;
- loads the instruction prompt (`load_prompt` reads the packaged `<prompt_id>.md`);
- resolves the model (`get_agent_model`, honoring per-agent overrides and
  retries);
- assembles an `AgentBuildContext` and delegates to the descriptor's `factory`.

`build_llm_agent` maps the profile's context mode onto ADK's `include_contents`
(`isolated → "none"`, `history → "default"`) and wires every callback list from
the validated chain. An agent's `mcp_server_ids` are resolved into
`ResilientMcpToolset`s (via `build_mcp_toolset`) and appended to the agent's
`tools`, so MCP tools flow through the same `tools` list as function tools (the
registered-tool guard stays first in `before_tool`, the output compactor last in
`after_tool`).

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
seeds `RUN_ID` and `MEMORY_SCOPE_ID` into ADK session state (so every callback
can attribute its writes), runs the root agent through an ADK `InMemoryRunner`,
and **always** closes both the runner and the scope in a `finally` block, even
when runner construction itself raises. The runner and its memory service are
injected together through one `RunnerFactory` boundary so a run's execution and
its memory scope always come from the same place; tests inject a fake and never
touch a live provider or the SQLite-backed default.

`cli.py` wraps the runner in an `argparse` front end with three modes: one-shot
`--query`, the ADK developer web UI (`--web`), and an interactive Rich session
(`/help`, `/status`, `/clear`, `/exit`). `--help` and `--version` never import
the runner, composition, or agent modules, so neither requires provider
credentials. Domain packages (e.g. `src/reverse_engineer/`) expose their own
`agent.py` with a module-level `root_agent` for ADK discovery; the neutral core
(`src/arema`) is a library with no `agent.py`. See
[`AGENTS_AND_DISCOVERY.md`](./AGENTS_AND_DISCOVERY.md) for the multi-agent
layout.

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

1. **Sandbox identity.** An explicit case ID wins; otherwise the ADK invocation ID is hashed into the persisted sandbox case ID.
2. **One resolver.** Every sandbox-backed tool calls the neutral
   `resolve_sandbox_case_id`; private production defaults are prohibited, so one
   invocation shares one sandbox identity across Radare2, Ghidra, UPX, FLOSS,
   jadx, and androguard.
3. **Execution boundary.** Binary execution remains Kubernetes-only.
4. **Evidence bus.** Session state (not conversation history) is the evidence bus.
   Every producer writes a bounded, artifact-bound JSON evidence envelope to a
   named key, and conversation history is never authoritative evidence.
5. **Deep completion.** Deep analysis completes only with preparation, a
   cross-function semantic search, and a targeted decompile/p-code result;
   metadata alone can never complete it.
6. **No false negatives.** Negative report language requires completed relevant
   coverage; otherwise the stage reports "not determined" with the blocking
   limitation.
7. **Out of scope.** Threat-intelligence enrichment remains the next
   independent, out-of-scope slice; all findings derive from tools operating on
   the supplied artifact inside AREMA's Kubernetes sandboxes.
