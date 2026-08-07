# AREMA — Project Instructions

## Project Overview

AREMA (Autonomous Reverse Engineering & Malware Analysis) is a **domain-neutral
agent shell** built on the Google Agent Development Kit (ADK). This milestone is
an **infrastructure shell only**.

> **Reverse engineering and malware analysis are NOT implemented yet.** There are
> no scanners, disassemblers, sandboxes, browser automation, or containerized
> tools in this codebase. The shipped capability is a single **no-tools smoke
> agent** that proves the runtime is wired end to end. Do not describe, imply, or
> add security/pentest/RE tooling that does not exist. Keep all wording neutral.

The design separates **declaration** (immutable capability descriptors) from
**construction** (ADK agents and callbacks), with a strict downward dependency
layering enforced by structural `Protocol` seams.

## Architecture

```
cli.py / agent.py      entry points (interactive / --query / --web; ADK root_agent)
      │
runner.py              run_single_query — one turn, one memory scope (always closed)
      │
composition.py         build_default_composition → ApplicationComposition (lru_cached)
      │
registry/              CatalogBuilder → frozen, validated CapabilityCatalog; descriptors
      │
runtime/               agent_factory.compose_agents → ADK LlmAgent(s)
      │                 callbacks/chain.build_callback_chain → validated CallbackChain
      │                 context/ (budget + compactor); services (injected collaborators)
      │
memory/                MemoryService over a MemoryStore port (InMemory | SQLite); codecs
      │
core/                  config (Settings), logging, model_factory (LiteLLM)
```

- **Composition root:** `src/arema/composition.py` — `build_default_composition`
  registers the runtime profile + root agent, freezes the catalog, wires the
  memory service, validates tool codecs, and composes the agent graph.
  `get_default_composition()` memoizes one instance per process.
- **Smoke agent:** `src/arema/agents/smoke_agent.py` (`SMOKE_AGENT_DESCRIPTOR`).
- **Registry:** `src/arema/registry/` — `descriptors.py` (frozen `RuntimeProfile`,
  `AgentDescriptor`, `ToolDescriptor`, `McpServerDescriptor`, `OutputPolicy`,
  `ToolLifecycleCallbacks`, transports), `catalog.py` (`CatalogBuilder`,
  `CapabilityCatalog`, whole-graph validation), `mcp.py` (`ResilientMcpToolset`,
  `build_mcp_toolset`).
- **Runtime:** `src/arema/runtime/` — `agent_factory.py` (`compose_agents`,
  `build_llm_agent`, `AgentBuildContext`/`ToolBuildContext`), `callbacks/chain.py`
  (`build_callback_chain`, ordering invariants), `callbacks/roles.py` (identity
  role markers), `context/budget.py`, `context/compactor.py`, `services.py`
  (`RuntimeServices`, `ToolEvent`, sinks, `make_checkpoint_recorder`).
- **Memory:** `src/arema/memory/` — `store.py` (`MemoryStore` protocol port),
  `backends/memory.py` + `backends/sqlite.py`, `codecs.py`, `models.py`,
  `service.py`, `migrations.py`.
- **Config:** `src/arema/core/config.py` (Pydantic `Settings`, env-driven).
- **Prompts:** packaged `.md` files under `src/arema/prompts/`, loaded by
  `prompts/loader.py` via `importlib.resources`.

## Critical Constraints (ADK-Specific)

These apply to any future tool/callback code added to the shell.

### Parameter annotations
- **NEVER** use bare `typing.Any` as a function parameter annotation on tool
  functions. Python 3.14 removed `isinstance()` support for `Any`, and ADK's
  `_function_parameter_parse_util.py` calls `isinstance(default, annotation)` at
  import time. Use `object` for generic params; compound types like
  `dict[str, Any]` are fine.

### State type guards
- **NEVER** use `isinstance(state, dict)` on ADK's `CallbackContext.state` /
  `ToolContext.state`. ADK's `State` is a custom proxy (not a `dict`, not a
  `Mapping`). Duck-type on `.get` or compare `state is None`, as
  `runtime/services.py:_state_value` and `context/budget.py` already do.

### Callback chain ordering (enforced)
- The chain is assembled in one approved order and re-validated by
  `validate_callback_chain`. Two invariants hold via **identity role markers**
  (never name comparisons): the registered-tool guard is **first** in
  `before_tool`; the output compactor is the **single last** step in
  `after_tool`. When adding profile/tool callbacks, do not break these; add a
  role marker in `callbacks/roles.py` if a new callback participates in ordering.

### MCP attachment is a future seam
- `build_mcp_toolset` produces a `ResilientMcpToolset`, and `McpServerDescriptor`
  is fully validated, but the agent factory does **not** yet resolve an agent's
  `mcp_server_ids` onto that agent — `_build_agent` raises `NotImplementedError`
  for a non-empty `mcp_server_ids`. Wiring the toolset onto an `LlmAgent` is the
  next construction task.

## Capability Catalog

`CatalogBuilder.freeze(root_agent_id)` validates the whole graph and raises on:
missing references (`runtime_profile_id`, `tool_ids`, `mcp_server_ids`,
`sub_agent_ids`), an agent unreachable from the root, a cycle in the sub-agent
graph, unsafe transports (bad URL scheme, unsanitized header/env, embedded
credentials), or duplicate ids. A frozen catalog is guaranteed safe to build.
`composition.py` additionally validates that every tool's `memory_codec_ids`
resolve against the codec registry.

## Context & Resilience

- **Layer 1 — output compaction** (`context/compactor.py`): per-tool
  `OutputPolicy` drives recursive field-drop → bounded list truncation →
  largest-value-first deep truncation. Always the last after-tool callback.
  Fail-open.
- **Layers 2/3 — context budget** (`context/budget.py`): `ContextPressure` tiers
  NORMAL/WARNING/HARD/CRITICAL classify token occupancy against
  `CONTEXT_BUDGET_TOKENS`; older tool results and then older model text are
  compacted with tier-dependent preservation. At unrecoverable CRITICAL the run
  stops cleanly with a checkpoint.
- **Resilient MCP** (`registry/mcp.py`): optional servers degrade to `[]` tools;
  required servers re-raise; cancellation is never an availability signal.
- **Fail-open memory** (`memory/service.py`): lifecycle writes catch
  `MemoryStoreError`, log the error *type* only, set degraded, and continue. Only
  neutral lifecycle metadata is ever persisted — never prompts, tool args, model
  text, or output.

See `docs/CONTEXT_AND_RESILIENCE.md` for details.

## Extending the shell

Register immutable descriptors in `build_default_composition`
(`src/arema/composition.py`) before `builder.freeze(...)`. One registration for
each kind:

```python
# Agent (needs src/arema/prompts/<prompt_id>.md)
builder.add_agent(AgentDescriptor(id="worker_agent", name="worker_agent",
    description="A neutral agent.", prompt_id="worker_agent",
    factory=build_llm_agent, runtime_profile_id="safe_default"))

# Tool (descriptor id MUST equal the tool's runtime name for its OutputPolicy to bind)
builder.add_tool(ToolDescriptor(id="clock_now", description="Return UTC time.",
    tool=clock_now, output_policy=OutputPolicy(max_chars=2_000)))

# MCP server (descriptor validated + build_mcp_toolset ready; agent attachment NYI)
builder.add_mcp_server(McpServerDescriptor(id="example_mcp",
    transport=StdioTransport(command="example-mcp-server", args=("--stdio",))))

# Memory codec (on the composition's codec registry)
codecs.register(RecordCodec(namespace="example", kind="finding",
    schema_version=1, payload_type=FindingRecord))

# Runtime profile
builder.add_runtime_profile(RuntimeProfile(id="fast_isolated",
    context_mode=ContextMode.ISOLATED, throttle_model=False))
```

Full recipes and validation rules: `docs/EXTENDING_AREMA.md`. Architecture and
data flow: `docs/ARCHITECTURE.md`.

## Neutrality guardrails (enforced by tests)

`tests/architecture/test_neutral_boundaries.py` fails the build if:
- project metadata is not `arema` (name, `arema.cli:main` script, wheel packages
  `["src/arema"]`);
- any `src/arema` module imports the removed legacy domain package;
- `composition.py` mentions any concrete tool or domain term from the
  test's forbidden list.

Keep `src/arema` and `composition.py` domain-neutral. The legacy security-domain
tree and its assets have been removed from the repository (see the recovery tag
`pre-arema-domain-reset-2026-07-21` for the prior state).

## Testing & tooling

- All checks: `make check` (lint + format-check + type-check + tests).
- Tests: `make test` (`tests`), `make test-unit`, `make test-component`.
- `make lint` / `make format-check` run Ruff on `src/arema tests`;
  `make type-check` runs `mypy src/arema`.
- Multi-agent layout, ADK discovery, and the add-a-domain recipe:
  **`docs/AGENTS_AND_DISCOVERY.md`** (authoritative — read before adding agents/domains).
  Short version: ADK discovers agents from `src/` (each package with `agent.py`
  exposing `root_agent`); `src/greeter_agent` is the welcome router that delegates
  to domain packages (`src/reverse_engineer`, …); `src/arema` is the neutral core
  (no `agent.py`). No top-level `agents/` folder.
- Run the agent: `make adk-run` (interactive greeter via `adk run src/greeter_agent`),
  `make adk-web` (web UI, lists greeter_agent + domains), or `adk run src/<domain>`
  to drive a domain directly. `uv run arema` is the neutral-core smoke CLI.
- Config is env-driven; `.env.example` is the reference. Tests redirect `HOME`
  to a temp dir so the default SQLite store never touches your real home.
- Current test suite: ~630 tests in `tests` (unit, component, architecture).

<!-- rtk-instructions v2 -->
# RTK (Rust Token Killer) - Token-Optimized Commands

## Golden Rule

**Always prefix commands with `rtk`**. If RTK has a dedicated filter, it uses it. If not, it passes through unchanged. This means RTK is always safe to use.

**Important**: Even in command chains with `&&`, use `rtk`:
```bash
# ❌ Wrong
git add . && git commit -m "msg" && git push

# ✅ Correct
rtk git add . && rtk git commit -m "msg" && rtk git push
```

## RTK Commands by Workflow

### Build & Compile (80-90% savings)
```bash
rtk cargo build         # Cargo build output
rtk cargo check         # Cargo check output
rtk cargo clippy        # Clippy warnings grouped by file (80%)
rtk tsc                 # TypeScript errors grouped by file/code (83%)
rtk lint                # ESLint/Biome violations grouped (84%)
rtk prettier --check    # Files needing format only (70%)
rtk next build          # Next.js build with route metrics (87%)
```

### Test (60-99% savings)
```bash
rtk cargo test          # Cargo test failures only (90%)
rtk go test             # Go test failures only (90%)
rtk jest                # Jest failures only (99.5%)
rtk vitest              # Vitest failures only (99.5%)
rtk playwright test     # Playwright failures only (94%)
rtk pytest              # Python test failures only (90%)
rtk rake test           # Ruby test failures only (90%)
rtk rspec               # RSpec test failures only (60%)
rtk test <cmd>          # Generic test wrapper - failures only
```

### Git (59-80% savings)
```bash
rtk git status          # Compact status
rtk git log             # Compact log (works with all git flags)
rtk git diff            # Compact diff (80%)
rtk git show            # Compact show (80%)
rtk git add             # Ultra-compact confirmations (59%)
rtk git commit          # Ultra-compact confirmations (59%)
rtk git push            # Ultra-compact confirmations
rtk git pull            # Ultra-compact confirmations
rtk git branch          # Compact branch list
rtk git fetch           # Compact fetch
rtk git stash           # Compact stash
rtk git worktree        # Compact worktree
```

Note: Git passthrough works for ALL subcommands, even those not explicitly listed.

### GitHub (26-87% savings)
```bash
rtk gh pr view <num>    # Compact PR view (87%)
rtk gh pr checks        # Compact PR checks (79%)
rtk gh run list         # Compact workflow runs (82%)
rtk gh issue list       # Compact issue list (80%)
rtk gh api              # Compact API responses (26%)
```

### JavaScript/TypeScript Tooling (70-90% savings)
```bash
rtk pnpm list           # Compact dependency tree (70%)
rtk pnpm outdated       # Compact outdated packages (80%)
rtk pnpm install        # Compact install output (90%)
rtk npm run <script>    # Compact npm script output
rtk npx <cmd>           # Compact npx command output
rtk prisma              # Prisma without ASCII art (88%)
```

### Files & Search (60-75% savings)
```bash
rtk ls <path>           # Tree format, compact (65%)
rtk read <file>         # Code reading with filtering (60%)
rtk grep <pattern>      # Search grouped by file (75%). Format flags (-c, -l, -L, -o, -Z) run raw.
rtk find <pattern>      # Find grouped by directory (70%)
```

### Analysis & Debug (70-90% savings)
```bash
rtk err <cmd>           # Filter errors only from any command
rtk log <file>          # Deduplicated logs with counts
rtk json <file>         # JSON structure without values
rtk deps                # Dependency overview
rtk env                 # Environment variables compact
rtk summary <cmd>       # Smart summary of command output
rtk diff                # Ultra-compact diffs
```

### Infrastructure (85% savings)
```bash
rtk docker ps           # Compact container list
rtk docker images       # Compact image list
rtk docker logs <c>     # Deduplicated logs
rtk kubectl get         # Compact resource list
rtk kubectl logs        # Deduplicated pod logs
```

### Network (65-70% savings)
```bash
rtk curl <url>          # Compact HTTP responses (70%)
rtk wget <url>          # Compact download output (65%)
```

### Meta Commands
```bash
rtk gain                # View token savings statistics
rtk gain --history      # View command history with savings
rtk discover            # Analyze Claude Code sessions for missed RTK usage
rtk proxy <cmd>         # Run command without filtering (for debugging)
rtk init                # Add RTK instructions to CLAUDE.md
rtk init --global       # Add RTK to ~/.claude/CLAUDE.md
```

## Token Savings Overview

| Category | Commands | Typical Savings |
|----------|----------|-----------------|
| Tests | vitest, playwright, cargo test | 90-99% |
| Build | next, tsc, lint, prettier | 70-87% |
| Git | status, log, diff, add, commit | 59-80% |
| GitHub | gh pr, gh run, gh issue | 26-87% |
| Package Managers | pnpm, npm, npx | 70-90% |
| Files | ls, read, grep, find | 60-75% |
| Infrastructure | docker, kubectl | 85% |
| Network | curl, wget | 65-70% |

Overall average: **60-90% token reduction** on common development operations.
<!-- /rtk-instructions -->