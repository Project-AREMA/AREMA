# Agents & ADK discovery: architecture patterns

> **Read this before adding an agent, a domain, or touching how agents are
> launched.** It is the canonical reference for the multi-agent layout. The goal
> is one clean, repeatable structure so the framework extends without ad-hoc
> ("vibe") wiring.

AREMA is a **domain-neutral core** (`src/arema`) plus a set of **domain
packages** (`src/<domain>/`), fronted by a single **welcome router**
(`src/greeter_agent/`). Users talk to the greeter; it delegates to the right
domain; each domain is a self-contained agent graph.

```
greeter_agent  (welcome router, the only top-level entry users see)
   └─ sub_agents = [ reverse_engineer, <future domains…> ]
                    └─ each domain is itself a root + its own sub-agents
                        e.g. reverse_engineer (a SequentialAgent shell): sample_intake → triage_recon → deep_decompile → evidence_critic → report_generator
```

## 1. ADK discovery: `src/` is the agents directory

`adk web` / `adk run` discover agents from a single directory. AREMA sets that
directory to **`src/`** (`src/arema/cli.py:243` runs `adk web` with `cwd=src/`).
Therefore **every package under `src/` that contains an `agent.py` exposing a
module-level `root_agent` is one discoverable agent.**

```
src/
  arema/              # neutral core LIBRARY, no agent.py → NOT an adk entry
  greeter_agent/      # agent.py → discoverable as "greeter_agent"  (the router)
  reverse_engineer/   # agent.py → discoverable as "reverse_engineer"
  <new_domain>/       # agent.py → discoverable as "<new_domain>"
```

### The folder-IS-package rule (no shadowing)

Because `src/` is put on `sys.path`, a package folder and the importable module
share the same name. This is **correct and intended**: `src/reverse_engineer/`
*is* the `reverse_engineer` package, so `from reverse_engineer.composition …`
inside `src/reverse_engineer/agent.py` resolves to itself, with no shadowing.

> **Never** introduce a *separate* discovery folder (e.g. a top-level `agents/`
> dir) whose name matches an installed package. ADK inserts the discovery dir at
> `sys.path[0]`, so `agents/reverse_engineer/` would shadow
> `src/reverse_engineer/` and `agents/arema/` would shadow `src/arema/`, breaking
> imports. (This was the root cause of the earlier `adk run`/`adk web` failures.
> The fix was to delete `agents/` entirely and discover from `src/`.)

### What `agent.py` must contain

```python
# src/<domain>/agent.py
from <domain>.composition import get_<domain>_composition  # or get_<domain>_agent

root_agent = get_<domain>_composition().root_agent  # or ..._agent()

__all__ = ["root_agent"]
```

ADK looks for `root_agent` at module scope. Building the composition at import
is expected (it is `@lru_cache`d and cheap until a run actually calls the model).

## 2. The three package kinds

| Package | Example | Has `agent.py`? | Role |
|---|---|---|---|
| **Neutral core** | `src/arema/` | **No** | Domain-neutral shell: config, registry, runtime, memory, sandbox, runner. Never names a domain. |
| **Welcome router** | `src/greeter_agent/` | Yes | The single top-level entry. Owns no tools; holds domain roots as ADK sub-agents and routes via ADK's auto `transfer_to_agent`. |
| **Domain** | `src/reverse_engineer/` | Yes | One specialist capability. A full composition (catalog + memory + tools/MCP + its own sub-agents). |

Dependency direction is strictly downward: **router/domain → arema**, never the
reverse. Domains never import each other (the router composes them; a domain
that needs another's output gets it via routing, not imports).

## 3. Domain package anatomy

A domain mirrors the neutral core's composition shape but lives outside the
neutrality perimeter (so it may name its tools, such as `radare2` or `ghidra`).

```
src/reverse_engineer/
  __init__.py
  agent.py              # root_agent = get_reverse_engineer_composition().root_agent
  composition.py        # build_<domain>_composition() + @lru_cache get_<domain>_composition()
  prompts/              # <domain>-relative prompt loader + *.md instruction files
    loader.py           # load_<domain>_prompt(id) via importlib.resources
    *.md
  agents/               # AgentDescriptors + factories for the domain's sub-agents
  tools/                # function tools + ToolDescriptors
  mcp/                  # McpServerDescriptors
  artifacts/ evidence/  # domain stores / codecs as needed
  runtime/              # domain runtime helpers (e.g. port-forward registry)
```

Key points (see also `docs/EXTENDING_AREMA.md` for descriptor details):
- **Prompts are package-relative.** The neutral core's `load_prompt` only reads
  `arema.prompts`. Each domain ships its own loader
  (`load_<domain>_prompt`) and passes it to its `AgentDescriptor` via the
  **`prompt_loader`** field (a neutral seam in `arema.registry.descriptors`).
  Domain agents use the neutral `factory=build_llm_agent`.
- **Settings resolve via `get_settings()`** (reads `.env`/env), exactly like the
  core's `get_default_composition`. Tests stay hermetic by pinning a
  credential-free provider in the domain's `tests/<domain>/conftest.py`
  (mirror `tests/component/conftest.py`).
- **The descriptor `id` must equal the tool function's `__name__`** so its
  `OutputPolicy` binds at compaction time.
- **Function tools needing `RuntimeServices`** (e.g. the sandbox executor) use a
  `ToolDescriptor(factory=…)` that closes over `context.services`. A tool with a
  `tool_context: ToolContext` parameter must import `ToolContext` **at runtime**
  (`# noqa: TC002`), because ADK resolves annotations via `typing.get_type_hints`.

### Composite (orchestrator) agents

A domain root may be a **composite shell** (an ADK `SequentialAgent`,
`ParallelAgent`, or `LoopAgent`) by setting `prompt_id=None` and
`factory=build_sequential_agent` / `build_parallel_agent` / `build_loop_agent`
(from `arema.runtime.agent_factory`). Such a descriptor declares only
`sub_agent_ids` (no `tool_ids`, `mcp_server_ids`, or `output_key`); the catalog
enforces this at freeze time. The framework runs the children in declared order
(sequence) / concurrently (parallel) / looped (loop, which requires
`metadata["max_iterations"]` as a positive int). The `reverse_engineer` domain
uses a `SequentialAgent` root so the pipeline cannot loop on complex binaries
(LESSONS_LEARNED #1). `build_parallel_agent` / `build_loop_agent` ship as the
ready foundation and are wired by later slices (r2 ∥ Ghidra consensus; the
deobfuscation loop).

## 4. The welcome router (`greeter_agent`)

The greeter is deliberately a **thin router**, not a tool-bearing agent:

```python
# src/greeter_agent/composition.py
def build_greeter_agent(settings=None) -> LlmAgent:
    return LlmAgent(
        name="greeter_agent",
        model=get_agent_model("greeter_agent", settings=resolved, use_retries=True),
        instruction=load_greeter_prompt("greeter"),
        sub_agents=list(_domain_roots()),   # [reverse_engineer root, …]
    )
```

- It has **no AREMA function tools** and therefore no registered-tool guard,
  output compactor, or per-tool memory callbacks (those belong on the domain
  agents that actually call tools). ADK auto-generates a `transfer_to_agent`
  tool per registered domain root; the model routes by calling it. AREMA's
  `registered_tool_guard` only blocks ADK's `_unknown_tool_*` stubs, so
  legitimate transfer tools pass through.
- **`_domain_roots()`** is the single registration point. Adding a domain =
  appending one line (see §6).
- Each domain root is a fully-built composition (its own catalog/memory/callbacks).
  The greeter just holds the references; ADK's delegation moves control between
  them. The greeter does **not** merge domains into one catalog.

## 5. Invariants (do not break)

1. **Discovery = `src/`.** No top-level `agents/` folder. A package is an agent
   iff it has `agent.py` with `root_agent`.
2. **Folder name == package name == discovery name.** Never alias to dodge a
   collision; fix the collision by using the `src/` model.
3. **`src/arema` is domain-neutral.** Architecture tests
   (`tests/architecture/test_neutral_boundaries.py`) scan it for domain terms
   (`radare2`, `ghidra`, …) and fail the build if any appear. Domain code lives
   in `src/<domain>/`.
4. **Direction:** router/domain → arema, downward only; domains never import each
   other.
5. **One welcome router.** Users reach domains *through* the greeter. Domains are
   also independently runnable (`adk run src/<domain>`) for focused testing.
6. **`make adk-run` launches the greeter** (`adk run src/greeter_agent`).
   `uv run arema` remains the neutral-core smoke CLI for infra checks.
7. **Named state is the evidence bus.** In a multi-stage analysis domain,
   authoritative inter-stage evidence travels through named session-state keys
   (bounded JSON envelopes), never ambient conversation history; a downstream
   stage that infers from conversation history rather than its declared state
   aliases is a bug. Each ADK invocation resolves one sandbox case ID (explicit
   wins; otherwise the invocation ID seeds the persisted sandbox case). See
   `docs/ARCHITECTURE.md` → "Analysis pipeline invariants".

## 6. Recipe: add a new domain (e.g. `vulnerability_researcher`)

1. **Scaffold the package** under `src/vulnerability_researcher/` (copy the
   `reverse_engineer` anatomy): `__init__.py`, `agent.py`, `composition.py`,
   `prompts/` (loader + `.md`), and whatever `agents/`/`tools/`/`mcp/` it needs.
2. **`composition.py`**: write `build_vulnerability_researcher_composition()` +
   `@lru_cache get_vulnerability_researcher_composition()`, registering its
   profile/agents/tools/MCP/codec and freezing on its root. Use
   `get_settings()`; provide a `load_<domain>_prompt` via each descriptor's
   `prompt_loader`.
3. **`agent.py`**: `root_agent = get_vulnerability_researcher_composition().root_agent`.
4. **`pyproject.toml`**: add `"src/vulnerability_researcher"` to
   `[tool.hatch.build.targets.wheel].packages` (`src/arema` stays first).
5. **Register with the router**: in `src/greeter_agent/composition.py::_domain_roots()`
   append `get_vulnerability_researcher_composition().root_agent`.
6. **Tests**: `tests/vulnerability_researcher/` with a `conftest.py` pinning
   `AREMA_LLM_PROVIDER=ollama` (+ cache clears) like
   `tests/reverse_engineer/conftest.py`.
7. **Verify**: `make check` green; `adk run src/vulnerability_researcher` loads;
   the greeter routes to it (`adk run src/greeter_agent`).

That is the entire surface area. No core changes are required to add a domain.

## 7. Running & smoke-testing

- **Web UI:** `make adk-web` → lists `greeter_agent` and every domain. Pick one
  and chat. (Runs `adk web` with `cwd=src/`.)
- **Interactive CLI:** `make adk-run` → `adk run src/greeter_agent` (the router).
  For a domain directly: `adk run src/reverse_engineer`.
- **Sandbox (RE flow):** disabled by default. Enable per-run with
  `AREMA_SANDBOX_ENABLED=true` (and `--extra sandbox` for the k8s client). The
  pool map in `.env` must list all six engine pools:
  `AREMA_SANDBOX_POOL_MAP={"radare2-mcp":"radare2-mcp-pool","ghidra-rpc":"ghidra-rpc-pool","deobfuscation-tools":"deobfuscation-tools-pool","ilspy-mcp":"ilspy-mcp-pool","jadx":"jadx-pool","analysis-workbench":"analysis-workbench-pool"}`.
  Prune orphaned claimed pods with `make sandbox-prune`.

### Malformed tool-call JSON (auto-repaired)

LLMs occasionally emit tool-call arguments that aren't strict JSON: single-
quoted keys, trailing commas, unquoted keys, Python literals (`None`/`True`).
AREMA repairs these automatically: every provider response is passed through
[`json_repair`](https://github.com/mangiucugna/json_repair) in
`src/arema/core/model_factory.py` (`_ConfiguredRetryLiteLLMClient`) **before**
ADK parses the tool call, so ADK never sees invalid JSON.

- **Universal:** works for *all* tools, including external MCP tools (r2mcp)
  whose schemas can't be made strict-conformant, and *all* providers. No flag,
  no per-tool opt-in. Valid JSON passes through unchanged (json_repair tries
  `json.loads` first). ADK's own malformed-JSON retry remains as a final backstop.
- **Why not OpenAI `strict`/Structured Outputs here:** strict mode requires
  *all* params required (`additionalProperties:false`, no optionals), which is
  incompatible with tools that have optional params, notably r2mcp's
  `open_file` (`baddr`/`arch`/`bits`/`cpu` are optional numerics; forcing them
  required makes the model fill `""`, which r2mcp rejects with
  *"expected numeric string"*). json_repair fixes the malformed-JSON problem
  without that downside, so it is the default mechanism. (Strict mode was
  evaluated and removed for this reason; constrained decoding via `outlines` is
  only viable for self-hosted models with logits access, not the zai API.)
- **For structured *final* outputs** (a different need, e.g. a typed report),
  use ADK's `LlmAgent(output_schema=…)` (Pydantic); note ADK's caveat that
  `output_schema` + `tools` is reliable only on some models.

### Known caveats
- **Sandbox terminate** at session end may log a non-fatal `SSLError` (the k8s
  client's local tunnel is torn down before the sandboxclaim is deleted). The
  `release_case` / `release_ghidra_case` helpers retry on transient errors and
  fall back to `kubectl delete sandboxclaim`, but a verbose urllib3 traceback may
  still appear in the logs. Analysis always completes first; prune orphans with
  `make sandbox-prune`.
- The arema CLI (`uv run arema`) is the **neutral-core smoke** agent (no tools),
  useful for infra checks, not analysis.
- **Ghidra image is large** (~1.3 GB). The first `make sandbox-build-images` takes a
  few minutes (Ghidra dominates); subsequent builds use the Docker cache.
