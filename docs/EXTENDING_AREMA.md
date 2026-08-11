# Extending AREMA

AREMA is a shell: you extend it by adding **immutable descriptors** to the
capability catalog inside a composition root, not by editing the runtime. This
guide gives one concrete registration recipe for each descriptor kind: an agent,
a tool, an MCP server, a memory codec, and a runtime profile.

> **Domain packages.** The neutral core (`src/arema/composition.py`) ships only
> the smoke agent. Real capabilities live in **domain packages**
> (`src/<domain>/composition.py`) that mirror the core's composition shape but
> live outside the neutrality perimeter. See
> [`AGENTS_AND_DISCOVERY.md`](./AGENTS_AND_DISCOVERY.md) for the multi-agent
> layout and the add-a-domain recipe, and
> [`CREATING_TOOLS.md`](./CREATING_TOOLS.md) for the dedicated guide on building
> function tools, MCP tools, and CLI-driven toolsets.

The examples below use the neutral core's `build_default_composition` for
illustrative simplicity, but the same patterns apply in a domain's
`build_<domain>_composition`. `build_default_composition` itself is the
minimal reference (`src/arema/composition.py`): it registers
`RuntimeProfile.safe_default()` and `SMOKE_AGENT_DESCRIPTOR`, then freezes on
`"smoke_agent"`.

```python
builder = CatalogBuilder()
builder.add_runtime_profile(RuntimeProfile.safe_default())
builder.add_agent(SMOKE_AGENT_DESCRIPTOR)
# ── your registrations go here ──
catalog = builder.freeze(_ROOT_AGENT_ID)
```

After `freeze`, a composition root also calls `validate_tool_codecs(catalog,
codecs)` to confirm every tool's `memory_codec_ids` resolve against the codec
registry it holds.

## Catalog validation rules you must satisfy

`builder.freeze(root_agent_id)` validates the whole graph. Registrations that
violate any of these raise at composition time (never silently):

- **References resolve.** An agent's `runtime_profile_id`, `tool_ids`,
  `mcp_server_ids`, and `sub_agent_ids` must all name registered descriptors.
- **Every agent is reachable from the root.** A newly added agent must be a
  (transitive) `sub_agent` of the root, or be the root itself. An orphan agent
  fails validation.
- **The sub-agent graph is acyclic.**
- **Agent kind is consistent with its inputs.** `_effective_agent_kind` resolves
  `AgentKind.AUTO` to `LLM` when `prompt_id` is set and to `COMPOSITE` when it
  is `None`. The resolved kind then constrains the descriptor:
  - **LLM** requires a non-empty `prompt_id`.
  - **COMPOSITE** requires `prompt_id=None`, forbids `tool_ids`/`mcp_server_ids`/
    `output_key`, and requires at least one `sub_agent`.
  - **DETERMINISTIC** requires `prompt_id=None` and forbids `prompt_loader`,
    tools, MCP servers, `output_key`, and `sub_agent_ids`.
- **`output_schema` pairs with `output_key`.** An `AgentDescriptor` that sets
  `output_schema` must also set `output_key`, and must not declare tools or MCP
  servers (ADK's schema coercion is unreliable on a tool-using turn). Enforced
  in the dataclass `__post_init__`.
- **A tool carries exactly one of `tool` or `factory`.** Plain callable,
  `BaseTool`, or `BaseToolset` on one side; a `ToolFactory` on the other.
- **Tool codecs exist.** Every `memory_codec_ids` entry a tool declares must
  resolve against the composition's codec registry (checked post-freeze).
- **IDs are unique** within each descriptor kind.

## 1. Register an agent

An `AgentDescriptor` (`src/arema/registry/descriptors.py`) carries everything
the runtime needs: id, name, description, a `factory`, a `runtime_profile_id`,
and the prompt/tools/MCP/sub-agent references the factory consumes. Fields not
shown below keep their defaults (`prompt_loader=None`, `output_key=None`,
`output_schema=None`, `after_agent_callbacks=()`, `metadata={}`, `version="1"`,
`kind=AgentKind.AUTO`).

### 1a. LLM agent (the common case)

An LLM agent needs a packaged prompt and the `build_llm_agent` factory. The
prompt ships as `<prompt_package>/<prompt_id>.md`.

```python
from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_llm_agent


WORKER_AGENT = AgentDescriptor(
    id="worker_agent",
    name="worker_agent",
    description="A neutral demonstration agent.",
    prompt_id="worker_agent",          # needs src/arema/prompts/worker_agent.md
    factory=build_llm_agent,
    runtime_profile_id="safe_default",
    output_key="worker_result",        # optional: publishes its answer to state
    # output_schema=WorkerResult,      # optional: requires output_key; no tools
    # after_agent_callbacks=(normalize,),  # optional: ADK after-agent callbacks
    # metadata={"max_iterations": 3},  # optional: arbitrary JSON metadata
)

builder.add_agent(WORKER_AGENT)
```

#### The `prompt_loader` seam

By default the runtime loads `prompt_id` from the neutral
`arema.prompts` package via `load_prompt`. A domain that ships its own prompts
passes its package-relative loader instead — the loader is a plain
`Callable[[str], str]`:

```python
from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_llm_agent
from reverse_engineering.prompts.loader import load_domain_prompt
# load_domain_prompt resolves ``reverse_engineering.prompts/<prompt_id>.md``.

SAMPLE_INTAKE = AgentDescriptor(
    id="sample_intake",
    name="sample_intake",
    description="First pipeline stage of the RE domain.",
    prompt_id="sample_intake",
    factory=build_llm_agent,
    prompt_loader=load_domain_prompt,   # domain-relative prompt resolution
    tool_ids=("acquire_sample", "prepare_sandbox"),
)
```

### 1b. Composite agents (sequential / parallel / loop)

A composite shell has `prompt_id=None`, no tools, no MCP, and no `output_key`,
only ordered `sub_agent_ids`. The runtime ships three factories:

- `build_sequential_agent` — sub-agents run in fixed order, each to completion,
  sharing one session (framework-enforced orchestration).
- `build_parallel_agent` — sub-agents run concurrently in isolated branches.
- `build_loop_agent` — sub-agents repeat until one escalates or the cap is hit.
  `metadata["max_iterations"]` **must** be a positive integer (the factory
  raises at build time otherwise); the loop is always capped.

```python
from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import (
    build_loop_agent,
    build_parallel_agent,
    build_sequential_agent,
)

PIPELINE_ROOT = AgentDescriptor(
    id="pipeline_root",
    name="pipeline_root",
    description="A fixed-order pipeline shell.",
    prompt_id=None,
    factory=build_sequential_agent,
    sub_agent_ids=("intake", "analyze", "report"),
    after_agent_callbacks=(release_session,),  # optional pipeline-end hook
)

DEEP_LOOP = AgentDescriptor(
    id="deep_loop",
    name="deep_loop",
    description="A bounded worker/gate loop.",
    prompt_id=None,
    factory=build_loop_agent,
    sub_agent_ids=("worker", "completion_gate"),
    metadata={"max_iterations": 3},
)

BROADCAST = AgentDescriptor(
    id="broadcast",
    name="broadcast",
    description="Run two extractors concurrently.",
    prompt_id=None,
    factory=build_parallel_agent,
    sub_agent_ids=("extract_a", "extract_b"),
)
```

### 1c. Deterministic agents (escalation gate / token-usage reporter)

A deterministic leaf has `prompt_id=None`, no loader, no tools, no MCP, no
`output_key`, and no sub-agents — set `kind=AgentKind.DETERMINISTIC`. Two
factories ship:

- `build_token_usage_reporter(context)` — renders the run's per-model token
  usage as a final report section.
- `build_escalation_gate(context, *, evaluator)` — emits one event whose
  `EventActions` carry an `escalate` flag and a `state_delta`. `evaluator` is a
  `Callable[[Mapping[str, object]], EscalationDecision]`; wire it via
  `functools.partial`.

```python
from functools import partial

from arema.registry.descriptors import AgentDescriptor, AgentKind
from arema.runtime.agent_factory import (
    EscalationDecision,
    build_escalation_gate,
    build_token_usage_reporter,
)


def evaluate(state) -> EscalationDecision:
    return EscalationDecision(escalate=state.get("done", False), state_delta={})


GATE = AgentDescriptor(
    id="completion_gate",
    name="completion_gate",
    description="Deterministically exits the loop when coverage is reached.",
    prompt_id=None,
    factory=partial(build_escalation_gate, evaluator=evaluate),
    kind=AgentKind.DETERMINISTIC,
)

REPORTER = AgentDescriptor(
    id="token_usage_reporter",
    name="token_usage_reporter",
    description="Renders per-model token usage as a final appendix.",
    prompt_id=None,
    factory=build_token_usage_reporter,
    kind=AgentKind.DETERMINISTIC,
)
```

### Reachability

To keep a new agent reachable, make it a child of the root. The shipped
`SMOKE_AGENT_DESCRIPTOR` has no sub-agents, so wiring a child means defining
your own root descriptor with `sub_agent_ids=("worker_agent",)` and freezing on
that root's id (update `_ROOT_AGENT_ID`), or making `worker_agent` the new root.

## 2. Register a tool

A `ToolDescriptor` (`src/arema/registry/descriptors.py`) carries exactly one of
a concrete `tool` (a plain callable, `BaseTool`, or `BaseToolset`) or a deferred
`factory`; validation rejects both-set and neither-set. Its `OutputPolicy`
governs how the tool's responses are bounded before entering context (defaults:
`max_chars=15_000`, `max_list_items=30`). Optional `memory_codec_ids` advertise
the record kinds the tool persists, and `callbacks` attach per-tool lifecycle
hooks.

```python
from datetime import UTC, datetime

from arema.registry.descriptors import OutputPolicy, ToolDescriptor


def clock_now() -> dict[str, str]:
    """Return the current UTC time as an ISO-8601 string."""
    return {"utc": datetime.now(UTC).isoformat()}


CLOCK_TOOL = ToolDescriptor(
    id="clock_now",                    # must match the tool's runtime name
    description="Return the current UTC time.",
    tool=clock_now,
    output_policy=OutputPolicy(max_chars=2_000, max_list_items=10),
    # memory_codec_ids=("example/finding",),  # optional, validated post-freeze
    # callbacks=ToolLifecycleCallbacks(before=(budget_guard,)),  # optional
)

builder.add_tool(CLOCK_TOOL)
```

Then reference it from an agent: `AgentDescriptor(..., tool_ids=("clock_now",))`.

> **ID must equal the runtime tool name.** The output compactor looks up a
> policy by the tool's ADK runtime `name`. For a plain function that name is its
> `__name__`, so the descriptor `id` (`"clock_now"`) must match the function
> name for its `OutputPolicy` to bind; otherwise the safe default policy applies.

### Factory-based tools (need services)

For a tool built lazily — one that needs `RuntimeServices` (e.g. the sandbox
executor) or sibling capabilities — supply a `factory` instead of `tool`. The
factory is `Callable[[ToolBuildContext], ToolLike]`, called once at agent-build
time with a frozen `ToolBuildContext(settings, services, catalog)`. The inner
callable it returns is what ADK invokes per turn.

```python
from arema.registry.descriptors import OutputPolicy, ToolDescriptor, ToolLifecycleCallbacks
from arema.runtime.agent_factory import ToolBuildContext
from arema.registry.descriptors import ToolLike


def build_run_python(context: ToolBuildContext) -> ToolLike:
    sandbox = context.services.sandbox      # SandboxExecutor | None
    settings = context.settings             # typed Settings

    def run_python(code: str) -> dict[str, object]:
        # ... close over `sandbox` / `settings` ...
        return {"exit_code": 0, "stdout": ""}

    return run_python


RUN_PYTHON_TOOL = ToolDescriptor(
    id="run_python",
    description="Run agent-authored Python in the workbench sandbox.",
    factory=build_run_python,
    output_policy=OutputPolicy(max_chars=32_000, max_list_items=200),
    callbacks=ToolLifecycleCallbacks(before=(run_python_budget_guard,)),
)
```

> **See [`CREATING_TOOLS.md`](./CREATING_TOOLS.md)** for the complete guide on
> building tools: the deferred-factory pattern, the spec-driven CLI toolset
> builder (for wrapping a CLI engine like ghidra-rpc as a family of typed
> tools), MCP server attachment via `StreamableHttpTransport`, and the
> `prompt_loader` seam for domain-relative prompts.

## 3. Register an MCP server

A `McpServerDescriptor` names one MCP server and its exposed-tool policy.
`required=False` (the default) honors the resilience contract — an unreachable
server degrades to an empty toolset instead of aborting the run; `required=True`
re-raises. The optional `tool_allowlist` restricts the exposed surface and
`tool_name_prefix` namespaces the server's tool names.

```python
from arema.registry.descriptors import (
    McpServerDescriptor,
    StdioTransport,
    StreamableHttpTransport,
    SseTransport,
)

EXAMPLE_STDIO = McpServerDescriptor(
    id="example_mcp",
    transport=StdioTransport(command="example-mcp-server", args=("--stdio",)),
    required=False,                    # optional servers degrade to no-tools
    tool_allowlist=("do_thing",),      # optional: restrict exposed tools
    # tool_name_prefix="ex",           # optional: namespace tool names
    # header_provider=_headers,        # per-request headers (HTTP transports)
)

EXAMPLE_HTTP = McpServerDescriptor(
    id="engine_mcp",
    transport=StreamableHttpTransport(
        url="http://127.0.0.1:8765/mcp",   # ${VAR} subst happens at build time
        read_timeout=600.0,
    ),
    required=False,
    tool_allowlist=("open_file", "analyze", "decompile_function"),
)

builder.add_mcp_server(EXAMPLE_STDIO)
builder.add_mcp_server(EXAMPLE_HTTP)
```

Three transports ship: `StdioTransport(command, args, env, connect_timeout)`,
`SseTransport(url, headers, connect_timeout, read_timeout)`, and
`StreamableHttpTransport(url, headers, connect_timeout, read_timeout,
terminate_on_close)`. URLs must be `http`/`https`, must have a host, and must
not embed credentials; header names/values and `${VAR}` placeholders are
validated at freeze time and resolved from the environment when the toolset is
built via `build_mcp_toolset`. `SseTransport` and `StreamableHttpTransport`
support a `header_provider: Callable[[object], dict[str, str]]` on the
descriptor (its return value is merged into every request) for per-run routing
of a sandboxed MCP server — e.g. `X-Sandbox-ID` / `X-Sandbox-Port` /
`Authorization`.

> **Attached.** MCP attachment is wired end to end. The agent factory's
> `_build_agent` (`src/arema/runtime/agent_factory.py`) resolves each id in an
> agent's `mcp_server_ids` via `build_mcp_toolset(...)` and appends the
> resulting `ResilientMcpToolset` to that agent's `tools`. Reference the server
> from an agent with `AgentDescriptor(..., mcp_server_ids=("engine_mcp",))`.

## 4. Register a memory codec

Codecs bind a `(namespace, kind, schema_version)` triple to a Pydantic payload
model. Register yours on the composition's codec registry, right after it is
created in `build_default_composition` (or the domain's equivalent):

```python
from pydantic import BaseModel

from arema.memory.codecs import RecordCodec

class FindingRecord(BaseModel):
    title: str
    detail: str


# in build_default_composition, after: codecs = default_core_codec_registry()
codecs.register(
    RecordCodec(
        namespace="example",
        kind="finding",
        schema_version=1,             # version 1 must not define an upgrade fn
        payload_type=FindingRecord,
    )
)
```

The registry exposes ids as `"namespace/kind"`. A tool may then declare it, and
`validate_tool_codecs` checks the reference at composition time (post-freeze):

```python
ToolDescriptor(
    id="record_finding",
    description="Persist a finding.",
    tool=record_finding,
    memory_codec_ids=("example/finding",),
)
```

Two rules are worth knowing:

- **Version chains are contiguous and forward-only.** Versions register
  starting at 1; version 1 must not carry an `upgrade_from_previous`, every
  later version must. `decode` walks the chain from the envelope's version up to
  the current version, applying each upgrade in order, then validates only the
  final payload.
- **Envelope hashes are canonical.** `encode` hashes the payload with
  `canonical_content_hash` — SHA-256 of JSON serialised with `sort_keys=True`
  and compact separators — so two semantically identical payloads always hash to
  the same value regardless of dict insertion order.

To evolve the schema, register version 2 with an `upgrade_from_previous` that
maps a v1 payload dict to the v2 shape; `decode` walks the chain automatically.

## 5. Register a runtime profile

A `RuntimeProfile` is the declarative switch surface for one agent's runtime.
The default, `RuntimeProfile.safe_default()` (id `"safe_default"`), turns every
guard on; you register a custom one and reference it by id from an agent. The
profile fields, in addition to `id` and `context_mode`, are ten boolean toggles
and three extra-callback tuples:

```python
from arema.registry.descriptors import ContextMode, RuntimeProfile

FAST_ISOLATED = RuntimeProfile(
    id="fast_isolated",
    context_mode=ContextMode.ISOLATED,   # each turn starts from a fresh context
    capture_request=True,
    throttle_model=False,                # disable inter-call spacing
    retry_model=True,
    enforce_turn_limit=True,
    enforce_context_budget=True,
    record_metrics=True,
    guard_tools=True,
    record_memory=True,
    compact_tool_output=True,
    recover_tool_errors=True,
    # extra_before_model=(...),          # optional profile-wide before-model hooks
    # extra_before_tool=(...),           # optional profile-wide before-tool hooks
    # extra_after_tool=(...),            # optional profile-wide after-tool hooks
)

builder.add_runtime_profile(FAST_ISOLATED)
```

Then: `AgentDescriptor(..., runtime_profile_id="fast_isolated")`. The callback
chain is rebuilt per agent from its profile (plus the agent's per-tool
callbacks) and re-validated, so enabling or disabling a concern — or extending
an `extra_*` tuple — can never break the approved callback ordering (registered
tool-guard first in `before_tool`, compactor last in `after_tool`).

## Putting it together

A typical extension registers a runtime profile, one or more tools (and their
codecs), and an agent that references them, then either makes that agent the
root or wires it under a custom root. Because the catalog is frozen and fully
validated at `freeze` time — references, cycles, reachability, agent-kind
constraints, and tool/factory/exactly-one rules all checked up front — a
mistake surfaces immediately at startup with a precise error, not as a silent
misconfiguration at run time.
