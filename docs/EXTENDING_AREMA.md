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
`build_<domain>_composition`.

```python
builder = CatalogBuilder()
builder.add_runtime_profile(RuntimeProfile.safe_default())
builder.add_agent(SMOKE_AGENT_DESCRIPTOR)
# ── your registrations go here ──
catalog = builder.freeze(_ROOT_AGENT_ID)
```

## Catalog validation rules you must satisfy

`builder.freeze(root_agent_id)` validates the whole graph. Registrations that
violate any of these raise at composition time (never silently):

- **References resolve.** An agent's `runtime_profile_id`, `tool_ids`,
  `mcp_server_ids`, and `sub_agent_ids` must all name registered descriptors.
- **Every agent is reachable from the root.** A newly added agent must be a
  (transitive) `sub_agent` of the root, or be the root itself. An orphan agent
  fails validation.
- **The sub-agent graph is acyclic.**
- **Tool codecs exist.** Every `memory_codec_ids` entry a tool declares must
  resolve against the composition's codec registry.
- **IDs are unique** within each descriptor kind.

## 1. Register an agent

An agent needs a packaged prompt (`src/arema/prompts/<prompt_id>.md`) and a
factory. The factory usually just delegates to `build_llm_agent`.

```python
from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_llm_agent


def build_worker_agent(context):
    # `context` is a fully resolved AgentBuildContext (model, instruction,
    # tools, sub-agents, validated callback chain).
    return build_llm_agent(context)


WORKER_AGENT = AgentDescriptor(
    id="worker_agent",
    name="worker_agent",
    description="A neutral demonstration agent.",
    prompt_id="worker_agent",          # needs src/arema/prompts/worker_agent.md
    factory=build_worker_agent,
    runtime_profile_id="safe_default",
    output_key="worker_result",        # optional: publishes its answer to state
)

builder.add_agent(WORKER_AGENT)
```

To keep it reachable, make it a child of the root. Because the shipped
`SMOKE_AGENT_DESCRIPTOR` has no sub-agents, wiring a child means defining your own
root descriptor with `sub_agent_ids=("worker_agent",)` and freezing on that root's
id (update `_ROOT_AGENT_ID` accordingly), or making `worker_agent` the new root.

## 2. Register a tool

A `ToolDescriptor` carries exactly one of a concrete `tool` (a plain callable,
`BaseTool`, or `BaseToolset`) or a deferred `factory`. Its `OutputPolicy` governs
how the tool's responses are bounded before entering context.

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
)

builder.add_tool(CLOCK_TOOL)
```

Then reference it from an agent: `AgentDescriptor(..., tool_ids=("clock_now",))`.

> **ID must equal the runtime tool name.** The output compactor looks up a
> policy by the tool's ADK runtime `name`. For a plain function that name is its
> `__name__`, so the descriptor `id` (`"clock_now"`) must match the function name
> for its `OutputPolicy` to bind; otherwise the safe default policy applies.

For a tool built lazily (e.g. one that needs settings or sibling capabilities),
supply a `factory` instead of `tool`; it receives a `ToolBuildContext` with the
`settings`, `services`, and read-only `catalog`.

> **See [`CREATING_TOOLS.md`](./CREATING_TOOLS.md)** for the complete guide on
> building tools: the deferred-factory pattern (for tools that need
> `RuntimeServices`, like the sandbox executor), the spec-driven CLI toolset
> builder (for wrapping a CLI engine like ghidra-rpc as a family of typed tools),
> MCP server attachment via `StreamableHttpTransport`, and the `prompt_loader`
> seam for domain-relative prompts.

## 3. Register an MCP server

```python
from arema.registry.descriptors import McpServerDescriptor, StdioTransport

EXAMPLE_MCP = McpServerDescriptor(
    id="example_mcp",
    transport=StdioTransport(command="example-mcp-server", args=("--stdio",)),
    required=False,                    # optional servers degrade to no-tools
    tool_allowlist=("do_thing",),      # optional: restrict exposed tools
)

builder.add_mcp_server(EXAMPLE_MCP)
```

Transports may also be `SseTransport(url=...)` or
`StreamableHttpTransport(url=...)`; both are URL- and header-validated at freeze
time, and support `${VAR}` placeholders resolved from the environment when the
toolset is built via `build_mcp_toolset`.

> **Attached.** `build_mcp_toolset` produces a `ResilientMcpToolset`, and the agent
> factory resolves an agent's `mcp_server_ids` onto that agent. Each referenced
> server's toolset is appended to the agent's `tools`. For per-run routing of a
> sandboxed MCP server, give the descriptor a `header_provider`
> (`Callable[[object], dict[str,str]]`) whose return value ADK injects into every
> request (e.g. `X-Sandbox-ID` / `X-Sandbox-Port` / `Authorization`).

## 4. Register a memory codec

Codecs bind a `(namespace, kind, schema_version)` triple to a Pydantic payload
model. Register yours on the composition's codec registry, right after it is
created in `build_default_composition`:

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
`_validate_tool_codecs` checks the reference at composition time:

```python
ToolDescriptor(
    id="record_finding",
    description="Persist a finding.",
    tool=record_finding,
    memory_codec_ids=("example/finding",),
)
```

Schema evolution is forward-only: register version 2 with an
`upgrade_from_previous` function that maps a v1 payload dict to the v2 shape;
`decode` walks the chain automatically.

## 5. Register a runtime profile

A `RuntimeProfile` is a set of declarative switches plus optional extra
callbacks. Register a custom one and reference it by id from an agent.

```python
from arema.registry.descriptors import ContextMode, RuntimeProfile

FAST_ISOLATED = RuntimeProfile(
    id="fast_isolated",
    context_mode=ContextMode.ISOLATED,  # each turn starts from a fresh context
    throttle_model=False,               # disable inter-call spacing
    # all other concerns (turn limit, context budget, tool guard, memory,
    # compaction, metrics, retry, capture) keep their guarded defaults
)

builder.add_runtime_profile(FAST_ISOLATED)
```

Then: `AgentDescriptor(..., runtime_profile_id="fast_isolated")`. The callback
chain is rebuilt per agent from its profile and re-validated, so enabling or
disabling a concern can never break the approved callback ordering.

## Putting it together

A typical extension registers a runtime profile, one or more tools (and their
codecs), and an agent that references them, then either makes that agent the root
or wires it under a custom root. Because the catalog is frozen and fully
validated at `freeze` time, a mistake surfaces immediately at startup with a
precise error, not as a silent misconfiguration at run time.
