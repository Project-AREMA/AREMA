# Creating Tools in AREMA

This guide covers the five ways to add tools to an AREMA agent, from simplest to
most advanced. Each pattern is backed by a real example in the codebase.

> **Prerequisites:** Read [`AGENTS_AND_DISCOVERY.md`](./AGENTS_AND_DISCOVERY.md)
> (domain package anatomy) and [`EXTENDING_AREMA.md`](./EXTENDING_AREMA.md)
> (descriptor registration) first.

## The five tool patterns

| Pattern | When to use | Example in the codebase |
|---------|-------------|------------------------|
| **Plain function tool** | A pure function that needs no injected services | `clock_now` (neutral core example) |
| **Deferred-factory tool** | A tool that needs `RuntimeServices` (sandbox executor, settings) | `prepare_sandbox`, `acquire_sample` |
| **Stateless sandbox-CLI tool** | One-shot file-in/result-out execution with no retained analysis session | `upx_unpack`, `floss_decode` |
| **Stateful CLI toolset** | A family of typed tools sharing a daemon/project lifecycle | The `ghidra_*` tools (ghidra-rpc) |
| **MCP server attachment** | An external MCP server the agent drives | The `radare2_mcp` tools (r2mcp) |

All five produce `ToolDescriptor`s that are registered in the composition's
`CatalogBuilder` and referenced from an agent's `tool_ids` (or `mcp_server_ids`
for MCP).

---

## 1. Plain function tool

The simplest case: a callable that takes args, returns a dict, and needs no
injected services. The descriptor's `id` MUST equal the function's `__name__`
(so the `OutputPolicy` binds at compaction time).

```python
from datetime import UTC, datetime
from arema.registry.descriptors import OutputPolicy, ToolDescriptor


def clock_now() -> dict[str, str]:
    """Return the current UTC time."""
    return {"utc": datetime.now(UTC).isoformat()}


CLOCK_TOOL = ToolDescriptor(
    id="clock_now",
    description="Return the current UTC time.",
    tool=clock_now,
    output_policy=OutputPolicy(max_chars=2_000),
)
```

Register: `builder.add_tool(CLOCK_TOOL)`. Reference: `tool_ids=("clock_now",)`.

---

## 2. Deferred-factory tool (needs RuntimeServices)

Most real tools need the sandbox executor, settings, or the codec registry at
call time. A plain callable can't see those, so use a **factory**. The factory
receives a `ToolBuildContext` (with `settings`, `services`, `catalog`) at
agent-build time and returns the callable ADK injects at call time.

**Pattern** (from `src/reverse_engineer/tools/prepare_sandbox.py`):

```python
from arema.registry.descriptors import OutputPolicy, ToolDescriptor


def build_prepare_sandbox(context: ToolBuildContext) -> ToolLike:
    executor = context.services.sandbox          # the K8sSandboxExecutor
    namespace = context.settings.sandbox_namespace

    def prepare_sandbox(artifact_id: str, tool_context: ToolContext) -> dict:
        # `executor` and `namespace` are closed over from the factory.
        handle = executor.claim(key=case_id, pool="radare2-mcp")
        pod = handle.backend_id
        kubectl_cp(artifact_path, namespace, pod, f"/app/{artifact_id}")
        return {"pod": pod, "ready": True}

    return prepare_sandbox


PREPARE_SANDBOX_TOOL = ToolDescriptor(
    id="prepare_sandbox",
    description="Claim a sandbox pod, copy the artifact, open a port-forward.",
    factory=build_prepare_sandbox,               # deferred, not `tool=`
    output_policy=OutputPolicy(max_chars=2_000),
)
```

> **Key points:**
> - The returned callable's `__name__` must match the descriptor `id` (for
>   `OutputPolicy` binding). In the example, the inner function is named
>   `prepare_sandbox` matching `id="prepare_sandbox"`.
> - Read the case_id from `tool_context.state` via duck-typed `.get` (NEVER
>   `isinstance(state, dict)`: ADK's State is a custom proxy).
> - `ToolContext` must be imported at runtime (`# noqa: TC002`). ADK resolves
>   annotations via `typing.get_type_hints` at tool-registration time.
> - Fail-open: wrap the body in try/except and return a degraded dict, never
>   raise.

---

## 3. Stateless sandbox-CLI tool

Use this pattern when one invocation can take an artifact file, run to
completion, and return a bounded result without retaining an interactive
analysis session. UPX and FLOSS fit this boundary: each call claims the shared
`deobfuscation-tools` pool, stages one content-addressed artifact, runs one
upstream CLI, reads bounded output, and returns. Additional utilities can share
the image without sharing wrapper semantics.

The shared runtime in
`src/reverse_engineering/tools/deobfuscation/runtime.py` owns only mechanics:

1. claim a Kubernetes sandbox from the `deobfuscation-tools` pool;
2. stage validated artifact bytes into an isolated work directory;
3. run a developer-constructed argv; and
4. size-check and read result files.

Keep applicability checks, exit-code interpretation, output parsing,
normalization, public error codes, provenance, and state updates in one wrapper
module per tool. Do not add tool-specific parsing to the shared runtime.

### Concise deferred-factory example

```python
# src/reverse_engineering/tools/deobfuscation/metadata.py
from google.adk.tools.tool_context import (
    ToolContext,  # noqa: TC002 - ADK resolves annotations at runtime
)

from arema.registry.descriptors import OutputPolicy, ToolDescriptor
from reverse_engineering.tools.deobfuscation.runtime import (
    ArtifactInputTooLarge,
    run_argv,
    stage_artifact,
)
from reverse_engineering.tools.deobfuscation.state import parse_current_classification

MAX_FILE_METADATA_INPUT_BYTES = 512 * 1024 * 1024


def build_file_metadata(context):
    def file_metadata(tool_context: ToolContext) -> dict[str, object]:
        """Inspect one artifact without retaining a sandbox analysis session."""
        try:
            # Expose no artifact selector to the model. This strict parser binds
            # classification.artifact_id to trusted canonical current-artifact state.
            plan = parse_current_classification(tool_context.state)
            staged = stage_artifact(
                context,
                plan.artifact_id,
                tool_context,
                tool_name="file-metadata",
                max_input_bytes=MAX_FILE_METADATA_INPUT_BYTES,
            )
            result = run_argv(staged, ["file", "--brief", "--", staged.input_path])
        except ArtifactInputTooLarge:
            return {
                "success": True,
                "applicable": False,
                "degraded": False,
                "reason": "input_too_large",
                "source_artifact_id": plan.artifact_id,
            }
        except (OSError, TimeoutError, ValueError, RuntimeError):
            return {
                "success": False,
                "applicable": True,
                "degraded": True,
                "error_code": "metadata_unavailable",
            }
        if result.exit_code != 0 or result.truncated:
            return {
                "success": False,
                "applicable": True,
                "degraded": True,
                "error_code": "metadata_failed",
            }
        return {
            "success": True,
            "applicable": True,
            "degraded": False,
            "source_artifact_id": plan.artifact_id,
            "description": result.stdout.strip(),
        }

    return file_metadata


FILE_METADATA_TOOL = ToolDescriptor(
    id="file_metadata",  # matches the returned callable's __name__
    description="Inspect one artifact with the sandboxed file CLI.",
    factory=build_file_metadata,
    output_policy=OutputPolicy(max_chars=2_000, max_list_items=10),
)
```

The callable accepts only `ToolContext`; an LLM must never select an arbitrary
artifact id from the global store. `parse_current_classification` enforces both
the lowercase SHA-256 shape and equality with trusted
`deobf:current_artifact_id` before custody passes to the runtime. Every wrapper
must also set a documented fixed input cap and pass it to `stage_artifact`.
Staging reads at most `cap + 1` bytes and rejects an oversized input before
claiming a pod or writing into the sandbox.

Installing a CLI is part of the security boundary, not a convenience step.
Pin the upstream release/version and verify its published checksum in
`images/deobfuscation-tools/Dockerfile` (and keep language dependency locks
fully hashed). Extend `deobfuscation-tools-healthcheck` with an exact version
assertion for every added binary. Because that healthcheck is the pod readiness
probe, a missing or unexpected tool version must keep the warm-pool pod
unready.

Exporting a binary in the image does **not** expose it to an agent. Add the
descriptor deliberately to the curated toolset:

```python
# src/reverse_engineering/tools/deobfuscation/toolset.py
DEOBFUSCATION_TOOLSET = (
    UPX_UNPACK_TOOL,
    FLOSS_DECODE_TOOL,
    FILE_METADATA_TOOL,
)
```

`register_re_infrastructure` then registers every descriptor in
`DEOBFUSCATION_TOOLSET` with the `CatalogBuilder`; an agent still needs the
descriptor id in its own `tool_ids`. This two-step allowlisting keeps future
image additions private until both registration and reachability are explicit.

Before exposing a stateless sandbox tool, add tests for:

- applicability and non-applicability (including file-format and size limits);
- canonical artifact equality/custody with no model-controlled artifact selector;
- stable, fail-open public failures with backend diagnostics excluded;
- shell-injection resistance and validated artifact/path inputs;
- bounded output through both wrapper limits and `OutputPolicy`;
- normalization of malformed, oversized, truncated, and adversarial output;
- evidence provenance bound to the input and any recovered artifact id; and
- `re_guarded` registration with the tool id in
  `StructuralSanitizer.untrusted_tools` for binary-origin text.

Also update every evidence-policy allowlist that will consume the result. In
the malware pipeline this includes the evidence critic's exact known-tool
allowlist and its provenance rules. A descriptor that is registered and
reachable but absent from the sanitizer or critic policy is not fully
integrated.

`OutputPolicy` limits context size; it is not a substitute for wrapper-level
size preflights, semantic validation, or provenance. Likewise, the structural
sanitizer frames and redacts untrusted binary-origin text, but does not decide
whether a result is applicable or successful.

### Choosing the execution boundary

- Use this stateless function-tool pattern for a one-shot CLI whose complete
  contract is file-in/result-out and whose invocation needs no retained
  session.
- Use radare2 MCP when the upstream server already provides a broad, typed,
  interactive analysis surface (open, analyze, enumerate, navigate, and
  decompile). Recreating that surface as individual wrappers would duplicate
  the upstream protocol.
- Use a separate Ghidra-like pool and lifecycle when tools share a long-lived
  daemon, loaded binary, or project. A preparation tool owns claim/load state;
  the typed command family consumes that state; cleanup releases it.

Do not promote a stateless utility to MCP or a stateful lifecycle merely because
it shares an image with other tools. Select the boundary from its execution
semantics.

---

## 4. Stateful CLI toolset (wrapping a CLI engine)

When a tool surface is a family of related commands against an external CLI
(e.g. `ghidra-rpc decompile`, `ghidra-rpc search-decompiled`, ...), hand-writing
each as a separate factory is boilerplate. The **spec-driven builder** turns a
table of command specs into typed tools automatically. This is the function-tool
analog of the MCP `McpServerDescriptor` seam.

**Pattern** (from `src/reverse_engineer/tools/ghidra/`):

### Step 1: Define the command spec table

```python
# src/<domain>/tools/<engine>/commands.py
from dataclasses import dataclass
from arema.registry.descriptors import OutputPolicy


@dataclass(frozen=True, slots=True)
class CliCommandSpec:
    name: str                    # the tool's __name__ + descriptor id
    description: str
    subcommand: str              # the CLI subcommand
    output_policy: OutputPolicy
    arg_template: str = ""       # {placeholder} args (e.g. "{function}")
    extra_flags: str = ""        # static flags (e.g. "--high")


ENGINE_COMMANDS: tuple[CliCommandSpec, ...] = (
    CliCommandSpec(
        name="engine_decompile",
        description="Decompile a function.",
        subcommand="decompile",
        output_policy=OutputPolicy(max_chars=10_000),
        arg_template="{function}",
    ),
    # ... one spec per command
)
```

### Step 2: Build the toolset

```python
# src/<domain>/tools/<engine>/toolset.py
from arema.runtime.agent_factory import ToolBuildContext


def build_engine_tool(context: ToolBuildContext, spec: CliCommandSpec) -> ToolDescriptor:
    namespace = context.settings.sandbox_namespace

    def _tool(tool_context, **kwargs):
        case_state = _CASE_STATE.get(_resolve_case_id(tool_context))
        if case_state is None:
            return {"success": False, "error": "engine not prepared"}
        cmd_args = ["engine-cli", spec.subcommand, case_state["binary"]]
        cmd_args += _tokenize(spec.arg_template, kwargs)
        if spec.extra_flags:
            cmd_args += spec.extra_flags.split()
        stdout = kubectl_exec(cmd_args, namespace, case_state["pod"])
        return {"success": True, "output": stdout}

    _tool.__name__ = spec.name
    return ToolDescriptor(id=spec.name, description=spec.description,
                          factory=lambda ctx, s=spec: build_engine_tool(ctx, s),
                          output_policy=spec.output_policy)


def build_engine_toolset() -> tuple[ToolDescriptor, ...]:
    """Returns deferred-factory ToolDescriptors: one per command spec."""
    return tuple(
        ToolDescriptor(id=spec.name, description=spec.description,
                       factory=lambda ctx, s=spec: build_engine_tool(ctx, s),
                       output_policy=spec.output_policy)
        for spec in ENGINE_COMMANDS
    )
```

### Step 3: Register in the composition

```python
for desc in build_engine_toolset():
    builder.add_tool(desc)
```

> **Key points:**
> - Each tool's factory is deferred: it receives `ToolBuildContext` at
>   agent-build time (matching the deferred-factory pattern).
> - `kubectl_exec` takes `list[str]` args (NO `sh -c`) to prevent shell injection
>   from agent-controlled values (function names, regex patterns).
> - The binary name / pod name is injected from a case-state registry (populated
>   by a `prepare_<engine>` lifecycle tool), never passed by the agent.
> - The spec table IS the tool surface. Adding a tool = one `CliCommandSpec` line.

---

## 5. MCP server attachment

An MCP server (like r2mcp) is attached to an agent via `mcp_server_ids`. The
descriptor declares the transport; the agent factory resolves it into a
`ResilientMcpToolset` appended to the agent's tools.

**Pattern** (from `src/reverse_engineer/mcp/radare2.py`):

```python
from arema.registry.descriptors import McpServerDescriptor, StreamableHttpTransport


RADARE2_MCP = McpServerDescriptor(
    id="radare2_mcp",
    transport=StreamableHttpTransport(
        url="http://127.0.0.1:8765/mcp",       # reached via kubectl port-forward
        read_timeout=120.0,                      # hard bound on wedged calls
    ),
    required=False,                              # optional: degrades to no-tools
    tool_allowlist=("open_file", "analyze", "list_functions", ...),  # curated
)
```

Register: `builder.add_mcp_server(RADARE2_MCP)`.
Reference: `AgentDescriptor(..., mcp_server_ids=("radare2_mcp",))`.

> **Key points:**
> - `StreamableHttpTransport` is used for sandbox MCP servers (r2mcp runs in a
>   pod, reached via `kubectl port-forward`). The sandbox-router is NOT a
>   transparent MCP proxy: use direct pod port-forward.
> - `required=False` makes the server optional: on failure it degrades to
>   no-tools (the run continues). `required=True` re-raises.
> - `tool_allowlist` curates which MCP tools the agent sees (defense in depth).
> - `read_timeout` is the hard bound on a wedged call (no-response). Set it
>   sensibly (120s, not 600s).

---

## Conventions for all tool patterns

### OutputPolicy

Every tool must declare an `OutputPolicy`: it bounds the tool's response before
it enters the model's context (the compactor runs as the last `after_tool`
callback). Tune `max_chars` and `max_list_items` per tool's expected output size.

### The `prompt_loader` seam

Domain agents ship their own prompts (the neutral core's `load_prompt` only reads
`arema.prompts`). Each domain provides a `load_<domain>_prompt` and passes it via
the descriptor's `prompt_loader` field:

```python
AgentDescriptor(
    ...,
    factory=build_llm_agent,
    prompt_loader=load_domain_prompt,    # reads src/<domain>/prompts/<id>.md
)
```

### Sanitization for binary-origin tools

If a tool's output originates from an untrusted binary (decompiled code, strings,
hex dumps), the agent should use a `re_guarded`-style profile whose
`extra_after_tool` carries the `StructuralSanitizer` (see
[`CONTEXT_AND_RESILIENCE.md`](./CONTEXT_AND_RESILIENCE.md) § Output sanitization).
The sanitizer frames + redacts prompt-injection signatures in the tool output
before it reaches the model. Add the tool's name to the profile's
`untrusted_tools` set.

### Tools that reach the public internet

A tool that calls an external HTTP API runs in the **host process**, never in a
sandbox. This is not a preference: every pool declares
`spec.networkPolicy.egress: []`, so a pod cannot resolve DNS, and per
[`LESSONS_LEARNED.md`](./LESSONS_LEARNED.md) #15 a NetworkPolicy denies by DROP
rather than REJECT, which turns an attempted call into a multi-minute stall
instead of a fast failure.

`src/reverse_engineering/intel/` is the worked example. Four rules it follows,
all of which apply to any future outbound tool:

1. **An explicit timeout on every call**, plus a ceiling on the sum when several
   calls run in sequence. An outbound tool on the intake path turns a dead
   endpoint into a user-visible stall.
2. **Fail open, and log the error type only.** The tool's own job continues
   without the enrichment.
3. **Gate on configuration.** With nothing configured, make no request at all.
   That is what keeps a fresh clone and the test suite off the network.
4. **Sanitize everything that comes back.** A response field can be
   attacker-controlled text arriving through a trusted-looking API (a filename
   chosen at submission time, for instance), and it is heading for an ADK
   instruction template where a brace is a placeholder. Reuse the bounded
   ASCII-only reduction in `intel/models.py::sanitize_summary`.

Tests fake the transport by `monkeypatch.setattr` on the importing module's
symbol, never by hitting the network. Capture one real response body per
endpoint and commit it as a fixture, the same discipline
`tests/reverse_engineering/test_detect_it_easy.py` states for DIE.

### kubectl helpers

For sandbox-driven tools, two helpers live in `src/reverse_engineer/runtime/portforward.py`:
- `kubectl_cp(src, namespace, pod, dest)`: copy a file into a pod.
- `kubectl_exec(args: list[str], namespace, pod)`: run a command (no shell; prevents injection).

Both raise `RuntimeError` on failure; callers should catch + return a degraded
dict (fail-open).

### The case-state registry pattern

Tools that share a sandbox session (like the ghidra tools sharing a claimed pod)
use a module-level dict keyed by `case_id` to stash the pod name + binary name.
A `prepare_<engine>` lifecycle tool populates it; the analysis tools read it.

### Sandbox identity (invariant)

Every sandbox-backed tool resolves its `case_id` through the neutral
`arema.runtime.sessions.resolve_sandbox_case_id(tool_context)`, never a private
per-tool default. The resolver preserves an explicit
`SessionKeys.SANDBOX_CASE_ID` when present, otherwise derives one from the ADK
invocation ID and persists it into session state, and raises
`SandboxIdentityError` when neither source is available. This guarantees every
sandbox operation in one invocation shares one identity across Radare2, Ghidra,
UPX, and FLOSS. Binary execution remains Kubernetes-only. Authoritative
inter-stage evidence travels through named session state, not conversation
history; a tool's job is to return bounded structured results, never to treat
prior model messages as authoritative.
