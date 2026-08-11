# Creating Tools in AREMA

This guide covers the six ways to add a tool to an AREMA agent, from simplest to
most advanced. Each pattern is backed by a real example in the codebase.

> **Prerequisites:** Read [`AGENTS_AND_DISCOVERY.md`](./AGENTS_AND_DISCOVERY.md)
> (domain package anatomy) and [`EXTENDING_AREMA.md`](./EXTENDING_AREMA.md)
> (descriptor registration) first.

## The six tool patterns

| Pattern | When to use | Example in the codebase |
|---------|-------------|------------------------|
| **Plain function tool** | A callable that needs no injected `RuntimeServices` | `acquire_sample` (`src/reverse_engineering/tools/acquire_sample.py`) |
| **Deferred-factory tool** | A tool that needs `RuntimeServices` (sandbox executor, settings) | `prepare_sandbox`, `prepare_ilspy`, `prepare_ghidra`, `prepare_jadx` |
| **Stateless sandbox-CLI tool** | One-shot file-in/result-out execution with no retained analysis session | `upx_unpack`, `floss_decode` (`deobfuscation-tools` pool) |
| **Stateful CLI toolset** | A family of typed tools sharing a daemon/project lifecycle | The `ghidra_*` tools (`ghidra-rpc` pool) |
| **MCP server attachment** | An external MCP server the agent drives | `radare2_mcp`, `ilspy_mcp` |
| **Tool with lifecycle callbacks** | A tool that needs a per-tool budget guard or a loop-level advisor | `run_python` (budget guard + thrash detector) |

The first five produce `ToolDescriptor`s that are registered in the composition's
`CatalogBuilder` and referenced from an agent's `tool_ids` (or `mcp_server_ids`
for MCP). The sixth is the same `ToolDescriptor` carrying a
`ToolLifecycleCallbacks`, plus optional profile-level callbacks that govern the
loop around it.

---

## 1. Plain function tool

The simplest case: a callable registered with `tool=` rather than `factory=`. It
may read and write trusted session state through `ToolContext` and use module-level
collaborators (the artifact store, the intel sweep), but it cannot see
`RuntimeServices` — that is the only real distinction from pattern 2. The
descriptor's `id` MUST equal the function's `__name__` (so the `OutputPolicy`
binds at compaction time).

```python
from google.adk.tools.tool_context import ToolContext  # noqa: TC002 - ADK resolves annotations

from arema.registry.descriptors import OutputPolicy, ToolDescriptor
from reverse_engineering.artifacts import ArtifactStore, default_artifacts_root


def acquire_sample(path: str, tool_context: ToolContext | None = None) -> dict[str, str | int]:
    """Ingest a binary sample from a local path into the content-addressed store."""
    resolved = Path(path).expanduser()
    store = ArtifactStore(default_artifacts_root())
    artifact_id = store.acquire(resolved)
    # ... classify format, name packer, run the no-upload hash-reputation sweep,
    # and publish all of it into trusted session state for the engine router.
    return {"artifact_id": artifact_id, "sha256": artifact_id, "size": size, "format": fmt}


ACQUIRE_SAMPLE_TOOL = ToolDescriptor(
    id="acquire_sample",                              # == acquire_sample.__name__
    description="Ingest a binary sample ... return its SHA-256 artifact id.",
    tool=acquire_sample,                              # plain callable, NOT factory=
    output_policy=OutputPolicy(max_chars=2_000, max_list_items=10),
)
```

Register: `builder.add_tool(ACQUIRE_SAMPLE_TOOL)`. Reference:
`tool_ids=("acquire_sample",)`. `acquire_sample_by_hash` is the second instance of
this pattern (`tool=acquire_sample_by_hash`, same `OutputPolicy`).

> **Key points:**
> - `tool=` vs `factory=` is the dividing line with pattern 2. Use `tool=` when
>   the callable can be built at import time and does not need to close over the
>   build context.
> - `ToolContext` is imported at runtime with `# noqa: TC002` because ADK resolves
>   annotations via `typing.get_type_hints` at tool-registration time.
> - **Never** use bare `typing.Any` as a parameter annotation on a tool function.
>   Python 3.14 removed `isinstance()` support for `Any`, and ADK's parameter
>   parser calls `isinstance(default, annotation)` at import time. Use `object`
>   for generic parameters; compound types like `dict[str, object]` are fine.

---

## 2. Deferred-factory tool (needs RuntimeServices)

Most real tools need the sandbox executor, settings, or the codec registry at
call time. A plain callable cannot see those, so use a **factory**. The factory
receives a `ToolBuildContext` (with `settings`, `services`, `catalog`) at
agent-build time and returns the callable ADK injects at call time.

**Pattern** (condensed from
`src/reverse_engineering/tools/prepare_sandbox.py`):

```python
from google.adk.tools.tool_context import (
    ToolContext,  # noqa: TC002 - runtime import: ADK resolves this via get_type_hints
)

from arema.registry.descriptors import OutputPolicy, ToolDescriptor
from arema.runtime.sessions import SandboxIdentityError, resolve_sandbox_case_id
from reverse_engineering.runtime.sandbox_session import provision_pod


def build_prepare_sandbox(context: ToolBuildContext) -> ToolLike:
    # Closed over at agent-build time:
    executor = context.services.sandbox           # the SandboxExecutor (K8s in prod)
    namespace = context.settings.sandbox_namespace

    def prepare_sandbox(artifact_id: str, tool_context: ToolContext) -> dict[str, str | bool]:
        # Resolve the shared sandbox identity BEFORE claiming. Never invent a
        # private per-tool case id.
        try:
            case_id = resolve_sandbox_case_id(tool_context)
        except SandboxIdentityError:
            return {"pod": "", "ready": False, "error_code": "sandbox_identity_unavailable"}
        # Fail-open: any provisioning failure is caught and returned as a degraded
        # dict, never raised across the ADK tool boundary.
        try:
            return provision_pod(
                executor=executor, case_id=case_id, pool="radare2-mcp",
                namespace=namespace, provision=_push_artifact_and_open_tunnel,
            )
        except Exception as exc:  # noqa: BLE001 - intentional fail-open
            return {"pod": "", "ready": False, "error": str(exc)}

    return prepare_sandbox


PREPARE_SANDBOX_TOOL = ToolDescriptor(
    id="prepare_sandbox",                           # == the inner callable's __name__
    description="Claim a radare2-mcp pod, copy the artifact, open a port-forward.",
    factory=build_prepare_sandbox,                  # deferred, not tool=
    output_policy=OutputPolicy(max_chars=2_000, max_list_items=10),
)
```

`prepare_ilspy`, `prepare_ghidra`, and `prepare_jadx` follow the same factory
shape, each closing over `context.services.sandbox` + the namespace and claiming
its own pool (`ilspy-mcp`, `ghidra-rpc`, `jadx`).

> **Key points:**
> - The returned callable's `__name__` must match the descriptor `id` (for
>   `OutputPolicy` binding). The inner function is named `prepare_sandbox`
>   matching `id="prepare_sandbox"`.
> - Read sandbox identity from `resolve_sandbox_case_id(tool_context)` (the
>   neutral core's shared resolver). Never read the case id from a private slot.
> - Read other state via duck-typed `.get` (NEVER `isinstance(state, dict)`:
>   ADK's `State` is a custom proxy, not a `dict`/`Mapping`).
> - `ToolContext` is imported at runtime (`# noqa: TC002`).
> - **Never** annotate a parameter with bare `typing.Any` (Python 3.14 removed
>   `isinstance(Any)`; ADK calls `isinstance(default, annotation)`). Use `object`.
> - Fail-open: wrap the body in try/except and return a degraded dict, never
>   raise across the tool boundary.

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

1. enforce the **Kubernetes-only** boundary — `_validate_and_resolve` raises
   `DeobfuscationUnavailable` unless `settings.sandbox_backend == "k8s"` and
   explicitly rejects a `LocalSandboxExecutor` ("local execution is forbidden");
2. resolve the shared case id via `resolve_sandbox_case_id`;
3. claim a sandbox pod from the `deobfuscation-tools` pool;
4. stage validated artifact bytes into an isolated work directory (reading at
   most `max_input_bytes + 1` bytes, so an oversize input is rejected **before**
   a pod is claimed); and
5. run a developer-constructed argv, then size-check and read result files.

Keep applicability checks, exit-code interpretation, output parsing,
normalization, public error codes, provenance, and state updates in one wrapper
module per tool. Do not add tool-specific parsing to the shared runtime.

### Concise factory sketch (mirrors the real `upx_unpack` / `floss_decode` shape)

```python
# Sketch — the real wrappers live in
# src/reverse_engineering/tools/deobfuscation/{upx,floss,dotnet,dnlib_roundtrip}.py
from google.adk.tools.tool_context import (
    ToolContext,  # noqa: TC002 - ADK resolves annotations at runtime
)

from arema.registry.descriptors import OutputPolicy, ToolDescriptor
from reverse_engineering.tools.deobfuscation.runtime import (
    ArtifactInputTooLarge,
    DeobfuscationUnavailable,
    run_argv,
    stage_artifact,
)
from reverse_engineering.tools.deobfuscation.state import parse_current_classification

MAX_INPUT_BYTES = 512 * 1024 * 1024


def build_my_cli_tool(context):
    def my_cli_tool(tool_context: ToolContext) -> dict[str, object]:
        """Inspect one artifact without retaining a sandbox analysis session."""
        try:
            plan = parse_current_classification(tool_context.state)
            staged = stage_artifact(
                context, plan.artifact_id, tool_context,
                tool_name="my-cli", max_input_bytes=MAX_INPUT_BYTES,
            )
            result = run_argv(staged, ["my-cli", "--brief", "--", staged.input_path])
        except ArtifactInputTooLarge:
            return {"success": True, "applicable": False, "reason": "input_too_large"}
        except DeobfuscationUnavailable as exc:
            return {"success": False, "applicable": True, "degraded": True,
                    "error_code": "sandbox_unavailable"}
        except (OSError, TimeoutError, ValueError, RuntimeError):
            return {"success": False, "applicable": True, "degraded": True,
                    "error_code": "my_cli_failed"}
        if result.exit_code != 0 or result.truncated:
            return {"success": False, "applicable": True, "degraded": True,
                    "error_code": "my_cli_failed"}
        return {"success": True, "applicable": True, "source_artifact_id": plan.artifact_id,
                "description": result.stdout.strip()}

    return my_cli_tool


MY_CLI_TOOL = ToolDescriptor(
    id="my_cli_tool",  # matches the returned callable's __name__
    description="Inspect one artifact with the sandboxed CLI.",
    factory=build_my_cli_tool,
    output_policy=OutputPolicy(max_chars=4_000, max_list_items=20),
)
```

The callable accepts only `ToolContext`; an LLM must never select an arbitrary
artifact id from the global store. `parse_current_classification` enforces both
the lowercase SHA-256 shape and equality with trusted
`deobf:current_artifact_id` before custody passes to the runtime. Every wrapper
must also set a documented fixed input cap and pass it to `stage_artifact`.
Staging reads at most `cap + 1` bytes and rejects an oversized input before
claiming a pod or writing into the sandbox.

Real `OutputPolicy` values vary by tool — tune to expected output size:
`upx_unpack` is `4_000 / 20`; `floss_decode` (large decoded-string sets) is
`50_000 / 200`; `dnlib_roundtrip` runs on the `analysis-workbench` pool.

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
    DE4DOT_DEOBFUSCATE_TOOL,
    DNLIB_ROUNDTRIP_TOOL,
)
DEOBFUSCATION_TOOL_NAMES = frozenset(tool.id for tool in DEOBFUSCATION_TOOLSET)
```

`register_re_infrastructure` then registers every descriptor in
`DEOBFUSCATION_TOOLSET` with the `CatalogBuilder`; an agent still needs the
descriptor id in its own `tool_ids`. This two-step allowlisting keeps future
image additions private until both registration and reachability are explicit.
`DEOBFUSCATION_TOOL_NAMES` is also what the `re_guarded` profile consumes as
part of its sanitizer's `binary_origin_tools` (see Conventions).

Before exposing a stateless sandbox tool, add tests for:

- applicability and non-applicability (including file-format and size limits);
- canonical artifact equality/custody with no model-controlled artifact selector;
- the Kubernetes-only boundary (local backend → `DeobfuscationUnavailable`);
- stable, fail-open public failures with backend diagnostics excluded;
- shell-injection resistance and validated artifact/path inputs;
- bounded output through both wrapper limits and `OutputPolicy`;
- normalization of malformed, oversized, truncated, and adversarial output;
- evidence provenance bound to the input and any recovered artifact id; and
- `re_guarded` registration with the tool id in the sanitizer's
  `binary_origin_tools` set for binary-origin text.

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
- Use radare2/ILSpy MCP when the upstream server already provides a broad,
  typed, interactive analysis surface (open, analyze, enumerate, navigate, and
  decompile). Recreating that surface as individual wrappers would duplicate
  the upstream protocol.
- Use a separate Ghidra/jadx pool and lifecycle when tools share a long-lived
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

**Pattern** (from `src/reverse_engineering/tools/ghidra/`).

### Step 1: Define the command spec table

```python
# src/reverse_engineering/tools/ghidra/commands.py
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
    result_field: str | None = None   # empty-result detection (e.g. "c_code")
    timeout_seconds: int = 300        # per-command kubectl exec deadline


GHIDRA_COMMANDS: tuple[CliCommandSpec, ...] = (
    CliCommandSpec(
        name="ghidra_decompile",
        description="Decompile a function to Ghidra pseudo-C.",
        subcommand="decompile",
        output_policy=OutputPolicy(max_chars=10_000),
        arg_template="{function}",
        result_field="c_code",   # treat empty c_code as degraded, not success
    ),
    CliCommandSpec(
        name="ghidra_search_decompiled",
        description="Regex-search decompiled C across ALL functions.",
        subcommand="search-decompiled",
        output_policy=OutputPolicy(max_chars=10_000, max_list_items=30),
        arg_template="{pattern}",
        extra_flags="--socket-timeout 600",  # whole-binary sweep
        timeout_seconds=660,
    ),
    # ... one spec per subcommand (metadata, functions, basic_blocks, xrefs_to,
    # imports, strings, pcode)
)
```

### Step 2: Build the toolset

```python
# src/reverse_engineering/tools/ghidra/toolset.py
import inspect

from google.adk.tools.tool_context import ToolContext  # runtime annotation value

from arema.runtime.sessions import resolve_sandbox_case_id
from reverse_engineering.runtime.portforward import kubectl_exec
from reverse_engineering.tools.ghidra.commands import GHIDRA_COMMANDS, CliCommandSpec

# Populated by prepare_ghidra; read by every tool. Keyed by case id.
_GHIDRA_CASE_STATE: dict[str, dict[str, str]] = {}


def build_ghidra_tool(context: ToolBuildContext, spec: CliCommandSpec) -> ToolLike:
    namespace = context.settings.sandbox_namespace
    param_names = _placeholders(spec.arg_template)   # ["function"], ["pattern"], ...

    def _tool(tool_context: ToolContext, **kwargs: str) -> dict[str, str | bool]:
        case_id = resolve_sandbox_case_id(tool_context)
        case_state = _GHIDRA_CASE_STATE.get(case_id)
        if case_state is None:
            return {"success": False, "error": "ghidra not prepared for this case"}
        # The binary name + project path are injected from case state, never
        # passed by the agent. arg tokens are inserted as single argv entries.
        argv = ["ghidra-rpc", spec.subcommand, case_state["binary"],
                *_tokenize_arg_template(spec.arg_template, kwargs),
                *spec.extra_flags.split(), "--project", case_state["project"]]
        stdout = kubectl_exec(argv, namespace, case_state["pod"],
                              timeout=spec.timeout_seconds)
        ...

    # Give the callable a typed surface ADK introspects: one parameter per
    # {placeholder} plus the injected tool_context.
    _tool.__name__ = spec.name
    _tool.__doc__ = spec.description
    setattr(_tool, "__signature__", inspect.Signature(parameters=params))
    return _tool


def build_ghidra_toolset() -> tuple[ToolDescriptor, ...]:
    """One deferred-factory ToolDescriptor per command spec."""
    return tuple(
        ToolDescriptor(
            id=spec.name,
            description=spec.description,
            factory=lambda ctx, s=spec: build_ghidra_tool(ctx, s),
            output_policy=spec.output_policy,
        )
        for spec in GHIDRA_COMMANDS
    )
```

### Step 3: Register in the composition

```python
# src/reverse_engineering/composition.py :: register_re_infrastructure
for desc in build_ghidra_toolset():
    builder.add_tool(desc)
```

> **Key points:**
> - Each tool's factory is deferred: it receives `ToolBuildContext` at
>   agent-build time (matching the deferred-factory pattern).
> - `kubectl_exec` takes a tokenized `list[str]` (NO `sh -c`) so agent-controlled
>   values (function names, regex patterns) are never shell-interpreted.
> - The binary name / pod name / project path are injected from the case-state
>   registry (populated by `prepare_ghidra`), never passed by the agent.
> - `result_field` lets a spec declare that an empty result (e.g. `c_code=""`)
>   is a degraded run, not a success — ghidra-rpc exits 0 with `ok:true` even
>   when the decompiler never ran.
> - The spec table IS the tool surface. Adding a tool = one `CliCommandSpec`
>   line, and (because `re_guarded` derives its sanitizer set from
>   `GHIDRA_COMMANDS`) it is sanitized by construction.

The jadx toolset (`src/reverse_engineering/tools/jadx/`) is a second instance of
the same pattern against the `jadx` pool.

---

## 5. MCP server attachment

An MCP server (like r2mcp or ILSpy-MCP) is attached to an agent via
`mcp_server_ids`. The descriptor declares the transport; the agent factory
resolves it into a `ResilientMcpToolset` appended to the agent's tools.

**Pattern** (from `src/reverse_engineering/mcp/radare2.py`):

```python
from arema.registry.descriptors import McpServerDescriptor, StreamableHttpTransport


RADARE2_MCP = McpServerDescriptor(
    id="radare2_mcp",
    transport=StreamableHttpTransport(
        url="http://127.0.0.1:8765/mcp",       # reached via kubectl port-forward
        read_timeout=600.0,                      # accommodate a long r2 `analyze`
    ),
    required=False,                              # optional: degrades to no-tools
    tool_allowlist=("open_file", "analyze", "list_functions", ...),  # 31 read-only tools
)
```

Register: `builder.add_mcp_server(RADARE2_MCP)`.
Reference: `AgentDescriptor(..., mcp_server_ids=("radare2_mcp",))`.

> **Key points:**
> - `StreamableHttpTransport` is used for sandbox MCP servers (r2mcp / ILSpy-MCP
>   run in a pod, reached via `kubectl port-forward`). There is no transparent
>   MCP proxy: each engine's `prepare_*` tool opens its own direct pod
>   port-forward.
> - `required=False` makes the server optional: on failure it degrades to
>   no-tools (the run continues). `required=True` re-raises.
> - `tool_allowlist` curates which MCP tools the agent sees (defense in depth).
>   radare2's allowlist carries 31 read-only tools; ILSpy's carries 24.
> - `read_timeout` is a hard bound on a wedged call. radare2's `analyze`
>   (`aaa`) on a large binary can legitimately run minutes; 600s is the value
>   that survived the regression sample. `register_re_infrastructure` further
>   caps radare2 to `min(settings.mcp_read_timeout, 300.0)` at composition time
>   because radare2 is the fast-triage engine and a single pathological call
>   should not hold the session. ILSpy decompilation is legitimately slow and
>   keeps the full 600s.

---

## 6. Tool with lifecycle callbacks (budget guard + thrash detector)

The most advanced shape: the `ToolDescriptor` carries a
`ToolLifecycleCallbacks`, and the runtime profile around the agent contributes
loop-level callbacks. The worked example is `run_python` (the agent-authored
Python workbench on the `analysis-workbench` pool), which is governed on **two
axes** by one `before_tool` guard and profile-level thrash detection.

### Per-tool budget guard (`before_tool`)

`run_python` is a deferred-factory tool (pattern 2) that additionally declares a
`before` callback. ADK invokes it before the tool runs; when the per-case budget
is exhausted it returns a `run_python`-shaped result and the sandbox is never
touched.

```python
# src/reverse_engineering/tools/workbench/run_python.py
from arema.registry.descriptors import OutputPolicy, ToolDescriptor, ToolLifecycleCallbacks
from reverse_engineering.tools.workbench.budget import run_python_budget_guard

RUN_PYTHON_TOOL = ToolDescriptor(
    id="run_python",                                      # == inner callable __name__
    description="Run an agent-authored Python script in the sandboxed workbench ...",
    factory=build_run_python,
    output_policy=OutputPolicy(max_chars=32_000, max_list_items=200),
    callbacks=ToolLifecycleCallbacks(before=(run_python_budget_guard,)),
)
```

`run_python_budget_guard` bounds the loop along two axes — execution count
(`WORKBENCH_MAX_EXECUTIONS = 100`) and tokens spent since this stage's first
script (`WORKBENCH_MAX_TOKENS = 16_000_000`, measured from the same
`SessionKeys.MODEL_USAGE` accumulator the cost report renders). It is
**self-scoped** to `run_python` (it returns `None` for any other `tool.name`),
because `build_callback_chain` flattens every tool's `before` callbacks into one
agent-global list ADK runs before every tool call. A guard that did not
self-scope would charge radare2 calls against the workbench budget.

### Loop-level thrash detector (profile callbacks)

A weaker model re-running the same dead approach needs a different lever than a
budget. The `re_deep_agentic` runtime profile adds two callbacks around the
agent — a `record_run_python_thrash` **Monitor** (`after_tool`) that hashes each
failure into a stable `approach|failure` signature and counts consecutive
repeats, and an `advise_on_thrash` **Advisor** (`before_model`) that injects a
one-time pivot directive into the system instruction once the streak reaches
`THRASH_STRIKE_THRESHOLD = 3`. The Monitor runs **before** the SanitizationMembrane
so it classifies raw stderr; the compactor is still the always-last after-tool
step.

```python
# src/reverse_engineering/profiles.py
RE_DEEP_AGENTIC_PROFILE: RuntimeProfile = replace(
    RE_GUARDED_PROFILE,
    id="re_deep_agentic",
    extra_after_tool=(record_run_python_thrash, *RE_GUARDED_PROFILE.extra_after_tool),
    extra_before_model=(advise_on_thrash,),
)
```

> **Key points:**
> - `ToolLifecycleCallbacks` carries `before` / `after` / `on_error` / `memory`
>   tuples; each is flattened into the agent-global callback chain. Every
>   per-tool callback must self-scope on `tool.name` (the workbench guard and
>   the thrash Monitor both do) or it will fire for unrelated tools.
> - Budget and advisor state live in **global** session state so they span
>   every deobfuscation-loop round, not a single iteration.
> - The Advisor names only what recon observed (approach + opaque failure hash)
>   and points at technique classes, never a sample-specific answer — the
>   directive is appended to the system instruction, which the SanitizationMembrane
>   never sees, so raw sample-influenced stderr must never surface there.

---

## Conventions for all tool patterns

### OutputPolicy

Every tool must declare an `OutputPolicy`: it bounds the tool's response before
it enters the model's context (the compactor runs as the last `after_tool`
callback). Tune `max_chars` and `max_list_items` per tool. Real values in the RE
library: ingest/prepare tools `2_000 / 10`; `upx_unpack` `4_000 / 20`;
`floss_decode` `50_000 / 200`; `run_python` `32_000 / 200`; ghidra decompile
`10_000`; default `OutputPolicy` is `15_000 / 30`.

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
hex dumps, attacker-chosen identifiers), it must run under a profile whose
`extra_after_tool` carries a sanitizer built from
`make_sanitizing_after_tool(sanitizer, binary_origin_tools)` (see
[`CONTEXT_AND_RESILIENCE.md`](./CONTEXT_AND_RESILIENCE.md) § Output sanitization).
The default `StructuralSanitizer` wraps the response in
`=== BEGIN/END UNTRUSTED TOOL-DERIVED DATA ===` framing and applies the
prompt-injection denylist in `signatures.py`. The callback sanitizes only the
tools whose names appear in `binary_origin_tools`; everything else passes through.

The RE `re_guarded` profile is the worked example: its `_BINARY_ORIGIN_TOOLS` is
the union of every engine surface that returns attacker-authored bytes or names
— derived from each engine's own descriptor/command table
(`DEOBFUSCATION_TOOL_NAMES`, `GHIDRA_COMMANDS`, `JADX_COMMANDS`,
`WORKBENCH_TOOL_NAMES`, the radare2/ILSpy allowlists, the android tools) rather
than hand-listed, so a tool added to an engine is sanitized by construction.

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
`tests/reverse_engineering/test_detect_it_easy.py` states for DIE. The
no-upload guarantee (only the digest ever leaves the host) is enforced
structurally by `tests/architecture/test_no_sample_upload.py`.

### kubectl helpers

For sandbox-driven tools, two helpers live in
`src/reverse_engineering/runtime/portforward.py`:
- `kubectl_cp(src, namespace, pod, dest)`: copy a file into a pod.
- `kubectl_exec(args: list[str], namespace, pod, *, timeout=300, ok_exit_codes=(0,))`:
  run a tokenized command (no shell; prevents injection). `ok_exit_codes` lets a
  caller accept a partial-result code (jadx exits 1 on a partial decompile).

Both raise `RuntimeError` on failure; callers should catch + return a degraded
dict (fail-open).

### The case-state registry pattern

Tools that share a sandbox session (like the ghidra tools sharing a claimed pod)
use a module-level dict keyed by `case_id` to stash the pod name, binary name,
and project path. A `prepare_<engine>` lifecycle tool populates it; the analysis
tools read it.

### Sandbox identity (invariant)

Every sandbox-backed tool resolves its `case_id` through the neutral
`arema.runtime.sessions.resolve_sandbox_case_id(tool_context)`, never a private
per-tool default. The resolver preserves an explicit
`SessionKeys.SANDBOX_CASE_ID` when present, otherwise derives one from the ADK
invocation ID and persists it into session state, and raises
`SandboxIdentityError` when neither source is available. This guarantees every
sandbox operation in one invocation shares one identity across Radare2, Ghidra,
UPX, FLOSS, ILSpy, jadx, and the workbench. Binary execution is Kubernetes-only
(the deobfuscation runtime enforces `sandbox_backend == "k8s"` and rejects a
`LocalSandboxExecutor`). Authoritative inter-stage evidence travels through
named session state, not conversation history; a tool's job is to return bounded
structured results, never to treat prior model messages as authoritative.
