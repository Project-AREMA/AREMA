# Kubernetes Sandbox Execution Layer — Design

**Status:** Approved (brainstormed 2026-07-23)
**Spec ID:** A (of the sandbox-then-MVP decomposition)
**Predecessor:** `2026-07-21-arema-domain-neutral-shell-design.md` (the shell this extends)

## Goal

A domain-neutral execution layer that lets any AREMA tool run commands and
transfer files inside an isolated Kubernetes pod (or a local subprocess
fallback), bound to an ADK session, with no cluster-specific knowledge leaking
into `src/arema`. The layer is the foundation for the RE/malware MVP (Spec B),
which will register radare2/ghidra-backed tools on top of it.

The hard requirement this satisfies: **tool execution is transparent and
independent of where it runs, as long as kubectl access is available.**

## Decisions (locked during brainstorm)

| # | Decision | Choice |
|---|----------|--------|
| 1 | Decomposition | Two specs in sequence. **This is Spec A** (domain-neutral sandbox layer). Spec B (RE/malware MVP) builds on top. |
| 2 | Execution pattern | **Pattern 3 — hybrid, per-session pod.** Sandbox-exec backbone; one pod per ADK session so radare2 state persists across queries on the same binary. No MCP-server-in-a-pod. |
| 3 | Artifact transfer | **Files API** (`sandbox.files.write` / read back). Portable, only needs kubectl. |
| 4 | Pod lifetime | **Session-bound, explicit-only cleanup.** Terminated on explicit session end / shutdown. No automatic idle/max timeout reaper (accepted trade-off for single-user dev on Kind); defense-in-depth via template annotations. |
| 5 | Image scope | Generic executor **plus the radare2 image build** in this spec. ghidra image is Spec B. Images ship as cluster infra outside `src/arema`. |
| 6 | Testability | **Hexagonal port + two adapters**: `K8sSandboxExecutor` (real pods) and `LocalSandboxExecutor` (subprocess, no cluster). Mirrors the `MemoryStore` pattern. |
| 7 | Env prefix | **`AREMA_` prefix on all app settings** (via `env_prefix="arema_"`); provider API keys (`GOOGLE_API_KEY`, etc.) stay un-prefixed because LiteLLM/the SDK read them by standard name. |

### Why not the prior `r2-mcp` approach (Pattern 2)

The prior `security-agent-adk/mcp-servers/r2-mcp` image runs `r2mcp` +
Supergateway (stdio→SSE) in a long-lived pod and connects from the host as an
MCP client. It is elegant for a host-side-MCP architecture but is the **wrong
fit** here:

- It conflicts with sandboxed execution — the MCP server is a long-lived attack
  surface holding attacker bytes, not an ephemeral sandbox.
- It makes MCP-attachment wiring MVP-blocking (`agent_factory._build_agent`
  raises `NotImplementedError` for `mcp_server_ids` today).
- The agent talks to a stateful server rather than receiving bounded outputs
  through `OutputPolicy`.
- It is harder to keep transparent/cluster-agnostic.

We **reuse its Dockerfile knowledge** (radare2 built from source via meson,
non-root user, `/targets` + `/workspace` layout) for the radare2 image, but
**drop Supergateway/SSE entirely** — Spec A tools exec commands in the pod, they
do not host an MCP server.

## Scope

### In scope (this spec)

- `SandboxExecutor` Protocol port + data model (`SandboxHandle`, `ExecutionResult`).
- `SandboxSessionManager` (session→handle map, idempotent claim, explicit release).
- Two adapters: `K8sSandboxExecutor` (`k8s-agent-sandbox` client) and
  `LocalSandboxExecutor` (subprocess fallback).
- Files-API artifact transfer (upload bytes / run command / read result).
- `Settings` extension: `AREMA_`-prefixed env vars (all app settings);
  `AREMA_SANDBOX_*` fields; `AREMA_SANDBOX_ENABLED=False` default.
- `RuntimeServices` extension (optional `sandbox`) + composition wiring.
- Runner `finally` hook for explicit session cleanup.
- The **radare2 container image** + `SandboxTemplate`/`SandboxWarmPool` manifests
  (cluster infra, outside `src/arema`).
- Agent-sandbox install scripted (`make sandbox-up` / `sandbox-down`).
- Shared contract test (port) + adapter unit tests + one opt-in k8s integration test.
- Neutrality/architecture test extension (downward-only import rule for `sandbox/`).

### Out of scope (deferred)

- MCP-attachment wiring onto agents (Pattern 3 does not need it).
- `ParallelAgent` / `LoopAgent` factories (Spec B and beyond).
- ghidra headless image (Spec B).
- Actual RE agents/tools — triage, decompile, evidence critic, report (Spec B).
- Dynamic analysis / sandbox detonation (post-MVP).
- gVisor / Kata `runtimeClassName` — documented as **required before hostile
  code**, but it is cluster configuration, not AREMA Python code.

## Architecture & placement in AREMA's layering

New module `src/arema/runtime/sandbox/`, at the same level as `runtime/context/`
and `runtime/callbacks/`:

```
runtime/
  services.py            ← extended: RuntimeServices gains optional `sandbox: SandboxExecutor | None`
  sessions.py            ← (existing) SessionKeys — reused for sandbox binding key
  sandbox/
    __init__.py
    port.py              ← SandboxExecutor Protocol, SandboxHandle, ExecutionResult, errors
    session.py           ← SandboxSessionManager (session→handle map, explicit cleanup)
    local.py             ← LocalSandboxExecutor (subprocess, no cluster)
    k8s.py               ← K8sSandboxExecutor (k8s-agent-sandbox SandboxClient)
    contract.py          ← shared contract test base (run by both adapters)
```

**Dependency rule (enforced structurally and by an architecture test):**

- `runtime/sandbox/` depends only downward on `core/` (config, logging).
- It **never** imports `registry/`, `memory/`, or concrete ADK agent types.
- `runtime/services.py` references the `SandboxExecutor` Protocol only — never a
  concrete adapter — so the seam is structural (a `runtime_checkable` `Protocol`,
  exactly like `MemoryStore`, `Clock`, `MetricsSink`).
- Adapters are selected in `composition.py` (the single wiring point), mirroring
  how `InMemoryStore` vs `SQLiteStore` are selected today.

This keeps the neutral boundary intact: `src/arema` and `composition.py` name no
concrete domain pool, so the neutrality tests
(`tests/architecture/test_neutral_boundaries.py`) stay green.

## The `SandboxExecutor` port & data model

```python
# runtime/sandbox/port.py  (sketch — final signatures in implementation)
@dataclass(frozen=True, slots=True)
class ExecutionResult:
    exit_code: int
    stdout: str
    stderr: str
    truncated: bool = False        # stdout/stderr bounded to AREMA_SANDBOX_OUTPUT_CAP

@dataclass(frozen=True, slots=True)
class SandboxHandle:
    key: str                       # the session id it is bound to
    pool: str                      # logical pool name it was claimed from
    backend_id: str                # pod name (k8s) / workdir path (local)

class SandboxExecutor(Protocol):
    """Opaque, domain-neutral command/file execution in an isolated environment."""
    def claim(self, *, key: str, pool: str) -> SandboxHandle: ...
    def run(self, handle: SandboxHandle, command: str, *, timeout: float) -> ExecutionResult: ...
    def write_file(self, handle: SandboxHandle, path: str, data: bytes) -> None: ...
    def read_file(self, handle: SandboxHandle, path: str) -> bytes: ...
    def terminate(self, handle: SandboxHandle) -> None: ...
    def release_session(self, key: str) -> None: ...   # explicit cleanup of all handles for a session
```

**The port is deliberately opaque and domain-neutral.** A "command" is an
arbitrary string, a "file" is opaque bytes, a "pool" is a logical name. Nothing
here knows radare2 exists.

**Session binding:** `SandboxSessionManager` layers idempotent claim-on-first-use
(`claim` returns the existing handle for a **`(key, pool)` pair**, so one session
may hold one handle per pool it touches) and explicit `release_session`
(terminates **every** handle for that key, across all pools) on top of a concrete
adapter. The binding key is an **opaque caller-supplied key**, not necessarily the
ADK session id: the current `run_single_query` creates a fresh ADK session **per
query** (runner.py), so keying on `session.id` would yield one sandbox per query
and defeat per-session persistence. Instead the runner seeds a stable
**case id** into ADK state for an interactive session
(`SessionKeys.SANDBOX_CASE_ID`), and a tool resolves it by duck-typing
`tool_context.state.get(SessionKeys.SANDBOX_CASE_ID)` (never `isinstance(..., dict)` —
ADK's `State` is a proxy). This matches the north star's "one Session per case"
(Axis 1). A sandbox therefore outlives any single query, scoped to a case.

**Parameter-annotation guard (ADK constraint):** tool functions that carry
`sandbox`-derived params must not annotate them as bare `typing.Any` (Python 3.14
removed `isinstance(x, Any)`; ADK's parameter util calls it at import time). Use
`object` for generic params; compound types (`dict[str, Any]`) are fine. Same
rule as the rest of AREMA.

## Adapters

### `LocalSandboxExecutor` (tests / no-cluster dev)

One subprocess workdir per session key under a temp root. `run` =
`subprocess.run(..., timeout=...)`; `write_file`/`read_file` hit the workdir;
`release_session` deletes the workdir. No kubectl, fully deterministic, used by
all unit tests. The "pool" name selects a subdirectory layout only (it does not
pick a real image).

### `K8sSandboxExecutor` (real pods)

Wraps `k8s_agent_sandbox.SandboxClient`:

- `claim` creates a `Sandbox` from the `SandboxWarmPool` named by
  `AREMA_SANDBOX_POOL_MAP[logical_pool]` (lazily, memoized per session key).
- `run` / `write_file` / `read_file` delegate to `sandbox.commands.run` /
  `sandbox.files`.
- `release_session` terminates every handle for that key.
- **Connection mode is configurable** from `Settings`:
  `SandboxLocalTunnelConnectionConfig` for Kind/minikube/CI (the documented
  default, `AREMA_SANDBOX_LOCAL_TUNNEL=true`); in-cluster / kubeconfig for real
  clusters (`AREMA_SANDBOX_LOCAL_TUNNEL=false`). This is what makes execution
  "transparent/independent of where it runs, as long as kubectl access" holds.

**Failure & cancellation semantics** mirror `ResilientMcpToolset`
(`registry/mcp.py`): pool exhaustion or sandbox-call failure raises (the tool
decides — typically returns a structured error dict); `asyncio.CancelledError`
disguised in the k8s client's `__cause__`/`__context__`/`ExceptionGroup` chain is
re-raised untouched and **never** treated as an availability signal.

## Configuration (`Settings`)

### `AREMA_` prefix (decision 7)

`Settings.model_config` gains `env_prefix="arema_"`, so every AREMA-owned app
setting is namespaced. The existing `.env.example` is rewritten accordingly
(`LLM_PROVIDER` → `AREMA_LLM_PROVIDER`, `MEMORY_BACKEND` →
`AREMA_MEMORY_BACKEND`, etc.).

**Provider API keys stay un-prefixed** because LiteLLM / the Google / OpenAI /
Anthropic / ZAI / xAI SDKs read them by standard name. These fields override the
prefix with an explicit alias:

```python
google_api_key: SecretStr | None = Field(
    default=None, validation_alias=AliasChoices("GOOGLE_API_KEY")
)
# likewise: OPENAI_API_KEY, ANTHROPIC_API_KEY, ZAI_API_KEY, XAI_API_KEY,
#           OPENAI_COMPATIBLE_API_KEY
```

This is the only naming asymmetry, and it is deliberate: those are upstream
library credentials, not AREMA app settings.

### New sandbox fields (all `AREMA_SANDBOX_*`)

```
AREMA_SANDBOX_ENABLED=false                       # shell still boots with no cluster
AREMA_SANDBOX_BACKEND=auto|local|k8s              # auto: k8s if enabled + client importable + kubeconfig present, else local
AREMA_SANDBOX_NAMESPACE=agent-sandbox-demo
AREMA_SANDBOX_DEFAULT_POOL=python-runtime-pool
AREMA_SANDBOX_LOCAL_TUNNEL=true                   # Kind/minikube/CI; false → in-cluster/kubeconfig
AREMA_SANDBOX_RUN_TIMEOUT=120                     # per-command seconds
AREMA_SANDBOX_CONNECT_TIMEOUT=30
AREMA_SANDBOX_OUTPUT_CAP=65536                     # stdout/stderr bound before returning to the tool
AREMA_SANDBOX_POOL_MAP={"radare2":"radare2-pool"} # logical pool name → warmpool name (JSON)
```

**Validators:** timeouts positive; `AREMA_SANDBOX_RUN_TIMEOUT >
AREMA_SANDBOX_CONNECT_TIMEOUT`; `pool_map` parses as a JSON `dict[str,str]`;
`backend` constrained to `auto|local|k8s`. No `SecretStr` fields cross this
boundary — the only credential is kubeconfig, held by the k8s-agent-sandbox
client, never by AREMA.

**Migration note:** existing tests/fixtures that set un-prefixed env names for
app settings are updated as part of this spec. `clear_settings_cache()` is used
in fixtures as today.

## Wiring into composition & `RuntimeServices`

- `RuntimeServices` (frozen dataclass, `runtime/services.py`) gains one optional
  field: `sandbox: SandboxExecutor | None = None`. Default `None` → tools see
  "no sandbox" and degrade. The dataclass stays backward-compatible (every
  existing call site that does not pass `sandbox` keeps working).
- `build_memory_backed_services(...)` gains an optional `sandbox` param, threaded
  from `composition.build_default_composition`.
- `composition.build_default_composition` builds the executor **once** from
  `Settings`:
  - `AREMA_SANDBOX_ENABLED=false` → `None` (no sandbox anywhere; current behavior).
  - `backend=local` (or `auto` with no cluster) → `LocalSandboxExecutor`.
  - `backend=k8s` (or `auto` with cluster + client importable) → `K8sSandboxExecutor`.
  It passes the executor through `build_memory_backed_services(..., sandbox=...)`,
  and from there it flows into every `ToolBuildContext.services`.
- **Neutrality preserved:** `composition.py` selects a backend and names no
  concrete domain pool. The radare2 pool is referenced only by Spec B tools,
  never by the shell.
- **Explicit-only cleanup hook (decision 4):** cleanup fires at the
  **ADK-session / process lifecycle boundary** — the CLI interactive loop
  (`/exit`, `/reset`), web session teardown, and an `atexit` guard on process
  shutdown — each calling `services.sandbox.release_session(session_id)`. It is
  **not** wired into `run_single_query`'s per-turn `finally` (that would
  terminate the pod every turn and defeat per-session persistence). This mirrors
  the existing "always close the memory scope" discipline, but at the session
  boundary the sandbox actually spans. A process crash can leak a pod (accepted
  trade-off). Defense-in-depth: templates carry an `arema.dev/max-lifetime`
  annotation + `terminationGracePeriodSeconds`, and the warm pool
  self-replenishes, so a leaked pod consumes resources until manual cleanup
  rather than corrupting state.

## Cluster infrastructure (radare2 image + manifests)

Shipped **outside** `src/arema`, as cluster setup (the same category as installing
agent-sandbox itself):

```
images/radare2/
  Dockerfile              ← adapted from the prior r2-mcp Dockerfile:
                           radare2 from source via meson (pinned release tag),
                           non-root user (r2user), /targets (ro) + /workspace (rw).
                           NO Supergateway/SSE — we exec commands, not host an MCP server.
deploy/sandbox/
  00-agent-sandbox.yaml   ← the SANDBOXING.md install (CRDs + controller + router), pinned v0.5.2
  10-radare2-template.yaml← SandboxTemplate referencing the image + hardened securityContext
  20-radare2-pool.yaml     ← SandboxWarmPool (replicas: 2)
  Makefile targets         ← sandbox-up / sandbox-down / sandbox-test / sandbox-image
```

**SecurityContext baked into the template** (the SANDBOXING.md minimum):

```yaml
securityContext:
  runAsNonRoot: true
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true        # only /workspace writable (emptyDir)
  capabilities:
    drop: [ALL]
# no host paths; no mounted service-account token; deny-all egress NetworkPolicy
```

The spec **documents** that gVisor/Kata is required before hostile code and is
cluster configuration (a `runtimeClassName` field on the template), not AREMA
Python code. The dev Kind cluster has neither; it is sufficient for plumbing,
lifecycle, and file/command APIs, **not** for hostile samples.

## Resilience & context interaction

- **`OutputPolicy` unchanged and still binds by tool name.** Large radare2/ghidra
  stdout is bounded twice: once by `AREMA_SANDBOX_OUTPUT_CAP` (before it leaves
  the executor) and again by the tool's `OutputPolicy` (before it enters context).
  The callback chain, compactor, and budget tiers need **zero changes** — they
  are already domain-neutral.
- **Fail-open discipline:** when `sandbox is None` (disabled), a tool that needs
  it returns a structured `{"ok": False, "error": "sandbox unavailable"}`; the
  run continues. Sandbox hard failures surface to the tool, which returns a
  structured error; the agent decides.
- **Neutral lifecycle memory:** if sandbox events are ever recorded to memory,
  they carry only `(tool_id, pool, exit_code, elapsed)` — never command text,
  bytes, or output — consistent with the existing `ToolEvent` contract
  (`runtime/services.py`).

## Testing strategy

- **Contract test** (`runtime/sandbox/contract.py`): both adapters must pass —
  `claim` is idempotent per key; `run` returns exit/stdout/stderr; write→read
  round-trips; `release_session` removes the handle and a subsequent `claim`
  yields a fresh one. Run via a shared pytest base, mirroring the `MemoryStore`
  contract test.
- **Unit tests (local adapter):** the full suite runs with
  `AREMA_SANDBOX_BACKEND=local`, no cluster. Tool-shaped tests assert on
  `ExecutionResult`.
- **Integration test (opt-in):** one test marked `@pytest.mark.k8s` that claims
  from a real Kind pool and runs `r2 -v` / a trivial python job. Skipped unless
  `AREMA_K8S_INTEGRATION=1` and the cluster is reachable. CI runs unit only.
- **Neutrality/architecture test extension:** add assertions to
  `tests/architecture/` that `runtime/sandbox/` imports nothing from `registry/`
  or concrete ADK agents, keeping the downward-only rule structural, and that
  `composition.py` still names no concrete domain pool.

## Deliverables checklist

- [ ] `src/arema/runtime/sandbox/` (port, session manager, local + k8s adapters, contract base)
- [ ] `RuntimeServices.sandbox` field + `build_memory_backed_services(sandbox=...)`
- [ ] `Settings` `AREMA_` prefix + `AREMA_SANDBOX_*` fields + validators + `.env.example`
- [ ] `composition.build_default_composition` executor selection
- [ ] runner `finally` session cleanup hook
- [ ] `images/radare2/Dockerfile` (no Supergateway/SSE)
- [ ] `deploy/sandbox/` manifests + Makefile targets
- [ ] contract + unit + opt-in k8s integration tests
- [ ] architecture-test extension for `sandbox/` downward-only imports
- [ ] `make check` green; neutrality tests green

## Open questions for Spec B (not this spec)

- Exact radare2 tool surface (which r2 commands become which tools) and the
  ghidra headless image.
- Agent roster, sub-agent wiring, and whether Spec B needs `ParallelAgent`/
  `LoopAgent` factory support.
- MCP-attachment wiring — only if Spec B introduces a tool that is genuinely
  better as an MCP server than as a command-exec tool.
