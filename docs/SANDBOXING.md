# Sandboxing

## The important distinction

Your ADK agent keeps running the reasoning loop on the host under `adk web` /
`adk run`. The Kubernetes sandbox pods do **not** run the reasoning loop.

Instead the host agent reaches engines that live inside pods: it claims a warm
pod, stages the artifact into it, opens a tunnel (or shells in), and calls the
engine. The model never runs in the cluster; only the analysis tooling does.

```
Browser / CLI
  │
  │  ADK web / adk run / uv run arema        ← reasoning loop lives HERE (host)
  ▼
ADK agent (host) calls a tool, e.g. prepare_sandbox / prepare_ghidra / run_python
  │
  ▼
arema SandboxExecutor (neutral core)        ← claim/run/write/read/terminate
  │
  ▼
k8s-agent-sandbox SandboxClient             ← optional extra, pinned 0.5.2
  │
  ▼
SandboxClaim  →  pre-warmed pod from a WarmPool   ← engine + artifact live HERE
  │
  ├─ MCP engine (radare2 / ILSpy):  kubectl port-forward pod/<name> 8765:8765
  │                                 → StreamableHttp at 127.0.0.1:<port>/mcp
  └─ Command engine (Ghidra / jadx): kubectl exec pod/<name> -- <argv>
  └─ Workbench (run_python):         sandbox.commands.run(...) inside the pod
```

For a local Kind cluster you should not use `GkeCodeExecutor`. That executor is
tied to GKE-specific sandbox infrastructure and expects a GCP resource name that
`kubectl` credentials cannot produce. AREMA's equivalent is the
`SandboxExecutor` port (below) backed by `k8s-agent-sandbox`'s `SandboxClient`
in local-tunnel mode — the kubeconfig/`kubectl port-forward` developer path.

## The SandboxExecutor port (neutral core, default OFF)

`src/arema/runtime/sandbox/port.py` defines a domain-neutral
`SandboxExecutor` `Protocol`. Nothing in the neutral core knows what tooling
lives inside a pool; a "command" is an opaque string, a "pool" is a logical
name. The port is:

```python
class SandboxExecutor(Protocol):
    def claim(self, *, key: str, pool: str) -> SandboxHandle: ...      # idempotent per (key, pool)
    def run(self, handle, command: str, *, timeout: float) -> ExecutionResult: ...
    def write_file(self, handle, path: str, data: bytes) -> None: ...
    def read_file(self, handle, path: str) -> bytes: ...
    def terminate(self, handle: SandboxHandle) -> None: ...            # one handle
    def release_session(self, key: str) -> None: ...                   # every handle for key
```

`ExecutionResult` carries `exit_code`, `stdout`, `stderr`, `truncated`.
`SandboxHandle` is an opaque `(key, pool, backend_id)` triple; for the k8s
backend `backend_id` is the claimed pod name, which lets domain tools address
the pod directly (e.g. open a `kubectl port-forward` to a named pod).

`ApplicationComposition.sandbox: SandboxExecutor | None` — it is `None` unless
`AREMA_SANDBOX_ENABLED=true`. The executor is injected into `RuntimeServices`
and reaches tools via `context.services.sandbox`.

### Two executors

- **`LocalSandboxExecutor`** (`sandbox/local.py`) — one workdir per `(key, pool)`
  under a root dir; commands run via `subprocess.run(..., shell=True)` with a
  timeout. No kubectl, no cluster. Used by tests and no-cluster dev.
- **`K8sSandboxExecutor`** (`sandbox/k8s.py`) — claims real warm pods through
  `k8s-agent-sandbox==0.5.2` (the optional `sandbox` extra, imported lazily so
  the rest of AREMA never requires it). `backend_id` is the pod name. stdout/stderr
  are capped to `AREMA_SANDBOX_OUTPUT_CAP`. On `terminate`, if the client
  transport is dead it falls back to a scoped
  `kubectl delete sandboxclaim.extensions.agents.x-k8s.io <name>` so the claim is
  released instead of leaked.

Connection-mode selection matches the configs that `k8s-agent-sandbox` exposes:
`SandboxLocalTunnelConnectionConfig` (kubectl port-forward; the kubeconfig
developer path, the default and the safe fallback) or
`SandboxInClusterConnectionConfig` (when AREMA itself runs inside a pod and
local tunnel is disabled). `SandboxDirectConnectionConfig` and
`SandboxGatewayConnectionConfig` exist in the package but are not wired yet.

### Selection

`build_sandbox_executor` (`composition.py`) returns `None` when disabled. With
`AREMA_SANDBOX_BACKEND=local` it builds a `LocalSandboxExecutor`. With `k8s` or
`auto` it tries to construct `K8sSandboxExecutor`; `k8s` raises a clean
`CompositionError` if the extra is missing, `auto` falls back to local.

### Session manager

`SandboxSessionManager` (`sandbox/session.py`) layers a thread-safe,
idempotent claim per `(key, pool)` over any executor, for concurrent callers
(e.g. a future `ParallelAgent` fanning out tool calls under one case). The
single-threaded CLI uses the raw executor today.

## Configuration

All settings are `AREMA_`-prefixed env vars (`src/arema/core/config.py`). The
sandbox is **disabled by default**.

| Setting | Default | Meaning |
|---|---|---|
| `AREMA_SANDBOX_ENABLED` | `false` | Master switch. Off → no executor is built. |
| `AREMA_SANDBOX_BACKEND` | `auto` | `auto` \| `local` \| `k8s`. |
| `AREMA_SANDBOX_NAMESPACE` | `agent-sandbox-demo` | Where claims are created. |
| `AREMA_SANDBOX_DEFAULT_POOL` | `python-runtime-pool` | Fallback warmpool for an unmapped pool name (almost always a misconfiguration for a domain tool). |
| `AREMA_SANDBOX_LOCAL_TUNNEL` | `true` | Force local-tunnel mode (Kind/minikube/CI); false allows in-cluster when `KUBERNETES_SERVICE_HOST` is set. |
| `AREMA_SANDBOX_RUN_TIMEOUT` | `120` | Per-command ceiling (seconds). |
| `AREMA_SANDBOX_CONNECT_TIMEOUT` | `30` | Connect ceiling. Must be < run_timeout. |
| `AREMA_SANDBOX_OUTPUT_CAP` | `65536` | Per-stream stdout/stderr cap (k8s backend). |
| `AREMA_SANDBOX_POOL_MAP` | `{}` | JSON map of logical pool → warmpool name. |
| `AREMA_MCP_READ_TIMEOUT` | `600.0` | SSE read timeout for MCP servers reached via StreamableHTTP. |

`.env.example` ships the full pool map:

```
AREMA_SANDBOX_POOL_MAP={"radare2-mcp":"radare2-mcp-pool","ghidra-rpc":"ghidra-rpc-pool","deobfuscation-tools":"deobfuscation-tools-pool","ilspy-mcp":"ilspy-mcp-pool","jadx":"jadx-pool","analysis-workbench":"analysis-workbench-pool"}
```

## The six engine pools

`deploy/sandbox/` holds six `SandboxTemplate` + `SandboxWarmPool` pairs. Each
warm pool pre-creates pods that wait to be claimed; a `SandboxClaim` adopts one
and the controller replenishes the pool.

| Logical pool | WarmPool | Engine | Reached via |
|---|---|---|---|
| `radare2-mcp` | `radare2-mcp-pool` | r2mcp server | MCP — `kubectl port-forward :8765`, StreamableHttp at `127.0.0.1:8765/mcp` |
| `ghidra-rpc` | `ghidra-rpc-pool` | ghidra-rpc CLI | `kubectl exec` (argv-only, no shell) |
| `deobfuscation-tools` | `deobfuscation-tools-pool` | upx / floss / de4dot | `sandbox.commands.run` inside the pod |
| `ilspy-mcp` | `ilspy-mcp-pool` | ILSpy-MCP server | MCP — `kubectl port-forward :3001`, StreamableHttp at `127.0.0.1:3001/mcp` |
| `jadx` | `jadx-pool` | jadx CLI | `kubectl exec` (argv-only, no shell) |
| `analysis-workbench` | `analysis-workbench-pool` | python (agent-authored) | `sandbox.commands.run` inside the pod |

These are the RE domain's pools (registered by
`reverse_engineering.register_re_infrastructure`). The neutral core hardcodes
none of them — pool names come only from settings.

## How an engine is reached

The shared lifecycle lives in `src/reverse_engineering/runtime/sandbox_session.py`
and `src/reverse_engineering/runtime/portforward.py`.

1. **Claim a pod.** `provision_pod` calls `executor.claim(key=case_id, pool=<pool>)`.
   Idempotent per `(case, pool)` — the same case calling the same engine twice
   gets the same pod.
2. **Provision.** The engine's `provision` callable does engine-specific work:
   stage the artifact (raw `kubectl cp` to `/app/<sha256>`), verify the pod
   actually holds it (`kubectl exec -- test -f <path>`), and start the service.
3. **Reach the engine** — one of:
   - **MCP tunnel** (radare2, ILSpy): `PortForwardRegistry.open` starts one
     `kubectl port-forward pod/<name> <port>:<port>` per `(case, port)`, blocking
     until the MCP server answers an HTTP probe at `127.0.0.1:<port>/mcp` (not
     just a TCP connect — the StreamableHTTP server can accept TCP before it is
     ready to handle the initialize handshake). ADK then reaches the server as a
     normal `StreamableHttpTransport` MCP server (`radare2_mcp`, `ilspy_mcp`).
     Both are `required=False`: a down or unreachable server degrades to an empty
     toolset instead of aborting the run.
   - **Direct command** (Ghidra, jadx): `kubectl_exec` runs tokenized argv
     (`["ghidra-rpc", "decompile", binary, func]`) with **no** `sh -c`, so
     agent-controlled values are passed directly and cannot shell-inject.
     Callers declare tolerated exit codes (e.g. `(0, 1)` for jadx's
     partial-decompile / grep no-match).
   - **In-pod run** (workbench, deobfuscation): `sandbox.commands.run` inside
     the claimed pod, capped by the pool's output policy and run timeout.

`PortForwardRegistry` reconciles rather than blindly reusing: an existing
forward for `(case, port)` is reused only when it points at the same pod, its
process is alive, **and it still answers** a probe. A different pod (the caller
re-claimed after a failed provision), a dead process, or a live-but-useless
tunnel is replaced. Two MCP engines (radare2 on 8765, ILSpy on 3001) coexist
under one case as separate `(case, port)` forwards.

## Per-case lifecycle

One case id binds all of an invocation's pod claims, port-forwards, and
in-pod state.

- **Case id.** `SessionKeys.SANDBOX_CASE_ID = "arema:sandbox_case_id"`. The
  runner seeds it when a run supplies a case id; otherwise
  `resolve_sandbox_case_id` (`runtime/sessions.py`) derives a stable fallback
  `inv-<sha256(invocation_id)[:32]>` from the ADK invocation id and persists it
  in session state.
- **Release at pipeline end.** The domain root hangs
  `release_case_at_pipeline_end` on its `after_agent_callbacks`. This is the
  one point at which the executor's own client can release cleanly (see
  Caveats). It runs every per-pod cleanup hook (e.g. stop the ghidra daemon),
  closes the case's port-forwards, and calls `release_session(case_id)`.
- **atexit backstop.** `release_all_cases` is `atexit`-registered as the
  process-exit sweep for a crashed or interrupted run. After a clean run it
  finds nothing.
- **CLI release.** In the interactive CLI, `/reset`, `/exit`, and Ctrl+C
  release the bound session fail-open.
- **Scoped release.** Every release is scoped — `terminate` of one
  `(case, pool)` handle, never a namespace-wide delete — so a per-analysis
  teardown never touches another in-flight analysis's claims.
- **Orphan pruning.** A claim that escapes cleanup (rare transient failure) is
  reaped by `make sandbox-prune`
  (`kubectl delete sandboxclaim --all -n agent-sandbox-demo`).

## Recycling resilience

A WarmPool can hand out or reclaim a pod around the moment of the claim, so a
claim + stage that both succeed can still leave a later call facing an
empty/recycled pod. `provision_pod` handles this: on any failure during
`provision` it releases **that one** `(case, pool)` claim scoped (via
`terminate`, never `--all`) and re-claims a fresh pod, up to 3 attempts with a
1s delay. The engine's `provision` callable must verify the pod really holds
the artifact and raise if not, which is what drives the re-claim.

`release_case` retries transient tunnel errors on `release_session` but never
escalates to a namespace-wide fallback: a residual failure leaks one claim
(reaped by `make sandbox-prune`) rather than deleting other in-flight analyses'
claims.

## Defense in depth: the workbench deny-all egress

`deploy/sandbox/30-analysis-workbench-denyall-egress.yaml` is a NetworkPolicy
that selects every pod labelled `arema.dev/pool=analysis-workbench` and permits
**zero** egress (DNS included). The `analysis-workbench` pool is where
`run_python` decrypts live malware, so a compromised pod must have no network
path off the node.

A NetworkPolicy is only enforced by a policy-enforcing CNI. **Kind's default CNI
(kindnet) silently ignores NetworkPolicy**, so on a stock `kind create cluster`
the deny-all is a no-op and the pod keeps a full exfil path. The cluster must
run Calico:

- `deploy/sandbox/kind-cluster.yaml` creates the cluster with
  `disableDefaultCNI: true` and a podSubnet matching Calico's default pool.
- `deploy/sandbox/install-agent-sandbox.sh` refuses to proceed while kindnet is
  installed, installs Calico, then installs the Agent Sandbox framework
  (controller + router) and applies the engine templates.

Because a policy can be applied yet do nothing, presence is not enforcement.
`deploy/sandbox/verify-egress-denied.sh` (and `make sandbox-verify-egress`)
proves it: a baseline pod (no policy) must reach the probe IP, while a **live
warm-pool pod** (subject to the framework's managed policy) must be refused. It
probes a real warm-pool pod, not a `kubectl run` stand-in, because the managed
policy selects warm-pool pods by their template-ref-hash label. Exit `0` =
enforced, `1` = not enforced, `2` = inconclusive.

## Local backend limitation

The deobfuscation staging primitives are k8s-only.
`src/reverse_engineering/tools/deobfuscation/runtime.py` rejects
`LocalSandboxExecutor` (and requires `sandbox_backend='k8s'`) before any file
read or pod claim: deobfuscation stages live malware and runs it through
unpackers, which must not happen on the host. The local backend exists for
no-cluster dev/test of the neutral machinery, not for running these tools.

## Known caveats

- **Non-fatal transport error at teardown.** During interpreter shutdown the
  kubernetes client tears down its TLS transport in its own `atexit` handler,
  which can run before AREMA's release. The client's `sandbox.terminate()` then
  fails mid-handshake with an SSL/transport error. `K8sSandboxExecutor.terminate`
  logs the error type only and falls back to `kubectl delete sandboxclaim`
  (kubectl carries its own transport), so the claim is released correctly. This
  is exactly why `release_case_at_pipeline_end` is wired on the domain root:
  it runs while the process is still healthy, and is the only point at which
  the executor's own client can release cleanly. The `atexit` sweep is the
  backstop for a crashed run.
- **Ordinary Kind is not hardened isolation.** A standard cluster created with
  `kind create cluster` does not provide gVisor or VM-level isolation. The
  controls AREMA ships (deny-all egress under Calico, scoped claims, argv-only
  `kubectl exec`, read-only MCP allowlists) are meaningful but should not be
  treated as a hardened environment for arbitrary hostile code. Add stronger
  container isolation before allowing untrusted prompts.
- **Default pool fallback is usually a misconfiguration.** An unmapped pool
  falls back to `AREMA_SANDBOX_DEFAULT_POOL`, which will not host the engine;
  the claim then fails against a pool that does not have it. AREMA logs the
  fallback loudly rather than degrading silently.

## Bring-up

The Makefile encodes the lifecycle:
`sandbox-cluster` (once) → `setup-sandbox` (once) → `sandbox-build-images` →
`sandbox-up` → `sandbox-verify-egress` → run AREMA → `sandbox-prune` (as
needed) → `sandbox-down`.

```
make sandbox-cluster      # kind create cluster --config deploy/sandbox/kind-cluster.yaml (CNI disabled)
make setup-sandbox        # uv sync --extra sandbox; install-agent-sandbox.sh (Calico + agent-sandbox 0.5.2 + router)
make sandbox-build-images # build the six engine images and load them into kind
make sandbox-up           # apply the six templates+pools and the deny-all egress; wait for Ready
make sandbox-verify-egress# prove the deny-all egress is enforced on real warm-pool pods
# run AREMA against the cluster
make sandbox-prune        # delete orphaned SandboxClaims
make sandbox-down         # delete engine pools+templates (leaves the framework installed)
```

The agent-sandbox framework (controller + router) lives in the
`agent-sandbox-system` namespace and is intentionally left running by
`sandbox-down`. The six engine pools live in `agent-sandbox-demo`.

No-model smoke drivers (`scripts/smoke/ilspy_route.py`, `scripts/smoke/jadx_route.py`)
exercise the ILSpy and jadx routes end to end without involving the model.
