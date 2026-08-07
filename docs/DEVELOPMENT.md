# AREMA development setup

End-to-end environment setup for running AREMA's autonomous reverse-engineering
pipeline against a live Kubernetes sandbox.

## Prerequisites

| Requirement | Version | Purpose |
|-------------|---------|---------|
| **Python** | 3.11+ | AREMA runtime + ADK |
| **uv** | latest | Python package manager (replaces pip/venv) |
| **Docker** | latest | Building engine images + Kind |
| **Kind** | latest | Local Kubernetes cluster (or any k8s: minikube, k3s, etc.) |
| **kubectl** | latest | Cluster interaction (CRDs, pods, port-forwards) |
| **A cluster** | Kind (or any k8s) | `make sandbox-cluster` creates a policy-ready one, or bring your own with `kubectl get nodes` Ready |

> **Kubernetes alternative:** Kind is the default path, but any k8s works
> (minikube, k3s, GKE, EKS) as long as it enforces NetworkPolicy. The
> analysis-workbench pool's deny-all egress depends on it. Kind's default CNI
> does not enforce NetworkPolicy, which is why `make sandbox-cluster` disables it
> and `make setup-sandbox` installs Calico. AREMA uses
> `SandboxLocalTunnelConnectionConfig` (kubectl port-forward) for local dev; if
> it runs inside a pod itself, it switches to `SandboxInClusterConnectionConfig`
> automatically.

## Setup sequence

```bash
# 1. Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh
source $HOME/.local/bin/env

# 2. Clone the repository
git clone https://github.com/<your-org>/AREMA.git
cd AREMA

# 3. Install Python + dev dependencies
make setup                   # uv sync --extra dev

# 4. Create a Kind cluster with the default CNI disabled, so the deny-all egress
#    NetworkPolicy on the analysis-workbench pool is actually enforced (Calico is
#    installed in the next step). Any NetworkPolicy-capable cluster works; this is
#    the turnkey path.
make sandbox-cluster         # kind create cluster --config deploy/sandbox/kind-cluster.yaml

# 5. Install the policy-enforcing CNI (Calico) + the sandbox client deps + the
#    Agent Sandbox framework (controller + router). One-time per cluster.
make setup-sandbox           # uv sync --extra sandbox + deploy/sandbox/install-agent-sandbox.sh

# 6. Configure the LLM provider + sandbox
cp .env.example .env
#   Edit .env to set at minimum:
#
#   AREMA_LLM_PROVIDER=zai                       # or google, openai, anthropic, xai, ollama, ...
#   ZAI_API_KEY=your-key-here                    # the matching provider API key
#   AREMA_SANDBOX_ENABLED=true
#   (AREMA_SANDBOX_POOL_MAP ships preset in .env.example for all six pools)

# 7. Build + load all six engine images into kind (one-time; Ghidra is the slow one)
make sandbox-build-images    # radare2-mcp, ghidra-rpc, deobfuscation-tools, ilspy-mcp, jadx, analysis-workbench

# 8. Apply every SandboxTemplate + WarmPool (incl. the workbench deny-all egress
#    policy) and wait for the pods to be Ready
make sandbox-up

# 9. (recommended) Prove the workbench egress is actually denied, then check pods
make sandbox-verify-egress
kubectl get pods -n agent-sandbox-demo

# 10. Run the agent (greeter router → malware_analyst)
AREMA_SANDBOX_ENABLED=true make adk-run
#   Then ask: "analyze the sample at /path/to/file"
```

## What each step does

| Step | Command | Effect | Repeat? |
|------|---------|--------|---------|
| 1 | `curl ... uv` | Installs the uv package manager | Once per machine |
| 2 | `git clone` | Gets the code | Once |
| 3 | `make setup` | Installs Python + dev dependencies | After dependency changes |
| 4 | `make sandbox-cluster` | Creates a Kind cluster with the default CNI disabled so NetworkPolicy (egress denial) is enforceable | Once per cluster |
| 5 | `make setup-sandbox` | Installs Calico (policy-enforcing CNI) + the sandbox client deps + the Agent Sandbox framework (controller + router) | Once per cluster |
| 6 | `cp .env.example .env` | Configures provider + sandbox | Once (edit as needed) |
| 7 | `make sandbox-build-images` | Builds + loads all six engine images (radare2-mcp, ghidra-rpc, deobfuscation-tools, ilspy-mcp, jadx, analysis-workbench) | After image changes only |
| 8 | `make sandbox-up` | Applies the SandboxTemplates + WarmPools + workbench deny-all egress policy; waits for pods Ready | After cluster restart |
| 9 | `make sandbox-verify-egress` + `kubectl get pods` | Proves workbench egress is denied; sanity-checks pods | As needed |
| 10 | `make adk-run` | Starts the interactive agent (greeter → malware_analyst) | Every run |

## Day-to-day commands

```bash
# Start the agent (both pools already up)
AREMA_SANDBOX_ENABLED=true make adk-run

# Start the web UI instead
AREMA_SANDBOX_ENABLED=true make adk-web

# Run all checks (lint + format + type-check + tests)
make check

# Run tests only
make test

# Drive one decompile route against the live cluster, no model in the loop
make smoke-ilspy SAMPLE=/path/to/assembly.dll
make smoke-jadx SAMPLE=/path/to/app.apk

# Clean up orphaned sandbox claims
make sandbox-prune

# Tear down all engine pods (leaves agent-sandbox CRDs installed)
make sandbox-down

# Bring everything back up
make sandbox-up
```

## Architecture reference

For the multi-agent layout, add-a-domain recipe, and ADK discovery model, see
[`AGENTS_AND_DISCOVERY.md`](./AGENTS_AND_DISCOVERY.md). For building tools (function
tools, CLI toolsets, MCP servers), see [`CREATING_TOOLS.md`](./CREATING_TOOLS.md).
For the full architecture, see [`ARCHITECTURE.md`](./ARCHITECTURE.md).

## Troubleshooting

### Pods not Ready

```bash
kubectl describe pod <pod-name> -n agent-sandbox-demo    # check events
kubectl logs <pod-name> -n agent-sandbox-demo            # check container logs
```

### SSLError at session end

Non-fatal: the k8s client tunnel tears down before the sandboxclaim deletes. The
`release_case` helper retries + falls back to `kubectl delete sandboxclaim`. Prune
orphans:

```bash
make sandbox-prune
```

### Ghidra daemon won't start

Ghidra 11.4.x requires JDK 21. The image uses `eclipse-temurin:21-jdk`. If you
rebuilt the image and see "unsupported java version", confirm the Dockerfile base
is `eclipse-temurin:21-jdk` (not `debian:bookworm-slim` + `openjdk-17`).

### adk run hangs / agent stuck

Check the r2mcp pod is reachable (the port-forward is open):

```bash
kubectl get pods -n agent-sandbox-demo -l arema.dev/pool=radare2-mcp
pgrep -fl "kubectl.*port-forward"    # should show an active forward
```

If the port-forward died, restart the run (prepare_sandbox re-opens it).

### Wrong provider / missing API key

The composition reads `.env` via `get_settings()`. If the agent silently uses the
wrong provider, check that `.env` (not `.env.example`) has the correct
`AREMA_LLM_PROVIDER` + matching API key. Tests pin `AREMA_LLM_PROVIDER=ollama`
via conftest so they never need real credentials.
