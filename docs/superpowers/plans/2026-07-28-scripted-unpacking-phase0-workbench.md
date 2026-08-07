# Scripted Unpacking — Phase 0: Workbench Foundation — Implementation Plan

> **STATUS: COMPLETE (2026-07-28).** All six tasks implemented, tested, and
> committed on branch `feat/scripted-unpacking` (`8ac22ce`..`04e0591`); `make
> check` green (1303 passed, 1 skipped). A consolidation pass (`04e0591`) DRY'd
> the sandbox staging preamble into `_validate_and_resolve`/`_claim_paths` (one
> copy of the Local-executor guard), added `stage_persistent_workspace` guard
> tests, structural PE-signature validation in `register_unpacked_artifact`, a
> `run_python` `timeout_s` default, and `aplib` in the image inventory.
> **Not done (correctly deferred to Phase 1):** the `packer_analyst` agent,
> `scripted_recover` gating stage, deobfuscation-loop wiring, `max_iterations`
> raise, prompt. **Remaining Phase-0 step is manual only:** the live-cluster
> validation under "Manual validation" below (needs a Calico Kind cluster; not a
> unit test).

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the sandboxed Python+radare2 "workbench" foundation — a hardened pool, a `run_python` code-execution tool over a persistent per-case workspace, a `register_unpacked_artifact` hand-off tool, and an execution-budget governor — with **no agent and no pipeline wiring yet** (that is Phase 1).

**Architecture:** A new hardened `analysis-workbench` image + warm pool hosts an exec-driven Python environment (python3 + radare2 + r2pipe + static-analysis libs). Two deferred-factory function tools drive it through the existing Kubernetes staging/exec layer: `run_python` (stateless process per call over a *persistent* `/work` workspace, returning an `ExecutionResult`-shaped dict and spilling oversized output to the SHA-256 artifact store) and `register_unpacked_artifact` (validate → `ArtifactStore.acquire` → set `CURRENT_ARTIFACT_KEY` + provenance). A per-tool `before` callback caps total `run_python` executions per case.

**Tech Stack:** Python 3.12, Google ADK 1.25.1, Kubernetes Agent Sandbox (`extensions.agents.x-k8s.io/v1beta1`), Docker, radare2 + r2pipe, pefile/LIEF/die-python/yara-python/pycryptodome, pytest, Ruff, mypy.

## Global Constraints

- **k8s sandbox is mandatory.** `run_python`/`register_unpacked_artifact` require `sandbox_backend == "k8s"`; `LocalSandboxExecutor` is forbidden (raise `DeobfuscationUnavailable`, mirroring the existing runtime).
- **Neutral-core boundary.** All new code lives under `src/reverse_engineering/`. Never add `radare2`/`ghidra`/`r2pipe` names to `src/arema/` — `tests/architecture/test_neutral_boundaries.py` fails the build otherwise.
- **ADK annotation rule.** Never `param: Any` on a tool function; use `object` for generic params. `dict[str, Any]` return annotations are fine.
- **Never `isinstance(state, dict)`.** Duck-type on `.get`/`__setitem__` (ADK `State` is a proxy).
- **Pod hardening (mandatory):** deny-all egress `NetworkPolicy` **enforced by a policy CNI (Calico)**, `readOnlyRootFilesystem: true` (writable `emptyDir` at `/work` only), `runAsNonRoot`+fixed UID 1000, drop `ALL` caps, `seccompProfile: RuntimeDefault`, `resources.limits.memory` **set** (hard OOM ceiling). Runtime isolation (`runtimeClassName: gvisor`/`kata`) is a **documented production prereq applied at deploy time — NOT hard-set in the base template** (fleet convention; the reference Kind cluster provisions no such RuntimeClass, so hard-setting it makes the pool unschedulable).
- **Image tag:** `arema-analysis-workbench:0.1.0`. **Pool logical name:** `analysis-workbench`.
- **No pipeline wiring in Phase 0.** Do NOT add any agent, do NOT touch `malware_analyst` composition or the deobfuscation loop. Only register infrastructure/tools + reserve the sanitization entry.

---

## File map

### Create

- `images/analysis-workbench/Dockerfile` — hardened python3 + radare2 + r2pipe + static-analysis libs, pinned.
- `images/analysis-workbench/.dockerignore` — minimal build context.
- `images/analysis-workbench/healthcheck.sh` — verifies `python3 -c "import r2pipe, pefile, lief, yara, Crypto"` and `radare2 -v`.
- `deploy/sandbox/10-analysis-workbench-template.yaml` — hardened, exec-driven `SandboxTemplate`.
- `deploy/sandbox/20-analysis-workbench-pool.yaml` — one-replica development warm pool.
- `deploy/sandbox/30-analysis-workbench-denyall-egress.yaml` — deny-all egress `NetworkPolicy` for the pool label.
- `src/reverse_engineering/tools/workbench/__init__.py` — curated exports + `WORKBENCH_POOL`.
- `src/reverse_engineering/tools/workbench/state.py` — workbench session-state keys + budget constant.
- `src/reverse_engineering/tools/workbench/run_python.py` — `build_run_python` factory + `RUN_PYTHON_TOOL`.
- `src/reverse_engineering/tools/workbench/register.py` — `build_register_unpacked_artifact` factory + `REGISTER_UNPACKED_ARTIFACT_TOOL`.
- `src/reverse_engineering/tools/workbench/budget.py` — `run_python_budget_guard` before-callback.
- `tests/unit/test_analysis_workbench_manifest.py` — structural manifest + Makefile + `.env.example` test.
- `tests/reverse_engineering/test_workbench_runtime.py` — persistent-staging tests.
- `tests/reverse_engineering/test_run_python_tool.py` — `run_python` tool tests.
- `tests/reverse_engineering/test_register_unpacked_artifact.py` — registration tool tests.
- `tests/reverse_engineering/test_workbench_budget.py` — execution-budget guard tests.

### Modify

- `src/reverse_engineering/tools/deobfuscation/runtime.py` — add `stage_persistent_workspace(...)` (parameterized pool, idempotent workspace, stage sample once).
- `src/reverse_engineering/profiles.py` — add the two workbench tool names to `_BINARY_ORIGIN_TOOLS` (sanitization membrane), per spec §5.1.
- `src/reverse_engineering/composition.py` — register `RUN_PYTHON_TOOL` + `REGISTER_UNPACKED_ARTIFACT_TOOL` + the `analysis-workbench` pool map entry.
- `Makefile` — fold the workbench image/pool into `sandbox-build-images` / `sandbox-up` / `sandbox-down`.
- `.env.example` — add `"analysis-workbench":"analysis-workbench-pool"` to the pool map.

---

## Task 1: Workbench image, sandbox manifest, and Makefile/.env wiring

**Files:**
- Create: `images/analysis-workbench/Dockerfile`, `images/analysis-workbench/.dockerignore`, `images/analysis-workbench/healthcheck.sh`
- Create: `deploy/sandbox/10-analysis-workbench-template.yaml`, `deploy/sandbox/20-analysis-workbench-pool.yaml`, `deploy/sandbox/30-analysis-workbench-denyall-egress.yaml`
- Modify: `Makefile`, `.env.example`
- Test: `tests/unit/test_analysis_workbench_manifest.py`

**Interfaces:**
- Produces: image `arema-analysis-workbench:0.1.0`; pool label `arema.dev/pool=analysis-workbench`; container exec-driven on `/work` (no port); `.env` pool key `analysis-workbench`.

- [ ] **Step 1: Write the failing manifest test** (models `tests/unit/test_ilspy_mcp_manifest.py`)

```python
"""Structural test for the analysis-workbench sandbox manifest (no cluster).

Validates the v1beta1 podTemplate shape, exec-driven (no port), the mandatory
hardening (gvisor runtimeClass, non-root fixed UID, dropped caps, RO rootfs,
memory limit), the deny-all egress NetworkPolicy, and that the engine is wired
into sandbox-build-images / sandbox-up / sandbox-down + the .env.example pool map.
"""

from __future__ import annotations

from pathlib import Path

import yaml

TEMPLATE = Path("deploy/sandbox/10-analysis-workbench-template.yaml")
POOL = Path("deploy/sandbox/20-analysis-workbench-pool.yaml")
NETPOL = Path("deploy/sandbox/30-analysis-workbench-denyall-egress.yaml")
MAKEFILE = Path("Makefile")
ENV_EXAMPLE = Path(".env.example")
EXPECTED_IMAGE = "arema-analysis-workbench:0.1.0"


def _container() -> dict[str, object]:
    doc = yaml.safe_load(TEMPLATE.read_text())
    assert doc["kind"] == "SandboxTemplate"
    pod = doc["spec"]["podTemplate"]["spec"]
    assert "runtimeClassName" not in pod, "runtime isolation is a deploy-time prereq, not hard-set"
    containers = pod["containers"]
    assert len(containers) == 1
    return containers[0]


def test_container_is_hardened_and_exec_driven() -> None:
    c = _container()
    assert c["image"] == EXPECTED_IMAGE
    assert "ports" not in c, "exec-driven: no container port"
    sec = c["securityContext"]
    assert sec["runAsNonRoot"] is True and sec["runAsUser"] == 1000
    assert sec["allowPrivilegeEscalation"] is False
    assert sec["readOnlyRootFilesystem"] is True
    assert sec["capabilities"]["drop"] == ["ALL"]
    assert c["resources"]["limits"]["memory"], "a hard memory ceiling is mandatory"


def test_denyall_egress_targets_the_pool() -> None:
    doc = yaml.safe_load(NETPOL.read_text())
    assert doc["kind"] == "NetworkPolicy"
    assert doc["spec"]["podSelector"]["matchLabels"]["arema.dev/pool"] == "analysis-workbench"
    assert doc["spec"]["policyTypes"] == ["Egress"]
    assert doc["spec"].get("egress", []) == [], "egress must be empty (deny all)"


def test_wired_into_make_targets_and_env() -> None:
    mk = MAKEFILE.read_text()
    assert "arema-analysis-workbench:0.1.0" in mk
    assert "20-analysis-workbench-pool.yaml" in mk
    assert "analysis-workbench" in ENV_EXAMPLE.read_text()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `rtk uv run --extra dev pytest tests/unit/test_analysis_workbench_manifest.py -q`
Expected: FAIL (files do not exist → `FileNotFoundError`).

- [ ] **Step 3: Create the image files**

`images/analysis-workbench/Dockerfile`:

```dockerfile
# Hardened Python + radare2 workbench for scripted static unpacking.
# Exec-driven (no network service); AREMA drives it via kubectl exec.
FROM debian:12-slim AS base
ENV DEBIAN_FRONTEND=noninteractive PIP_NO_CACHE_DIR=1
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-venv radare2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Pinned analysis libraries (static reimplementation inventory).
RUN pip3 install --break-system-packages \
      r2pipe==1.9.4 pefile==2024.8.26 lief==0.15.1 die-python==0.4.0 \
      yara-python==4.5.1 pycryptodome==3.21.0 arc4==0.4.0
RUN useradd --uid 1000 --create-home workbench && mkdir -p /work && chown workbench /work
COPY healthcheck.sh /usr/local/bin/analysis-workbench-healthcheck
RUN chmod +x /usr/local/bin/analysis-workbench-healthcheck
USER 1000
WORKDIR /work
# Keep the container alive for exec-driven use.
ENTRYPOINT ["sleep", "infinity"]
```

`images/analysis-workbench/healthcheck.sh`:

```bash
#!/bin/sh
set -e
radare2 -v >/dev/null
python3 -c "import r2pipe, pefile, lief, yara, Crypto, arc4"
```

`images/analysis-workbench/.dockerignore`:

```
*
!Dockerfile
!healthcheck.sh
```

- [ ] **Step 4: Create the sandbox manifests**

`deploy/sandbox/10-analysis-workbench-template.yaml`:

```yaml
apiVersion: extensions.agents.x-k8s.io/v1beta1
kind: SandboxTemplate
metadata:
  name: analysis-workbench-runtime-template
  namespace: agent-sandbox-demo
spec:
  podTemplate:
    metadata:
      labels:
        arema.dev/pool: analysis-workbench
    spec:
      # runtimeClassName (gvisor/kata) is a deploy-time production prereq, not
      # hard-set here (fleet convention; the reference cluster provisions none).
      restartPolicy: OnFailure
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        seccompProfile: { type: RuntimeDefault }
      containers:
        - name: analysis-workbench
          image: arema-analysis-workbench:0.1.0
          imagePullPolicy: IfNotPresent
          readinessProbe:
            exec: { command: ["analysis-workbench-healthcheck"] }
            initialDelaySeconds: 2
            periodSeconds: 5
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: { drop: ["ALL"] }
          volumeMounts:
            - { name: work, mountPath: /work }
          resources:
            requests: { cpu: "500m", memory: "1Gi" }
            limits: { cpu: "2", memory: "4Gi" }
      volumes:
        - name: work
          emptyDir: { sizeLimit: "2Gi" }
```

`deploy/sandbox/20-analysis-workbench-pool.yaml`:

```yaml
apiVersion: extensions.agents.x-k8s.io/v1beta1
kind: SandboxWarmPool
metadata:
  name: analysis-workbench-pool
  namespace: agent-sandbox-demo
spec:
  replicas: 1
  templateRef:
    name: analysis-workbench-runtime-template
```

`deploy/sandbox/30-analysis-workbench-denyall-egress.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: analysis-workbench-denyall-egress
  namespace: agent-sandbox-demo
spec:
  podSelector:
    matchLabels:
      arema.dev/pool: analysis-workbench
  policyTypes: ["Egress"]
  egress: []
```

- [ ] **Step 5: Wire the Makefile and `.env.example`**

In `Makefile`, add to `sandbox-build-images` (after the ilspy image lines):

```makefile
	docker build -t arema-analysis-workbench:0.1.0 images/analysis-workbench
	kind load docker-image arema-analysis-workbench:0.1.0
```

Add to `sandbox-up` (after the ilspy apply lines, before the waits):

```makefile
	kubectl apply -f deploy/sandbox/10-analysis-workbench-template.yaml
	kubectl apply -f deploy/sandbox/20-analysis-workbench-pool.yaml
	kubectl apply -f deploy/sandbox/30-analysis-workbench-denyall-egress.yaml
```

Add the corresponding `kubectl wait` for `arema.dev/pool=analysis-workbench`, and add `20-analysis-workbench-pool.yaml` deletion to `sandbox-down`. In `.env.example`, extend the pool map comment/value to include `"analysis-workbench":"analysis-workbench-pool"`.

- [ ] **Step 6: Run the test to verify it passes**

Run: `rtk uv run --extra dev pytest tests/unit/test_analysis_workbench_manifest.py -q`
Expected: PASS (3 tests).

- [ ] **Step 7: Commit**

```bash
rtk git add images/analysis-workbench deploy/sandbox/10-analysis-workbench-template.yaml deploy/sandbox/20-analysis-workbench-pool.yaml deploy/sandbox/30-analysis-workbench-denyall-egress.yaml Makefile .env.example tests/unit/test_analysis_workbench_manifest.py
rtk git commit -m "feat(workbench): hardened analysis-workbench image, pool, and wiring"
```

---

## Task 2: Persistent-workspace staging in the sandbox runtime

**Files:**
- Modify: `src/reverse_engineering/tools/deobfuscation/runtime.py`
- Create: `src/reverse_engineering/tools/workbench/__init__.py`, `src/reverse_engineering/tools/workbench/state.py`
- Test: `tests/reverse_engineering/test_workbench_runtime.py`

**Interfaces:**
- Consumes: existing `runtime.py` helpers (`_ARTIFACT_ID_PATTERN`, `_TOOL_NAME_PATTERN`, `_kubectl_exec_result`, `_kubectl_write_bytes`, `StagedArtifact`, `_read_artifact_input`, `ArtifactStore`).
- Produces: `stage_persistent_workspace(context: ToolBuildContext, artifact_id: str, tool_context: ToolContext, *, pool: str, tool_name: str) -> StagedArtifact`. Unlike `stage_artifact`, it prepares `/work/<tool_name>/<sha>` with `mkdir -p` **without** wiping, and copies the input **only if absent** — so scripts and dumps persist across calls. `WORKBENCH_POOL = "analysis-workbench"`; `WORKBENCH_INPUT_NAME = "input"`.

- [ ] **Step 1: Write the failing test** (harness models `tests/reverse_engineering/test_deobfuscation_runtime.py`'s `_FakeExecutor`)

```python
from __future__ import annotations

import pytest

from arema.runtime.sandbox.port import ExecutionResult, SandboxHandle


class _FakeExecutor:
    def __init__(self) -> None:
        self.claims: list[tuple[str, str]] = []
        self.runs: list[str] = []
        self.writes: list[tuple[str, bytes]] = []

    def claim(self, *, key: str, pool: str) -> SandboxHandle:
        self.claims.append((key, pool))
        return SandboxHandle(key=key, pool=pool, backend_id=f"{pool}-{key}")

    def run(self, handle: SandboxHandle, command: str, *, timeout: float) -> ExecutionResult:
        self.runs.append(command)
        return ExecutionResult(exit_code=0, stdout="", stderr="")

    def write_file(self, handle: SandboxHandle, path: str, data: bytes) -> None:
        self.writes.append((path, data))

    def read_file(self, handle: SandboxHandle, path: str) -> bytes:
        return b""

    def terminate(self, handle: SandboxHandle) -> None:
        pass


def test_persistent_workspace_preps_without_wiping(monkeypatch, tmp_path) -> None:
    from reverse_engineering.tools.deobfuscation import runtime as rt
    from reverse_engineering.tools.workbench import WORKBENCH_POOL

    # Build a minimal context + a staged artifact in a local ArtifactStore.
    ctx, tool_ctx, sha = _local_context(monkeypatch, tmp_path, executor=_FakeExecutor())
    staged = rt.stage_persistent_workspace(
        ctx, sha, tool_ctx, pool=WORKBENCH_POOL, tool_name="analysis"
    )
    assert staged.work_dir == f"/work/analysis/{sha}"
    # The prep command must NOT contain `rm -rf` (persistence), only mkdir -p.
    prep = ctx.services.sandbox.runs[0]
    assert "rm -rf" not in prep
    assert "mkdir" in prep
```

(`_local_context` is a small fixture that builds a `ToolBuildContext` with `sandbox_backend="k8s"`, a `_FakeExecutor`, a `RuntimeServices` carrying it, a `_FakeToolContext` with a valid sandbox case id, and stages one byte-string artifact into a temp `ArtifactStore`; copy the equivalent helper from `test_deobfuscation_runtime.py`.)

- [ ] **Step 2: Run the test to verify it fails**

Run: `rtk uv run --extra dev pytest tests/reverse_engineering/test_workbench_runtime.py -q`
Expected: FAIL (`AttributeError: module 'runtime' has no attribute 'stage_persistent_workspace'`).

- [ ] **Step 3: Add the constants module and the staging function**

`src/reverse_engineering/tools/workbench/state.py`:

```python
"""Workbench session-state keys and budget constant."""

from __future__ import annotations

WORKBENCH_POOL = "analysis-workbench"
WORKBENCH_INPUT_NAME = "input"
WORKBENCH_EXEC_COUNT_KEY = "workbench:exec_count"
WORKBENCH_MAX_EXECUTIONS = 40
```

`src/reverse_engineering/tools/workbench/__init__.py`:

```python
"""Sandboxed Python+radare2 workbench tools (scripted static unpacking)."""

from __future__ import annotations

from reverse_engineering.tools.workbench.state import (
    WORKBENCH_EXEC_COUNT_KEY,
    WORKBENCH_INPUT_NAME,
    WORKBENCH_MAX_EXECUTIONS,
    WORKBENCH_POOL,
)

__all__ = [
    "WORKBENCH_EXEC_COUNT_KEY",
    "WORKBENCH_INPUT_NAME",
    "WORKBENCH_MAX_EXECUTIONS",
    "WORKBENCH_POOL",
]
```

In `src/reverse_engineering/tools/deobfuscation/runtime.py`, add (reusing the existing validators + `_kubectl_*` helpers + `StagedArtifact`):

```python
def _prepare_persistent_work_dir_command(work_dir: str) -> str:
    """Create the work dir idempotently WITHOUT wiping it (persistence)."""
    tool_dir = work_dir.rsplit("/", 1)[0]
    check_parent = shlex.join(["test", "!", "-L", tool_dir])
    create = shlex.join(["mkdir", "-m", "0700", "-p", "--", work_dir])
    return f"{check_parent} && {create}"


def stage_persistent_workspace(
    context: ToolBuildContext,
    artifact_id: str,
    tool_context: ToolContext,
    *,
    pool: str,
    tool_name: str,
) -> StagedArtifact:
    """Claim the case pod and ensure a PERSISTENT `/work/<tool>/<sha>` workspace.

    Unlike ``stage_artifact`` this never wipes the work dir and copies the
    input only when absent, so scripts and dumps survive across calls.
    """
    if context.settings.sandbox_backend != "k8s":
        raise DeobfuscationUnavailable("workbench requires sandbox_backend='k8s'")
    executor = context.services.sandbox
    if executor is None or isinstance(executor, LocalSandboxExecutor):
        raise DeobfuscationUnavailable("workbench requires K8sSandboxExecutor")
    if _ARTIFACT_ID_PATTERN.fullmatch(artifact_id) is None:
        raise ValueError("artifact_id must be a lowercase SHA-256")
    if _TOOL_NAME_PATTERN.fullmatch(tool_name) is None:
        raise ValueError("tool_name must be a safe single path component")
    try:
        case_id = resolve_sandbox_case_id(tool_context)
    except SandboxIdentityError as exc:
        raise DeobfuscationUnavailable("sandbox identity unavailable") from exc
    handle = executor.claim(key=case_id, pool=pool)
    work_dir = f"/work/{tool_name}/{artifact_id}"
    input_path = f"{work_dir}/input"
    direct_kubectl = isinstance(executor, K8sSandboxExecutor)
    namespace = context.settings.sandbox_namespace
    output_cap = context.settings.sandbox_output_cap
    prep = _prepare_persistent_work_dir_command(work_dir)
    if direct_kubectl:
        _validate_kubernetes_namespace(namespace)
        _validate_kubernetes_pod(handle.backend_id)
        setup = _kubectl_exec_result(
            ["sh", "-c", prep], namespace, handle.backend_id, timeout=30, output_cap=output_cap
        )
    else:
        setup = executor.run(handle, prep, timeout=30)
    if setup.exit_code != 0 or setup.truncated:
        raise RuntimeError("failed to prepare workbench workspace: " + _bounded_diagnostic(setup))
    # Copy the sample only if absent, so a persistent workspace is not re-seeded.
    exists = _kubectl_exec_result(
        ["test", "-f", input_path], namespace, handle.backend_id, timeout=30, output_cap=output_cap
    ) if direct_kubectl else executor.run(handle, shlex.join(["test", "-f", input_path]), timeout=30)
    if exists.exit_code != 0:
        source = ArtifactStore(default_artifacts_root()).path_for(artifact_id)
        data = _read_artifact_input(source, None)
        if direct_kubectl:
            _kubectl_write_bytes(data, namespace, handle.backend_id, input_path)
        else:
            executor.write_file(handle, input_path, data)
    return StagedArtifact(
        executor=executor,
        handle=handle,
        artifact_id=artifact_id,
        input_path=input_path,
        work_dir=work_dir,
        timeout=float(context.settings.sandbox_run_timeout),
        namespace=namespace,
        output_cap=output_cap,
        direct_kubectl=direct_kubectl,
    )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `rtk uv run --extra dev pytest tests/reverse_engineering/test_workbench_runtime.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
rtk git add src/reverse_engineering/tools/workbench/__init__.py src/reverse_engineering/tools/workbench/state.py src/reverse_engineering/tools/deobfuscation/runtime.py tests/reverse_engineering/test_workbench_runtime.py
rtk git commit -m "feat(workbench): persistent per-case staging in the sandbox runtime"
```

---

## Task 3: The `run_python` tool

**Files:**
- Create: `src/reverse_engineering/tools/workbench/run_python.py`
- Test: `tests/reverse_engineering/test_run_python_tool.py`

**Interfaces:**
- Consumes: `stage_persistent_workspace`, `run_argv`, `read_bounded_file` (runtime); `WORKBENCH_POOL`; `CURRENT_ARTIFACT_KEY` (deobfuscation state); `ArtifactStore`.
- Produces: `build_run_python(context: ToolBuildContext) -> ToolLike`; inner `run_python(code: str, timeout_s: int, tool_context: ToolContext) -> dict[str, object]` returning `{"exit_code": int, "stdout": str, "stderr": str, "truncated": bool, "spilled_artifact_id": str}`; module constant `RUN_PYTHON_TOOL: ToolDescriptor` (id `"run_python"`, `output_policy=OutputPolicy(max_chars=32_000, max_list_items=200)`). Behavior: stage the CURRENT artifact into a persistent `analysis` workspace, write `code` to `scripts/step_<n>.py`, run `python3` with the runtime timeout wrapper while **redirecting the script's stdout to a workspace file** (`scripts/step_<n>.out`) so the full, byte-accurate output is captured in the pod rather than discarded past the transport cap. The returned `stdout` is a bounded prefix of that capture; when the full output overflows the inline cap, spill the full bytes verbatim (`read_bounded_prefix` → `ArtifactStore.acquire_bytes`, up to `MAX_RESULT_BYTES`) and return its sha in `spilled_artifact_id` (else `""`). The spill is gated on *actual stdout overflow* (`remote_file_size(stdout_path) > output_cap`), not the run's combined `truncated` flag, so a stderr-only overflow never triggers a spurious spill.

- [ ] **Step 1: Write the failing test**

```python
from __future__ import annotations

from reverse_engineering.tools.workbench.run_python import RUN_PYTHON_TOOL, build_run_python


def test_run_python_stages_current_artifact_and_runs_a_script(monkeypatch, tmp_path) -> None:
    ctx, tool_ctx, sha = _workbench_context(monkeypatch, tmp_path)  # sets CURRENT_ARTIFACT_KEY=sha
    run_python = build_run_python(ctx)
    result = run_python(code="print('hello')", timeout_s=30, tool_context=tool_ctx)
    assert result["exit_code"] == 0
    assert "step_0.py" in "".join(ctx.services.sandbox.runs)  # a script was written+run
    assert result["spilled_artifact_id"] == ""  # small output not spilled


def test_run_python_descriptor_binds_output_policy() -> None:
    assert RUN_PYTHON_TOOL.id == "run_python"
    assert RUN_PYTHON_TOOL.output_policy.max_chars == 32_000
    assert RUN_PYTHON_TOOL.factory is build_run_python
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `rtk uv run --extra dev pytest tests/reverse_engineering/test_run_python_tool.py -q`
Expected: FAIL (`ModuleNotFoundError: ...workbench.run_python`).

- [ ] **Step 3: Implement the tool** (deferred-factory pattern models `tools/prepare_ilspy.py`)

```python
"""The run_python tool: execute agent-authored Python in the workbench sandbox."""

from __future__ import annotations

import dataclasses
import shlex
from typing import TYPE_CHECKING

from google.adk.tools.tool_context import ToolContext  # noqa: TC002 - ADK resolves annotations

from arema.registry.descriptors import OutputPolicy, ToolDescriptor
from reverse_engineering.artifacts import ArtifactStore, default_artifacts_root
from reverse_engineering.tools.deobfuscation.runtime import (
    MAX_RESULT_BYTES,
    read_bounded_prefix,
    remote_file_size,
    run_argv_to_file,
    stage_persistent_workspace,
    write_staged_file,
)
from reverse_engineering.tools.deobfuscation.state import CURRENT_ARTIFACT_KEY
from reverse_engineering.tools.workbench.state import WORKBENCH_EXEC_COUNT_KEY, WORKBENCH_POOL

if TYPE_CHECKING:
    from arema.registry.descriptors import ToolLike
    from arema.runtime.agent_factory import ToolBuildContext

_TOOL_NAME = "analysis"


def build_run_python(context: ToolBuildContext) -> ToolLike:
    """Build ``run_python`` closing over the live sandbox executor."""

    def run_python(code: str, timeout_s: int, tool_context: ToolContext) -> dict[str, object]:
        state = tool_context.state
        getter = getattr(state, "get", None)
        artifact_id = getter(CURRENT_ARTIFACT_KEY) if callable(getter) else None
        if not isinstance(artifact_id, str):
            return {"exit_code": 1, "stdout": "", "stderr": "no current artifact", "truncated": False, "spilled_artifact_id": ""}
        staged = stage_persistent_workspace(
            context, artifact_id, tool_context, pool=WORKBENCH_POOL, tool_name=_TOOL_NAME
        )
        step = int(getter(WORKBENCH_EXEC_COUNT_KEY) or 0) if callable(getter) else 0
        script_path = f"{staged.work_dir}/scripts/step_{step}.py"
        stdout_path = f"{staged.work_dir}/scripts/step_{step}.out"
        # Write the script, then run it with INPUT/WORKDIR exported, redirecting
        # the script's stdout to a workspace file so the FULL, byte-accurate
        # output is captured in the pod (the transport otherwise discards
        # everything past the output cap). stderr stays inline for debugging.
        write_staged_file(staged, script_path, code.encode())
        command = (
            f"INPUT={shlex.quote(staged.input_path)} "
            f"WORKDIR={shlex.quote(staged.work_dir)} "
            f"python3 {shlex.quote(script_path)}"
        )
        result = run_argv_to_file(staged, ["sh", "-c", command], stdout_path)

        output_cap = staged.output_cap
        stdout_size = remote_file_size(staged, stdout_path)
        stdout_overflow = stdout_size > output_cap
        # Read the capture once, byte-accurately, up to a hard ceiling: the inline
        # field is its bounded prefix and the same bytes back the spill (no lossy
        # decode/re-encode ever reaches the store). Gate the spill on real stdout
        # overflow, not the run's combined truncated flag.
        captured = read_bounded_prefix(staged, stdout_path, min(stdout_size, MAX_RESULT_BYTES))
        spilled = ""
        if stdout_overflow:
            spilled = ArtifactStore(default_artifacts_root()).acquire_bytes(captured)
        return {
            "exit_code": result.exit_code,
            "stdout": captured[:output_cap].decode(errors="replace"),
            "stderr": result.stderr,
            "truncated": stdout_overflow,
            "spilled_artifact_id": spilled,
        }

    return run_python


RUN_PYTHON_TOOL = ToolDescriptor(
    id="run_python",
    description=(
        "Run an agent-authored Python script in the sandboxed analysis workbench "
        "(python3 + radare2/r2pipe + pefile/LIEF/pycryptodome) against the current "
        "artifact at $INPUT, writing dumps under $WORKDIR. Returns exit_code, "
        "stdout, stderr, truncation, and the sha of any spilled full output."
    ),
    factory=build_run_python,
    output_policy=OutputPolicy(max_chars=32_000, max_list_items=200),
)
```

> If `ArtifactStore` has no `acquire_bytes`, add a small helper that hashes+stores a byte string and returns its sha (mirror `acquire`); include that one-line addition in this task's commit.

- [ ] **Step 4: Run the test to verify it passes**

Run: `rtk uv run --extra dev pytest tests/reverse_engineering/test_run_python_tool.py -q`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
rtk git add src/reverse_engineering/tools/workbench/run_python.py tests/reverse_engineering/test_run_python_tool.py src/reverse_engineering/artifacts.py
rtk git commit -m "feat(workbench): run_python tool over a persistent workspace with output spill"
```

---

## Task 4: The `register_unpacked_artifact` tool

**Files:**
- Create: `src/reverse_engineering/tools/workbench/register.py`
- Test: `tests/reverse_engineering/test_register_unpacked_artifact.py`

**Interfaces:**
- Consumes: `read_bounded_file`, `stage_persistent_workspace` (to reach the workspace file), `ArtifactStore`, `CURRENT_ARTIFACT_KEY`, and the deobfuscation provenance key `UPX_PROVENANCE_PROMPT_KEY` pattern (reuse a `recovered ← original` provenance string).
- Produces: `build_register_unpacked_artifact(context) -> ToolLike`; inner `register_unpacked_artifact(workspace_path: str, method: str, tool_context: ToolContext) -> dict[str, object]` returning `{"registered": bool, "artifact_id": str, "size": int, "entropy_before": float, "entropy_after": float, "format": str}` or `{"registered": False, "error": str}`. On success: `ArtifactStore.acquire_bytes(recovered)` → sets `CURRENT_ARTIFACT_KEY` + provenance. **Rejects** a dump whose entropy did not drop meaningfully vs. the current artifact (a "still-packed" dump). Returns only structured, non-content metadata (spec §5.1).

- [ ] **Step 1: Write the failing test**

```python
from __future__ import annotations

from reverse_engineering.tools.workbench.register import (
    REGISTER_UNPACKED_ARTIFACT_TOOL,
    build_register_unpacked_artifact,
)
from reverse_engineering.tools.deobfuscation.state import CURRENT_ARTIFACT_KEY


def test_registers_lower_entropy_payload_and_updates_current_artifact(monkeypatch, tmp_path) -> None:
    # workspace file = low-entropy bytes; current artifact = high-entropy packed input.
    ctx, tool_ctx, packed_sha = _workbench_context(monkeypatch, tmp_path, current_entropy=7.9)
    monkeypatch.setattr(  # the tool reads the recovered file via read_bounded_file
        "reverse_engineering.tools.workbench.register.read_bounded_file",
        lambda staged, path, max_bytes: b"MZ" + b"\x00" * 4096,
    )
    register = build_register_unpacked_artifact(ctx)
    out = register(workspace_path="unpacked.bin", method="rc4-static", tool_context=tool_ctx)
    assert out["registered"] is True
    assert out["entropy_after"] < out["entropy_before"]
    assert tool_ctx.state.get(CURRENT_ARTIFACT_KEY) == out["artifact_id"]


def test_rejects_a_still_packed_dump(monkeypatch, tmp_path) -> None:
    import os

    ctx, tool_ctx, packed_sha = _workbench_context(monkeypatch, tmp_path, current_entropy=7.9)
    monkeypatch.setattr(
        "reverse_engineering.tools.workbench.register.read_bounded_file",
        lambda staged, path, max_bytes: os.urandom(4096),  # still high entropy
    )
    register = build_register_unpacked_artifact(ctx)
    out = register(workspace_path="unpacked.bin", method="x", tool_context=tool_ctx)
    assert out["registered"] is False
    assert tool_ctx.state.get(CURRENT_ARTIFACT_KEY) == packed_sha  # unchanged
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `rtk uv run --extra dev pytest tests/reverse_engineering/test_register_unpacked_artifact.py -q`
Expected: FAIL (module missing).

- [ ] **Step 3: Implement the tool**

```python
"""register_unpacked_artifact: admit a recovered payload back into the pipeline."""

from __future__ import annotations

import math
from collections import Counter
from typing import TYPE_CHECKING

from google.adk.tools.tool_context import ToolContext  # noqa: TC002

from arema.registry.descriptors import OutputPolicy, ToolDescriptor
from reverse_engineering.artifacts import ArtifactStore, default_artifacts_root
from reverse_engineering.tools.deobfuscation.runtime import read_bounded_file, stage_persistent_workspace
from reverse_engineering.tools.deobfuscation.state import CURRENT_ARTIFACT_KEY
from reverse_engineering.tools.workbench.state import WORKBENCH_POOL

if TYPE_CHECKING:
    from arema.registry.descriptors import ToolLike
    from arema.runtime.agent_factory import ToolBuildContext

_MAX_RECOVERED_BYTES = 512 * 1024 * 1024
_MIN_ENTROPY_DROP = 0.5
_TOOL_NAME = "analysis"


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def build_register_unpacked_artifact(context: ToolBuildContext) -> ToolLike:
    def register_unpacked_artifact(
        workspace_path: str, method: str, tool_context: ToolContext
    ) -> dict[str, object]:
        state = tool_context.state
        getter = getattr(state, "get", None)
        setter = getattr(state, "__setitem__", None)
        current = getter(CURRENT_ARTIFACT_KEY) if callable(getter) else None
        if not isinstance(current, str) or not callable(setter):
            return {"registered": False, "error": "no current artifact"}
        store = ArtifactStore(default_artifacts_root())
        before = _entropy(store.path_for(current).read_bytes())
        staged = stage_persistent_workspace(
            context, current, tool_context, pool=WORKBENCH_POOL, tool_name=_TOOL_NAME
        )
        recovered = read_bounded_file(staged, f"{staged.work_dir}/{workspace_path}", _MAX_RECOVERED_BYTES)
        after = _entropy(recovered)
        if before - after < _MIN_ENTROPY_DROP:
            return {"registered": False, "error": "entropy did not drop; dump still packed"}
        new_id = store.acquire_bytes(recovered)
        setter(CURRENT_ARTIFACT_KEY, new_id)
        setter("deobf_upx_provenance", f"recovered {new_id} from {current} via {method}")
        return {
            "registered": True,
            "artifact_id": new_id,
            "size": len(recovered),
            "entropy_before": round(before, 3),
            "entropy_after": round(after, 3),
            "format": "recovered",
        }

    return register_unpacked_artifact


REGISTER_UNPACKED_ARTIFACT_TOOL = ToolDescriptor(
    id="register_unpacked_artifact",
    description=(
        "Admit a recovered payload written under $WORKDIR back into the pipeline: "
        "validates entropy dropped vs the packed input, stores it by SHA-256, and "
        "makes it the current artifact for the downstream stages. Returns only "
        "structured metadata (id, sizes, entropy, method) -- never raw content."
    ),
    factory=build_register_unpacked_artifact,
    output_policy=OutputPolicy(max_chars=2_000, max_list_items=10),
)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `rtk uv run --extra dev pytest tests/reverse_engineering/test_register_unpacked_artifact.py -q`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
rtk git add src/reverse_engineering/tools/workbench/register.py tests/reverse_engineering/test_register_unpacked_artifact.py
rtk git commit -m "feat(workbench): register_unpacked_artifact hand-off via CURRENT_ARTIFACT_KEY"
```

---

## Task 5: Execution-budget guard + sanitization entry

**Files:**
- Create: `src/reverse_engineering/tools/workbench/budget.py`
- Modify: `src/reverse_engineering/tools/workbench/run_python.py` (attach the guard), `src/reverse_engineering/profiles.py`
- Test: `tests/reverse_engineering/test_workbench_budget.py`

**Interfaces:**
- Consumes: `WORKBENCH_EXEC_COUNT_KEY`, `WORKBENCH_MAX_EXECUTIONS`.
- Produces: `run_python_budget_guard(tool, args, tool_context) -> dict | None` — increments the per-case counter; returns a short-circuit dict once the cap is exceeded (never runs the sandbox again), else `None`. Attached via `RUN_PYTHON_TOOL.callbacks = ToolLifecycleCallbacks(before=(run_python_budget_guard,))`. `run_python` + `register_unpacked_artifact` names added to `profiles._BINARY_ORIGIN_TOOLS`.

- [ ] **Step 1: Write the failing test**

```python
from __future__ import annotations

from reverse_engineering.tools.workbench.budget import run_python_budget_guard
from reverse_engineering.tools.workbench.state import WORKBENCH_EXEC_COUNT_KEY, WORKBENCH_MAX_EXECUTIONS


class _State(dict):
    pass


def test_guard_counts_and_then_short_circuits() -> None:
    state = _State()
    ctx = type("C", (), {"state": state})()
    tool = type("T", (), {"name": "run_python"})()
    for _ in range(WORKBENCH_MAX_EXECUTIONS):
        assert run_python_budget_guard(tool, {}, ctx) is None
    blocked = run_python_budget_guard(tool, {}, ctx)
    assert isinstance(blocked, dict) and "budget" in blocked["stderr"].lower()
    assert state[WORKBENCH_EXEC_COUNT_KEY] == WORKBENCH_MAX_EXECUTIONS


def test_run_python_descriptor_has_the_budget_guard() -> None:
    from reverse_engineering.tools.workbench.run_python import RUN_PYTHON_TOOL

    assert run_python_budget_guard in RUN_PYTHON_TOOL.callbacks.before


def test_workbench_tools_are_sanitized() -> None:
    from reverse_engineering.profiles import _BINARY_ORIGIN_TOOLS

    assert {"run_python", "register_unpacked_artifact"} <= _BINARY_ORIGIN_TOOLS
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `rtk uv run --extra dev pytest tests/reverse_engineering/test_workbench_budget.py -q`
Expected: FAIL (module missing / guard not attached / names not in set).

- [ ] **Step 3: Implement the guard and wire it**

`src/reverse_engineering/tools/workbench/budget.py`:

```python
"""Per-case execution budget for run_python (the resource governor)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from reverse_engineering.tools.workbench.state import (
    WORKBENCH_EXEC_COUNT_KEY,
    WORKBENCH_MAX_EXECUTIONS,
)

if TYPE_CHECKING:
    from google.adk.tools.base_tool import BaseTool
    from google.adk.tools.tool_context import ToolContext


def run_python_budget_guard(
    tool: BaseTool, args: dict[str, object], tool_context: ToolContext
) -> dict[str, object] | None:
    """Cap total run_python executions per case; short-circuit when exhausted."""
    del tool, args
    state = tool_context.state
    getter = getattr(state, "get", None)
    setter = getattr(state, "__setitem__", None)
    if not callable(getter) or not callable(setter):
        return None
    used = int(getter(WORKBENCH_EXEC_COUNT_KEY) or 0)
    if used >= WORKBENCH_MAX_EXECUTIONS:
        return {
            "exit_code": 1,
            "stdout": "",
            "stderr": f"run_python budget exhausted ({WORKBENCH_MAX_EXECUTIONS}); finalize now.",
            "truncated": False,
            "spilled_artifact_id": "",
        }
    setter(WORKBENCH_EXEC_COUNT_KEY, used + 1)
    return None
```

In `run_python.py`, attach the guard to the descriptor:

```python
from arema.registry.descriptors import ToolLifecycleCallbacks
from reverse_engineering.tools.workbench.budget import run_python_budget_guard
# ...
RUN_PYTHON_TOOL = ToolDescriptor(
    id="run_python",
    description=(...),  # unchanged
    factory=build_run_python,
    output_policy=OutputPolicy(max_chars=32_000, max_list_items=200),
    callbacks=ToolLifecycleCallbacks(before=(run_python_budget_guard,)),
)
```

In `src/reverse_engineering/profiles.py`, extend the binary-origin set:

```python
_WORKBENCH_TOOLS = frozenset({"run_python", "register_unpacked_artifact"})
_BINARY_ORIGIN_TOOLS = (
    _R2_BINARY_TOOLS | _GHIDRA_BINARY_TOOLS | DEOBFUSCATION_TOOL_NAMES | _WORKBENCH_TOOLS
)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `rtk uv run --extra dev pytest tests/reverse_engineering/test_workbench_budget.py -q`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
rtk git add src/reverse_engineering/tools/workbench/budget.py src/reverse_engineering/tools/workbench/run_python.py src/reverse_engineering/profiles.py tests/reverse_engineering/test_workbench_budget.py
rtk git commit -m "feat(workbench): per-case run_python budget guard + membrane entry"
```

---

## Task 6: Register the tools in the composition + full-suite gate

**Files:**
- Modify: `src/reverse_engineering/composition.py`
- Test: `tests/reverse_engineering/test_domain_composition.py` (or extend an existing composition test)

**Interfaces:**
- Consumes: `RUN_PYTHON_TOOL`, `REGISTER_UNPACKED_ARTIFACT_TOOL`, `WORKBENCH_POOL`.
- Produces: both tools registered on the RE catalog; the `analysis-workbench` pool present in the `.env` pool-map documentation. No agent references them yet (Phase 1).

- [ ] **Step 1: Write the failing test**

```python
def test_workbench_tools_are_registered() -> None:
    from reverse_engineering.composition import register_re_infrastructure
    from arema.registry.catalog import CatalogBuilder
    from arema.core.config import Settings
    from arema.memory.codecs import RecordCodecRegistry

    builder = CatalogBuilder()
    register_re_infrastructure(builder, RecordCodecRegistry(), Settings(_env_file=None, llm_provider="ollama"))
    catalog = builder.freeze_tools_only() if hasattr(builder, "freeze_tools_only") else None
    # Fall back to inspecting the builder's registered tool ids directly.
    ids = {t.id for t in builder.iter_tools()} if hasattr(builder, "iter_tools") else set()
    assert {"run_python", "register_unpacked_artifact"} <= ids
```

(If `CatalogBuilder` exposes no tool iterator, assert via a minimal reachable agent freeze as `test_deobf_gate_descriptor_freezes_and_composes_as_a_real_agent` does; keep the assertion to "both ids resolve".)

- [ ] **Step 2: Run the test to verify it fails**

Run: `rtk uv run --extra dev pytest tests/reverse_engineering/test_domain_composition.py -q`
Expected: FAIL (tools not registered).

- [ ] **Step 3: Register the tools**

In `src/reverse_engineering/composition.py`, inside `register_re_infrastructure`, after the existing `builder.add_tool(...)` calls:

```python
from reverse_engineering.tools.workbench.run_python import RUN_PYTHON_TOOL
from reverse_engineering.tools.workbench.register import REGISTER_UNPACKED_ARTIFACT_TOOL
# ...
builder.add_tool(RUN_PYTHON_TOOL)
builder.add_tool(REGISTER_UNPACKED_ARTIFACT_TOOL)
```

- [ ] **Step 4: Run the test, then the full gate**

Run: `rtk uv run --extra dev pytest tests/reverse_engineering/test_domain_composition.py -q` → PASS
Run: `make check`
Expected: lint + format + type-check clean; full suite green (existing + new workbench tests).

- [ ] **Step 5: Commit**

```bash
rtk git add src/reverse_engineering/composition.py tests/reverse_engineering/test_domain_composition.py
rtk git commit -m "feat(workbench): register run_python + register_unpacked_artifact tools"
```

---

## Manual validation (live cluster — not a unit test)

After Task 6, prove the foundation end-to-end against a real pod (no agent):

0. **Enforcing datapath (prerequisite).** The deny-all egress NetworkPolicy is
   only enforced by a policy-enforcing CNI; Kind's default kindnet ignores it.
   Create the cluster with the default CNI disabled and install Calico:
   `make sandbox-cluster && make setup-sandbox`
   (uses `deploy/sandbox/kind-cluster.yaml` + `install-agent-sandbox.sh`, which
   refuses to proceed on a kindnet cluster).
1. `make sandbox-build-images && make sandbox-up` — confirm `analysis-workbench-pool` pods reach Ready and carry **no memory-limit anomaly** and the deny-all egress policy (`kubectl get networkpolicy -n agent-sandbox-demo`). Then **prove the policy is actually enforced, not just present**: `make sandbox-verify-egress` (a labelled pod's outbound connection must be refused while an unlabelled baseline pod's succeeds). Merely asserting the policy object exists is false assurance.
2. Write a 6-line driver (scratch, not committed) that builds a `ToolBuildContext` against the live `K8sSandboxExecutor`, sets `CURRENT_ARTIFACT_KEY` to a staged sample, and calls `run_python(code="import r2pipe,pefile; open('/work/analysis/'+__import__('os').environ.get('WORKDIR','').split('/')[-1]+'/dump','wb').write(open(__import__('os').environ['INPUT'],'rb').read()[:1024])", ...)`, then `register_unpacked_artifact(workspace_path="dump", method="smoke")`.
3. Confirm: the script runs bounded (timeout/output caps observed), `register_unpacked_artifact` either registers or rejects on the entropy check, and a 41st `run_python` call is refused by the budget guard.
4. `make sandbox-down`.

---

## Self-review

- **Spec coverage:** Task 1 = workbench pool + hardening (§4.1); Task 2 = persistent workspace (§4.2); Task 3 = `run_python` + spill (§4.2/§4.3); Task 4 = `register_unpacked_artifact` + `CURRENT_ARTIFACT_KEY` hand-off (§4.3); Task 5 = execution-budget governor (§4.5) + membrane entry (§5.1); Task 6 = registration. **Deferred to Phase 1 (correctly out of scope):** the `packer_analyst` agent, `scripted_recover` gating, deobfuscation-loop wiring, `max_iterations` raise, prompt.
- **Type consistency:** `stage_persistent_workspace(...) -> StagedArtifact`, `run_python(code, timeout_s, tool_context) -> dict` with keys `{exit_code, stdout, stderr, truncated, spilled_artifact_id}`, `register_unpacked_artifact(workspace_path, method, tool_context) -> dict`, guard `-> dict | None`, `WORKBENCH_POOL="analysis-workbench"`, `WORKBENCH_EXEC_COUNT_KEY`, `WORKBENCH_MAX_EXECUTIONS=40` — used consistently across Tasks 2–6.
- **Known adaptation points for the implementer** (verify against the live API, adjust names only): `ArtifactStore.acquire_bytes` (add if absent — Task 3 note); the `CatalogBuilder` tool-inspection call in Task 6 (use whatever the builder actually exposes, or a reachable-agent freeze); the exact `Makefile`/`.env.example` line placement.
