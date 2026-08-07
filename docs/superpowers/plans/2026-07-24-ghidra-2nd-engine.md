# Ghidra 2nd Engine Implementation Plan (Spec B, Slice 3 / B.4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Ghidra as the second analysis engine — a `deep_decompile` agent that drives `ghidra-rpc` (CLI daemon in a sandbox pod) for deep pseudo-C decompilation, semantic search, and control-flow analysis, emitting deeper evidence-backed findings that flow through the existing evidence_critic.

**Architecture:** ghidra-rpc runs as a headless daemon in a separate sandbox pool. AREMA wraps its CLI as typed function tools via a spec-driven builder (the function-tool analog of the MCP `McpServerDescriptor` seam). The pod is driven via raw `kubectl exec` (consistent with B.2's `kubectl cp` pattern). A new `deep_decompile` agent sits between `triage_recon` and `evidence_critic`. Spec: `docs/superpowers/specs/2026-07-24-ghidra-2nd-engine-design.md`.

**Tech Stack:** Python 3.11+, Google ADK 1.25.1, Ghidra 11.x + JDK 17 + ghidra-rpc, kubectl, pytest. Refs: `docs/AGENTS_AND_DISCOVERY.md`, the r2mcp image/manifests as templates.

> **Commit signing:** use `git -c commit.gpgsign=false commit -m "..."` for every commit. Branch: `feat/b4-ghidra` (off `main`).

---

## Resolved design decisions (do not re-litigate)

1. **ghidra-rpc** (cellebrite), NOT ghidra-mcp. CLI daemon, headless, PyGhidra.
2. **Function tools** wrapping the CLI (not MCP). Spec-driven builder.
3. **`deep_decompile` agent**, sequential after triage_recon.
4. **Separate ghidra pool** (own image + template + warm pool).
5. **Raw `kubectl exec`** drives the pod (not the executor's `/execute`; the image has no python-runtime). Claim via executor, exec via kubectl.
6. **`re_guarded` profile** for deep_decompile; `binary_origin_tools` grows to r2mcp ∪ ghidra.
7. All domain code in `src/reverse_engineer/`; `src/arema` untouched.

## File structure

```
images/ghidra-rpc/Dockerfile                              NEW (Task 1)
deploy/sandbox/10-ghidra-rpc-template.yaml                NEW (Task 1)
deploy/sandbox/20-ghidra-rpc-pool.yaml                    NEW (Task 1)
Makefile                                                  MODIFY (Task 1)
tests/unit/test_ghidra_rpc_manifest.py                    NEW (Task 1)
src/reverse_engineer/runtime/portforward.py               MODIFY — add kubectl_exec (Task 2)
src/reverse_engineer/tools/ghidra/
  __init__.py                                             NEW (Task 2)
  commands.py                                             NEW — CliCommandSpec + GHIDRA_COMMANDS (Task 2)
  toolset.py                                              NEW — build_ghidra_toolset (Task 2)
  prepare_ghidra.py                                       NEW — prepare_ghidra + release_ghidra_case (Task 2)
tests/reverse_engineer/test_ghidra_toolset.py             NEW (Task 2)
src/reverse_engineer/agents/deep_decompile.py             NEW (Task 3)
src/reverse_engineer/prompts/deep_decompile.md            NEW (Task 3)
src/reverse_engineer/prompts/ghidra_rpc_reference.md      NEW (Task 3)
src/reverse_engineer/agents/reverse_engineer.py           MODIFY — sub_agent_ids + prepare_ghidra (Task 3)
src/reverse_engineer/prompts/reverse_engineer.md          MODIFY — workflow (Task 3)
src/reverse_engineer/profiles.py                          MODIFY — binary_origin_tools union (Task 3)
src/reverse_engineer/prompts/evidence_critic.md           MODIFY — ghidra tool names (Task 3)
src/reverse_engineer/composition.py                       MODIFY — register agent + tools (Task 3)
tests/reverse_engineer/test_deep_decompile.py             NEW (Task 3)
tests/reverse_engineer/test_re_composition.py             MODIFY — 5-agent graph (Task 3)
```

---

## Task 1: Ghidra image + sandbox manifests + make targets

**Files:** Create `images/ghidra-rpc/Dockerfile`, `deploy/sandbox/10-ghidra-rpc-template.yaml`, `deploy/sandbox/20-ghidra-rpc-pool.yaml`. Modify `Makefile`. Create `tests/unit/test_ghidra_rpc_manifest.py`.

- [ ] **Step 1: Write the manifest test (TDD)**

Create `tests/unit/test_ghidra_rpc_manifest.py` (mirror `tests/unit/test_radare2_mcp_manifest.py`):

```python
"""Structural unit tests for the ghidra-rpc sandbox manifest (Spec B, B.4)."""

from __future__ import annotations

from pathlib import Path

import yaml

TEMPLATE_PATH = Path("deploy/sandbox/10-ghidra-rpc-template.yaml")
POOL_PATH = Path("deploy/sandbox/20-ghidra-rpc-pool.yaml")
EXPECTED_IMAGE = "arema-ghidra-rpc:0.1.0"


def _template_spec() -> dict[str, object]:
    doc = yaml.safe_load(TEMPLATE_PATH.read_text())
    assert doc["kind"] == "SandboxTemplate"
    return doc["spec"]  # type: ignore[return-value]


def _container() -> dict[str, object]:
    pod_spec = _template_spec()["podTemplate"]["spec"]  # type: ignore[index]
    containers = pod_spec["containers"]  # type: ignore[index]
    assert len(containers) == 1
    return containers[0]  # type: ignore[return-value]


def test_template_uses_v1beta1_podtemplate() -> None:
    spec = _template_spec()
    assert "podTemplate" in spec
    assert "template" not in spec


def test_template_name_matches_pool_ref() -> None:
    template = yaml.safe_load(TEMPLATE_PATH.read_text())
    pool = yaml.safe_load(POOL_PATH.read_text())
    assert template["metadata"]["name"] == "ghidra-rpc-runtime-template"
    assert pool["spec"]["sandboxTemplateRef"]["name"] == "ghidra-rpc-runtime-template"  # type: ignore[index]
    assert pool["spec"]["replicas"] >= 1  # type: ignore[index]


def test_container_image() -> None:
    container = _container()
    assert container["image"] == EXPECTED_IMAGE  # type: ignore[index]


def test_container_runs_nonroot_fixed_uid() -> None:
    container = _container()
    pod_spec = _template_spec()["podTemplate"]["spec"]  # type: ignore[index]
    assert pod_spec["securityContext"]["runAsNonRoot"] is True  # type: ignore[index]
    assert container["securityContext"]["runAsNonRoot"] is True  # type: ignore[index]
    assert container["securityContext"]["runAsUser"] == 1000  # type: ignore[index]
    assert "ALL" in container["securityContext"]["capabilities"]["drop"]  # type: ignore[index]
    assert pod_spec["automountServiceAccountToken"] is False  # type: ignore[index]
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
uv run --extra dev pytest tests/unit/test_ghidra_rpc_manifest.py -v
```
Expected: FAIL (files not found).

- [ ] **Step 3: Create the Dockerfile**

Create `images/ghidra-rpc/Dockerfile`:

```dockerfile
# ghidra-rpc sandbox image for AREMA (Spec B, B.4).
#
# Single container: Ghidra 11.x + JDK 17 + ghidra-rpc (cellebrite-labs).
# The pod is driven via raw `kubectl exec` (AREMA's prepare_ghidra starts the
# daemon + loads the binary; the ghidra tools exec ghidra-rpc CLI commands).
# No python-runtime playground /execute — the kubectl-exec path mirrors B.2's
# kubectl-cp pattern.
#
# The agent's artifact is copied into /app/<sha256> by prepare_ghidra (kubectl cp);
# ghidra-rpc load opens it and returns a short_name used in subsequent commands.

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# JDK 17 (Ghidra requirement) + tar (kubectl cp) + wget (Ghidra download) + pip.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openjdk-17-jdk-headless ca-certificates wget unzip tar python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Download + extract Ghidra 11.x to /opt/ghidra.
ARG GHIDRA_VERSION=11.4.1
RUN wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/Ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_VERSION}.zip" -O /tmp/ghidra.zip \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && ln -s "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" /opt/ghidra \
    && rm /tmp/ghidra.zip

ENV GHIDRA_INSTALL_DIR=/opt/ghidra
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64

# Install ghidra-rpc (cellebrite-labs). It is a Python package that provides the
# `ghidra-rpc` CLI. Install from PyPI; if not on PyPI, clone + pip install.
RUN pip3 install --break-system-packages ghidra-rpc || \
    (git clone --depth 1 https://github.com/cellebrite-labs/ghidra-rpc.git /tmp/ghidra-rpc \
     && pip3 install --break-system-packages /tmp/ghidra-rpc \
     && rm -rf /tmp/ghidra-rpc)

# Non-root runtime user at fixed UID 1000 (kubelet runAsNonRoot convention).
RUN groupadd -r -g 1000 guser \
    && useradd -r -u 1000 -g 1000 -m -d /home/guser guser \
    && mkdir -p /app \
    && chown -R 1000:1000 /app /home/guser

USER 1000
ENV HOME=/home/guser
WORKDIR /app

# The pod stays warm (sleep); ghidra-rpc daemon is started on-demand by prepare_ghidra.
CMD ["sleep", "infinity"]
```

> **Build-time note:** verify the Ghidra download URL + the ghidra-rpc PyPI name at `docker build` time. If the URL 404s, check https://github.com/NationalSecurityAgency/ghidra/releases for the exact asset name. If `pip install ghidra-rpc` fails, the fallback clones from source.

- [ ] **Step 4: Create the manifests**

Create `deploy/sandbox/10-ghidra-rpc-template.yaml` (mirror `10-radare2-mcp-template.yaml`):

```yaml
# ghidra-rpc sandbox template (Spec B, B.4).
# Single-container pod with Ghidra + ghidra-rpc. Driven via kubectl exec.
# Before hostile code, set spec.podTemplate.spec.runtimeClassName to gvisor/kata.
apiVersion: extensions.agents.x-k8s.io/v1beta1
kind: SandboxTemplate
metadata:
  name: ghidra-rpc-runtime-template
  namespace: agent-sandbox-demo
spec:
  podTemplate:
    metadata:
      labels:
        arema.dev/pool: ghidra-rpc
    spec:
      restartPolicy: OnFailure
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
      containers:
        - name: ghidra-rpc
          image: arema-ghidra-rpc:0.1.0
          imagePullPolicy: IfNotPresent
          readinessProbe:
            exec:
              command: ["ghidra-rpc", "--help"]
            initialDelaySeconds: 2
            periodSeconds: 5
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          resources:
            requests: { cpu: "500m", memory: "2Gi" }
            limits: { cpu: "2", memory: "4Gi" }
```

Create `deploy/sandbox/20-ghidra-rpc-pool.yaml`:

```yaml
apiVersion: extensions.agents.x-k8s.io/v1beta1
kind: SandboxWarmPool
metadata:
  name: ghidra-rpc-pool
  namespace: agent-sandbox-demo
spec:
  replicas: 1
  sandboxTemplateRef:
    name: ghidra-rpc-runtime-template
```

- [ ] **Step 5: Add make targets**

In `Makefile`, add to the `.PHONY` line: `sandbox-ghidra-image sandbox-ghidra-up sandbox-ghidra-down`. Add these target blocks (after the `sandbox-mcp-down` block):

```makefile
# -- ghidra-rpc (Spec B, B.4) ------------------------------------------------
sandbox-ghidra-image: ## Build the ghidra-rpc image (Ghidra + JDK + ghidra-rpc) and load into kind
	docker build -t arema-ghidra-rpc:0.1.0 images/ghidra-rpc
	kind load docker-image arema-ghidra-rpc:0.1.0 2>/dev/null || true

sandbox-ghidra-up: ## Apply the ghidra-rpc SandboxTemplate + WarmPool and wait for Ready
	kubectl apply -f deploy/sandbox/10-ghidra-rpc-template.yaml
	kubectl apply -f deploy/sandbox/20-ghidra-rpc-pool.yaml
	kubectl wait --for=condition=Ready pod -l arema.dev/pool=ghidra-rpc \
		-n agent-sandbox-demo --timeout=300s || true

sandbox-ghidra-down: ## Delete the ghidra-rpc pool/template
	kubectl delete -f deploy/sandbox/20-ghidra-rpc-pool.yaml --ignore-not-found
	kubectl delete -f deploy/sandbox/10-ghidra-rpc-template.yaml --ignore-not-found
```

- [ ] **Step 6: Run manifest tests + make check**

```bash
uv run --extra dev pytest tests/unit/test_ghidra_rpc_manifest.py -v
make check
```
Expected: manifest tests PASS; make check green.

- [ ] **Step 7: Build the image (verify the Dockerfile works)**

```bash
make sandbox-ghidra-image
```
If the build fails (URL, PyPI name), fix the Dockerfile and retry. This is the de-risking step for the whole slice.

- [ ] **Step 8: Commit**

```bash
git add images/ghidra-rpc deploy/sandbox/10-ghidra-rpc-template.yaml deploy/sandbox/20-ghidra-rpc-pool.yaml Makefile tests/unit/test_ghidra_rpc_manifest.py
git -c commit.gpgsign=false commit -m "feat: ghidra-rpc sandbox image + manifests + make targets"
```

---

## Task 2: kubectl_exec + CliCommandSpec + build_ghidra_toolset + prepare_ghidra

**Files:** Modify `src/reverse_engineer/runtime/portforward.py` (add `kubectl_exec`). Create `src/reverse_engineer/tools/ghidra/__init__.py`, `commands.py`, `toolset.py`, `prepare_ghidra.py`. Create `tests/reverse_engineer/test_ghidra_toolset.py`.

- [ ] **Step 1: Write the failing tests**

Create `tests/reverse_engineer/test_ghidra_toolset.py`:

```python
"""Unit tests for the ghidra function-tool layer: spec table, builder, prepare_ghidra."""

from __future__ import annotations

from typing import Any

from reverse_engineer.tools.ghidra.commands import GHIDRA_COMMANDS, CliCommandSpec
from reverse_engineer.tools.ghidra.prepare_ghidra import _GHIDRA_CASE_STATE, release_ghidra_case
from reverse_engineer.tools.ghidra.toolset import build_ghidra_toolset
from arema.registry.descriptors import OutputPolicy


def test_command_table_has_curated_read_only_surface() -> None:
    names = {spec.name for spec in GHIDRA_COMMANDS}
    assert "ghidra_decompile" in names
    assert "ghidra_search_decompiled" in names
    assert "ghidra_basic_blocks" in names
    assert "ghidra_pcode" in names
    assert "ghidra_metadata" in names
    assert "ghidra_list_functions" in names
    assert "ghidra_xrefs_to" in names
    # no write/rename/patch tools in the curated set
    assert not any("rename" in n or "patch" in n or "write" in n for n in names)


def test_command_specs_have_output_policies() -> None:
    for spec in GHIDRA_COMMANDS:
        assert isinstance(spec.output_policy, OutputPolicy)
        assert spec.output_policy.max_chars > 0


def test_build_ghidra_toolset_produces_descriptors() -> None:
    from reverse_engineer.tools.ghidra.toolset import build_ghidra_toolset

    class _FakeBuildContext:
        services = type("S", (), {"sandbox": None})()
        settings = type("Z", (), {"sandbox_namespace": "agent-sandbox-demo"})()

    descriptors = build_ghidra_toolset(_FakeBuildContext())
    names = {d.id for d in descriptors}
    assert "ghidra_decompile" in names
    assert len(descriptors) == len(GHIDRA_COMMANDS)


def test_kubectl_exec_helper_exists_and_signs_correctly() -> None:
    from reverse_engineer.runtime.portforward import kubectl_exec

    # kubectl_exec is callable with (command, namespace, pod) — tested via monkeypatch in prepare test
    assert callable(kubectl_exec)
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
uv run --extra dev pytest tests/reverse_engineer/test_ghidra_toolset.py -v
```
Expected: FAIL (modules not found).

- [ ] **Step 3: Add `kubectl_exec` to portforward.py**

In `src/reverse_engineer/runtime/portforward.py`, add after the `kubectl_cp` function:

```python
def kubectl_exec(command: str, namespace: str, pod: str) -> str:
    """Run *command* inside the pod at ``namespace/pod`` via ``kubectl exec``.

    Returns stdout. Raises :class:`RuntimeError` on a nonzero exit or timeout so
    the fail-open caller can surface a clear message. Mirrors :func:`kubectl_cp`.
    """
    try:
        result = subprocess.run(
            [
                "kubectl",
                "exec",
                f"pod/{pod}",
                "-n",
                namespace,
                "--",
                "sh",
                "-c",
                command,
            ],
            capture_output=True,
            check=False,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("kubectl exec failed: timed out after 300s") from None
    if result.returncode != 0:
        stderr = result.stderr.decode(errors="replace").strip()
        raise RuntimeError(f"kubectl exec failed (exit {result.returncode}): {stderr}")
    return result.stdout.decode(errors="replace")
```

- [ ] **Step 4: Create `commands.py`**

Create `src/reverse_engineer/tools/ghidra/__init__.py` (empty).

Create `src/reverse_engineer/tools/ghidra/commands.py`:

```python
"""The curated ghidra-rpc command table: spec-driven function-tool surface.

Each entry is one :class:`CliCommandSpec` that :func:`build_ghidra_toolset`
turns into a typed AREMA function tool. Adding a tool = one spec line. The
shape generalizes to any future sandbox-CLI engine (promote ``SandboxCliToolset``
to the neutral core when a 2nd engine appears — rule of three).
"""

from __future__ import annotations

from dataclasses import dataclass

from arema.registry.descriptors import OutputPolicy


@dataclass(frozen=True, slots=True)
class CliCommandSpec:
    name: str
    description: str
    subcommand: str
    output_policy: OutputPolicy
    arg_template: str = ""
    extra_flags: str = ""


GHIDRA_COMMANDS: tuple[CliCommandSpec, ...] = (
    CliCommandSpec(
        name="ghidra_metadata",
        description="Get binary metadata (arch, bits, format) from Ghidra.",
        subcommand="metadata",
        output_policy=OutputPolicy(max_chars=4_000),
    ),
    CliCommandSpec(
        name="ghidra_list_functions",
        description="List functions in the binary (paginated).",
        subcommand="functions",
        output_policy=OutputPolicy(max_chars=8_000, max_list_items=50),
        arg_template="--limit 100",
    ),
    CliCommandSpec(
        name="ghidra_decompile",
        description="Decompile a function to Ghidra pseudo-C. Pass a function name or hex address.",
        subcommand="decompile",
        output_policy=OutputPolicy(max_chars=10_000),
        arg_template="{function}",
    ),
    CliCommandSpec(
        name="ghidra_search_decompiled",
        description="Regex-search decompiled C across ALL functions in one call. Use to find crypto constants, API-call patterns, or vulnerability sinks.",
        subcommand="search-decompiled",
        output_policy=OutputPolicy(max_chars=10_000, max_list_items=30),
        arg_template="{pattern}",
    ),
    CliCommandSpec(
        name="ghidra_basic_blocks",
        description="Get basic blocks (CFG) of a function for control-flow analysis.",
        subcommand="basic-blocks",
        output_policy=OutputPolicy(max_chars=8_000),
        arg_template="{function}",
    ),
    CliCommandSpec(
        name="ghidra_xrefs_to",
        description="Find cross-references TO a symbol or address (who calls this).",
        subcommand="xrefs-to",
        output_policy=OutputPolicy(max_chars=6_000, max_list_items=30),
        arg_template="{target}",
    ),
    CliCommandSpec(
        name="ghidra_imports",
        description="List imported symbols.",
        subcommand="imports",
        output_policy=OutputPolicy(max_chars=6_000, max_list_items=50),
    ),
    CliCommandSpec(
        name="ghidra_strings",
        description="Search defined strings (substring match).",
        subcommand="strings",
        output_policy=OutputPolicy(max_chars=6_000, max_list_items=30),
        arg_template="{query}",
    ),
    CliCommandSpec(
        name="ghidra_pcode",
        description="Get Ghidra P-code IR for a function. Use --high for high SSA form. Fallback when decompile produces bad output (common on ARM Thumb).",
        subcommand="pcode",
        output_policy=OutputPolicy(max_chars=10_000),
        arg_template="{function}",
        extra_flags="--high",
    ),
)
```

- [ ] **Step 5: Create `toolset.py`**

Create `src/reverse_engineer/tools/ghidra/toolset.py`:

```python
"""Build AREMA function tools from the ghidra-rpc command table.

Each tool is a thin wrapper that shells out via :func:`kubectl_exec` to run a
``ghidra-rpc`` CLI command in the claimed sandbox pod. The binary name is
injected from the case state (stashed by ``prepare_ghidra``) — the agent never
passes it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from arema.core.logging import get_logger
from arema.registry.descriptors import ToolDescriptor
from reverse_engineer.runtime.portforward import kubectl_exec
from reverse_engineer.tools.ghidra.commands import GHIDRA_COMMANDS, CliCommandSpec

if TYPE_CHECKING:
    from arema.runtime.agent_factory import ToolBuildContext

logger = get_logger(__name__)


def _build_tool(spec: CliCommandSpec, context: ToolBuildContext) -> ToolDescriptor:
    namespace = context.settings.sandbox_namespace
    executor = context.services.sandbox

    def _tool(_tool_context: Any = None, **kwargs: Any) -> dict[str, Any]:
        # Resolve the pod + binary name from the case state.
        case_state = _GHIDRA_CASE_STATE.get(_resolve_case_id(_tool_context))
        if case_state is None:
            return {"success": False, "error": "ghidra not prepared for this case"}
        pod = case_state["pod"]
        binary = case_state["binary"]
        # Build the ghidra-rpc command.
        args = spec.arg_template.format(**kwargs) if spec.arg_template else ""
        flags = f" {spec.extra_flags}" if spec.extra_flags else ""
        cmd = f"ghidra-rpc {spec.subcommand} {binary} {args}{flags} --project {case_state['project']}"
        try:
            stdout = kubectl_exec(cmd, namespace, pod)
            return {"success": True, "output": stdout}
        except Exception as exc:  # noqa: BLE001
            logger.warning("ghidra tool failed", tool=spec.name, error_type=type(exc).__name__)
            return {"success": False, "error": str(exc), "tool": spec.name}

    _tool.__name__ = spec.name
    _tool.__doc__ = spec.description
    return ToolDescriptor(
        id=spec.name,
        description=spec.description,
        tool=_tool,
        output_policy=spec.output_policy,
    )


def _resolve_case_id(_tool_context: Any) -> str:
    """Read the case id from the tool context state (duck-typed .get), fallback to the default."""
    state = getattr(_tool_context, "state", None)
    getter = getattr(state, "get", None)
    if callable(getter):
        from arema.runtime.sessions import SessionKeys

        return str(getter(SessionKeys.SANDBOX_CASE_ID, "re-mvp"))
    return "re-mvp"


def build_ghidra_toolset(context: ToolBuildContext) -> tuple[ToolDescriptor, ...]:
    """Build the full set of ghidra function-tool descriptors from the command table."""
    return tuple(_build_tool(spec, context) for spec in GHIDRA_COMMANDS)


# The case state registry is populated by prepare_ghidra and read by every tool.
# Keyed by case_id; value: {pod, binary, project, executor}.
_GHIDRA_CASE_STATE: dict[str, dict[str, str]] = {}
```

> **Note:** `_GHIDRA_CASE_STATE` is imported by `prepare_ghidra` too (same module-level dict). To avoid a circular import, define it in `toolset.py` and import it in `prepare_ghidra`. Update the test import accordingly: `from reverse_engineer.tools.ghidra.toolset import _GHIDRA_CASE_STATE`. (Fix the test in Step 1 if needed.)

- [ ] **Step 6: Create `prepare_ghidra.py`**

Create `src/reverse_engineer/tools/ghidra/prepare_ghidra.py`:

```python
"""The prepare_ghidra tool: claim a ghidra pod, copy the artifact, start the daemon, load the binary.

Mirrors prepare_sandbox's pattern: a deferred-factory tool that closes over the
sandbox executor and namespace. The pod is driven via raw kubectl (cp + exec),
consistent with B.2.
"""

from __future__ import annotations

import atexit
import json
from typing import TYPE_CHECKING, Any

from arema.core.logging import get_logger
from arema.registry.descriptors import OutputPolicy, ToolDescriptor
from arema.runtime.sessions import SessionKeys
from reverse_engineer.artifacts import ArtifactStore, default_artifacts_root
from reverse_engineer.runtime.portforward import kubectl_cp, kubectl_exec
from reverse_engineer.tools.ghidra.toolset import _GHIDRA_CASE_STATE

if TYPE_CHECKING:
    from arema.registry.descriptors import ToolLike
    from arema.runtime.agent_factory import ToolBuildContext
    from arema.runtime.sandbox.port import SandboxExecutor

logger = get_logger(__name__)

_GHIDRA_POOL = "ghidra-rpc"
_PROJECT_PATH = "/tmp/arema_ghidra.gpr"
_DEFAULT_CASE_KEY = "re-mvp"

_GHIDRA_EXECUTORS: dict[str, SandboxExecutor] = {}


def build_prepare_ghidra(context: ToolBuildContext) -> ToolLike:
    """Build the prepare_ghidra tool closing over the live sandbox executor."""
    executor = context.services.sandbox
    namespace = context.settings.sandbox_namespace

    def prepare_ghidra(artifact_id: str, tool_context: Any = None) -> dict[str, Any]:
        state = getattr(tool_context, "state", None)
        getter = getattr(state, "get", None)
        case_id = (
            str(getter(SessionKeys.SANDBOX_CASE_ID, _DEFAULT_CASE_KEY))
            if callable(getter)
            else _DEFAULT_CASE_KEY
        )
        pod = ""
        try:
            if executor is None:
                return {"pod": "", "binary": "", "ready": False, "error": "sandbox executor is not configured"}
            handle = executor.claim(key=case_id, pool=_GHIDRA_POOL)
            pod = handle.backend_id
            _GHIDRA_EXECUTORS[case_id] = executor
            local_path = ArtifactStore(default_artifacts_root()).path_for(artifact_id)
            kubectl_cp(str(local_path), namespace, pod, f"/app/{artifact_id}")
            # Start the daemon (headless, detached).
            kubectl_exec(
                f"ghidra-rpc start --project {_PROJECT_PATH} --headless --detach",
                namespace, pod,
            )
            # Load the binary; capture the short_name from the JSON response.
            load_out = kubectl_exec(
                f"ghidra-rpc load /app/{artifact_id} --project {_PROJECT_PATH}",
                namespace, pod,
            )
            binary_name = artifact_id  # fallback
            try:
                load_json = json.loads(load_out.strip().splitlines()[-1])
                binary_name = load_json.get("short_name", artifact_id)
            except Exception:
                pass  # keep the fallback; the agent can still use the sha256
            _GHIDRA_CASE_STATE[case_id] = {
                "pod": pod,
                "binary": binary_name,
                "project": _PROJECT_PATH,
            }
            return {"pod": pod, "binary": binary_name, "ready": True}
        except Exception as exc:
            logger.warning("prepare_ghidra failed", error_type=type(exc).__name__, exc_info=True)
            return {"pod": pod, "binary": "", "ready": False, "error": str(exc)}

    return prepare_ghidra


def release_ghidra_case(case_id: str) -> None:
    """Stop the daemon + release the executor. Fail-open."""
    state = _GHIDRA_CASE_STATE.pop(case_id, None)
    if state is not None:
        try:
            kubectl_exec(f"ghidra-rpc stop --project {state['project']}", "agent-sandbox-demo", state["pod"])
        except Exception as exc:
            logger.warning("ghidra stop failed - swallowed", error_type=type(exc).__name__)
    executor = _GHIDRA_EXECUTORS.pop(case_id, None)
    if executor is not None:
        try:
            executor.release_session(case_id)
        except Exception as exc:
            logger.warning("ghidra release_session failed - swallowed", error_type=type(exc).__name__)


def _release_all_ghidra_cases() -> None:
    for case_id in list(_GHIDRA_EXECUTORS):
        release_ghidra_case(case_id)


atexit.register(_release_all_ghidra_cases)


PREPARE_GHIDRA_TOOL = ToolDescriptor(
    id="prepare_ghidra",
    description=(
        "Claim a ghidra-rpc sandbox pod, copy the artifact into /app/<sha256>, "
        "start the headless Ghidra daemon, and load the binary. Returns the pod "
        "name, the binary short_name, and readiness."
    ),
    factory=build_prepare_ghidra,
    output_policy=OutputPolicy(max_chars=2_000, max_list_items=10),
)
```

- [ ] **Step 7: Fix the test import + run tests**

If the test in Step 1 imported `_GHIDRA_CASE_STATE` from `prepare_ghidra`, fix it to import from `toolset`:

```python
from reverse_engineer.tools.ghidra.toolset import _GHIDRA_CASE_STATE
```

Run:
```bash
uv run --extra dev pytest tests/reverse_engineer/test_ghidra_toolset.py -v
```
Expected: PASS.

- [ ] **Step 8: make check + commit**

```bash
make check
git add src/reverse_engineer/tools/ghidra src/reverse_engineer/runtime/portforward.py tests/reverse_engineer/test_ghidra_toolset.py
git -c commit.gpgsign=false commit -m "feat: ghidra-rpc function-tool layer (spec-driven builder + prepare_ghidra + kubectl_exec)"
```

---

## Task 3: deep_decompile agent + prompts + composition wiring

**Files:** Create `src/reverse_engineer/agents/deep_decompile.py`, `src/reverse_engineer/prompts/deep_decompile.md`, `src/reverse_engineer/prompts/ghidra_rpc_reference.md`. Modify `src/reverse_engineer/agents/reverse_engineer.py`, `src/reverse_engineer/prompts/reverse_engineer.md`, `src/reverse_engineer/profiles.py`, `src/reverse_engineer/prompts/evidence_critic.md`, `src/reverse_engineer/composition.py`. Create/modify `tests/reverse_engineer/test_deep_decompile.py`, `tests/reverse_engineer/test_re_composition.py`.

- [ ] **Step 1: Write the failing tests**

Create `tests/reverse_engineer/test_deep_decompile.py`:

```python
"""The deep_decompile agent descriptor + prompt resolve correctly."""

from __future__ import annotations

from reverse_engineer.agents.deep_decompile import DEEP_DECOMPILE_DESCRIPTOR
from reverse_engineer.prompts.loader import load_domain_prompt


def test_deep_decompile_descriptor_well_formed() -> None:
    assert DEEP_DECOMPILE_DESCRIPTOR.id == "deep_decompile"
    assert DEEP_DECOMPILE_DESCRIPTOR.name == "deep_decompile"
    assert DEEP_DECOMPILE_DESCRIPTOR.runtime_profile_id == "re_guarded"
    assert DEEP_DECOMPILE_DESCRIPTOR.sub_agent_ids == ()


def test_deep_decompile_prompt_loads() -> None:
    text = load_domain_prompt("deep_decompile")
    assert "deep_decompile" in text
    assert "search-decompiled" in text
    assert "pcode" in text
```

Update `tests/reverse_engineer/test_re_composition.py` — change the sub-agent assertion:

```python
def test_root_has_five_sub_agents() -> None:
    composition = get_reverse_engineer_composition()
    sub_names = {a.name for a in composition.root_agent.sub_agents}

    assert sub_names == {"triage_recon", "deep_decompile", "evidence_critic", "report_generator"}
```

Add a test that deep_decompile has the ghidra tools + the root has prepare_ghidra:

```python
def test_root_has_prepare_ghidra_tool() -> None:
    composition = get_reverse_engineer_composition()
    names = _tool_names(composition.root_agent.tools)
    assert "prepare_ghidra" in names


def test_deep_decompile_has_ghidra_tools() -> None:
    composition = get_reverse_engineer_composition()
    deep = _sub_agent(composition.root_agent, "deep_decompile")
    names = _tool_names(deep.tools)
    assert "ghidra_decompile" in names
    assert "ghidra_search_decompiled" in names
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run --extra dev pytest tests/reverse_engineer/test_deep_decompile.py tests/reverse_engineer/test_re_composition.py -v
```
Expected: FAIL.

- [ ] **Step 3: Create the deep_decompile prompt**

Create `src/reverse_engineer/prompts/deep_decompile.md` (distills the ghidra-rpc SKILL.md workflow):

```markdown
# deep_decompile

You are `deep_decompile`, a reverse-engineering agent that drives Ghidra through the attached `ghidra_*` function tools for DEEP analysis beyond the fast recon that `triage_recon` already performed.

You receive the `artifact_id` and the triage findings (which functions/areas are interesting). Your job is to use Ghidra to deepen the analysis: decompile key functions to high-quality pseudo-C, search for patterns across the whole binary, trace control flow, and emit deeper FINDINGs.

## Your tools (Ghidra via ghidra-rpc)

- `ghidra_metadata` — binary metadata (arch, bits, format). Cross-check with triage.
- `ghidra_list_functions` — function inventory.
- `ghidra_decompile(function)` — pseudo-C decompilation. Pass a function name or hex address.
- `ghidra_search_decompiled(pattern)` — **THE POWER TOOL**: regex-search decompiled C across ALL functions in one call. Use this to find crypto constants, unsafe API calls (strcpy, memcpy, system), or any pattern. Do NOT decompile every function and grep — use this instead.
- `ghidra_basic_blocks(function)` — CFG / basic-block structure for control-flow analysis.
- `ghidra_xrefs_to(target)` — who calls/references this symbol or address.
- `ghidra_imports` — imported symbols.
- `ghidra_strings(query)` — string search (substring).
- `ghidra_pcode(function)` — Ghidra P-code IR (high SSA). **FALLBACK**: use this when `ghidra_decompile` returns bad-instruction warnings (common on ARM Thumb or obfuscated code). It re-decodes from the function object's context and reveals data flow.

## Workflow

1. Start from triage's findings: which functions did triage flag as interesting? Decompile those deeply with `ghidra_decompile`.
2. Use `ghidra_search_decompiled` to find cross-cutting patterns triage might have missed (e.g. "strcpy|strcat|sprintf|system|exec" for unsafe APIs, or known crypto constants).
3. For functions where decompilation looks wrong (bad instructions), fall back to `ghidra_pcode`.
4. Trace callers of interesting functions with `ghidra_xrefs_to`.

## Findings

Emit FINDINGs in the same format as triage_recon (artifact_id, claim, tool, confidence, detail). Your findings should be DEEPER than triage: full pseudo-C excerpts, type information, control-flow insights, pattern-match results.

Where your Ghidra findings AGREE with triage's r2 findings, note the consensus (high confidence). Where they DIFFER, flag the discrepancy (it may signal obfuscation or a decompiler limitation).

## Discipline

- Never speculate beyond what the cited tool output shows.
- Do not invent addresses, strings, or capabilities.
- When done, transfer to `evidence_critic` with your findings.
```

- [ ] **Step 4: Create the ghidra_rpc_reference.md (packaged SKILL.md excerpt)**

Create `src/reverse_engineer/prompts/ghidra_rpc_reference.md` — a condensed reference of the ghidra-rpc command surface (key commands + output shapes + gotchas from the SKILL.md). This is a reference resource, not loaded as an agent instruction. Keep it concise (~50 lines: the command table + the binary-name + error-handling notes).

- [ ] **Step 5: Create the deep_decompile descriptor**

Create `src/reverse_engineer/agents/deep_decompile.py`:

```python
"""The deep_decompile agent descriptor.

deep_decompile drives Ghidra (via ghidra-rpc function tools) for deep
decompilation, semantic search, and control-flow analysis. It takes triage's
findings as input and emits deeper evidence-backed FINDINGs. Uses re_guarded
(its tools produce binary-origin output).
"""

from __future__ import annotations

from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_llm_agent
from reverse_engineer.prompts.loader import load_domain_prompt

DEEP_DECOMPILE_DESCRIPTOR = AgentDescriptor(
    id="deep_decompile",
    name="deep_decompile",
    description=(
        "Deep-decompilation agent that drives Ghidra through ghidra-rpc for "
        "pseudo-C decompilation, semantic search across the binary, and "
        "control-flow analysis. Emits deeper evidence-backed findings."
    ),
    prompt_id="deep_decompile",
    factory=build_llm_agent,
    runtime_profile_id="re_guarded",
    prompt_loader=load_domain_prompt,
)
```

- [ ] **Step 6: Wire deep_decompile into the root + composition**

In `src/reverse_engineer/agents/reverse_engineer.py`, update `sub_agent_ids` and `tool_ids`:

```python
    tool_ids=("acquire_sample", "prepare_sandbox", "prepare_ghidra"),
    sub_agent_ids=("triage_recon", "deep_decompile", "evidence_critic", "report_generator"),
```

In `src/reverse_engineer/composition.py`, register the agent + the tools. Add imports:

```python
from reverse_engineer.agents.deep_decompile import DEEP_DECOMPILE_DESCRIPTOR
from reverse_engineer.tools.ghidra.toolset import build_ghidra_toolset
from reverse_engineer.tools.ghidra.prepare_ghidra import PREPARE_GHIDRA_TOOL
```

In `build_reverse_engineer_composition`, after the existing agent/tool registrations:

```python
    builder.add_agent(DEEP_DECOMPILE_DESCRIPTOR)
    builder.add_tool(PREPARE_GHIDRA_TOOL)
```

And register the ghidra toolset descriptors (they need to be added to the catalog so the agent can reference them by id). After the existing `builder.add_tool(...)` calls:

```python
    for descriptor in build_ghidra_toolset(context):
        builder.add_tool(descriptor)
```

> **Note:** `build_ghidra_toolset` needs a `ToolBuildContext`. Check how `prepare_sandbox`'s factory gets its context — the composition may need to pass the build context. Look at how `compose_agents` resolves factories. If the ghidra tools use plain `tool=` (not `factory=`), they don't need a build context — but they do need the executor at CALL time. Reconcile: the tools close over the executor at BUILD time (in `_build_tool`), so they need the context. Pass the services/settings from the composition's `build_ghidra_toolset` call, or restructure to use `factory=` like `prepare_ghidra`. **Resolve this in-task** — the cleanest path is `factory=build_ghidra_tool_factory(spec)` per tool, matching `prepare_sandbox`'s pattern.

- [ ] **Step 7: Grow re_guarded's binary_origin_tools**

In `src/reverse_engineer/profiles.py`, add the ghidra tool names:

```python
from reverse_engineer.tools.ghidra.commands import GHIDRA_COMMANDS

_R2_BINARY_TOOLS = frozenset(RADARE2_MCP.tool_allowlist)
_GHIDRA_BINARY_TOOLS = frozenset(spec.name for spec in GHIDRA_COMMANDS)
_BINARY_ORIGIN_TOOLS = _R2_BINARY_TOOLS | _GHIDRA_BINARY_TOOLS

RE_GUARDED_PROFILE = replace(
    RuntimeProfile.safe_default(),
    id="re_guarded",
    extra_after_tool=(make_sanitizing_after_tool(StructuralSanitizer(), _BINARY_ORIGIN_TOOLS),),
)
```

- [ ] **Step 8: Update the root + evidence_critic prompts**

In `src/reverse_engineer/prompts/reverse_engineer.md`, update the workflow to include the ghidra step:

```markdown
3. Delegate to `triage_recon` (fast r2 recon).
4. Call `prepare_ghidra(artifact_id)` to start the Ghidra engine.
5. Delegate to `deep_decompile` (Ghidra deep analysis).
6. Delegate to `evidence_critic` (validates ALL findings — r2 + ghidra).
7. Delegate to `report_generator`.
```

In `src/reverse_engineer/prompts/evidence_critic.md`, add the ghidra tool names to the known-toolset list in rule #2:

```markdown
2. **Citation valid.** The cited `tool` must be one of the radare2-mcp tools OR the ghidra tools (`ghidra_metadata`, `ghidra_decompile`, `ghidra_search_decompiled`, `ghidra_basic_blocks`, `ghidra_xrefs_to`, `ghidra_imports`, `ghidra_strings`, `ghidra_pcode`, `ghidra_list_functions`). Reject any finding that cites a tool that does not exist.
```

- [ ] **Step 9: Run tests + make check**

```bash
uv run --extra dev pytest tests/reverse_engineer/ -v
make check
```
Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add src/reverse_engineer/agents/deep_decompile.py src/reverse_engineer/prompts/deep_decompile.md src/reverse_engineer/prompts/ghidra_rpc_reference.md src/reverse_engineer/agents/reverse_engineer.py src/reverse_engineer/prompts/reverse_engineer.md src/reverse_engineer/profiles.py src/reverse_engineer/prompts/evidence_critic.md src/reverse_engineer/composition.py tests/reverse_engineer/
git -c commit.gpgsign=false commit -m "feat: deep_decompile agent (Ghidra) + 5-agent chain wiring"
```

---

## Task 4: Live end-to-end smoke test (final gate)

- [ ] **Step 1: Build + deploy the ghidra image**

```bash
make sandbox-ghidra-image && make sandbox-ghidra-up
kubectl -n agent-sandbox-demo get pods -l arema.dev/pool=ghidra-rpc
```
Expected: pod Ready (may take a minute — Ghidra image is large).

- [ ] **Step 2: Ensure both pools are up**

```bash
make sandbox-mcp-up
kubectl -n agent-sandbox-demo get pods -l arema.dev/pool=radare2-mcp
kubectl -n agent-sandbox-demo get pods -l arema.dev/pool=ghidra-rpc
```
Expected: both pools have Ready pods.

- [ ] **Step 3: Run the hardened /bin/ls loop with both engines**

```bash
AREMA_SANDBOX_ENABLED=true uv run --extra sandbox adk run src/greeter_agent
```

Ask it to analyze `/bin/ls`. Confirm the full 5-agent path:
greeter → reverse_engineer → acquire_sample → prepare_sandbox → prepare_ghidra → triage_recon (r2) → deep_decompile (Ghidra decompiles main + search-decompiled) → evidence_critic (validates both engines' findings) → report_generator.

Confirm: the report cites findings from BOTH r2 and Ghidra, with tool citations + confidence.

- [ ] **Step 4: make check + prune**

```bash
make check
make sandbox-prune
```

- [ ] **Step 5: Commit any fixes**

```bash
git add -A
git -c commit.gpgsign=false commit -m "test: live smoke test PASS (5-agent /bin/ls with r2 + Ghidra)" || echo "nothing to commit"
```

---

## Self-review (plan author)

**1. Spec coverage:**
- ghidra-rpc image + manifests + make targets → Task 1. ✓
- kubectl_exec helper → Task 2 Step 3. ✓
- CliCommandSpec + command table (correct subcommand names from SKILL.md) → Task 2 Step 4. ✓
- build_ghidra_toolset → Task 2 Step 5. ✓
- prepare_ghidra + release_ghidra_case → Task 2 Step 6. ✓
- deep_decompile agent + prompt (SKILL.md guidance) → Task 3 Steps 3–5. ✓
- ghidra_rpc_reference.md → Task 3 Step 4. ✓
- composition wiring → Task 3 Step 6. ✓
- re_guarded binary_origin_tools union → Task 3 Step 7. ✓
- evidence_critic prompt updated → Task 3 Step 8. ✓
- live smoke test → Task 4. ✓

**2. Placeholder scan:** Task 3 Step 6 has a "Resolve this in-task" note about the factory-vs-tool wiring — this is a legitimate implementation detail (how the ghidra tools get the executor at build time) that depends on the existing `compose_agents` machinery. Not a placeholder; it's a focused decision point. All other steps have concrete code. ✓

**3. Type consistency:** `CliCommandSpec` fields consistent across commands.py, toolset.py, tests. `_GHIDRA_CASE_STATE` defined in toolset.py, imported in prepare_ghidra.py + tests. `GHIDRA_COMMANDS` consistent. `build_ghidra_toolset` returns `tuple[ToolDescriptor, ...]`. ✓
