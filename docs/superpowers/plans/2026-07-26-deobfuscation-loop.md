# Deobfuscation LoopAgent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a capped malware deobfuscation loop that uses real, pinned UPX and Mandiant FLOSS inside a Kubernetes-only stateless tool sandbox, then retriages recovered bytes before deep decompilation.

**Architecture:** A new hardened `deobfuscation-tools` image and warm pool host stateless file-in/result-out tools. Deferred-factory wrappers share one Kubernetes staging/runtime layer but retain tool-specific applicability and parsing. The malware pipeline inserts a `LoopAgent` after initial triage; a deterministic non-LLM gate evaluates typed session state and exits on clean input, no progress, p-code preference, or total recovery degradation.

**Tech Stack:** Python 3.11+, Google ADK 1.25.1 (`LoopAgent`, `SequentialAgent`, `BaseAgent`, `EventActions`), Kubernetes Agent Sandbox 0.5.2, Docker, UPX 5.2.0, `flare-floss` 3.1.1, pytest, Ruff, mypy.

---

## File map

### Create

- `images/deobfuscation-tools/Dockerfile` — multi-architecture image with pinned UPX and FLOSS.
- `images/deobfuscation-tools/.dockerignore` — minimal build context.
- `images/deobfuscation-tools/healthcheck.sh` — readiness/version check for installed tools.
- `deploy/sandbox/10-deobfuscation-tools-template.yaml` — hardened command-driven sandbox.
- `deploy/sandbox/20-deobfuscation-tools-pool.yaml` — one-replica development warm pool.
- `src/reverse_engineering/tools/deobfuscation/__init__.py` — public curated tool exports.
- `src/reverse_engineering/tools/deobfuscation/state.py` — domain session-state keys and classification parsing.
- `src/reverse_engineering/tools/deobfuscation/runtime.py` — Kubernetes-only claim/stage/run/read boundary.
- `src/reverse_engineering/tools/deobfuscation/toolset.py` — explicit descriptor collection.
- `src/reverse_engineering/tools/deobfuscation/upx.py` — UPX applicability, recovery, and artifact admission.
- `src/reverse_engineering/tools/deobfuscation/floss.py` — PE gate and FLOSS v3.1.1 JSON parsing.
- `src/reverse_engineering/agents/deobfuscation.py` — capped LoopAgent descriptor.
- `src/reverse_engineering/agents/recover.py` — UPX→FLOSS SequentialAgent descriptor.
- `src/reverse_engineering/agents/deobf_classify.py` — classifier descriptor.
- `src/reverse_engineering/agents/upx_unpack.py` — UPX recovery descriptor.
- `src/reverse_engineering/agents/floss_decode.py` — FLOSS recovery descriptor.
- `src/reverse_engineering/agents/retriage.py` — radare2 retriage descriptor.
- `src/reverse_engineering/agents/deobf_gate.py` — deterministic deobfuscation evaluator and gate descriptor.
- `src/reverse_engineering/prompts/deobf_classify.md` — strict classification JSON contract.
- `src/reverse_engineering/prompts/upx_unpack.md` — always-call/skip-aware UPX workflow.
- `src/reverse_engineering/prompts/floss_decode.md` — always-call/skip-aware FLOSS workflow.
- `src/reverse_engineering/prompts/retriage.md` — restage, reopen, analyze, and snapshot workflow.
- `tests/reverse_engineering/test_deobfuscation_runtime.py` — shared runtime tests.
- `tests/reverse_engineering/test_upx_deobfuscation_tool.py` — UPX wrapper tests.
- `tests/reverse_engineering/test_floss_deobfuscation_tool.py` — FLOSS wrapper tests.
- `tests/reverse_engineering/test_deobfuscation_agents.py` — descriptors, gate, prompts, and nested graph tests.
- `tests/unit/test_deobfuscation_tools_manifest.py` — image/manifest structural tests.

### Modify

- `src/reverse_engineering/artifacts/store.py` — add byte admission.
- `tests/reverse_engineering/test_artifact_store.py` — cover byte admission/idempotence.
- `src/arema/runtime/agent_factory.py` — add generic evaluator-backed escalation gate.
- `tests/unit/runtime/test_agent_factory.py` — verify escalation events and state deltas.
- `src/reverse_engineering/composition.py` — register curated deobfuscation tools.
- `src/reverse_engineering/__init__.py` — export reusable deobfuscation descriptors.
- `src/reverse_engineering/profiles.py` — sanitize UPX/FLOSS binary-origin output.
- `tests/reverse_engineering/test_re_guarded_profile.py` — assert both tool names are guarded.
- `src/malware_analyst/agents/malware_analyst.py` — insert deobfuscation after triage.
- `src/malware_analyst/composition.py` — register loop/recovery child descriptors.
- `tests/malware_analyst/test_malware_analyst_composition.py` — assert nine-stage nested graph.
- `src/reverse_engineering/prompts/deep_decompile.md` — honor `pcode_preferred`.
- `src/reverse_engineering/prompts/evidence_critic.md` — accept recovery provenance.
- `Makefile` — build/up/down targets and aggregate wiring.
- `.env.example` — document Kubernetes backend and pool mapping.
- `docs/CREATING_TOOLS.md` — document the stateless sandbox-CLI extension pattern.

## Session-state contract

All keys below are ordinary shared session keys, not `_runtime:` core keys:

```python
CLASSIFICATION_KEY = "deobf:classification"
CURRENT_ARTIFACT_KEY = "deobf:current_artifact_id"
CURRENT_ARTIFACT_PROMPT_KEY = "deobf_current_artifact_id"
DEOBF_BASELINE_PROMPT_KEY = "deobf_previous_snapshot_json"
PCODE_PREFERRED_PROMPT_KEY = "deobf_pcode_preferred"
UPX_PROVENANCE_PROMPT_KEY = "deobf_upx_provenance"
UPX_CHANGED_KEY = "deobf:upx_changed"
UPX_DEGRADED_KEY = "deobf:upx_degraded"
UPX_CALLED_KEY = "deobf:upx_called"
UPX_RESULT_KEY = "deobf:upx_result"
FLOSS_COUNT_KEY = "deobf:floss_count"
FLOSS_DEGRADED_KEY = "deobf:floss_degraded"
FLOSS_CALLED_KEY = "deobf:floss_called"
FLOSS_RESULT_KEY = "deobf:floss_result"
RETRIAGE_SNAPSHOT_KEY = "deobf:retriage_snapshot"
PREVIOUS_SNAPSHOT_KEY = "deobf:previous_snapshot"
GATE_ERROR_KEY = "deobf:gate_error"
```

`deobf_classify` and `retriage` use ADK `output_key` to store JSON-only model responses.
Both recovery agents always call their single function tool. Each wrapper parses
`CLASSIFICATION_KEY`; when its plan flag is false it resets its per-iteration state and
returns `applicable=false` without executing a sandbox command. This avoids stale state
across loop iterations while retaining the user-approved skip behavior. Call markers enforce
one execution per recovery child and result keys cache the first structured result; the gate
resets the markers after valid evaluation while preserving harmless caches. A successful new
`acquire_sample` clears classification, aliases, baselines, snapshots, gate facts, markers,
and caches before setting `CURRENT_ARTIFACT_KEY` to the new artifact id, preventing
cross-analysis authority leakage. Identifier-safe aliases are used for prompt injection; the
optional current-artifact alias permits retriage to emit a zero sentinel snapshot rather than
calling tools when no authority exists. The gate emits the normalized p-code preference alias,
and UPX emits bounded source/destination provenance only after an actual artifact change.
Every recovery/gate consumer requires the strict classification artifact id to equal the
valid canonical current id. On admitted UPX recovery, both authorities advance together;
missing, malformed, or mismatched authority fails closed without rewinding current state.
Provenance survives no-op iterations only when its destination is still canonical.
`prepare_ghidra` treats canonical current-artifact state as authoritative over its model
argument, validates it before sandbox side effects, and returns the resolved artifact id.
Because ADK state has no deletion operation, reset
uses neutral values (`None`, empty aliases, false markers, and zero counts); the gate treats
`PREVIOUS_SNAPSHOT_KEY=None` as no previous snapshot while rejecting other malformed values.

---

### Task 1: Admit sandbox-recovered bytes into ArtifactStore

**Files:**
- Modify: `src/reverse_engineering/artifacts/store.py`
- Modify: `tests/reverse_engineering/test_artifact_store.py`

- [ ] **Step 1: Write failing byte-admission tests**

Append:

```python
def test_acquire_bytes_content_addresses_and_persists(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "store")
    payload = b"recovered-from-sandbox"

    artifact_id = store.acquire_bytes(payload)

    assert artifact_id == hashlib.sha256(payload).hexdigest()
    assert store.path_for(artifact_id).read_bytes() == payload


def test_acquire_bytes_is_idempotent(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "store")
    payload = b"same-recovery"

    first = store.acquire_bytes(payload)
    original_mtime = store.path_for(first).stat().st_mtime_ns
    second = store.acquire_bytes(payload)

    assert first == second
    assert store.path_for(second).stat().st_mtime_ns == original_mtime
```

- [ ] **Step 2: Run the focused tests and verify RED**

Run:

```bash
uv run --extra dev pytest \
  tests/reverse_engineering/test_artifact_store.py::test_acquire_bytes_content_addresses_and_persists \
  tests/reverse_engineering/test_artifact_store.py::test_acquire_bytes_is_idempotent -v
```

Expected: both fail with `AttributeError: 'ArtifactStore' object has no attribute 'acquire_bytes'`.

- [ ] **Step 3: Implement byte admission**

Add to `ArtifactStore`:

```python
def acquire_bytes(self, data: bytes) -> str:
    """Store immutable bytes under their SHA-256 digest and return the digest."""
    sha256 = hashlib.sha256(data).hexdigest()
    self.root.mkdir(parents=True, exist_ok=True)
    dest = self.root / sha256
    if not dest.exists():
        dest.write_bytes(data)
    return sha256
```

- [ ] **Step 4: Run the artifact-store suite**

Run: `uv run --extra dev pytest tests/reverse_engineering/test_artifact_store.py -v`

Expected: all artifact-store tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/reverse_engineering/artifacts/store.py tests/reverse_engineering/test_artifact_store.py
git -c commit.gpgsign=false commit -m "feat: admit recovered artifact bytes"
```

---

### Task 2: Build the pinned deobfuscation image and Kubernetes pool

**Files:**
- Create: `images/deobfuscation-tools/Dockerfile`
- Create: `images/deobfuscation-tools/.dockerignore`
- Create: `images/deobfuscation-tools/healthcheck.sh`
- Create: `deploy/sandbox/10-deobfuscation-tools-template.yaml`
- Create: `deploy/sandbox/20-deobfuscation-tools-pool.yaml`
- Create: `tests/unit/test_deobfuscation_tools_manifest.py`
- Modify: `Makefile`
- Modify: `.env.example`

- [ ] **Step 1: Write failing structural tests**

Create `tests/unit/test_deobfuscation_tools_manifest.py` with tests that load both YAML
documents and inspect the Dockerfile:

```python
from pathlib import Path

import yaml

DOCKERFILE = Path("images/deobfuscation-tools/Dockerfile")
TEMPLATE = Path("deploy/sandbox/10-deobfuscation-tools-template.yaml")
POOL = Path("deploy/sandbox/20-deobfuscation-tools-pool.yaml")


def _docs() -> tuple[dict, dict]:
    return yaml.safe_load(TEMPLATE.read_text()), yaml.safe_load(POOL.read_text())


def test_image_pins_real_upstream_tools_and_both_architectures() -> None:
    text = DOCKERFILE.read_text()
    assert "flare-floss==3.1.1" in text
    assert "UPX_VERSION=5.2.0" in text
    assert "3db5d3294707439db97866feab8d75d800f028f48481a40547411824da4288a1" in text
    assert "55d48a61e8ffd17152db871c855376cba7f08e830b37799d0947a16dff8ec36c" in text
    assert "TARGETARCH" in text


def test_template_is_hardened_exec_driven_and_bounded() -> None:
    template, pool = _docs()
    pod = template["spec"]["podTemplate"]["spec"]
    container = pod["containers"][0]
    assert container["image"] == "arema-deobfuscation-tools:0.1.0"
    assert pod["automountServiceAccountToken"] is False
    assert pod["securityContext"]["runAsNonRoot"] is True
    assert container["securityContext"]["runAsUser"] == 1000
    assert container["securityContext"]["allowPrivilegeEscalation"] is False
    assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]
    assert "exec" in container["readinessProbe"]
    assert "ports" not in container
    assert container["resources"]["requests"] == {"cpu": "500m", "memory": "1Gi"}
    assert container["resources"]["limits"] == {"cpu": "2", "memory": "4Gi"}
    assert pool["spec"]["replicas"] == 1
    assert pool["spec"]["sandboxTemplateRef"]["name"] == template["metadata"]["name"]
```

- [ ] **Step 2: Verify the tests fail because files do not exist**

Run: `uv run --extra dev pytest tests/unit/test_deobfuscation_tools_manifest.py -v`

Expected: collection succeeds and tests fail with `FileNotFoundError`.

- [ ] **Step 3: Add the image**

Use this Dockerfile shape:

```dockerfile
FROM python:3.11-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive
ARG TARGETARCH
ARG UPX_VERSION=5.2.0
ARG UPX_AMD64_SHA256=3db5d3294707439db97866feab8d75d800f028f48481a40547411824da4288a1
ARG UPX_ARM64_SHA256=55d48a61e8ffd17152db871c855376cba7f08e830b37799d0947a16dff8ec36c

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN case "${TARGETARCH}" in \
      amd64) upx_arch=amd64; upx_sha="${UPX_AMD64_SHA256}" ;; \
      arm64) upx_arch=arm64; upx_sha="${UPX_ARM64_SHA256}" ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac \
    && archive="upx-${UPX_VERSION}-${upx_arch}_linux.tar.xz" \
    && curl -fsSL "https://github.com/upx/upx/releases/download/v${UPX_VERSION}/${archive}" -o "/tmp/${archive}" \
    && echo "${upx_sha}  /tmp/${archive}" | sha256sum -c - \
    && tar -xJf "/tmp/${archive}" -C /tmp \
    && install -m 0755 "/tmp/upx-${UPX_VERSION}-${upx_arch}_linux/upx" /usr/local/bin/upx \
    && rm -rf "/tmp/${archive}" "/tmp/upx-${UPX_VERSION}-${upx_arch}_linux"

RUN pip install --no-cache-dir "flare-floss==3.1.1" \
    && upx --version \
    && floss --version

COPY --chmod=0755 healthcheck.sh /usr/local/bin/deobfuscation-tools-healthcheck

RUN groupadd -r -g 1000 deobf \
    && useradd -r -u 1000 -g 1000 -m -d /home/deobf deobf \
    && mkdir -p /work \
    && chown -R 1000:1000 /work /home/deobf

USER 1000
ENV HOME=/home/deobf
WORKDIR /work
CMD ["sleep", "infinity"]
```

`healthcheck.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
upx --version >/dev/null
floss --version >/dev/null
```

`.dockerignore`:

```text
*
!Dockerfile
!healthcheck.sh
```

- [ ] **Step 4: Add the hardened template and pool**

The template must use `SandboxTemplate` `v1beta1`, image
`arema-deobfuscation-tools:0.1.0`, exec readiness command
`["deobfuscation-tools-healthcheck"]`, the security settings asserted above, and no ports.
The pool must reference `deobfuscation-tools-runtime-template` with one replica.

- [ ] **Step 5: Add Make/config wiring**

Add `sandbox-deobfuscation-image`, `sandbox-deobfuscation-up`, and
`sandbox-deobfuscation-down`; include them in `sandbox-images`, `sandbox-up`, and
`sandbox-down`. Extend the documented pool map:

```text
AREMA_SANDBOX_BACKEND=k8s
AREMA_SANDBOX_POOL_MAP={"radare2-mcp":"radare2-mcp-pool","ghidra-rpc":"ghidra-rpc-pool","deobfuscation-tools":"deobfuscation-tools-pool"}
```

- [ ] **Step 6: Run structural verification**

Run:

```bash
uv run --extra dev pytest tests/unit/test_deobfuscation_tools_manifest.py -v
make -n sandbox-deobfuscation-image
make -n sandbox-deobfuscation-up
```

Expected: manifest tests pass; dry-run output contains the correct Docker build, kind load,
two `kubectl apply` commands, and readiness wait.

- [ ] **Step 7: Build and smoke the real image**

Run:

```bash
docker build -t arema-deobfuscation-tools:0.1.0 images/deobfuscation-tools
docker run --rm arema-deobfuscation-tools:0.1.0 upx --version
docker run --rm arema-deobfuscation-tools:0.1.0 floss --version
```

Expected: UPX reports `5.2.0`; FLOSS reports `3.1.1`.

- [ ] **Step 8: Commit**

```bash
git add images/deobfuscation-tools deploy/sandbox/10-deobfuscation-tools-template.yaml \
  deploy/sandbox/20-deobfuscation-tools-pool.yaml tests/unit/test_deobfuscation_tools_manifest.py \
  Makefile .env.example
git -c commit.gpgsign=false commit -m "feat: add deobfuscation tools sandbox"
```

---

### Task 3: Add the reusable Kubernetes-only stateless runtime

**Files:**
- Create: `src/reverse_engineering/tools/deobfuscation/state.py`
- Create: `src/reverse_engineering/tools/deobfuscation/runtime.py`
- Create: `tests/reverse_engineering/test_deobfuscation_runtime.py`

- [ ] **Step 1: Write fake-executor runtime tests**

Write these six concrete tests using `tmp_path`, a `_FakeExecutor`, a `ToolBuildContext`
whose unused catalog field is `cast("CapabilityCatalog", object())`, and a
`_FakeToolContext` whose state exposes duck-typed `get`/`__setitem__`:

- `test_stage_requires_explicit_k8s_backend`
- `test_stage_rejects_non_sha256_artifact_id`
- `test_stage_claims_case_scoped_pool_and_writes_fixed_path`
- `test_repeated_stage_reuses_same_case_pool_identity`
- `test_run_uses_configured_timeout_and_tokenized_command`
- `test_remote_size_rejects_over_limit_before_read`

The fake executor must implement all six `SandboxExecutor` methods and record `claim`,
`write_file`, `run`, and `read_file`. Assert a local backend returns
`DeobfuscationUnavailable("deobfuscation tools require sandbox_backend='k8s'")` before any
fake call is recorded.

- [ ] **Step 2: Run the tests and verify import failure**

Run: `uv run --extra dev pytest tests/reverse_engineering/test_deobfuscation_runtime.py -v`

Expected: FAIL because `reverse_engineering.tools.deobfuscation.runtime` does not exist.

- [ ] **Step 3: Add state constants and strict classification parser**

`state.py` must define the keys from the session-state contract and:

```python
@dataclass(frozen=True, slots=True)
class DeobfPlan:
    artifact_id: str
    upx: bool
    floss: bool
    pcode_preferred: bool
    obf_class: str
    pre_snapshot: dict[str, int]


def parse_classification(state: object) -> DeobfPlan:
    getter = getattr(state, "get", None)
    raw = getter(CLASSIFICATION_KEY) if callable(getter) else None
    data = json.loads(raw) if isinstance(raw, str) else raw
    if not isinstance(data, dict):
        raise ValueError("missing deobfuscation classification")
    plan = data.get("deobf_plan")
    if not isinstance(plan, dict):
        raise ValueError("classification.deobf_plan must be an object")
    return DeobfPlan(
        artifact_id=str(data["artifact_id"]),
        upx=plan.get("upx") is True,
        floss=plan.get("floss") is True,
        pcode_preferred=data.get("pcode_preferred") is True,
        obf_class=str(data.get("obf_class", "unknown")),
        pre_snapshot={str(k): int(v) for k, v in dict(data.get("pre_snapshot", {})).items()},
    )
```

- [ ] **Step 4: Implement the runtime boundary**

`runtime.py` must expose:

```python
POOL = "deobfuscation-tools"
MAX_RECOVERED_BYTES = 512 * 1024 * 1024
MAX_RESULT_BYTES = 32 * 1024 * 1024


class DeobfuscationUnavailable(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class StagedArtifact:
    executor: SandboxExecutor
    handle: SandboxHandle
    artifact_id: str
    input_path: str
    work_dir: str
    timeout: float


def stage_artifact(
    context: ToolBuildContext, artifact_id: str, tool_context: ToolContext, *, tool_name: str
) -> StagedArtifact:
    if context.settings.sandbox_backend != "k8s":
        raise DeobfuscationUnavailable(
            "deobfuscation tools require sandbox_backend='k8s'"
        )
    executor = context.services.sandbox
    if executor is None:
        raise DeobfuscationUnavailable("sandbox executor is not configured")
    if re.fullmatch(r"[0-9a-f]{64}", artifact_id) is None:
        raise ValueError("artifact_id must be a lowercase SHA-256")
    source = ArtifactStore(default_artifacts_root()).path_for(artifact_id)
    data = source.read_bytes()
    case_id = _resolve_case_id(tool_context)
    handle = executor.claim(key=case_id, pool=POOL)
    work_dir = f"/work/{tool_name}/{artifact_id}"
    input_path = f"{work_dir}/input"
    executor.run(handle, shlex.join(["mkdir", "-p", work_dir]), timeout=30)
    executor.write_file(handle, input_path, data)
    return StagedArtifact(
        executor=executor,
        handle=handle,
        artifact_id=artifact_id,
        input_path=input_path,
        work_dir=work_dir,
        timeout=float(context.settings.sandbox_run_timeout),
    )
```

Also implement `run_argv(staged, argv)`, `run_argv_to_file(staged, argv, output_path)`,
`remote_file_size(staged, path)`, and `read_bounded_file(staged, path, max_bytes)`.
Use `shlex.join`; only developer-specified flags and validated fixed paths may enter commands.
`read_bounded_file` must call `remote_file_size` before `executor.read_file`.

Resolve the case id without assuming ADK state is a `dict`:

```python
def _resolve_case_id(tool_context: object) -> str:
    state = getattr(tool_context, "state", None)
    getter = getattr(state, "get", None)
    if callable(getter):
        return str(getter(SessionKeys.SANDBOX_CASE_ID, "re-mvp"))
    return "re-mvp"
```

- [ ] **Step 5: Run and refine the runtime tests**

Run: `uv run --extra dev pytest tests/reverse_engineering/test_deobfuscation_runtime.py -v`

Expected: all tests pass and the local-backend test records zero executor calls.

- [ ] **Step 6: Commit**

```bash
git add src/reverse_engineering/tools/deobfuscation/state.py \
  src/reverse_engineering/tools/deobfuscation/runtime.py \
  tests/reverse_engineering/test_deobfuscation_runtime.py
git -c commit.gpgsign=false commit -m "feat: add stateless deobfuscation runtime"
```

---

### Task 4: Add the UPX recovery function tool

**Files:**
- Create: `src/reverse_engineering/tools/deobfuscation/upx.py`
- Create: `tests/reverse_engineering/test_upx_deobfuscation_tool.py`

- [ ] **Step 1: Write UPX contract tests**

Use a fake runtime/executor and temporary artifact root to write:

- `test_upx_skips_and_resets_state_when_plan_disabled`
- `test_upx_not_packed_is_successful_non_applicability`
- `test_upx_recovery_admits_new_content_hash_and_updates_state`
- `test_upx_rejects_output_over_512_mib_before_read`
- `test_upx_timeout_and_corrupt_input_degrade_without_raising`
- `test_upx_factory_callable_name_matches_descriptor`

For recovery, return `b"unpacked"` from `read_file` and assert:

```python
assert result["source_artifact_id"] == source_artifact_id
assert result["source_size"] == source_size
assert result["recovered_artifact_id"] == hashlib.sha256(b"unpacked").hexdigest()
assert result["recovered_size"] == len(b"unpacked")
assert tool_context.state[CURRENT_ARTIFACT_KEY] == result["recovered_artifact_id"]
assert tool_context.state[UPX_CHANGED_KEY] is True
assert result["tool_version"] == "5.2.0"
```

- [ ] **Step 2: Run and verify RED**

Run: `uv run --extra dev pytest tests/reverse_engineering/test_upx_deobfuscation_tool.py -v`

Expected: import failure for `deobfuscation.upx`.

- [ ] **Step 3: Implement `build_upx_unpack` and descriptor**

The deferred callable must:

1. Strictly parse `CLASSIFICATION_KEY` and require its artifact id to equal the valid
   canonical `CURRENT_ARTIFACT_KEY`.
2. Reset `UPX_CHANGED_KEY=False`, `UPX_DEGRADED_KEY=False`.
   Do not derive or rewrite canonical authority from model classification.
3. Return `{success: true, applicable: false, reason: "plan_disabled",
   source_artifact_id: plan.artifact_id}` without staging when `plan.upx` is false.
4. Preflight a fixed `MAX_UPX_INPUT_BYTES = 512 MiB` cap before pod claim/write, then stage
   `plan.artifact_id` with that cap; execute
   `["upx", "-d", "-o", output_path, staged.input_path]`.
5. Treat stderr containing `notpackedexception` or `not packed by upx` as expected
   non-applicability.
6. On exit 0, call
   `read_bounded_file(staged, output_path, max_bytes=MAX_RECOVERED_BYTES)`, then
   `ArtifactStore.acquire_bytes`.
7. Only after recovered bytes are successfully admitted and the digest actually changes,
   atomically advance the custody transition: `CURRENT_ARTIFACT_KEY`, the strict
   classification document's `artifact_id`, `CURRENT_ARTIFACT_PROMPT_KEY`, and bounded
   destination-bound `UPX_PROVENANCE_PROMPT_KEY`. Model output never advances custody.
   Set `UPX_CHANGED_KEY` and `UPX_DEGRADED_KEY` consistently with the result.
8. Return locked responses with canonical `source_artifact_id`, `source_size` whenever
   known, and `recovered_size` whenever recovered bytes were bounded/read. Catch operational
   exceptions and return a stable public error code/message without backend diagnostics.

Descriptor:

```python
UPX_UNPACK_TOOL = ToolDescriptor(
    id="upx_unpack",
    description="Unpack a UPX-packed artifact inside the Kubernetes deobfuscation sandbox.",
    factory=build_upx_unpack,
    output_policy=OutputPolicy(max_chars=4_000, max_list_items=20),
)
```

- [ ] **Step 4: Run UPX and runtime tests**

Run:

```bash
uv run --extra dev pytest \
  tests/reverse_engineering/test_upx_deobfuscation_tool.py \
  tests/reverse_engineering/test_deobfuscation_runtime.py -v
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/reverse_engineering/tools/deobfuscation/upx.py \
  tests/reverse_engineering/test_upx_deobfuscation_tool.py
git -c commit.gpgsign=false commit -m "feat: add sandboxed UPX recovery tool"
```

---

### Task 5: Add the FLOSS structured recovery tool and curated toolset

**Files:**
- Create: `src/reverse_engineering/tools/deobfuscation/floss.py`
- Create: `src/reverse_engineering/tools/deobfuscation/toolset.py`
- Create: `src/reverse_engineering/tools/deobfuscation/__init__.py`
- Create: `tests/reverse_engineering/test_floss_deobfuscation_tool.py`
- Modify: `src/reverse_engineering/profiles.py`
- Modify: `tests/reverse_engineering/test_re_guarded_profile.py`

- [ ] **Step 1: Add a realistic FLOSS v3.1.1 JSON fixture in the test module**

Use:

```python
FLOSS_RESULT = {
    "metadata": {"file_path": "/work/input", "version": "3.1.1", "imagebase": 4194304},
    "analysis": {},
    "strings": {
        "decoded_strings": [{
            "address": 6295552,
            "address_type": "GLOBAL",
            "string": "https://c2.example",
            "encoding": "ASCII",
            "decoded_at": 4198964,
            "decoding_routine": 4198400,
        }],
        "stack_strings": [{
            "function": 4199000,
            "string": "cmd.exe /c whoami",
            "encoding": "ASCII",
            "program_counter": 4199050,
            "stack_pointer": 1048576,
            "original_stack_pointer": 1048704,
            "offset": 16,
            "frame_offset": 112,
        }],
        "tight_strings": [],
        "static_strings": [],
        "language_strings": [],
        "language_strings_missed": [],
    },
}
```

- [ ] **Step 2: Write failing FLOSS tests**

Cover PE signature validation (DOS `MZ`, `e_lfanew`, `PE\0\0`), non-PE non-applicability,
the 16 MiB input guard, JSON schema rejection, decoded/stack/tight normalization, the
200-record cap, 32 MiB result-file rejection before read, timeout degradation, state reset,
and descriptor output policy.

- [ ] **Step 3: Run and verify RED**

Run: `uv run --extra dev pytest tests/reverse_engineering/test_floss_deobfuscation_tool.py -v`

Expected: import failure for `deobfuscation.floss`.

- [ ] **Step 4: Implement PE detection and record normalization**

Implement `_is_pe(path: Path)` by reading the DOS header, little-endian `e_lfanew` at
offset `0x3C`, then checking the PE signature. Do not execute `file` on the host.

Normalize records to:

```python
{
    "type": "decoded",
    "string": "https://c2.example",
    "encoding": "ASCII",
    "function": "0x401000",
    "location": "0x401234",
}
```

For decoded strings, `function=decoding_routine`, `location=decoded_at`; for stack/tight,
`function=function`, `location=program_counter`. Preserve `counts` for all records even when
only the first 200 are returned.

- [ ] **Step 5: Implement `build_floss_decode` and descriptor**

The deferred callable must parse the strict classification and require its `artifact_id` to
equal a valid canonical `CURRENT_ARTIFACT_KEY`. Missing, malformed, or mismatched authority
is an invalid/degraded classification and must not stage anything. Reset FLOSS state, skip
if the plan flag is false, reject non-PE and inputs over 16 MiB as `applicable=false`, stage
exactly that validated artifact, and execute:

```python
["floss", "--json", "--only", "decoded", "stack", "tight", "--", staged.input_path]
```

through `run_argv_to_file`. Read at most 32 MiB, parse JSON, normalize/cap records, set
`FLOSS_DEGRADED_KEY`, and return the locked
`format`/`records`/`counts`/`new_count`/version/truncation schema with canonical source id.
Fingerprint the exact normalized record fields into bounded trusted session state;
`FLOSS_COUNT_KEY` is only the number of newly observed fingerprints this invocation, and
malformed/overflowing seen state degrades fail-closed.

Descriptor:

```python
FLOSS_DECODE_TOOL = ToolDescriptor(
    id="floss_decode",
    description="Recover PE decoded, stack, and tight strings with Mandiant FLOSS.",
    factory=build_floss_decode,
    output_policy=OutputPolicy(max_chars=50_000, max_list_items=200),
)
```

- [ ] **Step 6: Add the explicit toolset and sanitizer registration**

`toolset.py`:

```python
DEOBFUSCATION_TOOLSET = (UPX_UNPACK_TOOL, FLOSS_DECODE_TOOL)
DEOBFUSCATION_TOOL_NAMES = frozenset(tool.id for tool in DEOBFUSCATION_TOOLSET)
```

Union `DEOBFUSCATION_TOOL_NAMES` into `_BINARY_ORIGIN_TOOLS`. Extend the profile test to
invoke the sanitizer callback with `upx_unpack` and `floss_decode` fake tools and assert
binary-origin framing/redaction occurs.

- [ ] **Step 7: Run focused tests**

Run:

```bash
uv run --extra dev pytest \
  tests/reverse_engineering/test_floss_deobfuscation_tool.py \
  tests/reverse_engineering/test_upx_deobfuscation_tool.py \
  tests/reverse_engineering/test_re_guarded_profile.py -v
```

Expected: all tests pass.

- [ ] **Step 8: Commit**

```bash
git add src/reverse_engineering/tools/deobfuscation \
  src/reverse_engineering/profiles.py \
  tests/reverse_engineering/test_floss_deobfuscation_tool.py \
  tests/reverse_engineering/test_re_guarded_profile.py
git -c commit.gpgsign=false commit -m "feat: add structured FLOSS recovery tool"
```

---

### Task 6: Add the generic deterministic escalation gate

**Files:**
- Modify: `src/arema/runtime/agent_factory.py`
- Modify: `tests/unit/runtime/test_agent_factory.py`
- Create: `src/reverse_engineering/agents/deobf_gate.py`
- Create: `tests/reverse_engineering/test_deobfuscation_agents.py`

- [ ] **Step 1: Write failing neutral gate-factory tests**

Add tests using
`SimpleNamespace(session=SimpleNamespace(state={"ready": True}), invocation_id="inv-1")`
as the invocation context. Verify exactly one event, the descriptor name as author, evaluator-provided
`state_delta`, and both `escalate=True` and `False`.

```python
def _decision(_state: Mapping[str, object]) -> EscalationDecision:
    return EscalationDecision(escalate=True, state_delta={"seen": True})


agent = build_escalation_gate(_ctx(name="gate"), evaluator=_decision)
events = [event async for event in agent._run_async_impl(fake_ctx)]
assert events[0].actions.escalate is True
assert events[0].actions.state_delta == {"seen": True}
```

- [ ] **Step 2: Run the neutral tests and verify RED**

Run:

```bash
uv run --extra dev pytest tests/unit/runtime/test_agent_factory.py -k escalation -v
```

Expected: import failure for `EscalationDecision`/`build_escalation_gate`.

- [ ] **Step 3: Implement the evaluator-backed neutral gate**

Add:

```python
@dataclass(frozen=True, slots=True)
class EscalationDecision:
    escalate: bool
    state_delta: Mapping[str, object] = field(default_factory=dict)


EscalationEvaluator = Callable[[Mapping[str, object]], EscalationDecision]


class _EscalationGate(BaseAgent):
    evaluator: EscalationEvaluator

    async def _run_async_impl(self, ctx: InvocationContext) -> AsyncGenerator[Event, None]:
        decision = self.evaluator(ctx.session.state)
        yield Event(
            author=self.name,
            invocation_id=ctx.invocation_id,
            actions=EventActions(
                escalate=decision.escalate,
                state_delta=dict(decision.state_delta),
            ),
        )


def build_escalation_gate(
    context: AgentBuildContext, *, evaluator: EscalationEvaluator
) -> BaseAgent:
    return _EscalationGate(
        name=context.descriptor.name,
        description=context.descriptor.description,
        evaluator=evaluator,
        after_agent_callback=list(context.after_agent),
    )
```

Export both public names from `__all__`. Keep the core generic: it knows no deobfuscation
keys or rules.

- [ ] **Step 4: Write the four domain evaluator tests**

In `test_deobfuscation_agents.py`, directly test `evaluate_deobf_gate` for:

1. both plan flags false;
2. `pcode_preferred=true`;
3. every enabled recovery tool degraded;
4. no new artifact, zero FLOSS records, and no retriage metric growth;
5. progress present, which returns `escalate=false`.

Each result must carry `PREVIOUS_SNAPSHOT_KEY` in its state delta when a valid current
snapshot exists.

- [ ] **Step 5: Implement the domain evaluator and descriptor**

First parse classification shape and canonical-artifact equality as one trust boundary.
Compare these integer snapshot fields:
`size`, `function_count`, `import_count`, `string_count`, `section_count`. Baseline is
`PREVIOUS_SNAPSHOT_KEY` when present, otherwise classification `pre_snapshot`.

```python
def evaluate_deobf_gate(state: Mapping[str, object]) -> EscalationDecision:
    try:
        plan = parse_current_classification(state)
    except ValueError:
        return EscalationDecision(
            escalate=True,
            state_delta={
                GATE_ERROR_KEY: "invalid_state",
                PCODE_PREFERRED_PROMPT_KEY: "",
            },
        )

    pcode_alias = "true" if plan.pcode_preferred else "false"
    try:
        if not _recovery_called(state):
            return EscalationDecision(
                escalate=True,
                state_delta={
                    GATE_ERROR_KEY: "recovery_not_called",
                    PCODE_PREFERRED_PROMPT_KEY: pcode_alias,
                },
            )
        current = _parse_snapshot(state.get(RETRIAGE_SNAPSHOT_KEY))
        raw_previous = state.get(PREVIOUS_SNAPSHOT_KEY)
        previous = None if raw_previous is None else _parse_snapshot(raw_previous)
        upx_changed = _state_bool(state, UPX_CHANGED_KEY)
        upx_degraded = _state_bool(state, UPX_DEGRADED_KEY)
        floss_degraded = _state_bool(state, FLOSS_DEGRADED_KEY)
        floss_count = _floss_count(state)
    except ValueError:
        return EscalationDecision(
            escalate=True,
            state_delta={
                GATE_ERROR_KEY: "invalid_state",
                PCODE_PREFERRED_PROMPT_KEY: pcode_alias,
            },
        )

    baseline = previous or plan.pre_snapshot
    grew = any(current.get(key, 0) > baseline.get(key, 0) for key in SNAPSHOT_FIELDS)
    enabled_degraded = (
        (not plan.upx or upx_degraded)
        and (not plan.floss or floss_degraded)
        and (plan.upx or plan.floss)
    )
    no_progress = (
        not upx_changed
        and floss_count == 0
        and not grew
    )
    exit_loop = (
        (not plan.upx and not plan.floss)
        or plan.pcode_preferred
        or enabled_degraded
        or no_progress
    )
    return EscalationDecision(
        escalate=exit_loop,
        state_delta={
            PREVIOUS_SNAPSHOT_KEY: current,
            PCODE_PREFERRED_PROMPT_KEY: pcode_alias,
        },
    )
```

Malformed/missing classification or canonical mismatch fails closed and clears the p-code
alias because no model policy is trusted. Once shape and authority are valid, normalize the
alias to `"true"`/`"false"` and include it on success, `recovery_not_called`, and every
later malformed-state failure.

Use:

```python
factory=partial(build_escalation_gate, evaluator=evaluate_deobf_gate)
```

in `DEOBF_GATE_DESCRIPTOR`. This supplies domain behavior without importing the domain into
`src/arema`.

- [ ] **Step 6: Run gate tests and architecture boundary tests**

Run:

```bash
uv run --extra dev pytest \
  tests/unit/runtime/test_agent_factory.py \
  tests/reverse_engineering/test_deobfuscation_agents.py \
  tests/architecture/test_neutral_boundaries.py -v
```

Expected: all pass; neutral boundary test confirms no reverse-engineering import under
`src/arema`.

- [ ] **Step 7: Commit**

```bash
git add src/arema/runtime/agent_factory.py tests/unit/runtime/test_agent_factory.py \
  src/reverse_engineering/agents/deobf_gate.py \
  tests/reverse_engineering/test_deobfuscation_agents.py
git -c commit.gpgsign=false commit -m "feat: add deterministic loop escalation gate"
```

---

### Task 7: Add the LoopAgent/recovery descriptors and prompts

**Files:**
- Create: `src/reverse_engineering/agents/deobfuscation.py`
- Create: `src/reverse_engineering/agents/recover.py`
- Create: `src/reverse_engineering/agents/deobf_classify.py`
- Create: `src/reverse_engineering/agents/upx_unpack.py`
- Create: `src/reverse_engineering/agents/floss_decode.py`
- Create: `src/reverse_engineering/agents/retriage.py`
- Create: `src/reverse_engineering/prompts/deobf_classify.md`
- Create: `src/reverse_engineering/prompts/upx_unpack.md`
- Create: `src/reverse_engineering/prompts/floss_decode.md`
- Create: `src/reverse_engineering/prompts/retriage.md`
- Modify: `src/reverse_engineering/tools/acquire_sample.py`
- Modify: `src/reverse_engineering/tools/deobfuscation/state.py`
- Modify: `src/reverse_engineering/tools/deobfuscation/upx.py`
- Modify: `src/reverse_engineering/tools/deobfuscation/floss.py`
- Modify: `src/reverse_engineering/tools/prepare_sandbox.py`
- Modify: `src/reverse_engineering/agents/deobf_gate.py`
- Modify: `src/reverse_engineering/prompts/triage_recon.md`
- Modify: `src/reverse_engineering/prompts/deobf_classify.md`
- Modify: `src/reverse_engineering/prompts/retriage.md`
- Modify: `tests/reverse_engineering/test_deobfuscation_agents.py`
- Modify: `tests/reverse_engineering/test_acquire_sample.py`
- Modify: `tests/reverse_engineering/test_deobfuscation_runtime.py`
- Modify: `tests/reverse_engineering/test_upx_deobfuscation_tool.py`
- Modify: `tests/reverse_engineering/test_floss_deobfuscation_tool.py`
- Modify: `tests/reverse_engineering/test_prepare_sandbox.py`

- [ ] **Step 1: Write failing descriptor and prompt tests**

Assert:

```python
assert DEOBFUSCATION_DESCRIPTOR.factory is build_loop_agent
assert DEOBFUSCATION_DESCRIPTOR.metadata["max_iterations"] == 3
assert DEOBFUSCATION_DESCRIPTOR.sub_agent_ids == (
    "deobf_classify", "recover", "retriage", "deobf_gate"
)
assert RECOVER_DESCRIPTOR.sub_agent_ids == ("upx_unpack", "floss_decode")
assert DEOBF_CLASSIFY_DESCRIPTOR.output_key == CLASSIFICATION_KEY
assert RETRIAGE_DESCRIPTOR.output_key == RETRIAGE_SNAPSHOT_KEY
assert RETRIAGE_DESCRIPTOR.tool_ids == ("prepare_sandbox",)
assert RETRIAGE_DESCRIPTOR.mcp_server_ids == ("radare2_mcp",)
assert UPX_UNPACK_DESCRIPTOR.tool_ids == ("upx_unpack",)
assert FLOSS_DECODE_DESCRIPTOR.tool_ids == ("floss_decode",)
```

Load every new prompt and assert it contains neither `transfer to` nor `delegate to`.
Add regressions for new-sample state reset, optional injected aliases, exact baseline totals,
and distinct r2 count/evidence pagination signatures. Initial triage must call the four
inventory tools with `count=true`, use `show_info` for size, and emit the exact structured
`DEOBF_PRE_SNAPSHOT` consumed by the first classifier iteration; it must never infer totals
from paginated inventories.

- [ ] **Step 2: Run and verify RED**

Run:

```bash
uv run --extra dev pytest tests/reverse_engineering/test_deobfuscation_agents.py -v
```

Expected: imports fail for the new descriptor modules.

- [ ] **Step 3: Create the composite descriptors**

Use prompt-less `AgentDescriptor`s:

```python
DEOBFUSCATION_DESCRIPTOR = AgentDescriptor(
    id="deobfuscation",
    name="deobfuscation",
    description="Classify, recover, retriage, and gate obfuscated artifacts.",
    prompt_id=None,
    factory=build_loop_agent,
    sub_agent_ids=("deobf_classify", "recover", "retriage", "deobf_gate"),
    metadata={"max_iterations": 3},
)

RECOVER_DESCRIPTOR = AgentDescriptor(
    id="recover",
    name="recover",
    description="Run binary-level recovery in fixed UPX then FLOSS order.",
    prompt_id=None,
    factory=build_sequential_agent,
    sub_agent_ids=("upx_unpack", "floss_decode"),
)
```

- [ ] **Step 4: Create the four LlmAgent descriptors**

- `deobf_classify`: tool-less, `re_guarded`, `output_key=CLASSIFICATION_KEY`.
- `upx_unpack`: `re_guarded`, `tool_ids=("upx_unpack",)`.
- `floss_decode`: `re_guarded`, `tool_ids=("floss_decode",)`.
- `retriage`: `re_guarded`, `tool_ids=("prepare_sandbox",)`,
  `mcp_server_ids=("radare2_mcp",)`, `output_key=RETRIAGE_SNAPSHOT_KEY`.

All use `load_domain_prompt`.

- [ ] **Step 5: Write strict prompt contracts**

Classifier output must be JSON only:

```json
{
  "artifact_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "deobf_plan": {"upx": false, "floss": false},
  "pcode_preferred": false,
  "obf_class": "none|upx|packed-other|cff|vm|opaque-predicate|unknown",
  "pre_snapshot": {
    "size": 0,
    "function_count": 0,
    "import_count": 0,
    "string_count": 0,
    "section_count": 0
  }
}
```

Set `floss=true` only for PE. Set `pcode_preferred=true` for CFF/VM/bogus control flow/
opaque predicates. Recovery prompts must always call their tool once; the tool implements
plan-disabled skipping and state reset.

Retriage must:

1. use the current artifact id from UPX state/result;
2. call `prepare_sandbox(current_id)`;
3. call r2mcp `open_file("/app/" + current_id)`, then `analyze`;
4. collect exact count totals with `count=true`; use `list_functions(count=false,start=0,max_length=25)`
   for function evidence and `count=false,page_size=25` with no cursor/page argument for other
   first-page evidence;
5. return JSON only with the same snapshot fields plus `artifact_id` and a `findings`
   array. Each finding object carries the normal `artifact_id`, `claim`, `tool`,
   `confidence`, and `detail` fields so downstream evidence validation retains the
   recovered artifact's r2 evidence.

Use this exact top-level shape:

```json
{
  "artifact_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "size": 0,
  "function_count": 0,
  "import_count": 0,
  "string_count": 0,
  "section_count": 0,
  "findings": [
    {
      "artifact_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "claim": "Observed fact from retriage",
      "tool": "show_info",
      "confidence": 0.9,
      "detail": "Bounded supporting excerpt"
    }
  ]
}
```

- [ ] **Step 6: Run descriptor/prompt tests**

Run: `uv run --extra dev pytest tests/reverse_engineering/test_deobfuscation_agents.py -v`

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add src/reverse_engineering/agents src/reverse_engineering/prompts \
  tests/reverse_engineering/test_deobfuscation_agents.py
git -c commit.gpgsign=false commit -m "feat: add deobfuscation loop agents"
```

---

### Task 8: Wire the nine-stage malware pipeline and downstream policy

**Files:**
- Modify: `src/reverse_engineering/composition.py`
- Modify: `src/reverse_engineering/__init__.py`
- Modify: `src/malware_analyst/agents/malware_analyst.py`
- Modify: `src/malware_analyst/composition.py`
- Modify: `src/reverse_engineering/prompts/deep_decompile.md`
- Modify: `src/reverse_engineering/prompts/evidence_critic.md`
- Modify: `tests/malware_analyst/test_malware_analyst_composition.py`
- Modify: `tests/reverse_engineering/test_deobfuscation_agents.py`

- [ ] **Step 1: Extend component tests first**

Change the expected root order to:

```python
[
    "sample_intake",
    "triage_recon",
    "deobfuscation",
    "ioc_extraction",
    "deep_decompile",
    "behavior_characterization",
    "attack_mapper",
    "evidence_critic",
    "malware_report_generator",
]
```

Add:

```python
deobf = next(a for a in root.sub_agents if a.name == "deobfuscation")
assert isinstance(deobf, LoopAgent)
assert deobf.max_iterations == 3
assert [a.name for a in deobf.sub_agents] == [
    "deobf_classify", "recover", "retriage", "deobf_gate"
]
recover = next(a for a in deobf.sub_agents if a.name == "recover")
assert isinstance(recover, SequentialAgent)
assert [a.name for a in recover.sub_agents] == ["upx_unpack", "floss_decode"]
assert isinstance(next(a for a in deobf.sub_agents if a.name == "deobf_gate"), BaseAgent)
assert not isinstance(next(a for a in deobf.sub_agents if a.name == "deobf_gate"), LlmAgent)
```

Also assert the catalog contains both recovery tools with the expected output policies.

- [ ] **Step 2: Run and verify RED**

Run:

```bash
uv run --extra dev pytest \
  tests/malware_analyst/test_malware_analyst_composition.py \
  tests/reverse_engineering/test_deobfuscation_agents.py -v
```

Expected: root-order and missing-registration failures.

- [ ] **Step 3: Register tools and export descriptors**

In `register_re_infrastructure`, loop over `DEOBFUSCATION_TOOLSET` and add each descriptor.
Export all seven deobfuscation/recovery descriptors from `reverse_engineering.__init__`.

- [ ] **Step 4: Register every reachable agent and update the spine**

Insert `"deobfuscation"` after `"triage_recon"` in `MALWARE_ANALYST_DESCRIPTOR`.
In `malware_analyst.composition`, add the loop shell, recovery shell, classifier, UPX,
FLOSS, retriage, and gate descriptors before catalog freeze.

- [ ] **Step 5: Update deep-decompile and critic prompts**

Add to deep-decompile:

```text
Read the normalized identifier-safe p-code alias and begin with ghidra_pcode only
when its exact value is true. Read the identifier-safe current-artifact alias and
call prepare_ghidra with it; always use the authoritative artifact id returned by
preparation. For recovered artifacts, select targets from the latest retriage
findings and append the internally generated UPX provenance alias to detail while
retaining the normal Ghidra citation.
```

Add `upx_unpack` and `floss_decode` to the critic's exact known-tool list. Consume the
retriage snapshot's `findings` array as ordinary evidence. Require recovered-artifact
findings to retain their normal r2/Ghidra citation and mention `upx_unpack` recovery
provenance in `detail`.

- [ ] **Step 6: Run component/profile/architecture tests**

Run:

```bash
uv run --extra dev pytest \
  tests/malware_analyst/test_malware_analyst_composition.py \
  tests/reverse_engineering/test_deobfuscation_agents.py \
  tests/reverse_engineering/test_re_guarded_profile.py \
  tests/architecture/test_neutral_boundaries.py -v
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add src/reverse_engineering/composition.py src/reverse_engineering/__init__.py \
  src/reverse_engineering/prompts/deep_decompile.md \
  src/reverse_engineering/prompts/evidence_critic.md \
  src/malware_analyst/agents/malware_analyst.py src/malware_analyst/composition.py \
  tests/malware_analyst/test_malware_analyst_composition.py \
  tests/reverse_engineering/test_deobfuscation_agents.py
git -c commit.gpgsign=false commit -m "feat: wire deobfuscation into malware pipeline"
```

---

### Task 9: Document extension rules and run complete verification

**Files:**
- Modify: `docs/CREATING_TOOLS.md`
- Verify: all files from Tasks 1–8

- [ ] **Step 1: Add the stateless sandbox-CLI documentation**

Document:

- eligibility: one-shot, file-in/result-out, no retained analysis session;
- use the shared runtime for claim/stage/run/read only;
- keep semantic parsing in one wrapper module;
- explicit toolset registration is required;
- image installation never auto-exposes a tool;
- sanitizer, `OutputPolicy`, evidence provenance, applicability, and failure tests are
  mandatory;
- choose radare2 MCP for a broad upstream typed interactive surface;
- choose a separate Ghidra-like pool/lifecycle for a stateful daemon/project.

Include a concise example importing `stage_artifact`, defining a deferred factory, and
adding its descriptor to `DEOBFUSCATION_TOOLSET`.

- [ ] **Step 2: Run formatting and static checks**

Run:

```bash
make lint
make format-check
make type-check
```

Expected: all exit 0. Fix only issues introduced by this plan; do not reformat unrelated
user changes.

- [ ] **Step 3: Run the full automated suite**

Run: `make test`

Expected: all tests pass with zero collection errors. If a new test basename collides,
rename it rather than adding `__init__.py` to test directories.

- [ ] **Step 4: Deploy the new sandbox resources**

Run:

```bash
make sandbox-deobfuscation-image
make sandbox-deobfuscation-up
kubectl get pods -n agent-sandbox-demo -l arema.dev/pool=deobfuscation-tools
```

Expected: one Ready warm-pool pod using `arema-deobfuscation-tools:0.1.0`.

- [ ] **Step 5: Run the real UPX smoke**

Inside a claimed test pod or via the wrapper integration:

1. pack a copy of `/bin/ls` with the pinned UPX 5.2.0;
2. acquire the packed bytes;
3. call `upx_unpack`;
4. assert `success=true`, `applicable=true`, and a different recovered artifact id;
5. compare recovered bytes/hash with the original;
6. call against unpacked `/bin/ls` and assert `success=true`, `applicable=false`.

Record the exact commands and hashes in the implementation session notes; do not commit
sample binaries.

- [ ] **Step 6: Run the real FLOSS smoke**

Use a controlled redistributable PE fixture with a known stack/decoded-string test case.
Acquire it, call `floss_decode`, and assert:

```text
success=true
applicable=true
tool_version=3.1.1
counts decoded+stack+tight > 0
new_count > 0 on first observation and = 0 for an identical later iteration
every returned record has type, string, encoding, function, and location
```

Do not substitute ELF `/bin/ls`; FLOSS decoded/stack/tight recovery is PE-specific.

- [ ] **Step 7: Run the end-to-end malware pipeline**

Run one UPX-packed sample through `malware_analyst`. Verify from emitted events/state:

- root has nine stages;
- loop performs classify→recover→retriage→gate and never exceeds three iterations;
- recovered artifact id reaches IOC extraction and Ghidra preparation;
- evidence critic accepts `upx_unpack`/`floss_decode` provenance;
- report completes even when either recovery tool degrades.

- [ ] **Step 8: Commit documentation**

```bash
git add docs/CREATING_TOOLS.md
git -c commit.gpgsign=false commit -m "docs: document stateless sandbox tools"
```

If verification exposed an implementation defect, return to the owning task's focused
tests, fix it with a regression test, rerun that task's verification command, and create a
separate narrowly scoped `fix:` commit before continuing.

- [ ] **Step 9: Final evidence gate**

Run: `make check`

Expected: lint, format, type-check, and the full pytest suite all exit 0. Capture the exact
test count in the handoff. Then inspect:

```bash
git status --short
git log --oneline --decorate -12
```

Expected: clean worktree and one focused commit per task.

---

### Task 10: Lock recovery contracts and downstream evidence flow

- [x] **Step 1: Bind retriage identity**

Add RED tests proving missing, malformed, uppercase, and stale retriage `artifact_id`
values fail closed. Require exact equality with the strict canonical-bound classification
before current metrics influence progress; retain the previous baseline as metric-only.

- [x] **Step 2: Track FLOSS progress deltas**

Add RED multi-iteration tests for first-seen, repeated, genuinely new, and malformed seen
state. Fingerprint exact normalized public record fields into a bounded trusted-state list,
reset it on new-sample intake, expose `new_count`, and make `FLOSS_COUNT_KEY` the current
invocation's new-record delta.

- [x] **Step 3: Lock tool response schemas and UPX input**

Replace legacy FLOSS `strings`/`totals` with `records`/`counts`, include format, canonical
source id, tool version, truncation, and delta semantics. Include UPX source id/size and
recovered size whenever known. Define `MAX_UPX_INPUT_BYTES = 512 MiB`, preflight before
claim/write, and pass it to `stage_artifact` so the runtime reads at most cap + 1.
At every normal gate boundary, clear both wrapper caches plus called/progress/degraded
iteration facts, but retain FLOSS's seen-fingerprint set. Fresh calls invalidate old cache
before setting called; corrupt duplicate-call cache state is replaced atomically by the
locked degraded zero-progress response.

- [x] **Step 4: Connect recovery evidence**

Require the FLOSS agent's one faithful call to emit at most 20 evidence-backed FINDINGs
from meaningful successful records tied to the canonical source artifact. Make both IOC
lenses prefer matching latest retriage/FLOSS evidence after recovery, ignore stale artifact
ids, retain initial triage only as the non-recovery fallback, and preserve upstream
citations plus UPX recovery provenance.

- [x] **Step 5: Harden extension guidance and verify**

Document a `ToolContext`-only wrapper with strict canonical classification parsing, no
model artifact selector, and a fixed input cap. Run focused wrapper/runtime/gate/agent/
composition/IOC tests, Ruff, format check, mypy, then `make check`.
