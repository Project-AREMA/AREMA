# Scripted Unpacking — Phase 2: The .NET Companion (deterministic de4dot) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a protected .NET/CLR sample (the motivating `1595d92f…`, SmartAssembly/Dotfuscator) recoverable end-to-end by adding **de4dot as one more self-gating deterministic recovery tool inside the existing `deobfuscation-tools` sandbox and `recover` stage** — no new pod, pool, template, stage, or path.

**Architecture:** de4dot mirrors `upx.py` exactly — a deferred-factory tool that stages the current artifact into the `deobfuscation-tools` pool, runs de4dot, and on success advances `CURRENT_ARTIFACT_KEY` + provenance + writes `DE4DOT_RESULT_KEY`. It **self-gates**: `applicable: False` for a non-`dotnet` sample (read from `SAMPLE_FORMAT_KEY`) or when de4dot detects no obfuscator. The recovered assembly stays `dotnet`, so `deep_engine_router` routes it to ILSpy unchanged — ILSpy now decompiles deobfuscated C#. The gate folds de4dot evidence like upx/floss.

**Tech Stack:** Python 3.12, Google ADK 1.25.1, mono + de4dot (in the `deobfuscation-tools` image), pytest, Ruff, mypy. Spec authority: `docs/superpowers/specs/2026-07-28-scripted-unpacking-agent-design.md` §12.

## Global Constraints

- **Spec §12 is authoritative.** This plan implements it exactly.
- **No new pod/pool/template/stage/path.** de4dot lives in the existing `deobfuscation-tools` image and the existing `recover` `SequentialAgent`. It self-gates by format (`SAMPLE_FORMAT_KEY == "dotnet"`) exactly as upx/floss no-op for non-PE.
- **Mirror `upx.py`.** The de4dot tool is a sibling of `src/reverse_engineering/tools/deobfuscation/upx.py` (an artifact-producing recovery tool): the same cache / `_degraded_result` / `advance_classification_artifact` / provenance shape, with de4dot-specific gating, command, obfuscator detection, and validation.
- **Validation is de4dot-success + valid-CLR, NOT the native entropy-drop gate.** Admit the output only when de4dot **detected an obfuscator**, the output **parses as a valid CLR assembly** (`detect_format_bytes(...) == "dotnet"`), and it **differs from the input** (`recovered_artifact_id != source`). Otherwise `applicable: False` / rejected — never fabricate a recovery.
- **`deobf_classify` is NOT changed.** de4dot self-gates on `SAMPLE_FORMAT_KEY` + its own obfuscator detection, independent of `obf_class`.
- **`_recovery_called` stays `{UPX, FLOSS}`.** de4dot is a *later* child of the same `recover` `SequentialAgent`, so upx/floss running transitively guarantees de4dot ran; its evidence is folded *when present* (like `scripted`), keeping the gate stable as tools are added.
- **ADK annotation rule.** Never `param: Any` on a tool function; `object` for generic params. **Never `isinstance(state, dict)`** — duck-type on `.get`/`__setitem__`.
- **Neutral-core boundary.** All new code under `src/reverse_engineering/`; never add `de4dot`/`dotnet`/domain names to `src/arema/`.
- **Acceptance:** live end-to-end on the real `1595d92f…` sample (de4dot → ILSpy → report reflects deobfuscated code), plus unit/component coverage. `make check` green.
- **Every task ends `make check`-clean and is committed with `rtk` + the standard trailers.**

---

## File map

### Create
- `src/reverse_engineering/tools/deobfuscation/dotnet.py` — the `de4dot` tool (mirrors `upx.py`) + `DE4DOT_DEOBFUSCATE_TOOL`.
- `src/reverse_engineering/agents/de4dot_deobfuscate.py` — the `de4dot_deobfuscate` LlmAgent descriptor (mirrors `agents/upx_unpack.py`).
- `src/reverse_engineering/prompts/de4dot_deobfuscate.md` — the one-tool prompt (mirrors `prompts/upx_unpack.md`).
- `images/deobfuscation-tools/de4dot` — a tiny `mono`-wrapper so the tool runs `de4dot <in> -o <out>` (confirmed in Task 1).
- `docs/superpowers/notes/2026-07-29-de4dot-probe.md` — Task 1's recorded de4dot CLI + output markers + unprotected/protected behavior.
- Tests: `test_de4dot_deobfuscation_tool.py`, `test_de4dot_deobfuscate.py` under `tests/reverse_engineering/`.

### Modify
- `images/deobfuscation-tools/Dockerfile` — add a pinned mono runtime + de4dot; `images/deobfuscation-tools/healthcheck.sh` — assert de4dot runs.
- `src/reverse_engineering/tools/deobfuscation/state.py` — `DE4DOT_*` keys; reset them in `reset_deobfuscation_state`.
- `src/reverse_engineering/tools/acquire_sample.py` — extract a bytes-based `detect_format_bytes` (DRY, reused by de4dot); `_detect_format(path)` calls it.
- `src/reverse_engineering/tools/deobfuscation/toolset.py` — add `DE4DOT_DEOBFUSCATE_TOOL` to `DEOBFUSCATION_TOOLSET`.
- `src/reverse_engineering/tools/deobfuscation/upx.py` — extend `_PROVENANCE_PATTERN` to recognize `de4dot_deobfuscate` so its provenance is not wiped.
- `src/reverse_engineering/agents/recover.py` — append `de4dot_deobfuscate` to `sub_agent_ids`.
- `src/reverse_engineering/agents/deobf_gate.py` — `_de4dot_outcome`, fold into `_build_evidence`, reset de4dot keys in `_iteration_delta`.
- `src/reverse_engineering/__init__.py` + `src/malware_analyst/composition.py` — export + register `DE4DOT_DEOBFUSCATE_DESCRIPTOR`.

---

## Task 1: de4dot in the `deobfuscation-tools` image + feasibility probe

**Files:**
- Modify: `images/deobfuscation-tools/Dockerfile`, `images/deobfuscation-tools/healthcheck.sh`
- Create: `images/deobfuscation-tools/de4dot` (wrapper), `docs/superpowers/notes/2026-07-29-de4dot-probe.md`
- Test: `tests/unit/test_deobfuscation_tools_manifest.py` (this image's existing manifest-test sibling — extend it with the de4dot assertions rather than starting a second file, so the Dockerfile/healthcheck pins stay a single source of truth)

**Interfaces:**
- Produces: an image where the command **`de4dot`** deobfuscates a .NET assembly (`de4dot <input> -o <output>`), and a probe note recording (a) the exact CLI, (b) the stdout line that names a detected obfuscator, (c) whether de4dot writes an output file when NO obfuscator is detected. Tasks 4/6 consume (b) and (c).

- [ ] **Step 1: Add mono + de4dot to the Dockerfile**

In `images/deobfuscation-tools/Dockerfile`, after the UPX install stage and before the venv step, add a de4dot stage. Pin a specific de4dot build and verify a checksum (mirror the UPX pattern). Use the maintained **de4dot-cex** release (broadest obfuscator coverage) run under the distro `mono-runtime`:

```dockerfile
# de4dot (managed-code deobfuscator) runs under mono. Pinned + checksum-verified,
# mirroring the UPX install above.
ARG DE4DOT_VERSION=<research the de4dot-cex release tag>
ARG DE4DOT_SHA256=<research the release asset sha256>
RUN apt-get update \
    && apt-get install -y --no-install-recommends mono-runtime libmono-system-windows-forms4.0-cil unzip \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL "<research the de4dot-cex release asset url>" -o /tmp/de4dot.zip \
    && echo "${DE4DOT_SHA256}  /tmp/de4dot.zip" | sha256sum -c - \
    && unzip -q /tmp/de4dot.zip -d /opt/de4dot \
    && rm -f /tmp/de4dot.zip
COPY --chmod=0755 de4dot /usr/local/bin/de4dot
```

Create `images/deobfuscation-tools/de4dot` (the wrapper — confirm the `.exe` path against the release layout during the live build):

```sh
#!/bin/sh
exec mono /opt/de4dot/de4dot.exe "$@"
```

**Autonomous scope:** WebSearch/WebFetch the de4dot-cex GitHub releases and fill the `DE4DOT_VERSION`, asset URL, and `DE4DOT_SHA256` with real values (verify the sha against the published asset). Do NOT attempt a Docker build here — this environment has no cluster/Docker; the actual image build + de4dot behavior probe happens at Task 7 on the user's cluster.

- [ ] **Step 2: Record expected de4dot behavior (probe deferred to the live build)**

Write `docs/superpowers/notes/2026-07-29-de4dot-probe.md` documenting the **expected** de4dot-cex behavior to confirm at live-build time (Task 7):
- the invocation `de4dot <input> -o <output>` (note any required flags found in the release docs),
- the **stdout line naming a detected obfuscator** — de4dot-cex prints `Detected <Name> (...)`; Task 4's `_DETECTED_PATTERN` targets this. Record the exact wording to confirm live.
- **whether an output file is written when no obfuscator is detected** — de4dot-cex prints `Could not detect obfuscator!` and writes nothing; Task 4 treats "no `Detected` line" as `no_obfuscator`. Confirm live.
- the `--version`/build string for the healthcheck.

Task 4's tool + unit tests validate the parsing logic against a **fake sandbox** (scripted stdout), so the code lands green now; the live build (Task 7) confirms the real markers and the plan's constants are adjusted there if they differ.

- [ ] **Step 3: Healthcheck**

In `images/deobfuscation-tools/healthcheck.sh`, add (using the build string from the probe):

```bash
de4dot_ok="$(de4dot 2>&1 | grep -c 'de4dot' || true)"
test "${de4dot_ok}" -ge 1
```

- [ ] **Step 4: Assert the manifest wiring in a test**

Add a text-assertion test (mirrors the existing image manifest tests) that the Dockerfile installs `mono-runtime`, copies the `de4dot` wrapper, and the healthcheck invokes `de4dot`.

Run: `rtk uv run --extra dev pytest tests/unit/test_deobfuscation_tools_manifest.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
rtk git add images/deobfuscation-tools docs/superpowers/notes/2026-07-29-de4dot-probe.md tests/unit/test_deobfuscation_tools_manifest.py
rtk git commit -m "feat(deobf): add mono + de4dot to the deobfuscation-tools image"
```

---

## Task 2: `DE4DOT_*` state keys

**Files:**
- Modify: `src/reverse_engineering/tools/deobfuscation/state.py`
- Test: `tests/reverse_engineering/test_deobfuscation_state.py`

**Interfaces:**
- Produces: `DE4DOT_CALLED_KEY`, `DE4DOT_RESULT_KEY`, `DE4DOT_CHANGED_KEY`, `DE4DOT_DEGRADED_KEY` (all `"deobf:de4dot_*"`). Provenance reuses the shared `UPX_PROVENANCE_PROMPT_KEY`. `reset_deobfuscation_state` clears the four keys (`*_RESULT → None`, the rest → `False`).

- [ ] **Step 1: Write the failing test**

```python
def test_de4dot_keys_defined_and_reset() -> None:
    from reverse_engineering.tools.deobfuscation.state import (
        DE4DOT_CALLED_KEY, DE4DOT_CHANGED_KEY, DE4DOT_DEGRADED_KEY, DE4DOT_RESULT_KEY,
        reset_deobfuscation_state,
    )
    assert DE4DOT_RESULT_KEY == "deobf:de4dot_result"
    state: dict[str, object] = {
        DE4DOT_CALLED_KEY: True, DE4DOT_RESULT_KEY: {"x": 1},
        DE4DOT_CHANGED_KEY: True, DE4DOT_DEGRADED_KEY: True,
    }
    reset_deobfuscation_state(state, "a" * 64)
    assert state[DE4DOT_RESULT_KEY] is None
    assert state[DE4DOT_CALLED_KEY] is False
    assert state[DE4DOT_CHANGED_KEY] is False
    assert state[DE4DOT_DEGRADED_KEY] is False
```

- [ ] **Step 2: Run to verify it fails** — `rtk uv run --extra dev pytest tests/reverse_engineering/test_deobfuscation_state.py -q` → ImportError.

- [ ] **Step 3: Add the keys**

In `state.py`, next to the UPX keys:

```python
DE4DOT_CHANGED_KEY = "deobf:de4dot_changed"
DE4DOT_DEGRADED_KEY = "deobf:de4dot_degraded"
DE4DOT_CALLED_KEY = "deobf:de4dot_called"
DE4DOT_RESULT_KEY = "deobf:de4dot_result"
```

In `reset_deobfuscation_state`'s `cleared` dict:

```python
        DE4DOT_CHANGED_KEY: False,
        DE4DOT_DEGRADED_KEY: False,
        DE4DOT_CALLED_KEY: False,
        DE4DOT_RESULT_KEY: None,
```

- [ ] **Step 4: Run to verify it passes.** **Step 5: Commit** `feat(deobf): de4dot loop state keys`.

---

## Task 3: bytes-based `detect_format_bytes` (DRY reuse for CLR validation)

**Files:**
- Modify: `src/reverse_engineering/tools/acquire_sample.py`
- Test: `tests/reverse_engineering/test_acquire_sample.py`

**Interfaces:**
- Produces: `detect_format_bytes(data: bytes) -> str` returning `"dotnet"|"pe"|"elf"|"macho"|"unknown"` from a header-only parse; `_detect_format(path)` reads the file and delegates to it (behavior unchanged). de4dot (Task 4) imports `detect_format_bytes` to validate its output is a real CLR assembly.

- [ ] **Step 1: Write the failing test**

```python
def test_detect_format_bytes_matches_file_detection(tmp_path) -> None:
    from reverse_engineering.tools.acquire_sample import _detect_format, detect_format_bytes
    elf = b"\x7fELF" + b"\x00" * 60
    assert detect_format_bytes(elf) == "elf"
    assert detect_format_bytes(b"not a binary") == "unknown"
    # A minimal PE with no CLI directory is "pe", not "dotnet".
    p = tmp_path / "x.bin"; p.write_bytes(elf)
    assert detect_format_bytes(elf) == _detect_format(p)
```

- [ ] **Step 2: Run to verify it fails** (ImportError).

- [ ] **Step 3: Refactor `_detect_format` into a bytes core**

Move the header-parsing body into `detect_format_bytes(data: bytes) -> str` operating on an in-memory buffer (`io.BytesIO(data)`), and have `_detect_format(path)` do `return detect_format_bytes(path.read_bytes())` inside the existing `try/except (OSError, struct.error)`. Keep all existing constants and the exact branch logic; only the input source changes. (This preserves every current `_detect_format` behavior — the existing acquire_sample tests must stay green.)

- [ ] **Step 4: Run** `rtk uv run --extra dev pytest tests/reverse_engineering/test_acquire_sample.py -q` → PASS. **Step 5: Commit** `refactor(re): bytes-based detect_format_bytes reused by de4dot`.

---

## Task 4: The `de4dot` tool

**Files:**
- Create: `src/reverse_engineering/tools/deobfuscation/dotnet.py`
- Modify: `src/reverse_engineering/tools/deobfuscation/toolset.py`, `src/reverse_engineering/tools/deobfuscation/upx.py`
- Test: `tests/reverse_engineering/test_de4dot_deobfuscation_tool.py`

**Interfaces:**
- Consumes: `stage_artifact`/`run_argv`/`read_bounded_file` (runtime), `parse_current_classification`/`advance_classification_artifact` + `DE4DOT_*` keys + `SAMPLE_FORMAT_KEY`, `detect_format_bytes` (Task 3).
- Produces: `DE4DOT_DEOBFUSCATE_TOOL` (id `"de4dot_deobfuscate"`). Writes `DE4DOT_RESULT_KEY` mirroring `UPX_RESULT_KEY` plus `obfuscator_name`; exports `_valid_cached_result` for the gate. On success: sets `CURRENT_ARTIFACT_KEY` + `advance_classification_artifact` + `UPX_PROVENANCE_PROMPT_KEY = "de4dot_deobfuscate source=<sha> destination=<sha> obfuscator=<name>"`.

- [ ] **Step 1: Write the failing test**

`tests/reverse_engineering/test_de4dot_deobfuscation_tool.py` — mirror `test_upx_deobfuscation_tool.py`'s harness (a fake sandbox `run_argv` returning a scripted `ExecutionResult`, `SAMPLE_FORMAT_KEY` in state). Cover: (a) non-dotnet sample → `applicable: False, reason "not_dotnet"`, no advance; (b) dotnet + de4dot detects an obfuscator + valid-CLR output that differs → `applicable: True, changed: True`, `CURRENT_ARTIFACT_KEY` advanced, `obfuscator_name` recorded, provenance written; (c) dotnet + de4dot detects no obfuscator (no "Detected" marker) → `applicable: False, reason "no_obfuscator"`, no advance; (d) dotnet + de4dot output that is not a valid CLR assembly → `degraded, error_code "output_invalid"`, no advance; (e) `_valid_cached_result` accepts each admitted shape.

(Use the same fake-sandbox monkeypatching `test_upx_deobfuscation_tool.py` uses — read it and reuse its fixtures verbatim so the harnesses match.)

- [ ] **Step 2: Run to verify it fails** (ModuleNotFoundError).

- [ ] **Step 3: Write the tool**

`src/reverse_engineering/tools/deobfuscation/dotnet.py` — a sibling of `upx.py`. Full implementation:

```python
"""Sandboxed .NET deobfuscation of protected CLR assemblies via de4dot."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from google.adk.tools.tool_context import (
    ToolContext,  # noqa: TC002 - ADK resolves annotations at runtime
)

from arema.registry.descriptors import OutputPolicy, ToolDescriptor
from reverse_engineering.artifacts import ArtifactStore, default_artifacts_root
from reverse_engineering.tools.acquire_sample import SAMPLE_FORMAT_KEY, detect_format_bytes
from reverse_engineering.tools.deobfuscation.runtime import (
    MAX_RECOVERED_BYTES,
    ArtifactInputTooLarge,
    DeobfuscationUnavailable,
    read_bounded_file,
    run_argv,
    stage_artifact,
)
from reverse_engineering.tools.deobfuscation.state import (
    CURRENT_ARTIFACT_KEY,
    CURRENT_ARTIFACT_PROMPT_KEY,
    DE4DOT_CALLED_KEY,
    DE4DOT_CHANGED_KEY,
    DE4DOT_DEGRADED_KEY,
    DE4DOT_RESULT_KEY,
    UPX_PROVENANCE_PROMPT_KEY,
    advance_classification_artifact,
    parse_current_classification,
)

if TYPE_CHECKING:
    from arema.registry.descriptors import ToolLike
    from arema.runtime.agent_factory import ToolBuildContext

_TOOL_VERSION = "de4dot-cex"  # pin exact build string from Task 1
MAX_DE4DOT_INPUT_BYTES = 512 * 1024 * 1024
_OUTPUT_NAME = "deobfuscated"
_MISSING = object()
# de4dot names the recognized protector on stdout ("Detected <Name> (...)").
# Confirm the exact wording in Task 1's probe; the SUCCESS decision does not rely
# on it alone -- applicability also requires a valid, changed CLR output.
_DETECTED_PATTERN = re.compile(r"Detected\s+(?P<name>.+?)\s*(?:\(|v\d|$)", re.MULTILINE)
_MAX_OBFUSCATOR_CHARS = 100
_ERROR_MESSAGES = {
    "invalid_classification": "The deobfuscation classification is invalid.",
    "artifact_unavailable": "The artifact is unavailable.",
    "sandbox_unavailable": "The deobfuscation sandbox is unavailable.",
    "output_invalid": "The recovered output is not a valid .NET assembly.",
    "de4dot_failed": "de4dot could not process the assembly.",
}


def build_de4dot_deobfuscate(context: ToolBuildContext) -> ToolLike:
    """Build the ``de4dot_deobfuscate`` tool for the live sandbox runtime."""

    def de4dot_deobfuscate(tool_context: ToolContext) -> dict[str, object]:
        """Deobfuscate a protected .NET assembly inside the deobfuscation sandbox."""
        state = tool_context.state
        try:
            cached = _cached_result(state, DE4DOT_CALLED_KEY, DE4DOT_RESULT_KEY)
        except ValueError:
            corrupt = _degraded_result("invalid_classification")
            state[DE4DOT_CHANGED_KEY] = False
            state[DE4DOT_DEGRADED_KEY] = True
            state[DE4DOT_RESULT_KEY] = dict(corrupt)
            return dict(corrupt)
        if cached is not None:
            state[DE4DOT_CHANGED_KEY] = cached["changed"]
            state[DE4DOT_DEGRADED_KEY] = cached["degraded"]
            return cached
        state[DE4DOT_RESULT_KEY] = None
        state[DE4DOT_CHANGED_KEY] = False
        state[DE4DOT_DEGRADED_KEY] = False
        state[DE4DOT_CALLED_KEY] = True

        def finish(result: dict[str, object]) -> dict[str, object]:
            state[DE4DOT_RESULT_KEY] = dict(result)
            return dict(result)

        try:
            plan = parse_current_classification(state)
        except ValueError:
            state[DE4DOT_DEGRADED_KEY] = True
            return finish(_degraded_result("invalid_classification"))

        state[CURRENT_ARTIFACT_PROMPT_KEY] = plan.artifact_id

        # Self-gate on the container format decided at intake. Managed-metadata
        # deobfuscation applies only to a .NET/CLR assembly.
        getter = getattr(state, "get", None)
        sample_format = getter(SAMPLE_FORMAT_KEY) if callable(getter) else None
        if sample_format != "dotnet":
            return finish(_not_applicable(plan.artifact_id, "not_dotnet"))

        try:
            source_size = (
                ArtifactStore(default_artifacts_root()).path_for(plan.artifact_id).stat().st_size
            )
        except (FileNotFoundError, OSError):
            state[DE4DOT_DEGRADED_KEY] = True
            return finish(_degraded_result("artifact_unavailable", source_artifact_id=plan.artifact_id))
        if source_size > MAX_DE4DOT_INPUT_BYTES:
            return finish(_not_applicable(plan.artifact_id, "input_too_large", source_size=source_size))

        try:
            staged = stage_artifact(
                context, plan.artifact_id, tool_context,
                tool_name="de4dot", max_input_bytes=MAX_DE4DOT_INPUT_BYTES,
            )
        except ArtifactInputTooLarge:
            return finish(_not_applicable(plan.artifact_id, "input_too_large", source_size=source_size))
        except DeobfuscationUnavailable:
            state[DE4DOT_DEGRADED_KEY] = True
            return finish(_degraded_result("sandbox_unavailable", source_artifact_id=plan.artifact_id, source_size=source_size))
        except FileNotFoundError:
            state[DE4DOT_DEGRADED_KEY] = True
            return finish(_degraded_result("artifact_unavailable", source_artifact_id=plan.artifact_id, source_size=source_size))
        except (OSError, TimeoutError, ValueError, RuntimeError):
            state[DE4DOT_DEGRADED_KEY] = True
            return finish(_degraded_result("sandbox_unavailable", source_artifact_id=plan.artifact_id, source_size=source_size))

        output_path = f"{staged.work_dir}/{_OUTPUT_NAME}"
        try:
            result = run_argv(staged, ["de4dot", staged.input_path, "-o", output_path])
        except (OSError, TimeoutError, ValueError, RuntimeError):
            state[DE4DOT_DEGRADED_KEY] = True
            return finish(_degraded_result("sandbox_unavailable", source_artifact_id=plan.artifact_id, source_size=source_size))
        if result.exit_code != 0 or result.truncated:
            state[DE4DOT_DEGRADED_KEY] = True
            return finish(_degraded_result("de4dot_failed", source_artifact_id=plan.artifact_id, source_size=source_size))

        detected = _DETECTED_PATTERN.search(result.stdout)
        if detected is None:
            # de4dot recognized no obfuscator: nothing to recover.
            return finish(_not_applicable(plan.artifact_id, "no_obfuscator", source_size=source_size))
        obfuscator = detected.group("name").strip()[:_MAX_OBFUSCATOR_CHARS] or "unknown"

        try:
            recovered = read_bounded_file(staged, output_path, max_bytes=MAX_RECOVERED_BYTES)
        except (FileNotFoundError, OSError, ValueError, RuntimeError):
            state[DE4DOT_DEGRADED_KEY] = True
            return finish(_degraded_result("output_invalid", source_artifact_id=plan.artifact_id, source_size=source_size))

        if not recovered or detect_format_bytes(recovered) != "dotnet":
            state[DE4DOT_DEGRADED_KEY] = True
            return finish(_degraded_result("output_invalid", source_artifact_id=plan.artifact_id, source_size=source_size, recovered_size=len(recovered)))

        try:
            recovered_artifact_id = ArtifactStore(default_artifacts_root()).acquire_bytes(recovered)
        except (FileNotFoundError, OSError, ValueError, RuntimeError):
            state[DE4DOT_DEGRADED_KEY] = True
            return finish(_degraded_result("artifact_unavailable", source_artifact_id=plan.artifact_id, source_size=source_size, recovered_size=len(recovered)))

        changed = recovered_artifact_id != plan.artifact_id
        state[DE4DOT_CHANGED_KEY] = changed
        if not changed:
            # de4dot named an obfuscator but produced byte-identical output: treat as
            # nothing recovered rather than a spurious advance.
            return finish(_not_applicable(plan.artifact_id, "no_change", source_size=source_size))
        state[CURRENT_ARTIFACT_KEY] = recovered_artifact_id
        state[CURRENT_ARTIFACT_PROMPT_KEY] = recovered_artifact_id
        advance_classification_artifact(state, plan, recovered_artifact_id)
        state[UPX_PROVENANCE_PROMPT_KEY] = (
            f"de4dot_deobfuscate source={plan.artifact_id} "
            f"destination={recovered_artifact_id} obfuscator={obfuscator}"
        )
        return finish({
            "success": True, "applicable": True, "degraded": False, "changed": True,
            "source_artifact_id": plan.artifact_id, "recovered_artifact_id": recovered_artifact_id,
            "source_size": source_size, "recovered_size": len(recovered),
            "obfuscator_name": obfuscator, "tool_version": _TOOL_VERSION,
        })

    return de4dot_deobfuscate


def _not_applicable(source_artifact_id: str, reason: str, *, source_size: int | None = None) -> dict[str, object]:
    result: dict[str, object] = {
        "success": True, "applicable": False, "degraded": False, "changed": False,
        "reason": reason, "source_artifact_id": source_artifact_id, "tool_version": _TOOL_VERSION,
    }
    if source_size is not None:
        result["source_size"] = source_size
    return result


def _degraded_result(error_code: str, *, source_artifact_id: str | None = None,
                     source_size: int | None = None, recovered_size: int | None = None) -> dict[str, object]:
    result: dict[str, object] = {
        "success": False, "applicable": True, "degraded": True, "changed": False,
        "error_code": error_code, "error": _ERROR_MESSAGES[error_code], "tool_version": _TOOL_VERSION,
    }
    if source_artifact_id is not None:
        result["source_artifact_id"] = source_artifact_id
    if source_size is not None:
        result["source_size"] = source_size
    if recovered_size is not None:
        result["recovered_size"] = recovered_size
    return result


def _cached_result(state: object, called_key: str, result_key: str) -> dict[str, object] | None:
    getter = getattr(state, "get", None)
    called = getter(called_key, _MISSING) if callable(getter) else _MISSING
    if called is _MISSING or called is False:
        return None
    if called is not True:
        raise ValueError("invalid de4dot call marker")
    cached = getter(result_key) if callable(getter) else None
    if not isinstance(cached, dict) or not _valid_cached_result(cached):
        raise ValueError("invalid de4dot result cache")
    return dict(cached)


def _valid_cached_result(result: dict[object, object]) -> bool:
    """Validate the locked de4dot response before reusing an in-iteration cache."""
    base = {"success", "applicable", "degraded", "changed", "tool_version"}
    if (not isinstance(result.get("success"), bool) or not isinstance(result.get("applicable"), bool)
            or not isinstance(result.get("degraded"), bool) or not isinstance(result.get("changed"), bool)
            or result.get("tool_version") != _TOOL_VERSION):
        return False
    success, applicable, degraded, changed = (result["success"], result["applicable"], result["degraded"], result["changed"])
    if success is False:
        required = base | {"error_code", "error"}
        optional = {"source_artifact_id", "source_size", "recovered_size"}
        if (not required <= set(result) <= required | optional or applicable is not True
                or degraded is not True or changed is not False):
            return False
        code = result["error_code"]
        if not isinstance(code, str) or code not in _ERROR_MESSAGES or result["error"] != _ERROR_MESSAGES[code]:
            return False
        if "source_artifact_id" in result and not _artifact_id(result["source_artifact_id"]):
            return False
        return all(k not in result or _nonnegative_int(result[k]) for k in ("source_size", "recovered_size"))
    if applicable is True:
        expected = base | {"source_artifact_id", "recovered_artifact_id", "source_size", "recovered_size", "obfuscator_name"}
        if set(result) != expected or degraded is not False or changed is not True:
            return False
        if not _artifact_id(result["source_artifact_id"]) or not _artifact_id(result["recovered_artifact_id"]):
            return False
        if result["source_artifact_id"] == result["recovered_artifact_id"]:
            return False
        if not isinstance(result["obfuscator_name"], str) or not result["obfuscator_name"]:
            return False
        return _nonnegative_int(result["source_size"]) and _nonnegative_int(result["recovered_size"])
    # applicable is False (non_applicable)
    if degraded is not False or changed is not False or success is not True:
        return False
    reason = result.get("reason")
    expected = base | {"reason", "source_artifact_id"}
    if reason in {"input_too_large", "no_obfuscator", "no_change"}:
        expected.add("source_size")
    elif reason != "not_dotnet":
        return False
    if set(result) != expected or not _artifact_id(result["source_artifact_id"]):
        return False
    return "source_size" not in result or _nonnegative_int(result["source_size"])


def _artifact_id(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _nonnegative_int(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= 0


DE4DOT_DEOBFUSCATE_TOOL = ToolDescriptor(
    id="de4dot_deobfuscate",
    description="Deobfuscate a protected .NET/CLR assembly with de4dot inside the deobfuscation sandbox.",
    factory=build_de4dot_deobfuscate,
    output_policy=OutputPolicy(max_chars=4_000, max_list_items=20),
)
```

- [ ] **Step 4: Register the tool + fix shared provenance**

In `toolset.py`:

```python
from reverse_engineering.tools.deobfuscation.dotnet import DE4DOT_DEOBFUSCATE_TOOL
DEOBFUSCATION_TOOLSET = (UPX_UNPACK_TOOL, FLOSS_DECODE_TOOL, DE4DOT_DEOBFUSCATE_TOOL)
```

In `upx.py`, extend `_PROVENANCE_PATTERN` so `de4dot_deobfuscate`'s provenance is preserved (not wiped by upx's stale-provenance guard):

```python
_PROVENANCE_PATTERN = re.compile(
    r"(?:upx_unpack|scripted_recover|de4dot_deobfuscate) "
    r"source=([0-9a-f]{64}) destination=([0-9a-f]{64})"
    r"(?: (?:method|obfuscator)=.*)?"
)
```

- [ ] **Step 5: Run tests** — `rtk uv run --extra dev pytest tests/reverse_engineering/test_de4dot_deobfuscation_tool.py tests/reverse_engineering/test_upx_deobfuscation_tool.py -q` → PASS (the provenance-pattern change must not break upx's tests). **Step 6: Commit** `feat(deobf): de4dot tool mirroring upx (self-gated .NET recovery)`.

---

## Task 5: The `de4dot_deobfuscate` agent + wiring into `recover`

**Files:**
- Create: `src/reverse_engineering/agents/de4dot_deobfuscate.py`, `src/reverse_engineering/prompts/de4dot_deobfuscate.md`
- Modify: `src/reverse_engineering/agents/recover.py`, `src/reverse_engineering/__init__.py`, `src/malware_analyst/composition.py`
- Test: `tests/reverse_engineering/test_de4dot_deobfuscate.py`, `tests/reverse_engineering/test_domain_composition.py`

**Interfaces:**
- Produces: `DE4DOT_DEOBFUSCATE_DESCRIPTOR` (mirrors `UPX_UNPACK_DESCRIPTOR`: `build_llm_agent`, `re_guarded`, `prompt_id="de4dot_deobfuscate"`, `tool_ids=("de4dot_deobfuscate",)`). `RECOVER_DESCRIPTOR.sub_agent_ids == ("upx_unpack", "floss_decode", "de4dot_deobfuscate")`.

- [ ] **Step 1: Write the failing tests** — descriptor shape + prompt loads (mirror `test_packer_analyst.py`); and in `test_domain_composition.py`: `RECOVER_DESCRIPTOR.sub_agent_ids[-1] == "de4dot_deobfuscate"` and the frozen `malware_analyst` catalog contains `de4dot_deobfuscate`.

- [ ] **Step 2: Run to verify they fail.**

- [ ] **Step 3: Write the prompt** (`prompts/de4dot_deobfuscate.md`, mirroring `upx_unpack.md`):

```markdown
# .NET deobfuscation (de4dot)

You have exactly one tool: `de4dot_deobfuscate`.

You MUST call `de4dot_deobfuscate` exactly once on every invocation, including when the sample is not .NET or is unprotected. The tool wrapper owns the format check, obfuscator detection, and applicability decisions; do not make those yourself.

After the one call, return the actual structured tool result faithfully. Do not retry. Do not fabricate, supplement, reinterpret, or omit result fields. Do not run host/local commands. Do not call any other tool.
```

- [ ] **Step 4: Write the descriptor** (`agents/de4dot_deobfuscate.py`):

```python
"""Descriptor for the de4dot .NET-deobfuscation recovery-tool agent."""

from __future__ import annotations

from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_llm_agent
from reverse_engineering.prompts.loader import load_domain_prompt

DE4DOT_DEOBFUSCATE_DESCRIPTOR = AgentDescriptor(
    id="de4dot_deobfuscate",
    name="de4dot_deobfuscate",
    description="Invoke the guarded de4dot .NET-deobfuscation recovery tool once.",
    prompt_id="de4dot_deobfuscate",
    factory=build_llm_agent,
    runtime_profile_id="re_guarded",
    prompt_loader=load_domain_prompt,
    tool_ids=("de4dot_deobfuscate",),
)
```

Append to `recover.py`'s `sub_agent_ids`: `("upx_unpack", "floss_decode", "de4dot_deobfuscate")`. Export `DE4DOT_DEOBFUSCATE_DESCRIPTOR` from `reverse_engineering/__init__.py`; register it in `malware_analyst/composition.py` beside `FLOSS_DECODE_DESCRIPTOR`.

- [ ] **Step 5: Run** `rtk uv run --extra dev pytest tests/reverse_engineering/test_de4dot_deobfuscate.py tests/reverse_engineering/test_domain_composition.py -q` → PASS. **Step 6: Commit** `feat(agents): de4dot_deobfuscate agent wired into the recover stage`.

---

## Task 6: Gate evidence fold (`_de4dot_outcome`)

**Files:**
- Modify: `src/reverse_engineering/agents/deobf_gate.py`
- Test: `tests/reverse_engineering/test_deobfuscation_agents.py`

**Interfaces:**
- Consumes: `DE4DOT_RESULT_KEY`, de4dot's `_valid_cached_result`.
- Produces: on a valid, changed `DE4DOT_RESULT_KEY` matching `plan.artifact_id`, a `tool="de4dot"` finding folded into `RECOVERY_EVIDENCE_KEY`; de4dot result/called/changed/degraded keys reset per round in `_iteration_delta`. `_recovery_called` unchanged (upx+floss).

- [ ] **Step 1: Write the failing tests** — extend `test_deobfuscation_agents.py`: (a) a round where `DE4DOT_RESULT_KEY` records a successful, changed recovery bound to the current artifact → the gate's `RECOVERY_EVIDENCE_KEY` delta contains a `tool="de4dot"` finding whose `detail` names the obfuscator and bound to the current id; (b) `_iteration_delta` resets `DE4DOT_RESULT_KEY`→None and `DE4DOT_CALLED_KEY`→False.

- [ ] **Step 2: Run to verify they fail.**

- [ ] **Step 3: Implement** — in `deobf_gate.py`:

Import from de4dot: `from reverse_engineering.tools.deobfuscation.dotnet import _valid_cached_result as _valid_de4dot_result` and the `DE4DOT_RESULT_KEY`/`DE4DOT_CALLED_KEY`/`DE4DOT_CHANGED_KEY`/`DE4DOT_DEGRADED_KEY` state keys.

Add `_de4dot_outcome` (mirrors `_scripted_outcome` — produces a mechanism finding):

```python
def _de4dot_outcome(raw: object, artifact_id: str) -> _ToolOutcome:
    """Build the de4dot evidence outcome from ``DE4DOT_RESULT_KEY`` (a mechanism
    finding), success only when de4dot changed the artifact into the current one."""
    if not isinstance(raw, dict) or not _valid_de4dot_result(raw):
        return _ToolOutcome("non_applicable", "")
    if raw["success"] is True and raw["applicable"] is True and raw["degraded"] is False and raw["changed"] is True:
        if raw.get("recovered_artifact_id") != artifact_id:
            return _ToolOutcome("non_applicable", "")
        record = {"obfuscator": str(raw.get("obfuscator_name", "unknown"))}
        return _ToolOutcome("success", "", records=(record,))
    if raw["degraded"] is True:
        code = raw.get("error_code")
        return _ToolOutcome("degraded", code if isinstance(code, str) else "result_invalid")
    return _ToolOutcome("non_applicable", "")
```

In `evaluate_deobf_gate`, after the `scripted = _scripted_outcome(...)` line, add `de4dot = _de4dot_outcome(state.get(DE4DOT_RESULT_KEY), plan.artifact_id)` and pass it to `_build_evidence(..., scripted, de4dot)`.

Extend `_build_evidence`'s signature with `de4dot: _ToolOutcome` and, after the scripted-findings block, add the de4dot fold (mirror scripted; also add `de4dot` to the `for prefix, outcome in (("upx", upx), ("floss", floss))` degraded-limitation loop → `(("upx", upx), ("floss", floss), ("de4dot", de4dot))`):

```python
    if de4dot.status == "success":
        surfaces = _stable_append(surfaces, "de4dot", 64)
        for record in de4dot.records:
            detail = json.dumps(record, sort_keys=True, separators=(",", ":"))
            identity = ("de4dot", detail)
            if identity in identities or len(findings) >= MAX_FINDINGS:
                continue
            identities.add(identity)
            findings.append(EvidenceFinding(
                artifact_id=artifact_id,
                claim=f"de4dot deobfuscated a {record['obfuscator']}-protected .NET assembly.",
                tool="de4dot", confidence=1.0, detail=detail, kind=FindingKind.METADATA,
            ))
```

In `_iteration_delta`, add the resets beside the UPX ones:

```python
        DE4DOT_RESULT_KEY: None,
        DE4DOT_CALLED_KEY: False,
        DE4DOT_CHANGED_KEY: False,
        DE4DOT_DEGRADED_KEY: False,
```

- [ ] **Step 4: Run** `rtk uv run --extra dev pytest tests/reverse_engineering/test_deobfuscation_agents.py -q` → PASS (new de4dot tests + all existing). **Step 5: Commit** `feat(deobf): gate folds de4dot deobfuscation evidence`.

---

## Task 7: Full-suite gate + live validation

**Files:** none new (validation).

- [ ] **Step 1: Full gate** — `rtk make check` → lint + format + type-check clean; full suite green (existing + all Phase 2 tests). Fix any finding inline (`rtk uv run --extra dev ruff format <files>`).

- [ ] **Step 2: Live end-to-end on the real sample** (needs the cluster + rebuilt image):
  - `make sandbox-build-images && make sandbox-up` (rebuilds `deobfuscation-tools` with de4dot).
  - `make adk-run` (or drive `src/malware_analyst`) on `/Users/alevsk/Downloads/samples/dotnet/1595d92f…exe`.
  - Confirm: `de4dot_deobfuscate` reports `applicable: True, changed: True` with the detected obfuscator; `CURRENT_ARTIFACT_KEY` advances to the deobfuscated assembly; `deep_engine_router` sends it to ILSpy; the report reflects **deobfuscated** C# (decrypted strings / real names) and a `de4dot` recovery finding + `deobfuscated ← original` provenance.
  - **Honest acceptance:** if de4dot's SmartAssembly support does not fully deobfuscate *this* build, record exactly what it did recover — the capability is delivered and the empirical result is the point. Note residue as a limitation, not a plan failure.

- [ ] **Step 3: Commit** any doc/notes updates from the live run: `test(deobf): Phase 2 full-suite gate + de4dot live-validation notes`.

---

## Self-review

**Spec coverage (§12):** §12.2 (de4dot in `deobfuscation-tools` + `recover`, self-gating) → Tasks 1/4/5; §12.3 (tool mirrors upx, de4dot-success + valid-CLR validation, not entropy) → Task 4; §12.4 (SAMPLE_FORMAT_KEY unchanged → ILSpy; evidence fold; classifier untouched) → Tasks 4/6; §12.5 extensibility recipe → the tool/agent/gate pattern is exactly the upx template; §12.6 decisions honored; §12.7 (agentic .NET deferred) → not in scope. Acceptance (live on `1595d92f`) → Task 7.

**Placeholder scan:** the only deferred specifics are de4dot's exact build pin, CLI flags, and the "Detected" marker — legitimately resolved by Task 1's probe (an external-tool unknown, not a lazy TODO), and Task 4's code is written to depend on them through one constant/pattern each. Everything else is complete code.

**Type consistency:** `DE4DOT_*` keys defined in Task 2 are consumed with identical names in Tasks 4/6; the `DE4DOT_RESULT_KEY` dict shape written in Task 4 (`obfuscator_name`, `recovered_artifact_id`, `changed`, …) is exactly what `_valid_cached_result` and `_de4dot_outcome` read in Tasks 4/6; `detect_format_bytes` (Task 3) is imported by the tool (Task 4); `de4dot`'s `_valid_cached_result` is imported by the gate (Task 6) as `_valid_de4dot_result`; provenance shape `de4dot_deobfuscate source=… destination=… obfuscator=…` matches the extended `_PROVENANCE_PATTERN` (Task 4).

**No-duplication check:** `dotnet.py` is a sibling of `upx.py` (like `floss.py`), not a verbatim copy — its cache/validation encode de4dot's own result schema (`obfuscator_name`, `not_dotnet`/`no_obfuscator`/`no_change` reasons). The genuinely-shared header-parse is extracted once (`detect_format_bytes`, Task 3) rather than re-implemented. A deeper shared recovery-tool scaffold (upx/floss/de4dot) is a worthwhile future refactor but out of Phase 2 scope (it would touch the working native path); noted for a later pass.
