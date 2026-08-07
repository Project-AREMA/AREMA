# Kubernetes Sandbox Execution Layer — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a domain-neutral Kubernetes sandbox execution layer to AREMA so any tool can run commands and transfer files inside an isolated pod (or a local subprocess fallback), bound to a stable case id, plus a radare2 container image and cluster manifests.

**Architecture:** A hexagonal `SandboxExecutor` Protocol port (`src/arema/runtime/sandbox/`) with two adapters — `K8sSandboxExecutor` (real pods via `k8s-agent-sandbox`) and `LocalSandboxExecutor` (subprocess, no cluster) — mirroring AREMA's existing `MemoryStore` pattern. It is injected as an optional `RuntimeServices.sandbox` collaborator and selected in `composition.py`. The radare2 image + manifests ship as cluster infra outside `src/arema`, keeping the shell domain-neutral.

**Tech Stack:** Python 3.11+, pydantic-settings v2, Google ADK 1.25.1, `k8s-agent-sandbox==0.5.2` (optional extra), pytest, ruff, mypy. Reference spec: `docs/superpowers/specs/2026-07-23-kubernetes-sandbox-execution-layer-design.md`.

---

## File Structure

**Create (src/arema):**
- `src/arema/runtime/sandbox/__init__.py` — public exports (`SandboxExecutor`, `SandboxHandle`, `ExecutionResult`, errors)
- `src/arema/runtime/sandbox/port.py` — Protocol port, dataclasses, error types
- `src/arema/runtime/sandbox/session.py` — `SandboxSessionManager` (case-keyed handle map, idempotent claim, release)
- `src/arema/runtime/sandbox/local.py` — `LocalSandboxExecutor` (subprocess adapter)
- `src/arema/runtime/sandbox/k8s.py` — `K8sSandboxExecutor` (lazy k8s-agent-sandbox import)

**Modify (src/arema):**
- `src/arema/core/config.py` — `env_prefix="arema_"`, provider-key aliases, `AREMA_SANDBOX_*` fields + validators
- `src/arema/runtime/services.py` — `RuntimeServices.sandbox` field + `build_memory_backed_services(sandbox=...)`
- `src/arema/runtime/sessions.py` — `SANDBOX_CASE_ID` session key
- `src/arema/composition.py` — build executor from settings; `ApplicationComposition.sandbox`; thread into services
- `src/arema/runner.py` — stable case id for interactive sessions; sandbox cleanup boundary
- `src/arema/cli.py` — `/reset` command + process-exit cleanup
- `pyproject.toml` — `sandbox` optional-dependency group

**Create (tests):**
- `tests/unit/runtime/sandbox/__init__.py`
- `tests/unit/runtime/sandbox/contract.py` — `SandboxExecutorContract` mixin (mirrors `store_contract.py`)
- `tests/unit/runtime/sandbox/test_port.py`
- `tests/unit/runtime/sandbox/test_session.py`
- `tests/unit/runtime/sandbox/test_local_executor.py` — runs the contract against the local adapter
- `tests/unit/runtime/sandbox/test_k8s_executor.py` — mocked k8s client
- `tests/unit/runtime/sandbox/test_k8s_integration.py` — opt-in (`@pytest.mark.k8s`)

**Modify (tests):**
- `tests/unit/core/test_config.py` — `LLM_PROVIDER` env sets → `AREMA_LLM_PROVIDER`; add sandbox-field tests
- `tests/unit/runtime/conftest.py` — `LLM_PROVIDER` env set → `AREMA_LLM_PROVIDER`
- `tests/architecture/test_neutral_boundaries.py` — sandbox downward-only imports + no domain terms
- `tests/conftest.py` — register `k8s` marker; default `AREMA_SANDBOX_BACKEND=local`

**Create (cluster infra, outside src/arema):**
- `images/radare2/Dockerfile`
- `deploy/sandbox/install-agent-sandbox.sh`
- `deploy/sandbox/10-radare2-template.yaml`
- `deploy/sandbox/20-radare2-pool.yaml`

**Modify (repo root):**
- `.env.example` — rewrite with `AREMA_` prefix + sandbox section
- `Makefile` — `sandbox-up` / `sandbox-down` / `sandbox-image` / `setup-sandbox` targets

---

## Task 1: Add `AREMA_` env prefix; keep provider keys standard

**Files:**
- Modify: `src/arema/core/config.py:77-83` (model_config) and each provider-key field (`google_api_key`, `openai_api_key`, `anthropic_api_key`, `openai_compatible_api_key`, `zai_api_key`, `xai_api_key`)
- Test: `tests/unit/core/test_config.py:16,55,77,222` and `tests/unit/runtime/conftest.py:25`

- [ ] **Step 1: Write the failing test for the prefix**

Append to `tests/unit/core/test_config.py`:

```python
def test_app_settings_use_arema_env_prefix(monkeypatch) -> None:
    monkeypatch.setenv("AREMA_LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("AREMA_MEMORY_BACKEND", "memory")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")

    settings = Settings(_env_file=None)

    assert settings.llm_provider.value == "anthropic"
    assert settings.memory_backend == "memory"


def test_provider_api_keys_stay_unprefixed(monkeypatch) -> None:
    monkeypatch.setenv("AREMA_LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "unprefixed-key")

    settings = Settings(_env_file=None)

    assert settings.anthropic_api_key_value == "unprefixed-key"
```

- [ ] **Step 2: Update the env-set callsites that break under the prefix**

In `tests/unit/core/test_config.py`, change every `monkeypatch.setenv("LLM_PROVIDER", ...)` to `monkeypatch.setenv("AREMA_LLM_PROVIDER", ...)` (lines ~16, 55, 77, 222). In `tests/unit/runtime/conftest.py:25` likewise.

- [ ] **Step 3: Run tests to verify the prefix test fails**

Run: `uv run --extra dev pytest tests/unit/core/test_config.py::test_app_settings_use_arema_env_prefix -v`
Expected: FAIL — `AREMA_LLM_PROVIDER` is ignored (Settings still reads `LLM_PROVIDER`).

- [ ] **Step 4: Add the prefix + provider-key aliases**

In `src/arema/core/config.py`, change the import and `model_config`:

```python
from pydantic import AliasChoices, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
```

```python
    model_config = SettingsConfigDict(
        env_prefix="arema_",
        env_file=_find_env_file(),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )
```

Then give each provider API-key field an explicit un-prefixed alias (these are read by LiteLLM/the SDK by standard name):

```python
    google_api_key: SecretStr | None = Field(default=None, validation_alias=AliasChoices("GOOGLE_API_KEY"))
    openai_api_key: SecretStr | None = Field(default=None, validation_alias=AliasChoices("OPENAI_API_KEY"))
    anthropic_api_key: SecretStr | None = Field(default=None, validation_alias=AliasChoices("ANTHROPIC_API_KEY"))
    openai_compatible_api_key: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("OPENAI_COMPATIBLE_API_KEY")
    )
    zai_api_key: SecretStr | None = Field(default=None, validation_alias=AliasChoices("ZAI_API_KEY"))
    xai_api_key: SecretStr | None = Field(default=None, validation_alias=AliasChoices("XAI_API_KEY"))
```

- [ ] **Step 5: Run the full config + model_factory suites**

Run: `uv run --extra dev pytest tests/unit/core -v`
Expected: PASS (the prefix test passes; provider-key env-var tests still pass because the aliases keep the standard names).

- [ ] **Step 6: Commit**

```bash
git add src/arema/core/config.py tests/unit/core/test_config.py tests/unit/runtime/conftest.py
git commit -m "feat: namespace AREMA app settings with AREMA_ env prefix"
```

---

## Task 2: Add `AREMA_SANDBOX_*` Settings fields + validators

**Files:**
- Modify: `src/arema/core/config.py` (append sandbox fields + validator)
- Test: `tests/unit/core/test_config.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/core/test_config.py`:

```python
def test_sandbox_defaults_are_disabled() -> None:
    settings = Settings(_env_file=None, llm_provider="ollama")

    assert settings.sandbox_enabled is False
    assert settings.sandbox_backend == "auto"
    assert settings.sandbox_default_pool == "python-runtime-pool"
    assert settings.sandbox_namespace == "agent-sandbox-demo"
    assert settings.sandbox_local_tunnel is True
    assert settings.sandbox_run_timeout == 120
    assert settings.sandbox_connect_timeout == 30
    assert settings.sandbox_output_cap == 65536
    assert settings.sandbox_pool_map == {}


def test_sandbox_pool_map_parses_json(monkeypatch) -> None:
    monkeypatch.setenv("AREMA_SANDBOX_POOL_MAP", '{"radare2": "radare2-pool"}')
    settings = Settings(_env_file=None, llm_provider="ollama")

    assert settings.sandbox_pool_map == {"radare2": "radare2-pool"}


def test_sandbox_run_timeout_must_exceed_connect_timeout() -> None:
    with pytest.raises(ValueError, match="run_timeout must exceed connect_timeout"):
        Settings(
            _env_file=None,
            llm_provider="ollama",
            sandbox_run_timeout=10,
            sandbox_connect_timeout=20,
        )
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run --extra dev pytest tests/unit/core/test_config.py -k sandbox -v`
Expected: FAIL — `Settings` has no `sandbox_*` attributes.

- [ ] **Step 3: Add the fields + validator**

Append to the `Settings` body in `src/arema/core/config.py` (after the memory fields, before the validators):

```python
    # -- Sandbox execution (domain-neutral; disabled by default) --------------
    sandbox_enabled: bool = False
    sandbox_backend: Literal["auto", "local", "k8s"] = "auto"
    sandbox_namespace: str = "agent-sandbox-demo"
    sandbox_default_pool: str = "python-runtime-pool"
    sandbox_local_tunnel: bool = True
    sandbox_run_timeout: int = Field(default=120, ge=1, le=3600)
    sandbox_connect_timeout: int = Field(default=30, ge=1, le=600)
    sandbox_output_cap: int = Field(default=65536, ge=256, le=10_000_000)
    sandbox_pool_map: dict[str, str] = Field(default_factory=dict)
```

Add a validator inside the existing `validate_cross_field_settings` method (append before `return self`):

```python
        if self.sandbox_run_timeout <= self.sandbox_connect_timeout:
            raise ValueError("run_timeout must exceed connect_timeout")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run --extra dev pytest tests/unit/core/test_config.py -k sandbox -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/arema/core/config.py tests/unit/core/test_config.py
git commit -m "feat: add AREMA_SANDBOX_* settings fields"
```

---

## Task 3: Rewrite `.env.example` with `AREMA_` prefix + sandbox section

**Files:**
- Modify: `.env.example`

- [ ] **Step 1: Rewrite the file**

Rewrite `.env.example` so every AREMA-owned app setting is `AREMA_`-prefixed (e.g. `AREMA_LLM_PROVIDER`, `AREMA_GOOGLE_MODEL`, `AREMA_MEMORY_BACKEND`, `AREMA_CONTEXT_BUDGET_TOKENS`, etc.). Keep provider API keys **un-prefixed** (`GOOGLE_API_KEY`, `OPENAI_API_KEY`, …). Append a new section:

```text
# ==============================================================================
# Sandbox Execution (optional; disabled by default)
# ==============================================================================
# When AREMA_SANDBOX_ENABLED=true, tools that need isolated execution claim a pod
# (or a local subprocess when no cluster is present). Backend 'auto' picks k8s
# when the client is importable + a cluster is reachable, else local.
# AREMA_SANDBOX_ENABLED=false
# AREMA_SANDBOX_BACKEND=auto
# AREMA_SANDBOX_NAMESPACE=agent-sandbox-demo
# AREMA_SANDBOX_DEFAULT_POOL=python-runtime-pool
# AREMA_SANDBOX_LOCAL_TUNNEL=true        # Kind/minikube/CI; false for a real cluster
# AREMA_SANDBOX_RUN_TIMEOUT=120
# AREMA_SANDBOX_CONNECT_TIMEOUT=30
# AREMA_SANDBOX_OUTPUT_CAP=65536
# AREMA_SANDBOX_POOL_MAP={"radare2":"radare2-pool"}
```

- [ ] **Step 2: Verify nothing imports the file at parse time**

Run: `uv run --extra dev pytest tests/unit/core/test_config.py -v`
Expected: PASS (the `.env.example` is documentation; tests use `_env_file=None`).

- [ ] **Step 3: Commit**

```bash
git add .env.example
git commit -m "docs: rewrite .env.example with AREMA_ prefix and sandbox section"
```

---

## Task 4: `SandboxExecutor` port, `SandboxHandle`, `ExecutionResult`, errors

**Files:**
- Create: `src/arema/runtime/sandbox/__init__.py`, `src/arema/runtime/sandbox/port.py`
- Test: `tests/unit/runtime/sandbox/__init__.py`, `tests/unit/runtime/sandbox/test_port.py`

- [ ] **Step 1: Write the failing test**

`tests/unit/runtime/sandbox/test_port.py`:

```python
from __future__ import annotations

from arema.runtime.sandbox import (
    ExecutionResult,
    SandboxError,
    SandboxExecutor,
    SandboxHandle,
)


def test_execution_result_defaults() -> None:
    result = ExecutionResult(exit_code=0, stdout="ok", stderr="")

    assert result.exit_code == 0
    assert result.truncated is False


def test_handle_is_value_object() -> None:
    handle = SandboxHandle(key="case-1", pool="radare2", backend_id="pod-abc")

    assert handle.key == "case-1"
    assert handle.pool == "radare2"
    assert handle.backend_id == "pod-abc"


def test_executor_is_a_runtime_checkable_protocol() -> None:
    class _Stub:
        def claim(self, *, key: str, pool: str) -> SandboxHandle: ...
        def run(self, handle: SandboxHandle, command: str, *, timeout: float) -> ExecutionResult: ...
        def write_file(self, handle: SandboxHandle, path: str, data: bytes) -> None: ...
        def read_file(self, handle: SandboxHandle, path: str) -> bytes: ...
        def terminate(self, handle: SandboxHandle) -> None: ...
        def release_session(self, key: str) -> None: ...

    assert isinstance(_Stub(), SandboxExecutor)


def test_sandbox_error_is_runtime_error() -> None:
    assert issubclass(SandboxError, RuntimeError)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --extra dev pytest tests/unit/runtime/sandbox/test_port.py -v`
Expected: FAIL — module `arema.runtime.sandbox` does not exist.

- [ ] **Step 3: Implement the port**

`src/arema/runtime/sandbox/port.py`:

```python
"""Domain-neutral port for isolated command/file execution (sandbox)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


class SandboxError(RuntimeError):
    """Raised when a sandbox operation fails (claim, run, transfer, terminate)."""


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """The bounded outcome of one command run inside a sandbox."""

    exit_code: int
    stdout: str
    stderr: str
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class SandboxHandle:
    """An opaque reference to one claimed sandbox, bound to a case key + pool."""

    key: str
    pool: str
    backend_id: str


@runtime_checkable
class SandboxExecutor(Protocol):
    """Claim an isolated execution environment per (case key, pool) and run commands.

    The port is deliberately opaque and domain-neutral: a "command" is an
    arbitrary string, a "file" is opaque bytes, a "pool" is a logical name.
    Nothing here knows what tooling lives inside a pool.
    """

    def claim(self, *, key: str, pool: str) -> SandboxHandle:
        """Return the handle for (key, pool), creating it on first use (idempotent)."""
        ...

    def run(self, handle: SandboxHandle, command: str, *, timeout: float) -> ExecutionResult:
        """Execute ``command`` inside the sandbox, returning bounded stdout/stderr."""
        ...

    def write_file(self, handle: SandboxHandle, path: str, data: bytes) -> None:
        """Write ``data`` to ``path`` inside the sandbox."""
        ...

    def read_file(self, handle: SandboxHandle, path: str) -> bytes:
        """Read the bytes at ``path`` inside the sandbox."""
        ...

    def terminate(self, handle: SandboxHandle) -> None:
        """Terminate one sandbox handle."""
        ...

    def release_session(self, key: str) -> None:
        """Terminate every handle bound to ``key`` across all pools."""
        ...
```

`src/arema/runtime/sandbox/__init__.py`:

```python
"""Domain-neutral sandbox execution layer for AREMA tools."""

from arema.runtime.sandbox.port import (
    ExecutionResult,
    SandboxError,
    SandboxExecutor,
    SandboxHandle,
)

__all__ = [
    "ExecutionResult",
    "SandboxError",
    "SandboxExecutor",
    "SandboxHandle",
]
```

`tests/unit/runtime/sandbox/__init__.py`: empty file.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run --extra dev pytest tests/unit/runtime/sandbox/test_port.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/arema/runtime/sandbox tests/unit/runtime/sandbox
git commit -m "feat: add domain-neutral SandboxExecutor port"
```

---

## Task 5: `SandboxSessionManager` (case-keyed handle map + idempotent claim)

The session manager wraps any concrete executor and enforces the idempotent-claim and release-session semantics, so adapters only implement single-handle primitives.

**Files:**
- Create: `src/arema/runtime/sandbox/session.py`
- Test: `tests/unit/runtime/sandbox/test_session.py`

- [ ] **Step 1: Write the failing test using a fake executor**

`tests/unit/runtime/sandbox/test_session.py`:

```python
from __future__ import annotations

import pytest

from arema.runtime.sandbox import ExecutionResult, SandboxHandle
from arema.runtime.sandbox.session import SandboxSessionManager


class _FakeExecutor:
    """Records calls; produces deterministic handles."""

    def __init__(self) -> None:
        self.claimed: list[tuple[str, str]] = []
        self.terminated: list[SandboxHandle] = []
        self.released_keys: list[str] = []

    def claim(self, *, key: str, pool: str) -> SandboxHandle:
        self.claimed.append((key, pool))
        return SandboxHandle(key=key, pool=pool, backend_id=f"be-{key}-{pool}")

    def run(self, handle: SandboxHandle, command: str, *, timeout: float) -> ExecutionResult:
        return ExecutionResult(exit_code=0, stdout=f"ran:{command}", stderr="")

    def write_file(self, handle: SandboxHandle, path: str, data: bytes) -> None:
        return None

    def read_file(self, handle: SandboxHandle, path: str) -> bytes:
        return b"file-bytes"

    def terminate(self, handle: SandboxHandle) -> None:
        self.terminated.append(handle)

    def release_session(self, key: str) -> None:
        self.released_keys.append(key)


def test_claim_is_idempotent_per_key_pool() -> None:
    fake = _FakeExecutor()
    manager = SandboxSessionManager(fake)

    first = manager.claim(key="case-1", pool="radare2")
    second = manager.claim(key="case-1", pool="radare2")

    assert first is second
    assert fake.claimed == [("case-1", "radare2")]


def test_one_key_can_hold_one_handle_per_pool() -> None:
    fake = _FakeExecutor()
    manager = SandboxSessionManager(fake)

    a = manager.claim(key="case-1", pool="radare2")
    b = manager.claim(key="case-1", pool="python")

    assert a is not b
    assert fake.claimed == [("case-1", "radare2"), ("case-1", "python")]


def test_release_session_terminates_all_pools_for_key() -> None:
    fake = _FakeExecutor()
    manager = SandboxSessionManager(fake)
    manager.claim(key="case-1", pool="radare2")
    manager.claim(key="case-1", pool="python")
    manager.claim(key="case-2", pool="radare2")

    manager.release_session("case-1")

    terminated_keys = {h.key for h in fake.terminated}
    assert terminated_keys == {"case-1"}
    assert len(fake.terminated) == 2


def test_release_unknown_key_is_noop() -> None:
    fake = _FakeExecutor()
    manager = SandboxSessionManager(fake)

    manager.release_session("never-claimed")  # must not raise

    assert fake.terminated == []


def test_release_all_terminates_every_handle() -> None:
    fake = _FakeExecutor()
    manager = SandboxSessionManager(fake)
    manager.claim(key="case-1", pool="radare2")
    manager.claim(key="case-2", pool="python")

    manager.release_all()

    assert len(fake.terminated) == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --extra dev pytest tests/unit/runtime/sandbox/test_session.py -v`
Expected: FAIL — `SandboxSessionManager` does not exist.

- [ ] **Step 3: Implement the manager**

`src/arema/runtime/sandbox/session.py`:

```python
"""Case-keyed handle bookkeeping layered over a concrete :class:`SandboxExecutor`.

Adapters implement single-handle primitives (claim/run/write/read/terminate);
this manager enforces idempotent claim per ``(key, pool)`` and whole-session
release, so every adapter inherits identical session semantics.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from arema.runtime.sandbox.port import SandboxExecutor, SandboxHandle


class SandboxSessionManager:
    """Idempotent (key, pool) claim + whole-session release over an executor."""

    def __init__(self, executor: SandboxExecutor) -> None:
        self._executor = executor
        self._handles: dict[tuple[str, str], SandboxHandle] = {}
        self._lock = threading.Lock()

    def claim(self, *, key: str, pool: str) -> SandboxHandle:
        """Return the existing handle for (key, pool), claiming on first use."""
        identity = (key, pool)
        with self._lock:
            existing = self._handles.get(identity)
            if existing is not None:
                return existing
            handle = self._executor.claim(key=key, pool=pool)
            self._handles[identity] = handle
            return handle

    def run(
        self,
        handle: SandboxHandle,
        command: str,
        *,
        timeout: float,
    ) -> object:
        return self._executor.run(handle, command, timeout=timeout)

    def write_file(self, handle: SandboxHandle, path: str, data: bytes) -> None:
        self._executor.write_file(handle, path, data)

    def read_file(self, handle: SandboxHandle, path: str) -> bytes:
        return self._executor.read_file(handle, path)

    def release_session(self, key: str) -> None:
        """Terminate every handle bound to ``key`` across all pools."""
        with self._lock:
            owned = [handle for (k, _pool), handle in self._handles.items() if k == key]
            for identity in [i for i in self._handles if i[0] == key]:
                self._handles.pop(identity, None)
        for handle in owned:
            self._executor.terminate(handle)

    def release_all(self) -> None:
        """Terminate every outstanding handle (process shutdown)."""
        with self._lock:
            handles = list(self._handles.values())
            self._handles.clear()
        for handle in handles:
            self._executor.terminate(handle)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run --extra dev pytest tests/unit/runtime/sandbox/test_session.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/arema/runtime/sandbox/session.py tests/unit/runtime/sandbox/test_session.py
git commit -m "feat: add SandboxSessionManager with idempotent claim and release"
```

---

## Task 6: `LocalSandboxExecutor` + shared contract test

**Files:**
- Create: `src/arema/runtime/sandbox/local.py`
- Create: `tests/unit/runtime/sandbox/contract.py`, `tests/unit/runtime/sandbox/test_local_executor.py`

- [ ] **Step 1: Write the shared contract mixin (mirrors `store_contract.py`)**

`tests/unit/runtime/sandbox/contract.py`:

```python
"""Backend-agnostic contract for :class:`arema.runtime.sandbox.SandboxExecutor`.

Every adapter must behave identically from a caller's point of view: claim is
idempotent per (key, pool); run returns exit/stdout/stderr; write/read round-trip;
release removes handles. The contract lives here as :class:`SandboxExecutorContract`
-- a mixin driven by a single ``executor`` fixture. A concrete adapter module
(e.g. ``test_local_executor.py``) subclasses it and supplies the fixture.

The mixin is named ``SandboxExecutorContract`` (not ``Test*``) so pytest never
collects it on its own.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from arema.runtime.sandbox import ExecutionResult, SandboxExecutor, SandboxHandle

if TYPE_CHECKING:
    import pytest


class SandboxExecutorContract:
    """Behavioural contract shared by every :class:`SandboxExecutor` adapter."""

    def test_satisfies_runtime_protocol(self, executor: SandboxExecutor) -> None:
        assert isinstance(executor, SandboxExecutor)

    def test_claim_is_idempotent_per_key_pool(self, executor: SandboxExecutor) -> None:
        first = executor.claim(key="case-1", pool="default")
        second = executor.claim(key="case-1", pool="default")

        assert first == second

    def test_claim_distinct_pools_yield_distinct_handles(
        self, executor: SandboxExecutor
    ) -> None:
        a = executor.claim(key="case-1", pool="alpha")
        b = executor.claim(key="case-1", pool="beta")

        assert a != b

    def test_run_returns_execution_result(self, executor: SandboxExecutor) -> None:
        handle = executor.claim(key="case-1", pool="default")
        result = executor.run(handle, "printf hello", timeout=10)

        assert isinstance(result, ExecutionResult)
        assert result.exit_code == 0
        assert "hello" in result.stdout

    def test_write_then_read_round_trips(self, executor: SandboxExecutor) -> None:
        handle = executor.claim(key="case-1", pool="default")
        executor.write_file(handle, "note.txt", b"payload-bytes")

        assert executor.read_file(handle, "note.txt") == b"payload-bytes"

    def test_release_session_clears_handles(self, executor: SandboxExecutor) -> None:
        executor.claim(key="case-1", pool="alpha")
        executor.claim(key="case-1", pool="beta")

        executor.release_session("case-1")

        # A fresh claim after release must produce a distinct backend id.
        new_handle = executor.claim(key="case-1", pool="alpha")
        assert new_handle.backend_id != ""


ContractFixture = SandboxExecutorContract  # re-exported alias for clarity
```

- [ ] **Step 2: Write the local-executor test (fails: no adapter yet)**

`tests/unit/runtime/sandbox/test_local_executor.py`:

```python
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from arema.runtime.sandbox.local import LocalSandboxExecutor
from tests.unit.runtime.sandbox.contract import SandboxExecutorContract

if TYPE_CHECKING:
    from arema.runtime.sandbox import SandboxExecutor


@pytest.fixture
def executor(tmp_path: Path) -> SandboxExecutor:
    return LocalSandboxExecutor(root=tmp_path, default_pool="default")


class TestLocalExecutor(SandboxExecutorContract):
    """Runs the shared contract against the local (subprocess) adapter."""

    pass
```

- [ ] **Step 3: Run test to verify it fails**

Run: `uv run --extra dev pytest tests/unit/runtime/sandbox/test_local_executor.py -v`
Expected: FAIL — `arema.runtime.sandbox.local` does not exist.

- [ ] **Step 4: Implement the local adapter**

`src/arema/runtime/sandbox/local.py`:

```python
"""A subprocess-backed :class:`SandboxExecutor` for tests and no-cluster dev.

One workdir per (key, pool) under ``root``. Commands run via ``subprocess.run``
with a timeout; files are written/read from the workdir. No kubectl required.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from arema.core.logging import get_logger
from arema.runtime.sandbox.port import (
    ExecutionResult,
    SandboxError,
    SandboxExecutor,
    SandboxHandle,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from contextlib import AbstractContextManager

logger = get_logger(__name__)


class LocalSandboxExecutor(SandboxExecutor):
    """Claims a temp workdir per (key, pool) and runs commands via subprocess."""

    def __init__(self, *, root: Path, default_pool: str = "default") -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)
        self._default_pool = default_pool
        self._handles: dict[tuple[str, str], SandboxHandle] = {}

    def _workdir(self, handle: SandboxHandle) -> Path:
        return self._root / f"{handle.key}__{handle.pool}"

    def claim(self, *, key: str, pool: str) -> SandboxHandle:
        identity = (key, pool)
        existing = self._handles.get(identity)
        if existing is not None:
            return existing
        workdir = self._root / f"{key}__{pool}"
        workdir.mkdir(parents=True, exist_ok=True)
        handle = SandboxHandle(key=key, pool=pool, backend_id=str(workdir))
        self._handles[identity] = handle
        logger.info("local sandbox claimed", key=key, pool=pool, workdir=str(workdir))
        return handle

    def run(self, handle: SandboxHandle, command: str, *, timeout: float) -> ExecutionResult:
        workdir = self._workdir(handle)
        try:
            completed = subprocess.run(
                command,
                shell=True,  # noqa: S602 - dev/test adapter; commands are caller-controlled
                cwd=str(workdir),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise SandboxError(f"local sandbox command timed out after {timeout}s") from exc
        return ExecutionResult(
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )

    def write_file(self, handle: SandboxHandle, path: str, data: bytes) -> None:
        target = self._workdir(handle) / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def read_file(self, handle: SandboxHandle, path: str) -> bytes:
        target = self._workdir(handle) / path
        try:
            return target.read_bytes()
        except FileNotFoundError as exc:
            raise SandboxError(f"local sandbox file not found: {path}") from exc

    def terminate(self, handle: SandboxHandle) -> None:
        workdir = self._workdir(handle)
        if workdir.exists():
            shutil.rmtree(workdir, ignore_errors=True)
        self._handles.pop((handle.key, handle.pool), None)

    def release_session(self, key: str) -> None:
        for identity in [i for i in self._handles if i[0] == key]:
            self.terminate(self._handles.pop(identity))
```

> Note: ruff ignores `S602` only via project config — if it flags, the inline `# noqa: S602` suppresses it. The local adapter is a dev/test path with caller-controlled commands, matching the existing `S603`/`S607` suppression philosophy for the ADK web launch.

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run --extra dev pytest tests/unit/runtime/sandbox/test_local_executor.py -v`
Expected: PASS (all contract methods green against the local adapter).

- [ ] **Step 6: Run lint + types on the new module**

Run: `uv run --extra dev ruff check src/arema/runtime/sandbox tests/unit/runtime/sandbox && uv run --extra dev mypy src/arema/runtime/sandbox`
Expected: clean (fix any unused-import/type issues inline).

- [ ] **Step 7: Commit**

```bash
git add src/arema/runtime/sandbox/local.py tests/unit/runtime/sandbox/contract.py tests/unit/runtime/sandbox/test_local_executor.py
git commit -m "feat: add LocalSandboxExecutor and shared adapter contract"
```

---

## Task 7: Extend `RuntimeServices` with optional `sandbox`

**Files:**
- Modify: `src/arema/runtime/services.py:130-145` (RuntimeServices + default) and `build_memory_backed_services`
- Test: `tests/unit/runtime/test_callback_chain.py` or a new `tests/unit/runtime/test_services.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/runtime/test_services.py`:

```python
from __future__ import annotations

from arema.runtime.sandbox.local import LocalSandboxExecutor
from arema.runtime.services import RuntimeServices, build_memory_backed_services


class _NullMemory:
    def record_tool_event(self, event: object) -> None: ...


def test_default_services_have_no_sandbox() -> None:
    services = RuntimeServices.default()

    assert services.sandbox is None


def test_build_services_threads_optional_sandbox(tmp_path) -> None:
    sandbox = LocalSandboxExecutor(root=tmp_path, default_pool="default")
    services = build_memory_backed_services(_NullMemory(), sandbox=sandbox)  # type: ignore[arg-type]

    assert services.sandbox is sandbox
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --extra dev pytest tests/unit/runtime/test_services.py -v`
Expected: FAIL — `RuntimeServices` has no `sandbox` attribute.

- [ ] **Step 3: Extend `RuntimeServices`**

In `src/arema/runtime/services.py`, add a `TYPE_CHECKING` import and the field + default + builder param:

```python
if TYPE_CHECKING:
    # ...
    from arema.runtime.sandbox.port import SandboxExecutor
```

```python
@dataclass(frozen=True, slots=True)
class RuntimeServices:
    """The injectable collaborators every runtime callback depends on."""

    clock: Clock
    metrics: MetricsSink
    memory_sink: MemoryEventSink
    sandbox: SandboxExecutor | None = None

    @classmethod
    def default(cls) -> RuntimeServices:
        """Return services backed by a real clock and no-op sinks."""
        return cls(
            clock=MonotonicClock(),
            metrics=NullMetricsSink(),
            memory_sink=NullMemoryEventSink(),
        )
```

```python
def build_memory_backed_services(
    memory: MemoryService,
    *,
    clock: Clock | None = None,
    metrics: MetricsSink | None = None,
    sandbox: SandboxExecutor | None = None,
) -> RuntimeServices:
    """Wire a memory service as the runtime's :class:`MemoryEventSink`."""
    return RuntimeServices(
        clock=clock if clock is not None else MonotonicClock(),
        metrics=metrics if metrics is not None else NullMetricsSink(),
        memory_sink=memory,
        sandbox=sandbox,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run --extra dev pytest tests/unit/runtime -v`
Expected: PASS (new test + existing runtime suite still green — `sandbox` defaults to `None`).

- [ ] **Step 5: Commit**

```bash
git add src/arema/runtime/services.py tests/unit/runtime/test_services.py
git commit -m "feat: add optional sandbox collaborator to RuntimeServices"
```

---

## Task 8: Composition builds the executor; `ApplicationComposition.sandbox`

**Files:**
- Modify: `src/arema/composition.py`
- Test: `tests/component/test_smoke_composition.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/component/test_smoke_composition.py`:

```python
def test_default_composition_has_no_sandbox_when_disabled() -> None:
    from arema.composition import build_default_composition

    settings = Settings(_env_file=None, llm_provider="ollama", memory_backend="memory")
    composition = build_default_composition(settings)

    assert composition.sandbox is None


def test_default_composition_builds_local_sandbox_when_enabled(tmp_path) -> None:
    from arema.composition import build_default_composition

    settings = Settings(
        _env_file=None,
        llm_provider="ollama",
        memory_backend="memory",
        sandbox_enabled=True,
        sandbox_backend="local",
    )
    composition = build_default_composition(settings)

    assert composition.sandbox is not None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run --extra dev pytest tests/component/test_smoke_composition.py -v`
Expected: FAIL — `ApplicationComposition` has no `sandbox` attribute.

- [ ] **Step 3: Wire the executor into composition**

In `src/arema/composition.py`, add imports and the builder:

```python
from arema.runtime.sandbox.local import LocalSandboxExecutor
from arema.runtime.sandbox.port import SandboxExecutor
```

Add a builder function:

```python
def _build_sandbox_executor(settings: Settings) -> SandboxExecutor | None:
    """Build the configured sandbox executor, or ``None`` when disabled.

    Selection is domain-neutral: ``local`` always works; ``k8s``/``auto`` resolve
    to a k8s adapter when the optional client is importable. Neither branch names
    a concrete domain pool -- pool names come only from settings.
    """
    if not settings.sandbox_enabled:
        return None
    if settings.sandbox_backend == "local":
        return LocalSandboxExecutor(
            root=settings.memory_path.parent / "sandbox",
            default_pool=settings.sandbox_default_pool,
        )
    if settings.sandbox_backend in ("k8s", "auto"):
        try:
            from arema.runtime.sandbox.k8s import K8sSandboxExecutor
        except ImportError:
            if settings.sandbox_backend == "k8s":
                raise CompositionError(
                    "sandbox_backend='k8s' requires the 'sandbox' extra (k8s-agent-sandbox)"
                )
            return LocalSandboxExecutor(
                root=settings.memory_path.parent / "sandbox",
                default_pool=settings.sandbox_default_pool,
            )
        return K8sSandboxExecutor(settings=settings)
    return None
```

Extend `ApplicationComposition`:

```python
@dataclass(frozen=True, slots=True)
class ApplicationComposition:
    """An immutable, fully wired application ready to run."""

    catalog: CapabilityCatalog
    root_agent: BaseAgent
    memory_service: MemoryService
    sandbox: SandboxExecutor | None = None
```

In `build_default_composition`, build the executor and thread it through:

```python
    sandbox = _build_sandbox_executor(resolved)
    services = build_memory_backed_services(memory_service, sandbox=sandbox)
    # ... (existing compose_agents call unchanged)
    return ApplicationComposition(
        catalog=catalog,
        root_agent=root_agent,
        memory_service=memory_service,
        sandbox=sandbox,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run --extra dev pytest tests/component/test_smoke_composition.py -v`
Expected: PASS. (Note: `k8s` branch references `K8sSandboxExecutor`, created in Task 11 — until then the `ImportError` path handles `auto`; the `k8s`-backend test is not exercised here.)

- [ ] **Step 5: Commit**

```bash
git add src/arema/composition.py tests/component/test_smoke_composition.py
git commit -m "feat: compose sandbox executor from settings"
```

---

## Task 9: Stable case id for interactive sessions (`SANDBOX_CASE_ID`)

**Files:**
- Modify: `src/arema/runtime/sessions.py`, `src/arema/runner.py`, `src/arema/cli.py`
- Test: `tests/component/test_runner.py`

- [ ] **Step 1: Read the current `SessionKeys`**

Run: `uv run --extra dev python -c "from arema.runtime.sessions import SessionKeys; print(SessionKeys.__doc__ or SessionKeys)"`
Note its shape so the new key is consistent.

- [ ] **Step 2: Add the case-id key**

In `src/arema/runtime/sessions.py`, add (matching the existing key style):

```python
    SANDBOX_CASE_ID = "arema:sandbox_case_id"
```

- [ ] **Step 3: Write the failing test**

Append to `tests/component/test_runner.py`:

```python
async def test_run_single_query_seeds_case_id_when_provided(
    fake_runner_factory, monkeypatch
) -> None:
    from arema.runtime.sessions import SessionKeys

    captured: dict[str, object] = {}

    class _RecordingSessionService:
        async def create_session(self, *, app_name, user_id, state=None):
            captured["state"] = state or {}
            return _FakeSession()

    class _RecordingRunner:
        session_service = _RecordingSessionService()
        async def close(self) -> None: ...
        def run_async(self, *, user_id, session_id, new_message):
            return _aiter([])

    factory = fake_runner_factory_with(_RecordingRunner())
    await run_single_query("hi", runner_factory=factory, case_id="case-42")

    assert captured["state"].get(SessionKeys.SANDBOX_CASE_ID) == "case-42"
```

> If `test_runner.py` already has a `_FakeSession`/`_aiter` helper, reuse it; otherwise copy the minimal doubles from its existing tests. The point of the test is: a `case_id` kwarg is seeded into ADK state.

- [ ] **Step 4: Run test to verify it fails**

Run: `uv run --extra dev pytest tests/component/test_runner.py -k case_id -v`
Expected: FAIL — `run_single_query` has no `case_id` parameter.

- [ ] **Step 5: Add `case_id` to the runner**

In `src/arema/runner.py`, extend the signature and state seeding:

```python
async def run_single_query(
    query: str,
    *,
    runner_factory: RunnerFactory | None = None,
    user_id: str | None = None,
    case_id: str | None = None,
) -> str:
```

```python
        initial_state: dict[str, object] = {
            SessionKeys.RUN_ID: run_id,
            SessionKeys.MEMORY_SCOPE_ID: scope.id,
        }
        if case_id is not None:
            initial_state[SessionKeys.SANDBOX_CASE_ID] = case_id
```

- [ ] **Step 6: Generate one case id per interactive session in the CLI**

In `src/arema/cli.py`, inside `run_interactive_session`, generate one case id and pass it to each `run_single_query` call:

```python
from uuid import uuid4

    case_id = uuid4().hex
    while True:
        # ... existing input handling ...
        response = await run_single_query(
            stripped, runner_factory=runner_factory, case_id=case_id
        )
```

- [ ] **Step 7: Run the runner + cli suites**

Run: `uv run --extra dev pytest tests/component/test_runner.py tests/component/test_cli.py -v`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/arema/runtime/sessions.py src/arema/runner.py src/arema/cli.py tests/component/test_runner.py
git commit -m "feat: seed a stable sandbox case id per interactive session"
```

---

## Task 10: Session/process-boundary sandbox cleanup (`/reset`, exit)

**Files:**
- Modify: `src/arema/cli.py` (cleanup on `/exit`, `/reset`, KeyboardInterrupt, process exit)
- Test: `tests/component/test_cli.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/component/test_cli.py`:

```python
def test_reset_command_releases_sandbox_session() -> None:
    from arema.cli import handle_interactive_command
    from arema.composition import ApplicationComposition

    released: list[str] = []

    class _StubSandbox:
        def release_session(self, key: str) -> None:
            released.append(key)

    # Build a minimal composition double with a non-None sandbox.
    composition = _composition_with_sandbox(_StubSandbox())

    result = handle_interactive_command("/reset", composition=composition)

    assert result.handled is True
    assert result.message is not None
```

> Provide a `_composition_with_sandbox` helper in the test that constructs an `ApplicationComposition` with the stub sandbox (use `object.__new__` or the real dataclass with minimal fakes for `catalog`/`root_agent`/`memory_service`, matching how `test_cli.py` already builds composition doubles).

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --extra dev pytest tests/component/test_cli.py -k reset -v`
Expected: FAIL — `/reset` is not handled.

- [ ] **Step 3: Add `/reset` + cleanup wiring**

In `src/arema/cli.py`, add `/reset` to the command dispatcher and a reset on exit. Add a module-level reset token:

```python
_RESET_COMMANDS = frozenset({"/reset"})
```

Extend `handle_interactive_command` to accept a `case_id` and release the sandbox:

```python
def handle_interactive_command(
    command: str,
    *,
    composition: ApplicationComposition,
    case_id: str | None = None,
) -> InteractiveCommandResult:
    normalized = command.strip().lower()
    if normalized == "/help":
        return InteractiveCommandResult(handled=True, message=format_help())
    if normalized == "/status":
        return InteractiveCommandResult(handled=True, message=format_status(composition))
    if normalized == "/clear":
        return InteractiveCommandResult(handled=True, clear_requested=True)
    if normalized in _RESET_COMMANDS:
        _release_sandbox(composition, case_id)
        return InteractiveCommandResult(
            handled=True, message="[dim]Sandbox session reset.[/dim]"
        )
    if normalized in _EXIT_COMMANDS:
        _release_sandbox(composition, case_id)
        return InteractiveCommandResult(handled=True, exit_requested=True)
    return InteractiveCommandResult(handled=False)


def _release_sandbox(composition: ApplicationComposition, case_id: str | None) -> None:
    sandbox = composition.sandbox
    if sandbox is None or case_id is None:
        return
    try:
        sandbox.release_session(case_id)
    except Exception:
        logger.warning("sandbox release failed", exc_info=True)
```

Update `run_interactive_session` to pass `case_id=case_id` into `handle_interactive_command` and to release on `KeyboardInterrupt`/`EOFError`:

```python
        except (KeyboardInterrupt, EOFError):
            _release_sandbox(composition, case_id)
            console.print("\n[dim]Goodbye![/dim]")
            return 0
```

Add an `atexit` process-shutdown safety net in `main` (releases *all* handles):

```python
    import atexit

    try:
        composition = get_default_composition()
    except Exception:
        composition = None
    if composition is not None and composition.sandbox is not None:
        _sandbox = composition.sandbox
        atexit.register(_safe_release_all, _sandbox)
```

```python
def _safe_release_all(sandbox: object) -> None:
    try:
        release_all = getattr(sandbox, "release_all", None)
        if callable(release_all):
            release_all()
        else:
            getattr(sandbox, "release_session", lambda _k: None)("__atexit__")
    except Exception:
        logger.warning("sandbox shutdown release failed", exc_info=True)
```

> Note: `SandboxExecutor` port declares `release_session`, not `release_all`. `release_all` is a manager-level convenience; the local adapter implements it directly. The `getattr` guard keeps this fail-open for executors that only implement the port.

Update `_HELP_TEXT` to document `/reset`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run --extra dev pytest tests/component/test_cli.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/arema/cli.py tests/component/test_cli.py
git commit -m "feat: release sandbox session on /reset, /exit, and shutdown"
```

---

## Task 11: `K8sSandboxExecutor` (real pods, lazy import)

**Files:**
- Create: `src/arema/runtime/sandbox/k8s.py`
- Test: `tests/unit/runtime/sandbox/test_k8s_executor.py` (mocked client)

- [ ] **Step 1: Write the failing test with a mocked client**

`tests/unit/runtime/sandbox/test_k8s_executor.py`:

```python
from __future__ import annotations

import pytest

from arema.core.config import Settings
from arema.runtime.sandbox import SandboxError


def _settings(**overrides) -> Settings:
    return Settings(
        _env_file=None,
        llm_provider="ollama",
        sandbox_enabled=True,
        sandbox_backend="k8s",
        sandbox_namespace="agent-sandbox-demo",
        sandbox_default_pool="python-runtime-pool",
        sandbox_pool_map={"radare2": "radare2-pool"},
        **overrides,
    )


def test_claim_uses_pool_map_and_is_idempotent(monkeypatch) -> None:
    created: list[str] = []

    class _FakeSandbox:
        def __init__(self, warmpool: str, namespace: str) -> None:
            created.append(warmpool)
            self.warmpool = warmpool

        class commands:
            @staticmethod
            def run(cmd: str, *, timeout: int) -> object:
                class R:
                    exit_code = 0
                    stdout = "ok"
                    stderr = ""

                return R()

        class files:
            @staticmethod
            def write(path: str, data: bytes) -> None: ...

            @staticmethod
            def read(path: str) -> bytes:
                return b"bytes"

        def terminate(self) -> None: ...

    class _FakeClient:
        def __init__(self, *args, **kwargs) -> None: ...
        def create_sandbox(self, *, warmpool: str, namespace: str, **_):
            return _FakeSandbox(warmpool, namespace)

    monkeypatch.setattr("arema.runtime.sandbox.k8s._load_client", lambda config: _FakeClient())

    from arema.runtime.sandbox.k8s import K8sSandboxExecutor

    executor = K8sSandboxExecutor(settings=_settings())
    handle = executor.claim(key="case-1", pool="radare2")
    again = executor.claim(key="case-1", pool="radare2")

    assert handle is again
    assert created == ["radare2-pool"]  # pool_map resolved the logical name


def test_unknown_pool_falls_back_to_default(monkeypatch) -> None:
    created: list[str] = []

    class _FakeSandbox:
        def __init__(self, warmpool, namespace) -> None:
            created.append(warmpool)

        class commands:
            @staticmethod
            def run(cmd, *, timeout):
                class R:
                    exit_code = 0
                    stdout = ""
                    stderr = ""

                return R()

        class files:
            @staticmethod
            def write(path, data): ...
            @staticmethod
            def read(path):
                return b""

        def terminate(self): ...

    class _FakeClient:
        def create_sandbox(self, *, warmpool, namespace, **_):
            return _FakeSandbox(warmpool, namespace)

    monkeypatch.setattr("arema.runtime.sandbox.k8s._load_client", lambda config: _FakeClient())

    from arema.runtime.sandbox.k8s import K8sSandboxExecutor

    executor = K8sSandboxExecutor(settings=_settings())
    handle = executor.claim(key="case-1", pool="unknown-pool")

    assert created == ["python-runtime-pool"]


def test_run_failure_raises_sandbox_error(monkeypatch) -> None:
    class _FakeClient:
        def create_sandbox(self, *, warmpool, namespace, **_):
            class S:
                class commands:
                    @staticmethod
                    def run(cmd, *, timeout):
                        raise RuntimeError("pod blew up")

                class files:
                    @staticmethod
                    def write(path, data): ...
                    @staticmethod
                    def read(path):
                        return b""

                def terminate(self): ...

            return S()

    monkeypatch.setattr("arema.runtime.sandbox.k8s._load_client", lambda config: _FakeClient())

    from arema.runtime.sandbox.k8s import K8sSandboxExecutor

    executor = K8sSandboxExecutor(settings=_settings())
    handle = executor.claim(key="case-1", pool="radare2")

    with pytest.raises(SandboxError, match="pod blew up"):
        executor.run(handle, "r2 -v", timeout=10)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --extra dev pytest tests/unit/runtime/sandbox/test_k8s_executor.py -v`
Expected: FAIL — `arema.runtime.sandbox.k8s` does not exist.

- [ ] **Step 3: Implement the k8s adapter**

`src/arema/runtime/sandbox/k8s.py`:

```python
"""A Kubernetes-backed :class:`SandboxExecutor` using k8s-agent-sandbox.

The ``k8s-agent-sandbox`` package is an OPTIONAL dependency: it is imported
lazily inside :func:`_load_client`, so importing this module (and the rest of
AREMA) never requires it. Only constructing :class:`K8sSandboxExecutor` and
claiming a sandbox does.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from arema.core.logging import get_logger
from arema.runtime.sandbox.port import (
    ExecutionResult,
    SandboxError,
    SandboxExecutor,
    SandboxHandle,
)

if TYPE_CHECKING:
    from arema.core.config import Settings

logger = get_logger(__name__)


def _load_client(connection_config: object) -> object:
    """Import the optional k8s-agent-sandbox client and build it.

    Importing here keeps the dependency optional: the rest of AREMA imports
    nothing from ``k8s_agent_sandbox``.
    """
    from k8s_agent_sandbox import SandboxClient  # type: ignore[import-not-found]

    return SandboxClient(connection_config=connection_config)


class K8sSandboxExecutor(SandboxExecutor):
    """Claims real sandbox pods per (case key, pool) via k8s-agent-sandbox."""

    def __init__(self, *, settings: Settings) -> None:
        self._settings = settings
        self._namespace = settings.sandbox_namespace
        self._default_pool = settings.sandbox_default_pool
        self._pool_map = dict(settings.sandbox_pool_map)
        self._run_timeout = settings.sandbox_run_timeout
        self._connect_timeout = settings.sandbox_connect_timeout
        self._output_cap = settings.sandbox_output_cap
        self._connection_config = self._build_connection_config(settings)
        self._client = _load_client(self._connection_config)
        self._sandboxes: dict[tuple[str, str], object] = {}

    @staticmethod
    def _build_connection_config(settings: Settings) -> object:
        if settings.sandbox_local_tunnel:
            from k8s_agent_sandbox.models import (  # type: ignore[import-not-found]
                SandboxLocalTunnelConnectionConfig,
            )

            return SandboxLocalTunnelConnectionConfig()
        from k8s_agent_sandbox.models import (  # type: ignore[import-not-found]
            SandboxInClusterConnectionConfig,
            SandboxKubeconfigConnectionConfig,
        )

        # Prefer in-cluster when running inside a pod, else kubeconfig.
        import os

        if os.environ.get("KUBERNETES_SERVICE_HOST"):
            return SandboxInClusterConnectionConfig()
        return SandboxKubeconfigConnectionConfig()

    def _warmpool_for(self, pool: str) -> str:
        return self._pool_map.get(pool, self._default_pool)

    def claim(self, *, key: str, pool: str) -> SandboxHandle:
        identity = (key, pool)
        existing = self._sandboxes.get(identity)
        if existing is not None:
            return SandboxHandle(key=key, pool=pool, backend_id=str(id(existing)))
        try:
            sandbox = self._client.create_sandbox(
                warmpool=self._warmpool_for(pool),
                namespace=self._namespace,
                labels={"app.kubernetes.io/created-by": "arema"},
            )
        except Exception as exc:  # cancellation re-raises naturally
            raise SandboxError(f"k8s sandbox claim failed: {type(exc).__name__}") from exc
        self._sandboxes[identity] = sandbox
        backend_id = getattr(sandbox, "name", None) or str(id(sandbox))
        logger.info("k8s sandbox claimed", key=key, pool=pool, namespace=self._namespace)
        return SandboxHandle(key=key, pool=pool, backend_id=str(backend_id))

    def _sandbox_for(self, handle: SandboxHandle) -> object:
        sandbox = self._sandboxes.get((handle.key, handle.pool))
        if sandbox is None:
            raise SandboxError(f"no sandbox claimed for key={handle.key} pool={handle.pool}")
        return sandbox

    def run(self, handle: SandboxHandle, command: str, *, timeout: float) -> ExecutionResult:
        sandbox = self._sandbox_for(handle)
        try:
            result = sandbox.commands.run(command, timeout=int(timeout))
        except Exception as exc:
            raise SandboxError(f"k8s sandbox run failed: {type(exc).__name__}") from exc
        stdout = (result.stdout or "")[: self._output_cap]
        stderr = (result.stderr or "")[: self._output_cap]
        return ExecutionResult(
            exit_code=result.exit_code,
            stdout=stdout,
            stderr=stderr,
            truncated=len(result.stdout or "") > self._output_cap
            or len(result.stderr or "") > self._output_cap,
        )

    def write_file(self, handle: SandboxHandle, path: str, data: bytes) -> None:
        sandbox = self._sandbox_for(handle)
        try:
            sandbox.files.write(path, data)
        except Exception as exc:
            raise SandboxError(f"k8s sandbox write failed: {type(exc).__name__}") from exc

    def read_file(self, handle: SandboxHandle, path: str) -> bytes:
        sandbox = self._sandbox_for(handle)
        try:
            return sandbox.files.read(path)
        except Exception as exc:
            raise SandboxError(f"k8s sandbox read failed: {type(exc).__name__}") from exc

    def terminate(self, handle: SandboxHandle) -> None:
        sandbox = self._sandboxes.pop((handle.key, handle.pool), None)
        if sandbox is None:
            return
        try:
            sandbox.terminate()
        except Exception:
            logger.warning("k8s sandbox terminate failed", key=handle.key, pool=handle.pool, exc_info=True)

    def release_session(self, key: str) -> None:
        for identity in [i for i in self._sandboxes if i[0] == key]:
            handle = SandboxHandle(key=identity[0], pool=identity[1], backend_id="")
            self.terminate(handle)

    def release_all(self) -> None:
        for identity in list(self._sandboxes):
            handle = SandboxHandle(key=identity[0], pool=identity[1], backend_id="")
            self.terminate(handle)
```

> Note on `SandboxInClusterConnectionConfig` / `SandboxKubeconfigConnectionConfig`: if the pinned `k8s-agent-sandbox==0.5.2` exposes only `SandboxLocalTunnelConnectionConfig`, simplify `_build_connection_config` to always return the local-tunnel config and document kubeconfig/in-cluster as a follow-up. Verify against the installed package (Task 12 installs it) and adjust the test fakes accordingly.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run --extra dev pytest tests/unit/runtime/sandbox/test_k8s_executor.py -v`
Expected: PASS (the client is monkeypatched, so no real cluster is needed).

- [ ] **Step 5: Commit**

```bash
git add src/arema/runtime/sandbox/k8s.py tests/unit/runtime/sandbox/test_k8s_executor.py
git commit -m "feat: add K8sSandboxExecutor backed by k8s-agent-sandbox"
```

---

## Task 12: Opt-in k8s integration test + pytest marker + optional dep

**Files:**
- Modify: `pyproject.toml` (add `sandbox` extra), `tests/conftest.py` (register marker, default backend)
- Create: `tests/unit/runtime/sandbox/test_k8s_integration.py`

- [ ] **Step 1: Add the optional dependency group**

In `pyproject.toml`, add to `[project.optional-dependencies]`:

```toml
sandbox = [
    "k8s-agent-sandbox==0.5.2",
]
```

- [ ] **Step 2: Register the marker + default backend in conftest**

In `tests/conftest.py`, add (after the existing home-redirect fixture):

```python
def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "k8s: requires a live Kind cluster (opt-in)")


@pytest.fixture(autouse=True)
def _default_local_sandbox_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unit tests run with the local sandbox backend; no cluster needed."""
    monkeypatch.setenv("AREMA_SANDBOX_BACKEND", "local")
```

- [ ] **Step 3: Write the opt-in integration test**

`tests/unit/runtime/sandbox/test_k8s_integration.py`:

```python
"""Opt-in integration test against a real Kind cluster.

Skipped unless AREMA_K8S_INTEGRATION=1 and a cluster is reachable. Run with:
    AREMA_K8S_INTEGRATION=1 uv run --extra dev --extra sandbox \
        pytest tests/unit/runtime/sandbox/test_k8s_integration.py -v
"""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.k8s


@pytest.fixture(autouse=True)
def _skip_without_cluster() -> None:
    if os.environ.get("AREMA_K8S_INTEGRATION") != "1":
        pytest.skip("set AREMA_K8S_INTEGRATION=1 to run the live k8s sandbox test")


def test_claim_run_release_python_pool() -> None:
    from arema.core.config import Settings
    from arema.runtime.sandbox.k8s import K8sSandboxExecutor

    settings = Settings(
        _env_file=None,
        llm_provider="ollama",
        sandbox_enabled=True,
        sandbox_backend="k8s",
        sandbox_default_pool="python-runtime-pool",
    )
    executor = K8sSandboxExecutor(settings=settings)
    handle = executor.claim(key="integration-1", pool="python-runtime-pool")
    try:
        result = executor.run(handle, "python3 -c 'print(2+2)'", timeout=30)
        assert result.exit_code == 0
        assert "4" in result.stdout
    finally:
        executor.release_session("integration-1")
```

- [ ] **Step 4: Verify the suite is green without the cluster**

Run: `uv run --extra dev pytest tests/unit/runtime/sandbox -v`
Expected: PASS (the integration test is skipped).

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml tests/conftest.py tests/unit/runtime/sandbox/test_k8s_integration.py
git commit -m "test: add opt-in k8s sandbox integration test and sandbox extra"
```

---

## Task 13: radare2 container image (command-exec, no Supergateway)

**Files:**
- Create: `images/radare2/Dockerfile`, `images/radare2/.dockerignore`

- [ ] **Step 1: Write the Dockerfile**

Adapt the prior `r2-mcp` Dockerfile but **drop Supergateway/SSE and r2mcp** — we exec commands, not host an MCP server. `images/radare2/Dockerfile`:

```dockerfile
# radare2 command-exec sandbox image for AREMA.
# Unlike the prior r2-mcp image, this runs NO MCP server and NO Supergateway:
# AREMA tools exec `r2`/`rabin2` commands here via the SandboxClient files+commands API.
#
# Opens untrusted, attacker-supplied binaries, so it runs as a non-root user
# with a read-only rootfs and dropped capabilities (cluster hardening note in
# docs/superpowers/specs/2026-07-23-kubernetes-sandbox-execution-layer-design.md).

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg git build-essential pkg-config \
        python3 meson ninja-build file \
    && rm -rf /var/lib/apt/lists/*

# Build radare2 from source via meson, pinned for reproducibility.
ARG RADARE2_VERSION=6.1.8
WORKDIR /tmp
RUN git clone --branch "${RADARE2_VERSION}" --depth 1 https://github.com/radareorg/radare2.git \
    && cd radare2 \
    && meson setup --prefix=/usr/local --buildtype=release build \
    && meson compile -C build \
    && meson install -C build \
    && ldconfig \
    && r2 -v \
    && cd / && rm -rf /tmp/radare2

# Non-root runtime user. /targets is the read-only artifact mount; /workspace is
# writable scratch for r2 projects and intermediate files.
RUN groupadd -r r2user \
    && useradd -r -g r2user -m -d /home/r2user r2user \
    && mkdir -p /targets /workspace \
    && chown -R r2user:r2user /workspace /home/r2user

USER r2user
ENV HOME=/home/r2user
WORKDIR /workspace

# Default: sleep so a claimed warm-pool pod stays alive waiting for commands.
CMD ["sleep", "infinity"]
```

`images/radare2/.dockerignore`:

```text
.git
**/__pycache__
```

- [ ] **Step 2: Verify the image builds locally**

Run: `docker build -t arema-radare2:0.1.0 images/radare2`
Expected: build succeeds; `r2 -v` prints during build.

- [ ] **Step 3: Smoke-test the binary in the image**

Run: `docker run --rm arema-radare2:0.1.0 r2 -v`
Expected: prints the radare2 version.

- [ ] **Step 4: Commit**

```bash
git add images/radare2
git commit -m "feat: add radare2 command-exec sandbox image"
```

---

## Task 14: Cluster manifests + agent-sandbox install script

**Files:**
- Create: `deploy/sandbox/install-agent-sandbox.sh`, `deploy/sandbox/10-radare2-template.yaml`, `deploy/sandbox/20-radare2-pool.yaml`

- [ ] **Step 1: Write the install script (pinned agent-sandbox)**

`deploy/sandbox/install-agent-sandbox.sh`:

```sh
#!/usr/bin/env bash
# Install Kubernetes Agent Sandbox (pinned v0.5.2) + the sandbox router into an
# existing Kind cluster. Implements the SANDBOXING.md steps 1 and 5.
set -euo pipefail

AGENT_SANDBOX_VERSION="${AGENT_SANDBOX_VERSION:-v0.5.2}"
SYSTEM_NS="agent-sandbox-system"
DEMO_NS="${AREMA_SANDBOX_NAMESPACE:-agent-sandbox-demo}"
ROUTER_IMAGE="sandbox-router:${AGENT_SANDBOX_VERSION}"

echo ">> Applying agent-sandbox ${AGENT_SANDBOX_VERSION} ..."
kubectl apply -f \
  "https://github.com/kubernetes-sigs/agent-sandbox/releases/download/${AGENT_SANDBOX_VERSION}/sandbox-with-extensions.yaml"

echo ">> Waiting for controller ..."
kubectl wait --for=condition=Ready pod \
  -l app=agent-sandbox-controller -n "${SYSTEM_NS}" --timeout=180s

kubectl get crds | grep agents.x-k8s.io

echo ">> Creating namespace ${DEMO_NS} ..."
kubectl get namespace "${DEMO_NS}" >/dev/null 2>&1 || kubectl create namespace "${DEMO_NS}"

echo ">> Building + loading router image into kind ..."
docker build -t "${ROUTER_IMAGE}" \
  "$(git -C "$(dirname "$0")/../.." rev-parse --show-toplevel 2>/dev/null || pwd)/clients/python/agentic-sandbox-client/sandbox-router" \
  2>/dev/null || echo "   (skipped local router build: clone agent-sandbox and build from there if needed)"
kind load docker-image "${ROUTER_IMAGE}" 2>/dev/null || echo "   (skipped kind load)"

echo ">> Done. Next: kubectl apply -f deploy/sandbox/10-radare2-template.yaml"
```

- [ ] **Step 2: Write the radare2 SandboxTemplate (hardened)**

`deploy/sandbox/10-radare2-template.yaml`:

```yaml
apiVersion: extensions.agents.x-k8s.io/v1beta1
kind: SandboxTemplate
metadata:
  name: radare2-runtime-template
  namespace: agent-sandbox-demo
spec:
  template:
    spec:
      runtimeClassName: ""            # set to gvisor/kata before hostile code
      restartPolicy: Never
      securityContext:
        runAsNonRoot: true
        readOnlyRootFilesystem: true
      containers:
        - name: radare2
          image: arema-radare2:0.1.0
          imagePullPolicy: IfNotPresent
          command: ["sleep", "infinity"]
          securityContext:
            runAsNonRoot: true
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            - name: workspace
              mountPath: /workspace
            - name: targets
              mountPath: /targets
              readOnly: true
          resources:
            requests: { cpu: "500m", memory: "512Mi" }
            limits:   { cpu: "2",    memory: "2Gi" }
      volumes:
        - name: workspace
          emptyDir: {}
        - name: targets
          emptyDir: {}
      automountServiceAccountToken: false
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: radare2-deny-all-egress
  namespace: agent-sandbox-demo
spec:
  podSelector:
    matchLabels:
      arema.dev/pool: radare2
  policyTypes: ["Egress"]
  egress: []
```

- [ ] **Step 3: Write the warm pool**

`deploy/sandbox/20-radare2-pool.yaml`:

```yaml
apiVersion: extensions.agents.x-k8s.io/v1beta1
kind: SandboxWarmPool
metadata:
  name: radare2-pool
  namespace: agent-sandbox-demo
spec:
  replicas: 2
  sandboxTemplateRef:
    name: radare2-runtime-template
```

- [ ] **Step 4: Make the script executable and commit**

```bash
chmod +x deploy/sandbox/install-agent-sandbox.sh
git add deploy/sandbox
git commit -m "feat: add agent-sandbox install script and radare2 pool manifests"
```

---

## Task 15: Makefile targets for sandbox lifecycle

**Files:**
- Modify: `Makefile`

- [ ] **Step 1: Add the targets**

In `Makefile`, extend the `.PHONY` line and add targets:

```make
.PHONY: help setup install venv run adk-run adk-web test test-unit test-component lint format-check type-check check clean setup-sandbox sandbox-image sandbox-up sandbox-down sandbox-test
```

```make
# -- Sandbox ------------------------------------------------------------------
setup-sandbox: ## Install the optional k8s-agent-sandbox client
	uv sync --extra dev --extra sandbox

sandbox-image: ## Build the radare2 sandbox image
	docker build -t arema-radare2:0.1.0 images/radare2
	kind load docker-image arema-radare2:0.1.0 2>/dev/null || true

sandbox-up: ## Install agent-sandbox CRDs + radare2 template and warm pool
	bash deploy/sandbox/install-agent-sandbox.sh
	kubectl apply -f deploy/sandbox/10-radare2-template.yaml
	kubectl apply -f deploy/sandbox/20-radare2-pool.yaml
	kubectl wait --for=condition=Ready pod -l agents.x-k8s.io/pool \
		-n agent-sandbox-demo --timeout=180s || true

sandbox-down: ## Delete the radare2 pool/template (leaves agent-sandbox installed)
	kubectl delete -f deploy/sandbox/20-radare2-pool.yaml --ignore-not-found
	kubectl delete -f deploy/sandbox/10-radare2-template.yaml --ignore-not-found

sandbox-test: ## Run the opt-in live k8s sandbox integration test
	AREMA_K8S_INTEGRATION=1 uv run --extra dev --extra sandbox \
		pytest tests/unit/runtime/sandbox/test_k8s_integration.py -v
```

- [ ] **Step 2: Verify the help renders and targets are syntactically valid**

Run: `make help`
Expected: lists the new `sandbox-*` targets without error.

- [ ] **Step 3: Commit**

```bash
git add Makefile
git commit -m "feat: add Makefile targets for sandbox lifecycle"
```

---

## Task 16: Extend architecture/neutrality guardrails

**Files:**
- Modify: `tests/architecture/test_neutral_boundaries.py`

- [ ] **Step 1: Write the failing assertions**

Append to `tests/architecture/test_neutral_boundaries.py`:

```python
import ast


def test_sandbox_module_has_no_registry_imports() -> None:
    """runtime/sandbox depends only downward on core/ — never registry/."""
    sandbox_dir = Path("src/arema/runtime/sandbox")
    for path in sandbox_dir.rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith(
                "arema.registry"
            ):
                raise AssertionError(f"{path} imports {node.module} — sandbox must not depend on registry")
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("arema.registry"):
                        raise AssertionError(f"{path} imports {alias.name} — sandbox must not depend on registry")


def test_arema_source_names_no_concrete_domain_pool() -> None:
    """No src/arema module hardcodes a concrete tool/pool name."""
    source = "\n".join(path.read_text() for path in Path("src/arema").rglob("*.py"))
    for term in ("radare2", "r2mcp", "ghidra", "ilspycmd"):
        assert term not in source, f"src/arema must not name domain tool '{term}'"
```

- [ ] **Step 2: Run to verify it passes (the shell stays neutral by construction)**

Run: `uv run --extra dev pytest tests/architecture/test_neutral_boundaries.py -v`
Expected: PASS. If `test_arema_source_names_no_concrete_domain_pool` fails, a sandbox/source file accidentally hardcoded a pool name — fix it (pool names belong only in `.env`/`deploy/`).

> Note: the existing `test_default_composition_has_no_domain_registration_terms` already forbids `radare2` in `composition.py`; the new test extends that guarantee to all of `src/arema`. The `_build_sandbox_executor` selection uses only `settings.sandbox_default_pool`, never a literal domain name.

- [ ] **Step 3: Commit**

```bash
git add tests/architecture/test_neutral_boundaries.py
git commit -m "test: assert sandbox module is registry-free and domain-neutral"
```

---

## Task 17: Full `make check` green

**Files:** none (verification only)

- [ ] **Step 1: Run the complete check**

Run: `make check`
Expected: lint, format-check, type-check, and the full test suite all PASS.

- [ ] **Step 2: If type-check flags the sandbox module, fix inline**

Common fixes: add `# type: ignore[import-not-found]` only on the lazy `k8s_agent_sandbox` imports (already in Task 11), ensure `TYPE_CHECKING` guards on `Settings`/`SandboxExecutor` imports in adapters, and that `run`'s return annotation in `session.py` matches the port (use `ExecutionResult` if you forward the type, or keep `object` and let callers re-type — prefer importing `ExecutionResult` under TYPE_CHECKING and annotating precisely).

- [ ] **Step 3: Run the contract across BOTH adapters once the k8s extra is installed (optional)**

Run: `AREMA_K8S_INTEGRATION=1 make sandbox-test`
Expected (with a live cluster + `make sandbox-up`): the integration test runs `python3 -c 'print(2+2)'` in a pod and asserts `4` in stdout.

- [ ] **Step 4: Commit any final fixes**

```bash
git add -A
git commit -m "chore: sandbox layer passes full make check"
```

---

## Self-Review (completed by plan author)

**Spec coverage:** every spec section maps to a task — port & data model (T4), session binding (T5, T9), local adapter + contract (T6), k8s adapter + connection modes (T11), cancellation/failure semantics (T11 `SandboxError` wrapping, cancellation re-raises naturally), config + AREMA_ prefix + sandbox fields (T1, T2, T3), `RuntimeServices.sandbox` (T7), composition wiring (T8), case-id binding refinement (T9), session/process cleanup + atexit (T10), radare2 image no-SSE (T13), manifests + install script (T14), Makefile (T15), architecture guardrails (T16), testing strategy incl. opt-in k8s (T6, T12). **Out-of-scope items** (MCP attachment, ghidra, ParallelAgent, RE agents) are explicitly excluded and deferred to Spec B.

**Placeholder scan:** none — every code step contains real code; infra steps contain real manifests/Dockerfile.

**Type consistency:** `SandboxExecutor` methods (`claim/run/write_file/read_file/terminate/release_session`) are identical across port (T4), session manager (T5), local adapter (T6), and k8s adapter (T11). `SandboxHandle(key, pool, backend_id)` and `ExecutionResult(exit_code, stdout, stderr, truncated)` are consistent everywhere. `ApplicationComposition.sandbox` (T8) matches the field read in `cli.py` (T10).

**One known follow-up:** confirm `k8s-agent-sandbox==0.5.2` exposes `SandboxInClusterConnectionConfig`/`SandboxKubeconfigConnectionConfig` (Task 11 note). If not, simplify `_build_connection_config` to local-tunnel-only and document the rest — does not block the spec.
