"""Tests for the persistent-workspace staging variant of the sandbox runtime.

Unlike ``stage_artifact`` (which wipes ``/work/<tool>/<sha>`` on every call),
``stage_persistent_workspace`` prepares the work dir idempotently *without*
wiping and copies the sample in only when it is absent, so agent-authored
scripts and dumps survive across ``run_python`` calls. The harness mirrors
``test_deobfuscation_runtime.py``'s ``_FakeExecutor``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from arema.core.config import LLMProvider, Settings
from arema.runtime.agent_factory import ToolBuildContext
from arema.runtime.sandbox.port import ExecutionResult, SandboxHandle
from arema.runtime.services import RuntimeServices
from arema.runtime.sessions import SessionKeys
from reverse_engineering.artifacts import ArtifactStore

if TYPE_CHECKING:
    from pathlib import Path

    import pytest

    from arema.registry.catalog import CapabilityCatalog
    from arema.runtime.sandbox.port import SandboxExecutor


class _FakeExecutor:
    """Protocol-complete sandbox fake recording persistent-staging interactions."""

    def __init__(self) -> None:
        self.claims: list[tuple[str, str]] = []
        self.runs: list[str] = []
        self.writes: list[tuple[str, bytes]] = []
        self.files: dict[str, bytes] = {}
        self._handles: dict[tuple[str, str], SandboxHandle] = {}

    def claim(self, *, key: str, pool: str) -> SandboxHandle:
        self.claims.append((key, pool))
        return self._handles.setdefault(
            (key, pool), SandboxHandle(key=key, pool=pool, backend_id=f"{pool}-{key}")
        )

    def run(self, handle: SandboxHandle, command: str, *, timeout: float) -> ExecutionResult:
        del handle, timeout
        self.runs.append(command)
        prefix = "test -f "
        if command.startswith(prefix):
            path = command[len(prefix) :]
            return ExecutionResult(exit_code=0 if path in self.files else 1, stdout="", stderr="")
        return ExecutionResult(exit_code=0, stdout="", stderr="")

    def write_file(self, handle: SandboxHandle, path: str, data: bytes) -> None:
        del handle
        self.writes.append((path, data))
        self.files[path] = data

    def read_file(self, handle: SandboxHandle, path: str) -> bytes:
        del handle
        return self.files.get(path, b"")

    def terminate(self, handle: SandboxHandle) -> None:
        pass

    def release_session(self, key: str) -> None:
        pass


class _FakeState:
    """Duck-typed ADK state stand-in; deliberately not a mapping subclass."""

    def __init__(self, values: dict[str, object] | None = None) -> None:
        self._values = values or {}

    def get(self, key: str, default: object = None) -> object:
        return self._values.get(key, default)

    def __setitem__(self, key: str, value: object) -> None:
        self._values[key] = value


class _FakeToolContext:
    def __init__(self, values: dict[str, object] | None = None) -> None:
        self.state = _FakeState(values)


def _local_context(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    executor: object,
    data: bytes = b"packed-sample",
    backend: str = "k8s",
) -> tuple[ToolBuildContext, _FakeToolContext, str]:
    import reverse_engineering.tools.deobfuscation.runtime as rt

    root = tmp_path / "artifacts"
    source = tmp_path / "sample.bin"
    source.write_bytes(data)
    sha = ArtifactStore(root).acquire(source)
    monkeypatch.setattr(rt, "default_artifacts_root", lambda: root)

    settings = Settings(
        _env_file=None,
        llm_provider=LLMProvider.OLLAMA,
        sandbox_backend=backend,
        sandbox_namespace="agent-sandbox-demo",
        sandbox_run_timeout=90,
    )
    base = RuntimeServices.default()
    services = RuntimeServices(
        clock=base.clock,
        metrics=base.metrics,
        memory_sink=base.memory_sink,
        sandbox=cast("SandboxExecutor", executor),
    )
    context = ToolBuildContext(
        settings=settings,
        services=services,
        catalog=cast("CapabilityCatalog", object()),
    )
    tool_context = _FakeToolContext({SessionKeys.SANDBOX_CASE_ID: "case-wb"})
    return context, tool_context, sha


def test_persistent_workspace_preps_without_wiping(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from reverse_engineering.tools.deobfuscation import runtime as rt
    from reverse_engineering.tools.workbench import WORKBENCH_POOL

    executor = _FakeExecutor()
    ctx, tool_ctx, sha = _local_context(monkeypatch, tmp_path, executor=executor)

    staged = rt.stage_persistent_workspace(
        ctx, sha, tool_ctx, pool=WORKBENCH_POOL, tool_name="analysis"
    )

    assert staged.work_dir == f"/work/analysis/{sha}"
    assert staged.input_path == f"/work/analysis/{sha}/input"
    assert executor.claims == [("case-wb", WORKBENCH_POOL)]
    # The prep command must NOT wipe the work dir (persistence), only mkdir -p.
    prep = executor.runs[0]
    assert "rm -rf" not in prep
    assert "mkdir" in prep


def test_persistent_workspace_seeds_input_only_when_absent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from reverse_engineering.tools.deobfuscation import runtime as rt
    from reverse_engineering.tools.workbench import WORKBENCH_POOL

    executor = _FakeExecutor()
    ctx, tool_ctx, sha = _local_context(monkeypatch, tmp_path, executor=executor)

    first = rt.stage_persistent_workspace(
        ctx, sha, tool_ctx, pool=WORKBENCH_POOL, tool_name="analysis"
    )
    # The sample is seeded exactly once, at its persistent input path.
    assert executor.writes == [(first.input_path, b"packed-sample")]

    rt.stage_persistent_workspace(ctx, sha, tool_ctx, pool=WORKBENCH_POOL, tool_name="analysis")
    # A second staging call reuses the persistent workspace and does NOT re-seed.
    assert executor.writes == [(first.input_path, b"packed-sample")]


def test_persistent_workspace_rejects_failed_prep_before_seeding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import pytest as _pytest

    from reverse_engineering.tools.deobfuscation import runtime as rt
    from reverse_engineering.tools.workbench import WORKBENCH_POOL

    class _FailingPrepExecutor(_FakeExecutor):
        def run(self, handle: SandboxHandle, command: str, *, timeout: float) -> ExecutionResult:
            del handle, timeout
            self.runs.append(command)
            return ExecutionResult(exit_code=1, stdout="", stderr="mkdir denied")

    executor = _FailingPrepExecutor()
    ctx, tool_ctx, sha = _local_context(monkeypatch, tmp_path, executor=executor)

    with _pytest.raises(RuntimeError, match="failed to prepare sandbox work directory"):
        rt.stage_persistent_workspace(ctx, sha, tool_ctx, pool=WORKBENCH_POOL, tool_name="analysis")

    assert executor.writes == []


def test_persistent_workspace_requires_explicit_k8s_backend(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The persistent-workspace entry point is a public staging seam of its own, so
    # it must enforce the same k8s-only boundary as stage_artifact -- verified here
    # directly (not merely via the shared helper) so a future divergence is caught.
    import pytest as _pytest

    from reverse_engineering.tools.deobfuscation import runtime as rt
    from reverse_engineering.tools.deobfuscation.runtime import DeobfuscationUnavailable
    from reverse_engineering.tools.workbench import WORKBENCH_POOL

    executor = _FakeExecutor()
    ctx, tool_ctx, sha = _local_context(monkeypatch, tmp_path, executor=executor, backend="local")

    with _pytest.raises(
        DeobfuscationUnavailable, match="sandbox tools require sandbox_backend='k8s'"
    ):
        rt.stage_persistent_workspace(ctx, sha, tool_ctx, pool=WORKBENCH_POOL, tool_name="analysis")

    # The guard fires before any pod is claimed or touched.
    assert executor.claims == []
    assert executor.runs == []
    assert executor.writes == []


def test_persistent_workspace_rejects_local_executor_even_when_backend_is_k8s(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import pytest as _pytest

    from arema.runtime.sandbox.local import LocalSandboxExecutor
    from reverse_engineering.tools.deobfuscation import runtime as rt
    from reverse_engineering.tools.deobfuscation.runtime import DeobfuscationUnavailable
    from reverse_engineering.tools.workbench import WORKBENCH_POOL

    class _RecordingLocalExecutor(LocalSandboxExecutor):
        def __init__(self) -> None:
            super().__init__(root=tmp_path / "local-sandbox")
            self.calls: list[str] = []

        def claim(self, *, key: str, pool: str) -> SandboxHandle:
            self.calls.append("claim")
            return super().claim(key=key, pool=pool)

    executor = _RecordingLocalExecutor()
    ctx, tool_ctx, sha = _local_context(monkeypatch, tmp_path, executor=executor, backend="k8s")

    with _pytest.raises(DeobfuscationUnavailable, match="requires K8sSandboxExecutor"):
        rt.stage_persistent_workspace(ctx, sha, tool_ctx, pool=WORKBENCH_POOL, tool_name="analysis")

    # A LocalSandboxExecutor is forbidden outright: never claimed, never run.
    assert executor.calls == []


def test_persistent_workspace_rejects_unsafe_tool_name(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import pytest as _pytest

    from reverse_engineering.tools.deobfuscation import runtime as rt
    from reverse_engineering.tools.workbench import WORKBENCH_POOL

    executor = _FakeExecutor()
    ctx, tool_ctx, sha = _local_context(monkeypatch, tmp_path, executor=executor)

    with _pytest.raises(ValueError, match="tool_name must be a safe single path component"):
        rt.stage_persistent_workspace(ctx, sha, tool_ctx, pool=WORKBENCH_POOL, tool_name="../evil")

    assert executor.claims == []
    assert executor.runs == []
    assert executor.writes == []
