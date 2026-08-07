"""Tests for the ``run_python`` workbench tool.

``run_python`` stages the *current* artifact into a persistent ``analysis``
workspace, writes the agent-authored script to ``scripts/step_<n>.py``, and runs
it under the sandbox timeout/output governor with ``$INPUT``/``$WORKDIR``
exported. The script's stdout is redirected to a workspace file so the full,
byte-accurate output is captured; when it overflows the inline cap it is spilled
verbatim to the SHA-256 artifact store so the model receives a hash for the
unseen overflow rather than losing it. The harness models just enough of the pod
filesystem (the ``>`` redirect capture, ``stat`` sizing, and ``read_file``) to
exercise that path against a string-recording ``_FakeExecutor``.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, cast

from arema.core.config import LLMProvider, Settings
from arema.runtime.agent_factory import ToolBuildContext
from arema.runtime.sandbox.port import ExecutionResult, SandboxHandle
from arema.runtime.services import RuntimeServices
from arema.runtime.sessions import SessionKeys
from reverse_engineering.artifacts import ArtifactStore
from reverse_engineering.tools.deobfuscation.state import CURRENT_ARTIFACT_KEY
from reverse_engineering.tools.workbench.run_python import (
    _STDOUT_INLINE_CHARS,
    RUN_PYTHON_TOOL,
    build_run_python,
)

if TYPE_CHECKING:
    from pathlib import Path

    import pytest

    from arema.registry.catalog import CapabilityCatalog
    from arema.runtime.sandbox.port import SandboxExecutor


class _FakeExecutor:
    """Protocol-complete sandbox fake recording the workbench interactions.

    Models just enough of the (non-``kubectl``) executor transport that
    ``run_python`` drives: a ``test -f`` presence probe, a ``stat --format=%s``
    size query, and the stdout ``>`` redirect that captures the script's output
    into a workspace file. ``script_stdout`` is the byte stream the redirected
    script is pretended to emit; ``script_truncated`` lets a test simulate a
    stderr-only overflow on the run itself.
    """

    def __init__(
        self,
        *,
        script_stdout: bytes = b"",
        script_stderr: str = "",
        script_exit: int = 0,
        script_truncated: bool = False,
    ) -> None:
        self.script_stdout = script_stdout
        self.script_stderr = script_stderr
        self.script_exit = script_exit
        self.script_truncated = script_truncated
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
        probe = "test -f "
        if command.startswith(probe):
            path = command[len(probe) :]
            return ExecutionResult(exit_code=0 if path in self.files else 1, stdout="", stderr="")
        stat = "stat --format=%s -- "
        if command.startswith(stat):
            path = command[len(stat) :]
            return ExecutionResult(
                exit_code=0, stdout=f"{len(self.files.get(path, b''))}\n", stderr=""
            )
        if " > " in command:
            target = command.rsplit(" > ", 1)[1]
            self.files[target] = self.script_stdout
            return ExecutionResult(
                exit_code=self.script_exit,
                stdout="",
                stderr=self.script_stderr,
                truncated=self.script_truncated,
            )
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


def _workbench_context(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    executor: _FakeExecutor,
    data: bytes = b"packed-sample",
) -> tuple[ToolBuildContext, _FakeToolContext, str]:
    """Build a k8s ToolBuildContext with the sample staged and set as current."""
    import reverse_engineering.tools.deobfuscation.runtime as rt

    root = tmp_path / "artifacts"
    source = tmp_path / "sample.bin"
    source.write_bytes(data)
    sha = ArtifactStore(root).acquire(source)
    monkeypatch.setattr(rt, "default_artifacts_root", lambda: root)

    settings = Settings(
        _env_file=None,
        llm_provider=LLMProvider.OLLAMA,
        sandbox_backend="k8s",
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
    tool_context = _FakeToolContext(
        {SessionKeys.SANDBOX_CASE_ID: "case-wb", CURRENT_ARTIFACT_KEY: sha}
    )
    return context, tool_context, sha


def test_run_python_stages_current_artifact_and_runs_a_script(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executor = _FakeExecutor()
    ctx, tool_ctx, _sha = _workbench_context(monkeypatch, tmp_path, executor=executor)

    run_python = build_run_python(ctx)
    result = run_python(code="print('hello')", timeout_s=30, tool_context=tool_ctx)

    assert result["exit_code"] == 0
    # A step script was written into the persistent workspace and then executed.
    assert "step_0.py" in "".join(executor.runs)
    assert any(path.endswith("/scripts/step_0.py") for path, _ in executor.writes)
    # Small output is not spilled to the artifact store.
    assert result["spilled_artifact_id"] == ""


def test_run_python_without_current_artifact_is_a_clean_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executor = _FakeExecutor()
    ctx, _tool_ctx, _sha = _workbench_context(monkeypatch, tmp_path, executor=executor)
    empty_ctx = _FakeToolContext({SessionKeys.SANDBOX_CASE_ID: "case-wb"})

    run_python = build_run_python(ctx)
    result = run_python(code="print('x')", timeout_s=30, tool_context=empty_ctx)

    assert result["exit_code"] == 1
    assert result["stderr"] == "no current artifact"
    # Nothing was staged or executed without a current artifact.
    assert executor.claims == []
    assert executor.runs == []


def test_run_python_spills_full_byte_accurate_stdout_on_overflow(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A binary payload larger than the default 64 KiB output cap, with bytes that
    # are not valid UTF-8 -- so a lossy decode/re-encode would corrupt the spill.
    payload = (b"\x00\xff\x80MZ" * 20_000)[:80_000]
    assert len(payload) > 65_536
    executor = _FakeExecutor(script_stdout=payload)
    ctx, tool_ctx, _sha = _workbench_context(monkeypatch, tmp_path, executor=executor)
    # run_python binds ``default_artifacts_root`` in its own module namespace,
    # separate from the runtime module's staging binding; point it at the store.
    root = tmp_path / "artifacts"
    monkeypatch.setattr(
        "reverse_engineering.tools.workbench.run_python.default_artifacts_root",
        lambda: root,
    )

    run_python = build_run_python(ctx)
    result = run_python(code="emit-binary", timeout_s=30, tool_context=tool_ctx)

    assert result["truncated"] is True
    # The spilled artifact is the SHA-256 of the *full, byte-accurate* stdout.
    expected_sha = hashlib.sha256(payload).hexdigest()
    assert result["spilled_artifact_id"] == expected_sha
    stored = ArtifactStore(root).path_for(expected_sha)
    assert stored.exists()
    assert stored.read_bytes() == payload
    # The inline stdout is only a bounded prefix (the tool's inline budget), not
    # the full blob.
    assert result["stdout"] == payload[:_STDOUT_INLINE_CHARS].decode(errors="replace")


def test_run_python_spills_stdout_in_the_compactor_truncation_window(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Regression: stdout larger than the inline budget but SMALLER than the sandbox
    # output cap (65536) must still spill. Gating the spill on the transport cap
    # instead let the after-tool compactor truncate this window to a tiny preview
    # with truncated=False and no recoverable SHA -- silent data loss.
    payload = b"A" * (_STDOUT_INLINE_CHARS + 8_000)
    assert _STDOUT_INLINE_CHARS < len(payload) <= 65_536
    executor = _FakeExecutor(script_stdout=payload)
    ctx, tool_ctx, _sha = _workbench_context(monkeypatch, tmp_path, executor=executor)
    root = tmp_path / "artifacts"
    monkeypatch.setattr(
        "reverse_engineering.tools.workbench.run_python.default_artifacts_root",
        lambda: root,
    )

    run_python = build_run_python(ctx)
    result = run_python(code="mid-size", timeout_s=30, tool_context=tool_ctx)

    assert result["truncated"] is True, "output the compactor will hide must report truncated"
    assert result["spilled_artifact_id"] != "", "the hidden overflow must be recoverable by SHA"
    assert ArtifactStore(root).path_for(
        cast("str", result["spilled_artifact_id"])
    ).read_bytes() == (payload)
    assert len(cast("str", result["stdout"])) <= _STDOUT_INLINE_CHARS


def test_run_python_does_not_spill_on_stderr_only_overflow(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The run reports truncated=True (a stderr overflow), but stdout is tiny; the
    # spill must gate on actual stdout overflow, not the combined truncated flag.
    executor = _FakeExecutor(script_stdout=b"ok\n", script_stderr="boom", script_truncated=True)
    ctx, tool_ctx, _sha = _workbench_context(monkeypatch, tmp_path, executor=executor)

    run_python = build_run_python(ctx)
    result = run_python(code="noisy-stderr", timeout_s=30, tool_context=tool_ctx)

    assert result["stdout"] == "ok\n"
    assert result["truncated"] is False
    assert result["spilled_artifact_id"] == ""


def test_run_python_descriptor_binds_output_policy() -> None:
    assert RUN_PYTHON_TOOL.id == "run_python"
    assert RUN_PYTHON_TOOL.output_policy.max_chars == 32_000
    assert RUN_PYTHON_TOOL.output_policy.max_list_items == 200
    assert RUN_PYTHON_TOOL.factory is build_run_python
