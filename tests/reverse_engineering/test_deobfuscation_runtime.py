"""Tests for the Kubernetes-only deobfuscation execution helpers."""

from __future__ import annotations

import json
import sys
import time
from typing import TYPE_CHECKING, cast

import pytest

from arema.core.config import LLMProvider, Settings
from arema.runtime.agent_factory import ToolBuildContext
from arema.runtime.sandbox.local import LocalSandboxExecutor
from arema.runtime.sandbox.port import ExecutionResult, SandboxHandle
from arema.runtime.services import RuntimeServices
from arema.runtime.sessions import SandboxIdentityError, SessionKeys
from reverse_engineering.artifacts import ArtifactStore
from reverse_engineering.tools.deobfuscation.runtime import (
    ArtifactInputTooLarge,
    DeobfuscationUnavailable,
    StagedArtifact,
    read_bounded_file,
    read_bounded_prefix,
    remote_file_size,
    run_argv,
    run_argv_to_file,
    stage_artifact,
)
from reverse_engineering.tools.deobfuscation.state import (
    CLASSIFICATION_KEY,
    DeobfPlan,
    parse_classification,
)

if TYPE_CHECKING:
    from pathlib import Path

    from arema.registry.catalog import CapabilityCatalog
    from arema.runtime.sandbox.port import SandboxExecutor


class _FakeExecutor:
    """Protocol-complete sandbox fake recording the runtime interactions."""

    def __init__(self) -> None:
        self.claims: list[tuple[str, str]] = []
        self.writes: list[tuple[SandboxHandle, str, bytes]] = []
        self.runs: list[tuple[SandboxHandle, str, float]] = []
        self.reads: list[tuple[SandboxHandle, str]] = []
        self.files: dict[str, bytes] = {}
        self._handles: dict[tuple[str, str], SandboxHandle] = {}
        self.results: list[ExecutionResult] = []

    def claim(self, *, key: str, pool: str) -> SandboxHandle:
        self.claims.append((key, pool))
        return self._handles.setdefault(
            (key, pool), SandboxHandle(key=key, pool=pool, backend_id=f"{pool}-{key}")
        )

    def run(self, handle: SandboxHandle, command: str, *, timeout: float) -> ExecutionResult:
        self.runs.append((handle, command, timeout))
        if self.results:
            return self.results.pop(0)
        return ExecutionResult(exit_code=0, stdout="", stderr="")

    def write_file(self, handle: SandboxHandle, path: str, data: bytes) -> None:
        self.writes.append((handle, path, data))
        self.files[path] = data

    def read_file(self, handle: SandboxHandle, path: str) -> bytes:
        self.reads.append((handle, path))
        return self.files[path]

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


class _NoStateToolContext:
    pass


class _ExplodingGetterState:
    def get(self, _key: str, _default: object = None) -> object:
        raise RuntimeError("state getter exploded")

    def __setitem__(self, _key: str, _value: object) -> None:
        pass


class _ExplodingGetterToolContext:
    invocation_id = "deobfuscation-test"
    state = _ExplodingGetterState()


def _build_context(
    *, executor: object, backend: str = "k8s", namespace: str = "agent-sandbox-demo"
) -> ToolBuildContext:
    settings = Settings(
        _env_file=None,
        llm_provider=LLMProvider.OLLAMA,
        sandbox_backend=backend,
        sandbox_namespace=namespace,
        sandbox_run_timeout=90,
    )
    services = RuntimeServices.default()
    services_with_sandbox = RuntimeServices(
        clock=services.clock,
        metrics=services.metrics,
        memory_sink=services.memory_sink,
        sandbox=cast("SandboxExecutor", executor),
    )
    return ToolBuildContext(
        settings=settings,
        services=services_with_sandbox,
        catalog=cast("CapabilityCatalog", object()),
    )


def _store_artifact(tmp_path: Path, data: bytes = b"packed-sample") -> tuple[Path, str]:
    root = tmp_path / "artifacts"
    source = tmp_path / "sample.bin"
    source.write_bytes(data)
    return root, ArtifactStore(root).acquire(source)


def _staged(executor: _FakeExecutor) -> StagedArtifact:
    handle = SandboxHandle(key="case-1", pool="deobfuscation-tools", backend_id="pod-1")
    return StagedArtifact(
        executor=executor,
        handle=handle,
        artifact_id="a" * 64,
        input_path="/work/floss/" + "a" * 64 + "/input",
        work_dir="/work/floss/" + "a" * 64,
        timeout=47.5,
    )


def _direct_staged(executor: _FakeExecutor) -> StagedArtifact:
    staged = _staged(executor)
    return StagedArtifact(
        executor=staged.executor,
        handle=staged.handle,
        artifact_id=staged.artifact_id,
        input_path=staged.input_path,
        work_dir=staged.work_dir,
        timeout=staged.timeout,
        namespace="agent-sandbox-demo",
        output_cap=65_536,
        direct_kubectl=True,
    )


def test_stage_requires_explicit_k8s_backend() -> None:
    executor = _FakeExecutor()

    with pytest.raises(
        DeobfuscationUnavailable,
        match="sandbox tools require sandbox_backend='k8s'",
    ):
        stage_artifact(
            _build_context(executor=executor, backend="local"),
            "a" * 64,
            _FakeToolContext(),
            tool_name="upx",
        )

    assert executor.claims == []
    assert executor.writes == []
    assert executor.runs == []
    assert executor.reads == []


def test_stage_rejects_local_executor_even_when_backend_setting_is_k8s(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import reverse_engineering.tools.deobfuscation.runtime as runtime

    root, artifact_id = _store_artifact(tmp_path)
    monkeypatch.setattr(runtime, "default_artifacts_root", lambda: root)

    class _RecordingLocalExecutor(LocalSandboxExecutor):
        def __init__(self) -> None:
            super().__init__(root=tmp_path / "local-sandbox")
            self.calls: list[str] = []

        def claim(self, *, key: str, pool: str) -> SandboxHandle:
            self.calls.append("claim")
            return super().claim(key=key, pool=pool)

        def run(self, handle: SandboxHandle, command: str, *, timeout: float) -> ExecutionResult:
            self.calls.append("run")
            return super().run(handle, command, timeout=timeout)

        def write_file(self, handle: SandboxHandle, path: str, data: bytes) -> None:
            self.calls.append("write")
            super().write_file(handle, path, data)

    executor = _RecordingLocalExecutor()

    with pytest.raises(DeobfuscationUnavailable, match="requires K8sSandboxExecutor"):
        stage_artifact(
            _build_context(executor=executor, backend="k8s"),
            artifact_id,
            _FakeToolContext({SessionKeys.SANDBOX_CASE_ID: "case-local"}),
            tool_name="upx",
        )

    assert executor.calls == []


def test_stage_rejects_non_sha256_artifact_id() -> None:
    executor = _FakeExecutor()

    with pytest.raises(ValueError, match="artifact_id must be a lowercase SHA-256"):
        stage_artifact(
            _build_context(executor=executor),
            "not-a-digest",
            _FakeToolContext(),
            tool_name="upx",
        )

    assert executor.claims == []


@pytest.mark.parametrize("tool_name", ["../upx", "upx/tool", ".", "UPX", "upx;id"])
def test_stage_rejects_unsafe_tool_name_before_executor_calls(tool_name: str) -> None:
    executor = _FakeExecutor()

    with pytest.raises(ValueError, match="tool_name must be a safe single path component"):
        stage_artifact(
            _build_context(executor=executor),
            "a" * 64,
            _FakeToolContext({SessionKeys.SANDBOX_CASE_ID: "case-1"}),
            tool_name=tool_name,
        )

    assert executor.claims == []
    assert executor.runs == []
    assert executor.writes == []


def test_stage_claims_case_scoped_pool_and_writes_fixed_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import reverse_engineering.tools.deobfuscation.runtime as runtime

    root, artifact_id = _store_artifact(tmp_path)
    monkeypatch.setattr(runtime, "default_artifacts_root", lambda: root)
    executor = _FakeExecutor()

    staged = stage_artifact(
        _build_context(executor=executor),
        artifact_id,
        _FakeToolContext({SessionKeys.SANDBOX_CASE_ID: "case-77"}),
        tool_name="upx",
    )

    expected_dir = f"/work/upx/{artifact_id}"
    assert executor.claims == [("case-77", "deobfuscation-tools")]
    assert executor.runs == [
        (
            staged.handle,
            f"test '!' -L /work/upx && rm -rf -- {expected_dir} "
            f"&& mkdir -m 0700 -p -- {expected_dir}",
            30,
        )
    ]
    assert executor.writes == [(staged.handle, f"{expected_dir}/input", b"packed-sample")]
    assert staged.input_path == f"{expected_dir}/input"
    assert staged.work_dir == expected_dir
    assert staged.timeout == 90.0


def test_live_k8s_runtime_uses_claimed_pod_exec_and_file_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exec-only tool images must not use the sandbox router's :8888 API."""
    import reverse_engineering.tools.deobfuscation.runtime as runtime

    root, artifact_id = _store_artifact(tmp_path)
    monkeypatch.setattr(runtime, "default_artifacts_root", lambda: root)
    executor = _FakeExecutor()
    monkeypatch.setattr(runtime, "K8sSandboxExecutor", _FakeExecutor, raising=False)
    exec_calls: list[tuple[list[str], str, str, float, int]] = []
    writes: list[tuple[str, str, str, bytes]] = []
    reads: list[tuple[list[str], str, str, float, int]] = []

    def _exec_result(
        argv: list[str],
        namespace: str,
        pod: str,
        *,
        timeout: float,
        output_cap: int,
    ) -> ExecutionResult:
        exec_calls.append((argv, namespace, pod, timeout, output_cap))
        if argv[0] == "stat":
            return ExecutionResult(exit_code=0, stdout="7\n", stderr="")
        return ExecutionResult(exit_code=0, stdout="ok", stderr="")

    def _write_bytes(data: bytes, namespace: str, pod: str, path: str) -> None:
        writes.append((namespace, pod, path, data))

    def _exec_bytes(
        argv: list[str],
        namespace: str,
        pod: str,
        *,
        timeout: float,
        output_cap: int,
    ) -> object:
        reads.append((argv, namespace, pod, timeout, output_cap))
        return runtime._BoundedProcessResult(
            returncode=0,
            stdout=b"payload",
            stderr=b"",
            stdout_truncated=False,
            stderr_truncated=False,
        )

    monkeypatch.setattr(runtime, "_kubectl_exec_result", _exec_result, raising=False)
    monkeypatch.setattr(runtime, "_kubectl_write_bytes", _write_bytes, raising=False)
    monkeypatch.setattr(runtime, "_kubectl_exec_bytes", _exec_bytes, raising=False)

    staged = stage_artifact(
        _build_context(executor=executor),
        artifact_id,
        _FakeToolContext({SessionKeys.SANDBOX_CASE_ID: "case-live"}),
        tool_name="upx",
    )
    result = run_argv(staged, ["upx", "-t", staged.input_path])
    output = read_bounded_file(staged, f"{staged.work_dir}/result.bin", max_bytes=7)

    assert result.exit_code == 0
    assert output == b"payload"
    assert executor.runs == []
    assert executor.writes == []
    assert executor.reads == []
    assert writes == [
        (
            "agent-sandbox-demo",
            "deobfuscation-tools-case-live",
            staged.input_path,
            b"packed-sample",
        )
    ]
    assert reads == [
        (
            ["head", "-c", "8", "--", f"{staged.work_dir}/result.bin"],
            "agent-sandbox-demo",
            "deobfuscation-tools-case-live",
            90.0,
            8,
        )
    ]
    assert [call[0][0] for call in exec_calls] == ["sh", "upx", "stat"]


@pytest.mark.parametrize(
    ("namespace", "pod"),
    [
        ("Bad_Namespace", "pod-1"),
        ("agent-sandbox-demo", "Bad_Pod"),
        ("agent-sandbox-demo", "-pod"),
        ("agent-sandbox-demo", "pod..name"),
    ],
)
def test_live_stage_rejects_invalid_kubernetes_names_after_claim_before_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    namespace: str,
    pod: str,
) -> None:
    import reverse_engineering.tools.deobfuscation.runtime as runtime

    root, artifact_id = _store_artifact(tmp_path)
    monkeypatch.setattr(runtime, "default_artifacts_root", lambda: root)
    executor = _FakeExecutor()
    executor._handles[("case-name", "deobfuscation-tools")] = SandboxHandle(
        key="case-name",
        pool="deobfuscation-tools",
        backend_id=pod,
    )
    monkeypatch.setattr(runtime, "K8sSandboxExecutor", _FakeExecutor)
    transport_calls: list[object] = []
    monkeypatch.setattr(
        runtime,
        "_kubectl_exec_result",
        lambda *_args, **_kwargs: transport_calls.append(object()),
    )
    monkeypatch.setattr(
        runtime,
        "_kubectl_write_bytes",
        lambda *_args, **_kwargs: transport_calls.append(object()),
    )

    with pytest.raises(ValueError, match="Kubernetes"):
        stage_artifact(
            _build_context(executor=executor, namespace=namespace),
            artifact_id,
            _FakeToolContext({SessionKeys.SANDBOX_CASE_ID: "case-name"}),
            tool_name="upx",
        )

    assert executor.claims == [("case-name", "deobfuscation-tools")]
    assert transport_calls == []
    assert executor.runs == []
    assert executor.writes == []


def test_bounded_process_drains_both_pipes_without_retaining_excess() -> None:
    import reverse_engineering.tools.deobfuscation.runtime as runtime

    script = "import os;os.write(1,b'A'*200000);os.write(2,b'B'*200000)"

    result = runtime._run_bounded_process(
        [sys.executable, "-c", script],
        timeout=5,
        stdout_cap=17,
        stderr_cap=19,
    )

    assert result.returncode == 0
    assert result.stdout == b"A" * 17
    assert result.stderr == b"B" * 19
    assert result.stdout_truncated is True
    assert result.stderr_truncated is True


def test_bounded_process_timeout_kills_and_reaps_local_process(tmp_path: Path) -> None:
    import reverse_engineering.tools.deobfuscation.runtime as runtime

    pid_path = tmp_path / "pid"
    script = f"import os,time;open({str(pid_path)!r},'w').write(str(os.getpid()));time.sleep(30)"
    started = time.monotonic()

    with pytest.raises(RuntimeError, match="timed out"):
        runtime._run_bounded_process(
            [sys.executable, "-c", script],
            timeout=0.5,
            stdout_cap=16,
            stderr_cap=16,
        )

    assert time.monotonic() - started < 5
    pid = int(pid_path.read_text())
    with pytest.raises(ProcessLookupError):
        import os

        os.kill(pid, 0)


def test_kubectl_exec_wraps_remote_command_in_timeout_and_bounds_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import reverse_engineering.tools.deobfuscation.runtime as runtime

    calls: list[tuple[list[str], float, int, int]] = []

    def _run(command: list[str], *, timeout: float, stdout_cap: int, stderr_cap: int) -> object:
        calls.append((command, timeout, stdout_cap, stderr_cap))
        return runtime._BoundedProcessResult(
            returncode=7,
            stdout=b"out",
            stderr=b"err",
            stdout_truncated=False,
            stderr_truncated=False,
        )

    monkeypatch.setattr(runtime, "_run_bounded_process", _run)

    result = runtime._kubectl_exec_result(
        ["upx", "-t", "/work/upx/" + "a" * 64 + "/input"],
        "agent-sandbox-demo",
        "deobfuscation-tools-pool-abc12",
        timeout=47.5,
        output_cap=123,
    )

    assert calls == [
        (
            [
                "kubectl",
                "exec",
                "pod/deobfuscation-tools-pool-abc12",
                "-n",
                "agent-sandbox-demo",
                "--",
                "timeout",
                "--signal=TERM",
                "--kill-after=5s",
                "47.5s",
                "upx",
                "-t",
                "/work/upx/" + "a" * 64 + "/input",
            ],
            62.5,
            123,
            123,
        )
    ]
    assert result == ExecutionResult(exit_code=7, stdout="out", stderr="err")


@pytest.mark.parametrize(
    ("timeout", "output_cap"),
    [(0, 1), (-1, 1), (True, 1), (1, 0), (1, -1), (1, True)],
)
def test_kubectl_exec_rejects_invalid_bounds_without_spawning(
    monkeypatch: pytest.MonkeyPatch, timeout: object, output_cap: object
) -> None:
    import reverse_engineering.tools.deobfuscation.runtime as runtime

    calls: list[object] = []
    monkeypatch.setattr(
        runtime,
        "_run_bounded_process",
        lambda *_args, **_kwargs: calls.append(object()),
    )

    with pytest.raises(ValueError, match="positive"):
        runtime._kubectl_exec_result(
            ["true"],
            "agent-sandbox-demo",
            "deobfuscation-tools-pool-abc12",
            timeout=cast("float", timeout),
            output_cap=cast("int", output_cap),
        )

    assert calls == []


@pytest.mark.parametrize(
    ("namespace", "pod"),
    [
        ("Bad_Namespace", "pod-1"),
        ("namespace", "Bad_Pod"),
        ("namespace", ".pod"),
    ],
)
def test_kubectl_exec_rejects_invalid_names_without_spawning(
    monkeypatch: pytest.MonkeyPatch, namespace: str, pod: str
) -> None:
    import reverse_engineering.tools.deobfuscation.runtime as runtime

    calls: list[object] = []
    monkeypatch.setattr(
        runtime,
        "_run_bounded_process",
        lambda *_args, **_kwargs: calls.append(object()),
    )

    with pytest.raises(ValueError, match="Kubernetes"):
        runtime._kubectl_exec_result(
            ["true"],
            namespace,
            pod,
            timeout=1,
            output_cap=1,
        )

    assert calls == []


def test_kubectl_cp_uses_exact_endpoints_and_bounded_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import reverse_engineering.tools.deobfuscation.runtime as runtime

    calls: list[tuple[list[str], float, int, int]] = []

    def _run(command: list[str], *, timeout: float, stdout_cap: int, stderr_cap: int) -> object:
        calls.append((command, timeout, stdout_cap, stderr_cap))
        return runtime._BoundedProcessResult(
            returncode=0,
            stdout=b"",
            stderr=b"",
            stdout_truncated=False,
            stderr_truncated=False,
        )

    monkeypatch.setattr(runtime, "_run_bounded_process", _run)

    runtime._kubectl_cp(
        "/tmp/input",
        "agent-sandbox-demo/deobfuscation-tools-pool-abc12:/work/upx/" + "a" * 64 + "/input",
    )

    assert calls == [
        (
            [
                "kubectl",
                "cp",
                "/tmp/input",
                "agent-sandbox-demo/deobfuscation-tools-pool-abc12:/work/upx/"
                + "a" * 64
                + "/input",
            ],
            120,
            4_096,
            4_096,
        )
    ]


@pytest.mark.parametrize(
    ("result", "message"),
    [
        (
            (1, b"", b"copy denied", False, False),
            "kubectl cp failed",
        ),
        (
            (0, b"x", b"", True, False),
            "kubectl cp output exceeded",
        ),
    ],
)
def test_kubectl_cp_rejects_failure_or_truncated_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
    result: tuple[int, bytes, bytes, bool, bool],
    message: str,
) -> None:
    import reverse_engineering.tools.deobfuscation.runtime as runtime

    monkeypatch.setattr(
        runtime,
        "_run_bounded_process",
        lambda *_args, **_kwargs: runtime._BoundedProcessResult(
            returncode=result[0],
            stdout=result[1],
            stderr=result[2],
            stdout_truncated=result[3],
            stderr_truncated=result[4],
        ),
    )

    with pytest.raises(RuntimeError, match=message):
        runtime._kubectl_cp("/tmp/input", "ns/pod:/work/output")


def test_kubectl_cp_propagates_timeout_after_kill_and_reap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import reverse_engineering.tools.deobfuscation.runtime as runtime

    monkeypatch.setattr(
        runtime,
        "_run_bounded_process",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("process timed out after 120s")
        ),
    )

    with pytest.raises(RuntimeError, match="timed out"):
        runtime._kubectl_cp("/tmp/input", "ns/pod:/work/output")


def test_stage_reads_at_most_cap_plus_one_bytes_when_input_cap_is_supplied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import reverse_engineering.tools.deobfuscation.runtime as runtime

    class _RecordingReader:
        def __init__(self, source: _RecordingSource) -> None:
            self.source = source

        def __enter__(self) -> _RecordingReader:
            return self

        def __exit__(self, *_args: object) -> None:
            pass

        def read(self, size: int = -1) -> bytes:
            self.source.read_sizes.append(size)
            return self.source.data if size == -1 else self.source.data[:size]

    class _RecordingSource:
        def __init__(self, data: bytes) -> None:
            self.data = data
            self.read_sizes: list[int] = []

        def open(self, mode: str) -> _RecordingReader:
            assert mode == "rb"
            return _RecordingReader(self)

    class _FakeArtifactStore:
        def __init__(self, _root: object) -> None:
            pass

        def path_for(self, _artifact_id: str) -> _RecordingSource:
            return source

    source = _RecordingSource(b"abcde")
    monkeypatch.setattr(runtime, "ArtifactStore", _FakeArtifactStore)
    executor = _FakeExecutor()

    staged = stage_artifact(
        _build_context(executor=executor),
        "a" * 64,
        _FakeToolContext({SessionKeys.SANDBOX_CASE_ID: "case-1"}),
        tool_name="floss",
        max_input_bytes=5,
    )

    assert source.read_sizes == [6]
    assert executor.writes == [(staged.handle, f"{staged.work_dir}/input", b"abcde")]


def test_stage_rejects_oversize_capped_input_before_claim_or_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import reverse_engineering.tools.deobfuscation.runtime as runtime

    class _Source:
        def __init__(self) -> None:
            self.read_sizes: list[int] = []

        def open(self, mode: str) -> _Source:
            assert mode == "rb"
            return self

        def __enter__(self) -> _Source:
            return self

        def __exit__(self, *_args: object) -> None:
            pass

        def read(self, size: int = -1) -> bytes:
            self.read_sizes.append(size)
            return b"abcdef"[:size]

    class _FakeArtifactStore:
        def __init__(self, _root: object) -> None:
            pass

        def path_for(self, _artifact_id: str) -> _Source:
            return source

    source = _Source()
    monkeypatch.setattr(runtime, "ArtifactStore", _FakeArtifactStore)
    executor = _FakeExecutor()

    with pytest.raises(ArtifactInputTooLarge, match="artifact input exceeds maximum size"):
        stage_artifact(
            _build_context(executor=executor),
            "a" * 64,
            _FakeToolContext({SessionKeys.SANDBOX_CASE_ID: "case-1"}),
            tool_name="floss",
            max_input_bytes=5,
        )

    assert source.read_sizes == [6]
    assert executor.claims == []
    assert executor.runs == []
    assert executor.writes == []


def test_stage_rejects_negative_input_cap_before_executor_calls() -> None:
    executor = _FakeExecutor()

    with pytest.raises(ValueError, match="max_input_bytes must be nonnegative"):
        stage_artifact(
            _build_context(executor=executor),
            "a" * 64,
            _FakeToolContext({SessionKeys.SANDBOX_CASE_ID: "case-1"}),
            tool_name="floss",
            max_input_bytes=-1,
        )

    assert executor.claims == []
    assert executor.runs == []
    assert executor.writes == []


def test_repeated_stage_reuses_same_case_pool_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import reverse_engineering.tools.deobfuscation.runtime as runtime

    root, artifact_id = _store_artifact(tmp_path)
    monkeypatch.setattr(runtime, "default_artifacts_root", lambda: root)
    executor = _FakeExecutor()
    context = _build_context(executor=executor)
    tool_context = _FakeToolContext({SessionKeys.SANDBOX_CASE_ID: "repeat-case"})

    first = stage_artifact(context, artifact_id, tool_context, tool_name="upx")
    second = stage_artifact(context, artifact_id, tool_context, tool_name="floss")

    assert executor.claims == [
        ("repeat-case", "deobfuscation-tools"),
        ("repeat-case", "deobfuscation-tools"),
    ]
    assert first.handle.key == second.handle.key == "repeat-case"
    assert first.handle.pool == second.handle.pool == "deobfuscation-tools"
    assert first.handle is second.handle


@pytest.mark.parametrize("state_values", [None, {}, {SessionKeys.SANDBOX_CASE_ID: "  "}])
def test_stage_requires_nonempty_case_id_before_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state_values: dict[str, object] | None,
) -> None:
    import reverse_engineering.tools.deobfuscation.runtime as runtime

    root, artifact_id = _store_artifact(tmp_path)
    monkeypatch.setattr(runtime, "default_artifacts_root", lambda: root)
    executor = _FakeExecutor()
    tool_context = _NoStateToolContext() if state_values is None else _FakeToolContext(state_values)

    with pytest.raises(DeobfuscationUnavailable, match="sandbox identity unavailable") as error:
        stage_artifact(
            _build_context(executor=executor), artifact_id, tool_context, tool_name="upx"
        )

    assert isinstance(error.value.__cause__, SandboxIdentityError)
    assert executor.claims == []
    assert executor.runs == []
    assert executor.writes == []


def test_stage_translates_identity_access_failure_before_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import reverse_engineering.tools.deobfuscation.runtime as runtime

    root, artifact_id = _store_artifact(tmp_path)
    monkeypatch.setattr(runtime, "default_artifacts_root", lambda: root)
    executor = _FakeExecutor()

    with pytest.raises(DeobfuscationUnavailable, match="sandbox identity unavailable") as error:
        stage_artifact(
            _build_context(executor=executor),
            artifact_id,
            _ExplodingGetterToolContext(),
            tool_name="upx",
        )

    assert isinstance(error.value.__cause__, SandboxIdentityError)
    assert executor.claims == []
    assert executor.runs == []
    assert executor.writes == []


@pytest.mark.parametrize(
    "result",
    [
        ExecutionResult(exit_code=1, stdout="", stderr="mkdir denied"),
        ExecutionResult(exit_code=0, stdout="partial", stderr="", truncated=True),
    ],
)
def test_stage_rejects_failed_or_truncated_setup_before_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, result: ExecutionResult
) -> None:
    import reverse_engineering.tools.deobfuscation.runtime as runtime

    root, artifact_id = _store_artifact(tmp_path)
    monkeypatch.setattr(runtime, "default_artifacts_root", lambda: root)
    executor = _FakeExecutor()
    executor.results.append(result)

    with pytest.raises(RuntimeError, match="failed to prepare sandbox work directory"):
        stage_artifact(
            _build_context(executor=executor),
            artifact_id,
            _FakeToolContext({SessionKeys.SANDBOX_CASE_ID: "case-setup"}),
            tool_name="upx",
        )

    assert executor.claims == [("case-setup", "deobfuscation-tools")]
    assert len(executor.runs) == 1
    assert executor.writes == []


def test_run_uses_configured_timeout_and_tokenized_command() -> None:
    executor = _FakeExecutor()
    executor.results.extend(
        [
            ExecutionResult(exit_code=0, stdout="ok", stderr=""),
            ExecutionResult(exit_code=0, stdout="ok", stderr=""),
        ]
    )
    staged = _staged(executor)

    result = run_argv(staged, ["floss", "--only", "static strings", staged.input_path])
    redirected = run_argv_to_file(
        staged, ["floss", staged.input_path], f"{staged.work_dir}/out.txt"
    )

    assert result == ExecutionResult(exit_code=0, stdout="ok", stderr="")
    assert redirected == ExecutionResult(exit_code=0, stdout="ok", stderr="")
    assert executor.runs == [
        (staged.handle, "floss --only 'static strings' " + staged.input_path, 47.5),
        (staged.handle, f"floss {staged.input_path} > {staged.work_dir}/out.txt", 47.5),
    ]


@pytest.mark.parametrize(
    "output_path",
    [
        "/tmp/out.txt",
        "/work/floss/" + "a" * 64,
        "/work/floss/" + "a" * 64 + "/../out.txt",
        "/work/floss/" + "a" * 64 + "/input",
        "/work/floss/" + "a" * 64 + "/out;id",
    ],
)
def test_run_to_file_rejects_invalid_output_path_without_executor_calls(output_path: str) -> None:
    executor = _FakeExecutor()
    staged = _staged(executor)

    with pytest.raises(ValueError, match="remote path"):
        run_argv_to_file(staged, ["floss", staged.input_path], output_path)

    assert executor.runs == []


def test_remote_size_rejects_over_limit_before_read() -> None:
    executor = _FakeExecutor()
    executor.results.extend(
        [
            ExecutionResult(exit_code=0, stdout="33\n", stderr=""),
            ExecutionResult(exit_code=0, stdout="33\n", stderr=""),
        ]
    )
    staged = _staged(executor)
    path = f"{staged.work_dir}/recovered.bin"
    executor.files[path] = b"x" * 33

    assert remote_file_size(staged, path) == 33
    assert executor.runs == [
        (staged.handle, f"stat --format=%s -- {path}", 47.5),
    ]
    with pytest.raises(ValueError, match="remote file exceeds maximum size"):
        read_bounded_file(staged, path, max_bytes=32)

    assert executor.reads == []


def test_read_bounded_file_returns_remote_bytes_after_size_check() -> None:
    executor = _FakeExecutor()
    executor.results.append(ExecutionResult(exit_code=0, stdout="7\n", stderr=""))
    staged = _staged(executor)
    path = f"{staged.work_dir}/report.json"
    executor.files[path] = b"payload"

    assert read_bounded_file(staged, path, max_bytes=7) == b"payload"
    assert executor.reads == [(staged.handle, path)]


@pytest.mark.parametrize(
    ("preflight_size", "payload", "max_bytes"),
    [
        (3, b"xx", 3),
        (3, b"xxxx", 3),
        (3, b"xxxx", 4),
    ],
)
def test_direct_bounded_read_rejects_shrinking_or_growing_remote_file(
    monkeypatch: pytest.MonkeyPatch,
    preflight_size: int,
    payload: bytes,
    max_bytes: int,
) -> None:
    import reverse_engineering.tools.deobfuscation.runtime as runtime

    executor = _FakeExecutor()
    staged = _direct_staged(executor)
    path = f"{staged.work_dir}/result.bin"
    calls: list[tuple[list[str], int]] = []
    monkeypatch.setattr(runtime, "remote_file_size", lambda *_args: preflight_size)

    def _exec_bytes(
        argv: list[str],
        _namespace: str,
        _pod: str,
        *,
        timeout: float,
        output_cap: int,
    ) -> object:
        assert timeout == staged.timeout
        calls.append((argv, output_cap))
        return runtime._BoundedProcessResult(
            returncode=0,
            stdout=payload[:output_cap],
            stderr=b"",
            stdout_truncated=len(payload) > output_cap,
            stderr_truncated=False,
        )

    monkeypatch.setattr(runtime, "_kubectl_exec_bytes", _exec_bytes)

    with pytest.raises(RuntimeError, match="remote file changed during read"):
        read_bounded_file(staged, path, max_bytes=max_bytes)

    assert calls == [(["head", "-c", str(max_bytes + 1), "--", path], max_bytes + 1)]


def test_direct_bounded_read_returns_binary_without_decoding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import reverse_engineering.tools.deobfuscation.runtime as runtime

    staged = _direct_staged(_FakeExecutor())
    path = f"{staged.work_dir}/result.bin"
    payload = b"\x00\xff\x80binary"
    monkeypatch.setattr(runtime, "remote_file_size", lambda *_args: len(payload))
    monkeypatch.setattr(
        runtime,
        "_kubectl_exec_bytes",
        lambda *_args, **_kwargs: runtime._BoundedProcessResult(
            returncode=0,
            stdout=payload,
            stderr=b"",
            stdout_truncated=False,
            stderr_truncated=False,
        ),
    )

    assert read_bounded_file(staged, path, max_bytes=len(payload)) == payload


@pytest.mark.parametrize(
    "result",
    [
        ExecutionResult(exit_code=1, stdout="", stderr="stat failed"),
        ExecutionResult(exit_code=0, stdout="12\n", stderr="", truncated=True),
        ExecutionResult(exit_code=0, stdout="-1\n", stderr=""),
        ExecutionResult(exit_code=0, stdout="12\nextra", stderr=""),
        ExecutionResult(exit_code=0, stdout=" 12\n", stderr=""),
    ],
)
def test_remote_size_rejects_non_decimal_or_unreliable_results(result: ExecutionResult) -> None:
    executor = _FakeExecutor()
    executor.results.append(result)
    staged = _staged(executor)

    with pytest.raises(RuntimeError, match="failed to measure remote file"):
        remote_file_size(staged, f"{staged.work_dir}/result.bin")


def test_bounded_read_rejects_negative_limit_without_executor_calls() -> None:
    executor = _FakeExecutor()
    staged = _staged(executor)

    with pytest.raises(ValueError, match="max_bytes must be nonnegative"):
        read_bounded_file(staged, f"{staged.work_dir}/result.bin", max_bytes=-1)

    assert executor.runs == []
    assert executor.reads == []


def test_read_bounded_prefix_returns_leading_bytes_on_direct_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import reverse_engineering.tools.deobfuscation.runtime as runtime

    staged = _direct_staged(_FakeExecutor())
    path = f"{staged.work_dir}/result.bin"
    payload = b"\x00\xff\x80binary-prefix-and-then-some-more"
    calls: list[tuple[list[str], int]] = []

    def _exec_bytes(
        argv: list[str],
        _namespace: str,
        _pod: str,
        *,
        timeout: float,
        output_cap: int,
    ) -> object:
        assert timeout == staged.timeout
        calls.append((argv, output_cap))
        return runtime._BoundedProcessResult(
            returncode=0,
            stdout=payload[:output_cap],
            stderr=b"",
            stdout_truncated=len(payload) > output_cap,
            stderr_truncated=False,
        )

    monkeypatch.setattr(runtime, "_kubectl_exec_bytes", _exec_bytes)

    # A prefix shorter than the file returns exactly those bytes, byte-accurately,
    # without raising on the (expected) larger file -- unlike read_bounded_file.
    assert read_bounded_prefix(staged, path, 8) == payload[:8]
    assert calls == [(["head", "-c", "8", "--", path], 8)]


def test_read_bounded_prefix_zero_bytes_makes_no_remote_call() -> None:
    staged = _direct_staged(_FakeExecutor())

    assert read_bounded_prefix(staged, f"{staged.work_dir}/result.bin", 0) == b""


def test_read_bounded_prefix_rejects_negative_limit() -> None:
    executor = _FakeExecutor()
    staged = _staged(executor)

    with pytest.raises(ValueError, match="max_bytes must be nonnegative"):
        read_bounded_prefix(staged, f"{staged.work_dir}/result.bin", -1)

    assert executor.runs == []
    assert executor.reads == []


@pytest.mark.parametrize("contents", [b"xx", b"xxxx"])
def test_bounded_read_rejects_changed_or_oversize_remote_file(contents: bytes) -> None:
    executor = _FakeExecutor()
    executor.results.append(ExecutionResult(exit_code=0, stdout="3\n", stderr=""))
    staged = _staged(executor)
    path = f"{staged.work_dir}/result.bin"
    executor.files[path] = contents

    with pytest.raises(RuntimeError, match="remote file changed during read"):
        read_bounded_file(staged, path, max_bytes=3)

    assert executor.reads == [(staged.handle, path)]


def _valid_classification(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "artifact_id": "b" * 64,
        "deobf_plan": {"upx": True, "floss": False},
        "pcode_preferred": True,
        "obf_class": "upx",
        "pre_snapshot": {
            "size": 1,
            "function_count": 2,
            "import_count": 3,
            "string_count": 4,
            "section_count": 5,
        },
    }
    data.update(overrides)
    return data


def test_parse_classification_accepts_exact_json_contract() -> None:
    data = _valid_classification()

    assert parse_classification(_FakeState({CLASSIFICATION_KEY: json.dumps(data)})) == DeobfPlan(
        artifact_id="b" * 64,
        upx=True,
        floss=False,
        pcode_preferred=True,
        obf_class="upx",
        pre_snapshot={
            "size": 1,
            "function_count": 2,
            "import_count": 3,
            "string_count": 4,
            "section_count": 5,
        },
    )


def test_parse_classification_accepts_json_code_fenced_payload() -> None:
    # Regression: deobf_classify is a composed agent with no output_schema, so its
    # classification is free-form model text that routinely arrives wrapped in a
    # ```json code fence. A bare json.loads rejected the fence as "invalid
    # deobfuscation classification JSON"; routing through loads_model_json strips
    # the fence and parses it. This would have raised before the fix.
    fenced = "```json\n" + json.dumps(_valid_classification()) + "\n```"

    assert parse_classification(_FakeState({CLASSIFICATION_KEY: fenced})) == DeobfPlan(
        artifact_id="b" * 64,
        upx=True,
        floss=False,
        pcode_preferred=True,
        obf_class="upx",
        pre_snapshot={
            "size": 1,
            "function_count": 2,
            "import_count": 3,
            "string_count": 4,
            "section_count": 5,
        },
    )


def test_parse_classification_rejects_unrecoverable_text() -> None:
    # A genuinely malformed classification is unrecoverable even by the
    # json_repair salvage layer, so it still raises the same failure the bare
    # json.loads raised -- behavior preserved by the loads_model_json routing.
    with pytest.raises(ValueError, match="invalid deobfuscation classification JSON"):
        parse_classification(_FakeState({CLASSIFICATION_KEY: "this is not json at all ~~~"}))


@pytest.mark.parametrize(
    "key", ["artifact_id", "deobf_plan", "pcode_preferred", "obf_class", "pre_snapshot"]
)
def test_parse_classification_rejects_missing_top_level_key(key: str) -> None:
    data = _valid_classification()
    del data[key]

    with pytest.raises(ValueError, match="top-level keys"):
        parse_classification(_FakeState({CLASSIFICATION_KEY: data}))


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (_valid_classification(extra=True), "top-level keys"),
        (_valid_classification(deobf_plan={"upx": True}), "deobf_plan keys"),
        (
            _valid_classification(deobf_plan={"upx": True, "floss": False, "extra": False}),
            "deobf_plan keys",
        ),
        (_valid_classification(deobf_plan={"upx": 1, "floss": False}), "upx must be a boolean"),
        (_valid_classification(pcode_preferred=1), "pcode_preferred must be a boolean"),
        (_valid_classification(obf_class="packed"), "obf_class"),
        (_valid_classification(pre_snapshot={"size": 0}), "pre_snapshot keys"),
        (
            _valid_classification(
                pre_snapshot={**_valid_classification()["pre_snapshot"], "extra": 0}
            ),
            "pre_snapshot keys",
        ),
        (
            _valid_classification(
                pre_snapshot={**_valid_classification()["pre_snapshot"], "size": True}
            ),
            "nonnegative integers",
        ),
        (_valid_classification(artifact_id="A" * 64), "artifact_id"),
    ],
)
def test_parse_classification_rejects_schema_violations(
    data: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        parse_classification(_FakeState({CLASSIFICATION_KEY: data}))


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_parse_classification_rejects_non_standard_json_constants(constant: str) -> None:
    raw = json.dumps(_valid_classification()).replace("true", constant, 1)

    with pytest.raises(ValueError, match="invalid deobfuscation classification JSON"):
        parse_classification(_FakeState({CLASSIFICATION_KEY: raw}))
