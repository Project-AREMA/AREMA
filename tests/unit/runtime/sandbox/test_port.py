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
        def run(
            self, handle: SandboxHandle, command: str, *, timeout: float
        ) -> ExecutionResult: ...
        def write_file(self, handle: SandboxHandle, path: str, data: bytes) -> None: ...
        def read_file(self, handle: SandboxHandle, path: str) -> bytes: ...
        def terminate(self, handle: SandboxHandle) -> None: ...
        def release_session(self, key: str) -> None: ...

    assert isinstance(_Stub(), SandboxExecutor)


def test_sandbox_error_is_runtime_error() -> None:
    assert issubclass(SandboxError, RuntimeError)
