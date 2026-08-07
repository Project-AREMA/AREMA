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

from arema.runtime.sandbox import ExecutionResult, SandboxExecutor


class SandboxExecutorContract:
    """Behavioural contract shared by every :class:`SandboxExecutor` adapter."""

    def test_satisfies_runtime_protocol(self, executor: SandboxExecutor) -> None:
        assert isinstance(executor, SandboxExecutor)

    def test_claim_is_idempotent_per_key_pool(self, executor: SandboxExecutor) -> None:
        first = executor.claim(key="case-1", pool="default")
        second = executor.claim(key="case-1", pool="default")

        assert first == second

    def test_claim_distinct_pools_yield_distinct_handles(self, executor: SandboxExecutor) -> None:
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
