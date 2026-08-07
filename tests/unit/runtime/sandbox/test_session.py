from __future__ import annotations

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

    def run(self, handle: SandboxHandle, command: str, *, timeout: float) -> ExecutionResult:  # noqa: ARG002
        return ExecutionResult(exit_code=0, stdout=f"ran:{command}", stderr="")

    def write_file(self, handle: SandboxHandle, path: str, data: bytes) -> None:  # noqa: ARG002
        return None

    def read_file(self, handle: SandboxHandle, path: str) -> bytes:  # noqa: ARG002
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
