"""Case-keyed handle bookkeeping layered over a concrete :class:`SandboxExecutor`.

Adapters implement single-handle primitives (claim/run/write/read/terminate);
this manager enforces idempotent claim per ``(key, pool)`` and whole-session
release, so every adapter inherits identical session semantics.

Design note: every concrete :class:`SandboxExecutor` already implements the full
port (including idempotent ``claim`` and ``release_session``) because the port
requires it -- so for single-threaded use (the current CLI) the raw executor is
sufficient and that is what the composition wires today. This manager adds a
thread-safe :class:`~threading.Lock` around claim/release and is intended for
concurrent callers (e.g. a future ``ParallelAgent`` in Spec B that fans out tool
calls sharing one case). When wiring it, wrap a single executor instance in one
manager and have all concurrent callers go through the manager.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from arema.runtime.sandbox.port import ExecutionResult, SandboxExecutor, SandboxHandle


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
    ) -> ExecutionResult:
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
