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
