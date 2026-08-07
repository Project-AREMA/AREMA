"""A subprocess-backed :class:`SandboxExecutor` for tests and no-cluster dev.

One workdir per (key, pool) under ``root``. Commands run via ``subprocess.run``
with a timeout; files are written/read from the workdir. No kubectl required.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from arema.core.logging import get_logger
from arema.runtime.sandbox.port import (
    ExecutionResult,
    SandboxError,
    SandboxExecutor,
    SandboxHandle,
)

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
            completed = subprocess.run(  # noqa: S602 - dev/test adapter; commands are caller-controlled
                command,
                shell=True,
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
