from __future__ import annotations

from typing import TYPE_CHECKING

from arema.runtime.sandbox.local import LocalSandboxExecutor
from arema.runtime.services import RuntimeServices, build_memory_backed_services

if TYPE_CHECKING:
    from pathlib import Path


class _NullMemory:
    def record_tool_event(self, event: object) -> None: ...


def test_default_services_have_no_sandbox() -> None:
    services = RuntimeServices.default()

    assert services.sandbox is None


def test_build_services_threads_optional_sandbox(tmp_path: Path) -> None:
    sandbox = LocalSandboxExecutor(root=tmp_path, default_pool="default")
    services = build_memory_backed_services(_NullMemory(), sandbox=sandbox)  # type: ignore[arg-type]

    assert services.sandbox is sandbox
