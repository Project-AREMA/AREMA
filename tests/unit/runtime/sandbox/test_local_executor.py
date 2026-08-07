from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from arema.runtime.sandbox.local import LocalSandboxExecutor
from sandbox.contract import SandboxExecutorContract

if TYPE_CHECKING:
    from pathlib import Path

    from arema.runtime.sandbox import SandboxExecutor


@pytest.fixture
def executor(tmp_path: Path) -> SandboxExecutor:
    return LocalSandboxExecutor(root=tmp_path, default_pool="default")


class TestLocalExecutor(SandboxExecutorContract):
    """Runs the shared contract against the local (subprocess) adapter."""

    pass
