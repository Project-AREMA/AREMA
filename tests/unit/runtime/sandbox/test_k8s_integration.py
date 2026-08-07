"""Opt-in integration test against a real Kind cluster + the radare2 sandbox.

Skipped unless ``AREMA_K8S_INTEGRATION=1`` and a cluster is reachable.

Prerequisites (run first, in order):
    make setup-sandbox         # install the Agent Sandbox framework into the cluster
    make sandbox-build-images  # build the engine images and load them into kind
    make sandbox-up            # apply the SandboxTemplates + WarmPools

Then:
    AREMA_K8S_INTEGRATION=1 uv run --extra dev --extra sandbox \
        pytest tests/unit/runtime/sandbox/test_k8s_integration.py -v
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.k8s


@pytest.fixture(autouse=True)
def _skip_without_cluster() -> None:
    if os.environ.get("AREMA_K8S_INTEGRATION") != "1":
        pytest.skip("set AREMA_K8S_INTEGRATION=1 to run the live k8s sandbox test")
    # The session-wide _redirect_home fixture points HOME at a temp dir (to keep the
    # default SQLite store out of the real home), which hides ~/.kube/config from the
    # kubernetes client's load_kube_config(). Repoint KUBECONFIG at the real home's
    # config (resolved via the passwd DB, which ignores the HOME env override).
    if not os.environ.get("KUBECONFIG"):
        import pwd

        real_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        candidate = real_home / ".kube" / "config"
        if candidate.exists():
            os.environ["KUBECONFIG"] = str(candidate)


def test_radare2_pool_runs_commands_and_transfers_files() -> None:
    """Claim a radare2 sandbox, run radare2, and round-trip a file via /app."""
    from arema.core.config import Settings
    from arema.runtime.sandbox.k8s import K8sSandboxExecutor

    settings = Settings(
        _env_file=None,
        llm_provider="ollama",
        sandbox_enabled=True,
        sandbox_backend="k8s",
        sandbox_namespace="agent-sandbox-demo",
        sandbox_default_pool="radare2-mcp-pool",
        sandbox_pool_map={"radare2": "radare2-mcp-pool"},
    )
    executor = K8sSandboxExecutor(settings=settings)
    handle = executor.claim(key="integration-radare2", pool="radare2")
    try:
        version = executor.run(handle, "r2 -v", timeout=90)
        assert version.exit_code == 0
        assert "radare2" in version.stdout.lower()

        # The agent-sandbox runtime confines file ops to /app; round-trip a file.
        executor.write_file(handle, "note.txt", b"hello-from-arema")
        assert executor.read_file(handle, "note.txt") == b"hello-from-arema"

        listing = executor.run(handle, "ls -1 /app", timeout=30)
        assert listing.exit_code == 0
        assert "note.txt" in listing.stdout
    finally:
        executor.release_session("integration-radare2")
