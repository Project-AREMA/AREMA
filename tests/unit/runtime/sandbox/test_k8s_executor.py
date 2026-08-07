"""Mocked-client unit tests for :class:`K8sSandboxExecutor`.

The ``k8s-agent-sandbox`` package is installed (the ``sandbox`` extra), so the
adapter's real ``_build_connection_config`` runs; only ``_load_client`` (which
builds the ``SandboxClient``) is monkeypatched so no real cluster is contacted.

The fake stubs swallow their arguments (``*args``/``**kwargs``) because they
only need to satisfy the call shape; they don't inspect specifics. This keeps
the fakes free of unused-argument noise while mirroring the real client/sandbox
surface (``client.create_sandbox(...)``, ``sandbox.commands.run(...)``,
``sandbox.files.write/read(...)``, ``sandbox.terminate()``).
"""

from __future__ import annotations

import pytest

# These tests construct K8sSandboxExecutor, whose __init__ builds a real
# connection config from k8s_agent_sandbox. Skip gracefully when the optional
# `sandbox` extra is not installed, so `make check` (dev-only) stays green.
pytest.importorskip("k8s_agent_sandbox")

from arema.core.config import Settings
from arema.runtime.sandbox import SandboxError


def _settings(**overrides: object) -> Settings:
    return Settings(
        _env_file=None,
        llm_provider="ollama",
        sandbox_enabled=True,
        sandbox_backend="k8s",
        sandbox_namespace="agent-sandbox-demo",
        sandbox_default_pool="python-runtime-pool",
        sandbox_pool_map={"radare2": "radare2-pool"},
        **overrides,
    )


def test_claim_uses_pool_map_and_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    created: list[str] = []

    class _FakeSandbox:
        def __init__(self, warmpool: str, *_args: object, **_kwargs: object) -> None:
            created.append(warmpool)

        class commands:
            @staticmethod
            def run(*_args: object, **_kwargs: object) -> object:
                class R:
                    exit_code = 0
                    stdout = "ok"
                    stderr = ""

                return R()

        class files:
            @staticmethod
            def write(*_args: object, **_kwargs: object) -> None: ...

            @staticmethod
            def read(*_args: object, **_kwargs: object) -> bytes:
                return b"bytes"

        def terminate(self) -> None: ...

    class _FakeClient:
        def __init__(self, *_args: object, **_kwargs: object) -> None: ...

        def create_sandbox(self, *, warmpool: str, namespace: str, **_: object) -> _FakeSandbox:
            return _FakeSandbox(warmpool, namespace)

    monkeypatch.setattr("arema.runtime.sandbox.k8s._load_client", lambda _config: _FakeClient())

    from arema.runtime.sandbox.k8s import K8sSandboxExecutor

    executor = K8sSandboxExecutor(settings=_settings())
    handle = executor.claim(key="case-1", pool="radare2")
    again = executor.claim(key="case-1", pool="radare2")

    assert handle is again
    assert created == ["radare2-pool"]  # pool_map resolved the logical name


def test_unknown_pool_falls_back_to_default(monkeypatch: pytest.MonkeyPatch) -> None:
    created: list[str] = []

    class _FakeSandbox:
        def __init__(self, warmpool: str, *_args: object, **_kwargs: object) -> None:
            created.append(warmpool)

        class commands:
            @staticmethod
            def run(*_args: object, **_kwargs: object) -> object:
                class R:
                    exit_code = 0
                    stdout = ""
                    stderr = ""

                return R()

        class files:
            @staticmethod
            def write(*_args: object, **_kwargs: object) -> None: ...

            @staticmethod
            def read(*_args: object, **_kwargs: object) -> bytes:
                return b""

        def terminate(self) -> None: ...

    class _FakeClient:
        def create_sandbox(self, *, warmpool: str, namespace: str, **_: object) -> _FakeSandbox:
            return _FakeSandbox(warmpool, namespace)

    monkeypatch.setattr("arema.runtime.sandbox.k8s._load_client", lambda _config: _FakeClient())

    from arema.runtime.sandbox.k8s import K8sSandboxExecutor

    executor = K8sSandboxExecutor(settings=_settings())
    executor.claim(key="case-1", pool="unknown-pool")

    assert created == ["python-runtime-pool"]


def test_run_failure_raises_sandbox_error(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeClient:
        def create_sandbox(self, *_args: object, **_kwargs: object) -> object:
            class S:
                class commands:
                    @staticmethod
                    def run(*_args: object, **_kwargs: object) -> object:
                        raise RuntimeError("pod blew up")

                class files:
                    @staticmethod
                    def write(*_args: object, **_kwargs: object) -> None: ...

                    @staticmethod
                    def read(*_args: object, **_kwargs: object) -> bytes:
                        return b""

                def terminate(self) -> None: ...

            return S()

    monkeypatch.setattr("arema.runtime.sandbox.k8s._load_client", lambda _config: _FakeClient())

    from arema.runtime.sandbox.k8s import K8sSandboxExecutor

    executor = K8sSandboxExecutor(settings=_settings())
    handle = executor.claim(key="case-1", pool="radare2")

    with pytest.raises(SandboxError, match="pod blew up"):
        executor.run(handle, "r2 -v", timeout=10)


def test_claim_backend_id_is_the_pod_name(monkeypatch: pytest.MonkeyPatch) -> None:
    """backend_id must be the claimed pod's name (sandbox_id), not a Python id."""

    class _FakeSandbox:
        # k8s-agent-sandbox exposes the pod name as ``sandbox_id``.
        sandbox_id = "radare2-mcp-pool-abcd1"

        class commands:
            @staticmethod
            def run(*_args: object, **_kwargs: object) -> object: ...

        class files:
            @staticmethod
            def write(*_args: object, **_kwargs: object) -> None: ...

            @staticmethod
            def read(*_args: object, **_kwargs: object) -> bytes:
                return b""

        def terminate(self) -> None: ...

    class _FakeClient:
        def create_sandbox(self, *_args: object, **_kwargs: object) -> _FakeSandbox:
            return _FakeSandbox()

    monkeypatch.setattr("arema.runtime.sandbox.k8s._load_client", lambda _config: _FakeClient())

    from arema.runtime.sandbox.k8s import K8sSandboxExecutor

    executor = K8sSandboxExecutor(settings=_settings())
    handle = executor.claim(key="case-1", pool="radare2")

    assert handle.backend_id == "radare2-mcp-pool-abcd1"


def _executor_with_terminatable_sandbox(
    monkeypatch: pytest.MonkeyPatch,
    *,
    terminate_exc: BaseException | None,
    claim_name: str = "sandbox-claim-abcd1",
    namespace: str = "agent-sandbox-demo",
) -> object:
    """Build an executor whose single sandbox has a configurable terminate."""

    class _FakeSandbox:
        def __init__(self) -> None:
            self.claim_name = claim_name
            self.namespace = namespace

        def terminate(self) -> None:
            if terminate_exc is not None:
                raise terminate_exc

    class _FakeClient:
        def create_sandbox(self, *_args: object, **_kwargs: object) -> _FakeSandbox:
            return _FakeSandbox()

    monkeypatch.setattr("arema.runtime.sandbox.k8s._load_client", lambda _config: _FakeClient())
    from arema.runtime.sandbox.k8s import K8sSandboxExecutor

    # _settings() already pins sandbox_namespace to agent-sandbox-demo, which the
    # default claim_name/namespace above match; do not re-pass it.
    return K8sSandboxExecutor(settings=_settings())


def test_terminate_success_does_not_invoke_kubectl(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[object] = []
    monkeypatch.setattr(
        "arema.runtime.sandbox.k8s.subprocess.run",
        lambda *a, **k: calls.append((a, k)),
    )
    executor = _executor_with_terminatable_sandbox(monkeypatch, terminate_exc=None)
    handle = executor.claim(key="case-1", pool="radare2")  # type: ignore[attr-defined]

    executor.terminate(handle)  # type: ignore[attr-defined]

    assert calls == []  # healthy client path never shells out


def test_terminate_client_failure_falls_back_to_kubectl(monkeypatch: pytest.MonkeyPatch) -> None:
    import ssl

    captured: dict[str, object] = {}

    class _Ok:
        returncode = 0

    def _fake_run(argv: list[str], **_kwargs: object) -> _Ok:
        captured["argv"] = argv
        return _Ok()

    monkeypatch.setattr("arema.runtime.sandbox.k8s.subprocess.run", _fake_run)
    executor = _executor_with_terminatable_sandbox(
        monkeypatch, terminate_exc=ssl.SSLError("dead transport at exit")
    )
    handle = executor.claim(key="case-1", pool="radare2")  # type: ignore[attr-defined]

    executor.terminate(handle)  # type: ignore[attr-defined]  # must not raise

    argv = captured["argv"]
    assert isinstance(argv, list)
    assert argv[:3] == ["kubectl", "delete", "sandboxclaim.extensions.agents.x-k8s.io"]
    assert "sandbox-claim-abcd1" in argv
    assert argv[argv.index("-n") + 1] == "agent-sandbox-demo"


def test_terminate_kubectl_fallback_failure_is_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_a: object, **_k: object) -> object:
        raise FileNotFoundError("kubectl not on PATH")

    monkeypatch.setattr("arema.runtime.sandbox.k8s.subprocess.run", _boom)
    executor = _executor_with_terminatable_sandbox(
        monkeypatch, terminate_exc=RuntimeError("client dead")
    )
    handle = executor.claim(key="case-1", pool="radare2")  # type: ignore[attr-defined]

    executor.terminate(handle)  # type: ignore[attr-defined]  # fail-open: must not raise
