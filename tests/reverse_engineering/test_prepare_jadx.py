"""Tests for the prepare_jadx tool (claim a jadx pod, copy the sample, decompile once).

Mirrors ``test_prepare_ilspy.py``: ``kubectl_cp``/``kubectl_exec`` and the
artifacts root are monkeypatched on the ``prepare_jadx`` module so no real
``kubectl`` runs. jadx is a one-shot CLI (no daemon, no port-forward), so
preparation copies the sample in, runs ``jadx -d <out> <sample>`` once, counts the
recovered classes, and seeds ``_JADX_CASE_STATE`` for the read tools.

Like the sibling tool, ``prepare_jadx`` resolves the sandbox case id through
``resolve_sandbox_case_id``, so the fake tool context exposes a writable ``state``
(``get`` + ``__setitem__``) and an ``invocation_id``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from arema.core.config import LLMProvider, Settings
from arema.runtime.agent_factory import ToolBuildContext
from arema.runtime.sandbox.port import SandboxHandle
from arema.runtime.services import RuntimeServices
from arema.runtime.sessions import SessionKeys
from reverse_engineering.runtime import sandbox_session
from reverse_engineering.tools.jadx import prepare_jadx
from reverse_engineering.tools.jadx import toolset as jadx_toolset

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from arema.runtime.sandbox.port import SandboxExecutor

_CASE = "jadx-case"
_ARTIFACT = "a" * 64


class FakeExecutor:
    """A minimal ``SandboxExecutor`` recording claim/release calls."""

    def __init__(self, pod_name: str = "jadx-1") -> None:
        self.pod_name = pod_name
        self.claimed: list[tuple[str, str]] = []
        self.released: list[str] = []

    def claim(self, *, key: str, pool: str) -> SandboxHandle:
        self.claimed.append((key, pool))
        return SandboxHandle(key=key, pool=pool, backend_id=self.pod_name)

    def terminate(self, handle: SandboxHandle) -> None:
        self.released.append(handle.key)

    def release_session(self, key: str) -> None:
        self.released.append(key)


class _FakeState:
    """Duck-typed stand-in for ADK's ``State`` proxy (never a ``dict``)."""

    def __init__(self, values: dict[str, str] | None = None) -> None:
        self._values: dict[str, str] = values or {}

    def get(self, key: str, default: str | None = None) -> str | None:
        return self._values.get(key, default)

    def __setitem__(self, key: str, value: str) -> None:
        self._values[key] = value


class _FakeToolContext:
    def __init__(
        self,
        state_values: dict[str, str] | None = None,
        invocation_id: str = "prepare-jadx-test",
    ) -> None:
        self.state = _FakeState(state_values)
        self.invocation_id = invocation_id


@pytest.fixture(autouse=True)
def _isolate_module_state(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    sandbox_session._SESSIONS.clear()
    jadx_toolset._JADX_CASE_STATE.clear()
    monkeypatch.setattr(sandbox_session.time, "sleep", lambda _s: None)
    yield
    sandbox_session._SESSIONS.clear()
    jadx_toolset._JADX_CASE_STATE.clear()


def _build_context(
    *,
    executor: SandboxExecutor | None,
    namespace: str = "test-ns",
) -> ToolBuildContext:
    settings = Settings(
        _env_file=None, llm_provider=LLMProvider.OLLAMA, sandbox_namespace=namespace
    )  # type: ignore[call-arg]
    services = RuntimeServices.default()
    services_with_sandbox = RuntimeServices(
        clock=services.clock,
        metrics=services.metrics,
        memory_sink=services.memory_sink,
        sandbox=executor,
    )
    return ToolBuildContext(settings=settings, services=services_with_sandbox, catalog=None)  # type: ignore[arg-type]


def _patch_kube(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    find_output: str,
) -> list[str]:
    """Stub kubectl_cp/kubectl_exec; return the argv of the first exec call (jadx)."""
    monkeypatch.setattr(prepare_jadx, "default_artifacts_root", lambda: tmp_path)
    monkeypatch.setattr(prepare_jadx, "kubectl_cp", lambda *_args: None)
    jadx_argv: list[str] = []

    def _fake_exec(argv: list[str], namespace: str, pod: str, **_kw: Any) -> str:  # noqa: ARG001
        if argv and argv[0] == "jadx":
            jadx_argv.extend(argv)
            return ""
        return find_output

    monkeypatch.setattr(prepare_jadx, "kubectl_exec", _fake_exec)
    return jadx_argv


def test_happy_path_claims_decompiles_and_seeds_case_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    jadx_argv = _patch_kube(monkeypatch, tmp_path, find_output="A.java\nB.java\nC.java\n")
    executor = FakeExecutor(pod_name="jadx-1")
    tool = prepare_jadx.build_prepare_jadx(_build_context(executor=executor))

    tool_context = _FakeToolContext({SessionKeys.SANDBOX_CASE_ID: _CASE})
    result = tool(_ARTIFACT, "apk", tool_context)

    assert result == {
        "pod": "jadx-1",
        "output_dir": f"/tmp/jadx_{_ARTIFACT}",
        "classes": 3,
        "ready": True,
    }
    assert executor.claimed == [(_CASE, "jadx")]
    assert jadx_argv == [
        "jadx",
        "--no-imports",
        "-d",
        f"/tmp/jadx_{_ARTIFACT}",
        f"/app/{_ARTIFACT}",
    ]
    assert jadx_toolset._JADX_CASE_STATE[_CASE] == {
        "pod": "jadx-1",
        "out": f"/tmp/jadx_{_ARTIFACT}",
        "namespace": "test-ns",
        "format": "apk",
    }


def test_fail_open_when_executor_is_none() -> None:
    tool = prepare_jadx.build_prepare_jadx(_build_context(executor=None))

    result = tool(_ARTIFACT, "apk", _FakeToolContext({SessionKeys.SANDBOX_CASE_ID: _CASE}))

    assert result["ready"] is False
    assert "error" in result
    assert jadx_toolset._JADX_CASE_STATE == {}


def test_zero_classes_is_not_ready(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A decompile that recovered nothing is a stand-down, not a usable case."""
    _patch_kube(monkeypatch, tmp_path, find_output="   \n")
    tool = prepare_jadx.build_prepare_jadx(_build_context(executor=FakeExecutor()))

    result = tool(_ARTIFACT, "dex", _FakeToolContext({SessionKeys.SANDBOX_CASE_ID: _CASE}))

    assert result["ready"] is False
    assert result["error"] == "jadx produced no decompiled sources"
    assert _CASE not in jadx_toolset._JADX_CASE_STATE


def test_fail_open_when_kubectl_exec_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(prepare_jadx, "default_artifacts_root", lambda: tmp_path)
    monkeypatch.setattr(prepare_jadx, "kubectl_cp", lambda *_args: None)

    def _boom(*_args: Any, **_kwargs: Any) -> str:
        raise RuntimeError("kubectl exec failed (137): OOMKilled")

    monkeypatch.setattr(prepare_jadx, "kubectl_exec", _boom)
    tool = prepare_jadx.build_prepare_jadx(_build_context(executor=FakeExecutor()))

    result = tool(_ARTIFACT, "jar", _FakeToolContext({SessionKeys.SANDBOX_CASE_ID: _CASE}))

    assert result["ready"] is False
    assert "OOMKilled" in str(result["error"])


def test_release_jadx_case_releases_the_executor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_kube(monkeypatch, tmp_path, find_output="A.java\n")
    executor = FakeExecutor()
    tool = prepare_jadx.build_prepare_jadx(_build_context(executor=executor))
    tool(_ARTIFACT, "apk", _FakeToolContext({SessionKeys.SANDBOX_CASE_ID: _CASE}))

    assert "jadx" in sandbox_session.released_pools(_CASE)  # registered for cleanup

    prepare_jadx.release_jadx_case(_CASE)

    assert executor.released == [_CASE]
    assert _CASE not in jadx_toolset._JADX_CASE_STATE
    assert sandbox_session.released_pools(_CASE) == frozenset()


def test_descriptor_id_matches_factory_function_name() -> None:
    tool = prepare_jadx.build_prepare_jadx(_build_context(executor=FakeExecutor()))
    assert prepare_jadx.PREPARE_JADX_TOOL.id == "prepare_jadx"
    assert tool.__name__ == "prepare_jadx"


def test_descriptor_has_output_policy() -> None:
    policy = prepare_jadx.PREPARE_JADX_TOOL.output_policy
    assert policy is not None
    assert policy.max_chars > 0
