"""Tests for the prepare_ilspy tool (claim + kubectl cp + port-forward on :3001).

Mirrors ``test_prepare_sandbox.py``. ``kubectl cp`` and the port-forward registry
are monkeypatched on the ``prepare_ilspy`` module so no real ``kubectl`` runs; the
executor registry is patched on ``prepare_sandbox``, which owns it -- cleanup is
deliberately shared so one case's r2mcp and ILSpy pods are released together.

The fakes are duplicated from ``test_prepare_sandbox.py`` rather than imported:
test directories carry no ``__init__.py`` (they would shadow the src packages), so
cross-module test imports do not resolve. Like the sibling tool, ``prepare_ilspy``
resolves the sandbox case id through ``resolve_sandbox_case_id``, so the fake tool
context exposes a writable ``state`` (``get`` + ``__setitem__``) and an
``invocation_id``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from arema.core.config import LLMProvider, Settings
from arema.runtime.agent_factory import ToolBuildContext
from arema.runtime.sandbox.port import SandboxHandle
from arema.runtime.services import RuntimeServices
from arema.runtime.sessions import SessionKeys
from reverse_engineering.artifacts import ArtifactStore
from reverse_engineering.runtime import sandbox_session
from reverse_engineering.tools import prepare_ilspy

if TYPE_CHECKING:
    from pathlib import Path

    from arema.runtime.sandbox.port import SandboxExecutor


class FakeExecutor:
    """A minimal ``SandboxExecutor`` recording claim/release calls."""

    def __init__(self, pod_name: str = "fake-pod-1") -> None:
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
        invocation_id: str = "prepare-ilspy-test",
    ) -> None:
        self.state = _FakeState(state_values)
        self.invocation_id = invocation_id


class _NoStateToolContext:
    invocation_id = "prepare-ilspy-test"


class _RecordingRegistry:
    def __init__(self) -> None:
        self.opened: list[dict[str, Any]] = []
        self.closed: list[str] = []

    def open(self, *, case_id: str, namespace: str, pod: str, port: int) -> None:
        self.opened.append({"case_id": case_id, "namespace": namespace, "pod": pod, "port": port})

    def close(self, case_id: str) -> None:
        self.closed.append(case_id)

    def has(self, case_id: str) -> bool:  # noqa: ARG002
        return False

    def close_all(self) -> None:
        pass


@pytest.fixture(autouse=True)
def _isolate_module_state(monkeypatch: pytest.MonkeyPatch) -> Any:
    sandbox_session._SESSIONS.clear()
    monkeypatch.setattr(prepare_ilspy, "kubectl_exec", lambda *_a, **_k: "")
    monkeypatch.setattr(sandbox_session.time, "sleep", lambda _s: None)
    yield
    sandbox_session._SESSIONS.clear()


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


def _make_artifact(tmp_path: Path) -> str:
    src = tmp_path / "sample.dll"
    src.write_bytes(b"hello-assembly")
    return ArtifactStore(tmp_path / "artifacts").acquire(src)


def test_happy_path_copies_assembly_and_opens_port_forward(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_id = _make_artifact(tmp_path)
    root = tmp_path / "artifacts"
    cp_calls: list[tuple[str, str, str, str]] = []
    registry = _RecordingRegistry()

    monkeypatch.setattr(prepare_ilspy, "default_artifacts_root", lambda: root)
    monkeypatch.setattr(
        prepare_ilspy,
        "kubectl_cp",
        lambda src, namespace, pod, dest: cp_calls.append((src, namespace, pod, dest)),
    )
    monkeypatch.setattr(prepare_ilspy, "default_registry", lambda: registry)

    executor = FakeExecutor()
    tool = prepare_ilspy.build_prepare_ilspy(_build_context(executor=executor))

    tool_context = _FakeToolContext()
    result = tool(artifact_id, tool_context)

    resolved_case = tool_context.state._values[SessionKeys.SANDBOX_CASE_ID]
    assert result == {
        "pod": "fake-pod-1",
        "assembly_path": f"/app/{artifact_id}.dll",
        "ready": True,
    }
    assert executor.claimed == [(resolved_case, "ilspy-mcp")]
    assert registry.opened == [
        {
            "case_id": resolved_case,
            "namespace": "test-ns",
            "pod": "fake-pod-1",
            "port": 3001,
        }
    ]
    assert cp_calls == [
        (str(root / artifact_id), "test-ns", "fake-pod-1", f"/app/{artifact_id}.dll")
    ]


def test_destination_carries_the_dll_suffix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ILSpy resolves assemblies by extension: a bare sha256 path fails to load."""
    artifact_id = _make_artifact(tmp_path)
    destinations: list[str] = []

    monkeypatch.setattr(prepare_ilspy, "default_artifacts_root", lambda: tmp_path / "artifacts")
    monkeypatch.setattr(
        prepare_ilspy,
        "kubectl_cp",
        lambda _src, _ns, _pod, dest: destinations.append(dest),
    )
    monkeypatch.setattr(prepare_ilspy, "default_registry", lambda: _RecordingRegistry())

    tool = prepare_ilspy.build_prepare_ilspy(_build_context(executor=FakeExecutor()))
    result = tool(artifact_id, _FakeToolContext())

    assert destinations == [f"/app/{artifact_id}.dll"]
    assert result["assembly_path"] == destinations[0]


def test_case_id_read_from_tool_context_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(prepare_ilspy, "default_artifacts_root", lambda: tmp_path / "artifacts")
    monkeypatch.setattr(prepare_ilspy, "kubectl_cp", lambda *_args: None)
    monkeypatch.setattr(prepare_ilspy, "default_registry", lambda: _RecordingRegistry())

    executor = FakeExecutor()
    tool = prepare_ilspy.build_prepare_ilspy(_build_context(executor=executor))

    tool("artifact", _FakeToolContext({SessionKeys.SANDBOX_CASE_ID: "custom-case"}))

    assert executor.claimed == [("custom-case", "ilspy-mcp")]


def test_case_id_derives_from_invocation_when_state_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(prepare_ilspy, "default_artifacts_root", lambda: tmp_path / "artifacts")
    monkeypatch.setattr(prepare_ilspy, "kubectl_cp", lambda *_args: None)
    monkeypatch.setattr(prepare_ilspy, "default_registry", lambda: _RecordingRegistry())

    executor = FakeExecutor()
    tool = prepare_ilspy.build_prepare_ilspy(_build_context(executor=executor))

    tool_context = _FakeToolContext()
    tool("artifact", tool_context)

    assert executor.claimed == [
        (tool_context.state._values[SessionKeys.SANDBOX_CASE_ID], "ilspy-mcp")
    ]


def test_registers_executor_so_release_case_tears_it_down(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One case may hold both engines; cleanup is the shared sandbox_session.release_case."""
    registry = _RecordingRegistry()
    monkeypatch.setattr(prepare_ilspy, "default_artifacts_root", lambda: tmp_path / "artifacts")
    monkeypatch.setattr(prepare_ilspy, "kubectl_cp", lambda *_args: None)
    monkeypatch.setattr(prepare_ilspy, "default_registry", lambda: registry)
    monkeypatch.setattr(sandbox_session, "default_registry", lambda: registry)

    executor = FakeExecutor()
    tool = prepare_ilspy.build_prepare_ilspy(_build_context(executor=executor))
    tool("artifact", _FakeToolContext({SessionKeys.SANDBOX_CASE_ID: "case-42"}))

    assert "ilspy-mcp" in sandbox_session.released_pools("case-42")  # registered for cleanup

    sandbox_session.release_case("case-42")

    assert executor.released == ["case-42"]
    assert registry.closed == ["case-42"]
    assert sandbox_session.released_pools("case-42") == frozenset()


def test_identity_failure_happens_before_claim_copy_or_port_forward(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(prepare_ilspy, "default_artifacts_root", lambda: tmp_path / "artifacts")
    cp_calls: list[object] = []
    open_calls: list[object] = []
    monkeypatch.setattr(prepare_ilspy, "kubectl_cp", lambda *_args: cp_calls.append(object()))
    monkeypatch.setattr(
        prepare_ilspy,
        "default_registry",
        lambda: type(
            "Registry", (), {"open": lambda *_args, **_kwargs: open_calls.append(object())}
        )(),
    )
    executor = FakeExecutor()

    result = prepare_ilspy.build_prepare_ilspy(_build_context(executor=executor))(
        "artifact",
        _NoStateToolContext(),  # type: ignore[arg-type]
    )

    assert result == {
        "pod": "",
        "assembly_path": "",
        "ready": False,
        "error_code": "sandbox_identity_unavailable",
        "error": "The sandbox identity is unavailable.",
    }
    assert executor.claimed == []
    assert cp_calls == []
    assert open_calls == []


def test_fail_open_when_executor_is_none() -> None:
    tool = prepare_ilspy.build_prepare_ilspy(_build_context(executor=None))

    result = tool("artifact", _FakeToolContext())

    assert result["ready"] is False
    assert result["assembly_path"] == ""
    assert "error" in result


def test_fail_open_when_kubectl_cp_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_args: str) -> None:
        raise RuntimeError("kubectl cp failed: connection refused")

    monkeypatch.setattr(prepare_ilspy, "default_artifacts_root", lambda: tmp_path / "artifacts")
    monkeypatch.setattr(prepare_ilspy, "kubectl_cp", _boom)
    monkeypatch.setattr(prepare_ilspy, "default_registry", lambda: _RecordingRegistry())

    tool = prepare_ilspy.build_prepare_ilspy(_build_context(executor=FakeExecutor()))

    result = tool("artifact", _FakeToolContext())

    assert result["ready"] is False
    assert "error" in result


def test_descriptor_id_matches_factory_function_name() -> None:
    tool = prepare_ilspy.build_prepare_ilspy(_build_context(executor=FakeExecutor()))
    assert prepare_ilspy.PREPARE_ILSPY_TOOL.id == "prepare_ilspy"
    assert tool.__name__ == "prepare_ilspy"


def test_descriptor_has_output_policy() -> None:
    policy = prepare_ilspy.PREPARE_ILSPY_TOOL.output_policy
    assert policy is not None
    assert policy.max_chars > 0
