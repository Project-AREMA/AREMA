"""Tests for the prepare_sandbox tool (claim + kubectl cp + port-forward).

The tool is built from a factory that closes over ``RuntimeServices.sandbox``
and ``Settings.sandbox_namespace``. ``kubectl cp`` and the port-forward registry
are monkeypatched so no real ``kubectl`` is ever invoked.
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
from reverse_engineering.tools import detect_it_easy, prepare_sandbox
from reverse_engineering.tools.deobfuscation.state import CURRENT_ARTIFACT_KEY

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
        invocation_id: str = "prepare-sandbox-test",
    ) -> None:
        self.state = _FakeState(state_values)
        self.invocation_id = invocation_id


class _NoStateToolContext:
    invocation_id = "prepare-sandbox-test"


class _ExplodingGetterState:
    def get(self, _key: str, _default: object = None) -> object:
        raise RuntimeError("state getter exploded")

    def __setitem__(self, _key: str, _value: object) -> None:
        pass


class _ExplodingGetterToolContext:
    invocation_id = "prepare-sandbox-test"
    state = _ExplodingGetterState()


class _ExplodingStateToolContext:
    invocation_id = "prepare-sandbox-test"

    @property
    def state(self) -> object:
        raise RuntimeError("state lookup exploded")


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
def _isolate_module_state() -> Any:
    sandbox_session._SESSIONS.clear()
    yield
    sandbox_session._SESSIONS.clear()


@pytest.fixture(autouse=True)
def _stub_sandbox_io(monkeypatch: pytest.MonkeyPatch) -> None:
    # By default the staged-file verification succeeds (the claimed pod holds the
    # file). Tests exercising a missing file / recycled pod override this. Retry
    # backoff (in the shared sandbox_session core) is stubbed so the bounded
    # re-claim loop does not slow the suite.
    monkeypatch.setattr(prepare_sandbox, "kubectl_exec", lambda *_a, **_k: "")
    monkeypatch.setattr(sandbox_session.time, "sleep", lambda _s: None)


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
    root = tmp_path / "artifacts"
    src = tmp_path / "sample.bin"
    src.write_bytes(b"hello-sandbox")
    return ArtifactStore(root).acquire(src)


def test_happy_path_copies_artifact_and_opens_port_forward(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_id = _make_artifact(tmp_path)
    root = tmp_path / "artifacts"
    monkeypatch.setattr(prepare_sandbox, "default_artifacts_root", lambda: root)

    cp_calls: list[tuple[str, str, str, str]] = []

    def _fake_cp(src: str, namespace: str, pod: str, dest: str) -> None:
        cp_calls.append((src, namespace, pod, dest))

    monkeypatch.setattr(prepare_sandbox, "kubectl_cp", _fake_cp)
    recording = _RecordingRegistry()
    monkeypatch.setattr(prepare_sandbox, "default_registry", lambda: recording)

    executor = FakeExecutor()
    tool = prepare_sandbox.build_prepare_sandbox(_build_context(executor=executor))

    tool_context = _FakeToolContext()
    result = tool(artifact_id, tool_context)

    assert result == {
        "pod": "fake-pod-1",
        "ready": True,
        "artifact_id": artifact_id,
        "file_path": f"/app/{artifact_id}",
        # No kubectl in this test, so the DIE scan degrades to no verdict. That
        # is the point: an unavailable pre-validator never blocks provisioning.
        "packer_scan": "",
    }
    assert cp_calls == [(str(root / artifact_id), "test-ns", "fake-pod-1", f"/app/{artifact_id}")]
    assert recording.opened == [
        {
            "case_id": tool_context.state._values[SessionKeys.SANDBOX_CASE_ID],
            "namespace": "test-ns",
            "pod": "fake-pod-1",
            "port": 8765,
        }
    ]
    case_id = tool_context.state._values[SessionKeys.SANDBOX_CASE_ID]
    assert "radare2-mcp" in sandbox_session.released_pools(case_id)  # registered for cleanup


def test_case_id_read_from_tool_context_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(prepare_sandbox, "default_artifacts_root", lambda: tmp_path / "artifacts")
    monkeypatch.setattr(prepare_sandbox, "kubectl_cp", lambda *_args: None)
    monkeypatch.setattr(prepare_sandbox, "default_registry", lambda: _RecordingRegistry())

    executor = FakeExecutor()
    tool = prepare_sandbox.build_prepare_sandbox(_build_context(executor=executor))

    tool("a" * 64, _FakeToolContext({SessionKeys.SANDBOX_CASE_ID: "custom-case"}))

    assert executor.claimed == [("custom-case", "radare2-mcp")]


def test_current_artifact_state_overrides_stale_model_argument(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_id = _make_artifact(tmp_path)
    root = tmp_path / "artifacts"
    monkeypatch.setattr(prepare_sandbox, "default_artifacts_root", lambda: root)
    copied: list[str] = []
    monkeypatch.setattr(
        prepare_sandbox,
        "kubectl_cp",
        lambda _src, _namespace, _pod, destination: copied.append(destination),
    )
    monkeypatch.setattr(prepare_sandbox, "default_registry", lambda: _RecordingRegistry())
    executor = FakeExecutor()

    result = prepare_sandbox.build_prepare_sandbox(_build_context(executor=executor))(
        "f" * 64,
        _FakeToolContext({CURRENT_ARTIFACT_KEY: artifact_id}),
    )

    assert result["artifact_id"] == artifact_id
    assert result["file_path"] == f"/app/{artifact_id}"
    assert copied == [f"/app/{artifact_id}"]


def test_malformed_current_artifact_state_fails_before_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(prepare_sandbox, "default_artifacts_root", lambda: tmp_path / "artifacts")
    executor = FakeExecutor()

    result = prepare_sandbox.build_prepare_sandbox(_build_context(executor=executor))(
        "a" * 64,
        _FakeToolContext({CURRENT_ARTIFACT_KEY: "malformed"}),
    )

    assert result == {"pod": "", "ready": False, "error": "invalid current artifact state"}
    assert executor.claimed == []


def test_case_id_derives_from_invocation_when_state_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(prepare_sandbox, "default_artifacts_root", lambda: tmp_path / "artifacts")
    monkeypatch.setattr(prepare_sandbox, "kubectl_cp", lambda *_args: None)
    monkeypatch.setattr(prepare_sandbox, "default_registry", lambda: _RecordingRegistry())

    executor = FakeExecutor()
    tool = prepare_sandbox.build_prepare_sandbox(_build_context(executor=executor))

    tool_context = _FakeToolContext()
    tool("a" * 64, tool_context)

    assert executor.claimed == [
        (tool_context.state._values[SessionKeys.SANDBOX_CASE_ID], "radare2-mcp")
    ]


def test_identity_failure_happens_before_claim_copy_or_port_forward(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(prepare_sandbox, "default_artifacts_root", lambda: tmp_path / "artifacts")
    copy_calls: list[object] = []
    open_calls: list[object] = []
    monkeypatch.setattr(prepare_sandbox, "kubectl_cp", lambda *_args: copy_calls.append(object()))
    monkeypatch.setattr(
        prepare_sandbox,
        "default_registry",
        lambda: type(
            "Registry", (), {"open": lambda *_args, **_kwargs: open_calls.append(object())}
        )(),
    )
    executor = FakeExecutor()

    result = prepare_sandbox.build_prepare_sandbox(_build_context(executor=executor))(
        "a" * 64,
        _NoStateToolContext(),
    )

    assert result == {
        "pod": "",
        "ready": False,
        "error_code": "sandbox_identity_unavailable",
        "error": "The sandbox identity is unavailable.",
    }
    assert executor.claimed == []
    assert copy_calls == []
    assert open_calls == []


@pytest.mark.parametrize(
    "tool_context", [_ExplodingGetterToolContext(), _ExplodingStateToolContext()]
)
def test_identity_access_failure_happens_before_artifact_lookup_or_sandbox_operations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tool_context: object,
) -> None:
    monkeypatch.setattr(prepare_sandbox, "default_artifacts_root", lambda: tmp_path / "artifacts")
    copy_calls: list[object] = []
    open_calls: list[object] = []
    monkeypatch.setattr(prepare_sandbox, "kubectl_cp", lambda *_args: copy_calls.append(object()))
    monkeypatch.setattr(
        prepare_sandbox,
        "default_registry",
        lambda: type(
            "Registry", (), {"open": lambda *_args, **_kwargs: open_calls.append(object())}
        )(),
    )
    executor = FakeExecutor()

    result = prepare_sandbox.build_prepare_sandbox(_build_context(executor=executor))(
        "a" * 64,
        tool_context,  # type: ignore[arg-type]
    )

    assert result == {
        "pod": "",
        "ready": False,
        "error_code": "sandbox_identity_unavailable",
        "error": "The sandbox identity is unavailable.",
    }
    assert executor.claimed == []
    assert copy_calls == []
    assert open_calls == []


def test_failed_cp_degrades_and_releases_the_claim_scoped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A cp that fails every attempt degrades cleanly; the shared sandbox_session core
    # releases each claim SCOPED (per-pod terminate, never a namespace-wide delete)
    # and leaves nothing registered. (The retry/re-claim mechanics are covered in
    # test_sandbox_session.)
    monkeypatch.setattr(prepare_sandbox, "default_artifacts_root", lambda: tmp_path / "artifacts")
    monkeypatch.setattr(prepare_sandbox, "default_registry", lambda: _RecordingRegistry())

    def _boom(*_args: str) -> None:
        raise RuntimeError("kubectl cp failed: connection refused")

    monkeypatch.setattr(prepare_sandbox, "kubectl_cp", _boom)

    executor = FakeExecutor()
    tool = prepare_sandbox.build_prepare_sandbox(_build_context(executor=executor))

    result = tool("a" * 64, _FakeToolContext({SessionKeys.SANDBOX_CASE_ID: "case-fail"}))

    assert result["ready"] is False
    assert "error" in result
    assert (
        executor.released == ["case-fail"] * sandbox_session.RETRY_ATTEMPTS
    )  # scoped, per attempt
    assert sandbox_session.released_pools("case-fail") == frozenset()  # nothing left registered


def test_fail_open_when_executor_is_none() -> None:
    tool = prepare_sandbox.build_prepare_sandbox(_build_context(executor=None))

    result = tool("a" * 64, _FakeToolContext())

    assert result["ready"] is False
    assert "error" in result


def test_fail_open_when_kubectl_cp_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(prepare_sandbox, "default_artifacts_root", lambda: tmp_path / "artifacts")

    def _boom(*_args: str) -> None:
        raise RuntimeError("kubectl cp failed: connection refused")

    monkeypatch.setattr(prepare_sandbox, "kubectl_cp", _boom)
    monkeypatch.setattr(prepare_sandbox, "default_registry", lambda: _RecordingRegistry())

    executor = FakeExecutor()
    tool = prepare_sandbox.build_prepare_sandbox(_build_context(executor=executor))

    result = tool("a" * 64, _FakeToolContext())

    assert result["ready"] is False
    assert "error" in result


def _prepared_with_die(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scan: object
) -> tuple[dict[str, object], _FakeToolContext]:
    """Run prepare_sandbox with a stubbed DIE scan and return (result, context)."""
    artifact_id = _make_artifact(tmp_path)
    monkeypatch.setattr(prepare_sandbox, "default_artifacts_root", lambda: tmp_path / "artifacts")
    monkeypatch.setattr(prepare_sandbox, "kubectl_cp", lambda *_a: None)
    monkeypatch.setattr(prepare_sandbox, "kubectl_exec", lambda *_a, **_k: "")
    monkeypatch.setattr(prepare_sandbox, "default_registry", lambda: _RecordingRegistry())
    monkeypatch.setattr(prepare_sandbox, "scan_staged_artifact", scan)

    tool = prepare_sandbox.build_prepare_sandbox(_build_context(executor=FakeExecutor()))
    tool_context = _FakeToolContext()
    return tool(artifact_id, tool_context), tool_context


def test_the_pre_validator_scans_the_staged_bytes_and_publishes_its_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """It runs inside the tool intake must call, so no model choice can skip it."""
    seen: list[tuple[str, str, str]] = []

    def _scan(namespace: str, pod: str, pod_path: str) -> str:
        seen.append((namespace, pod, pod_path))
        return "Packer: UPX 5.20"

    result, tool_context = _prepared_with_die(tmp_path, monkeypatch, _scan)

    assert result["packer_scan"] == "Packer: UPX 5.20"
    assert tool_context.state.get(detect_it_easy.SAMPLE_DIE_KEY) == "Packer: UPX 5.20"
    assert tool_context.state.get(detect_it_easy.SAMPLE_DIE_PROMPT_KEY) == "Packer: UPX 5.20"
    # Scanned in the claimed pod, at the path the artifact was just copied to.
    assert seen == [("test-ns", "fake-pod-1", f"/app/{result['artifact_id']}")]


def test_an_unavailable_pre_validator_still_leaves_the_sandbox_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pre-validator must never be able to stop the pipeline it precedes."""
    result, tool_context = _prepared_with_die(tmp_path, monkeypatch, lambda *_a: "")

    assert result["ready"] is True
    assert result["packer_scan"] == ""
    assert tool_context.state.get(detect_it_easy.SAMPLE_DIE_KEY) == ""


def test_a_stale_verdict_is_cleared_rather_than_left_for_the_next_sample(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """prepare_sandbox re-runs across a session; a prior sample's verdict must
    not survive to be cited against the current one."""
    monkeypatch.setattr(prepare_sandbox, "default_artifacts_root", lambda: tmp_path / "artifacts")
    monkeypatch.setattr(prepare_sandbox, "kubectl_cp", lambda *_a: None)
    monkeypatch.setattr(prepare_sandbox, "kubectl_exec", lambda *_a, **_k: "")
    monkeypatch.setattr(prepare_sandbox, "default_registry", lambda: _RecordingRegistry())
    monkeypatch.setattr(prepare_sandbox, "scan_staged_artifact", lambda *_a: "")

    artifact_id = _make_artifact(tmp_path)
    tool = prepare_sandbox.build_prepare_sandbox(_build_context(executor=FakeExecutor()))
    tool_context = _FakeToolContext({detect_it_easy.SAMPLE_DIE_PROMPT_KEY: "Packer: UPX 5.20"})

    tool(artifact_id, tool_context)

    assert tool_context.state.get(detect_it_easy.SAMPLE_DIE_PROMPT_KEY) == ""


def test_descriptor_id_matches_factory_function_name() -> None:
    tool = prepare_sandbox.build_prepare_sandbox(_build_context(executor=FakeExecutor()))
    assert prepare_sandbox.PREPARE_SANDBOX_TOOL.id == "prepare_sandbox"
    assert tool.__name__ == "prepare_sandbox"


def test_descriptor_has_output_policy() -> None:
    policy = prepare_sandbox.PREPARE_SANDBOX_TOOL.output_policy
    assert policy is not None
    assert policy.max_chars > 0
