"""Unit tests for the ghidra function-tool layer: spec table, builder, prepare_ghidra.

Mirrors the structure of ``test_prepare_sandbox``: ``kubectl_exec``/``kubectl_cp``
are monkeypatched so no real ``kubectl`` is ever invoked, and a ``FakeExecutor``
stands in for the sandbox executor.
"""

from __future__ import annotations

import inspect
import json
from typing import TYPE_CHECKING, Any

import pytest
from google.adk.tools.function_tool import FunctionTool

from arema.core.config import LLMProvider, Settings
from arema.registry.descriptors import OutputPolicy
from arema.runtime.agent_factory import ToolBuildContext
from arema.runtime.sandbox.port import SandboxHandle
from arema.runtime.services import RuntimeServices
from arema.runtime.sessions import SessionKeys
from reverse_engineering.runtime import sandbox_session
from reverse_engineering.tools.deobfuscation.state import CURRENT_ARTIFACT_KEY
from reverse_engineering.tools.ghidra import commands, prepare_ghidra, toolset

if TYPE_CHECKING:
    from pathlib import Path

    from arema.runtime.sandbox.port import SandboxExecutor

_TEST_CASE_ID = "ghidra-tool-test"


class FakeExecutor:
    """A minimal ``SandboxExecutor`` recording claim/release calls."""

    def __init__(self, pod_name: str = "ghidra-pod-1") -> None:
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
    def __init__(self, state_values: dict[str, str] | None = None) -> None:
        values = {SessionKeys.SANDBOX_CASE_ID: _TEST_CASE_ID}
        values.update(state_values or {})
        self.state = _FakeState(values)


class _NoStateToolContext:
    invocation_id = "ghidra-tool-test"


class _ExplodingGetterState:
    def get(self, _key: str, _default: object = None) -> object:
        raise RuntimeError("state getter exploded")

    def __setitem__(self, _key: str, _value: object) -> None:
        pass


class _ExplodingGetterToolContext:
    invocation_id = "ghidra-tool-test"
    state = _ExplodingGetterState()


class _ExplodingStateToolContext:
    invocation_id = "ghidra-tool-test"

    @property
    def state(self) -> object:
        raise RuntimeError("state lookup exploded")


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


@pytest.fixture(autouse=True)
def _isolate_case_state(monkeypatch: pytest.MonkeyPatch) -> Any:
    toolset._GHIDRA_CASE_STATE.clear()
    sandbox_session._SESSIONS.clear()
    monkeypatch.setattr(sandbox_session.time, "sleep", lambda _s: None)
    yield
    toolset._GHIDRA_CASE_STATE.clear()
    sandbox_session._SESSIONS.clear()


# --- command table -----------------------------------------------------------


def test_command_table_has_curated_read_only_surface() -> None:
    names = {spec.name for spec in commands.GHIDRA_COMMANDS}
    assert "ghidra_decompile" in names
    assert "ghidra_search_decompiled" in names
    assert "ghidra_basic_blocks" in names
    assert "ghidra_pcode" in names
    assert "ghidra_metadata" in names
    assert "ghidra_list_functions" in names
    assert "ghidra_xrefs_to" in names
    assert "ghidra_imports" in names
    assert "ghidra_strings" in names
    assert len(commands.GHIDRA_COMMANDS) == 9
    assert not any("rename" in n or "patch" in n or "write" in n for n in names)


def test_command_specs_have_output_policies() -> None:
    for spec in commands.GHIDRA_COMMANDS:
        assert isinstance(spec.output_policy, OutputPolicy)
        assert spec.output_policy.max_chars > 0


def test_command_spec_is_frozen_slots_dataclass() -> None:
    spec = commands.GHIDRA_COMMANDS[0]
    with pytest.raises((AttributeError, Exception)):
        spec.name = "x"  # type: ignore[misc]


def test_search_decompiled_bounds_server_deadline_under_client_deadline() -> None:
    spec = next(s for s in commands.GHIDRA_COMMANDS if s.name == "ghidra_search_decompiled")
    # Server graceful deadline must stay strictly below the client kubectl budget
    # so ghidra-rpc returns before kubectl would hard-kill the sweep.
    assert "--socket-timeout 600" in spec.extra_flags
    assert spec.timeout_seconds == 660


def test_fast_commands_keep_the_default_client_deadline() -> None:
    for name in ("ghidra_metadata", "ghidra_list_functions", "ghidra_imports"):
        spec = next(s for s in commands.GHIDRA_COMMANDS if s.name == name)
        assert spec.timeout_seconds == 300


def test_tool_forwards_per_command_timeout_to_kubectl_exec(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _seed_case()
    seen: dict[str, int] = {}

    def _fake_exec(args: list[str], namespace: str, pod: str, *, timeout: int) -> str:  # noqa: ARG001
        seen["timeout"] = timeout
        return "ok"

    monkeypatch.setattr(toolset, "kubectl_exec", _fake_exec)
    context = _build_context(executor=FakeExecutor())

    search = next(
        d.factory(context)  # type: ignore[union-attr]
        for d in toolset.build_ghidra_toolset()
        if d.id == "ghidra_search_decompiled"
    )
    search(_FakeToolContext(), pattern="malloc")  # type: ignore[call-arg]
    assert seen["timeout"] == 660

    metadata = next(
        d.factory(context)  # type: ignore[union-attr]
        for d in toolset.build_ghidra_toolset()
        if d.id == "ghidra_metadata"
    )
    metadata(_FakeToolContext())  # type: ignore[call-arg]
    assert seen["timeout"] == 300


# --- kubectl_exec ------------------------------------------------------------


def test_kubectl_exec_helper_is_callable() -> None:
    from reverse_engineering.runtime.portforward import kubectl_exec

    assert callable(kubectl_exec)


def test_kubectl_exec_returns_stdout_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    from reverse_engineering.runtime import portforward

    captured: dict[str, Any] = {}

    class _Ok:
        returncode = 0
        stdout = b'{"ok": true}'
        stderr = b""

    def _fake_run(args: list[str], **_kwargs: Any) -> _Ok:
        captured["args"] = list(args)
        return _Ok()

    monkeypatch.setattr(portforward.subprocess, "run", _fake_run)

    out = portforward.kubectl_exec(["ghidra-rpc", "metadata", "ls"], "ns", "pod-a")

    assert out == '{"ok": true}'
    assert captured["args"] == [
        "kubectl",
        "exec",
        "pod/pod-a",
        "-n",
        "ns",
        "--",
        "ghidra-rpc",
        "metadata",
        "ls",
    ]


def test_kubectl_exec_raises_on_nonzero_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    from reverse_engineering.runtime import portforward

    class _Fail:
        returncode = 1
        stdout = b""
        stderr = b"boom"

    monkeypatch.setattr(portforward.subprocess, "run", lambda *a, **k: _Fail())  # noqa: ARG005

    with pytest.raises(RuntimeError, match="kubectl exec failed"):
        portforward.kubectl_exec(["x"], "ns", "pod-a")


# --- build_ghidra_toolset ----------------------------------------------------


def test_toolset_produces_one_descriptor_per_spec() -> None:
    descriptors = toolset.build_ghidra_toolset()

    assert len(descriptors) == len(commands.GHIDRA_COMMANDS)
    ids = {d.id for d in descriptors}
    assert ids == {spec.name for spec in commands.GHIDRA_COMMANDS}
    assert "ghidra_decompile" in ids


def test_toolset_descriptors_use_deferred_factory() -> None:
    descriptors = toolset.build_ghidra_toolset()

    for spec, descriptor in zip(commands.GHIDRA_COMMANDS, descriptors, strict=True):
        assert descriptor.factory is not None
        assert descriptor.tool is None
        assert descriptor.output_policy == spec.output_policy
        assert descriptor.id == spec.name


def test_factory_builds_named_callable() -> None:
    context = _build_context(executor=FakeExecutor())
    descriptors = toolset.build_ghidra_toolset()
    decompile = next(d for d in descriptors if d.id == "ghidra_decompile")

    tool = decompile.factory(context)  # type: ignore[arg-type]

    assert callable(tool)
    assert tool.__name__ == "ghidra_decompile"  # type: ignore[attr-defined]


# --- tool signature (typed surface) ------------------------------------------


def test_tool_signature_extracts_placeholder_params() -> None:
    context = _build_context(executor=FakeExecutor())
    descriptors = toolset.build_ghidra_toolset()

    decompile = next(d.factory(context) for d in descriptors if d.id == "ghidra_decompile")  # type: ignore[union-attr]
    metadata = next(d.factory(context) for d in descriptors if d.id == "ghidra_metadata")  # type: ignore[union-attr]

    decompile_params = [p for p in inspect.signature(decompile).parameters if p != "tool_context"]
    metadata_params = [p for p in inspect.signature(metadata).parameters if p != "tool_context"]

    assert decompile_params == ["function"]
    assert metadata_params == []


# --- tool runtime behaviour --------------------------------------------------


def _seed_case(case_id: str = _TEST_CASE_ID) -> None:
    toolset._GHIDRA_CASE_STATE[case_id] = {
        "pod": "ghidra-pod-1",
        "binary": "ls",
        "project": "/tmp/arema_ghidra.gpr",
        "namespace": "test-ns",
    }


def test_tool_happy_path_runs_ghidra_rpc_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _seed_case()
    captured: dict[str, Any] = {}

    def _fake_exec(args: list[str], namespace: str, pod: str, **_kwargs: int) -> str:
        captured.update(argv=list(args), namespace=namespace, pod=pod)
        return "decompiled output"

    monkeypatch.setattr(toolset, "kubectl_exec", _fake_exec)

    context = _build_context(executor=FakeExecutor())
    descriptors = toolset.build_ghidra_toolset()
    tool = next(d.factory(context) for d in descriptors if d.id == "ghidra_decompile")  # type: ignore[union-attr]

    result = tool(_FakeToolContext(), function="main")  # type: ignore[call-arg]

    assert result == {"success": True, "output": "decompiled output"}
    assert captured["argv"] == [
        "ghidra-rpc",
        "decompile",
        "ls",
        "main",
        "--project",
        "/tmp/arema_ghidra.gpr",
    ]
    assert captured["namespace"] == "test-ns"
    assert captured["pod"] == "ghidra-pod-1"


def test_tool_includes_extra_flags_and_project(monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_case()
    captured: dict[str, Any] = {}

    def _fake_exec(args: list[str], namespace: str, pod: str, **_kwargs: int) -> str:  # noqa: ARG001
        captured["argv"] = list(args)
        return ""

    monkeypatch.setattr(toolset, "kubectl_exec", _fake_exec)

    context = _build_context(executor=FakeExecutor())
    tool = next(
        d.factory(context)
        for d in toolset.build_ghidra_toolset()
        if d.id == "ghidra_pcode"  # type: ignore[union-attr]
    )

    tool(_FakeToolContext(), function=" FUN_00401000 ")  # type: ignore[call-arg]

    assert captured["argv"] == [
        "ghidra-rpc",
        "pcode",
        "ls",
        " FUN_00401000 ",
        "--high",
        "--project",
        "/tmp/arema_ghidra.gpr",
    ]


def test_tool_read_case_id_from_state(monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_case("custom-case")
    monkeypatch.setattr(toolset, "kubectl_exec", lambda *a, **k: "ok")  # noqa: ARG005

    context = _build_context(executor=FakeExecutor())
    tool = next(
        d.factory(context)
        for d in toolset.build_ghidra_toolset()
        if d.id == "ghidra_metadata"  # type: ignore[union-attr]
    )

    result = tool(_FakeToolContext({SessionKeys.SANDBOX_CASE_ID: "custom-case"}))  # type: ignore[call-arg]

    assert result["success"] is True  # type: ignore[index]


def test_tool_fail_open_when_not_prepared() -> None:
    context = _build_context(executor=FakeExecutor())
    tool = next(
        d.factory(context)
        for d in toolset.build_ghidra_toolset()
        if d.id == "ghidra_decompile"  # type: ignore[union-attr]
    )

    result = tool(_FakeToolContext(), function="main")  # type: ignore[call-arg]

    assert result["success"] is False  # type: ignore[index]
    assert "error" in result  # type: ignore[operator]


def test_tool_identity_failure_returns_public_error_before_case_state_or_exec(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _seed_case()
    exec_calls: list[object] = []
    monkeypatch.setattr(toolset, "kubectl_exec", lambda *_args, **_k: exec_calls.append(object()))
    tool = _build_tool("ghidra_decompile")

    result = tool(_NoStateToolContext(), function="main")  # type: ignore[call-arg]

    assert result == {
        "success": False,
        "error_code": "sandbox_identity_unavailable",
        "error": "The sandbox identity is unavailable.",
        "tool": "ghidra_decompile",
    }
    assert exec_calls == []


def test_tool_identity_access_failure_returns_public_error_before_case_state_or_exec(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _seed_case()
    exec_calls: list[object] = []
    monkeypatch.setattr(toolset, "kubectl_exec", lambda *_args, **_k: exec_calls.append(object()))
    tool = _build_tool("ghidra_decompile")

    result = tool(_ExplodingGetterToolContext(), function="main")  # type: ignore[call-arg]

    assert result == {
        "success": False,
        "error_code": "sandbox_identity_unavailable",
        "error": "The sandbox identity is unavailable.",
        "tool": "ghidra_decompile",
    }
    assert exec_calls == []


def test_tool_fail_open_when_kubectl_exec_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _seed_case()

    def _boom(*_a: str, **_k: object) -> str:
        raise RuntimeError("kubectl exec failed: timeout")

    monkeypatch.setattr(toolset, "kubectl_exec", _boom)

    context = _build_context(executor=FakeExecutor())
    tool = next(
        d.factory(context)
        for d in toolset.build_ghidra_toolset()
        if d.id == "ghidra_decompile"  # type: ignore[union-attr]
    )

    result = tool(_FakeToolContext(), function="main")  # type: ignore[call-arg]

    assert result["success"] is False  # type: ignore[index]
    assert "timeout" in result["error"]  # type: ignore[index]


# --- decompiler silent-empty detection (defense-in-depth) --------------------
# ghidra-rpc returns ok:true with an empty result when the decompiler cannot
# instantiate (e.g. a missing native binary). Without introspection the tool
# would report success on empty output, hiding the failure. These tests pin the
# contract: empty decompiler output / explicit ok:false surfaces as degraded.


def _build_tool(tool_id: str) -> Any:
    context = _build_context(executor=FakeExecutor())
    return next(
        d.factory(context)
        for d in toolset.build_ghidra_toolset()
        if d.id == tool_id  # type: ignore[union-attr]
    )


def test_decompile_empty_c_code_is_reported_as_degraded(monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_case()
    payload = json.dumps({"id": "x", "ok": True, "result": {"name": "main", "c_code": ""}})
    monkeypatch.setattr(toolset, "kubectl_exec", lambda *_a, **_k: payload)

    result = _build_tool("ghidra_decompile")(_FakeToolContext(), function="main")  # type: ignore[call-arg]

    assert result["success"] is False  # type: ignore[index]
    assert result["degraded"] is True  # type: ignore[index]
    assert "c_code" in result["error"]  # type: ignore[index]


def test_decompile_nonempty_c_code_is_success(monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_case()
    payload = json.dumps(
        {"id": "x", "ok": True, "result": {"name": "main", "c_code": "void main(void){}"}}
    )
    monkeypatch.setattr(toolset, "kubectl_exec", lambda *_a, **_k: payload)

    result = _build_tool("ghidra_decompile")(_FakeToolContext(), function="main")  # type: ignore[call-arg]

    assert result["success"] is True  # type: ignore[index]


def test_pcode_empty_ops_is_reported_as_degraded(monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_case()
    payload = json.dumps({"id": "x", "ok": True, "result": {"mode": "high", "ops": []}})
    monkeypatch.setattr(toolset, "kubectl_exec", lambda *_a, **_k: payload)

    result = _build_tool("ghidra_pcode")(_FakeToolContext(), function="main")  # type: ignore[call-arg]

    assert result["success"] is False  # type: ignore[index]
    assert result["degraded"] is True  # type: ignore[index]


def test_ghidra_rpc_ok_false_is_reported_as_degraded(monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_case()
    payload = json.dumps({"id": "x", "ok": False, "error": "decompiler crashed"})
    monkeypatch.setattr(toolset, "kubectl_exec", lambda *_a, **_k: payload)

    result = _build_tool("ghidra_decompile")(_FakeToolContext(), function="main")  # type: ignore[call-arg]

    assert result["success"] is False  # type: ignore[index]
    assert "decompiler crashed" in result["error"]  # type: ignore[index]


def test_non_json_output_remains_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unintrospectable (non-JSON) stdout stays success with the raw output."""
    _seed_case()
    monkeypatch.setattr(toolset, "kubectl_exec", lambda *_a, **_k: "raw non-json output")

    result = _build_tool("ghidra_decompile")(_FakeToolContext(), function="main")  # type: ignore[call-arg]

    assert result == {"success": True, "output": "raw non-json output"}


# --- prepare_ghidra ----------------------------------------------------------


def _make_artifact(tmp_path: Path) -> str:
    root = tmp_path / "artifacts"
    src = tmp_path / "sample.bin"
    src.write_bytes(b"hello-ghidra")
    from reverse_engineering.artifacts import ArtifactStore

    return ArtifactStore(root).acquire(src)


def test_prepare_ghidra_happy_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    artifact_id = _make_artifact(tmp_path)
    root = tmp_path / "artifacts"
    monkeypatch.setattr(prepare_ghidra, "default_artifacts_root", lambda: root)

    cp_calls: list[tuple[str, str, str, str]] = []
    exec_calls: list[list[str]] = []

    def _fake_cp(src: str, namespace: str, pod: str, dest: str) -> None:
        cp_calls.append((src, namespace, pod, dest))

    def _fake_exec(
        args: list[str],
        _namespace: str,
        _pod: str,
        **_kwargs: int,
    ) -> str:
        exec_calls.append(list(args))
        if args[0] == "ghidra-rpc" and args[1] == "load":
            return json.dumps({"ok": True, "result": {"short_name": "ls"}})
        return ""

    monkeypatch.setattr(prepare_ghidra, "kubectl_cp", _fake_cp)
    monkeypatch.setattr(prepare_ghidra, "kubectl_exec", _fake_exec)

    executor = FakeExecutor()
    tool = prepare_ghidra.build_prepare_ghidra(_build_context(executor=executor))

    result = tool(artifact_id, _FakeToolContext())

    assert result == {
        "pod": "ghidra-pod-1",
        "binary": "ls",
        "ready": True,
        "artifact_id": artifact_id,
        "reused": False,
    }
    assert cp_calls == [(str(root / artifact_id), "test-ns", "ghidra-pod-1", f"/app/{artifact_id}")]
    assert any(c[0] == "ghidra-rpc" and c[1] == "start" for c in exec_calls)
    assert any(c[0] == "ghidra-rpc" and c[1] == "load" for c in exec_calls)
    state = toolset._GHIDRA_CASE_STATE[_TEST_CASE_ID]
    assert state["pod"] == "ghidra-pod-1"
    assert state["binary"] == "ls"
    assert state["project"] == prepare_ghidra._PROJECT_PATH
    assert state["namespace"] == "test-ns"
    assert state["artifact_id"] == artifact_id
    assert executor.claimed == [(_TEST_CASE_ID, "ghidra-rpc")]


def test_prepare_ghidra_reuses_prepared_project_for_same_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A second prepare for the same case+artifact reuses the loaded project."""
    artifact_id = _make_artifact(tmp_path)
    monkeypatch.setattr(prepare_ghidra, "default_artifacts_root", lambda: tmp_path / "artifacts")
    monkeypatch.setattr(prepare_ghidra, "kubectl_cp", lambda *_a: None)
    exec_calls: list[list[str]] = []

    def _fake_exec(args: list[str], _namespace: str, _pod: str, **_kwargs: int) -> str:
        exec_calls.append(list(args))
        if args[1] == "load":
            return json.dumps({"ok": True, "result": {"short_name": "ls"}})
        return ""

    monkeypatch.setattr(prepare_ghidra, "kubectl_exec", _fake_exec)
    executor = FakeExecutor()
    tool = prepare_ghidra.build_prepare_ghidra(_build_context(executor=executor))

    first = tool(artifact_id, _FakeToolContext())
    second = tool(artifact_id, _FakeToolContext())

    assert first["reused"] is False
    assert second["reused"] is True
    assert second["pod"] == first["pod"]
    assert second["binary"] == first["binary"]
    assert second["artifact_id"] == artifact_id
    assert len(executor.claimed) == 1
    assert sum(call[1] == "load" for call in exec_calls) == 1


def test_prepare_ghidra_does_not_reuse_for_a_different_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A different canonical artifact must re-claim and re-load, never reuse."""
    from reverse_engineering.artifacts import ArtifactStore

    root = tmp_path / "artifacts"
    store = ArtifactStore(root)
    src_a = tmp_path / "a.bin"
    src_a.write_bytes(b"alpha-sample")
    src_b = tmp_path / "b.bin"
    src_b.write_bytes(b"bravo-sample")
    artifact_a = store.acquire(src_a)
    artifact_b = store.acquire(src_b)
    monkeypatch.setattr(prepare_ghidra, "default_artifacts_root", lambda: root)
    monkeypatch.setattr(prepare_ghidra, "kubectl_cp", lambda *_a: None)
    exec_calls: list[list[str]] = []

    def _fake_exec(args: list[str], _namespace: str, _pod: str, **_kwargs: int) -> str:
        exec_calls.append(list(args))
        if args[1] == "load":
            return json.dumps({"ok": True, "result": {"short_name": "ls"}})
        return ""

    monkeypatch.setattr(prepare_ghidra, "kubectl_exec", _fake_exec)
    executor = FakeExecutor()
    tool = prepare_ghidra.build_prepare_ghidra(_build_context(executor=executor))

    first = tool(artifact_a, _FakeToolContext())
    second = tool(artifact_b, _FakeToolContext())

    assert first["reused"] is False
    assert second["reused"] is False
    assert first["artifact_id"] == artifact_a
    assert second["artifact_id"] == artifact_b
    assert len(executor.claimed) == 2
    assert sum(call[1] == "load" for call in exec_calls) == 2


def test_prepare_ghidra_load_timeout_exceeds_analysis_and_rpc_budgets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A slow import must not outlive the ghidra-rpc client or kubectl exec."""
    artifact_id = _make_artifact(tmp_path)
    monkeypatch.setattr(prepare_ghidra, "default_artifacts_root", lambda: tmp_path / "artifacts")
    monkeypatch.setattr(prepare_ghidra, "kubectl_cp", lambda *_a: None)
    exec_calls: list[tuple[list[str], int]] = []

    def _fake_exec(
        args: list[str],
        _namespace: str,
        _pod: str,
        *,
        timeout: int = 300,
    ) -> str:
        exec_calls.append((list(args), timeout))
        if args[1] == "load":
            return json.dumps({"ok": True, "result": {"short_name": "sample"}})
        return ""

    monkeypatch.setattr(prepare_ghidra, "kubectl_exec", _fake_exec)
    tool = prepare_ghidra.build_prepare_ghidra(_build_context(executor=FakeExecutor()))

    result = tool(artifact_id, _FakeToolContext())

    assert result["ready"] is True
    load_args, exec_timeout = next(call for call in exec_calls if call[0][1] == "load")
    analysis_timeout_index = load_args.index("--analysis-timeout") + 1
    analysis_timeout = int(load_args[analysis_timeout_index])
    assert analysis_timeout == 600
    # ghidra-rpc waits analysis_timeout + 30 seconds at the socket layer.
    assert exec_timeout == 660
    assert exec_timeout >= analysis_timeout + 60


def test_prepare_ghidra_falls_back_to_artifact_id_when_no_short_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_id = _make_artifact(tmp_path)
    monkeypatch.setattr(prepare_ghidra, "default_artifacts_root", lambda: tmp_path / "artifacts")
    monkeypatch.setattr(prepare_ghidra, "kubectl_cp", lambda *_a: None)
    monkeypatch.setattr(prepare_ghidra, "kubectl_exec", lambda *_a, **_k: "not json")

    tool = prepare_ghidra.build_prepare_ghidra(_build_context(executor=FakeExecutor()))

    result = tool(artifact_id, _FakeToolContext())

    assert result["ready"] is True  # type: ignore[index]
    assert result["binary"] == artifact_id  # type: ignore[index]
    assert result["artifact_id"] == artifact_id  # type: ignore[index]


def test_prepare_ghidra_canonical_state_overrides_stale_model_argument(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_id = _make_artifact(tmp_path)
    stale_id = "b" * 64
    root = tmp_path / "artifacts"
    monkeypatch.setattr(prepare_ghidra, "default_artifacts_root", lambda: root)
    copied: list[tuple[str, str]] = []
    monkeypatch.setattr(
        prepare_ghidra,
        "kubectl_cp",
        lambda src, _namespace, _pod, dest: copied.append((src, dest)),
    )
    monkeypatch.setattr(prepare_ghidra, "kubectl_exec", lambda *_a, **_k: "")

    tool = prepare_ghidra.build_prepare_ghidra(_build_context(executor=FakeExecutor()))
    result = tool(stale_id, _FakeToolContext({CURRENT_ARTIFACT_KEY: artifact_id}))

    assert result["artifact_id"] == artifact_id  # type: ignore[index]
    assert copied == [(str(root / artifact_id), f"/app/{artifact_id}")]


def test_prepare_ghidra_invalid_canonical_state_has_no_sandbox_side_effects() -> None:
    executor = FakeExecutor()
    tool = prepare_ghidra.build_prepare_ghidra(_build_context(executor=executor))

    result = tool("a" * 64, _FakeToolContext({CURRENT_ARTIFACT_KEY: "../escape"}))

    assert result["ready"] is False  # type: ignore[index]
    assert result["error"] == "artifact_id must be a lowercase SHA-256"  # type: ignore[index]
    assert executor.claimed == []


def test_prepare_ghidra_identity_failure_happens_before_claim_copy_or_exec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(prepare_ghidra, "default_artifacts_root", lambda: tmp_path / "artifacts")
    copy_calls: list[object] = []
    exec_calls: list[object] = []
    monkeypatch.setattr(prepare_ghidra, "kubectl_cp", lambda *_args: copy_calls.append(object()))
    monkeypatch.setattr(
        prepare_ghidra, "kubectl_exec", lambda *_args, **_kwargs: exec_calls.append(object())
    )
    executor = FakeExecutor()

    result = prepare_ghidra.build_prepare_ghidra(_build_context(executor=executor))(
        "a" * 64,
        _NoStateToolContext(),
    )

    assert result == {
        "pod": "",
        "binary": "",
        "ready": False,
        "error_code": "sandbox_identity_unavailable",
        "error": "The sandbox identity is unavailable.",
        "artifact_id": "a" * 64,
    }
    assert executor.claimed == []
    assert copy_calls == []
    assert exec_calls == []


@pytest.mark.parametrize(
    "tool_context", [_ExplodingGetterToolContext(), _ExplodingStateToolContext()]
)
def test_prepare_ghidra_identity_access_failure_happens_before_artifact_lookup_or_sandbox_operations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tool_context: object,
) -> None:
    monkeypatch.setattr(prepare_ghidra, "default_artifacts_root", lambda: tmp_path / "artifacts")
    copy_calls: list[object] = []
    exec_calls: list[object] = []
    monkeypatch.setattr(prepare_ghidra, "kubectl_cp", lambda *_args: copy_calls.append(object()))
    monkeypatch.setattr(
        prepare_ghidra,
        "kubectl_exec",
        lambda *_args, **_kwargs: exec_calls.append(object()),
    )
    executor = FakeExecutor()

    result = prepare_ghidra.build_prepare_ghidra(_build_context(executor=executor))(
        "a" * 64,
        tool_context,  # type: ignore[arg-type]
    )

    assert result == {
        "pod": "",
        "binary": "",
        "ready": False,
        "error_code": "sandbox_identity_unavailable",
        "error": "The sandbox identity is unavailable.",
        "artifact_id": "a" * 64,
    }
    assert executor.claimed == []
    assert copy_calls == []
    assert exec_calls == []


@pytest.mark.parametrize("artifact_id", ["artifact", "../" + "a" * 64, "A" * 64])
def test_prepare_ghidra_rejects_malformed_legacy_artifact_before_claim(artifact_id: str) -> None:
    executor = FakeExecutor()
    tool = prepare_ghidra.build_prepare_ghidra(_build_context(executor=executor))

    result = tool(artifact_id, _FakeToolContext())

    assert result["ready"] is False  # type: ignore[index]
    assert result["error"] == "artifact_id must be a lowercase SHA-256"  # type: ignore[index]
    assert executor.claimed == []


def test_prepare_ghidra_hides_tool_context_from_adk_schema() -> None:
    declaration = FunctionTool(
        prepare_ghidra.build_prepare_ghidra(_build_context(executor=None))
    )._get_declaration()

    assert declaration is not None
    assert declaration.parameters is not None
    assert set(declaration.parameters.properties) == {"artifact_id"}


def test_prepare_ghidra_fail_open_when_executor_is_none() -> None:
    tool = prepare_ghidra.build_prepare_ghidra(_build_context(executor=None))
    artifact_id = "a" * 64

    result = tool(artifact_id, _FakeToolContext())

    assert result["ready"] is False  # type: ignore[index]
    assert result["error"] == "sandbox executor is not configured"  # type: ignore[index]
    assert result["artifact_id"] == artifact_id  # type: ignore[index]


def test_prepare_ghidra_fail_open_when_kubectl_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(prepare_ghidra, "default_artifacts_root", lambda: tmp_path / "artifacts")

    def _boom(*_a: str) -> None:
        raise RuntimeError("kubectl cp failed: refused")

    monkeypatch.setattr(prepare_ghidra, "kubectl_cp", _boom)
    monkeypatch.setattr(prepare_ghidra, "kubectl_exec", lambda *_a, **_k: "")

    tool = prepare_ghidra.build_prepare_ghidra(_build_context(executor=FakeExecutor()))

    result = tool("a" * 64, _FakeToolContext({SessionKeys.SANDBOX_CASE_ID: "case-x"}))

    assert result["ready"] is False  # type: ignore[index]
    assert "error" in result  # type: ignore[operator]
    assert result["artifact_id"] == "a" * 64  # type: ignore[index]
    # A failed cp is released scoped by sandbox_session on every attempt: nothing left.
    assert sandbox_session.released_pools("case-x") == frozenset()


def test_prepare_ghidra_retries_transient_load_kill_then_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A transient exit-137 kill on load (memory contention) is retried, not fatal."""
    artifact_id = _make_artifact(tmp_path)
    monkeypatch.setattr(prepare_ghidra, "default_artifacts_root", lambda: tmp_path / "artifacts")
    monkeypatch.setattr(prepare_ghidra, "kubectl_cp", lambda *_a, **_k: None)
    monkeypatch.setattr(prepare_ghidra, "_LOAD_RETRY_BACKOFF_SECONDS", 0.0)

    load_attempts = 0

    def _fake_exec(args: list[str], _namespace: str, _pod: str, **_kwargs: int) -> str:
        nonlocal load_attempts
        if args[0] == "ghidra-rpc" and args[1] == "load":
            load_attempts += 1
            if load_attempts == 1:
                raise RuntimeError(
                    "kubectl exec failed (exit 137): command terminated with exit code 137"
                )
            return json.dumps({"ok": True, "result": {"short_name": "ls"}})
        return ""

    monkeypatch.setattr(prepare_ghidra, "kubectl_exec", _fake_exec)

    tool = prepare_ghidra.build_prepare_ghidra(_build_context(executor=FakeExecutor()))
    result = tool(artifact_id, _FakeToolContext())

    assert result["ready"] is True  # type: ignore[index]
    assert result["binary"] == "ls"  # type: ignore[index]
    assert load_attempts == 2, "the first load was killed; the second must have been retried"


def test_prepare_ghidra_degrades_when_all_load_attempts_are_killed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When every load attempt is killed, the stage degrades (never crashes)."""
    artifact_id = _make_artifact(tmp_path)
    monkeypatch.setattr(prepare_ghidra, "default_artifacts_root", lambda: tmp_path / "artifacts")
    monkeypatch.setattr(prepare_ghidra, "kubectl_cp", lambda *_a, **_k: None)
    monkeypatch.setattr(prepare_ghidra, "_LOAD_RETRY_BACKOFF_SECONDS", 0.0)

    load_attempts = 0

    def _fake_exec(args: list[str], _namespace: str, _pod: str, **_kwargs: int) -> str:
        nonlocal load_attempts
        if args[0] == "ghidra-rpc" and args[1] == "load":
            load_attempts += 1
            raise RuntimeError("kubectl exec failed (exit 137): command terminated")
        return ""

    monkeypatch.setattr(prepare_ghidra, "kubectl_exec", _fake_exec)

    tool = prepare_ghidra.build_prepare_ghidra(_build_context(executor=FakeExecutor()))
    result = tool(artifact_id, _FakeToolContext())

    assert result["ready"] is False  # type: ignore[index]
    assert "error" in result  # type: ignore[operator]
    assert load_attempts == prepare_ghidra._LOAD_ATTEMPTS, (
        "every attempt must be tried before degrading"
    )


def test_prepare_ghidra_descriptor_well_formed() -> None:
    desc = prepare_ghidra.PREPARE_GHIDRA_TOOL
    assert desc.id == "prepare_ghidra"
    assert desc.factory is build_prepare_ghidra_factory_ref()
    assert isinstance(desc.output_policy, OutputPolicy)
    assert desc.output_policy.max_chars > 0


def build_prepare_ghidra_factory_ref() -> Any:
    return prepare_ghidra.build_prepare_ghidra


def test_release_ghidra_case_delegates_scoped_release_and_stops_the_daemon(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # release_ghidra_case drops the cached load state and delegates to the shared
    # scoped release, which runs the daemon-stop on_release hook and frees the claim.
    stops: list[list[str]] = []
    monkeypatch.setattr(
        prepare_ghidra,
        "kubectl_exec",
        lambda args, *_a, **_k: stops.append(list(args)),
    )
    executor = FakeExecutor()
    # Register a ghidra session the way prepare_ghidra does -- with the daemon-stop hook.
    sandbox_session.provision_pod(
        executor=executor,
        case_id="case-9",
        pool="ghidra-rpc",
        namespace="ns",
        provision=lambda pod: pod,
        on_release=prepare_ghidra._stop_daemon_quietly,
    )
    toolset._GHIDRA_CASE_STATE["case-9"] = {
        "pod": "ghidra-pod-1",
        "binary": "ls",
        "project": "/tmp/p.gpr",
        "namespace": "ns",
    }

    prepare_ghidra.release_ghidra_case("case-9")

    assert any(a[:2] == ["ghidra-rpc", "stop"] for a in stops)  # daemon stopped via on_release
    assert executor.released == ["case-9"]  # scoped release
    assert "case-9" not in toolset._GHIDRA_CASE_STATE
    assert sandbox_session.released_pools("case-9") == frozenset()


def test_release_ghidra_case_is_safe_noop_for_unknown() -> None:
    prepare_ghidra.release_ghidra_case("never-claimed")  # must not raise
