"""Contract tests for the sandboxed UPX recovery tool."""

from __future__ import annotations

import hashlib
import json
from concurrent.futures import CancelledError
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import pytest
from google.adk.tools.function_tool import FunctionTool

from arema.core.config import LLMProvider, Settings
from arema.runtime.agent_factory import ToolBuildContext
from arema.runtime.sandbox.port import ExecutionResult, SandboxHandle
from arema.runtime.services import RuntimeServices
from arema.runtime.sessions import SessionKeys
from reverse_engineering.artifacts import ArtifactStore
from reverse_engineering.tools.deobfuscation.runtime import MAX_RECOVERED_BYTES
from reverse_engineering.tools.deobfuscation.state import (
    CLASSIFICATION_KEY,
    CURRENT_ARTIFACT_KEY,
    CURRENT_ARTIFACT_PROMPT_KEY,
    UPX_CALLED_KEY,
    UPX_CHANGED_KEY,
    UPX_DEGRADED_KEY,
    UPX_PROVENANCE_PROMPT_KEY,
    UPX_RESULT_KEY,
)
from reverse_engineering.tools.deobfuscation.upx import (
    MAX_UPX_INPUT_BYTES,
    UPX_UNPACK_TOOL,
    build_upx_unpack,
)

if TYPE_CHECKING:
    from pathlib import Path

    from arema.registry.catalog import CapabilityCatalog


class _FakeExecutor:
    def __init__(self) -> None:
        self.claims: list[tuple[str, str]] = []
        self.runs: list[tuple[SandboxHandle, str, float]] = []
        self.writes: list[tuple[SandboxHandle, str, bytes]] = []
        self.reads: list[tuple[SandboxHandle, str]] = []
        self.files: dict[str, bytes] = {}
        self.results: list[ExecutionResult | Exception] = []
        self.handle = SandboxHandle(
            key="case-1", pool="deobfuscation-tools", backend_id="deobfuscation-case-1"
        )

    def claim(self, *, key: str, pool: str) -> SandboxHandle:
        self.claims.append((key, pool))
        return self.handle

    def run(self, handle: SandboxHandle, command: str, *, timeout: float) -> ExecutionResult:
        self.runs.append((handle, command, timeout))
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    def write_file(self, handle: SandboxHandle, path: str, data: bytes) -> None:
        self.writes.append((handle, path, data))
        self.files[path] = data

    def read_file(self, handle: SandboxHandle, path: str) -> bytes:
        self.reads.append((handle, path))
        return self.files[path]

    def terminate(self, handle: SandboxHandle) -> None:
        pass

    def release_session(self, key: str) -> None:
        pass


class _FakeState:
    """Duck-typed ADK State stand-in, deliberately not a dict subclass."""

    def __init__(self, values: dict[str, object]) -> None:
        self.values = values

    def get(self, key: str, default: object = None) -> object:
        return self.values.get(key, default)

    def __getitem__(self, key: str) -> object:
        return self.values[key]

    def __setitem__(self, key: str, value: object) -> None:
        self.values[key] = value


class _FakeToolContext:
    def __init__(self, values: dict[str, object]) -> None:
        self.state = _FakeState(values)


def _build_context(executor: _FakeExecutor) -> ToolBuildContext:
    settings = Settings(
        _env_file=None,
        llm_provider=LLMProvider.OLLAMA,
        sandbox_backend="k8s",
        sandbox_run_timeout=45,
    )
    services = RuntimeServices.default()
    return ToolBuildContext(
        settings=settings,
        services=RuntimeServices(
            clock=services.clock,
            metrics=services.metrics,
            memory_sink=services.memory_sink,
            sandbox=executor,
        ),
        catalog=cast("CapabilityCatalog", object()),
    )


def _classification(artifact_id: str, *, upx: bool) -> str:
    return json.dumps(
        {
            "artifact_id": artifact_id,
            "deobf_plan": {"upx": upx, "floss": False},
            "pcode_preferred": False,
            "obf_class": "upx" if upx else "none",
            "pre_snapshot": {
                "size": 0,
                "function_count": 0,
                "import_count": 0,
                "string_count": 0,
                "section_count": 0,
            },
        }
    )


def _store_artifact(tmp_path: Path, data: bytes = b"packed") -> tuple[Path, str]:
    root = tmp_path / "artifacts"
    source = tmp_path / "sample.bin"
    source.write_bytes(data)
    return root, ArtifactStore(root).acquire(source)


def _tool_context(
    artifact_id: str, *, upx: bool, extra: dict[str, object] | None = None
) -> _FakeToolContext:
    values: dict[str, object] = {
        CLASSIFICATION_KEY: _classification(artifact_id, upx=upx),
        CURRENT_ARTIFACT_KEY: artifact_id,
        SessionKeys.SANDBOX_CASE_ID: "case-1",
    }
    if extra:
        values.update(extra)
    return _FakeToolContext(values)


def _patch_artifact_roots(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    import reverse_engineering.tools.deobfuscation.runtime as runtime
    import reverse_engineering.tools.deobfuscation.upx as upx

    monkeypatch.setattr(runtime, "default_artifacts_root", lambda: root)
    monkeypatch.setattr(upx, "default_artifacts_root", lambda: root)


def _assert_result_schema(result: dict[str, str | bool]) -> None:
    assert {"success", "applicable", "degraded", "changed", "tool_version"} <= result.keys()


def test_upx_skips_and_resets_state_when_plan_disabled() -> None:
    executor = _FakeExecutor()
    artifact_id = "a" * 64
    tool_context = _tool_context(
        artifact_id,
        upx=False,
        extra={UPX_CHANGED_KEY: True, UPX_DEGRADED_KEY: True},
    )

    result = build_upx_unpack(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert result == {
        "success": True,
        "applicable": False,
        "degraded": False,
        "changed": False,
        "reason": "plan_disabled",
        "source_artifact_id": artifact_id,
        "tool_version": "5.2.0",
    }
    assert tool_context.state[CURRENT_ARTIFACT_KEY] == artifact_id
    assert tool_context.state[UPX_CHANGED_KEY] is False
    assert tool_context.state[UPX_DEGRADED_KEY] is False
    assert executor.claims == []


def test_upx_duplicate_call_rehydrates_gate_facts_from_cached_result() -> None:
    executor = _FakeExecutor()
    artifact_id = "a" * 64
    tool_context = _tool_context(artifact_id, upx=False)
    tool = build_upx_unpack(_build_context(executor))

    first = tool(tool_context)  # type: ignore[operator]
    tool_context.state[UPX_CHANGED_KEY] = True
    tool_context.state[UPX_DEGRADED_KEY] = True
    second = tool(tool_context)  # type: ignore[operator]

    assert first == second
    assert first is not second
    assert tool_context.state[UPX_CALLED_KEY] is True
    assert tool_context.state[UPX_RESULT_KEY] == first
    assert tool_context.state[UPX_CHANGED_KEY] is False
    assert tool_context.state[UPX_DEGRADED_KEY] is False
    assert executor.claims == []


@pytest.mark.parametrize(
    ("cached", "expected_changed", "expected_degraded"),
    [
        (
            {
                "success": False,
                "applicable": True,
                "degraded": True,
                "changed": False,
                "error_code": "sandbox_unavailable",
                "error": "The deobfuscation sandbox is unavailable.",
                "source_artifact_id": "a" * 64,
                "source_size": 6,
                "tool_version": "5.2.0",
            },
            False,
            True,
        ),
        (
            {
                "success": True,
                "applicable": False,
                "degraded": False,
                "changed": False,
                "reason": "not_packed",
                "source_artifact_id": "a" * 64,
                "source_size": 6,
                "tool_version": "5.2.0",
            },
            False,
            False,
        ),
        (
            {
                "success": True,
                "applicable": False,
                "degraded": False,
                "changed": False,
                "reason": "plan_disabled",
                "source_artifact_id": "a" * 64,
                "tool_version": "5.2.0",
            },
            False,
            False,
        ),
        (
            {
                "success": True,
                "applicable": False,
                "degraded": False,
                "changed": False,
                "reason": "input_too_large",
                "source_artifact_id": "a" * 64,
                "source_size": 512 * 1024 * 1024 + 1,
                "tool_version": "5.2.0",
            },
            False,
            False,
        ),
        (
            {
                "success": True,
                "applicable": True,
                "degraded": False,
                "changed": True,
                "source_artifact_id": "a" * 64,
                "recovered_artifact_id": "b" * 64,
                "source_size": 6,
                "recovered_size": 7,
                "tool_version": "5.2.0",
            },
            True,
            False,
        ),
        (
            {
                "success": True,
                "applicable": True,
                "degraded": False,
                "changed": False,
                "source_artifact_id": "a" * 64,
                "recovered_artifact_id": "a" * 64,
                "source_size": 6,
                "recovered_size": 6,
                "tool_version": "5.2.0",
            },
            False,
            False,
        ),
    ],
)
def test_upx_valid_cached_variants_restore_missing_or_stale_gate_facts(
    cached: dict[str, object],
    expected_changed: bool,
    expected_degraded: bool,
) -> None:
    executor = _FakeExecutor()
    tool_context = _tool_context(
        "a" * 64,
        upx=False,
        extra={
            UPX_CALLED_KEY: True,
            UPX_RESULT_KEY: cached,
            UPX_CHANGED_KEY: not expected_changed,
        },
    )

    result = build_upx_unpack(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert result == cached
    assert tool_context.state[UPX_CHANGED_KEY] is expected_changed
    assert tool_context.state[UPX_DEGRADED_KEY] is expected_degraded
    assert executor.claims == []


@pytest.mark.parametrize(
    "cached",
    [
        {
            "success": False,
            "applicable": True,
            "degraded": True,
            "changed": False,
            "error_code": "made_up",
            "error": "arbitrary",
            "tool_version": "5.2.0",
        },
        {
            "success": False,
            "applicable": True,
            "degraded": True,
            "changed": False,
            "error_code": "upx_failed",
            "error": "wrong message",
            "reason": "not_packed",
            "tool_version": "5.2.0",
        },
        {
            "success": True,
            "applicable": False,
            "degraded": False,
            "changed": False,
            "reason": "plan_disabled",
            "source_artifact_id": "a" * 64,
            "source_size": 6,
            "tool_version": "5.2.0",
        },
        {
            "success": True,
            "applicable": False,
            "degraded": False,
            "changed": False,
            "reason": "not_packed",
            "source_artifact_id": "a" * 64,
            "source_size": 6,
            "recovered_size": 6,
            "tool_version": "5.2.0",
        },
        {
            "success": True,
            "applicable": True,
            "degraded": False,
            "changed": False,
            "source_artifact_id": "a" * 64,
            "recovered_artifact_id": "b" * 64,
            "source_size": 6,
            "recovered_size": 7,
            "tool_version": "5.2.0",
        },
        {
            "success": True,
            "applicable": True,
            "degraded": False,
            "changed": True,
            "source_artifact_id": "a" * 64,
            "recovered_artifact_id": "b" * 64,
            "source_size": 6,
            "recovered_size": 7,
            "reason": "not_packed",
            "tool_version": "5.2.0",
        },
        {
            "success": False,
            "applicable": True,
            "degraded": True,
            "changed": False,
            "error_code": "upx_failed",
            "error": "UPX could not unpack the artifact.",
            "source_artifact_id": "bad",
            "tool_version": "5.2.0",
        },
        {
            "success": False,
            "applicable": True,
            "degraded": True,
            "changed": False,
            "error_code": "upx_failed",
            "error": "UPX could not unpack the artifact.",
            "source_size": True,
            "tool_version": "5.2.0",
        },
        {
            "success": True,
            "applicable": False,
            "degraded": False,
            "changed": False,
            "reason": "unknown",
            "source_artifact_id": "a" * 64,
            "tool_version": "5.2.0",
        },
        {
            "success": True,
            "applicable": True,
            "degraded": False,
            "changed": True,
            "source_artifact_id": "a" * 64,
            "recovered_artifact_id": "b" * 64,
            "source_size": 6,
            "tool_version": "5.2.0",
        },
    ],
)
def test_upx_rejects_cache_variants_not_emitted_by_result_constructors(
    cached: dict[str, object],
) -> None:
    executor = _FakeExecutor()
    tool_context = _tool_context(
        "a" * 64,
        upx=False,
        extra={UPX_CALLED_KEY: True, UPX_RESULT_KEY: cached},
    )

    result = build_upx_unpack(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert result["error_code"] == "invalid_classification"
    assert tool_context.state[UPX_CHANGED_KEY] is False
    assert tool_context.state[UPX_DEGRADED_KEY] is True
    assert executor.claims == []


def test_upx_first_call_sets_identifier_safe_prompt_alias() -> None:
    executor = _FakeExecutor()
    artifact_id = "a" * 64
    tool_context = _tool_context(artifact_id, upx=False)

    build_upx_unpack(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert tool_context.state[CURRENT_ARTIFACT_PROMPT_KEY] == artifact_id


def test_upx_rejects_stale_classification_without_rewinding_canonical_state() -> None:
    executor = _FakeExecutor()
    classified_id = "a" * 64
    current_id = "b" * 64
    provenance = f"upx_unpack source={classified_id} destination={current_id}"
    tool_context = _tool_context(
        classified_id,
        upx=True,
        extra={
            CURRENT_ARTIFACT_KEY: current_id,
            CURRENT_ARTIFACT_PROMPT_KEY: current_id,
            UPX_PROVENANCE_PROMPT_KEY: provenance,
        },
    )

    result = build_upx_unpack(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert result["error_code"] == "invalid_classification"
    assert tool_context.state[CURRENT_ARTIFACT_KEY] == current_id
    assert tool_context.state[CURRENT_ARTIFACT_PROMPT_KEY] == current_id
    assert tool_context.state[UPX_PROVENANCE_PROMPT_KEY] == provenance
    assert executor.claims == []


def test_upx_malformed_duplicate_marker_fails_closed_without_executing() -> None:
    executor = _FakeExecutor()
    tool_context = _tool_context("a" * 64, upx=False, extra={UPX_CALLED_KEY: None})

    result = build_upx_unpack(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert result["success"] is False
    assert result["degraded"] is True
    assert tool_context.state[UPX_RESULT_KEY] == result
    assert tool_context.state[UPX_CHANGED_KEY] is False
    assert tool_context.state[UPX_DEGRADED_KEY] is True
    assert executor.claims == []


@pytest.mark.parametrize(
    ("cache_present", "cached"),
    [
        (False, None),
        (True, None),
        (True, {}),
        (
            True,
            {
                "success": "false",
                "applicable": True,
                "degraded": True,
                "changed": False,
                "tool_version": "5.2.0",
            },
        ),
        (
            True,
            {
                "success": False,
                "applicable": True,
                "degraded": True,
                "changed": False,
            },
        ),
    ],
)
def test_upx_corrupt_duplicate_cache_is_replaced_with_locked_degraded_result(
    cache_present: bool,
    cached: object,
) -> None:
    executor = _FakeExecutor()
    extra: dict[str, object] = {
        UPX_CALLED_KEY: True,
        UPX_CHANGED_KEY: True,
        UPX_DEGRADED_KEY: False,
    }
    if cache_present:
        extra[UPX_RESULT_KEY] = cached
    tool_context = _tool_context(
        "a" * 64,
        upx=False,
        extra=extra,
    )

    result = build_upx_unpack(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert result == {
        "success": False,
        "applicable": True,
        "degraded": True,
        "changed": False,
        "error_code": "invalid_classification",
        "error": "The deobfuscation classification is invalid.",
        "tool_version": "5.2.0",
    }
    assert tool_context.state[UPX_CHANGED_KEY] is False
    assert tool_context.state[UPX_DEGRADED_KEY] is True
    assert tool_context.state[UPX_RESULT_KEY] == result
    assert executor.claims == []


def test_upx_fresh_call_invalidates_old_result_before_execution() -> None:
    executor = _FakeExecutor()
    artifact_id = "a" * 64
    tool_context = _tool_context(
        artifact_id,
        upx=False,
        extra={
            UPX_CALLED_KEY: False,
            UPX_RESULT_KEY: {"stale": True},
        },
    )

    result = build_upx_unpack(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert result["reason"] == "plan_disabled"
    assert result["source_artifact_id"] == artifact_id
    assert "stale" not in result
    assert tool_context.state[UPX_RESULT_KEY] == result


def test_upx_cancellation_after_fresh_start_cannot_expose_old_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import reverse_engineering.tools.deobfuscation.upx as upx

    tool_context = _tool_context(
        "a" * 64,
        upx=True,
        extra={
            UPX_CALLED_KEY: False,
            UPX_RESULT_KEY: {"stale": True},
            UPX_CHANGED_KEY: True,
            UPX_DEGRADED_KEY: True,
        },
    )
    monkeypatch.setattr(
        upx,
        "parse_current_classification",
        lambda _state: (_ for _ in ()).throw(CancelledError()),
    )

    with pytest.raises(CancelledError):
        build_upx_unpack(_build_context(_FakeExecutor()))(tool_context)  # type: ignore[operator]

    assert tool_context.state[UPX_RESULT_KEY] is None
    assert tool_context.state[UPX_CHANGED_KEY] is False
    assert tool_context.state[UPX_DEGRADED_KEY] is False
    assert tool_context.state[UPX_CALLED_KEY] is True


def test_upx_not_packed_is_successful_non_applicability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    executor = _FakeExecutor()
    executor.results.extend(
        [
            ExecutionResult(exit_code=0, stdout="", stderr=""),
            ExecutionResult(exit_code=1, stdout="", stderr="NotPackedException: not packed by UPX"),
        ]
    )
    tool_context = _tool_context(artifact_id, upx=True)

    result = build_upx_unpack(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert result == {
        "success": True,
        "applicable": False,
        "degraded": False,
        "changed": False,
        "reason": "not_packed",
        "source_artifact_id": artifact_id,
        "source_size": 6,
        "tool_version": "5.2.0",
    }
    assert tool_context.state[CURRENT_ARTIFACT_KEY] == artifact_id
    assert tool_context.state[UPX_CHANGED_KEY] is False
    assert tool_context.state[UPX_DEGRADED_KEY] is False


def test_upx_valid_sandbox_result_is_cached_without_second_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    executor = _FakeExecutor()
    executor.results.extend(
        [
            ExecutionResult(exit_code=0, stdout="", stderr=""),
            ExecutionResult(exit_code=1, stdout="", stderr="not packed by UPX"),
        ]
    )
    tool_context = _tool_context(artifact_id, upx=True)
    tool = build_upx_unpack(_build_context(executor))

    first = tool(tool_context)  # type: ignore[operator]
    run_count = len(executor.runs)
    second = tool(tool_context)  # type: ignore[operator]

    assert second == first
    assert second is not first
    assert len(executor.runs) == run_count


def test_upx_rejects_oversized_input_before_claim_or_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import reverse_engineering.tools.deobfuscation.upx as upx

    artifact_id = "a" * 64
    source = SimpleNamespace(stat=lambda: SimpleNamespace(st_size=MAX_UPX_INPUT_BYTES + 1))
    monkeypatch.setattr(upx.ArtifactStore, "path_for", lambda _self, _artifact_id: source)
    executor = _FakeExecutor()

    result = build_upx_unpack(_build_context(executor))(_tool_context(artifact_id, upx=True))  # type: ignore[operator]

    assert result == {
        "success": True,
        "applicable": False,
        "degraded": False,
        "changed": False,
        "reason": "input_too_large",
        "source_artifact_id": artifact_id,
        "source_size": MAX_UPX_INPUT_BYTES + 1,
        "tool_version": "5.2.0",
    }
    assert executor.claims == []
    assert executor.writes == []


def test_upx_stages_at_bound_input_with_fixed_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import reverse_engineering.tools.deobfuscation.upx as upx

    artifact_id = "a" * 64
    source = SimpleNamespace(stat=lambda: SimpleNamespace(st_size=MAX_UPX_INPUT_BYTES))
    monkeypatch.setattr(upx.ArtifactStore, "path_for", lambda _self, _artifact_id: source)
    observed: dict[str, object] = {}

    def stage_with_cap(
        _context: object,
        staged_artifact_id: str,
        _tool_context: object,
        *,
        tool_name: str,
        max_input_bytes: int,
    ) -> object:
        observed.update(
            artifact_id=staged_artifact_id,
            tool_name=tool_name,
            max_input_bytes=max_input_bytes,
        )
        raise upx.DeobfuscationUnavailable

    monkeypatch.setattr(upx, "stage_artifact", stage_with_cap)

    result = build_upx_unpack(_build_context(_FakeExecutor()))(_tool_context(artifact_id, upx=True))  # type: ignore[operator]

    assert observed == {
        "artifact_id": artifact_id,
        "tool_name": "upx",
        "max_input_bytes": MAX_UPX_INPUT_BYTES,
    }
    assert result["source_artifact_id"] == artifact_id
    assert result["source_size"] == MAX_UPX_INPUT_BYTES


@pytest.mark.parametrize("exit_code", [0, 1])
@pytest.mark.parametrize("marker", ["nOtPaCkEdExCePtIoN", "NOT PACKED BY UPX"])
def test_upx_not_packed_markers_are_non_applicable_regardless_of_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, exit_code: int, marker: str
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    executor = _FakeExecutor()
    executor.results.extend(
        [
            ExecutionResult(exit_code=0, stdout="", stderr=""),
            ExecutionResult(exit_code=exit_code, stdout="", stderr=marker),
        ]
    )
    tool_context = _tool_context(artifact_id, upx=True)

    result = build_upx_unpack(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert result == {
        "success": True,
        "applicable": False,
        "degraded": False,
        "changed": False,
        "reason": "not_packed",
        "source_artifact_id": artifact_id,
        "source_size": 6,
        "tool_version": "5.2.0",
    }
    assert tool_context.state[CURRENT_ARTIFACT_KEY] == artifact_id
    assert tool_context.state[UPX_CHANGED_KEY] is False
    assert tool_context.state[UPX_DEGRADED_KEY] is False
    assert executor.reads == []


def test_upx_recovery_admits_new_content_hash_and_updates_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    executor = _FakeExecutor()
    output_path = f"/work/upx/{artifact_id}/unpacked"
    executor.files[output_path] = b"unpacked"
    executor.results.extend(
        [
            ExecutionResult(exit_code=0, stdout="", stderr=""),
            ExecutionResult(exit_code=0, stdout="", stderr=""),
            ExecutionResult(exit_code=0, stdout="8\n", stderr=""),
        ]
    )
    tool_context = _tool_context(artifact_id, upx=True)

    result = build_upx_unpack(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert set(result) == {
        "success",
        "applicable",
        "degraded",
        "changed",
        "source_artifact_id",
        "recovered_artifact_id",
        "source_size",
        "recovered_size",
        "tool_version",
    }
    assert result["source_artifact_id"] == artifact_id
    assert result["source_size"] == len((root / artifact_id).read_bytes())
    assert result["recovered_size"] == len(b"unpacked")
    assert result["recovered_artifact_id"] == hashlib.sha256(b"unpacked").hexdigest()
    assert tool_context.state[CURRENT_ARTIFACT_KEY] == result["recovered_artifact_id"]
    assert tool_context.state[UPX_CHANGED_KEY] is True
    assert tool_context.state[UPX_PROVENANCE_PROMPT_KEY] == (
        f"upx_unpack source={artifact_id} destination={result['recovered_artifact_id']}"
    )
    updated_classification = json.loads(cast("str", tool_context.state[CLASSIFICATION_KEY]))
    assert updated_classification["artifact_id"] == result["recovered_artifact_id"]
    assert result["tool_version"] == "5.2.0"
    assert result["success"] is True
    assert result["applicable"] is True
    assert result["degraded"] is False
    assert result["changed"] is True
    assert executor.runs[1][1] == f"upx -d -o {output_path} /work/upx/{artifact_id}/input"
    assert output_path.startswith(f"/work/upx/{artifact_id}/")
    assert output_path != f"/work/upx/{artifact_id}/input"


def test_upx_rejects_output_over_512_mib_before_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    executor = _FakeExecutor()
    executor.results.extend(
        [
            ExecutionResult(exit_code=0, stdout="", stderr=""),
            ExecutionResult(exit_code=0, stdout="", stderr=""),
            ExecutionResult(exit_code=0, stdout=f"{MAX_RECOVERED_BYTES + 1}\n", stderr=""),
        ]
    )
    tool_context = _tool_context(artifact_id, upx=True)

    result = build_upx_unpack(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert result["success"] is False
    assert result["applicable"] is True
    assert result["degraded"] is True
    assert result["changed"] is False
    assert result["error_code"] == "output_invalid"
    assert result["error"] == "The recovered output is invalid."
    assert tool_context.state[CURRENT_ARTIFACT_KEY] == artifact_id
    assert tool_context.state[UPX_CHANGED_KEY] is False
    assert tool_context.state[UPX_DEGRADED_KEY] is True
    assert executor.reads == []


@pytest.mark.parametrize(
    ("upx_result", "error_code"),
    [
        (TimeoutError("sandbox timed out"), "sandbox_unavailable"),
        (ExecutionResult(exit_code=2, stdout="", stderr="corrupt packed input"), "upx_failed"),
    ],
)
def test_upx_timeout_and_corrupt_input_degrade_without_raising(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    upx_result: ExecutionResult | Exception,
    error_code: str,
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    executor = _FakeExecutor()
    executor.results.extend([ExecutionResult(exit_code=0, stdout="", stderr=""), upx_result])
    tool_context = _tool_context(artifact_id, upx=True)

    result = build_upx_unpack(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert result["success"] is False
    assert result["applicable"] is True
    assert result["degraded"] is True
    assert result["changed"] is False
    assert result["error_code"] == error_code
    assert result["tool_version"] == "5.2.0"
    assert tool_context.state[CURRENT_ARTIFACT_KEY] == artifact_id
    assert tool_context.state[UPX_CHANGED_KEY] is False
    assert tool_context.state[UPX_DEGRADED_KEY] is True


def test_upx_malformed_classification_clears_stale_iteration_flags() -> None:
    executor = _FakeExecutor()
    tool_context = _FakeToolContext(
        {
            CLASSIFICATION_KEY: "{",
            SessionKeys.SANDBOX_CASE_ID: "case-1",
            UPX_CHANGED_KEY: True,
            UPX_DEGRADED_KEY: False,
        }
    )

    result = build_upx_unpack(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert result["success"] is False
    assert result["applicable"] is True
    assert result["degraded"] is True
    assert result["changed"] is False
    assert result["error_code"] == "invalid_classification"
    assert tool_context.state[UPX_CHANGED_KEY] is False
    assert tool_context.state[UPX_DEGRADED_KEY] is True
    assert executor.claims == []


def test_upx_factory_callable_name_matches_descriptor() -> None:
    tool = build_upx_unpack(_build_context(_FakeExecutor()))

    assert UPX_UNPACK_TOOL.id == "upx_unpack"
    assert tool.__name__ == UPX_UNPACK_TOOL.id  # type: ignore[union-attr]


def test_upx_rejects_empty_recovery_output_without_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    executor = _FakeExecutor()
    output_path = f"/work/upx/{artifact_id}/unpacked"
    executor.files[output_path] = b""
    executor.results.extend(
        [
            ExecutionResult(exit_code=0, stdout="", stderr=""),
            ExecutionResult(exit_code=0, stdout="", stderr=""),
            ExecutionResult(exit_code=0, stdout="0\n", stderr=""),
        ]
    )
    tool_context = _tool_context(artifact_id, upx=True)

    result = build_upx_unpack(_build_context(executor))(tool_context)  # type: ignore[operator]

    _assert_result_schema(result)
    assert result["success"] is False
    assert result["degraded"] is True
    assert result["changed"] is False
    assert result["error_code"] == "output_invalid"
    assert tool_context.state[CURRENT_ARTIFACT_KEY] == artifact_id
    assert tool_context.state[UPX_CHANGED_KEY] is False
    assert tool_context.state[UPX_DEGRADED_KEY] is True
    assert hashlib.sha256(b"").hexdigest() not in {path.name for path in root.iterdir()}


def test_upx_identical_recovery_is_successful_without_progress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = b"packed"
    root, artifact_id = _store_artifact(tmp_path, original)
    _patch_artifact_roots(monkeypatch, root)
    executor = _FakeExecutor()
    output_path = f"/work/upx/{artifact_id}/unpacked"
    executor.files[output_path] = original
    executor.results.extend(
        [
            ExecutionResult(exit_code=0, stdout="", stderr=""),
            ExecutionResult(exit_code=0, stdout="", stderr=""),
            ExecutionResult(exit_code=0, stdout=f"{len(original)}\n", stderr=""),
        ]
    )
    tool_context = _tool_context(artifact_id, upx=True)

    result = build_upx_unpack(_build_context(executor))(tool_context)  # type: ignore[operator]

    _assert_result_schema(result)
    assert result["success"] is True
    assert result["applicable"] is True
    assert result["degraded"] is False
    assert result["changed"] is False
    assert result["recovered_artifact_id"] == artifact_id
    assert tool_context.state[CURRENT_ARTIFACT_KEY] == artifact_id
    assert tool_context.state[UPX_CHANGED_KEY] is False
    assert tool_context.state[UPX_DEGRADED_KEY] is False
    assert tool_context.state.get(UPX_PROVENANCE_PROMPT_KEY) is None


def test_upx_noop_preserves_existing_provenance_for_current_recovered_artifact() -> None:
    executor = _FakeExecutor()
    artifact_id = "a" * 64
    provenance = f"upx_unpack source={'b' * 64} destination={artifact_id}"
    tool_context = _tool_context(
        artifact_id,
        upx=False,
        extra={
            CURRENT_ARTIFACT_KEY: artifact_id,
            UPX_PROVENANCE_PROMPT_KEY: provenance,
        },
    )

    build_upx_unpack(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert tool_context.state[UPX_PROVENANCE_PROMPT_KEY] == provenance


def test_upx_noop_clears_provenance_for_a_different_destination() -> None:
    executor = _FakeExecutor()
    artifact_id = "a" * 64
    tool_context = _tool_context(
        artifact_id,
        upx=False,
        extra={
            UPX_PROVENANCE_PROMPT_KEY: (f"upx_unpack source={'b' * 64} destination={'c' * 64}"),
        },
    )

    build_upx_unpack(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert tool_context.state[UPX_PROVENANCE_PROMPT_KEY] == ""


def test_upx_noop_preserves_scripted_recover_provenance_for_current_artifact() -> None:
    # The provenance slot is shared: register.py writes a
    # ``scripted_recover source=<sha> destination=<sha> method=<...>`` record here.
    # A subsequent upx_unpack round must NOT wipe it when it describes the current
    # artifact, or the scripted recovery's report attribution (spec §4.6) is lost.
    executor = _FakeExecutor()
    artifact_id = "a" * 64
    provenance = f"scripted_recover source={'b' * 64} destination={artifact_id} method=rc4-static"
    tool_context = _tool_context(
        artifact_id,
        upx=False,
        extra={
            CURRENT_ARTIFACT_KEY: artifact_id,
            UPX_PROVENANCE_PROMPT_KEY: provenance,
        },
    )

    build_upx_unpack(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert tool_context.state[UPX_PROVENANCE_PROMPT_KEY] == provenance


def test_upx_noop_clears_scripted_recover_provenance_for_a_different_destination() -> None:
    executor = _FakeExecutor()
    artifact_id = "a" * 64
    tool_context = _tool_context(
        artifact_id,
        upx=False,
        extra={
            UPX_PROVENANCE_PROMPT_KEY: (
                f"scripted_recover source={'b' * 64} destination={'c' * 64} method=x"
            ),
        },
    )

    build_upx_unpack(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert tool_context.state[UPX_PROVENANCE_PROMPT_KEY] == ""


def test_upx_missing_output_is_a_safe_degraded_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import reverse_engineering.tools.deobfuscation.upx as upx

    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    executor = _FakeExecutor()
    executor.results.extend(
        [
            ExecutionResult(exit_code=0, stdout="", stderr=""),
            ExecutionResult(exit_code=0, stdout="", stderr=""),
        ]
    )
    tool_context = _tool_context(artifact_id, upx=True)

    def read_missing_output(_staged: object, _path: str, *, max_bytes: int) -> bytes:
        del max_bytes
        raise FileNotFoundError("/private/artifacts/secret-output")

    monkeypatch.setattr(
        upx,
        "read_bounded_file",
        read_missing_output,
    )

    result = build_upx_unpack(_build_context(executor))(tool_context)  # type: ignore[operator]

    _assert_result_schema(result)
    assert result["error_code"] == "output_invalid"
    assert result["error"] == "The recovered output is invalid."
    assert "secret-output" not in str(result)
    assert tool_context.state[CURRENT_ARTIFACT_KEY] == artifact_id
    assert tool_context.state[UPX_CHANGED_KEY] is False
    assert tool_context.state[UPX_DEGRADED_KEY] is True


def test_upx_admission_failure_is_a_safe_degraded_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import reverse_engineering.tools.deobfuscation.upx as upx

    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    executor = _FakeExecutor()
    output_path = f"/work/upx/{artifact_id}/unpacked"
    executor.files[output_path] = b"unpacked"
    executor.results.extend(
        [
            ExecutionResult(exit_code=0, stdout="", stderr=""),
            ExecutionResult(exit_code=0, stdout="", stderr=""),
            ExecutionResult(exit_code=0, stdout="8\n", stderr=""),
        ]
    )
    tool_context = _tool_context(artifact_id, upx=True)
    monkeypatch.setattr(
        upx.ArtifactStore,
        "acquire_bytes",
        lambda _self, _data: (_ for _ in ()).throw(OSError("/private/artifacts/admission-secret")),
    )

    result = build_upx_unpack(_build_context(executor))(tool_context)  # type: ignore[operator]

    _assert_result_schema(result)
    assert result["error_code"] == "artifact_unavailable"
    assert "admission-secret" not in str(result)
    assert tool_context.state[CURRENT_ARTIFACT_KEY] == artifact_id
    assert tool_context.state[UPX_CHANGED_KEY] is False
    assert tool_context.state[UPX_DEGRADED_KEY] is True


def test_upx_nonzero_output_never_leaks_sandbox_diagnostics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    executor = _FakeExecutor()
    executor.results.extend(
        [
            ExecutionResult(exit_code=0, stdout="", stderr=""),
            ExecutionResult(
                exit_code=2,
                stdout="backend-token=stdout-secret",
                stderr="backend-token=stderr-secret",
            ),
        ]
    )

    result = build_upx_unpack(_build_context(executor))(_tool_context(artifact_id, upx=True))  # type: ignore[operator]

    _assert_result_schema(result)
    assert result["error_code"] == "upx_failed"
    assert result["error"] == "UPX could not unpack the artifact."
    assert "secret" not in str(result)


@pytest.mark.parametrize("exception", [AttributeError("programming fault"), CancelledError()])
def test_upx_programming_errors_and_cancellation_propagate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, exception: Exception
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    executor = _FakeExecutor()
    executor.results.extend([ExecutionResult(exit_code=0, stdout="", stderr=""), exception])

    with pytest.raises(type(exception)):
        build_upx_unpack(_build_context(executor))(_tool_context(artifact_id, upx=True))  # type: ignore[operator]


def test_upx_function_tool_uses_meaningful_callable_docstring() -> None:
    function_tool = FunctionTool(build_upx_unpack(_build_context(_FakeExecutor())))
    declaration = function_tool._get_declaration()

    assert function_tool.description == UPX_UNPACK_TOOL.description
    assert declaration is not None
    assert declaration.description == UPX_UNPACK_TOOL.description
    assert declaration.description != "Call self as a function."
    assert declaration.parameters is None
    assert declaration.parameters_json_schema is None
