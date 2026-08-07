"""Contract tests for structured FLOSS string recovery."""

from __future__ import annotations

import json
from concurrent.futures import CancelledError
from typing import TYPE_CHECKING, cast

import pytest
from google.adk.tools.function_tool import FunctionTool

from arema.core.config import LLMProvider, Settings
from arema.runtime.agent_factory import ToolBuildContext
from arema.runtime.sandbox.port import ExecutionResult, SandboxHandle
from arema.runtime.services import RuntimeServices
from arema.runtime.sessions import SessionKeys
from reverse_engineering.agents.deobf_gate import evaluate_deobf_gate
from reverse_engineering.artifacts import ArtifactStore
from reverse_engineering.tools.deobfuscation.floss import (  # type: ignore[import-not-found]
    FLOSS_DECODE_TOOL,
    MAX_INPUT_BYTES,
    MAX_SEEN_FINGERPRINTS,
    _is_pe,
    build_floss_decode,
)
from reverse_engineering.tools.deobfuscation.runtime import MAX_RESULT_BYTES
from reverse_engineering.tools.deobfuscation.state import (
    CLASSIFICATION_KEY,
    CURRENT_ARTIFACT_KEY,
    FLOSS_CALLED_KEY,
    FLOSS_COUNT_KEY,
    FLOSS_DEGRADED_KEY,
    FLOSS_RESULT_KEY,
    FLOSS_SEEN_FINGERPRINTS_KEY,
    RETRIAGE_SNAPSHOT_KEY,
    UPX_CALLED_KEY,
    UPX_CHANGED_KEY,
    UPX_DEGRADED_KEY,
)
from reverse_engineering.tools.deobfuscation.toolset import (  # type: ignore[import-not-found]
    DEOBFUSCATION_TOOL_NAMES,
    DEOBFUSCATION_TOOLSET,
)

if TYPE_CHECKING:
    from pathlib import Path

    from arema.registry.catalog import CapabilityCatalog


FLOSS_RESULT = {
    "metadata": {"file_path": "/work/input", "version": "3.1.1", "imagebase": 4194304},
    "analysis": {},
    "strings": {
        "decoded_strings": [
            {
                "address": 6295552,
                "address_type": "GLOBAL",
                "string": "https://c2.example",
                "encoding": "ASCII",
                "decoded_at": 4198964,
                "decoding_routine": 4198400,
            }
        ],
        "stack_strings": [
            {
                "function": 4199000,
                "string": "cmd.exe /c whoami",
                "encoding": "ASCII",
                "program_counter": 4199050,
                "stack_pointer": 1048576,
                "original_stack_pointer": 1048704,
                "offset": 16,
                "frame_offset": 112,
            }
        ],
        "tight_strings": [],
        "static_strings": [],
        "language_strings": [],
        "language_strings_missed": [],
    },
}


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


def _classification(artifact_id: str, *, floss: bool) -> str:
    return json.dumps(
        {
            "artifact_id": artifact_id,
            "deobf_plan": {"upx": False, "floss": floss},
            "pcode_preferred": False,
            "obf_class": "none",
            "pre_snapshot": {
                "size": 0,
                "function_count": 0,
                "import_count": 0,
                "string_count": 0,
                "section_count": 0,
            },
        }
    )


def _pe_bytes() -> bytes:
    payload = bytearray(0x84)
    payload[:2] = b"MZ"
    payload[0x3C:0x40] = (0x80).to_bytes(4, "little")
    payload[0x80:0x84] = b"PE\0\0"
    return bytes(payload)


def _store_artifact(tmp_path: Path, data: bytes | None = None) -> tuple[Path, str]:
    root = tmp_path / "artifacts"
    source = tmp_path / "sample.exe"
    source.write_bytes(_pe_bytes() if data is None else data)
    return root, ArtifactStore(root).acquire(source)


def _tool_context(
    artifact_id: str, *, floss: bool, extra: dict[str, object] | None = None
) -> _FakeToolContext:
    values: dict[str, object] = {
        CLASSIFICATION_KEY: _classification(artifact_id, floss=floss),
        CURRENT_ARTIFACT_KEY: artifact_id,
        SessionKeys.SANDBOX_CASE_ID: "case-1",
    }
    if extra:
        values.update(extra)
    return _FakeToolContext(values)


def test_floss_duplicate_call_rehydrates_gate_facts_from_cached_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, artifact_id = _store_artifact(tmp_path, b"not a PE")
    _patch_artifact_roots(monkeypatch, root)
    executor = _FakeExecutor()
    tool_context = _tool_context(artifact_id, floss=False)
    tool = build_floss_decode(_build_context(executor))

    first = tool(tool_context)  # type: ignore[operator]
    tool_context.state[FLOSS_COUNT_KEY] = 9
    tool_context.state[FLOSS_DEGRADED_KEY] = True
    second = tool(tool_context)  # type: ignore[operator]

    assert first == second
    assert first is not second
    assert first["reason"] == "not_pe"
    assert tool_context.state[FLOSS_CALLED_KEY] is True
    assert tool_context.state[FLOSS_RESULT_KEY] == first
    assert tool_context.state[FLOSS_COUNT_KEY] == 0
    assert tool_context.state[FLOSS_DEGRADED_KEY] is False
    assert executor.claims == []


@pytest.mark.parametrize(
    ("cached", "expected_count", "expected_degraded"),
    [
        (
            {
                "success": False,
                "applicable": True,
                "degraded": True,
                "error_code": "sandbox_unavailable",
                "error": "The deobfuscation sandbox is unavailable.",
                "source_artifact_id": "a" * 64,
                "source_size": 6,
                "format": "pe",
                "tool_version": "3.1.1",
                "new_count": 0,
                "counts": {"decoded": 0, "stack": 0, "tight": 0},
                "records": [],
                "truncated": False,
            },
            0,
            True,
        ),
        (
            {
                "success": True,
                "applicable": False,
                "degraded": False,
                "reason": "not_pe",
                "source_artifact_id": "a" * 64,
                "source_size": 6,
                "format": "unsupported",
                "tool_version": "3.1.1",
                "new_count": 0,
                "counts": {"decoded": 0, "stack": 0, "tight": 0},
                "records": [],
                "truncated": False,
            },
            0,
            False,
        ),
        (
            {
                "success": True,
                "applicable": False,
                "degraded": False,
                "reason": "plan_disabled",
                "source_artifact_id": "a" * 64,
                "format": "unknown",
                "tool_version": "3.1.1",
                "new_count": 0,
                "counts": {"decoded": 0, "stack": 0, "tight": 0},
                "records": [],
                "truncated": False,
            },
            0,
            False,
        ),
        (
            {
                "success": True,
                "applicable": False,
                "degraded": False,
                "reason": "input_too_large",
                "source_artifact_id": "a" * 64,
                "source_size": 16 * 1024 * 1024 + 1,
                "format": "unknown",
                "tool_version": "3.1.1",
                "new_count": 0,
                "counts": {"decoded": 0, "stack": 0, "tight": 0},
                "records": [],
                "truncated": False,
            },
            0,
            False,
        ),
        (
            {
                "success": True,
                "applicable": False,
                "degraded": False,
                "reason": "input_too_large",
                "source_artifact_id": "a" * 64,
                "source_size": 16 * 1024 * 1024 + 1,
                "format": "pe",
                "tool_version": "3.1.1",
                "new_count": 0,
                "counts": {"decoded": 0, "stack": 0, "tight": 0},
                "records": [],
                "truncated": False,
            },
            0,
            False,
        ),
        (
            {
                "success": True,
                "applicable": True,
                "degraded": False,
                "source_artifact_id": "a" * 64,
                "source_size": 6,
                "format": "pe",
                "tool_version": "3.1.1",
                "new_count": 1,
                "counts": {"decoded": 1, "stack": 0, "tight": 0},
                "records": [
                    {
                        "type": "decoded",
                        "string": "hello",
                        "encoding": "ASCII",
                        "function": "0x1000",
                        "location": "0x1010",
                    }
                ],
                "truncated": False,
            },
            1,
            False,
        ),
    ],
)
def test_floss_valid_cached_variants_restore_missing_or_stale_gate_facts(
    cached: dict[str, object],
    expected_count: int,
    expected_degraded: bool,
) -> None:
    executor = _FakeExecutor()
    tool_context = _tool_context(
        "a" * 64,
        floss=False,
        extra={
            FLOSS_CALLED_KEY: True,
            FLOSS_RESULT_KEY: cached,
            FLOSS_COUNT_KEY: expected_count + 7,
        },
    )

    result = build_floss_decode(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert result == cached
    assert tool_context.state[FLOSS_COUNT_KEY] == expected_count
    assert tool_context.state[FLOSS_DEGRADED_KEY] is expected_degraded
    assert executor.claims == []


@pytest.mark.parametrize(
    "cached",
    [
        {
            "success": False,
            "applicable": True,
            "degraded": True,
            "error_code": "made_up",
            "error": "arbitrary",
            "format": "unknown",
            "tool_version": "3.1.1",
            "new_count": 0,
            "counts": {"decoded": 0, "stack": 0, "tight": 0},
            "records": [],
            "truncated": False,
        },
        {
            "success": False,
            "applicable": True,
            "degraded": True,
            "error_code": "floss_failed",
            "error": "wrong message",
            "reason": "not_pe",
            "format": "pe",
            "tool_version": "3.1.1",
            "new_count": 0,
            "counts": {"decoded": 0, "stack": 0, "tight": 0},
            "records": [],
            "truncated": False,
        },
        {
            "success": True,
            "applicable": False,
            "degraded": False,
            "reason": "plan_disabled",
            "source_artifact_id": "a" * 64,
            "source_size": 6,
            "format": "unknown",
            "tool_version": "3.1.1",
            "new_count": 0,
            "counts": {"decoded": 0, "stack": 0, "tight": 0},
            "records": [],
            "truncated": False,
        },
        {
            "success": True,
            "applicable": False,
            "degraded": False,
            "reason": "not_pe",
            "source_artifact_id": "a" * 64,
            "source_size": 6,
            "format": "pe",
            "tool_version": "3.1.1",
            "new_count": 0,
            "counts": {"decoded": 0, "stack": 0, "tight": 0},
            "records": [],
            "truncated": False,
        },
        {
            "success": True,
            "applicable": True,
            "degraded": False,
            "source_artifact_id": "a" * 64,
            "source_size": 6,
            "format": "pe",
            "tool_version": "3.1.1",
            "new_count": 2,
            "counts": {"decoded": 1, "stack": 0, "tight": 0},
            "records": [
                {
                    "type": "decoded",
                    "string": "hello",
                    "encoding": "ASCII",
                    "function": "0x1000",
                    "location": "0x1010",
                }
            ],
            "truncated": False,
        },
        {
            "success": True,
            "applicable": True,
            "degraded": False,
            "source_artifact_id": "a" * 64,
            "source_size": 6,
            "format": "pe",
            "tool_version": "3.1.1",
            "new_count": 1,
            "counts": {"decoded": 2, "stack": 0, "tight": 0},
            "records": [
                {
                    "type": "decoded",
                    "string": "hello",
                    "encoding": "ASCII",
                    "function": "0x1000",
                    "location": "0x1010",
                }
            ],
            "truncated": False,
        },
        {
            "success": True,
            "applicable": True,
            "degraded": False,
            "source_artifact_id": "a" * 64,
            "source_size": 6,
            "format": "pe",
            "tool_version": "3.1.1",
            "new_count": 1,
            "counts": {"decoded": 1, "stack": 0, "tight": 0},
            "records": [
                {
                    "type": "decoded",
                    "string": "hello",
                    "encoding": "ASCII",
                    "function": "0x1000",
                    "location": "0x1010",
                    "extra": "bad",
                }
            ],
            "truncated": False,
        },
        {
            "success": False,
            "applicable": True,
            "degraded": True,
            "error_code": "floss_failed",
            "error": "FLOSS could not recover strings from the artifact.",
            "source_artifact_id": "bad",
            "format": "pe",
            "tool_version": "3.1.1",
            "new_count": 0,
            "counts": {"decoded": 0, "stack": 0, "tight": 0},
            "records": [],
            "truncated": False,
        },
        {
            "success": True,
            "applicable": False,
            "degraded": False,
            "reason": "unknown",
            "source_artifact_id": "a" * 64,
            "format": "unknown",
            "tool_version": "3.1.1",
            "new_count": 0,
            "counts": {"decoded": 0, "stack": 0, "tight": 0},
            "records": [],
            "truncated": False,
        },
        {
            "success": True,
            "applicable": True,
            "degraded": False,
            "source_artifact_id": "a" * 64,
            "source_size": 6,
            "format": "pe",
            "tool_version": "3.1.1",
            "new_count": 0,
            "counts": {"decoded": 0, "stack": 0, "tight": 0},
            "truncated": False,
        },
    ],
)
def test_floss_rejects_cache_variants_not_emitted_by_result_constructors(
    cached: dict[str, object],
) -> None:
    executor = _FakeExecutor()
    tool_context = _tool_context(
        "a" * 64,
        floss=False,
        extra={FLOSS_CALLED_KEY: True, FLOSS_RESULT_KEY: cached},
    )

    result = build_floss_decode(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert result["error_code"] == "invalid_classification"
    assert tool_context.state[FLOSS_COUNT_KEY] == 0
    assert tool_context.state[FLOSS_DEGRADED_KEY] is True
    assert executor.claims == []


def test_floss_accepts_semantically_consistent_truncated_cache() -> None:
    records = [
        {
            "type": "decoded",
            "string": f"value-{index}",
            "encoding": "ASCII",
            "function": "0x1000",
            "location": f"0x{index:x}",
        }
        for index in range(200)
    ]
    cached: dict[str, object] = {
        "success": True,
        "applicable": True,
        "degraded": False,
        "source_artifact_id": "a" * 64,
        "source_size": 6,
        "format": "pe",
        "tool_version": "3.1.1",
        "new_count": 200,
        "counts": {"decoded": 201, "stack": 0, "tight": 0},
        "records": records,
        "truncated": True,
    }
    executor = _FakeExecutor()
    tool_context = _tool_context(
        "a" * 64,
        floss=False,
        extra={FLOSS_CALLED_KEY: True, FLOSS_RESULT_KEY: cached},
    )

    result = build_floss_decode(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert result == cached
    assert tool_context.state[FLOSS_COUNT_KEY] == 200
    assert tool_context.state[FLOSS_DEGRADED_KEY] is False
    assert executor.claims == []


def test_floss_progress_counts_only_new_normalized_records_across_iterations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    executor = _ready_executor(artifact_id)
    tool_context = _tool_context(artifact_id, floss=True)
    tool = build_floss_decode(_build_context(executor))

    first = tool(tool_context)  # type: ignore[operator]
    tool_context.state[FLOSS_CALLED_KEY] = False
    executor = _ready_executor(artifact_id)
    tool = build_floss_decode(_build_context(executor))
    second = tool(tool_context)  # type: ignore[operator]

    assert first["new_count"] == 2
    assert second["new_count"] == 0
    assert tool_context.state[FLOSS_COUNT_KEY] == 0
    assert len(cast("list[str]", tool_context.state[FLOSS_SEEN_FINGERPRINTS_KEY])) == 2
    tool_context.state[UPX_CALLED_KEY] = True
    tool_context.state[UPX_CHANGED_KEY] = False
    tool_context.state[UPX_DEGRADED_KEY] = False
    tool_context.state[RETRIAGE_SNAPSHOT_KEY] = {
        "artifact_id": artifact_id,
        "size": 0,
        "function_count": 0,
        "import_count": 0,
        "string_count": 0,
        "section_count": 0,
    }
    assert evaluate_deobf_gate(tool_context.state.values).escalate is True


def test_floss_new_record_after_prior_iteration_reports_progress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    first_executor = _ready_executor(artifact_id)
    tool_context = _tool_context(artifact_id, floss=True)
    build_floss_decode(_build_context(first_executor))(tool_context)  # type: ignore[operator]
    tool_context.state[FLOSS_CALLED_KEY] = False
    changed = json.loads(json.dumps(FLOSS_RESULT))
    changed["strings"]["tight_strings"] = [
        {
            "function": 4199001,
            "string": "new-record",
            "encoding": "ASCII",
            "program_counter": 4199051,
        }
    ]

    result = build_floss_decode(_build_context(_ready_executor(artifact_id, changed)))(tool_context)  # type: ignore[operator]

    assert result["new_count"] == 1
    assert tool_context.state[FLOSS_COUNT_KEY] == 1
    tool_context.state[UPX_CALLED_KEY] = True
    tool_context.state[UPX_CHANGED_KEY] = False
    tool_context.state[UPX_DEGRADED_KEY] = False
    tool_context.state[RETRIAGE_SNAPSHOT_KEY] = {
        "artifact_id": artifact_id,
        "size": 0,
        "function_count": 0,
        "import_count": 0,
        "string_count": 0,
        "section_count": 0,
    }
    assert evaluate_deobf_gate(tool_context.state.values).escalate is False


@pytest.mark.parametrize(
    "seen",
    [
        None,
        "bad",
        [1],
        ["A" * 64],
        ["a" * 64, "a" * 64],
        [f"{index:064x}" for index in range(MAX_SEEN_FINGERPRINTS + 1)],
    ],
)
def test_floss_rejects_malformed_seen_fingerprint_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, seen: object
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    tool_context = _tool_context(
        artifact_id,
        floss=True,
        extra={FLOSS_SEEN_FINGERPRINTS_KEY: seen},
    )

    result = build_floss_decode(_build_context(_ready_executor(artifact_id)))(tool_context)  # type: ignore[operator]

    assert result["success"] is False
    assert result["degraded"] is True
    assert result["error_code"] == "invalid_seen_state"
    assert tool_context.state[FLOSS_COUNT_KEY] == 0


def test_floss_degrades_when_new_fingerprints_would_exceed_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    seen = [f"{index:064x}" for index in range(MAX_SEEN_FINGERPRINTS)]
    tool_context = _tool_context(
        artifact_id,
        floss=True,
        extra={FLOSS_SEEN_FINGERPRINTS_KEY: seen},
    )

    result = build_floss_decode(_build_context(_ready_executor(artifact_id)))(tool_context)  # type: ignore[operator]

    assert result["error_code"] == "seen_state_overflow"
    assert result["degraded"] is True
    assert tool_context.state[FLOSS_COUNT_KEY] == 0
    assert tool_context.state[FLOSS_SEEN_FINGERPRINTS_KEY] == seen


def test_floss_malformed_duplicate_marker_fails_closed_without_executing() -> None:
    executor = _FakeExecutor()
    tool_context = _tool_context("a" * 64, floss=False, extra={FLOSS_CALLED_KEY: None})

    result = build_floss_decode(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert result["success"] is False
    assert result["degraded"] is True
    assert tool_context.state[FLOSS_RESULT_KEY] == result
    assert tool_context.state[FLOSS_COUNT_KEY] == 0
    assert tool_context.state[FLOSS_DEGRADED_KEY] is True
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
                "format": "unknown",
                "tool_version": "3.1.1",
                "new_count": 0,
                "counts": {"decoded": 0, "stack": 0, "tight": 0},
                "records": [],
                "truncated": False,
            },
        ),
        (
            True,
            {
                "success": False,
                "applicable": True,
                "degraded": True,
                "format": "unknown",
                "new_count": 0,
                "counts": {"decoded": 0, "stack": 0, "tight": 0},
                "records": [],
                "truncated": False,
            },
        ),
    ],
)
def test_floss_corrupt_duplicate_cache_is_replaced_with_locked_degraded_result(
    cache_present: bool,
    cached: object,
) -> None:
    executor = _FakeExecutor()
    extra: dict[str, object] = {
        FLOSS_CALLED_KEY: True,
        FLOSS_COUNT_KEY: 9,
        FLOSS_DEGRADED_KEY: False,
    }
    if cache_present:
        extra[FLOSS_RESULT_KEY] = cached
    tool_context = _tool_context("a" * 64, floss=False, extra=extra)

    result = build_floss_decode(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert result == {
        "success": False,
        "applicable": True,
        "degraded": True,
        "error_code": "invalid_classification",
        "error": "The deobfuscation classification is invalid.",
        "format": "unknown",
        "tool_version": "3.1.1",
        "new_count": 0,
        "counts": {"decoded": 0, "stack": 0, "tight": 0},
        "records": [],
        "truncated": False,
    }
    assert tool_context.state[FLOSS_COUNT_KEY] == 0
    assert tool_context.state[FLOSS_DEGRADED_KEY] is True
    assert tool_context.state[FLOSS_RESULT_KEY] == result
    assert executor.claims == []


def test_floss_fresh_call_invalidates_old_result_before_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, artifact_id = _store_artifact(tmp_path, b"not a PE")
    _patch_artifact_roots(monkeypatch, root)
    executor = _FakeExecutor()
    tool_context = _tool_context(
        artifact_id,
        floss=False,
        extra={
            FLOSS_CALLED_KEY: False,
            FLOSS_RESULT_KEY: {"stale": True},
        },
    )

    result = build_floss_decode(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert result["reason"] == "not_pe"
    assert result["source_artifact_id"] == artifact_id
    assert "stale" not in result
    assert tool_context.state[FLOSS_RESULT_KEY] == result


def test_floss_cancellation_after_fresh_start_cannot_expose_old_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import reverse_engineering.tools.deobfuscation.floss as floss

    tool_context = _tool_context(
        "a" * 64,
        floss=True,
        extra={
            FLOSS_CALLED_KEY: False,
            FLOSS_RESULT_KEY: {"stale": True},
            FLOSS_COUNT_KEY: 9,
            FLOSS_DEGRADED_KEY: True,
        },
    )
    monkeypatch.setattr(
        floss,
        "parse_current_classification",
        lambda _state: (_ for _ in ()).throw(CancelledError()),
    )

    with pytest.raises(CancelledError):
        build_floss_decode(_build_context(_FakeExecutor()))(tool_context)  # type: ignore[operator]

    assert tool_context.state[FLOSS_RESULT_KEY] is None
    assert tool_context.state[FLOSS_COUNT_KEY] == 0
    assert tool_context.state[FLOSS_DEGRADED_KEY] is False
    assert tool_context.state[FLOSS_CALLED_KEY] is True


def _patch_artifact_roots(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    import reverse_engineering.tools.deobfuscation.floss as floss
    import reverse_engineering.tools.deobfuscation.runtime as runtime

    monkeypatch.setattr(runtime, "default_artifacts_root", lambda: root)
    monkeypatch.setattr(floss, "default_artifacts_root", lambda: root)


def _ready_executor(artifact_id: str, payload: object = FLOSS_RESULT) -> _FakeExecutor:
    executor = _FakeExecutor()
    output_path = f"/work/floss/{artifact_id}/floss.json"
    executor.files[output_path] = json.dumps(payload).encode()
    executor.results.extend(
        [
            ExecutionResult(exit_code=0, stdout="", stderr=""),
            ExecutionResult(exit_code=0, stdout="", stderr=""),
            ExecutionResult(
                exit_code=0, stdout=str(len(executor.files[output_path])) + "\n", stderr=""
            ),
        ]
    )
    return executor


def _assert_common(result: dict[str, object]) -> None:
    assert {
        "success",
        "applicable",
        "degraded",
        "format",
        "tool_version",
        "new_count",
        "counts",
        "records",
        "truncated",
    } <= result.keys()
    assert result["tool_version"] == "3.1.1"


@pytest.mark.parametrize("contents", [b"", b"MZ", b"MZ" + b"\0" * 60, b"NZ" + _pe_bytes()[2:]])
def test_is_pe_fails_closed_for_truncated_or_invalid_headers(
    tmp_path: Path, contents: bytes
) -> None:
    candidate = tmp_path / "candidate"
    candidate.write_bytes(contents)

    assert _is_pe(candidate) is False


def test_is_pe_requires_mz_little_endian_offset_and_pe_signature(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    candidate.write_bytes(_pe_bytes())

    assert _is_pe(candidate) is True
    candidate.write_bytes(b"MZ" + b"\0" * 62 + b"PE\0\0")
    assert _is_pe(candidate) is False


def test_floss_non_applicable_for_non_pe_resets_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, artifact_id = _store_artifact(tmp_path, b"not a PE")
    _patch_artifact_roots(monkeypatch, root)
    executor = _FakeExecutor()
    tool_context = _tool_context(
        artifact_id,
        floss=False,
        extra={FLOSS_COUNT_KEY: 9, FLOSS_DEGRADED_KEY: True},
    )

    result = build_floss_decode(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert result["success"] is True
    assert result["applicable"] is False
    assert result["degraded"] is False
    assert result["reason"] == "not_pe"
    assert result["source_artifact_id"] == artifact_id
    assert tool_context.state[FLOSS_COUNT_KEY] == 0
    assert tool_context.state[FLOSS_DEGRADED_KEY] is False
    assert executor.claims == []


def test_floss_runs_on_pe_even_when_the_plan_marks_floss_disabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FLOSS eligibility is deterministic (PE-only): a flaky floss=false plan
    on a real PE must still run FLOSS and recover its strings."""
    root, artifact_id = _store_artifact(tmp_path)  # default bytes are a valid PE
    _patch_artifact_roots(monkeypatch, root)
    executor = _ready_executor(artifact_id)
    tool_context = _tool_context(artifact_id, floss=False)

    result = build_floss_decode(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert result["applicable"] is True
    assert result["success"] is True
    assert result["new_count"] >= 1
    assert executor.claims  # the deterministic PE gate claimed a sandbox and ran


def test_floss_non_pe_is_successful_non_applicability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, artifact_id = _store_artifact(tmp_path, b"not a PE")
    _patch_artifact_roots(monkeypatch, root)
    executor = _FakeExecutor()

    result = build_floss_decode(_build_context(executor))(_tool_context(artifact_id, floss=True))  # type: ignore[operator]

    _assert_common(result)
    assert result["source_artifact_id"] == artifact_id
    assert result["format"] == "unsupported"
    assert result["success"] is True
    assert result["applicable"] is False
    assert result["degraded"] is False
    assert result["reason"] == "not_pe"
    assert executor.claims == []


def test_floss_pe_probe_io_failure_degrades_as_artifact_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import reverse_engineering.tools.deobfuscation.floss as floss

    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    artifact = root / artifact_id
    original_is_pe = floss._is_pe

    def remove_then_probe(path: Path) -> bool:
        artifact.unlink()
        return original_is_pe(path)

    monkeypatch.setattr(floss, "_is_pe", remove_then_probe)
    tool_context = _tool_context(artifact_id, floss=True)

    result = build_floss_decode(_build_context(_FakeExecutor()))(tool_context)  # type: ignore[operator]

    _assert_common(result)
    assert result["error_code"] == "artifact_unavailable"
    assert "not_pe" not in str(result)
    assert tool_context.state[FLOSS_COUNT_KEY] == 0
    assert tool_context.state[FLOSS_DEGRADED_KEY] is True


def test_floss_input_over_16_mib_is_not_staged_or_read_fully(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    artifact = root / artifact_id
    with artifact.open("r+b") as stream:
        stream.truncate(MAX_INPUT_BYTES + 1)
    _patch_artifact_roots(monkeypatch, root)
    executor = _FakeExecutor()

    result = build_floss_decode(_build_context(executor))(_tool_context(artifact_id, floss=True))  # type: ignore[operator]

    _assert_common(result)
    assert result["reason"] == "input_too_large"
    assert result["applicable"] is False
    assert executor.claims == []
    assert executor.writes == []


def test_floss_rechecks_input_cap_when_artifact_grows_after_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import reverse_engineering.tools.deobfuscation.floss as floss
    import reverse_engineering.tools.deobfuscation.runtime as runtime

    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    artifact = root / artifact_id
    executor = _ready_executor(artifact_id)

    def grow_then_stage(
        context: ToolBuildContext,
        staged_artifact_id: str,
        tool_context: _FakeToolContext,
        *,
        tool_name: str,
        max_input_bytes: int | None = None,
    ) -> object:
        artifact.write_bytes(_pe_bytes() + b"x" * MAX_INPUT_BYTES)
        if max_input_bytes is None:
            return runtime.stage_artifact(
                context, staged_artifact_id, tool_context, tool_name=tool_name
            )
        return runtime.stage_artifact(
            context,
            staged_artifact_id,
            tool_context,
            tool_name=tool_name,
            max_input_bytes=max_input_bytes,
        )

    monkeypatch.setattr(floss, "stage_artifact", grow_then_stage)
    tool_context = _tool_context(artifact_id, floss=True)

    result = build_floss_decode(_build_context(executor))(tool_context)  # type: ignore[operator]

    _assert_common(result)
    assert result["success"] is True
    assert result["applicable"] is False
    assert result["reason"] == "input_too_large"
    assert tool_context.state[FLOSS_COUNT_KEY] == 0
    assert tool_context.state[FLOSS_DEGRADED_KEY] is False
    assert executor.claims == []
    assert executor.writes == []


def test_floss_rejects_stale_classification_after_canonical_artifact_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, classified_id = _store_artifact(tmp_path)
    _, current_id = _store_artifact(tmp_path, _pe_bytes() + b"current")
    _patch_artifact_roots(monkeypatch, root)
    executor = _ready_executor(current_id)

    result = build_floss_decode(_build_context(executor))(
        _tool_context(classified_id, floss=True, extra={CURRENT_ARTIFACT_KEY: current_id})
    )  # type: ignore[operator]

    _assert_common(result)
    assert result["success"] is False
    assert result["error_code"] == "invalid_classification"
    assert executor.claims == []


def test_floss_rejects_classification_when_current_artifact_is_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    executor = _ready_executor(artifact_id)

    tool_context = _tool_context(artifact_id, floss=True)
    del tool_context.state.values[CURRENT_ARTIFACT_KEY]
    result = build_floss_decode(_build_context(executor))(tool_context)  # type: ignore[operator]

    _assert_common(result)
    assert result["success"] is False
    assert result["error_code"] == "invalid_classification"
    assert executor.claims == []


@pytest.mark.parametrize("current", [None, "", "../secret", "A" * 64, "a" * 63, 1])
def test_floss_rejects_present_malformed_current_artifact_without_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, current: object
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    executor = _ready_executor(artifact_id)
    tool_context = _tool_context(artifact_id, floss=True, extra={CURRENT_ARTIFACT_KEY: current})

    result = build_floss_decode(_build_context(executor))(tool_context)  # type: ignore[operator]

    _assert_common(result)
    assert result["error_code"] == "invalid_classification"
    assert tool_context.state[FLOSS_COUNT_KEY] == 0
    assert tool_context.state[FLOSS_DEGRADED_KEY] is True
    assert executor.claims == []


def test_floss_runs_fixed_json_argv_and_normalizes_all_string_kinds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    result_data = json.loads(json.dumps(FLOSS_RESULT))
    result_data["strings"]["tight_strings"] = [
        {"function": 4198400, "string": "tight", "encoding": "UTF-8", "program_counter": 4198416}
    ]
    _patch_artifact_roots(monkeypatch, root)
    executor = _ready_executor(artifact_id, result_data)

    result = build_floss_decode(_build_context(executor))(_tool_context(artifact_id, floss=True))  # type: ignore[operator]

    _assert_common(result)
    assert set(result) == {
        "success",
        "applicable",
        "degraded",
        "source_artifact_id",
        "source_size",
        "format",
        "tool_version",
        "new_count",
        "counts",
        "records",
        "truncated",
    }
    assert result["source_artifact_id"] == artifact_id
    assert result["format"] == "pe"
    assert result["success"] is True
    assert result["new_count"] == 3
    assert result["counts"] == {"decoded": 1, "stack": 1, "tight": 1}
    assert result["records"] == [
        {
            "type": "decoded",
            "string": "https://c2.example",
            "encoding": "ASCII",
            "function": "0x401000",
            "location": "0x401234",
        },
        {
            "type": "stack",
            "string": "cmd.exe /c whoami",
            "encoding": "ASCII",
            "function": "0x401258",
            "location": "0x40128a",
        },
        {
            "type": "tight",
            "string": "tight",
            "encoding": "UTF-8",
            "function": "0x401000",
            "location": "0x401010",
        },
    ]
    assert executor.runs[1][1] == (
        f"floss --json --only decoded stack tight -- /work/floss/{artifact_id}/input "
        f"> /work/floss/{artifact_id}/floss.json"
    )


def test_floss_valid_sandbox_result_is_cached_without_second_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    executor = _ready_executor(artifact_id)
    tool_context = _tool_context(artifact_id, floss=True)
    tool = build_floss_decode(_build_context(executor))

    first = tool(tool_context)  # type: ignore[operator]
    run_count = len(executor.runs)
    second = tool(tool_context)  # type: ignore[operator]

    assert second == first
    assert second is not first
    assert len(executor.runs) == run_count


def test_floss_preserves_totals_but_caps_records_at_200(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    result_data = json.loads(json.dumps(FLOSS_RESULT))
    result_data["strings"]["decoded_strings"] = [
        {
            "address": index,
            "address_type": "GLOBAL",
            "string": str(index),
            "encoding": "ASCII",
            "decoding_routine": index,
            "decoded_at": index + 1,
        }
        for index in range(201)
    ]
    result_data["strings"]["stack_strings"] = [
        {
            "string": "stack",
            "encoding": "ASCII",
            "function": 2,
            "program_counter": 3,
            "stack_pointer": 4,
            "original_stack_pointer": 5,
            "offset": 6,
            "frame_offset": 7,
        }
    ]
    _patch_artifact_roots(monkeypatch, root)
    executor = _ready_executor(artifact_id, result_data)

    result = build_floss_decode(_build_context(executor))(_tool_context(artifact_id, floss=True))  # type: ignore[operator]

    _assert_common(result)
    assert result["new_count"] == 200
    assert result["counts"] == {"decoded": 201, "stack": 1, "tight": 0}
    assert len(cast("list[object]", result["records"])) == 200
    assert result["truncated"] is True
    assert cast("list[dict[str, str]]", result["records"])[-1]["type"] == "decoded"


def test_floss_constructs_public_records_only_up_to_the_output_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import reverse_engineering.tools.deobfuscation.floss as floss

    root, artifact_id = _store_artifact(tmp_path)
    result_data = json.loads(json.dumps(FLOSS_RESULT))
    result_data["strings"]["decoded_strings"] = [
        {
            "address": index,
            "address_type": "GLOBAL",
            "string": str(index),
            "encoding": "ASCII",
            "decoding_routine": index,
            "decoded_at": index + 1,
        }
        for index in range(201)
    ]
    result_data["strings"]["stack_strings"] = []
    constructed: list[dict[str, str]] = []

    def record_public_construction(
        kind: str, text: str, encoding: str, function: int, location: int
    ) -> dict[str, str]:
        record = {
            "type": kind,
            "string": text,
            "encoding": encoding,
            "function": f"0x{function:x}",
            "location": f"0x{location:x}",
        }
        constructed.append(record)
        return record

    monkeypatch.setattr(floss, "_public_record", record_public_construction, raising=False)
    _patch_artifact_roots(monkeypatch, root)
    executor = _ready_executor(artifact_id, result_data)

    result = build_floss_decode(_build_context(executor))(_tool_context(artifact_id, floss=True))  # type: ignore[operator]

    _assert_common(result)
    assert result["new_count"] == 200
    assert result["counts"] == {"decoded": 201, "stack": 0, "tight": 0}
    assert len(cast("list[object]", result["records"])) == 200
    assert result["truncated"] is True
    assert len(constructed) == 200


def test_floss_validates_records_beyond_the_output_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    result_data = json.loads(json.dumps(FLOSS_RESULT))
    result_data["strings"]["decoded_strings"] = [
        {
            "address": index,
            "address_type": "GLOBAL",
            "string": str(index),
            "encoding": "ASCII",
            "decoding_routine": index,
            "decoded_at": index + 1,
        }
        for index in range(201)
    ]
    result_data["strings"]["decoded_strings"][-1]["string"] = ""
    result_data["strings"]["stack_strings"] = []
    _patch_artifact_roots(monkeypatch, root)
    executor = _ready_executor(artifact_id, result_data)
    tool_context = _tool_context(artifact_id, floss=True, extra={FLOSS_COUNT_KEY: 9})

    result = build_floss_decode(_build_context(executor))(tool_context)  # type: ignore[operator]

    _assert_common(result)
    assert result["error_code"] == "result_invalid"
    assert tool_context.state[FLOSS_COUNT_KEY] == 0
    assert tool_context.state[FLOSS_DEGRADED_KEY] is True


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {
            "metadata": {"file_path": "/work/input", "version": 3, "imagebase": 4194304},
            "analysis": {},
            "strings": {"decoded_strings": [], "stack_strings": [], "tight_strings": []},
        },
        {
            "metadata": {},
            "analysis": {},
            "strings": {"decoded_strings": "bad", "stack_strings": [], "tight_strings": []},
        },
        {
            "metadata": {},
            "analysis": {},
            "strings": {
                "decoded_strings": [
                    {"string": 1, "encoding": "ASCII", "decoded_at": 2, "decoding_routine": 3}
                ],
                "stack_strings": [],
                "tight_strings": [],
            },
        },
    ],
)
def test_floss_rejects_invalid_json_schema_as_degraded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, payload: object
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    executor = _ready_executor(artifact_id, payload)

    result = build_floss_decode(_build_context(executor))(_tool_context(artifact_id, floss=True))  # type: ignore[operator]

    _assert_common(result)
    assert result["error_code"] == "result_invalid"
    assert result["records"] == []
    assert result["degraded"] is True


@pytest.mark.parametrize(
    ("target", "value"),
    [
        ("string", ""),
        ("string", "   "),
        ("encoding", ""),
        ("address", -1),
        ("address", 2**64),
        ("address", True),
        ("file_path", ""),
        ("imagebase", -1),
        ("imagebase", 2**64),
        ("imagebase", True),
        ("version", "3.1.2"),
        ("missing_version", None),
    ],
)
def test_floss_rejects_semantically_invalid_result_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str, value: object
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    result_data = json.loads(json.dumps(FLOSS_RESULT))
    if target == "missing_version":
        del result_data["metadata"]["version"]
    elif target in {"file_path", "imagebase", "version"}:
        result_data["metadata"][target] = value
    else:
        result_data["strings"]["decoded_strings"][0][target] = value
    _patch_artifact_roots(monkeypatch, root)
    executor = _ready_executor(artifact_id, result_data)
    tool_context = _tool_context(artifact_id, floss=True, extra={FLOSS_COUNT_KEY: 9})

    result = build_floss_decode(_build_context(executor))(tool_context)  # type: ignore[operator]

    _assert_common(result)
    assert result["error_code"] == "result_invalid"
    assert tool_context.state[FLOSS_COUNT_KEY] == 0
    assert tool_context.state[FLOSS_DEGRADED_KEY] is True


@pytest.mark.parametrize("kind", ["stack", "tight"])
def test_floss_accepts_signed_frame_offset_for_stack_and_tight_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    result_data = json.loads(json.dumps(FLOSS_RESULT))
    if kind == "stack":
        result_data["strings"]["stack_strings"][0]["frame_offset"] = -4
    else:
        result_data["strings"]["tight_strings"] = [
            {
                "function": 4198400,
                "string": "tight",
                "encoding": "ASCII",
                "program_counter": 4198416,
                "frame_offset": -4,
            }
        ]
    _patch_artifact_roots(monkeypatch, root)
    executor = _ready_executor(artifact_id, result_data)

    result = build_floss_decode(_build_context(executor))(_tool_context(artifact_id, floss=True))  # type: ignore[operator]

    _assert_common(result)
    assert result["success"] is True
    assert result["new_count"] == (2 if kind == "stack" else 3)


@pytest.mark.parametrize("kind", ["stack", "tight"])
@pytest.mark.parametrize("frame_offset", [-(2**63) - 1, 2**63, True])
def test_floss_rejects_invalid_signed_frame_offset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, frame_offset: object
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    result_data = json.loads(json.dumps(FLOSS_RESULT))
    if kind == "stack":
        result_data["strings"]["stack_strings"][0]["frame_offset"] = frame_offset
    else:
        result_data["strings"]["tight_strings"] = [
            {
                "function": 4198400,
                "string": "tight",
                "encoding": "ASCII",
                "program_counter": 4198416,
                "frame_offset": frame_offset,
            }
        ]
    _patch_artifact_roots(monkeypatch, root)
    executor = _ready_executor(artifact_id, result_data)
    tool_context = _tool_context(artifact_id, floss=True, extra={FLOSS_COUNT_KEY: 9})

    result = build_floss_decode(_build_context(executor))(tool_context)  # type: ignore[operator]

    _assert_common(result)
    assert result["error_code"] == "result_invalid"
    assert tool_context.state[FLOSS_COUNT_KEY] == 0
    assert tool_context.state[FLOSS_DEGRADED_KEY] is True


@pytest.mark.parametrize("address_type", ["", "OTHER"])
def test_floss_rejects_unknown_decoded_address_type(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, address_type: str
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    result_data = json.loads(json.dumps(FLOSS_RESULT))
    result_data["strings"]["decoded_strings"][0]["address_type"] = address_type
    _patch_artifact_roots(monkeypatch, root)
    executor = _ready_executor(artifact_id, result_data)
    tool_context = _tool_context(artifact_id, floss=True, extra={FLOSS_COUNT_KEY: 9})

    result = build_floss_decode(_build_context(executor))(tool_context)  # type: ignore[operator]

    _assert_common(result)
    assert result["error_code"] == "result_invalid"
    assert tool_context.state[FLOSS_COUNT_KEY] == 0
    assert tool_context.state[FLOSS_DEGRADED_KEY] is True


@pytest.mark.parametrize("address_type", ["STACK", "GLOBAL", "HEAP"])
def test_floss_accepts_allowed_decoded_address_types(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, address_type: str
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    result_data = json.loads(json.dumps(FLOSS_RESULT))
    result_data["strings"]["decoded_strings"][0]["address_type"] = address_type
    _patch_artifact_roots(monkeypatch, root)
    executor = _ready_executor(artifact_id, result_data)

    result = build_floss_decode(_build_context(executor))(_tool_context(artifact_id, floss=True))  # type: ignore[operator]

    _assert_common(result)
    assert result["success"] is True
    assert result["new_count"] == 2


def test_floss_accepts_valid_empty_string_groups(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    result_data = json.loads(json.dumps(FLOSS_RESULT))
    result_data["strings"]["decoded_strings"] = []
    result_data["strings"]["stack_strings"] = []
    result_data["strings"]["tight_strings"] = []
    _patch_artifact_roots(monkeypatch, root)
    executor = _ready_executor(artifact_id, result_data)

    result = build_floss_decode(_build_context(executor))(_tool_context(artifact_id, floss=True))  # type: ignore[operator]

    _assert_common(result)
    assert result["success"] is True
    assert result["new_count"] == 0
    assert result["counts"] == {"decoded": 0, "stack": 0, "tight": 0}


@pytest.mark.parametrize("constant", [float("nan"), float("inf"), float("-inf")])
def test_floss_rejects_nonstandard_json_constants(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, constant: float
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    result_data = json.loads(json.dumps(FLOSS_RESULT))
    result_data["analysis"] = {"untrusted": constant}
    executor = _ready_executor(artifact_id, result_data)
    tool_context = _tool_context(
        artifact_id,
        floss=True,
        extra={FLOSS_COUNT_KEY: 9, FLOSS_DEGRADED_KEY: False},
    )

    result = build_floss_decode(_build_context(executor))(tool_context)  # type: ignore[operator]

    _assert_common(result)
    assert result["error_code"] == "result_invalid"
    assert result["records"] == []
    assert tool_context.state[FLOSS_COUNT_KEY] == 0
    assert tool_context.state[FLOSS_DEGRADED_KEY] is True


def test_floss_rejects_oversize_result_before_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    executor = _FakeExecutor()
    executor.results.extend(
        [
            ExecutionResult(exit_code=0, stdout="", stderr=""),
            ExecutionResult(exit_code=0, stdout="", stderr=""),
            ExecutionResult(exit_code=0, stdout=f"{MAX_RESULT_BYTES + 1}\n", stderr=""),
        ]
    )

    result = build_floss_decode(_build_context(executor))(_tool_context(artifact_id, floss=True))  # type: ignore[operator]

    _assert_common(result)
    assert result["error_code"] == "result_invalid"
    assert executor.reads == []


@pytest.mark.parametrize(
    "command_result",
    [
        ExecutionResult(exit_code=1, stdout="backend-secret", stderr="floss-secret"),
        ExecutionResult(exit_code=0, stdout="", stderr="", truncated=True),
        TimeoutError("backend timeout secret"),
    ],
)
def test_floss_command_failures_degrade_without_leaking_diagnostics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command_result: ExecutionResult | Exception
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    executor = _FakeExecutor()
    executor.results.extend([ExecutionResult(exit_code=0, stdout="", stderr=""), command_result])
    tool_context = _tool_context(artifact_id, floss=True)

    result = build_floss_decode(_build_context(executor))(tool_context)  # type: ignore[operator]

    _assert_common(result)
    assert result["error_code"] in {"floss_failed", "sandbox_unavailable"}
    assert "secret" not in str(result)
    assert tool_context.state[FLOSS_COUNT_KEY] == 0
    assert tool_context.state[FLOSS_DEGRADED_KEY] is True


def test_floss_missing_output_and_invalid_classification_degrade_stably(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import reverse_engineering.tools.deobfuscation.floss as floss

    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    executor = _FakeExecutor()
    executor.results.extend(
        [
            ExecutionResult(exit_code=0, stdout="", stderr=""),
            ExecutionResult(exit_code=0, stdout="", stderr=""),
        ]
    )
    monkeypatch.setattr(
        floss,
        "read_bounded_file",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(FileNotFoundError("/private/secret")),
    )

    result = build_floss_decode(_build_context(executor))(_tool_context(artifact_id, floss=True))  # type: ignore[operator]
    malformed = _FakeToolContext(
        {CLASSIFICATION_KEY: "{", FLOSS_COUNT_KEY: 4, FLOSS_DEGRADED_KEY: False}
    )
    invalid = build_floss_decode(_build_context(_FakeExecutor()))(malformed)  # type: ignore[operator]

    assert result["error_code"] == "result_invalid"
    assert "secret" not in str(result)
    assert invalid["error_code"] == "invalid_classification"
    assert malformed.state[FLOSS_COUNT_KEY] == 0
    assert malformed.state[FLOSS_DEGRADED_KEY] is True


@pytest.mark.parametrize("exception", [AttributeError("programming fault"), CancelledError()])
def test_floss_programming_errors_and_cancellation_propagate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, exception: Exception
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    executor = _FakeExecutor()
    executor.results.extend([ExecutionResult(exit_code=0, stdout="", stderr=""), exception])

    with pytest.raises(type(exception)):
        build_floss_decode(_build_context(executor))(_tool_context(artifact_id, floss=True))  # type: ignore[operator]


@pytest.mark.parametrize("operation", ["stage_artifact", "run_argv_to_file"])
def test_floss_propagates_programming_value_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    import reverse_engineering.tools.deobfuscation.floss as floss

    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    executor = _ready_executor(artifact_id)
    tool_context = _tool_context(artifact_id, floss=True)

    def raise_value_error(*_args: object, **_kwargs: object) -> object:
        raise ValueError(f"{operation} validation")

    monkeypatch.setattr(floss, operation, raise_value_error)

    with pytest.raises(ValueError, match=f"{operation} validation"):
        build_floss_decode(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert tool_context.state[FLOSS_COUNT_KEY] == 0
    assert tool_context.state[FLOSS_DEGRADED_KEY] is False
    if operation == "stage_artifact":
        assert executor.claims == []


def test_floss_descriptor_callable_and_curated_toolset() -> None:
    tool = build_floss_decode(_build_context(_FakeExecutor()))
    function_tool = FunctionTool(tool)
    declaration = function_tool._get_declaration()

    assert FLOSS_DECODE_TOOL.id == "floss_decode"
    assert (
        FLOSS_DECODE_TOOL.description
        == "Recover PE decoded, stack, and tight strings with Mandiant FLOSS."
    )
    assert FLOSS_DECODE_TOOL.output_policy.max_chars == 50_000
    assert FLOSS_DECODE_TOOL.output_policy.max_list_items == 200
    assert tool.__name__ == "floss_decode"  # type: ignore[union-attr]
    assert declaration is not None
    assert declaration.description == FLOSS_DECODE_TOOL.description
    assert declaration.parameters is None
    assert declaration.parameters_json_schema is None
    assert tuple(tool.id for tool in DEOBFUSCATION_TOOLSET) == (
        "upx_unpack",
        "floss_decode",
        "de4dot_deobfuscate",
        "dnlib_roundtrip",
    )
    assert (
        frozenset({"upx_unpack", "floss_decode", "de4dot_deobfuscate", "dnlib_roundtrip"})
        == DEOBFUSCATION_TOOL_NAMES
    )
