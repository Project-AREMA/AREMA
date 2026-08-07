"""Contract tests for the sandboxed androguard Android-triage scan tool."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, cast

from arema.core.config import LLMProvider, Settings
from arema.runtime.agent_factory import ToolBuildContext
from arema.runtime.sandbox.port import ExecutionResult, SandboxHandle
from arema.runtime.services import RuntimeServices
from arema.runtime.sessions import SessionKeys
from reverse_engineering.artifacts import ArtifactStore
from reverse_engineering.tools.acquire_sample import SAMPLE_FORMAT_KEY
from reverse_engineering.tools.android.triage_scan import (
    ANDROID_TRIAGE_SCAN_TOOL,
    build_android_triage_scan,
)

if TYPE_CHECKING:
    from pathlib import Path

    import pytest

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


def _store_artifact(tmp_path: Path, data: bytes = b"PK\x03\x04-fake-apk") -> tuple[Path, str]:
    root = tmp_path / "artifacts"
    source = tmp_path / "sample.bin"
    source.write_bytes(data)
    return root, ArtifactStore(root).acquire(source)


def _tool_context(*, sample_format: str) -> _FakeToolContext:
    return _FakeToolContext(
        {
            SAMPLE_FORMAT_KEY: sample_format,
            SessionKeys.SANDBOX_CASE_ID: "case-1",
        }
    )


def _patch_artifact_root(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    import reverse_engineering.tools.deobfuscation.runtime as runtime

    monkeypatch.setattr(runtime, "default_artifacts_root", lambda: root)


_REPORT = {
    "success": True,
    "package": "com.x",
    "permissions": {
        "requested": ["android.permission.SEND_SMS"],
        "dangerous": ["android.permission.SEND_SMS"],
    },
    "components": {
        "activities": [],
        "services": [],
        "receivers": ["com.x.Boot"],
        "providers": [],
        "exported": ["com.x.Boot"],
    },
    "flags": {"debuggable": False, "uses_cleartext_traffic": False},
    "sdk": {"min": 21, "target": 33},
    "certificate": {"sha256": None, "subject": None},
    "dex": {"count": 1, "classes": 10, "methods": 40},
    "native_libs": ["lib/arm64-v8a/libjiagu.so"],
    "url_candidates": [],
    "packer": {"detected": True, "name": "jiagu", "signals": ["libjiagu.so"]},
}


def test_scan_returns_structured_report_for_apk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_root(monkeypatch, root)
    executor = _FakeExecutor()
    executor.results.extend(
        [
            ExecutionResult(exit_code=0, stdout="", stderr=""),  # stage_artifact work-dir setup
            ExecutionResult(exit_code=0, stdout=json.dumps(_REPORT), stderr=""),
        ]
    )
    tool_context = _tool_context(sample_format="apk")

    result = build_android_triage_scan(_build_context(executor))(artifact_id, tool_context)  # type: ignore[operator]

    assert result == {"success": True, "report": _REPORT}
    input_path = f"/work/android_triage_scan/{artifact_id}/input"
    assert executor.runs[1][1] == f"python /opt/androguard_triage.py {input_path}"


def test_scan_reports_failure_on_nonzero_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The script's documented in-band failure: it runs to completion, prints its
    # own {"success": false, ...} error object, and exits non-zero. The tool must
    # surface a failure keyed on the exit code and MUST NOT parse the error JSON
    # and mislabel it as a successful triage.
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_root(monkeypatch, root)
    executor = _FakeExecutor()
    executor.results.extend(
        [
            ExecutionResult(exit_code=0, stdout="", stderr=""),  # stage_artifact work-dir setup
            ExecutionResult(
                exit_code=1,
                stdout=json.dumps({"success": False, "error": "unparseable"}),
                stderr="APKError: bad zip",
            ),
        ]
    )
    tool_context = _tool_context(sample_format="apk")

    result = build_android_triage_scan(_build_context(executor))(artifact_id, tool_context)  # type: ignore[operator]

    assert result == {"success": False, "error": "androguard triage exited 1"}
    assert "report" not in result


def test_scan_keeps_valid_report_despite_stderr_truncation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # androguard logs freely to stderr; a noisy sample can trip result.truncated
    # (stdout_truncated OR stderr_truncated) while still emitting a valid report
    # on stdout. Success is gated on the stdout payload alone, so the report is
    # preserved -- stderr overflow must never discard it.
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_root(monkeypatch, root)
    executor = _FakeExecutor()
    executor.results.extend(
        [
            ExecutionResult(exit_code=0, stdout="", stderr=""),  # stage_artifact work-dir setup
            ExecutionResult(
                exit_code=0,
                stdout=json.dumps(_REPORT),
                stderr="w" * 128,
                truncated=True,
            ),
        ]
    )
    tool_context = _tool_context(sample_format="apk")

    result = build_android_triage_scan(_build_context(executor))(artifact_id, tool_context)  # type: ignore[operator]

    assert result == {"success": True, "report": _REPORT}


def test_scan_fails_open_on_garbled_stdout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A truncated / non-JSON stdout is still caught -- via the parse, not a volume
    # flag: json.loads raises and the tool degrades fail-open.
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_root(monkeypatch, root)
    executor = _FakeExecutor()
    executor.results.extend(
        [
            ExecutionResult(exit_code=0, stdout="", stderr=""),  # stage_artifact work-dir setup
            ExecutionResult(
                exit_code=0, stdout='{"success": true, "package', stderr="", truncated=True
            ),
        ]
    )
    tool_context = _tool_context(sample_format="apk")

    result = build_android_triage_scan(_build_context(executor))(artifact_id, tool_context)  # type: ignore[operator]

    assert result["success"] is False
    assert "report" not in result


def test_scan_skips_a_native_sample() -> None:
    executor = _FakeExecutor()
    artifact_id = "a" * 64
    tool_context = _tool_context(sample_format="pe")

    result = build_android_triage_scan(_build_context(executor))(artifact_id, tool_context)  # type: ignore[operator]

    assert result["success"] is False
    assert result["skipped"] is True
    assert "pe" in cast("str", result["error"])
    assert executor.claims == []
    assert executor.runs == []


def test_scan_fails_open_on_pod_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_root(monkeypatch, root)
    executor = _FakeExecutor()
    executor.results.extend(
        [
            ExecutionResult(exit_code=0, stdout="", stderr=""),  # stage_artifact work-dir setup
            RuntimeError("pod is gone"),
        ]
    )
    tool_context = _tool_context(sample_format="apk")

    result = build_android_triage_scan(_build_context(executor))(artifact_id, tool_context)  # type: ignore[operator]

    assert result["success"] is False
    assert "skipped" not in result
    assert "pod is gone" in cast("str", result["error"])


def test_scan_factory_callable_name_matches_descriptor() -> None:
    tool = build_android_triage_scan(_build_context(_FakeExecutor()))

    assert ANDROID_TRIAGE_SCAN_TOOL.id == "android_triage_scan"
    assert tool.__name__ == ANDROID_TRIAGE_SCAN_TOOL.id  # type: ignore[union-attr]
