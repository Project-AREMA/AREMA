"""Contract tests for the sandboxed de4dot .NET recovery tool."""

from __future__ import annotations

import hashlib
import json
import struct
from typing import TYPE_CHECKING, cast

import pytest

from arema.core.config import LLMProvider, Settings
from arema.runtime.agent_factory import ToolBuildContext
from arema.runtime.sandbox.port import ExecutionResult, SandboxHandle
from arema.runtime.services import RuntimeServices
from arema.runtime.sessions import SessionKeys
from reverse_engineering.artifacts import ArtifactStore
from reverse_engineering.tools.acquire_sample import SAMPLE_FORMAT_KEY
from reverse_engineering.tools.deobfuscation.dotnet import (
    DE4DOT_DEOBFUSCATE_TOOL,
    _valid_cached_result,
    build_de4dot_deobfuscate,
)
from reverse_engineering.tools.deobfuscation.state import (
    CLASSIFICATION_KEY,
    CURRENT_ARTIFACT_KEY,
    CURRENT_ARTIFACT_PROMPT_KEY,
    DE4DOT_RESULT_KEY,
    UPX_PROVENANCE_PROMPT_KEY,
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


def _classification(artifact_id: str) -> str:
    return json.dumps(
        {
            "artifact_id": artifact_id,
            "deobf_plan": {"upx": False, "floss": False},
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


def _store_artifact(tmp_path: Path, data: bytes = b"protected-clr") -> tuple[Path, str]:
    root = tmp_path / "artifacts"
    source = tmp_path / "sample.bin"
    source.write_bytes(data)
    return root, ArtifactStore(root).acquire(source)


def _tool_context(
    artifact_id: str, *, sample_format: str, extra: dict[str, object] | None = None
) -> _FakeToolContext:
    values: dict[str, object] = {
        CLASSIFICATION_KEY: _classification(artifact_id),
        CURRENT_ARTIFACT_KEY: artifact_id,
        SAMPLE_FORMAT_KEY: sample_format,
        SessionKeys.SANDBOX_CASE_ID: "case-1",
    }
    if extra:
        values.update(extra)
    return _FakeToolContext(values)


def _patch_artifact_roots(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    import reverse_engineering.tools.deobfuscation.dotnet as dotnet
    import reverse_engineering.tools.deobfuscation.runtime as runtime

    monkeypatch.setattr(runtime, "default_artifacts_root", lambda: root)
    monkeypatch.setattr(dotnet, "default_artifacts_root", lambda: root)


def _assert_result_schema(result: dict[str, object]) -> None:
    assert {"success", "applicable", "degraded", "changed", "tool_version"} <= result.keys()


_PE_SIGNATURE_OFFSET = 0x80


def _dotnet_bytes(*, com_rva: int = 0x2008) -> bytes:
    """Build a header-only valid .NET PE, mirroring test_acquire_sample.py's ``_pe_bytes``."""
    buffer = bytearray(0x400)
    buffer[0:2] = b"MZ"
    struct.pack_into("<I", buffer, 0x3C, _PE_SIGNATURE_OFFSET)
    buffer[_PE_SIGNATURE_OFFSET : _PE_SIGNATURE_OFFSET + 4] = b"PE\0\0"
    optional_at = _PE_SIGNATURE_OFFSET + 24
    struct.pack_into("<H", buffer, optional_at, 0x10B)  # PE32
    directories_at = optional_at + 96
    struct.pack_into("<I", buffer, directories_at - 4, 16)
    struct.pack_into("<II", buffer, directories_at + 14 * 8, com_rva, 72 if com_rva else 0)
    return bytes(buffer)


# --- (a) non-dotnet sample: not applicable, no advance, no sandbox interaction ---


def test_de4dot_skips_non_dotnet_sample_without_advance() -> None:
    executor = _FakeExecutor()
    artifact_id = "a" * 64
    tool_context = _tool_context(artifact_id, sample_format="pe")

    result = build_de4dot_deobfuscate(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert result == {
        "success": True,
        "applicable": False,
        "degraded": False,
        "changed": False,
        "reason": "not_dotnet",
        "source_artifact_id": artifact_id,
        "tool_version": _tool_version(),
    }
    assert tool_context.state[CURRENT_ARTIFACT_KEY] == artifact_id
    assert executor.claims == []
    assert executor.runs == []


# --- (b) dotnet + obfuscator detected + valid changed CLR output: applicable/changed/advance ---


def test_de4dot_recovers_and_advances_when_obfuscator_detected_and_output_differs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    executor = _FakeExecutor()
    output_path = f"/work/de4dot/{artifact_id}/deobfuscated"
    recovered_bytes = _dotnet_bytes()
    executor.files[output_path] = recovered_bytes
    executor.results.extend(
        [
            ExecutionResult(exit_code=0, stdout="", stderr=""),
            ExecutionResult(exit_code=0, stdout="Detected SmartAssembly (7.4.0.2264)\n", stderr=""),
            ExecutionResult(exit_code=0, stdout=f"{len(recovered_bytes)}\n", stderr=""),
        ]
    )
    tool_context = _tool_context(artifact_id, sample_format="dotnet")

    result = build_de4dot_deobfuscate(_build_context(executor))(tool_context)  # type: ignore[operator]

    recovered_id = hashlib.sha256(recovered_bytes).hexdigest()
    assert result["success"] is True
    assert result["applicable"] is True
    assert result["degraded"] is False
    assert result["changed"] is True
    assert result["source_artifact_id"] == artifact_id
    assert result["recovered_artifact_id"] == recovered_id
    assert result["obfuscator_name"] == "SmartAssembly"
    assert tool_context.state[CURRENT_ARTIFACT_KEY] == recovered_id
    assert tool_context.state[CURRENT_ARTIFACT_PROMPT_KEY] == recovered_id
    assert tool_context.state[UPX_PROVENANCE_PROMPT_KEY] == (
        f"de4dot_deobfuscate source={artifact_id} destination={recovered_id} "
        f"obfuscator=SmartAssembly"
    )
    updated_classification = json.loads(cast("str", tool_context.state[CLASSIFICATION_KEY]))
    assert updated_classification["artifact_id"] == recovered_id
    input_path = f"/work/de4dot/{artifact_id}/input"
    assert executor.runs[1][1] == f"de4dot {input_path} -o {output_path}"


# --- (c) dotnet + no "Detected" marker: not applicable, reason no_obfuscator, no advance ---


def test_de4dot_no_detected_marker_is_not_applicable_without_reading_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    executor = _FakeExecutor()
    executor.results.extend(
        [
            ExecutionResult(exit_code=0, stdout="", stderr=""),
            ExecutionResult(exit_code=0, stdout="Could not detect obfuscator!\n", stderr=""),
        ]
    )
    tool_context = _tool_context(artifact_id, sample_format="dotnet")

    result = build_de4dot_deobfuscate(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert result["success"] is True
    assert result["applicable"] is False
    assert result["degraded"] is False
    assert result["changed"] is False
    assert result["reason"] == "no_obfuscator"
    assert result["source_artifact_id"] == artifact_id
    assert tool_context.state[CURRENT_ARTIFACT_KEY] == artifact_id
    assert executor.reads == []


# --- (c2) dotnet + no "Detected" marker on an assembly that still carries a
# protector watermark: a distinct reason carrying the name, not "no_obfuscator" ---


def test_de4dot_silence_on_a_watermarked_assembly_names_the_protector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A protector de4dot cannot process must not read as a clean assembly.

    de4dot exits 0 and names nothing in both cases, so without this the report
    cannot tell a ConfuserEx sample it failed on from an unobfuscated one.
    """
    root, artifact_id = _store_artifact(tmp_path, data=b"protected-clr" + b"ConfusedByAttribute")
    _patch_artifact_roots(monkeypatch, root)
    executor = _FakeExecutor()
    executor.results.extend(
        [
            ExecutionResult(exit_code=0, stdout="", stderr=""),
            ExecutionResult(exit_code=0, stdout="Could not detect obfuscator!\n", stderr=""),
        ]
    )
    tool_context = _tool_context(artifact_id, sample_format="dotnet")

    result = build_de4dot_deobfuscate(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert result["success"] is True
    assert result["applicable"] is False
    assert result["degraded"] is False
    assert result["changed"] is False
    assert result["reason"] == "protector_unsupported"
    assert result["protector_name"] == "ConfuserEx"
    assert result["source_artifact_id"] == artifact_id
    assert tool_context.state[CURRENT_ARTIFACT_KEY] == artifact_id
    assert executor.reads == []
    assert _valid_cached_result(result)


def test_the_protector_is_read_from_the_artifact_de4dot_ran_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stale ingest name must not be attached to a peeled inner layer.

    The loop can strip an outer UPX layer before de4dot runs, so the packer named
    at ingest describes bytes that are no longer under analysis. The current
    artifact carries no watermark, so this stays "no_obfuscator".
    """
    root, artifact_id = _store_artifact(tmp_path)  # inner layer, unmarked
    _patch_artifact_roots(monkeypatch, root)
    executor = _FakeExecutor()
    executor.results.extend(
        [
            ExecutionResult(exit_code=0, stdout="", stderr=""),
            ExecutionResult(exit_code=0, stdout="Could not detect obfuscator!\n", stderr=""),
        ]
    )
    tool_context = _tool_context(
        artifact_id, sample_format="dotnet", extra={"sample:packer": "UPX"}
    )

    result = build_de4dot_deobfuscate(_build_context(executor))(tool_context)  # type: ignore[operator]

    assert result["reason"] == "no_obfuscator"
    assert "protector_name" not in result


# --- (d) dotnet + de4dot output that fails to parse as a valid CLR assembly: degraded ---


def test_de4dot_invalid_clr_output_degrades_without_advance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    executor = _FakeExecutor()
    output_path = f"/work/de4dot/{artifact_id}/deobfuscated"
    invalid_bytes = b"not-a-clr-assembly"
    executor.files[output_path] = invalid_bytes
    executor.results.extend(
        [
            ExecutionResult(exit_code=0, stdout="", stderr=""),
            ExecutionResult(exit_code=0, stdout="Detected ConfuserEx (1.0.0)\n", stderr=""),
            ExecutionResult(exit_code=0, stdout=f"{len(invalid_bytes)}\n", stderr=""),
        ]
    )
    tool_context = _tool_context(artifact_id, sample_format="dotnet")

    result = build_de4dot_deobfuscate(_build_context(executor))(tool_context)  # type: ignore[operator]

    _assert_result_schema(result)
    assert result["success"] is False
    assert result["applicable"] is True
    assert result["degraded"] is True
    assert result["changed"] is False
    assert result["error_code"] == "output_invalid"
    assert result["error"] == "The recovered output is not a valid .NET assembly."
    assert result["recovered_size"] == len(invalid_bytes)
    assert tool_context.state[CURRENT_ARTIFACT_KEY] == artifact_id
    assert tool_context.state.get(UPX_PROVENANCE_PROMPT_KEY) is None


# --- (d2) dotnet + de4dot output with a malformed/truncated MZ header: degrades
# gracefully instead of letting detect_format_bytes's struct.error escape ---


def test_de4dot_malformed_mz_header_output_degrades_without_advance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_roots(monkeypatch, root)
    executor = _FakeExecutor()
    output_path = f"/work/de4dot/{artifact_id}/deobfuscated"
    # MZ-prefixed but far too short for detect_format_bytes's struct.unpack
    # reads to succeed -- reproduces struct.error: unpack requires a buffer
    # of 4 bytes.
    truncated_bytes = b"MZ" + b"\x00" * 10
    executor.files[output_path] = truncated_bytes
    executor.results.extend(
        [
            ExecutionResult(exit_code=0, stdout="", stderr=""),
            ExecutionResult(exit_code=0, stdout="Detected ConfuserEx (1.0.0)\n", stderr=""),
            ExecutionResult(exit_code=0, stdout=f"{len(truncated_bytes)}\n", stderr=""),
        ]
    )
    tool_context = _tool_context(artifact_id, sample_format="dotnet")

    result = build_de4dot_deobfuscate(_build_context(executor))(tool_context)  # type: ignore[operator]

    _assert_result_schema(result)
    assert result["success"] is False
    assert result["applicable"] is True
    assert result["degraded"] is True
    assert result["changed"] is False
    assert result["error_code"] == "output_invalid"
    assert result["error"] == "The recovered output is not a valid .NET assembly."
    assert result["recovered_size"] == len(truncated_bytes)
    assert tool_context.state[CURRENT_ARTIFACT_KEY] == artifact_id
    assert tool_context.state[DE4DOT_RESULT_KEY] == result
    assert tool_context.state.get(UPX_PROVENANCE_PROMPT_KEY) is None


# --- (e) _valid_cached_result accepts each admitted shape ---


@pytest.mark.parametrize(
    "cached",
    [
        {
            "success": True,
            "applicable": False,
            "degraded": False,
            "changed": False,
            "reason": "not_dotnet",
            "source_artifact_id": "a" * 64,
            "tool_version": "PLACEHOLDER",
        },
        {
            "success": True,
            "applicable": False,
            "degraded": False,
            "changed": False,
            "reason": "no_obfuscator",
            "source_artifact_id": "a" * 64,
            "source_size": 6,
            "tool_version": "PLACEHOLDER",
        },
        {
            "success": True,
            "applicable": False,
            "degraded": False,
            "changed": False,
            "reason": "protector_unsupported",
            "source_artifact_id": "a" * 64,
            "source_size": 6,
            "protector_name": "ConfuserEx",
            "tool_version": "PLACEHOLDER",
        },
        {
            "success": True,
            "applicable": False,
            "degraded": False,
            "changed": False,
            "reason": "no_change",
            "source_artifact_id": "a" * 64,
            "source_size": 6,
            "tool_version": "PLACEHOLDER",
        },
        {
            "success": True,
            "applicable": False,
            "degraded": False,
            "changed": False,
            "reason": "input_too_large",
            "source_artifact_id": "a" * 64,
            "source_size": 512 * 1024 * 1024 + 1,
            "tool_version": "PLACEHOLDER",
        },
        {
            "success": False,
            "applicable": True,
            "degraded": True,
            "changed": False,
            "error_code": "sandbox_unavailable",
            "error": "The deobfuscation sandbox is unavailable.",
            "source_artifact_id": "a" * 64,
            "source_size": 6,
            "tool_version": "PLACEHOLDER",
        },
        {
            "success": False,
            "applicable": True,
            "degraded": True,
            "changed": False,
            "error_code": "output_invalid",
            "error": "The recovered output is not a valid .NET assembly.",
            "source_artifact_id": "a" * 64,
            "source_size": 6,
            "recovered_size": 3,
            "tool_version": "PLACEHOLDER",
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
            "obfuscator_name": "SmartAssembly",
            "tool_version": "PLACEHOLDER",
        },
    ],
)
def test_de4dot_valid_cached_result_accepts_each_admitted_shape(cached: dict[str, object]) -> None:
    cached = dict(cached)
    cached["tool_version"] = _tool_version()

    assert _valid_cached_result(cached) is True


@pytest.mark.parametrize(
    "cached",
    [
        # protector_unsupported without the name it exists to carry
        {
            "success": True,
            "applicable": False,
            "degraded": False,
            "changed": False,
            "reason": "protector_unsupported",
            "source_artifact_id": "a" * 64,
            "source_size": 6,
            "tool_version": "PLACEHOLDER",
        },
        # ... or with an empty one, which reads as "unnamed" and defeats the point
        {
            "success": True,
            "applicable": False,
            "degraded": False,
            "changed": False,
            "reason": "protector_unsupported",
            "source_artifact_id": "a" * 64,
            "source_size": 6,
            "protector_name": "",
            "tool_version": "PLACEHOLDER",
        },
        # a name smuggled onto the reason that means "clean"
        {
            "success": True,
            "applicable": False,
            "degraded": False,
            "changed": False,
            "reason": "no_obfuscator",
            "source_artifact_id": "a" * 64,
            "source_size": 6,
            "protector_name": "ConfuserEx",
            "tool_version": "PLACEHOLDER",
        },
    ],
)
def test_de4dot_valid_cached_result_rejects_a_nameless_protector(
    cached: dict[str, object],
) -> None:
    cached = dict(cached)
    cached["tool_version"] = _tool_version()

    assert _valid_cached_result(cached) is False


def _tool_version() -> str:
    import reverse_engineering.tools.deobfuscation.dotnet as dotnet

    return dotnet._TOOL_VERSION


def test_de4dot_factory_callable_name_matches_descriptor() -> None:
    tool = build_de4dot_deobfuscate(_build_context(_FakeExecutor()))

    assert DE4DOT_DEOBFUSCATE_TOOL.id == "de4dot_deobfuscate"
    assert tool.__name__ == DE4DOT_DEOBFUSCATE_TOOL.id  # type: ignore[union-attr]
