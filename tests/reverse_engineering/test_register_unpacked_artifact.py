"""Tests for the ``register_unpacked_artifact`` workbench hand-off tool.

``register_unpacked_artifact`` admits a recovered payload written under the
persistent workspace back into the pipeline: it measures the entropy of the
current (packed) artifact, reads the recovered dump, and -- only when entropy
dropped meaningfully -- stores the dump by SHA-256, makes it the current
artifact (``CURRENT_ARTIFACT_KEY``), and records ``recovered <- original``
provenance. A dump whose entropy did not drop is rejected as "still packed" and
the current artifact is left untouched. The tool returns only structured,
non-content metadata (id, size, entropy, format) -- never raw decrypted bytes.

The harness mirrors the committed ``test_run_python_tool.py`` fake, monkeypatching
``read_bounded_file`` so the recovered dump is supplied directly instead of driven
through a real pod filesystem.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, cast

from arema.core.config import LLMProvider, Settings
from arema.runtime.agent_factory import ToolBuildContext
from arema.runtime.sandbox.port import ExecutionResult, SandboxHandle
from arema.runtime.services import RuntimeServices
from arema.runtime.sessions import SessionKeys
from reverse_engineering.artifacts import ArtifactStore
from reverse_engineering.tools.deobfuscation.state import (
    CLASSIFICATION_KEY,
    CURRENT_ARTIFACT_KEY,
    CURRENT_ARTIFACT_PROMPT_KEY,
    UPX_PROVENANCE_PROMPT_KEY,
)
from reverse_engineering.tools.workbench.register import (
    REGISTER_UNPACKED_ARTIFACT_TOOL,
    build_register_unpacked_artifact,
)

if TYPE_CHECKING:
    from pathlib import Path

    import pytest

    from arema.registry.catalog import CapabilityCatalog
    from arema.runtime.sandbox.port import SandboxExecutor


class _FakeExecutor:
    """Protocol-complete sandbox fake recording the staging interactions."""

    def __init__(self) -> None:
        self.claims: list[tuple[str, str]] = []
        self.runs: list[str] = []
        self.writes: list[tuple[str, bytes]] = []
        self.files: dict[str, bytes] = {}
        self._handles: dict[tuple[str, str], SandboxHandle] = {}

    def claim(self, *, key: str, pool: str) -> SandboxHandle:
        self.claims.append((key, pool))
        return self._handles.setdefault(
            (key, pool), SandboxHandle(key=key, pool=pool, backend_id=f"{pool}-{key}")
        )

    def run(self, handle: SandboxHandle, command: str, *, timeout: float) -> ExecutionResult:
        del handle, timeout
        self.runs.append(command)
        prefix = "test -f "
        if command.startswith(prefix):
            path = command[len(prefix) :]
            return ExecutionResult(exit_code=0 if path in self.files else 1, stdout="", stderr="")
        return ExecutionResult(exit_code=0, stdout="", stderr="")

    def write_file(self, handle: SandboxHandle, path: str, data: bytes) -> None:
        del handle
        self.writes.append((path, data))
        self.files[path] = data

    def read_file(self, handle: SandboxHandle, path: str) -> bytes:
        del handle
        return self.files.get(path, b"")

    def terminate(self, handle: SandboxHandle) -> None:
        pass

    def release_session(self, key: str) -> None:
        pass


class _FakeState:
    """Duck-typed ADK state stand-in; deliberately not a mapping subclass."""

    def __init__(self, values: dict[str, object] | None = None) -> None:
        self._values = values or {}

    def get(self, key: str, default: object = None) -> object:
        return self._values.get(key, default)

    def __setitem__(self, key: str, value: object) -> None:
        self._values[key] = value


class _FakeToolContext:
    def __init__(self, values: dict[str, object] | None = None) -> None:
        self.state = _FakeState(values)


def _minimal_pe(padding: int = 4096) -> bytes:
    """A structurally-valid, low-entropy PE: a 64-byte DOS header whose e_lfanew
    points to a ``PE\\0\\0`` signature. Registration validates the signature, not
    merely the ``MZ`` magic, so recovered payloads must carry a real PE header."""
    header = bytearray(b"\x00" * 0x40)
    header[0:2] = b"MZ"
    header[0x3C:0x40] = (0x40).to_bytes(4, "little")  # e_lfanew -> 0x40
    return bytes(header) + b"PE\x00\x00" + b"\x00" * padding


def _minimal_dotnet_assembly(padding: int = 512) -> bytes:
    """A structurally-valid, low-entropy PE with a populated CLI (COM descriptor)
    data directory, so ``detect_format_bytes`` classifies it as ``dotnet`` --
    matching a real .NET assembly. Extends ``_minimal_pe()``'s DOS+PE header with
    a PE32 optional header whose ``NumberOfRvaAndSizes`` is > 14 and whose
    data-directory index 14 (the CLI/COM-descriptor header) carries a non-zero
    RVA, mirroring ``acquire_sample.detect_format_bytes``'s parse."""
    pe_offset = 0x40
    optional_at = pe_offset + 24  # "PE\0\0" signature (4) + COFF header (20)
    directories_at = optional_at + 96  # PE32 optional header data-directory offset
    com_descriptor_at = directories_at + 14 * 8
    total = com_descriptor_at + 8 + padding
    header = bytearray(total)
    header[0:2] = b"MZ"
    header[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    header[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    header[optional_at : optional_at + 2] = (0x10B).to_bytes(2, "little")  # PE32 magic
    header[directories_at - 4 : directories_at] = (16).to_bytes(4, "little")  # NumberOfRvaAndSizes
    header[com_descriptor_at : com_descriptor_at + 4] = (0x2008).to_bytes(4, "little")  # CLI RVA
    return bytes(header)


def _truncated_pe_header(total: int = 68) -> bytes:
    """A structurally-malformed PE: a valid DOS header whose ``e_lfanew`` points
    at a real ``PE\\0\\0`` signature, but the buffer is cut off before the
    optional header that follows it. This is the exact shape that makes
    ``detect_format_bytes``'s ``struct.unpack("<H", handle.read(2))`` under-fill
    and raise ``struct.error`` -- register_unpacked_artifact must degrade this to
    a clean rejection, not let the exception escape. ``total`` must stay >=
    ``_MIN_RECOVERED_BYTES`` (64) so the buffer clears the size gate and actually
    reaches the format check."""
    pe_offset = 0x40
    header = bytearray(total)
    header[0:2] = b"MZ"
    header[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    header[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    return bytes(header)


def _workbench_context(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    executor: _FakeExecutor,
) -> tuple[ToolBuildContext, _FakeToolContext, str]:
    """Build a k8s ToolBuildContext with a HIGH-entropy current (packed) artifact."""
    import reverse_engineering.tools.deobfuscation.runtime as rt

    root = tmp_path / "artifacts"
    source = tmp_path / "packed.bin"
    # A high-entropy (~8.0) sample stands in for a packed input, so a low-entropy
    # recovered dump registers and an equally-random dump is rejected.
    source.write_bytes(os.urandom(65_536))
    sha = ArtifactStore(root).acquire(source)
    monkeypatch.setattr(rt, "default_artifacts_root", lambda: root)
    monkeypatch.setattr(
        "reverse_engineering.tools.workbench.register.default_artifacts_root",
        lambda: root,
    )

    settings = Settings(
        _env_file=None,
        llm_provider=LLMProvider.OLLAMA,
        sandbox_backend="k8s",
        sandbox_namespace="agent-sandbox-demo",
        sandbox_run_timeout=90,
    )
    base = RuntimeServices.default()
    services = RuntimeServices(
        clock=base.clock,
        metrics=base.metrics,
        memory_sink=base.memory_sink,
        sandbox=cast("SandboxExecutor", executor),
    )
    context = ToolBuildContext(
        settings=settings,
        services=services,
        catalog=cast("CapabilityCatalog", object()),
    )
    tool_context = _FakeToolContext(
        {SessionKeys.SANDBOX_CASE_ID: "case-wb", CURRENT_ARTIFACT_KEY: sha}
    )
    return context, tool_context, sha


def test_register_expands_workdir_literal_in_workspace_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # dotnet_analyst writes to $WORKDIR and reports that literal path; register (a
    # Python tool) does not expand env vars, so a leading "$WORKDIR/" must be
    # stripped to the staged work dir -- NOT joined verbatim (which would build
    # ".../$WORKDIR/out.dll" and fail validation, the empty-report bug from the
    # user's adk-web run).
    executor = _FakeExecutor()
    ctx, tool_ctx, _packed = _workbench_context(monkeypatch, tmp_path, executor=executor)
    recovered = _minimal_pe()
    seen: dict[str, str] = {}

    def _capture(staged: object, path: str, max_bytes: int) -> bytes:
        del max_bytes
        seen["path"] = path
        seen["work_dir"] = getattr(staged, "work_dir", "")
        return recovered

    monkeypatch.setattr("reverse_engineering.tools.workbench.register.read_bounded_file", _capture)
    out = build_register_unpacked_artifact(ctx)(
        workspace_path="$WORKDIR/out.dll", method="dnlib_roundtrip", tool_context=tool_ctx
    )
    assert out["registered"] is True
    assert "$WORKDIR" not in seen["path"], "the $WORKDIR literal must be expanded, not joined"
    assert seen["path"] == f"{seen['work_dir']}/out.dll"


def test_registers_lower_entropy_payload_and_updates_current_artifact(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executor = _FakeExecutor()
    ctx, tool_ctx, packed_sha = _workbench_context(monkeypatch, tmp_path, executor=executor)
    recovered = _minimal_pe()

    def _read_recovered(staged: object, path: str, max_bytes: int) -> bytes:
        del staged, path, max_bytes
        return recovered

    monkeypatch.setattr(
        "reverse_engineering.tools.workbench.register.read_bounded_file",
        _read_recovered,
    )

    register = build_register_unpacked_artifact(ctx)
    out = register(workspace_path="unpacked.bin", method="rc4-static", tool_context=tool_ctx)

    assert out["registered"] is True
    assert out["entropy_after"] < out["entropy_before"]
    assert out["size"] == len(recovered)
    assert out["format"] == "pe"
    # The recovered dump became the current artifact and was stored by SHA-256.
    new_id = cast("str", out["artifact_id"])
    assert tool_ctx.state.get(CURRENT_ARTIFACT_KEY) == new_id
    # The prompt-surfaced mirror advances too (always set, even with no
    # classification present -- the classification advance is covered separately).
    assert tool_ctx.state.get(CURRENT_ARTIFACT_PROMPT_KEY) == new_id
    assert ArtifactStore(tmp_path / "artifacts").path_for(new_id).read_bytes() == recovered
    # Provenance links recovered <- original + method in the shared deobf slot.
    provenance = cast("str", tool_ctx.state.get(UPX_PROVENANCE_PROMPT_KEY))
    assert new_id in provenance
    assert packed_sha in provenance
    assert "rc4-static" in provenance


def test_success_advances_classification_authority_like_upx(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Full upx-parity hand-off: when a classification (keyed on the packed
    # artifact, as deobf_classify leaves it) is present, register must advance its
    # artifact_id to the recovered sha -- otherwise Phase 1's downstream
    # validate_current_classification would reject "classification does not match
    # current artifact".
    import json

    executor = _FakeExecutor()
    ctx, tool_ctx, packed_sha = _workbench_context(monkeypatch, tmp_path, executor=executor)
    tool_ctx.state[CLASSIFICATION_KEY] = json.dumps(
        {
            "artifact_id": packed_sha,
            "deobf_plan": {"upx": False, "floss": False},
            "pcode_preferred": False,
            "obf_class": "packed-other",
            "pre_snapshot": {
                "size": 0,
                "function_count": 0,
                "import_count": 0,
                "string_count": 0,
                "section_count": 0,
            },
        }
    )
    recovered = _minimal_pe()

    def _read_recovered(staged: object, path: str, max_bytes: int) -> bytes:
        del staged, path, max_bytes
        return recovered

    monkeypatch.setattr(
        "reverse_engineering.tools.workbench.register.read_bounded_file",
        _read_recovered,
    )

    register = build_register_unpacked_artifact(ctx)
    out = register(workspace_path="unpacked.bin", method="xor", tool_context=tool_ctx)

    new_id = cast("str", out["artifact_id"])
    assert out["registered"] is True
    assert tool_ctx.state.get(CURRENT_ARTIFACT_KEY) == new_id
    assert tool_ctx.state.get(CURRENT_ARTIFACT_PROMPT_KEY) == new_id
    advanced = json.loads(cast("str", tool_ctx.state.get(CLASSIFICATION_KEY)))
    assert advanced["artifact_id"] == new_id  # authority tracks the recovered artifact
    assert advanced["obf_class"] == "packed-other"  # the plan itself is preserved


def test_rejects_a_still_packed_dump(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    executor = _FakeExecutor()
    ctx, tool_ctx, packed_sha = _workbench_context(monkeypatch, tmp_path, executor=executor)

    def _read_random(staged: object, path: str, max_bytes: int) -> bytes:
        del staged, path, max_bytes
        return os.urandom(4096)  # still high entropy

    monkeypatch.setattr(
        "reverse_engineering.tools.workbench.register.read_bounded_file",
        _read_random,
    )

    register = build_register_unpacked_artifact(ctx)
    out = register(workspace_path="unpacked.bin", method="x", tool_context=tool_ctx)

    assert out["registered"] is False
    assert "error" in out
    # The current artifact is unchanged and no provenance is recorded.
    assert tool_ctx.state.get(CURRENT_ARTIFACT_KEY) == packed_sha
    assert tool_ctx.state.get(UPX_PROVENANCE_PROMPT_KEY) is None


def test_rejects_an_empty_dump(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # A 0-byte dump has entropy 0.0, so it "drops" ~8 bits/byte against a
    # high-entropy packed input and clears the entropy gate -- but it is not a
    # recovery. The size floor must reject it and leave the current artifact intact.
    executor = _FakeExecutor()
    ctx, tool_ctx, packed_sha = _workbench_context(monkeypatch, tmp_path, executor=executor)

    def _read_empty(staged: object, path: str, max_bytes: int) -> bytes:
        del staged, path, max_bytes
        return b""

    monkeypatch.setattr(
        "reverse_engineering.tools.workbench.register.read_bounded_file",
        _read_empty,
    )

    register = build_register_unpacked_artifact(ctx)
    out = register(workspace_path="dump", method="x", tool_context=tool_ctx)

    assert out["registered"] is False
    assert "error" in out
    # The current artifact is unchanged and no provenance is recorded.
    assert tool_ctx.state.get(CURRENT_ARTIFACT_KEY) == packed_sha
    assert tool_ctx.state.get(UPX_PROVENANCE_PROMPT_KEY) is None


def test_rejects_a_constant_byte_dump(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # An all-zeros dump also has entropy 0.0 and clears the entropy gate, but it is
    # not a recognizable binary container. The format check must reject it so a
    # zero-filled stub cannot fabricate a false recovery.
    executor = _FakeExecutor()
    ctx, tool_ctx, packed_sha = _workbench_context(monkeypatch, tmp_path, executor=executor)

    def _read_zeros(staged: object, path: str, max_bytes: int) -> bytes:
        del staged, path, max_bytes
        return b"\x00" * 8192

    monkeypatch.setattr(
        "reverse_engineering.tools.workbench.register.read_bounded_file",
        _read_zeros,
    )

    register = build_register_unpacked_artifact(ctx)
    out = register(workspace_path="dump", method="x", tool_context=tool_ctx)

    assert out["registered"] is False
    assert out["format"] == "unknown"
    # The current artifact is unchanged and no provenance is recorded.
    assert tool_ctx.state.get(CURRENT_ARTIFACT_KEY) == packed_sha
    assert tool_ctx.state.get(UPX_PROVENANCE_PROMPT_KEY) is None


def test_rejects_mz_blob_without_pe_signature(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A low-entropy blob that merely STARTS with "MZ" but carries no valid PE
    # signature (e.g. a slice of some other file, or a truncated/garbage dump) is
    # not a recovered PE. The 2-byte magic alone must not admit it: the structural
    # PE-signature check rejects it and leaves the current artifact untouched.
    executor = _FakeExecutor()
    ctx, tool_ctx, packed_sha = _workbench_context(monkeypatch, tmp_path, executor=executor)

    def _read_mz_only(staged: object, path: str, max_bytes: int) -> bytes:
        del staged, path, max_bytes
        # MZ magic but e_lfanew (0x00000000) points back at "MZ", not "PE\0\0".
        return b"MZ" + b"\x00" * 4096

    monkeypatch.setattr(
        "reverse_engineering.tools.workbench.register.read_bounded_file",
        _read_mz_only,
    )

    register = build_register_unpacked_artifact(ctx)
    out = register(workspace_path="dump", method="x", tool_context=tool_ctx)

    assert out["registered"] is False
    assert out["format"] == "unknown"
    # The current artifact is unchanged and no provenance is recorded.
    assert tool_ctx.state.get(CURRENT_ARTIFACT_KEY) == packed_sha
    assert tool_ctx.state.get(UPX_PROVENANCE_PROMPT_KEY) is None


def test_rejects_when_there_is_no_current_artifact(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executor = _FakeExecutor()
    ctx, _tool_ctx, _packed_sha = _workbench_context(monkeypatch, tmp_path, executor=executor)
    empty_ctx = _FakeToolContext({SessionKeys.SANDBOX_CASE_ID: "case-wb"})

    register = build_register_unpacked_artifact(ctx)
    out = register(workspace_path="unpacked.bin", method="x", tool_context=empty_ctx)

    assert out["registered"] is False
    # Nothing was staged or claimed without a current artifact.
    assert executor.claims == []


def test_success_writes_scripted_result_for_the_gate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from reverse_engineering.tools.deobfuscation.state import SCRIPTED_RESULT_KEY

    executor = _FakeExecutor()
    ctx, tool_ctx, packed_sha = _workbench_context(monkeypatch, tmp_path, executor=executor)
    recovered = _minimal_pe()

    def _read_recovered(staged: object, path: str, max_bytes: int) -> bytes:
        del staged, path, max_bytes
        return recovered

    monkeypatch.setattr(
        "reverse_engineering.tools.workbench.register.read_bounded_file", _read_recovered
    )

    register = build_register_unpacked_artifact(ctx)
    out = register(workspace_path="unpacked.bin", method="custom rc4", tool_context=tool_ctx)

    result = tool_ctx.state.get(SCRIPTED_RESULT_KEY)
    assert isinstance(result, dict)
    assert result["artifact_id"] == out["artifact_id"]  # bound to the recovered id
    assert result["source_artifact_id"] == packed_sha
    assert result["method"] == "custom rc4"
    assert result["format"] == "pe"
    assert result["size"] == len(recovered)
    assert result["entropy_after"] < result["entropy_before"]


def test_rejected_dump_does_not_write_scripted_result(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from reverse_engineering.tools.deobfuscation.state import SCRIPTED_RESULT_KEY

    executor = _FakeExecutor()
    ctx, tool_ctx, _packed = _workbench_context(monkeypatch, tmp_path, executor=executor)

    def _read_random(staged: object, path: str, max_bytes: int) -> bytes:
        del staged, path, max_bytes
        return os.urandom(4096)  # still packed → rejected

    monkeypatch.setattr(
        "reverse_engineering.tools.workbench.register.read_bounded_file", _read_random
    )

    register = build_register_unpacked_artifact(ctx)
    out = register(workspace_path="x", method="x", tool_context=tool_ctx)

    assert out["registered"] is False
    assert tool_ctx.state.get(SCRIPTED_RESULT_KEY) is None


def test_dotnet_recovery_admitted_on_valid_clr_without_entropy_drop(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from reverse_engineering.tools.acquire_sample import SAMPLE_FORMAT_KEY
    from reverse_engineering.tools.deobfuscation.state import SCRIPTED_RESULT_KEY

    executor = _FakeExecutor()
    ctx, tool_ctx, _packed = _workbench_context(monkeypatch, tmp_path, executor=executor)
    tool_ctx.state[SAMPLE_FORMAT_KEY] = "dotnet"
    # A minimal valid .NET assembly (MZ + PE + CLI header). High-entropy source, but
    # the deobfuscated dump need NOT drop entropy: admission is valid-CLR + changed.
    recovered = _minimal_dotnet_assembly()
    monkeypatch.setattr(
        "reverse_engineering.tools.workbench.register.read_bounded_file",
        lambda *_args: recovered,
    )
    out = build_register_unpacked_artifact(ctx)(
        workspace_path="clean.dll", method="dnlib metadata repair", tool_context=tool_ctx
    )
    assert out["registered"] is True
    assert out["format"] == "dotnet"
    assert tool_ctx.state.get(SCRIPTED_RESULT_KEY)["format"] == "dotnet"


def test_dotnet_recovery_rejects_identical_no_op(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A no-op dnlib re-serialization that returns a byte-identical assembly is not a
    # recovery: the "changed" half of the dotnet valid-CLR + changed admission must
    # reject it and leave the current artifact untouched. (On the native branch the
    # entropy-drop gate already implies changed, so this check only bites for .NET.)
    from reverse_engineering.tools.acquire_sample import SAMPLE_FORMAT_KEY

    executor = _FakeExecutor()
    ctx, tool_ctx, _packed = _workbench_context(monkeypatch, tmp_path, executor=executor)
    dotnet = _minimal_dotnet_assembly()
    # Make the current artifact that exact .NET assembly.
    current_id = ArtifactStore(tmp_path / "artifacts").acquire_bytes(dotnet)
    tool_ctx.state[CURRENT_ARTIFACT_KEY] = current_id
    tool_ctx.state[SAMPLE_FORMAT_KEY] = "dotnet"
    monkeypatch.setattr(
        "reverse_engineering.tools.workbench.register.read_bounded_file",
        lambda *_args: dotnet,  # recovered == current
    )
    out = build_register_unpacked_artifact(ctx)(
        workspace_path="same.dll", method="noop", tool_context=tool_ctx
    )
    assert out["registered"] is False
    assert "identical" in str(out.get("error", "")).lower()
    assert tool_ctx.state.get(CURRENT_ARTIFACT_KEY) == current_id  # untouched


def test_dotnet_recovery_rejects_non_clr_dump(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from reverse_engineering.tools.acquire_sample import SAMPLE_FORMAT_KEY

    executor = _FakeExecutor()
    ctx, tool_ctx, _ = _workbench_context(monkeypatch, tmp_path, executor=executor)
    tool_ctx.state[SAMPLE_FORMAT_KEY] = "dotnet"
    monkeypatch.setattr(
        "reverse_engineering.tools.workbench.register.read_bounded_file",
        lambda *_args: b"MZ" + b"\x00" * 4096,  # PE but no CLI header
    )
    out = build_register_unpacked_artifact(ctx)(
        workspace_path="x", method="x", tool_context=tool_ctx
    )
    assert out["registered"] is False


def test_native_recovery_rejects_truncated_pe_header_without_crashing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A dump with a valid DOS header + e_lfanew pointing at a real "PE\0\0"
    # signature, but truncated before the optional header, clears the size
    # floor (>= 64 bytes) yet makes detect_format_bytes's struct.unpack
    # under-fill and raise struct.error. register_unpacked_artifact must
    # degrade that to a clean rejection, not propagate the exception.
    executor = _FakeExecutor()
    ctx, tool_ctx, packed_sha = _workbench_context(monkeypatch, tmp_path, executor=executor)
    monkeypatch.setattr(
        "reverse_engineering.tools.workbench.register.read_bounded_file",
        lambda *_args: _truncated_pe_header(),
    )

    register = build_register_unpacked_artifact(ctx)
    out = register(workspace_path="dump", method="x", tool_context=tool_ctx)

    assert out["registered"] is False
    assert out["format"] == "unknown"
    assert tool_ctx.state.get(CURRENT_ARTIFACT_KEY) == packed_sha
    assert tool_ctx.state.get(UPX_PROVENANCE_PROMPT_KEY) is None


def test_dotnet_recovery_rejects_truncated_pe_header_without_crashing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Same malformed/truncated header, but on the .NET branch (SAMPLE_FORMAT_KEY
    # == "dotnet"): the unguarded detect_format_bytes call sits before the
    # format branch splits, so it must not crash the .NET path either.
    from reverse_engineering.tools.acquire_sample import SAMPLE_FORMAT_KEY

    executor = _FakeExecutor()
    ctx, tool_ctx, packed_sha = _workbench_context(monkeypatch, tmp_path, executor=executor)
    tool_ctx.state[SAMPLE_FORMAT_KEY] = "dotnet"
    monkeypatch.setattr(
        "reverse_engineering.tools.workbench.register.read_bounded_file",
        lambda *_args: _truncated_pe_header(),
    )

    register = build_register_unpacked_artifact(ctx)
    out = register(workspace_path="dump", method="x", tool_context=tool_ctx)

    assert out["registered"] is False
    assert out["format"] == "unknown"
    assert tool_ctx.state.get(CURRENT_ARTIFACT_KEY) == packed_sha
    assert tool_ctx.state.get(UPX_PROVENANCE_PROMPT_KEY) is None


def test_register_descriptor_binds_output_policy() -> None:
    assert REGISTER_UNPACKED_ARTIFACT_TOOL.id == "register_unpacked_artifact"
    assert REGISTER_UNPACKED_ARTIFACT_TOOL.output_policy.max_chars == 2_000
    assert REGISTER_UNPACKED_ARTIFACT_TOOL.output_policy.max_list_items == 10
    assert REGISTER_UNPACKED_ARTIFACT_TOOL.factory is build_register_unpacked_artifact
