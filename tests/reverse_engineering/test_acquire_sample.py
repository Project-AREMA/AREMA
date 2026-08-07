"""Tests for the acquire_sample tool.

The tool ingests a local file into the content-addressed artifact store and
returns its SHA-256 artifact id, digest, and byte size. The default artifacts
root is patched to a temp dir so no real ``~/.arema`` path is touched.
"""

from __future__ import annotations

import io
import struct
import zipfile
from typing import TYPE_CHECKING

import pytest
from google.adk.tools.function_tool import FunctionTool

from reverse_engineering.tools.acquire_sample import (
    ACQUIRE_SAMPLE_TOOL,
    SAMPLE_FORMAT_KEY,
    SAMPLE_INTEL_KEY,
    SAMPLE_INTEL_PROMPT_KEY,
    SAMPLE_PACKER_KEY,
    SAMPLE_PACKER_PROMPT_KEY,
    _detect_format,
    acquire_sample,
    detect_format_bytes,
)
from reverse_engineering.tools.deobfuscation.state import (
    CLASSIFICATION_KEY,
    CURRENT_ARTIFACT_KEY,
    CURRENT_ARTIFACT_PROMPT_KEY,
    DEOBF_BASELINE_PROMPT_KEY,
    DEOBF_ITERATION_KEY,
    FLOSS_CALLED_KEY,
    FLOSS_RESULT_KEY,
    FLOSS_SEEN_FINGERPRINTS_KEY,
    PCODE_PREFERRED_PROMPT_KEY,
    PREVIOUS_SNAPSHOT_KEY,
    RECOVERY_EVIDENCE_KEY,
    RECOVERY_SUMMARY_KEY,
    RETRIAGE_SNAPSHOT_KEY,
    UPX_CALLED_KEY,
    UPX_PROVENANCE_PROMPT_KEY,
    UPX_RESULT_KEY,
)
from reverse_engineering.tools.ghidra.coverage import (
    DEEP_COVERAGE_KEY,
    DEEP_EVIDENCE_KEY,
    DEEP_ITERATION_KEY,
    DEEP_MISSING_PROMPT_KEY,
)

if TYPE_CHECKING:
    from pathlib import Path


def _set_root(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    monkeypatch.setattr(
        "reverse_engineering.tools.acquire_sample.default_artifacts_root",
        lambda: root,
    )


_PE_SIGNATURE_OFFSET = 0x80


def _pe_bytes(*, plus: bool = False, com_rva: int = 0, directory_count: int = 16) -> bytes:
    """Build a header-only PE: ``plus`` selects PE32+, ``com_rva`` makes it .NET.

    The offsets are the ones verified against real assemblies (Newtonsoft.Json,
    net20..net6.0): signature at 0x80, optional header 24 bytes later at 0x98.
    """
    buffer = bytearray(0x400)
    buffer[0:2] = b"MZ"
    struct.pack_into("<I", buffer, 0x3C, _PE_SIGNATURE_OFFSET)
    buffer[_PE_SIGNATURE_OFFSET : _PE_SIGNATURE_OFFSET + 4] = b"PE\0\0"
    optional_at = _PE_SIGNATURE_OFFSET + 24
    struct.pack_into("<H", buffer, optional_at, 0x20B if plus else 0x10B)
    directories_at = optional_at + (112 if plus else 96)
    struct.pack_into("<I", buffer, directories_at - 4, directory_count)
    struct.pack_into("<II", buffer, directories_at + 14 * 8, com_rva, 72 if com_rva else 0)
    return bytes(buffer)


def _zip_bytes(entries: list[tuple[str, bytes]]) -> bytes:
    """Build an in-memory ZIP archive from ``(name, data)`` entries."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return buffer.getvalue()


def test_detect_format_reads_a_dex_by_magic() -> None:
    assert detect_format_bytes(b"dex\n035\x00" + bytes(64)) == "dex"


def test_apk_wins_over_jar_despite_carrying_a_java_manifest() -> None:
    data = _zip_bytes(
        [
            ("AndroidManifest.xml", b"x"),
            ("classes.dex", b"y"),
            ("META-INF/MANIFEST.MF", b"z"),
        ]
    )
    assert detect_format_bytes(data) == "apk"


def test_detect_format_reads_an_ordinary_java_archive_as_jar() -> None:
    data = _zip_bytes([("META-INF/MANIFEST.MF", b"m"), ("org/x/Thing.class", b"c")])
    assert detect_format_bytes(data) == "jar"


def test_a_zip_without_java_or_android_markers_stays_unknown() -> None:
    data = _zip_bytes([("lib/net6.0/Thing.dll", b"d"), ("[Content_Types].xml", b"x")])
    assert detect_format_bytes(data) == "unknown"  # a .nupkg must not go to jadx


def test_detect_format_survives_a_corrupt_zip() -> None:
    assert detect_format_bytes(b"PK\x03\x04" + bytes(32)) == "unknown"  # no raise


class _FakeToolContext:
    def __init__(self, state: dict[str, object]) -> None:
        self.state = state


def test_acquire_sample_returns_artifact_id_sha256_size_format(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifacts_root = tmp_path / "artifacts"
    _set_root(monkeypatch, artifacts_root)
    payload = b"sample-bytes"
    src = tmp_path / "sample.bin"
    src.write_bytes(payload)

    result = acquire_sample(str(src))

    assert set(result) == {"artifact_id", "sha256", "size", "format", "packer"}
    assert result["artifact_id"] == result["sha256"]
    assert result["size"] == len(payload)
    assert result["format"] == "unknown"
    assert result["packer"] == ""


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (_pe_bytes(com_rva=0x2008), "dotnet"),
        (_pe_bytes(plus=True, com_rva=0x2008), "dotnet"),
        (_pe_bytes(com_rva=0), "pe"),
        (_pe_bytes(plus=True, com_rva=0), "pe"),
        # A short data-directory array cannot hold a CLI header; without the
        # NumberOfRvaAndSizes bound we would read section bytes and misroute.
        (_pe_bytes(com_rva=0x2008, directory_count=10), "pe"),
        (b"\x7fELF\x02\x01\x01" + bytes(64), "elf"),
        (b"\xcf\xfa\xed\xfe" + bytes(64), "macho"),
        (b"\xca\xfe\xba\xbe" + bytes(64), "macho"),
        (b"not a binary at all", "unknown"),
        (b"MZ", "unknown"),
        (b"", "unknown"),
    ],
)
def test_detect_format_classifies_containers(tmp_path: Path, payload: bytes, expected: str) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(payload)

    assert _detect_format(sample) == expected


def test_detect_format_never_raises_on_a_truncated_pe(tmp_path: Path) -> None:
    """A malformed header degrades to a weaker answer -- ingest must not fail."""
    truncated = tmp_path / "truncated.bin"
    truncated.write_bytes(_pe_bytes(com_rva=0x2008)[:0x90])

    assert _detect_format(truncated) in {"pe", "unknown"}


def test_acquire_sample_writes_format_to_session_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The router reads the format deterministically from state, not from a model."""
    _set_root(monkeypatch, tmp_path / "artifacts")
    src = tmp_path / "assembly.dll"
    src.write_bytes(_pe_bytes(com_rva=0x2008))
    context = _FakeToolContext({})

    result = acquire_sample(str(src), context)  # type: ignore[arg-type]

    assert result["format"] == "dotnet"
    assert context.state[SAMPLE_FORMAT_KEY] == "dotnet"


def test_acquire_sample_names_the_protector_at_ingest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Identification is decided from bytes, before any model turn."""
    _set_root(monkeypatch, tmp_path / "artifacts")
    src = tmp_path / "protected.dll"
    src.write_bytes(_pe_bytes(com_rva=0x2008) + b"ConfusedByAttribute")
    context = _FakeToolContext({})

    result = acquire_sample(str(src), context)  # type: ignore[arg-type]

    assert result["packer"] == "ConfuserEx"
    assert context.state[SAMPLE_PACKER_KEY] == "ConfuserEx"
    # The injectable alias carries the evidence with the name, so the triage
    # finding that quotes it is self-justifying.
    assert context.state[SAMPLE_PACKER_PROMPT_KEY] == "ConfuserEx (matched: ConfusedByAttribute)"


def test_an_unmarked_sample_leaves_the_packer_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_root(monkeypatch, tmp_path / "artifacts")
    src = tmp_path / "plain.exe"
    src.write_bytes(_pe_bytes(com_rva=0))
    context = _FakeToolContext({})

    result = acquire_sample(str(src), context)  # type: ignore[arg-type]

    assert result["packer"] == ""
    assert context.state[SAMPLE_PACKER_KEY] == ""
    assert context.state[SAMPLE_PACKER_PROMPT_KEY] == ""


def test_failed_acquire_clears_a_prior_samples_packer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stale protector name must not bleed into the next sample's report."""
    _set_root(monkeypatch, tmp_path / "artifacts")
    context = _FakeToolContext(
        {SAMPLE_PACKER_KEY: "UPX", SAMPLE_PACKER_PROMPT_KEY: "UPX (matched: UPX!)"}
    )

    with pytest.raises(FileNotFoundError):
        acquire_sample(str(tmp_path / "missing.exe"), context)  # type: ignore[arg-type]

    assert context.state[SAMPLE_PACKER_KEY] == ""
    assert context.state[SAMPLE_PACKER_PROMPT_KEY] == ""


def test_a_clean_sample_after_a_packed_one_clears_the_packer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_root(monkeypatch, tmp_path / "artifacts")
    packed = tmp_path / "packed.exe"
    packed.write_bytes(_pe_bytes(com_rva=0) + b"UPX0\x00\x00\x00\x00")
    plain = tmp_path / "plain.exe"
    plain.write_bytes(_pe_bytes(com_rva=0))
    context = _FakeToolContext({})

    assert acquire_sample(str(packed), context)["packer"] == "UPX"  # type: ignore[arg-type]
    assert acquire_sample(str(plain), context)["packer"] == ""  # type: ignore[arg-type]
    assert context.state[SAMPLE_PACKER_KEY] == ""


def test_acquire_sample_dedups_identical_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_root(monkeypatch, tmp_path / "artifacts")
    payload = b"identical"
    src_a = tmp_path / "a.bin"
    src_b = tmp_path / "b.bin"
    src_a.write_bytes(payload)
    src_b.write_bytes(payload)

    first = acquire_sample(str(src_a))
    second = acquire_sample(str(src_b))

    assert first["artifact_id"] == second["artifact_id"]


def test_new_sample_resets_deobfuscation_state_before_second_analysis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_root(monkeypatch, tmp_path / "artifacts")
    first_source = tmp_path / "first.bin"
    second_source = tmp_path / "second.bin"
    first_source.write_bytes(b"first")
    second_source.write_bytes(b"second")
    state: dict[str, object] = {
        CURRENT_ARTIFACT_KEY: "a" * 64,
        CURRENT_ARTIFACT_PROMPT_KEY: "a" * 64,
        DEOBF_BASELINE_PROMPT_KEY: '{"size":99}',
        CLASSIFICATION_KEY: {"stale": True},
        PREVIOUS_SNAPSHOT_KEY: {"size": 99},
        RETRIAGE_SNAPSHOT_KEY: {"size": 99},
        UPX_CALLED_KEY: True,
        FLOSS_CALLED_KEY: True,
        UPX_RESULT_KEY: {"stale": True},
        FLOSS_RESULT_KEY: {"stale": True},
        FLOSS_SEEN_FINGERPRINTS_KEY: ["a" * 64],
        PCODE_PREFERRED_PROMPT_KEY: "true",
        UPX_PROVENANCE_PROMPT_KEY: "stale provenance",
        "deobf:gate_error": "invalid_state",
        DEOBF_ITERATION_KEY: 2,
        RECOVERY_SUMMARY_KEY: {"stale": True},
        RECOVERY_EVIDENCE_KEY: {"stale": True},
        DEEP_COVERAGE_KEY: {"stale": True},
        DEEP_MISSING_PROMPT_KEY: "stale",
        DEEP_ITERATION_KEY: 2,
        DEEP_EVIDENCE_KEY: {"stale": True},
    }
    context = _FakeToolContext(state)

    first = acquire_sample(str(first_source), context)  # type: ignore[arg-type]
    second = acquire_sample(str(second_source), context)  # type: ignore[arg-type]

    assert first["artifact_id"] != second["artifact_id"]
    assert state[CURRENT_ARTIFACT_KEY] == second["artifact_id"]
    assert state[CURRENT_ARTIFACT_PROMPT_KEY] == ""
    assert state[DEOBF_BASELINE_PROMPT_KEY] == ""
    assert state[CLASSIFICATION_KEY] is None
    assert state[PREVIOUS_SNAPSHOT_KEY] is None
    assert state[RETRIAGE_SNAPSHOT_KEY] is None
    assert state[UPX_CALLED_KEY] is False
    assert state[FLOSS_CALLED_KEY] is False
    assert state[UPX_RESULT_KEY] is None
    assert state[FLOSS_RESULT_KEY] is None
    assert state[FLOSS_SEEN_FINGERPRINTS_KEY] == []
    assert state[PCODE_PREFERRED_PROMPT_KEY] == ""
    assert state[UPX_PROVENANCE_PROMPT_KEY] == ""
    assert state[DEOBF_ITERATION_KEY] == 0
    assert state[RECOVERY_SUMMARY_KEY] is None
    assert state[RECOVERY_EVIDENCE_KEY] is None
    assert state[DEEP_COVERAGE_KEY] is None
    assert state[DEEP_MISSING_PROMPT_KEY] == ""
    assert state[DEEP_ITERATION_KEY] == 0
    assert state[DEEP_EVIDENCE_KEY] is None


def test_acquire_sample_missing_path_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_root(monkeypatch, tmp_path / "artifacts")

    with pytest.raises(FileNotFoundError):
        acquire_sample(str(tmp_path / "nope.bin"))


def test_failed_acquire_clears_the_prior_samples_identity_so_it_never_bleeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Regression (in-cluster multi-turn): a second analysis whose file is missing
    # must NOT inherit the previous turn's format + artifact -- otherwise the
    # routers run the new (failed) sample through the prior sample's engine path
    # and the report cites the wrong artifact. acquire_sample invalidates the
    # sample identity up front, so a failed acquire leaves a clean "no sample".
    _set_root(monkeypatch, tmp_path / "artifacts")
    prior_apk_sha = "8" * 64
    context = _FakeToolContext({SAMPLE_FORMAT_KEY: "apk", CURRENT_ARTIFACT_KEY: prior_apk_sha})

    with pytest.raises(FileNotFoundError):
        acquire_sample(str(tmp_path / "missing.exe"), context)  # type: ignore[arg-type]

    assert context.state[SAMPLE_FORMAT_KEY] == ""  # not the stale "apk"
    assert context.state[CURRENT_ARTIFACT_KEY] == ""  # not the stale APK sha


def test_successful_acquire_after_a_failed_one_sets_the_new_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_root(monkeypatch, tmp_path / "artifacts")
    context = _FakeToolContext({SAMPLE_FORMAT_KEY: "apk", CURRENT_ARTIFACT_KEY: "8" * 64})
    with pytest.raises(FileNotFoundError):
        acquire_sample(str(tmp_path / "missing.exe"), context)  # type: ignore[arg-type]

    native = tmp_path / "sample.exe"
    native.write_bytes(_pe_bytes(com_rva=0))  # a plain PE -> format "pe"
    result = acquire_sample(str(native), context)  # type: ignore[arg-type]

    assert result["format"] == "pe"
    assert context.state[SAMPLE_FORMAT_KEY] == "pe"
    assert context.state[CURRENT_ARTIFACT_KEY] == result["artifact_id"]


def test_tool_descriptor_id_matches_function_name() -> None:
    assert ACQUIRE_SAMPLE_TOOL.id == "acquire_sample"
    assert acquire_sample.__name__ == "acquire_sample"


def test_acquire_sample_hides_injected_tool_context_from_adk_schema() -> None:
    declaration = FunctionTool(acquire_sample)._get_declaration()

    assert declaration is not None
    assert declaration.parameters is not None
    assert set(declaration.parameters.properties) == {"path"}


def test_tool_descriptor_has_output_policy() -> None:
    assert ACQUIRE_SAMPLE_TOOL.output_policy is not None
    assert ACQUIRE_SAMPLE_TOOL.output_policy.max_chars > 0


def test_detect_format_bytes_matches_file_detection(tmp_path: Path) -> None:
    from reverse_engineering.tools.acquire_sample import _detect_format, detect_format_bytes

    elf = b"\x7fELF" + b"\x00" * 60
    assert detect_format_bytes(elf) == "elf"
    assert detect_format_bytes(b"not a binary") == "unknown"
    # A minimal PE with no CLI directory is "pe", not "dotnet".
    p = tmp_path / "x.bin"
    p.write_bytes(elf)
    assert detect_format_bytes(elf) == _detect_format(p)


# --- hash reputation, recorded at intake --------------------------------------


def _stub_intel(monkeypatch: pytest.MonkeyPatch, line: str) -> list[str]:
    """Replace the sweep with a recorder; nothing here may touch the network."""
    seen: list[str] = []

    def _fake_gather(sha256: str) -> tuple[object, ...]:
        seen.append(sha256)
        return ()

    monkeypatch.setattr("reverse_engineering.tools.acquire_sample.gather", _fake_gather)
    monkeypatch.setattr(
        "reverse_engineering.tools.acquire_sample.render_intel_line", lambda _results: line
    )
    return seen


def test_the_reputation_line_is_recorded_under_both_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADK resolves ``{name?}`` by exact identifier, so the colon-free alias is
    the one a prompt can actually read."""
    _set_root(monkeypatch, tmp_path / "artifacts")
    _stub_intel(monkeypatch, "hashlookup: known file (catalogued in nsrl_legacy)")
    sample = tmp_path / "sample.exe"
    sample.write_bytes(_pe_bytes(com_rva=0))
    context = _FakeToolContext({})

    acquire_sample(str(sample), context)  # type: ignore[arg-type]

    line = "hashlookup: known file (catalogued in nsrl_legacy)"
    assert context.state[SAMPLE_INTEL_KEY] == line
    assert context.state[SAMPLE_INTEL_PROMPT_KEY] == line
    assert SAMPLE_INTEL_PROMPT_KEY.isidentifier()


def test_only_the_digest_is_handed_to_the_sweep(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The privacy contract at its call site: no path, no name, no bytes."""
    _set_root(monkeypatch, tmp_path / "artifacts")
    seen = _stub_intel(monkeypatch, "")
    sample = tmp_path / "very-identifying-name.exe"
    sample.write_bytes(_pe_bytes(com_rva=0))
    context = _FakeToolContext({})

    result = acquire_sample(str(sample), context)  # type: ignore[arg-type]

    assert seen == [result["artifact_id"]]


def test_a_stale_reputation_never_outlives_its_sample(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed acquire must not leave the previous sample's reputation behind
    for triage to cite against the current one."""
    _set_root(monkeypatch, tmp_path / "artifacts")
    _stub_intel(monkeypatch, "")
    context = _FakeToolContext(
        {
            SAMPLE_INTEL_KEY: "virustotal: FLAGGED MALICIOUS (62/74 Emotet)",
            SAMPLE_INTEL_PROMPT_KEY: "virustotal: FLAGGED MALICIOUS (62/74 Emotet)",
        }
    )

    with pytest.raises(FileNotFoundError):
        acquire_sample(str(tmp_path / "missing.exe"), context)  # type: ignore[arg-type]

    assert context.state[SAMPLE_INTEL_KEY] == ""
    assert context.state[SAMPLE_INTEL_PROMPT_KEY] == ""


def test_a_sweep_that_escapes_its_own_fail_open_does_not_fail_the_acquire(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Acquiring the sample is the job; enrichment is a bonus on top of it, and
    a bonus must never be able to fail the job."""
    _set_root(monkeypatch, tmp_path / "artifacts")

    def _explode(_sha256: str) -> tuple[object, ...]:
        raise RuntimeError("every source is on fire")

    monkeypatch.setattr("reverse_engineering.tools.acquire_sample.gather", _explode)
    sample = tmp_path / "sample.exe"
    sample.write_bytes(_pe_bytes(com_rva=0))
    context = _FakeToolContext({})

    result = acquire_sample(str(sample), context)  # type: ignore[arg-type]

    assert result["format"] == "pe"
    assert context.state[CURRENT_ARTIFACT_KEY] == result["artifact_id"]
    assert context.state[SAMPLE_INTEL_KEY] == ""


def test_an_unconfigured_checkout_acquires_without_touching_the_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No stub: the real sweep runs, and with no credential it must not make a
    request. httpx is replaced with a landmine to prove it."""
    _set_root(monkeypatch, tmp_path / "artifacts")

    def _landmine(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("acquire_sample reached the network without a credential")

    monkeypatch.setattr("reverse_engineering.intel.hashlookup.httpx.get", _landmine)
    sample = tmp_path / "sample.exe"
    sample.write_bytes(_pe_bytes(com_rva=0))
    context = _FakeToolContext({})

    result = acquire_sample(str(sample), context)  # type: ignore[arg-type]

    assert result["format"] == "pe"
    assert context.state[SAMPLE_INTEL_KEY] == ""


def test_acquire_without_a_tool_context_still_works(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_root(monkeypatch, tmp_path / "artifacts")
    _stub_intel(monkeypatch, "hashlookup: not present")
    sample = tmp_path / "sample.exe"
    sample.write_bytes(_pe_bytes(com_rva=0))

    assert acquire_sample(str(sample))["format"] == "pe"
