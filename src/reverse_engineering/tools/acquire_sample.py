"""The acquire_sample tool: ingest a local binary into the artifact store.

Ingest also classifies the sample's container format from its magic bytes and
records it in session state under :data:`SAMPLE_FORMAT_KEY`. That one field is the
pipeline's engine route (NORTH_STAR "format routes before engines"): a managed
``dotnet`` assembly goes to the .NET decompiler and skips the native one; every
other format does the reverse. Deciding it here -- deterministically, from bytes
-- means the router never depends on a model re-deriving it.

The packer/protector identity is decided on the same terms and for the same
reason: a watermark scan at ingest names UPX or ConfuserEx before any model turn,
so identification never depends on an agent remembering to reach for a signature
engine. It is recorded under :data:`SAMPLE_PACKER_KEY`, with the prompt-injectable
alias :data:`SAMPLE_PACKER_PROMPT_KEY` carrying the name and its signals as one
line for triage to cite. An empty value means "not named", never "not packed".

Hash reputation is recorded here for the third time on the same terms: the
digest exists at this point and nothing downstream needs to be running, so
:func:`reverse_engineering.intel.lookup.gather` asks the configured sources what
they already have on file and the answer lands in :data:`SAMPLE_INTEL_KEY`. It
is the one thing in this module that leaves the host, and only the digest does
-- never a name, a path, or a byte of the sample. With no credential configured
the sweep makes no request at all, so an unconfigured checkout behaves exactly
as it did before. An empty value means "nobody was asked or nobody answered",
which is further from evidence of a clean sample than a recorded miss is.
"""

from __future__ import annotations

import io
import struct
import zipfile
from pathlib import Path

from google.adk.tools.tool_context import ToolContext  # noqa: TC002 - ADK resolves annotations

from arema.core.logging import get_logger
from arema.registry.descriptors import OutputPolicy, ToolDescriptor
from reverse_engineering.artifacts import ArtifactStore, default_artifacts_root
from reverse_engineering.intel.lookup import (
    gather,
    gather_relations,
    render_intel_line,
    render_relations_block,
)
from reverse_engineering.tools.deobfuscation.state import (
    CURRENT_ARTIFACT_KEY,
    reset_deobfuscation_state,
)
from reverse_engineering.tools.ghidra.coverage import reset_deep_analysis_state
from reverse_engineering.tools.packer_signatures import detect_packer_bytes

logger = get_logger(__name__)

# Session-state key holding the deterministic container format decided at ingest.
SAMPLE_FORMAT_KEY = "sample:format"
# The packer/protector named at ingest, and its prompt-injectable alias. ADK
# resolves ``{name?}`` placeholders from state, and a colon is not identifier-safe,
# so the canonical key needs the alias to reach a prompt (the same pairing as
# CURRENT_ARTIFACT_KEY / CURRENT_ARTIFACT_PROMPT_KEY).
SAMPLE_PACKER_KEY = "sample:packer"
SAMPLE_PACKER_PROMPT_KEY = "sample_packer"
# What third parties already had on file about this digest, and its
# prompt-injectable alias. Same pairing, same reason.
SAMPLE_INTEL_KEY = "sample:intel"
SAMPLE_INTEL_PROMPT_KEY = "sample_intel"
# Indicators a third party associates with the digest -- URLs it was served
# from, files it drops, archives that carried it. Separate from the reputation
# line because it answers a different question and is reported, never asserted.
SAMPLE_RELATIONS_KEY = "sample:intel_relations"
SAMPLE_RELATIONS_PROMPT_KEY = "sample_intel_relations"

_MACHO_MAGICS = frozenset(
    {
        b"\xfe\xed\xfa\xce",  # 32-bit big-endian
        b"\xce\xfa\xed\xfe",  # 32-bit little-endian
        b"\xfe\xed\xfa\xcf",  # 64-bit big-endian
        b"\xcf\xfa\xed\xfe",  # 64-bit little-endian
        b"\xca\xfe\xba\xbe",  # universal ("fat") binary
    }
)
# The PE optional header follows the 4-byte "PE\0\0" signature and the 20-byte
# COFF header (verified against real assemblies: signature 0x80 -> optional 0x98).
_OPTIONAL_HEADER_OFFSET = 24
_PE32_MAGIC = 0x10B
_PE32_PLUS_MAGIC = 0x20B
# Offset of the data-directory array within the optional header, per PE format.
_PE32_DIRECTORIES_OFFSET = 96
_PE32_PLUS_DIRECTORIES_OFFSET = 112
# Data directory 14 is the CLI header ("COM descriptor"); a populated entry is
# what makes a PE a .NET assembly -- the check the CLR and ILSpy both use.
_COM_DESCRIPTOR_INDEX = 14

# ZIP entries that mark a container as an Android package. Checked before the
# JVM markers because an APK also carries META-INF/MANIFEST.MF.
_ANDROID_ZIP_MARKERS = ("AndroidManifest.xml", "classes.dex")


def _sniff_zip(data: bytes) -> str:
    """Classify a ZIP container as ``apk`` (Android markers), ``jar`` (JVM
    markers), or ``unknown``. Never raises: a bad archive is ``unknown``."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = archive.namelist()
    except (OSError, zipfile.BadZipFile):
        return "unknown"
    entries = set(names)
    if any(marker in entries for marker in _ANDROID_ZIP_MARKERS):
        return "apk"
    if "META-INF/MANIFEST.MF" in entries or any(n.endswith(".class") for n in names):
        return "jar"
    return "unknown"


def detect_format_bytes(data: bytes) -> str:
    """Classify in-memory bytes as ``dotnet``, ``pe``, ``elf``, ``macho``,
    ``dex``, ``apk``, ``jar``, or ``unknown``.

    Reads only the headers, from an in-memory buffer. A structurally malformed
    or truncated header (short reads that under-fill a ``struct.unpack``) may
    raise ``struct.error`` -- callers wanting the never-raises guarantee should
    go through :func:`_detect_format`, which wraps this in the same catch it
    always has.
    """
    handle = io.BytesIO(data)
    magic = handle.read(4)
    if magic[:4] == b"\x7fELF":
        return "elf"
    if magic in _MACHO_MAGICS:
        return "macho"
    if magic[:4] == b"dex\n":
        return "dex"
    if magic[:4] == b"PK\x03\x04":
        return _sniff_zip(data)
    if magic[:2] != b"MZ":
        return "unknown"

    handle.seek(0x3C)
    (pe_offset,) = struct.unpack("<I", handle.read(4))
    handle.seek(pe_offset)
    if handle.read(4) != b"PE\0\0":
        return "unknown"

    optional_at = pe_offset + _OPTIONAL_HEADER_OFFSET
    handle.seek(optional_at)
    (optional_magic,) = struct.unpack("<H", handle.read(2))
    if optional_magic == _PE32_MAGIC:
        directories_at = optional_at + _PE32_DIRECTORIES_OFFSET
    elif optional_magic == _PE32_PLUS_MAGIC:
        directories_at = optional_at + _PE32_PLUS_DIRECTORIES_OFFSET
    else:
        return "pe"

    # NumberOfRvaAndSizes sits immediately before the array. Without this
    # bound a short array would make us read section-header bytes and
    # mistake them for a CLI header.
    handle.seek(directories_at - 4)
    (directory_count,) = struct.unpack("<I", handle.read(4))
    if directory_count <= _COM_DESCRIPTOR_INDEX:
        return "pe"

    handle.seek(directories_at + _COM_DESCRIPTOR_INDEX * 8)
    (com_descriptor_rva,) = struct.unpack("<I", handle.read(4))
    return "dotnet" if com_descriptor_rva else "pe"


def _detect_format(path: Path) -> str:
    """Classify a sample file as ``dotnet``, ``pe``, ``elf``, ``macho``,
    ``dex``, ``apk``, ``jar``, or ``unknown``.

    Reads the file and delegates to :func:`detect_format_bytes`. Any malformed
    or truncated structure -- or an unreadable path -- degrades to ``unknown``
    rather than raising. ``zipfile.BadZipFile`` is an ``OSError`` subclass, so
    the existing catch already covers a corrupt archive.
    """
    try:
        return detect_format_bytes(path.read_bytes())
    except (OSError, struct.error):
        return "unknown"


def _detect_packer(path: Path) -> dict[str, object]:
    """Name the sample's packer/protector from its watermark, or report none.

    The packer-side mirror of :func:`_detect_format`: reads the file and delegates
    to :func:`detect_packer_bytes`, degrading an unreadable path to a
    not-detected result rather than raising. The scan itself cannot raise -- it is
    ``bytes.find`` over a buffer, with no structure to be malformed.
    """
    try:
        return detect_packer_bytes(path.read_bytes())
    except OSError:
        return {"detected": False, "name": None, "signals": []}


def _packer_prompt_line(packer: dict[str, object]) -> str:
    """Render a detection as one injectable line: the name and what matched it.

    Triage cites this verbatim, so the matched markers travel with the name and
    the resulting finding carries its own evidence.
    """
    if not packer["detected"]:
        return ""
    signals = packer["signals"]
    joined = ", ".join(signals) if isinstance(signals, list) else ""
    return f"{packer['name']} (matched: {joined})"


def _intel_line(artifact_id: str) -> str:
    """Ask the configured sources about this digest, never at acquisition's cost.

    Each source already fails open on its own, so reaching here means something
    escaped one of them. Acquiring the sample is the job; enrichment is a bonus
    on top of it, and a bonus must never be able to fail the job.
    """
    try:
        return render_intel_line(gather(artifact_id))
    except Exception as error:
        logger.warning("reputation sweep failed", error_type=type(error).__name__)
        return ""


def _relations_line(artifact_id: str) -> str:
    """Associated indicators, never at acquisition's cost. Same guard as above."""
    try:
        return render_relations_block(gather_relations(artifact_id))
    except Exception as error:
        logger.warning("relationship sweep failed", error_type=type(error).__name__)
        return ""


def acquire_sample(path: str, tool_context: ToolContext | None = None) -> dict[str, str | int]:
    """Ingest a binary sample from a local filesystem path into the
    content-addressed artifact store and return its SHA-256 artifact id.

    The file is hashed in place and copied verbatim into the store keyed by its
    digest, so identical bytes are never stored twice. Returns a dict with the
    ``artifact_id`` (equal to the SHA-256), the ``sha256`` digest, the byte
    ``size``, the container ``format`` (``dotnet`` for a managed .NET/CIL
    assembly, else ``pe`` / ``elf`` / ``macho`` / ``unknown``), and the ``packer``
    named from its watermark (e.g. ``UPX``, ``ConfuserEx``) or an empty string
    when no known watermark is present -- which means the sample is not named,
    not that it is unpacked. The format is also written to session state at
    :data:`SAMPLE_FORMAT_KEY` for the engine router.
    """
    resolved = Path(path).expanduser()
    if tool_context is not None:
        # This turn's acquisition OWNS the sample identity: invalidate any prior
        # sample up front so a FAILED acquire (missing/unreadable file) can never
        # leave the previous turn's format + artifact for the routers and analysis
        # stages to run on. store.acquire() below raises before the success block,
        # so without this a failed acquire silently inherits the last sample --
        # e.g. a missing native .exe getting routed and reported as a prior APK.
        # Repopulated below only on a successful acquire.
        tool_context.state[SAMPLE_FORMAT_KEY] = ""
        tool_context.state[SAMPLE_PACKER_KEY] = ""
        tool_context.state[SAMPLE_PACKER_PROMPT_KEY] = ""
        tool_context.state[SAMPLE_INTEL_KEY] = ""
        tool_context.state[SAMPLE_INTEL_PROMPT_KEY] = ""
        tool_context.state[SAMPLE_RELATIONS_KEY] = ""
        tool_context.state[SAMPLE_RELATIONS_PROMPT_KEY] = ""
        tool_context.state[CURRENT_ARTIFACT_KEY] = ""
    store = ArtifactStore(default_artifacts_root())
    artifact_id = store.acquire(resolved)
    size = resolved.stat().st_size
    sample_format = _detect_format(resolved)
    packer = _detect_packer(resolved)
    packer_name = str(packer["name"]) if packer["detected"] else ""
    if tool_context is not None:
        reset_deobfuscation_state(tool_context.state, artifact_id)
        reset_deep_analysis_state(tool_context.state)
        tool_context.state[SAMPLE_FORMAT_KEY] = sample_format
        tool_context.state[SAMPLE_PACKER_KEY] = packer_name
        tool_context.state[SAMPLE_PACKER_PROMPT_KEY] = _packer_prompt_line(packer)
        intel_line = _intel_line(artifact_id)
        tool_context.state[SAMPLE_INTEL_KEY] = intel_line
        tool_context.state[SAMPLE_INTEL_PROMPT_KEY] = intel_line
        relations_line = _relations_line(artifact_id)
        tool_context.state[SAMPLE_RELATIONS_KEY] = relations_line
        tool_context.state[SAMPLE_RELATIONS_PROMPT_KEY] = relations_line
    return {
        "artifact_id": artifact_id,
        "sha256": artifact_id,
        "size": size,
        "format": sample_format,
        "packer": packer_name,
    }


ACQUIRE_SAMPLE_TOOL = ToolDescriptor(
    id="acquire_sample",
    description=(
        "Ingest a binary sample from a local filesystem path into the "
        "content-addressed artifact store, classify its container format "
        "(dotnet/pe/elf/macho/dex/apk/jar/unknown), name its packer/protector "
        "from the watermark it carries, and return its SHA-256 artifact id."
    ),
    tool=acquire_sample,
    output_policy=OutputPolicy(max_chars=2_000, max_list_items=10),
)
