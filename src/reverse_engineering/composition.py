"""Registration seam for the reverse-engineering capability library.

Mindset domains (``malware_analyst``, future ``vuln_research``) call
:func:`register_re_infrastructure` to add the shared RE infrastructure — runtime
profiles, ingest/engine tools, the radare2 MCP server, and the finding codec — to
their own catalog builder. The domain then adds the agents it actually uses
(generic RE descriptors imported from here, plus its mindset lenses) and freezes
on its own root. This helper registers NO agents, so a domain never hits an
unreachable-agent catalog error from unused capability agents.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from arema.registry.descriptors import RuntimeProfile, StreamableHttpTransport
from reverse_engineering.evidence import FINDING_CODEC
from reverse_engineering.mcp.ilspy import ILSPY_MCP
from reverse_engineering.mcp.radare2 import RADARE2_MCP
from reverse_engineering.profiles import (
    EVIDENCE_ISOLATED_PROFILE,
    RE_DEEP_AGENTIC_PROFILE,
    RE_GUARDED_PROFILE,
)
from reverse_engineering.tools.acquire_by_hash import ACQUIRE_SAMPLE_BY_HASH_TOOL
from reverse_engineering.tools.acquire_sample import ACQUIRE_SAMPLE_TOOL
from reverse_engineering.tools.android.native_libs import EXTRACT_ANDROID_NATIVE_LIBS_TOOL
from reverse_engineering.tools.android.triage_scan import ANDROID_TRIAGE_SCAN_TOOL
from reverse_engineering.tools.deobfuscation.toolset import DEOBFUSCATION_TOOLSET
from reverse_engineering.tools.ghidra.prepare_ghidra import PREPARE_GHIDRA_TOOL
from reverse_engineering.tools.ghidra.toolset import build_ghidra_toolset
from reverse_engineering.tools.jadx.prepare_jadx import PREPARE_JADX_TOOL
from reverse_engineering.tools.jadx.toolset import build_jadx_toolset
from reverse_engineering.tools.prepare_ilspy import PREPARE_ILSPY_TOOL
from reverse_engineering.tools.prepare_sandbox import PREPARE_SANDBOX_TOOL
from reverse_engineering.tools.workbench.register import REGISTER_UNPACKED_ARTIFACT_TOOL
from reverse_engineering.tools.workbench.run_python import RUN_PYTHON_TOOL

if TYPE_CHECKING:
    from arema.core.config import Settings
    from arema.memory.codecs import RecordCodecRegistry
    from arema.registry.catalog import CatalogBuilder

# Ceiling for radare2's MCP read timeout (seconds). radare2 is the fast triage
# engine; a single call that runs longer than this is pathological (e.g. CIL
# auto-analysis on a packed .NET assembly), so it should fail and let the stage
# degrade rather than hold the session for the full global timeout.
_RADARE2_MAX_READ_TIMEOUT = 300.0


def register_re_infrastructure(
    builder: CatalogBuilder,
    codecs: RecordCodecRegistry,
    settings: Settings,
) -> None:
    """Register the shared RE infrastructure (profiles, tools, MCP, codec).

    Adds the ``safe_default`` + ``re_guarded`` + ``evidence_isolated`` profiles,
    ingest/engine and stateless deobfuscation tools, the scripted-unpacking
    workbench tools (``run_python`` + ``register_unpacked_artifact``), the radare2
    MCP server with its read_timeout taken from *settings*, and the finding codec.
    Adds NO agents — the caller registers the agents it reaches.
    """
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_runtime_profile(RE_GUARDED_PROFILE)
    builder.add_runtime_profile(RE_DEEP_AGENTIC_PROFILE)
    builder.add_runtime_profile(EVIDENCE_ISOLATED_PROFILE)
    builder.add_tool(ACQUIRE_SAMPLE_TOOL)
    builder.add_tool(ACQUIRE_SAMPLE_BY_HASH_TOOL)
    builder.add_tool(PREPARE_SANDBOX_TOOL)
    builder.add_tool(PREPARE_GHIDRA_TOOL)
    builder.add_tool(PREPARE_ILSPY_TOOL)
    for desc in DEOBFUSCATION_TOOLSET:
        builder.add_tool(desc)
    for desc in build_ghidra_toolset():
        builder.add_tool(desc)
    builder.add_tool(PREPARE_JADX_TOOL)
    for desc in build_jadx_toolset():
        builder.add_tool(desc)
    builder.add_tool(ANDROID_TRIAGE_SCAN_TOOL)
    builder.add_tool(EXTRACT_ANDROID_NATIVE_LIBS_TOOL)
    # Scripted-unpacking workbench tools (Phase 0). Registered as shared RE
    # infrastructure so a frozen domain catalog resolves them; no agent references
    # them yet -- the `scripted_recover` stage that drives them arrives in Phase 1.
    builder.add_tool(RUN_PYTHON_TOOL)
    builder.add_tool(REGISTER_UNPACKED_ARTIFACT_TOOL)
    for mcp in (RADARE2_MCP, ILSPY_MCP):
        transport = mcp.transport
        assert isinstance(transport, StreamableHttpTransport)
        # radare2 is the fast triage/recon engine; the deep, slow analysis is
        # Ghidra's job (with its own deadline). Cap radare2's read timeout so a
        # pathological call -- e.g. `analyze`/`list_functions` kicking off CIL
        # auto-analysis on a packed .NET assembly -- fails in minutes and the
        # stage degrades gracefully, instead of holding the session for the full
        # 1200s and stalling the whole pipeline. ILSpy keeps the full timeout
        # because a large assembly's decompilation is legitimately slow.
        read_timeout = settings.mcp_read_timeout
        if mcp is RADARE2_MCP:
            read_timeout = min(read_timeout, _RADARE2_MAX_READ_TIMEOUT)
        builder.add_mcp_server(
            replace(mcp, transport=replace(transport, read_timeout=read_timeout))
        )
    codecs.register(FINDING_CODEC)
