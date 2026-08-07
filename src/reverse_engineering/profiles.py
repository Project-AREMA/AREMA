"""Domain runtime profiles for the reverse-engineering agents.

``re_guarded`` extends ``safe_default`` with the SanitizationMembrane
after_tool callback so binary-origin tool output is framed + redacted before it
reaches the model context. Its ``binary_origin_tools`` is the union of every
engine surface that returns bytes, text, or names taken out of the sample --
radare2, ILSpy, Ghidra, jadx, androguard, the deobfuscation tools and the
workbench. Each set is derived from that engine's own descriptor or command
table rather than hand-listed, so a tool added to an engine is sanitized by
construction instead of by remembering.

The rule for deciding membership is simply: does this tool's output contain
anything the sample's author chose? If yes, it belongs here. A decompiler's
output qualifies as much as a string dump does -- identifiers, literals and
resource names are all attacker-authored, and a decompiler faithfully reproduces
them.
"""

from __future__ import annotations

from dataclasses import replace

from arema.registry.descriptors import ContextMode, RuntimeProfile
from arema.runtime.callbacks.sanitization import (
    StructuralSanitizer,
    make_sanitizing_after_tool,
)
from reverse_engineering.mcp import ILSPY_MCP, RADARE2_MCP
from reverse_engineering.tools.android.native_libs import EXTRACT_ANDROID_NATIVE_LIBS_TOOL
from reverse_engineering.tools.android.triage_scan import ANDROID_TRIAGE_SCAN_TOOL
from reverse_engineering.tools.deobfuscation.toolset import DEOBFUSCATION_TOOL_NAMES
from reverse_engineering.tools.ghidra.commands import GHIDRA_COMMANDS
from reverse_engineering.tools.jadx.commands import JADX_COMMANDS
from reverse_engineering.tools.workbench.state import WORKBENCH_TOOL_NAMES
from reverse_engineering.tools.workbench.thrash import (
    advise_on_thrash,
    record_run_python_thrash,
)

_R2_BINARY_TOOLS = frozenset(RADARE2_MCP.tool_allowlist)
# ILSpy reads a hostile .NET assembly and hands back its contents: decompiled C#,
# IL, type and member names, embedded resources, and string-table entries. Every
# one of those is authored by whoever built the sample. Measured on a live
# QuasarRAT run, this was the last unframed path into the model -- 17 of 17
# responses, 23,189 characters -- and one of the type names it returned was
# literally `SkiDzEX : https://discord.gg/...`, an attacker-chosen string sitting
# where an identifier belongs. It was latent only because ILSpy had never
# successfully run; the .NET native pivot made it real.
_ILSPY_BINARY_TOOLS = frozenset(ILSPY_MCP.tool_allowlist)
_GHIDRA_BINARY_TOOLS = frozenset(spec.name for spec in GHIDRA_COMMANDS)
_JADX_BINARY_TOOLS = frozenset(spec.name for spec in JADX_COMMANDS)
# androguard parses a hostile APK inside the deobf pod; its structured triage
# output (package/permissions/URLs/packer signals) is attacker-derived, so it is
# framed as untrusted, tool-derived data before it reaches the model.
# ``extract_android_native_libs`` echoes attacker-controlled ``.so`` file names
# out of the APK, so its output is framed the same way.
_ANDROID_BINARY_TOOLS = frozenset(
    {ANDROID_TRIAGE_SCAN_TOOL.id, EXTRACT_ANDROID_NATIVE_LIBS_TOOL.id}
)
# ``run_python`` is the single highest-risk prompt-injection surface in the
# pipeline: its stdout is where freshly-decrypted malware strings first appear in
# cleartext, and ``register_unpacked_artifact`` hands a recovered payload
# downstream. Both are inside the SanitizationMembrane so their output is framed as
# untrusted, tool-derived data before it ever reaches the model (spec §5.1).
_BINARY_ORIGIN_TOOLS = (
    _R2_BINARY_TOOLS
    | _ILSPY_BINARY_TOOLS
    | _GHIDRA_BINARY_TOOLS
    | _JADX_BINARY_TOOLS
    | _ANDROID_BINARY_TOOLS
    | DEOBFUSCATION_TOOL_NAMES
    | WORKBENCH_TOOL_NAMES
)

RE_GUARDED_PROFILE: RuntimeProfile = replace(
    RuntimeProfile.safe_default(),
    id="re_guarded",
    extra_after_tool=(make_sanitizing_after_tool(StructuralSanitizer(), _BINARY_ORIGIN_TOOLS),),
)

# Deep-agentic analyst profile: re_guarded PLUS the thrash detector. The Monitor
# is placed BEFORE the SanitizationMembrane so it classifies run_python's raw
# stderr; the sanitizer (which frames binary-origin output) still runs after it
# and stays inside the always-last compactor. Scoped to dotnet_analyst so the
# other re_guarded agents are unaffected.
RE_DEEP_AGENTIC_PROFILE: RuntimeProfile = replace(
    RE_GUARDED_PROFILE,
    id="re_deep_agentic",
    extra_after_tool=(record_run_python_thrash, *RE_GUARDED_PROFILE.extra_after_tool),
    extra_before_model=(advise_on_thrash,),
)

# Tool-less evidence consumers (host/network/behavior/ATT&CK/critic/report) run
# with no conversation history so ambient prior messages can never become
# authoritative evidence; their only authority is named session state.
EVIDENCE_ISOLATED_PROFILE: RuntimeProfile = replace(
    RuntimeProfile.safe_default(),
    id="evidence_isolated",
    context_mode=ContextMode.ISOLATED,
)
