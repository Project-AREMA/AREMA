"""The explicit, curated deobfuscation toolset."""

from __future__ import annotations

from reverse_engineering.tools.deobfuscation.dnlib_roundtrip import DNLIB_ROUNDTRIP_TOOL
from reverse_engineering.tools.deobfuscation.dotnet import DE4DOT_DEOBFUSCATE_TOOL
from reverse_engineering.tools.deobfuscation.floss import FLOSS_DECODE_TOOL
from reverse_engineering.tools.deobfuscation.upx import UPX_UNPACK_TOOL

DEOBFUSCATION_TOOLSET = (
    UPX_UNPACK_TOOL,
    FLOSS_DECODE_TOOL,
    DE4DOT_DEOBFUSCATE_TOOL,
    DNLIB_ROUNDTRIP_TOOL,
)
DEOBFUSCATION_TOOL_NAMES = frozenset(tool.id for tool in DEOBFUSCATION_TOOLSET)
