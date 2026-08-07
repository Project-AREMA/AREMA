"""MCP server descriptors exposed by the reverse-engineer domain agents."""

from __future__ import annotations

from reverse_engineering.mcp.ilspy import ILSPY_MCP
from reverse_engineering.mcp.radare2 import RADARE2_MCP

__all__ = ["ILSPY_MCP", "RADARE2_MCP"]
