"""Tests for the radare2_mcp McpServerDescriptor.

The descriptor declares the r2mcp server the TriageRecon agent (Task 7) attaches
via ``mcp_server_ids=("radare2_mcp",)``. The streamable-HTTP transport targets a
``kubectl port-forward`` to the analysis pod; ``required=False`` lets an
unreachable server degrade to no-tools rather than crash the run. The
``tool_allowlist`` pins the read-only surface the agent may call (defense in
depth in case a future image change adds mutating/exec tools).
"""

from __future__ import annotations

from arema.registry.descriptors import McpServerDescriptor, StreamableHttpTransport
from arema.registry.mcp import ResilientMcpToolset, build_mcp_toolset
from reverse_engineering.mcp import RADARE2_MCP

_ESSENTIAL_ANALYSIS_TOOLS = (
    "open_file",
    "analyze",
    "list_functions",
    "decompile_function",
    "list_strings",
    "show_info",
    "xrefs_to",
)

_EXCLUDED_TOOLS = (
    "run_command",
    "run_javascript",
    "run_frida_script",
    "rename_function",
    "rename_flag",
    "set_comment",
    "memory_map_here",
    "search",
    "dump_registers",
)


def test_descriptor_id_is_radare2_mcp() -> None:
    assert RADARE2_MCP.id == "radare2_mcp"


def test_transport_is_streamable_http_to_local_pod_forward() -> None:
    transport = RADARE2_MCP.transport
    assert isinstance(transport, StreamableHttpTransport)
    assert transport.url == "http://127.0.0.1:8765/mcp"
    # 600s accommodates r2 `analyze` (aaa) on large binaries (e.g. httpd at 1.7 MB
    # takes 2-4 min). A shorter timeout fires mid-analysis → MCP session drops →
    # r2mcp loses its open_file state → crash. See the comment in radare2.py.
    assert transport.read_timeout == 600.0


def test_descriptor_is_optional() -> None:
    assert RADARE2_MCP.required is False


def test_descriptor_has_no_header_provider() -> None:
    assert RADARE2_MCP.header_provider is None


def test_allowlist_includes_essential_analysis_tools() -> None:
    allowlist = RADARE2_MCP.tool_allowlist
    for name in _ESSENTIAL_ANALYSIS_TOOLS:
        assert name in allowlist, f"missing essential tool: {name}"


def test_allowlist_excludes_mutating_and_exec_tools() -> None:
    allowlist = RADARE2_MCP.tool_allowlist
    for name in _EXCLUDED_TOOLS:
        assert name not in allowlist, f"dangerous tool present in allowlist: {name}"


def test_allowlist_has_no_duplicate_entries() -> None:
    allowlist = RADARE2_MCP.tool_allowlist
    assert len(set(allowlist)) == len(allowlist)


def test_allowlist_size_pins_the_readonly_surface() -> None:
    """Pin the allowlist size so a silent drop/addition forces a deliberate edit."""
    assert len(RADARE2_MCP.tool_allowlist) == 31


def test_build_mcp_toolset_returns_resilient_toolset() -> None:
    toolset = build_mcp_toolset(RADARE2_MCP, environment={})
    assert isinstance(toolset, ResilientMcpToolset)


def test_descriptor_is_a_mcp_server_descriptor() -> None:
    assert isinstance(RADARE2_MCP, McpServerDescriptor)
