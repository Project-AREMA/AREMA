"""Tests for the ilspy_mcp McpServerDescriptor.

The descriptor declares the ILSpy-MCP server the dotnet_decompile agent attaches
via ``mcp_server_ids=("ilspy_mcp",)``. The streamable-HTTP transport targets a
``kubectl port-forward`` to the .NET analysis pod; ``required=False`` lets an
unreachable server degrade to no-tools rather than crash the run. The
``tool_allowlist`` pins the read-only surface, withholding the one tool that
writes to disk and the two that scan a directory of assemblies.

The tool names were captured from a live ``tools/list`` against ILSpy-MCP v1.2.0,
not from its README (which groups two of them under the wrong headings).
"""

from __future__ import annotations

from arema.registry.descriptors import McpServerDescriptor, StreamableHttpTransport
from arema.registry.mcp import ResilientMcpToolset, build_mcp_toolset
from reverse_engineering.mcp import ILSPY_MCP

_ESSENTIAL_ANALYSIS_TOOLS = (
    "analyze_assembly",
    "list_assembly_types",
    "get_type_members",
    "decompile_type",
    "decompile_method",
    "search_strings",
    "find_usages",
)

_EXCLUDED_TOOLS = (
    # writes a decompiled .csproj tree into the pod
    "export_project",
    # directory-wide scans; a case holds exactly one artifact
    "load_assembly_directory",
    "resolve_type",
)


def test_descriptor_id_is_ilspy_mcp() -> None:
    assert ILSPY_MCP.id == "ilspy_mcp"


def test_transport_is_streamable_http_to_local_pod_forward() -> None:
    transport = ILSPY_MCP.transport
    assert isinstance(transport, StreamableHttpTransport)
    assert transport.url == "http://127.0.0.1:3001/mcp"
    assert transport.read_timeout == 600.0


def test_transport_port_differs_from_radare2() -> None:
    """Both engines are forwarded for the same case, so the ports must not clash."""
    from reverse_engineering.mcp import RADARE2_MCP

    ilspy = ILSPY_MCP.transport
    radare2 = RADARE2_MCP.transport
    assert isinstance(ilspy, StreamableHttpTransport)
    assert isinstance(radare2, StreamableHttpTransport)
    assert ilspy.url != radare2.url


def test_descriptor_is_optional() -> None:
    assert ILSPY_MCP.required is False


def test_descriptor_has_no_header_provider() -> None:
    assert ILSPY_MCP.header_provider is None


def test_allowlist_includes_essential_analysis_tools() -> None:
    for name in _ESSENTIAL_ANALYSIS_TOOLS:
        assert name in ILSPY_MCP.tool_allowlist, f"missing essential tool: {name}"


def test_allowlist_excludes_disk_writing_and_directory_wide_tools() -> None:
    for name in _EXCLUDED_TOOLS:
        assert name not in ILSPY_MCP.tool_allowlist, f"withheld tool present: {name}"


def test_allowlist_has_no_duplicate_entries() -> None:
    assert len(set(ILSPY_MCP.tool_allowlist)) == len(ILSPY_MCP.tool_allowlist)


def test_allowlist_size_pins_the_readonly_surface() -> None:
    """24 of the server's 27 tools; a silent drop/addition forces a deliberate edit."""
    assert len(ILSPY_MCP.tool_allowlist) == 24


def test_build_mcp_toolset_returns_resilient_toolset() -> None:
    assert isinstance(build_mcp_toolset(ILSPY_MCP, environment={}), ResilientMcpToolset)


def test_descriptor_is_a_mcp_server_descriptor() -> None:
    assert isinstance(ILSPY_MCP, McpServerDescriptor)
