"""header_provider plumbing for the resilient MCP toolset + descriptor."""

from __future__ import annotations

from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams
from mcp import StdioServerParameters

from arema.registry.descriptors import McpServerDescriptor, StdioTransport
from arema.registry.mcp import ResilientMcpToolset, build_mcp_toolset


def _stdio_params() -> StdioConnectionParams:
    return StdioConnectionParams(
        server_params=StdioServerParameters(command="true", args=[]),
        timeout=5.0,
    )


def test_resilient_toolset_accepts_header_provider() -> None:
    def hp(_ctx: object) -> dict[str, str]:
        return {"X-Test": "v"}

    toolset = ResilientMcpToolset(
        descriptor_id="test",
        required=False,
        connection_params=_stdio_params(),
        header_provider=hp,
    )

    assert toolset.required is False
    # ADK's McpToolset stores the provider privately; reaching here proves the kwarg
    # was forwarded (super() would TypeError on an unexpected keyword otherwise).
    assert toolset._header_provider is hp


def test_resilient_toolset_header_provider_defaults_none() -> None:
    toolset = ResilientMcpToolset(
        descriptor_id="test",
        required=False,
        connection_params=_stdio_params(),
    )

    assert toolset._header_provider is None


def test_descriptor_carries_optional_header_provider() -> None:
    def hp(_ctx: object) -> dict[str, str]:
        return {"X-Sandbox-Port": "8765"}

    descriptor = McpServerDescriptor(
        id="radare2_mcp",
        transport=StdioTransport(command="true", args=()),
        header_provider=hp,
    )

    assert descriptor.header_provider is hp


def test_descriptor_header_provider_defaults_none() -> None:
    descriptor = McpServerDescriptor(
        id="radare2_mcp",
        transport=StdioTransport(command="true", args=()),
    )

    assert descriptor.header_provider is None


def test_build_mcp_toolset_forwards_header_provider() -> None:
    def hp(_ctx: object) -> dict[str, str]:
        return {"X-Sandbox-Port": "8765"}

    descriptor = McpServerDescriptor(
        id="radare2_mcp",
        transport=StdioTransport(command="true", args=()),
        header_provider=hp,
    )

    toolset = build_mcp_toolset(descriptor)

    assert isinstance(toolset, ResilientMcpToolset)
    assert toolset._header_provider is hp
