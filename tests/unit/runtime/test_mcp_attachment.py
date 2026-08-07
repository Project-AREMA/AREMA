"""An agent with mcp_server_ids resolves MCP toolsets into its tools."""

from __future__ import annotations

from typing import TYPE_CHECKING

from google.adk.tools.base_toolset import BaseToolset

from arema.core.config import Settings
from arema.registry.catalog import CatalogBuilder
from arema.registry.descriptors import (
    AgentDescriptor,
    McpServerDescriptor,
    RuntimeProfile,
    StdioTransport,
)
from arema.runtime.agent_factory import build_llm_agent, compose_agents
from arema.runtime.services import RuntimeServices

if TYPE_CHECKING:
    import pytest
    from google.adk.tools.base_tool import BaseTool

    from arema.runtime.sandbox.port import SandboxExecutor  # noqa: F401


class _FakeCheckpointSink:
    def append_checkpoint(self, *_args: object, **_kwargs: object) -> None:
        pass


def _settings() -> Settings:
    return Settings(_env_file=None, llm_provider="ollama")


class _SentinelToolset(BaseToolset):
    """A minimal BaseToolset instance ADK's tool validation will accept."""

    async def get_tools(self, _readonly_context: object = None) -> list[BaseTool]:
        return []


def test_agent_with_mcp_server_ids_has_the_toolset_in_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A sentinel returned by a stubbed build_mcp_toolset so we can assert it lands in
    # the agent's tools WITHOUT needing a live MCP server. It subclasses BaseToolset
    # because ADK's LlmAgent validates each entry in the tools list.
    sentinel = _SentinelToolset()

    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_mcp_server(
        McpServerDescriptor(
            id="stub_mcp",
            transport=StdioTransport(command="true", args=()),
        )
    )
    builder.add_agent(
        AgentDescriptor(
            id="mcp_agent",
            name="mcp_agent",
            description="An agent that delegates to an MCP server.",
            prompt_id="smoke_agent",
            factory=build_llm_agent,
            runtime_profile_id="safe_default",
            mcp_server_ids=("stub_mcp",),
        )
    )
    catalog = builder.freeze("mcp_agent")

    monkeypatch.setattr(
        "arema.runtime.agent_factory.build_mcp_toolset",
        lambda _descriptor, **_kw: sentinel,
    )

    built = compose_agents(
        catalog,
        settings=_settings(),
        services=RuntimeServices.default(),
        checkpoint_sink=_FakeCheckpointSink(),  # type: ignore[arg-type]
    )
    agent = built["mcp_agent"]

    assert sentinel in agent.tools


def test_agent_without_mcp_server_ids_is_unaffected() -> None:
    """Backward compatibility: agents without mcp_server_ids build exactly as before."""
    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_agent(
        AgentDescriptor(
            id="plain_agent",
            name="plain_agent",
            description="A plain agent.",
            prompt_id="smoke_agent",
            factory=build_llm_agent,
            runtime_profile_id="safe_default",
        )
    )
    catalog = builder.freeze("plain_agent")

    built = compose_agents(
        catalog,
        settings=_settings(),
        services=RuntimeServices.default(),
        checkpoint_sink=_FakeCheckpointSink(),  # type: ignore[arg-type]
    )

    assert built["plain_agent"].tools == []
