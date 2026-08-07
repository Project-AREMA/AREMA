"""The no-tools infrastructure smoke agent.

This agent proves the runtime is wired end to end -- model connection, session
state, context policies, resilience callbacks, and memory health -- while
claiming no tools, MCP servers, sub-agents, or analysis capabilities. Its
descriptor is the single root of the default composition.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_llm_agent

if TYPE_CHECKING:
    from google.adk.agents import BaseAgent

    from arema.runtime.agent_factory import AgentBuildContext

SMOKE_AGENT_ID = "smoke_agent"
SMOKE_AGENT_PROMPT_ID = "smoke_agent"


def build_smoke_agent(context: AgentBuildContext) -> BaseAgent:
    """Build the smoke agent as a plain ADK ``LlmAgent`` from its context."""
    return build_llm_agent(context)


SMOKE_AGENT_DESCRIPTOR = AgentDescriptor(
    id=SMOKE_AGENT_ID,
    name=SMOKE_AGENT_ID,
    description=(
        "Domain-neutral infrastructure smoke agent that verifies the runtime is "
        "operational and holds no tools, servers, or sub-agents."
    ),
    prompt_id=SMOKE_AGENT_PROMPT_ID,
    factory=build_smoke_agent,
    runtime_profile_id="safe_default",
)
