"""Compose the greeter welcome/router agent over the registered domains.

The greeter is intentionally a thin router, not a tool-bearing agent: it has no
AREMA function tools and therefore does not need the registered-tool guard,
output compactor, or per-tool memory callbacks that domain agents use. ADK
auto-generates a ``transfer_to_subagent`` tool per registered domain root, and
the model routes by invoking it. (AREMA's registered-tool guard only blocks
ADK's ``_unknown_tool_*`` stubs, so legitimate transfer tools pass through.)

Each domain is a self-contained composition (its own catalog, memory service,
and callback chains). The greeter simply holds the domains' root agents as ADK
sub-agents and lets ADK's delegation machinery move control between them.
"""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING

from google.adk.agents import LlmAgent

from arema.core.config import Settings, get_settings
from arema.core.model_factory import get_agent_model
from greeter_agent.prompts.loader import load_greeter_prompt

if TYPE_CHECKING:
    from google.adk.agents import BaseAgent


def _domain_roots() -> list[BaseAgent]:
    """Return the root agent of each registered domain, in display order.

    Domains are imported lazily so a missing/optional domain never breaks the
    greeter's import. Append a new domain here to make it routable.
    """
    from malware_analyst.composition import get_malware_analyst_composition

    return [
        get_malware_analyst_composition().root_agent,
    ]


def build_greeter_agent(settings: Settings | None = None) -> LlmAgent:
    """Build the greeter router agent over all registered domains."""
    resolved = settings if settings is not None else get_settings()
    return LlmAgent(
        name="greeter_agent",
        model=get_agent_model("greeter_agent", settings=resolved, use_retries=True),
        description=(
            "AREMA's welcome router. Greets the user and delegates each request "
            "to the appropriate specialist domain agent (e.g. malware_analyst)."
        ),
        instruction=load_greeter_prompt("greeter"),
        sub_agents=list(_domain_roots()),
    )


@lru_cache
def get_greeter_agent() -> LlmAgent:
    """Return the process-wide greeter agent, building it once."""
    return build_greeter_agent()
