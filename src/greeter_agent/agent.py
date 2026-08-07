"""ADK discovery entry point for the greeter (welcome router) agent."""

from __future__ import annotations

from greeter_agent.composition import get_greeter_agent

root_agent = get_greeter_agent()

__all__ = ["root_agent"]
