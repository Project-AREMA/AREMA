"""Tests for the greeter welcome/router agent.

The greeter is a thin router: it holds the registered domain root agents as ADK
sub-agents and delegates via ADK's auto-generated transfer tools. It owns no
function tools itself.
"""

from __future__ import annotations

from greeter_agent.composition import build_greeter_agent, get_greeter_agent
from greeter_agent.prompts.loader import load_greeter_prompt


def test_greeter_agent_is_named_and_cached() -> None:
    get_greeter_agent.cache_clear()
    first = get_greeter_agent()
    second = get_greeter_agent()

    assert first.name == "greeter_agent"
    assert first is second


def test_greeter_has_malware_analyst_as_subagent() -> None:
    agent = build_greeter_agent()

    sub_names = {sub.name for sub in agent.sub_agents}
    assert "malware_analyst" in sub_names


def test_greeter_has_no_function_tools_of_its_own() -> None:
    agent = build_greeter_agent()

    # The greeter routes via ADK's auto-generated transfer tools only; it has no
    # AREMA function tools (acquire_sample/prepare_sandbox live on sample_intake,
    # a stage of a malware_analyst pipeline).
    assert agent.tools == []


def test_greeter_prompt_loads() -> None:
    instruction = build_greeter_agent().instruction

    assert instruction is not None
    assert "malware_analyst" in load_greeter_prompt("greeter")


def test_adk_entry_exposes_root_agent() -> None:
    # ADK discovers agents from src/; greeter_agent.agent exposes root_agent.
    import greeter_agent.agent as greeter

    assert greeter.root_agent.name == "greeter_agent"
