from arema.runtime.agent_factory import build_llm_agent
from reverse_engineering.agents.dotnet_analyst import DOTNET_ANALYST_DESCRIPTOR
from reverse_engineering.prompts.loader import load_domain_prompt


def test_descriptor_shape() -> None:
    d = DOTNET_ANALYST_DESCRIPTOR
    assert d.id == "dotnet_analyst" and d.prompt_id == "dotnet_analyst"
    assert d.factory is build_llm_agent and d.runtime_profile_id == "re_deep_agentic"
    assert d.tool_ids == ("run_python", "register_unpacked_artifact")
    assert d.mcp_server_ids == ()


def test_prompt_loads_and_is_defensively_framed() -> None:
    t = load_domain_prompt("dotnet_analyst").lower()
    assert "de4dot" in t and "dnlib" in t and "register_unpacked_artifact" in t and "do not" in t
