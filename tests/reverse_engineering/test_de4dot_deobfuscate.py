from arema.runtime.agent_factory import build_llm_agent
from reverse_engineering.agents.de4dot_deobfuscate import DE4DOT_DEOBFUSCATE_DESCRIPTOR
from reverse_engineering.prompts.loader import load_domain_prompt


def test_descriptor_shape() -> None:
    d = DE4DOT_DEOBFUSCATE_DESCRIPTOR
    assert d.id == "de4dot_deobfuscate"
    assert d.name == "de4dot_deobfuscate"
    assert d.prompt_id == "de4dot_deobfuscate"
    assert d.factory is build_llm_agent
    assert d.runtime_profile_id == "re_guarded"
    assert d.tool_ids == ("de4dot_deobfuscate",)


def test_prompt_loads_and_requires_exactly_one_call() -> None:
    text = load_domain_prompt("de4dot_deobfuscate").lower()
    assert "de4dot_deobfuscate" in text
    assert "exactly one tool" in text
    assert "do not" in text
