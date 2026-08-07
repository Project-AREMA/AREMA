"""Drift guard pinning the evidence_critic citation allowlist to its descriptors.

Rule 1 of ``evidence_critic.md`` ("Citation present + valid") carries a literal
allowlist of known analysis tool names and instructs the model to REJECT any
finding whose ``tool`` is not in it. That list is a hand-maintained mirror of the
MCP descriptors' ``tool_allowlist`` tuples plus the non-MCP recovery tools. If the
descriptor gains a tool the prompt does not name, every finding citing that tool
is silently rejected; if the prompt names a tool the descriptor dropped, the gate
accepts a citation the agent can no longer produce. These assertions fail the
build the moment the prompt and descriptors diverge in either direction.
"""

from __future__ import annotations

from reverse_engineering.mcp import ILSPY_MCP, RADARE2_MCP
from reverse_engineering.prompts.loader import load_domain_prompt

# Recovery tools are not MCP tools (they are local deobfuscation helpers), so
# there is no descriptor allowlist to pin them to — hardcode the expected names.
RECOVERY_TOOLS = ("upx_unpack", "floss_decode")


def _cited(prompt: str, tool: str) -> bool:
    """A tool is cited when it appears as a backtick-wrapped name in the prompt."""
    return f"`{tool}`" in prompt


def test_ilspy_allowlist_is_pinned_to_the_prompt() -> None:
    prompt = load_domain_prompt("evidence_critic")
    missing = [tool for tool in ILSPY_MCP.tool_allowlist if not _cited(prompt, tool)]
    assert not missing, f"ILSpy tools absent from evidence_critic rule 1: {missing}"


def test_radare2_allowlist_is_pinned_to_the_prompt() -> None:
    prompt = load_domain_prompt("evidence_critic")
    missing = [tool for tool in RADARE2_MCP.tool_allowlist if not _cited(prompt, tool)]
    assert not missing, f"radare2 tools absent from evidence_critic rule 1: {missing}"


def test_recovery_tools_are_present() -> None:
    prompt = load_domain_prompt("evidence_critic")
    missing = [tool for tool in RECOVERY_TOOLS if not _cited(prompt, tool)]
    assert not missing, f"recovery tools absent from evidence_critic rule 1: {missing}"
