"""The dotnet_decompile worker descriptor + prompt resolve correctly.

``dotnet_decompile`` is the ILSpy counterpart of ``deep_decompile``: it drives the
``ilspy_mcp`` toolset to reconstruct C# from a .NET/CIL assembly and writes the
shared ``deep_evidence_json`` slot. A deterministic ``deep_engine_router`` now
guarantees the stage runs only on .NET samples, so the prompt must NOT carry any
stand-down / "not a .NET" / "skipped" routing gate (regression guard below).
"""

from __future__ import annotations

import pytest

from reverse_engineering.agents.dotnet_decompile import DOTNET_DECOMPILE_DESCRIPTOR
from reverse_engineering.prompts.loader import load_domain_prompt


def test_dotnet_decompile_descriptor_well_formed() -> None:
    assert DOTNET_DECOMPILE_DESCRIPTOR.id == "dotnet_decompile"
    assert DOTNET_DECOMPILE_DESCRIPTOR.name == "dotnet_decompile"
    assert DOTNET_DECOMPILE_DESCRIPTOR.prompt_id == "dotnet_decompile"
    assert DOTNET_DECOMPILE_DESCRIPTOR.runtime_profile_id == "re_guarded"


def test_dotnet_decompile_descriptor_writes_shared_deep_evidence_slot() -> None:
    assert DOTNET_DECOMPILE_DESCRIPTOR.output_key == "deep_evidence_json"


def test_dotnet_decompile_has_no_output_schema_but_normalizes_via_callback() -> None:
    """output_schema + tools is an unreliable ADK combination; this agent relies
    on its after-agent evidence normalizer to parse the model's raw text instead."""
    assert DOTNET_DECOMPILE_DESCRIPTOR.output_schema is None
    assert len(DOTNET_DECOMPILE_DESCRIPTOR.after_agent_callbacks) == 1


def test_dotnet_decompile_binds_ilspy_toolset_plus_prepare_ilspy() -> None:
    """ILSpy is attached as an MCP toolset; prepare_ilspy re-copies the CURRENT
    (possibly recovered) artifact into the pod before decompiling, mirroring how
    deep_decompile carries prepare_ghidra. Without it the stage would always
    analyse the protected original rather than the deobfuscation-loop recovery."""
    assert DOTNET_DECOMPILE_DESCRIPTOR.mcp_server_ids == ("ilspy_mcp",)
    assert DOTNET_DECOMPILE_DESCRIPTOR.tool_ids == ("prepare_ilspy",)


@pytest.fixture
def dotnet_prompt() -> str:
    return load_domain_prompt("dotnet_decompile")


def test_prompt_drives_ilspy(dotnet_prompt: str) -> None:
    assert "ILSpy" in dotnet_prompt
    assert "analyze_assembly" in dotnet_prompt
    for tool_name in ("decompile_type", "decompile_method", "search_strings"):
        assert tool_name in dotnet_prompt


def test_prompt_requires_the_dll_assembly_path(dotnet_prompt: str) -> None:
    """Every ILSpy tool takes the exact ``/app/<sha256>.dll`` path intake reported."""
    assert "assembly_path" in dotnet_prompt
    assert "assemblyPath" in dotnet_prompt
    assert ".dll" in dotnet_prompt
    assert "/app/<sha256>.dll" in dotnet_prompt


def test_prompt_requires_a_single_evidence_envelope_json(dotnet_prompt: str) -> None:
    assert "EvidenceEnvelope" in dotnet_prompt
    for field in ("artifact_id", "coverage", "surfaces", "limitations", "findings"):
        assert field in dotnet_prompt
    for finding_field in ("claim", "tool", "confidence", "detail", "kind"):
        assert finding_field in dotnet_prompt
    # The unavailable path returns the bounded limitation, not a skipped finding.
    assert "deep:ilspy_unavailable" in dotnet_prompt


def test_prompt_has_no_standdown_routing_gate(dotnet_prompt: str) -> None:
    """Regression guard: the deep_engine_router owns routing now.

    The stage runs only on .NET samples, so the prompt must never tell the agent
    to stand down or record a "skipped because not a .NET assembly" finding.
    """
    lowered = dotnet_prompt.lower()
    for forbidden in ("stand down", "stood down", "skipped", "skip", "not a .net"):
        assert forbidden not in lowered
