"""Composition test: the scripted-unpacking workbench tools are registered.

Phase 0 registers ``run_python`` and ``register_unpacked_artifact`` as shared
reverse-engineering infrastructure through
:func:`reverse_engineering.composition.register_re_infrastructure`, so they are
present on every frozen domain catalog that registers that infrastructure -- even
though no agent references them yet (agent wiring is Phase 1). These tests verify
the registration lands on the real, frozen ``malware_analyst`` catalog (which
routes through ``register_re_infrastructure``) and that each descriptor carries
its deferred factory and bounded output policy, mirroring
``test_deobfuscation_tools_are_registered_with_bounded_output_policies``.
"""

from __future__ import annotations


def test_workbench_tools_are_registered_on_the_re_catalog() -> None:
    from malware_analyst.composition import get_malware_analyst_composition

    tools = get_malware_analyst_composition().catalog.tools

    assert {"run_python", "register_unpacked_artifact"} <= tools.keys()


def test_workbench_tool_descriptors_bind_their_factories_and_policies() -> None:
    from malware_analyst.composition import get_malware_analyst_composition
    from reverse_engineering.tools.workbench.register import (
        build_register_unpacked_artifact,
    )
    from reverse_engineering.tools.workbench.run_python import build_run_python

    tools = get_malware_analyst_composition().catalog.tools

    run_python = tools["run_python"]
    assert run_python.factory is build_run_python
    assert run_python.tool is None
    assert run_python.output_policy.max_chars == 32_000
    assert run_python.output_policy.max_list_items == 200

    register = tools["register_unpacked_artifact"]
    assert register.factory is build_register_unpacked_artifact
    assert register.tool is None
    assert register.output_policy.max_chars == 2_000
    assert register.output_policy.max_list_items == 10


def test_scripted_recover_is_in_the_loop_between_recover_and_retriage() -> None:
    from reverse_engineering.agents.deobfuscation import DEOBFUSCATION_LOOP_DESCRIPTOR

    ids = DEOBFUSCATION_LOOP_DESCRIPTOR.sub_agent_ids
    assert ids == (
        "deobf_classify",
        "recover",
        "scripted_recover",
        "dotnet_scripted_recover",
        "retriage",
        "deobf_gate",
    )


def test_workbench_agents_freeze_and_compose_in_the_domain() -> None:
    from arema.core.config import Settings
    from malware_analyst.composition import build_malware_analyst_composition

    composition = build_malware_analyst_composition(Settings(_env_file=None, llm_provider="ollama"))
    ids = set(composition.catalog.agents)
    assert {
        "scripted_recover",
        "packer_analyst",
        "dotnet_scripted_recover",
        "dotnet_analyst",
    } <= ids


def test_run_python_is_membrane_framed_for_the_workbench() -> None:
    # Phase 0 added the workbench tools to the binary-origin set; assert it holds so
    # freshly-decrypted malware strings are framed as untrusted data (spec §5.1).
    from reverse_engineering.profiles import _BINARY_ORIGIN_TOOLS

    assert {"run_python", "register_unpacked_artifact"} <= _BINARY_ORIGIN_TOOLS


def test_dnlib_roundtrip_is_the_last_recover_sub_agent_after_de4dot() -> None:
    from reverse_engineering.agents.format_gate import DOTNET_RECOVER_DESCRIPTOR
    from reverse_engineering.agents.recover import RECOVER_DESCRIPTOR

    # The .NET-specific recovery (de4dot then dnlib) is now gated behind the
    # managed-only dotnet_recover, which is the last child of recover. Within it, the
    # deterministic dnlib metadata round-trip runs AFTER de4dot and is the last
    # deterministic recover step before the agentic dotnet_scripted_recover escalates.
    assert RECOVER_DESCRIPTOR.sub_agent_ids[-1] == "dotnet_recover"
    assert DOTNET_RECOVER_DESCRIPTOR.sub_agent_ids == ("de4dot_deobfuscate", "dnlib_roundtrip")


def test_de4dot_deobfuscate_agent_is_in_the_frozen_malware_analyst_catalog() -> None:
    from malware_analyst.composition import get_malware_analyst_composition

    ids = set(get_malware_analyst_composition().catalog.agents)
    assert "de4dot_deobfuscate" in ids
