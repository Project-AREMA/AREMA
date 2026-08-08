from arema.runtime.agent_factory import build_llm_agent
from reverse_engineering.agents.packer_analyst import PACKER_ANALYST_DESCRIPTOR
from reverse_engineering.prompts.loader import load_domain_prompt


def test_descriptor_shape() -> None:
    d = PACKER_ANALYST_DESCRIPTOR
    assert d.id == "packer_analyst"
    assert d.name == "packer_analyst"
    assert d.prompt_id == "packer_analyst"
    assert d.factory is build_llm_agent
    assert d.runtime_profile_id == "re_guarded"
    # prepare_sandbox first: an agent that uses an engine must be able to
    # establish it (LESSONS_LEARNED #6). This stage runs deep in the
    # deobfuscation loop, minutes after intake opened the radare2 tunnel.
    assert d.tool_ids == ("prepare_sandbox", "run_python", "register_unpacked_artifact")
    assert d.mcp_server_ids == ("radare2_mcp",)


def test_prompt_loads_and_is_defensively_framed() -> None:
    text = load_domain_prompt("packer_analyst").lower()
    # Defensively framed, exposes its two tools, and grounds any execution in the
    # disposable egress-denied sandbox (the sandbox isolation is the safety boundary).
    assert "run_python" in text
    assert "register_unpacked_artifact" in text
    assert "authorized" in text and "defensive" in text
    assert "sandbox" in text


def test_prompt_qualifies_the_die_database_path() -> None:
    """DIE's default database path silently detects nothing.

    Measured in the analysis-workbench pod on a UPX-packed ELF: ``scan_file`` with
    ``database=None`` and with ``database=die.database_path`` both return ``Unknown``;
    only ``database=die.database_path / "db"`` returns ``Packer: UPX(...)``. The
    signature root sits one level below where die-python points by default, so an
    unqualified call is a false negative on every packer, with no error raised.
    """
    text = load_domain_prompt("packer_analyst")
    assert 'die.database_path / "db"' in text
