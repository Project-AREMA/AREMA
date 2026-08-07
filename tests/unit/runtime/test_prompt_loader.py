"""An agent descriptor may carry its own ``prompt_loader`` to resolve instructions
from a peer domain package instead of the core ``arema.prompts`` package."""

from __future__ import annotations

from arema.core.config import Settings
from arema.registry.catalog import CatalogBuilder
from arema.registry.descriptors import AgentDescriptor, RuntimeProfile
from arema.runtime.agent_factory import build_llm_agent, compose_agents
from arema.runtime.services import RuntimeServices


class _FakeCheckpointSink:
    def append_checkpoint(self, *_args: object, **_kwargs: object) -> None:
        pass


def _settings() -> Settings:
    return Settings(_env_file=None, llm_provider="ollama")


def test_prompt_loader_resolves_the_instruction() -> None:
    def custom_loader(prompt_id: str) -> str:
        return f"CUSTOM-INSTRUCTION-FOR-{prompt_id}"

    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_agent(
        AgentDescriptor(
            id="domain_agent",
            name="domain_agent",
            description="An agent whose prompt is resolved by a custom loader.",
            prompt_id="triage",
            factory=build_llm_agent,
            runtime_profile_id="safe_default",
            prompt_loader=custom_loader,
        )
    )
    catalog = builder.freeze("domain_agent")

    built = compose_agents(
        catalog,
        settings=_settings(),
        services=RuntimeServices.default(),
        checkpoint_sink=_FakeCheckpointSink(),  # type: ignore[arg-type]
    )

    assert built["domain_agent"].instruction == "CUSTOM-INSTRUCTION-FOR-triage"


def test_agent_without_prompt_loader_uses_core_loader() -> None:
    """Backward compatibility: no prompt_loader falls back to the core loader."""
    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_agent(
        AgentDescriptor(
            id="plain_agent",
            name="plain_agent",
            description="A plain agent.",
            prompt_id="smoke_agent",
            factory=build_llm_agent,
            runtime_profile_id="safe_default",
        )
    )
    catalog = builder.freeze("plain_agent")

    built = compose_agents(
        catalog,
        settings=_settings(),
        services=RuntimeServices.default(),
        checkpoint_sink=_FakeCheckpointSink(),  # type: ignore[arg-type]
    )

    assert "smoke agent" in built["plain_agent"].instruction.lower()
