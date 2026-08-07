"""Component tests for the no-tools AREMA smoke composition.

These assert the composed root agent is a plain ADK ``LlmAgent`` with no
capabilities, the canonical guarded before-model order, history context mode,
the mandatory unregistered-tool error handler, and package-relative prompt
loading that works from an installed wheel.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from google.adk.agents import LlmAgent

from arema.composition import (
    ApplicationComposition,
    build_default_composition,
    get_default_composition,
)
from arema.core.config import Settings
from arema.prompts.loader import load_prompt
from arema.runtime.callbacks.roles import callback_role

_EXPECTED_BEFORE_MODEL_ORDER = (
    "capture_request",
    "throttle_model_calls",
    "enforce_turn_limit",
    "enforce_context_budget",
    "record_model_usage",
)


def ollama_settings() -> Settings:
    """Return credential-free settings using in-memory storage for tests."""
    return Settings(_env_file=None, llm_provider="ollama", memory_backend="memory")


def test_default_catalog_contains_only_smoke_agent() -> None:
    composition = build_default_composition(settings=ollama_settings())
    assert composition.catalog.root_agent_id == "smoke_agent"
    assert tuple(composition.catalog.agents) == ("smoke_agent",)
    assert not composition.catalog.tools
    assert not composition.catalog.mcp_servers


def test_root_agent_has_no_capabilities() -> None:
    from arema.composition import get_default_composition

    root_agent = get_default_composition().root_agent

    assert root_agent.name == "smoke_agent"
    assert root_agent.tools == []
    assert root_agent.sub_agents == []
    assert root_agent.on_tool_error_callback is not None


def test_composition_returns_frozen_application_composition() -> None:
    composition = build_default_composition(settings=ollama_settings())
    assert isinstance(composition, ApplicationComposition)
    with pytest.raises(FrozenInstanceError):
        composition.root_agent = composition.root_agent  # type: ignore[misc]
    assert composition.memory_service is not None


def test_root_agent_is_adk_llm_agent() -> None:
    composition = build_default_composition(settings=ollama_settings())
    assert isinstance(composition.root_agent, LlmAgent)


def test_before_model_callbacks_follow_canonical_order() -> None:
    composition = build_default_composition(settings=ollama_settings())
    before_model = composition.root_agent.before_model_callback
    assert isinstance(before_model, list)
    roles = tuple(callback_role(callback) for callback in before_model)
    assert roles == _EXPECTED_BEFORE_MODEL_ORDER


def test_smoke_agent_uses_history_context_mode() -> None:
    composition = build_default_composition(settings=ollama_settings())
    assert composition.root_agent.include_contents == "default"


def test_smoke_agent_has_no_transfer_tool() -> None:
    # With no sub-agents ADK adds no transfer tool to the tool list.
    composition = build_default_composition(settings=ollama_settings())
    assert composition.root_agent.tools == []
    assert composition.root_agent.sub_agents == []


def test_tool_error_handler_is_wired() -> None:
    composition = build_default_composition(settings=ollama_settings())
    handler = composition.root_agent.on_tool_error_callback
    assert handler is not None
    assert isinstance(handler, list)
    assert handler


def test_prompt_loads_package_relative() -> None:
    text = load_prompt("smoke_agent")
    assert text.startswith("# AREMA Infrastructure Smoke Agent")
    assert "no tools" in text.lower()
    assert "reverse-engineering" in text.lower()


def test_get_default_composition_is_cached() -> None:
    assert get_default_composition() is get_default_composition()


def test_default_composition_has_no_sandbox_when_disabled() -> None:
    from arema.composition import build_default_composition

    settings = Settings(_env_file=None, llm_provider="ollama", memory_backend="memory")
    composition = build_default_composition(settings)

    assert composition.sandbox is None


def test_default_composition_builds_local_sandbox_when_enabled() -> None:
    from arema.composition import build_default_composition

    settings = Settings(
        _env_file=None,
        llm_provider="ollama",
        memory_backend="memory",
        sandbox_enabled=True,
        sandbox_backend="local",
    )
    composition = build_default_composition(settings)

    assert composition.sandbox is not None


def test_auto_backend_falls_back_to_local_when_k8s_package_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When k8s_agent_sandbox is missing, 'auto' must degrade to local, not crash."""
    import sys

    from arema.composition import build_default_composition
    from arema.runtime.sandbox.local import LocalSandboxExecutor

    # Setting a sys.modules entry to None makes ``import k8s_agent_sandbox`` raise
    # ImportError, simulating an absent optional extra.
    monkeypatch.setitem(sys.modules, "k8s_agent_sandbox", None)
    monkeypatch.setitem(sys.modules, "k8s_agent_sandbox.models", None)

    settings = Settings(
        _env_file=None,
        llm_provider="ollama",
        memory_backend="memory",
        sandbox_enabled=True,
        sandbox_backend="auto",
    )
    composition = build_default_composition(settings)

    assert isinstance(composition.sandbox, LocalSandboxExecutor)


def test_k8s_backend_raises_clean_error_when_package_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When k8s_agent_sandbox is missing, 'k8s' must raise CompositionError, not leak ModuleNotFoundError."""
    import sys

    from arema.composition import CompositionError, build_default_composition

    monkeypatch.setitem(sys.modules, "k8s_agent_sandbox", None)
    monkeypatch.setitem(sys.modules, "k8s_agent_sandbox.models", None)

    settings = Settings(
        _env_file=None,
        llm_provider="ollama",
        memory_backend="memory",
        sandbox_enabled=True,
        sandbox_backend="k8s",
    )

    with pytest.raises(CompositionError, match="requires the 'sandbox' extra"):
        build_default_composition(settings)
