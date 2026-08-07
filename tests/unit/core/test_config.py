"""Tests for AREMA's domain-neutral runtime configuration."""

from pathlib import Path

import pytest

from arema.core.config import (
    LLMProvider,
    Settings,
    clear_settings_cache,
    get_settings,
)


def test_neutral_defaults_use_arema_paths(monkeypatch) -> None:
    monkeypatch.setenv("AREMA_LLM_PROVIDER", "ollama")
    settings = Settings(_env_file=None)

    assert settings.app_name == "arema"
    assert settings.log_level == "INFO"
    assert settings.memory_enabled is True
    assert settings.memory_backend == "sqlite"
    assert settings.memory_path == Path.home() / ".arema" / "memory" / "arema.db"
    assert settings.context_budget_tokens == 80_000
    assert settings.default_turn_limit == 100


def test_settings_have_no_security_domain_fields() -> None:
    fields = set(Settings.model_fields)

    assert not fields & {
        "virustotal_api_key",
        "shodan_api_key",
        "mcp_playwright_enabled",
        "report_output_dir",
        "scan_gate_enabled",
        "phase_turn_caps",
    }


def test_all_supported_providers_are_domain_neutral() -> None:
    assert {provider.value for provider in LLMProvider} == {
        "google",
        "openai",
        "anthropic",
        "ollama",
        "lmstudio",
        "openai_compatible",
        "zai",
        "xai",
    }


def test_google_requires_api_key(monkeypatch) -> None:
    monkeypatch.setenv("AREMA_LLM_PROVIDER", "google")
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)

    with pytest.raises(ValueError, match="GOOGLE_API_KEY is required"):
        Settings(_env_file=None)


@pytest.mark.parametrize(
    ("provider", "key_field", "message"),
    [
        ("openai", "OPENAI_API_KEY", "OPENAI_API_KEY is required"),
        ("anthropic", "ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY is required"),
        ("zai", "ZAI_API_KEY", "ZAI_API_KEY is required"),
        ("xai", "XAI_API_KEY", "XAI_API_KEY is required"),
    ],
)
def test_remote_providers_require_api_keys(
    monkeypatch,
    provider: str,
    key_field: str,
    message: str,
) -> None:
    monkeypatch.setenv("AREMA_LLM_PROVIDER", provider)
    monkeypatch.delenv(key_field, raising=False)

    with pytest.raises(ValueError, match=message):
        Settings(_env_file=None)


def test_remote_provider_rejects_empty_api_key() -> None:
    with pytest.raises(ValueError, match="OPENAI_API_KEY is required"):
        Settings(_env_file=None, llm_provider="openai", openai_api_key="")


@pytest.mark.parametrize(
    ("override", "key_name"),
    [
        ("gemini/gemini-test", "GOOGLE_API_KEY"),
        ("openai/gpt-test", "OPENAI_API_KEY"),
        ("anthropic/claude-test", "ANTHROPIC_API_KEY"),
        ("zai/glm-test", "ZAI_API_KEY"),
        ("xai/grok-test", "XAI_API_KEY"),
    ],
)
def test_qualified_agent_overrides_require_provider_credentials(
    monkeypatch,
    override: str,
    key_name: str,
) -> None:
    monkeypatch.delenv(key_name, raising=False)

    with pytest.raises(ValueError, match=key_name):
        Settings(
            _env_file=None,
            llm_provider="ollama",
            agent_model_overrides={"smoke_agent": override},
        )


def test_unknown_qualified_agent_override_is_rejected() -> None:
    with pytest.raises(
        ValueError,
        match="Unsupported model provider prefix 'mistral'",
    ):
        Settings(
            _env_file=None,
            llm_provider="google",
            agent_model_overrides={"smoke_agent": "mistral/mistral-large"},
        )


@pytest.mark.parametrize("provider", ["ollama", "lmstudio", "openai_compatible"])
def test_local_and_compatible_providers_allow_missing_api_keys(provider: str) -> None:
    settings = Settings(_env_file=None, llm_provider=provider)

    assert settings.llm_provider.value == provider


def test_provider_and_runtime_defaults() -> None:
    settings = Settings(_env_file=None, llm_provider="ollama")

    assert settings.google_model == "gemini-2.0-flash"
    assert settings.openai_model == "gpt-4o"
    assert settings.openai_api_base is None
    assert settings.anthropic_model == "claude-sonnet-4-20250514"
    assert settings.ollama_base_url == "http://localhost:11434"
    assert settings.ollama_model == "llama3.2"
    assert settings.lmstudio_base_url == "http://localhost:1234/v1"
    assert settings.lmstudio_model == "local-model"
    assert settings.openai_compatible_base_url == "http://localhost:8000/v1"
    assert settings.openai_compatible_model == "default"
    assert settings.zai_model == "glm-4.5-flash"
    assert settings.zai_api_base == "https://api.z.ai/api/paas/v4"
    assert settings.xai_model == "grok-4"
    assert settings.xai_api_base == "https://api.x.ai/v1"
    assert settings.agent_temperature == 0.7
    assert settings.agent_max_tokens is None
    assert settings.llm_num_retries == 3
    assert settings.llm_retry_min_wait == 1.0
    assert settings.llm_retry_max_wait == 60.0
    assert settings.llm_min_call_interval == 0.0
    assert settings.context_warning_ratio == 0.60
    assert settings.context_hard_ratio == 0.75
    assert settings.context_critical_ratio == 0.85
    assert settings.context_max_list_items == 30
    assert settings.context_preserve_recent_tools == 3
    assert settings.context_preserve_recent_model_turns == 4
    assert settings.memory_retrieval_max_records == 20
    assert settings.memory_retrieval_token_limit == 4_000


def test_context_ratios_must_be_strictly_ordered() -> None:
    with pytest.raises(ValueError, match="warning < hard < critical"):
        Settings(
            _env_file=None,
            llm_provider="ollama",
            context_warning_ratio=0.80,
            context_hard_ratio=0.75,
            context_critical_ratio=0.85,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("agent_model_max_tokens", {"smoke_agent": 0}),
        ("agent_turn_limits", {"smoke_agent": 0}),
    ],
)
def test_per_agent_limits_must_be_positive(field: str, value: dict[str, int]) -> None:
    with pytest.raises(ValueError, match="must be positive"):
        Settings(_env_file=None, llm_provider="ollama", **{field: value})


@pytest.mark.parametrize("temperature", [-0.1, 2.1])
def test_per_agent_temperatures_use_global_bounds(temperature: float) -> None:
    with pytest.raises(ValueError, match=r"between 0\.0 and 2\.0"):
        Settings(
            _env_file=None,
            llm_provider="ollama",
            agent_model_temperature={"smoke_agent": temperature},
        )


def test_memory_path_expands_user_directory() -> None:
    settings = Settings(
        _env_file=None,
        llm_provider="ollama",
        memory_path="~/.custom-arema/memory.db",
    )

    assert settings.memory_path == Path.home() / ".custom-arema" / "memory.db"


def test_active_model_tracks_selected_provider() -> None:
    settings = Settings(
        _env_file=None,
        llm_provider="anthropic",
        anthropic_api_key="test-key",
        anthropic_model="claude-test",
    )

    assert settings.active_model == "claude-test"
    assert settings.anthropic_api_key_value == "test-key"


def test_settings_cache_can_be_cleared(monkeypatch) -> None:
    monkeypatch.setenv("AREMA_LLM_PROVIDER", "ollama")
    clear_settings_cache()
    first = get_settings()
    second = get_settings()

    assert first is second

    clear_settings_cache()
    assert get_settings() is not first
    clear_settings_cache()


def test_app_settings_use_arema_env_prefix(monkeypatch) -> None:
    monkeypatch.setenv("AREMA_LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("AREMA_MEMORY_BACKEND", "memory")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")

    settings = Settings(_env_file=None)

    assert settings.llm_provider.value == "anthropic"
    assert settings.memory_backend == "memory"


def test_provider_api_keys_stay_unprefixed(monkeypatch) -> None:
    monkeypatch.setenv("AREMA_LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "unprefixed-key")

    settings = Settings(_env_file=None)

    assert settings.anthropic_api_key_value == "unprefixed-key"


def test_unprefixed_app_settings_are_ignored(monkeypatch) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "ollama")  # old name, must be ignored
    monkeypatch.setenv("AREMA_LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")

    settings = Settings(_env_file=None)

    assert settings.llm_provider.value == "anthropic"  # AREMA_ wins; bare ignored


def test_provider_key_read_by_standard_env_name(monkeypatch) -> None:
    monkeypatch.setenv("AREMA_LLM_PROVIDER", "google")
    monkeypatch.setenv("GOOGLE_API_KEY", "standard-name-key")

    settings = Settings(_env_file=None)

    assert settings.google_api_key_value == "standard-name-key"


def test_sandbox_defaults_are_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    # The suite-wide ``_default_local_sandbox_backend`` autouse fixture pins
    # ``AREMA_SANDBOX_BACKEND=local`` so unit tests never need a cluster. A test
    # asserting the *production default* must clear that override to observe the
    # true default ("auto") rather than the test-suite default.
    monkeypatch.delenv("AREMA_SANDBOX_BACKEND", raising=False)
    settings = Settings(_env_file=None, llm_provider="ollama")

    assert settings.sandbox_enabled is False
    assert settings.sandbox_backend == "auto"
    assert settings.sandbox_default_pool == "python-runtime-pool"
    assert settings.sandbox_namespace == "agent-sandbox-demo"
    assert settings.sandbox_local_tunnel is True
    assert settings.sandbox_run_timeout == 120
    assert settings.sandbox_connect_timeout == 30
    assert settings.sandbox_output_cap == 65536
    assert settings.sandbox_pool_map == {}


def test_sandbox_pool_map_parses_json(monkeypatch) -> None:
    monkeypatch.setenv("AREMA_SANDBOX_POOL_MAP", '{"alpha": "alpha-pool"}')
    settings = Settings(_env_file=None, llm_provider="ollama")

    assert settings.sandbox_pool_map == {"alpha": "alpha-pool"}


def test_sandbox_run_timeout_must_exceed_connect_timeout() -> None:
    with pytest.raises(ValueError, match="run_timeout must exceed connect_timeout"):
        Settings(
            _env_file=None,
            llm_provider="ollama",
            sandbox_run_timeout=10,
            sandbox_connect_timeout=20,
        )


def test_sandbox_equal_timeouts_are_rejected() -> None:
    with pytest.raises(ValueError, match="run_timeout must exceed connect_timeout"):
        Settings(
            _env_file=None,
            llm_provider="ollama",
            sandbox_run_timeout=20,
            sandbox_connect_timeout=20,
        )
