"""Tests for provider-neutral model construction."""

import asyncio
import os
from typing import Any

import pytest
from google.adk.models.lite_llm import LiteLlm, LiteLLMClient
from pydantic import ValidationError

from arema.core.config import Settings
from arema.core.model_factory import (
    create_model,
    get_agent_model,
    get_litellm_model_string,
    get_model_info,
)


@pytest.mark.parametrize(
    ("settings_kwargs", "expected"),
    [
        ({"llm_provider": "google", "google_api_key": "key"}, "gemini/gemini-2.0-flash"),
        ({"llm_provider": "openai", "openai_api_key": "key"}, "openai/gpt-4o"),
        (
            {"llm_provider": "anthropic", "anthropic_api_key": "key"},
            "anthropic/claude-sonnet-4-20250514",
        ),
        ({"llm_provider": "ollama"}, "ollama_chat/llama3.2"),
        ({"llm_provider": "lmstudio"}, "openai/local-model"),
        ({"llm_provider": "openai_compatible"}, "openai/default"),
        ({"llm_provider": "zai", "zai_api_key": "key"}, "openai/glm-4.5-flash"),
        ({"llm_provider": "xai", "xai_api_key": "key"}, "xai/grok-4"),
    ],
)
def test_default_models_use_provider_prefixes(
    settings_kwargs: dict[str, str], expected: str
) -> None:
    settings = Settings(_env_file=None, **settings_kwargs)

    assert get_litellm_model_string(settings) == expected


def test_bare_override_uses_active_provider_prefix() -> None:
    settings = Settings(
        _env_file=None,
        llm_provider="anthropic",
        anthropic_api_key="test-key",
    )

    assert get_litellm_model_string(settings, "claude-test") == "anthropic/claude-test"


def test_qualified_override_is_returned_verbatim() -> None:
    settings = Settings(_env_file=None, llm_provider="ollama")

    assert get_litellm_model_string(settings, "openai/gpt-test") == "openai/gpt-test"


def test_unknown_qualified_override_is_rejected_before_credentials_are_bound(
    monkeypatch,
) -> None:
    monkeypatch.setenv("GOOGLE_API_KEY", "existing-google")
    monkeypatch.setenv("GEMINI_API_KEY", "existing-gemini")
    settings = Settings(
        _env_file=None,
        llm_provider="google",
        google_api_key="configured-google",
    )

    with pytest.raises(ValueError, match="Unsupported model provider prefix 'mistral'"):
        create_model(settings, model_override="mistral/mistral-large")

    assert os.environ["GOOGLE_API_KEY"] == "existing-google"
    assert os.environ["GEMINI_API_KEY"] == "existing-gemini"


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
def test_direct_qualified_override_requires_provider_credentials(
    monkeypatch,
    override: str,
    key_name: str,
) -> None:
    monkeypatch.delenv(key_name, raising=False)
    settings = Settings(_env_file=None, llm_provider="ollama")

    with pytest.raises(ValueError, match=key_name):
        create_model(settings, model_override=override)


def test_google_default_uses_native_model_string(monkeypatch) -> None:
    monkeypatch.setenv("GOOGLE_API_KEY", "stale-google-key")
    monkeypatch.setenv("GEMINI_API_KEY", "stale-gemini-key")
    settings = Settings(
        _env_file=None,
        llm_provider="google",
        google_api_key="test-key",
    )

    model = create_model(settings)

    assert model == "gemini-2.0-flash"
    assert os.environ["GOOGLE_API_KEY"] == "test-key"
    assert os.environ["GEMINI_API_KEY"] == "test-key"


def test_litellm_uses_configured_retry_policy() -> None:
    settings = Settings(
        _env_file=None,
        llm_provider="ollama",
        llm_num_retries=4,
        llm_retry_min_wait=2.5,
        llm_retry_max_wait=90.0,
    )

    model = create_model(settings)

    assert isinstance(model, LiteLlm)
    assert model._additional_args["num_retries"] == 4
    assert model._additional_args["retry_min_wait"] == 2.5
    assert model._additional_args["retry_max_wait"] == 90.0


def test_disabling_retries_sets_wrapper_retry_count_to_zero() -> None:
    settings = Settings(_env_file=None, llm_provider="ollama", llm_num_retries=8)

    model = create_model(settings, use_retries=False)

    assert isinstance(model, LiteLlm)
    assert model._additional_args["num_retries"] == 0
    assert "retry_min_wait" not in model._additional_args
    assert "retry_max_wait" not in model._additional_args


@pytest.mark.parametrize(
    ("override", "expected_model", "expected_api_key", "expected_base_url"),
    [
        ("gemini/gemini-test", "gemini/gemini-test", "google-key", None),
        (
            "openai/gpt-test",
            "openai/gpt-test",
            "openai-key",
            "https://api.openai.com/v1",
        ),
        ("anthropic/claude-test", "anthropic/claude-test", "anthropic-key", None),
        (
            "ollama_chat/llama-test",
            "ollama_chat/llama-test",
            None,
            "http://ollama.example.test",
        ),
        (
            "lmstudio/local-test",
            "openai/local-test",
            "lm-studio",
            "http://lmstudio.example.test/v1",
        ),
        (
            "openai_compatible/custom-test",
            "openai/custom-test",
            "compatible-key",
            "https://compatible.example.test/v1",
        ),
        (
            "zai/glm-test",
            "openai/glm-test",
            "zai-key",
            "https://zai.example.test/v4",
        ),
        (
            "xai/grok-test",
            "xai/grok-test",
            "xai-key",
            "https://xai.example.test/v1",
        ),
    ],
)
def test_supported_qualified_overrides_route_without_mutating_environment(
    monkeypatch,
    override: str,
    expected_model: str,
    expected_api_key: str | None,
    expected_base_url: str | None,
) -> None:
    provider_environment = {
        "GOOGLE_API_KEY": "existing-google",
        "GEMINI_API_KEY": "existing-gemini",
        "OPENAI_API_KEY": "existing-openai",
        "OPENAI_API_BASE": "https://existing-api-base.example.test/v1",
        "OPENAI_BASE_URL": "https://existing-base-url.example.test/v1",
        "ANTHROPIC_API_KEY": "existing-anthropic",
        "OLLAMA_API_BASE": "http://existing-ollama.example.test",
    }
    for name, value in provider_environment.items():
        monkeypatch.setenv(name, value)
    settings = Settings(
        _env_file=None,
        llm_provider="ollama",
        google_api_key="google-key",
        openai_api_key="openai-key",
        openai_api_base=None,
        anthropic_api_key="anthropic-key",
        ollama_base_url="http://ollama.example.test",
        lmstudio_base_url="http://lmstudio.example.test/v1",
        openai_compatible_api_key="compatible-key",
        openai_compatible_base_url="https://compatible.example.test/v1",
        zai_api_key="zai-key",
        zai_api_base="https://zai.example.test/v4",
        xai_api_key="xai-key",
        xai_api_base="https://xai.example.test/v1",
    )

    model = create_model(settings, model_override=override)

    assert isinstance(model, LiteLlm)
    assert model.model == expected_model
    if expected_api_key is None:
        assert "api_key" not in model._additional_args
    else:
        assert model._additional_args["api_key"] == expected_api_key
    if expected_base_url is None:
        assert "base_url" not in model._additional_args
    else:
        assert model._additional_args["base_url"] == expected_base_url
    assert {name: os.environ[name] for name in provider_environment} == provider_environment


def test_litellm_construction_does_not_create_provider_environment(monkeypatch) -> None:
    provider_environment = {
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",
        "OPENAI_API_KEY",
        "OPENAI_API_BASE",
        "OPENAI_BASE_URL",
        "ANTHROPIC_API_KEY",
        "OLLAMA_API_BASE",
    }
    for name in provider_environment:
        monkeypatch.delenv(name, raising=False)
    settings = Settings(
        _env_file=None,
        llm_provider="ollama",
        anthropic_api_key="anthropic-key",
    )

    model = create_model(settings, model_override="anthropic/claude-test")

    assert isinstance(model, LiteLlm)
    assert not provider_environment & os.environ.keys()


def test_agent_override_can_select_another_provider(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "existing-key")
    settings = Settings(
        _env_file=None,
        llm_provider="ollama",
        agent_model_overrides={"smoke_agent": "anthropic/claude-sonnet-4-20250514"},
        anthropic_api_key="test-key",
    )

    model = get_agent_model("smoke_agent", settings=settings)

    assert isinstance(model, LiteLlm)
    assert model.model == "anthropic/claude-sonnet-4-20250514"
    assert model._additional_args["api_key"] == "test-key"
    assert os.environ["ANTHROPIC_API_KEY"] == "existing-key"


def test_bare_override_keeps_active_shared_prefix_provider(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    settings = Settings(
        _env_file=None,
        llm_provider="zai",
        zai_api_key="zai-key",
        agent_model_overrides={"smoke_agent": "glm-4.7"},
    )

    model = get_agent_model("smoke_agent", settings=settings)

    assert isinstance(model, LiteLlm)
    assert model.model == "openai/glm-4.7"
    assert model._additional_args["api_key"] == "zai-key"
    assert model._additional_args["base_url"] == settings.zai_api_base
    assert "OPENAI_API_KEY" not in os.environ


def test_agent_reasoning_effort_enables_zai_thinking(monkeypatch) -> None:
    """z.ai/GLM exposes thinking as a binary wire flag; a configured reasoning
    effort turns it on via extra_body (not the effort-level reasoning_effort)."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    settings = Settings(
        _env_file=None,
        llm_provider="zai",
        zai_api_key="zai-key",
        agent_model_overrides={"dotnet_analyst": "glm-5.2"},
        agent_reasoning_effort={"dotnet_analyst": "high"},
    )

    model = get_agent_model("dotnet_analyst", settings=settings)

    assert isinstance(model, LiteLlm)
    assert model.model == "openai/glm-5.2"
    assert model._additional_args["extra_body"] == {"thinking": {"type": "enabled"}}
    assert "reasoning_effort" not in model._additional_args


def test_agent_reasoning_effort_sets_reasoning_effort_for_effort_capable_provider() -> None:
    """An effort-capable provider (Anthropic/OpenAI/xAI) receives the standard
    reasoning_effort field verbatim rather than the GLM thinking extra_body."""
    settings = Settings(
        _env_file=None,
        llm_provider="ollama",
        anthropic_api_key="anthropic-key",
        agent_model_overrides={"deep_worker": "anthropic/claude-test"},
        agent_reasoning_effort={"deep_worker": "high"},
    )

    model = get_agent_model("deep_worker", settings=settings)

    assert isinstance(model, LiteLlm)
    assert model._additional_args["reasoning_effort"] == "high"
    assert "extra_body" not in model._additional_args


def test_no_reasoning_effort_leaves_request_untouched() -> None:
    """The default (empty map) never enables reasoning -- no extra_body, no
    reasoning_effort -- so existing agents keep their non-reasoning behavior."""
    settings = Settings(
        _env_file=None,
        llm_provider="zai",
        zai_api_key="zai-key",
        agent_model_overrides={"dotnet_analyst": "glm-5.2"},
    )

    model = get_agent_model("dotnet_analyst", settings=settings)

    assert isinstance(model, LiteLlm)
    assert "extra_body" not in model._additional_args
    assert "reasoning_effort" not in model._additional_args


def test_reasoning_effort_applies_without_a_model_override() -> None:
    """Reasoning is independent of a model override: an agent left on the active
    provider's default model can still opt into thinking."""
    settings = Settings(
        _env_file=None,
        llm_provider="zai",
        zai_api_key="zai-key",
        agent_reasoning_effort={"packer_analyst": "medium"},
    )

    model = get_agent_model("packer_analyst", settings=settings)

    assert isinstance(model, LiteLlm)
    assert model.model == "openai/glm-4.5-flash"  # active zai default model
    assert model._additional_args["extra_body"] == {"thinking": {"type": "enabled"}}


def test_invalid_reasoning_effort_is_rejected_at_config_time() -> None:
    """An out-of-range effort fails closed at Settings construction, matching the
    per-agent temperature/limit validators."""
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            llm_provider="zai",
            zai_api_key="zai-key",
            agent_reasoning_effort={"dotnet_analyst": "turbo"},
        )


def test_openai_override_cannot_inherit_zai_endpoint(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_BASE", "https://stale-api-base.example.test/v1")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://stale.example.test/v1")
    settings = Settings(
        _env_file=None,
        llm_provider="zai",
        zai_api_key="zai-key",
        openai_api_key="openai-key",
        openai_api_base=None,
        agent_model_overrides={"smoke_agent": "openai/gpt-4o"},
    )

    model = get_agent_model("smoke_agent", settings=settings)

    assert isinstance(model, LiteLlm)
    assert model._additional_args["api_key"] == "openai-key"
    assert model._additional_args["base_url"] == "https://api.openai.com/v1"
    assert os.environ["OPENAI_API_BASE"] == "https://stale-api-base.example.test/v1"
    assert os.environ["OPENAI_BASE_URL"] == "https://stale.example.test/v1"


def test_agent_override_applies_generation_options() -> None:
    settings = Settings(
        _env_file=None,
        llm_provider="ollama",
        agent_model_overrides={"smoke_agent": "llama3.3"},
        agent_model_max_tokens={"smoke_agent": 1_024},
        agent_model_temperature={"smoke_agent": 0.2},
    )

    model = get_agent_model("smoke_agent", settings=settings)

    assert isinstance(model, LiteLlm)
    assert model.model == "ollama_chat/llama3.3"
    assert model._additional_args["max_tokens"] == 1_024
    assert model._additional_args["temperature"] == 0.2


def test_unlisted_agent_uses_provider_default() -> None:
    settings = Settings(
        _env_file=None,
        llm_provider="ollama",
        agent_model_overrides={"other_agent": "llama3.3"},
    )

    model = get_agent_model("smoke_agent", settings=settings)

    assert isinstance(model, LiteLlm)
    assert model.model == "ollama_chat/llama3.2"


@pytest.mark.asyncio
async def test_retry_client_honors_configured_wait_bounds(monkeypatch) -> None:
    from arema.core.model_factory import _ConfiguredRetryLiteLLMClient

    attempts = 0
    completion_kwargs: list[dict[str, Any]] = []
    requests: list[tuple[str, list[dict[str, str]], object]] = []
    waits: list[float] = []
    expected = object()

    async def fake_acompletion(
        self,
        model: str,
        messages: list[dict[str, str]],
        tools: object,
        **kwargs: Any,
    ) -> object:
        nonlocal attempts
        del self
        attempts += 1
        completion_kwargs.append(kwargs)
        requests.append((model, messages, tools))
        if attempts < 3:
            raise ConnectionError("temporary")
        return expected

    async def fake_sleep(delay: float) -> None:
        waits.append(delay)

    monkeypatch.setattr(LiteLLMClient, "acompletion", fake_acompletion)
    monkeypatch.setattr("arema.core.model_factory.asyncio.sleep", fake_sleep)
    client = _ConfiguredRetryLiteLLMClient()

    result = await client.acompletion(
        model="ollama_chat/llama3.2",
        messages=[],
        tools=None,
        num_retries=2,
        retry_min_wait=1.5,
        retry_max_wait=2.0,
    )

    assert result is expected
    assert attempts == 3
    assert waits == [1.5, 2.0]
    assert requests == [("ollama_chat/llama3.2", [], None)] * 3
    assert all(kwargs["num_retries"] == 0 for kwargs in completion_kwargs)
    assert all("retry_min_wait" not in kwargs for kwargs in completion_kwargs)
    assert all("retry_max_wait" not in kwargs for kwargs in completion_kwargs)


def test_retryable_status_policy_is_explicit() -> None:
    from arema.core.model_factory import _is_retryable_error

    class StatusError(Exception):
        def __init__(self, status_code: int) -> None:
            self.status_code = status_code

    expected = {
        400: False,
        408: True,
        409: True,
        425: True,
        429: True,
        500: True,
        501: False,
        502: True,
        503: True,
        504: True,
        505: False,
    }

    assert {status: _is_retryable_error(StatusError(status)) for status in expected} == expected


@pytest.mark.asyncio
async def test_retry_client_propagates_non_transient_error_without_waiting(monkeypatch) -> None:
    from arema.core.model_factory import _ConfiguredRetryLiteLLMClient

    class NotImplementedResponseError(Exception):
        status_code = 501

    attempts = 0
    waits: list[float] = []

    async def fake_acompletion(
        self,
        model: str,
        messages: list[dict[str, str]],
        tools: object,
        **kwargs: Any,
    ) -> object:
        nonlocal attempts
        del self, model, messages, tools, kwargs
        attempts += 1
        raise NotImplementedResponseError

    async def fake_sleep(delay: float) -> None:
        waits.append(delay)

    monkeypatch.setattr(LiteLLMClient, "acompletion", fake_acompletion)
    monkeypatch.setattr("arema.core.model_factory.asyncio.sleep", fake_sleep)

    with pytest.raises(NotImplementedResponseError):
        await _ConfiguredRetryLiteLLMClient().acompletion(
            model="ollama_chat/llama3.2",
            messages=[],
            tools=None,
            num_retries=3,
            retry_min_wait=1.0,
            retry_max_wait=10.0,
        )

    assert attempts == 1
    assert waits == []


@pytest.mark.asyncio
async def test_retry_client_exhausts_attempts_and_preserves_backoff(monkeypatch) -> None:
    from arema.core.model_factory import _ConfiguredRetryLiteLLMClient

    attempts = 0
    waits: list[float] = []

    async def fake_acompletion(
        self,
        model: str,
        messages: list[dict[str, str]],
        tools: object,
        **kwargs: Any,
    ) -> object:
        nonlocal attempts
        del self, model, messages, tools, kwargs
        attempts += 1
        raise ConnectionError("still unavailable")

    async def fake_sleep(delay: float) -> None:
        waits.append(delay)

    monkeypatch.setattr(LiteLLMClient, "acompletion", fake_acompletion)
    monkeypatch.setattr("arema.core.model_factory.asyncio.sleep", fake_sleep)

    with pytest.raises(ConnectionError, match="still unavailable"):
        await _ConfiguredRetryLiteLLMClient().acompletion(
            model="ollama_chat/llama3.2",
            messages=[],
            tools=None,
            num_retries=3,
            retry_min_wait=1.0,
            retry_max_wait=2.5,
        )

    assert attempts == 4
    assert waits == [1.0, 2.0, 2.5]


@pytest.mark.asyncio
async def test_retry_client_does_not_swallow_cancellation(monkeypatch) -> None:
    from arema.core.model_factory import _ConfiguredRetryLiteLLMClient

    async def fake_acompletion(
        self,
        model: str,
        messages: list[dict[str, str]],
        tools: object,
        **kwargs: Any,
    ) -> object:
        del self, model, messages, tools, kwargs
        raise asyncio.CancelledError

    monkeypatch.setattr(LiteLLMClient, "acompletion", fake_acompletion)

    with pytest.raises(asyncio.CancelledError):
        await _ConfiguredRetryLiteLLMClient().acompletion(
            model="ollama_chat/llama3.2",
            messages=[],
            tools=None,
            num_retries=3,
            retry_min_wait=1.0,
            retry_max_wait=10.0,
        )


def test_model_info_contains_non_secret_runtime_details() -> None:
    settings = Settings(
        _env_file=None,
        llm_provider="openai_compatible",
        openai_compatible_api_key="secret-value",
        openai_compatible_base_url="https://models.example.test/v1",
        agent_temperature=0.4,
        agent_max_tokens=2_048,
    )

    info = get_model_info(settings)

    assert info == {
        "provider": "openai_compatible",
        "model": "default",
        "temperature": 0.4,
        "max_tokens": 2_048,
        "base_url": "https://models.example.test/v1",
    }
    assert "secret-value" not in repr(info)


def test_model_info_reports_xai_base_url() -> None:
    settings = Settings(
        _env_file=None,
        llm_provider="xai",
        xai_api_key="secret-value",
        xai_api_base="https://xai.example.test/v1",
        xai_model="grok-test",
    )

    info = get_model_info(settings)

    assert info == {
        "provider": "xai",
        "model": "grok-test",
        "temperature": 0.7,
        "max_tokens": None,
        "base_url": "https://xai.example.test/v1",
    }
    assert "secret-value" not in repr(info)
