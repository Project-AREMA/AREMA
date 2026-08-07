"""Provider-neutral model construction for AREMA agents."""

import asyncio
import os
from typing import Any

from google.adk.models.lite_llm import LiteLlm, LiteLLMClient
from json_repair import repair_json

from arema.core.config import (
    LLMProvider,
    Settings,
    get_settings,
    resolve_qualified_model_provider,
)
from arema.core.logging import get_logger

logger = get_logger(__name__)

_OPENAI_DEFAULT_BASE_URL = "https://api.openai.com/v1"


def _setup_native_google_environment(settings: Settings) -> None:
    """Synchronize the two key names consulted by the native Google client."""
    api_key = settings.google_api_key_value
    os.environ["GOOGLE_API_KEY"] = api_key
    os.environ["GEMINI_API_KEY"] = api_key


_PROVIDER_PREFIXES: dict[LLMProvider, str] = {
    LLMProvider.GOOGLE: "gemini",
    LLMProvider.OPENAI: "openai",
    LLMProvider.ANTHROPIC: "anthropic",
    LLMProvider.OLLAMA: "ollama_chat",
    LLMProvider.LMSTUDIO: "openai",
    LLMProvider.OPENAI_COMPATIBLE: "openai",
    LLMProvider.ZAI: "openai",
    LLMProvider.XAI: "xai",
}

_RETRYABLE_ERROR_NAMES = {
    "APIConnectionError",
    "InternalServerError",
    "RateLimitError",
    "ServiceUnavailableError",
    "Timeout",
}
_RETRYABLE_STATUS_CODES = frozenset({408, 409, 425, 429, 500, 502, 503, 504})


def _is_retryable_error(error: Exception) -> bool:
    """Recognize transient LiteLLM errors without importing LiteLLM eagerly."""
    if isinstance(error, (ConnectionError, TimeoutError)):
        return True
    if type(error).__name__ in _RETRYABLE_ERROR_NAMES:
        return True
    status_code = getattr(error, "status_code", None)
    return isinstance(status_code, int) and status_code in _RETRYABLE_STATUS_CODES


def _repair_tool_call_arguments(response: Any) -> Any:
    """Repair malformed JSON in tool-call arguments via ``json_repair``.

    LLMs occasionally emit tool-call arguments with single-quoted keys, trailing
    commas, unquoted keys, or Python literals (``None``/``True``). ``json_repair``
    fixes these post-hoc -- it tries ``json.loads`` first, so already-valid
    arguments pass through unchanged -- for **every** tool, including external
    MCP tools whose schemas cannot be made OpenAI-strict-conformant. This is the
    universal, provider-agnostic fix for malformed tool-call JSON.
    """
    choices = getattr(response, "choices", None) or []
    for choice in choices:
        message = getattr(choice, "message", None)
        tool_calls = getattr(message, "tool_calls", None) if message else None
        if not tool_calls:
            continue
        for tool_call in tool_calls:
            function = getattr(tool_call, "function", None)
            arguments = getattr(function, "arguments", None) if function is not None else None
            if function is not None and isinstance(arguments, str) and arguments:
                function.arguments = repair_json(arguments)
    return response


class _ConfiguredRetryLiteLLMClient(LiteLLMClient):
    """LiteLLM client that applies AREMA's bounded retry waits per model.

    Every provider response is passed through ``json_repair`` so malformed
    tool-call arguments (single quotes, trailing commas, Python literals) are
    normalized before ADK parses them -- robust for all tools and providers,
    without forcing strict schemas.
    """

    async def acompletion(
        self,
        model: str,
        messages: list[Any],
        tools: Any,
        **kwargs: Any,
    ) -> Any:
        retries = int(kwargs.pop("num_retries", 0) or 0)
        min_wait = float(kwargs.pop("retry_min_wait", 0.0))
        max_wait = float(kwargs.pop("retry_max_wait", min_wait))
        kwargs["num_retries"] = 0

        for attempt in range(retries + 1):
            try:
                result = await super().acompletion(
                    model=model,
                    messages=messages,
                    tools=tools,
                    **kwargs,
                )
                return _repair_tool_call_arguments(result)
            except Exception as error:
                if not _is_retryable_error(error) or attempt >= retries:
                    raise
                delay = min(max_wait, min_wait * 2**attempt)
                await asyncio.sleep(delay)

        raise RuntimeError("unreachable retry state")


def get_litellm_model_string(settings: Settings, model_name: str | None = None) -> str:
    """Return a LiteLLM-qualified model name for the active provider."""
    if model_name is None:
        return f"{_PROVIDER_PREFIXES[settings.llm_provider]}/{settings.active_model}"

    provider = resolve_qualified_model_provider(model_name)
    if provider is None:
        return f"{_PROVIDER_PREFIXES[settings.llm_provider]}/{model_name}"

    _, unqualified_name = model_name.split("/", 1)
    return f"{_PROVIDER_PREFIXES[provider]}/{unqualified_name}"


def _retry_arguments(settings: Settings, *, use_retries: bool) -> dict[str, Any]:
    """Build the retry arguments passed through the ADK LiteLLM wrapper."""
    if not use_retries:
        return {"num_retries": 0}
    return {
        "num_retries": settings.llm_num_retries,
        "retry_min_wait": settings.llm_retry_min_wait,
        "retry_max_wait": settings.llm_retry_max_wait,
    }


def _provider_model_arguments(settings: Settings, provider: LLMProvider) -> dict[str, Any]:
    """Bind credentials and endpoints to one model instead of relying on global state."""
    if provider == LLMProvider.GOOGLE:
        return {"api_key": settings.google_api_key_value}
    if provider == LLMProvider.OPENAI:
        return {
            "api_key": settings.openai_api_key_value,
            "base_url": settings.openai_api_base or _OPENAI_DEFAULT_BASE_URL,
        }
    if provider == LLMProvider.ANTHROPIC:
        return {"api_key": settings.anthropic_api_key_value}
    if provider == LLMProvider.OLLAMA:
        return {"base_url": settings.ollama_base_url}
    if provider == LLMProvider.LMSTUDIO:
        return {"api_key": "lm-studio", "base_url": settings.lmstudio_base_url}
    if provider == LLMProvider.OPENAI_COMPATIBLE:
        return {
            "api_key": settings.openai_compatible_api_key_value,
            "base_url": settings.openai_compatible_base_url,
        }
    if provider == LLMProvider.ZAI:
        return {"api_key": settings.zai_api_key_value, "base_url": settings.zai_api_base}
    if provider == LLMProvider.XAI:
        return {"api_key": settings.xai_api_key_value, "base_url": settings.xai_api_base}
    raise ValueError(f"Unsupported LLM provider: {provider}")


def _apply_reasoning_effort(
    model_arguments: dict[str, Any], provider: LLMProvider, reasoning_effort: str | None
) -> None:
    """Translate the provider-neutral reasoning-effort knob to provider wire params.

    z.ai/GLM exposes thinking as a binary wire flag (``thinking.type=enabled``)
    rather than an effort level, and its LiteLLM openai-compatible path forwards
    ``extra_body`` verbatim; every other reasoning-capable provider accepts the
    standard ``reasoning_effort`` field. A falsy effort leaves the request
    untouched (the default non-reasoning behavior) -- nothing is ever enabled
    unless configured via ``AREMA_AGENT_REASONING_EFFORT``.
    """
    if not reasoning_effort:
        return
    if provider == LLMProvider.ZAI:
        model_arguments["extra_body"] = {"thinking": {"type": "enabled"}}
    else:
        model_arguments["reasoning_effort"] = reasoning_effort


def _resolve_effective_provider(settings: Settings, model_override: str | None) -> LLMProvider:
    """Resolve qualified overrides while retaining the active provider for bare names."""
    if model_override is None:
        return settings.llm_provider
    return resolve_qualified_model_provider(model_override) or settings.llm_provider


def create_model(
    settings: Settings | None = None,
    *,
    model_override: str | None = None,
    max_tokens: int | None = None,
    temperature: float | None = None,
    reasoning_effort: str | None = None,
    use_retries: bool = True,
) -> str | LiteLlm:
    """Create the configured native Gemini model or LiteLLM wrapper."""
    resolved = settings or get_settings()
    provider = resolved.llm_provider
    effective_provider = _resolve_effective_provider(resolved, model_override)
    credential_context = (
        f"model override '{model_override}'"
        if model_override is not None
        else f"AREMA_LLM_PROVIDER={provider.value}"
    )
    resolved.require_provider_credentials(effective_provider, context=credential_context)

    if model_override is None and provider == LLMProvider.GOOGLE:
        _setup_native_google_environment(resolved)
        logger.info("Creating model", provider=provider.value, model=resolved.active_model)
        return resolved.google_model

    model_string = get_litellm_model_string(resolved, model_override)

    model_arguments = _retry_arguments(resolved, use_retries=use_retries)
    model_arguments.update(_provider_model_arguments(resolved, effective_provider))
    _apply_reasoning_effort(model_arguments, effective_provider, reasoning_effort)
    if max_tokens is not None:
        model_arguments["max_tokens"] = max_tokens
    if temperature is not None:
        model_arguments["temperature"] = temperature

    logger.info(
        "Creating model",
        provider=effective_provider.value,
        model=model_string,
        retries=model_arguments["num_retries"],
    )
    return LiteLlm(
        model=model_string,
        llm_client=_ConfiguredRetryLiteLLMClient(),
        **model_arguments,
    )


def get_model_info(settings: Settings | None = None) -> dict[str, Any]:
    """Return non-secret details about the active model configuration."""
    resolved = settings or get_settings()
    provider = resolved.llm_provider
    info: dict[str, Any] = {
        "provider": provider.value,
        "model": resolved.active_model,
        "temperature": resolved.agent_temperature,
        "max_tokens": resolved.agent_max_tokens,
    }
    if provider == LLMProvider.OLLAMA:
        info["base_url"] = resolved.ollama_base_url
    elif provider == LLMProvider.LMSTUDIO:
        info["base_url"] = resolved.lmstudio_base_url
    elif provider == LLMProvider.OPENAI_COMPATIBLE:
        info["base_url"] = resolved.openai_compatible_base_url
    elif provider == LLMProvider.ZAI:
        info["base_url"] = resolved.zai_api_base
    elif provider == LLMProvider.XAI:
        info["base_url"] = resolved.xai_api_base
    return info


def get_agent_model(
    agent_name: str | None = None,
    *,
    settings: Settings | None = None,
    use_retries: bool = True,
) -> str | LiteLlm:
    """Resolve the default or per-agent model configuration."""
    resolved = settings or get_settings()
    if agent_name is not None:
        override = resolved.agent_model_overrides.get(agent_name)
        reasoning_effort = resolved.agent_reasoning_effort.get(agent_name)
        # Per-agent tuning (model, tokens, temperature, reasoning) applies whenever
        # any knob is set for the agent -- reasoning does not require a model
        # override, so an agent on the default model can still opt into thinking.
        if override is not None or reasoning_effort is not None:
            return create_model(
                resolved,
                model_override=override,
                max_tokens=resolved.agent_model_max_tokens.get(agent_name),
                temperature=resolved.agent_model_temperature.get(agent_name),
                reasoning_effort=reasoning_effort,
                use_retries=use_retries,
            )
    return create_model(resolved, use_retries=use_retries)
