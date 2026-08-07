"""Type-safe, domain-neutral configuration for AREMA."""

from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _find_env_file() -> str | None:
    """Find the closest project ``.env`` file, preferring the current directory."""
    if Path(".env").is_file():
        return ".env"

    current = Path(__file__).resolve()
    for _ in range(5):
        parent = current.parent
        env_file = parent / ".env"
        if env_file.is_file():
            return str(env_file)
        current = parent
    return None


class LLMProvider(StrEnum):
    """LLM providers supported by the shared runtime."""

    GOOGLE = "google"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"
    LMSTUDIO = "lmstudio"
    OPENAI_COMPATIBLE = "openai_compatible"
    ZAI = "zai"
    XAI = "xai"


_QUALIFIED_MODEL_PROVIDERS: dict[str, LLMProvider] = {
    "google": LLMProvider.GOOGLE,
    "gemini": LLMProvider.GOOGLE,
    "openai": LLMProvider.OPENAI,
    "anthropic": LLMProvider.ANTHROPIC,
    "ollama": LLMProvider.OLLAMA,
    "ollama_chat": LLMProvider.OLLAMA,
    "lmstudio": LLMProvider.LMSTUDIO,
    "openai_compatible": LLMProvider.OPENAI_COMPATIBLE,
    "zai": LLMProvider.ZAI,
    "xai": LLMProvider.XAI,
}


def resolve_qualified_model_provider(model_name: str) -> LLMProvider | None:
    """Resolve a qualified model name to its logical provider.

    Bare model names deliberately return ``None`` so callers can retain the
    active provider. Qualified names must identify one of AREMA's supported
    logical providers rather than silently inheriting credentials.
    """
    if "/" not in model_name:
        return None

    prefix, model = model_name.split("/", 1)
    if not prefix or not model:
        raise ValueError(f"Invalid qualified model name '{model_name}'")

    try:
        return _QUALIFIED_MODEL_PROVIDERS[prefix]
    except KeyError:
        raise ValueError(f"Unsupported model provider prefix '{prefix}'") from None


class Settings(BaseSettings):
    """Application settings loaded from environment variables or ``.env``."""

    # App settings are AREMA_-prefixed for clean namespacing; provider API keys stay
    # un-prefixed (via validation_alias) because LiteLLM/ADK read them by their
    # canonical *_API_KEY name.
    model_config = SettingsConfigDict(
        env_prefix="arema_",
        env_file=_find_env_file(),
        env_file_encoding="utf-8",
        case_sensitive=False,
        populate_by_name=True,
        extra="ignore",
    )

    llm_provider: LLMProvider = LLMProvider.GOOGLE

    google_api_key: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("GOOGLE_API_KEY")
    )
    google_model: str = "gemini-2.0-flash"

    openai_api_key: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("OPENAI_API_KEY")
    )
    openai_model: str = "gpt-4o"
    openai_api_base: str | None = None

    anthropic_api_key: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("ANTHROPIC_API_KEY")
    )
    anthropic_model: str = "claude-sonnet-4-20250514"

    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"

    lmstudio_base_url: str = "http://localhost:1234/v1"
    lmstudio_model: str = "local-model"

    openai_compatible_api_key: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("OPENAI_COMPATIBLE_API_KEY")
    )
    openai_compatible_base_url: str = "http://localhost:8000/v1"
    openai_compatible_model: str = "default"

    zai_api_key: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("ZAI_API_KEY")
    )
    zai_model: str = "glm-4.5-flash"
    zai_api_base: str = "https://api.z.ai/api/paas/v4"

    xai_api_key: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("XAI_API_KEY")
    )
    xai_model: str = "grok-4"
    xai_api_base: str = "https://api.x.ai/v1"

    app_name: str = "arema"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    agent_temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    agent_max_tokens: int | None = Field(default=None, ge=1)

    agent_model_overrides: dict[str, str] = Field(default_factory=dict)
    agent_model_max_tokens: dict[str, int] = Field(default_factory=dict)
    agent_model_temperature: dict[str, float] = Field(default_factory=dict)
    # Provider-neutral per-agent reasoning knob (env AREMA_AGENT_REASONING_EFFORT),
    # e.g. {"dotnet_analyst": "high"}. Empty (the default) leaves every agent in
    # its provider's default mode -- nothing turns reasoning on unless configured
    # here. Effort-capable providers (OpenAI o-series, xAI, Anthropic) receive it
    # as reasoning_effort; z.ai/GLM exposes a binary thinking switch, so any level
    # there enables thinking. Translation lives in model_factory, not here.
    agent_reasoning_effort: dict[str, str] = Field(default_factory=dict)

    # Inner values are typed ``float | str`` (not ``float``) so a malformed
    # override survives construction rather than raising a validation error;
    # fail-open validation is centralized in ``PriceTable.from_settings``, which
    # logs and ignores any entry it cannot coerce (per the fail-open contract).
    model_price_overrides: dict[str, dict[str, float | str]] = Field(
        default_factory=dict,
        description="Per-model price overrides (per 1M tokens): {model: {input, cached, output}}.",
    )

    llm_num_retries: int = Field(default=3, ge=0, le=10)
    llm_retry_min_wait: float = Field(default=1.0, ge=0.1, le=30.0)
    llm_retry_max_wait: float = Field(default=60.0, ge=1.0, le=300.0)
    llm_min_call_interval: float = Field(default=0.0, ge=0.0, le=60.0)

    context_budget_tokens: int = Field(default=80_000, ge=10_000, le=500_000)
    context_warning_ratio: float = Field(default=0.60, gt=0.0, lt=1.0)
    context_hard_ratio: float = Field(default=0.75, gt=0.0, lt=1.0)
    context_critical_ratio: float = Field(default=0.85, gt=0.0, lt=1.0)
    context_max_list_items: int = Field(default=30, ge=5, le=200)
    context_preserve_recent_tools: int = Field(default=3, ge=1, le=10)
    context_preserve_recent_model_turns: int = Field(default=4, ge=1, le=20)

    default_turn_limit: int = Field(default=100, ge=1, le=1000)
    agent_turn_limits: dict[str, int] = Field(default_factory=dict)

    memory_enabled: bool = True
    memory_backend: Literal["sqlite", "memory"] = "sqlite"
    memory_path: Path = Field(
        default_factory=lambda: Path.home() / ".arema" / "memory" / "arema.db"
    )
    memory_retrieval_max_records: int = Field(default=20, ge=1, le=200)
    memory_retrieval_token_limit: int = Field(default=4_000, ge=100, le=50_000)

    # -- Sandbox execution (domain-neutral; disabled by default) --------------
    sandbox_enabled: bool = False
    sandbox_backend: Literal["auto", "local", "k8s"] = "auto"
    sandbox_namespace: str = "agent-sandbox-demo"
    sandbox_default_pool: str = "python-runtime-pool"
    sandbox_local_tunnel: bool = True
    sandbox_run_timeout: int = Field(default=120, ge=1, le=3600)
    sandbox_connect_timeout: int = Field(default=30, ge=1, le=600)
    sandbox_output_cap: int = Field(default=65536, ge=256, le=10_000_000)
    sandbox_pool_map: dict[str, str] = Field(default_factory=dict)
    # The SSE read timeout for MCP servers reached via StreamableHTTP (e.g. an
    # analysis engine in a sandbox pod). Must accommodate the longest tool call:
    # auto-analysis on a large binary can take minutes. Too short fires
    # mid-analysis, the session drops, and the server loses its state.
    mcp_read_timeout: float = Field(default=600.0, ge=10.0, le=7200.0)

    @field_validator("memory_path", mode="before")
    @classmethod
    def expand_memory_path(cls, value: Path | str) -> Path:
        """Expand a user-relative memory database path."""
        return Path(value).expanduser()

    @field_validator("agent_model_max_tokens", "agent_turn_limits")
    @classmethod
    def validate_per_agent_limits(cls, value: dict[str, int]) -> dict[str, int]:
        """Require positive per-agent token and turn limits."""
        invalid_agents = [agent for agent, limit in value.items() if limit <= 0]
        if invalid_agents:
            raise ValueError("per-agent limits must be positive")
        return value

    @field_validator("agent_model_temperature")
    @classmethod
    def validate_per_agent_temperatures(cls, value: dict[str, float]) -> dict[str, float]:
        """Keep per-agent temperatures within the global temperature bounds."""
        invalid_agents = [
            agent for agent, temperature in value.items() if not 0.0 <= temperature <= 2.0
        ]
        if invalid_agents:
            raise ValueError("per-agent temperatures must be between 0.0 and 2.0")
        return value

    @field_validator("agent_reasoning_effort")
    @classmethod
    def validate_per_agent_reasoning_effort(cls, value: dict[str, str]) -> dict[str, str]:
        """Restrict per-agent reasoning effort to the OpenAI-compatible levels."""
        allowed = {"minimal", "low", "medium", "high"}
        invalid_agents = [agent for agent, effort in value.items() if effort not in allowed]
        if invalid_agents:
            raise ValueError(
                "per-agent reasoning effort must be one of: minimal, low, medium, high"
            )
        return value

    @model_validator(mode="after")
    def validate_cross_field_settings(self) -> "Settings":
        """Validate credentials, ratio ordering, retry wait ordering, and sandbox timeout ordering."""
        override_providers = [
            (agent_name, resolve_qualified_model_provider(model_name))
            for agent_name, model_name in self.agent_model_overrides.items()
        ]
        self.require_provider_credentials(
            self.llm_provider,
            context=f"AREMA_LLM_PROVIDER={self.llm_provider.value}",
        )
        for agent_name, override_provider in override_providers:
            if override_provider is not None:
                self.require_provider_credentials(
                    override_provider,
                    context=f"agent model override '{agent_name}'",
                )

        if not (self.context_warning_ratio < self.context_hard_ratio < self.context_critical_ratio):
            raise ValueError("context ratios must be ordered warning < hard < critical")

        if self.llm_retry_min_wait > self.llm_retry_max_wait:
            raise ValueError("LLM retry minimum wait cannot exceed maximum wait")

        if self.sandbox_run_timeout <= self.sandbox_connect_timeout:
            raise ValueError("run_timeout must exceed connect_timeout")
        return self

    def require_provider_credentials(
        self,
        provider: LLMProvider,
        *,
        context: str,
    ) -> None:
        """Raise when a provider that requires credentials has none configured."""
        required_keys: dict[LLMProvider, tuple[str, SecretStr | None]] = {
            LLMProvider.GOOGLE: ("GOOGLE_API_KEY", self.google_api_key),
            LLMProvider.OPENAI: ("OPENAI_API_KEY", self.openai_api_key),
            LLMProvider.ANTHROPIC: ("ANTHROPIC_API_KEY", self.anthropic_api_key),
            LLMProvider.ZAI: ("ZAI_API_KEY", self.zai_api_key),
            LLMProvider.XAI: ("XAI_API_KEY", self.xai_api_key),
        }
        required = required_keys.get(provider)
        if required is None:
            return

        key_name, secret = required
        if secret is None or not secret.get_secret_value():
            raise ValueError(f"{key_name} is required for {context}")

    @property
    def active_model(self) -> str:
        """Return the model configured for the active provider."""
        models = {
            LLMProvider.GOOGLE: self.google_model,
            LLMProvider.OPENAI: self.openai_model,
            LLMProvider.ANTHROPIC: self.anthropic_model,
            LLMProvider.OLLAMA: self.ollama_model,
            LLMProvider.LMSTUDIO: self.lmstudio_model,
            LLMProvider.OPENAI_COMPATIBLE: self.openai_compatible_model,
            LLMProvider.ZAI: self.zai_model,
            LLMProvider.XAI: self.xai_model,
        }
        return models[self.llm_provider]

    @staticmethod
    def _secret_value(secret: SecretStr | None, *, fallback: str = "") -> str:
        return secret.get_secret_value() if secret is not None else fallback

    @property
    def google_api_key_value(self) -> str:
        """Return the unwrapped Google key for provider setup."""
        return self._secret_value(self.google_api_key)

    @property
    def openai_api_key_value(self) -> str:
        """Return the unwrapped OpenAI key for provider setup."""
        return self._secret_value(self.openai_api_key)

    @property
    def anthropic_api_key_value(self) -> str:
        """Return the unwrapped Anthropic key for provider setup."""
        return self._secret_value(self.anthropic_api_key)

    @property
    def openai_compatible_api_key_value(self) -> str:
        """Return the compatible endpoint key or a harmless local placeholder."""
        return self._secret_value(self.openai_compatible_api_key, fallback="not-needed")

    @property
    def zai_api_key_value(self) -> str:
        """Return the unwrapped Z.AI key for provider setup."""
        return self._secret_value(self.zai_api_key)

    @property
    def xai_api_key_value(self) -> str:
        """Return the unwrapped xAI key for provider setup."""
        return self._secret_value(self.xai_api_key)


@lru_cache
def get_settings() -> Settings:
    """Return the cached application settings instance."""
    return Settings()


def clear_settings_cache() -> None:
    """Clear the cached settings instance."""
    get_settings.cache_clear()
