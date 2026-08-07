"""Immutable capability descriptors used by AREMA composition roots."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Protocol, TypeAlias, TypeVar

from google.adk.tools.base_tool import BaseTool
from google.adk.tools.base_toolset import BaseToolset
from typing_extensions import TypeAliasType

from arema.registry.errors import (
    CatalogValidationError,
    InvalidCapabilityDescriptorError,
    InvalidToolDescriptorError,
    InvalidTransportError,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable
    from typing import Any

    from google.adk.agents import BaseAgent
    from google.adk.agents.callback_context import CallbackContext
    from google.adk.models.llm_request import LlmRequest
    from google.adk.models.llm_response import LlmResponse
    from google.adk.tools.tool_context import ToolContext
    from google.genai.types import Content
    from pydantic import BaseModel

    from arema.runtime.agent_factory import AgentBuildContext, ToolBuildContext


_Key = TypeVar("_Key")
_Value = TypeVar("_Value")
_Item = TypeVar("_Item")

# A callable that returns extra HTTP headers for a remote MCP server, invoked per
# request with the ADK readonly context. Used to inject per-run routing headers
# (e.g. X-Sandbox-ID / X-Sandbox-Port / Authorization) for a sandboxed MCP server.
# Typed as ``object`` to avoid coupling the descriptor layer to ADK's ReadonlyContext;
# the value passed at runtime is the ADK ReadonlyContext.
HeaderProvider = Callable[[object], dict[str, str]]

# Resolves an agent's ``prompt_id`` into its instruction text. When omitted the
# runtime loads the prompt from the core ``arema.prompts`` package; a peer domain
# package supplies its own loader so its prompts ship beside its agents.
PromptLoader = Callable[[str], str]


def _immutable_mapping(mapping: Mapping[_Key, _Value]) -> Mapping[_Key, _Value]:
    """Copy a mapping behind a read-only view."""
    return MappingProxyType(dict(mapping))


def _immutable_tuple(
    values: Iterable[_Item],
    *,
    field_name: str,
    error_type: type[CatalogValidationError],
) -> tuple[_Item, ...]:
    """Copy a tuple-like value without treating text as a sequence."""
    if isinstance(values, (str, bytes, bytearray)):
        raise error_type(f"Field '{field_name}' must be a non-text sequence")
    try:
        return tuple(values)
    except TypeError:
        raise error_type(f"Field '{field_name}' must be a tuple-like sequence") from None


def _immutable_callback_tuple(
    values: Sequence[_Item],
    *,
    field_name: str,
    error_type: type[CatalogValidationError],
) -> tuple[_Item, ...]:
    """Copy an ordered callback sequence and validate each member."""
    if isinstance(values, (str, bytes, bytearray)) or not isinstance(values, Sequence):
        raise error_type(f"Field '{field_name}' must be an ordered non-text sequence")
    callbacks = tuple(values)
    for index, callback in enumerate(callbacks):
        if not callable(callback):
            raise error_type(f"Field '{field_name}[{index}]' must be callable")
    return callbacks


class ContextMode(StrEnum):
    """Controls whether an agent receives conversational history."""

    HISTORY = "history"
    ISOLATED = "isolated"


class AgentKind(StrEnum):
    """Select an agent's runtime shape, with AUTO preserving legacy inference."""

    AUTO = "auto"
    LLM = "llm"
    COMPOSITE = "composite"
    DETERMINISTIC = "deterministic"


class BeforeModelCallback(Protocol):
    """One ADK before-model callback, synchronous or asynchronous.

    ADK invokes before-model callbacks by keyword (``callback_context=...``,
    ``llm_request=...``), so the parameter names below are part of the
    contract and must not be positional-only.
    """

    def __call__(
        self,
        callback_context: CallbackContext,
        llm_request: LlmRequest,
    ) -> Awaitable[LlmResponse | None] | LlmResponse | None:
        """Optionally replace an imminent model response."""
        ...


class AfterModelCallback(Protocol):
    """One ADK after-model callback, synchronous or asynchronous.

    ADK invokes after-model callbacks by keyword (``callback_context=...``,
    ``llm_response=...``), so the parameter names below are part of the
    contract and must not be positional-only.
    """

    def __call__(
        self,
        callback_context: CallbackContext,
        llm_response: LlmResponse,
    ) -> Awaitable[LlmResponse | None] | LlmResponse | None:
        """Optionally replace a completed model response."""
        ...


class BeforeToolCallback(Protocol):
    """One ADK before-tool callback, synchronous or asynchronous.

    ADK passes ``tool`` positionally and ``args``/``tool_context`` by keyword,
    so those names are part of the contract and must not be positional-only.
    """

    def __call__(
        self,
        tool: BaseTool,
        args: dict[str, Any],
        tool_context: ToolContext,
    ) -> Awaitable[dict[str, Any] | None] | dict[str, Any] | None:
        """Optionally replace an imminent tool response."""
        ...


class AfterToolCallback(Protocol):
    """One ADK after-tool callback, synchronous or asynchronous.

    ADK invokes after-tool callbacks entirely by keyword, so every parameter
    name below is part of the contract and must not be positional-only.
    """

    def __call__(
        self,
        tool: BaseTool,
        args: dict[str, Any],
        tool_context: ToolContext,
        tool_response: dict[str, Any],
    ) -> Awaitable[dict[str, Any] | None] | dict[str, Any] | None:
        """Optionally replace a completed tool response."""
        ...


class ToolErrorCallback(Protocol):
    """One ADK tool-error callback, synchronous or asynchronous.

    ADK invokes tool-error callbacks by keyword, so the parameter names below
    are part of the contract and must not be positional-only.
    """

    def __call__(
        self,
        tool: BaseTool,
        args: dict[str, Any],
        tool_context: ToolContext,
        error: Exception,
    ) -> Awaitable[dict[str, Any] | None] | dict[str, Any] | None:
        """Optionally recover from a failed tool call."""
        ...


class ToolMemoryCallback(Protocol):
    """An after-tool lifecycle callback that records tool memory.

    Shares the keyword-invoked after-tool signature, so the parameter names
    below are part of the contract and must not be positional-only.
    """

    def __call__(
        self,
        tool: BaseTool,
        args: dict[str, Any],
        tool_context: ToolContext,
        tool_response: dict[str, Any],
    ) -> Awaitable[dict[str, Any] | None] | dict[str, Any] | None:
        """Optionally update a response while recording lifecycle memory."""
        ...


class AfterAgentCallback(Protocol):
    """One ADK after-agent callback, synchronous or asynchronous.

    State-normalization callbacks must return ``None``. Returning a truthy ADK
    ``Content`` short-circuits the remaining callbacks, including checkpoint
    recorders appended after normalization.
    """

    def __call__(
        self,
        callback_context: CallbackContext,
    ) -> Awaitable[Content | None] | Content | None:
        """Optionally return ADK callback content after an agent completes."""
        ...


Callback: TypeAlias = (
    BeforeModelCallback
    | BeforeToolCallback
    | AfterToolCallback
    | ToolErrorCallback
    | ToolMemoryCallback
)


@dataclass(frozen=True, slots=True)
class RuntimeProfile:
    """Declarative switches and callback extensions for an agent runtime."""

    id: str
    context_mode: ContextMode = ContextMode.HISTORY
    capture_request: bool = True
    throttle_model: bool = True
    retry_model: bool = True
    enforce_turn_limit: bool = True
    enforce_context_budget: bool = True
    record_metrics: bool = True
    guard_tools: bool = True
    record_memory: bool = True
    compact_tool_output: bool = True
    recover_tool_errors: bool = True
    extra_before_model: tuple[BeforeModelCallback, ...] = ()
    extra_before_tool: tuple[BeforeToolCallback, ...] = ()
    extra_after_tool: tuple[AfterToolCallback, ...] = ()

    def __post_init__(self) -> None:
        """Detach callback sequences supplied by callers."""
        object.__setattr__(
            self,
            "extra_before_model",
            _immutable_tuple(
                self.extra_before_model,
                field_name="extra_before_model",
                error_type=InvalidCapabilityDescriptorError,
            ),
        )
        object.__setattr__(
            self,
            "extra_before_tool",
            _immutable_tuple(
                self.extra_before_tool,
                field_name="extra_before_tool",
                error_type=InvalidCapabilityDescriptorError,
            ),
        )
        object.__setattr__(
            self,
            "extra_after_tool",
            _immutable_tuple(
                self.extra_after_tool,
                field_name="extra_after_tool",
                error_type=InvalidCapabilityDescriptorError,
            ),
        )

    @classmethod
    def safe_default(cls) -> RuntimeProfile:
        """Return AREMA's guarded default runtime profile."""
        return cls(id="safe_default")


@dataclass(frozen=True, slots=True)
class OutputPolicy:
    """Bounds and field selection rules for persisted tool output."""

    max_chars: int = 15_000
    max_list_items: int = 30
    drop_fields: tuple[str, ...] = ()
    preserve_fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Detach field sequences supplied by callers."""
        object.__setattr__(
            self,
            "drop_fields",
            _immutable_tuple(
                self.drop_fields,
                field_name="drop_fields",
                error_type=InvalidToolDescriptorError,
            ),
        )
        object.__setattr__(
            self,
            "preserve_fields",
            _immutable_tuple(
                self.preserve_fields,
                field_name="preserve_fields",
                error_type=InvalidToolDescriptorError,
            ),
        )


JsonScalar: TypeAlias = str | int | float | bool | None

# Arbitrary JSON metadata: a scalar, or a nested mapping/sequence of the same.
# Covariant ``Mapping``/``Sequence`` (not ``dict``/``list``) so a narrower value
# such as ``dict[str, str]`` assigns cleanly. Mirrors ``arema.memory.models``.
JsonValue = TypeAliasType(
    "JsonValue",
    "JsonScalar | Sequence[JsonValue] | Mapping[str, JsonValue]",
)


@dataclass(frozen=True, slots=True)
class ToolLifecycleCallbacks:
    """Tool lifecycle extension callbacks grouped by phase."""

    before: tuple[BeforeToolCallback, ...] = ()
    after: tuple[AfterToolCallback, ...] = ()
    on_error: tuple[ToolErrorCallback, ...] = ()
    memory: tuple[ToolMemoryCallback, ...] = ()

    def __post_init__(self) -> None:
        """Detach callback sequences supplied by callers."""
        object.__setattr__(
            self,
            "before",
            _immutable_tuple(
                self.before,
                field_name="before",
                error_type=InvalidToolDescriptorError,
            ),
        )
        object.__setattr__(
            self,
            "after",
            _immutable_tuple(
                self.after,
                field_name="after",
                error_type=InvalidToolDescriptorError,
            ),
        )
        object.__setattr__(
            self,
            "on_error",
            _immutable_tuple(
                self.on_error,
                field_name="on_error",
                error_type=InvalidToolDescriptorError,
            ),
        )
        object.__setattr__(
            self,
            "memory",
            _immutable_tuple(
                self.memory,
                field_name="memory",
                error_type=InvalidToolDescriptorError,
            ),
        )


class AgentFactory(Protocol):
    """Construct an ADK agent from a future runtime build context."""

    def __call__(self, context: AgentBuildContext, /) -> BaseAgent:
        """Build an agent for the supplied runtime context."""
        ...


ToolLike: TypeAlias = Callable[..., object] | BaseTool | BaseToolset


class ToolFactory(Protocol):
    """Construct an ADK-compatible tool from a future build context."""

    def __call__(self, context: ToolBuildContext, /) -> ToolLike:
        """Build a tool for the supplied runtime context."""
        ...


@dataclass(frozen=True, slots=True)
class AgentDescriptor:
    """All declarative inputs required to build one agent."""

    id: str
    name: str
    description: str
    prompt_id: str | None
    factory: AgentFactory
    runtime_profile_id: str = "safe_default"
    prompt_loader: PromptLoader | None = None
    tool_ids: tuple[str, ...] = ()
    mcp_server_ids: tuple[str, ...] = ()
    sub_agent_ids: tuple[str, ...] = ()
    output_key: str | None = None
    # A Pydantic model class the agent's structured output must conform to. ADK
    # coerces the model to emit schema-valid JSON (a set_model_response call when
    # tools are present, native structured output otherwise) and validates it
    # before storing at ``output_key`` -- so model output can never arrive fenced
    # or as prose. Must be paired with ``output_key``.
    output_schema: type[BaseModel] | None = None
    after_agent_callbacks: tuple[AfterAgentCallback, ...] = ()
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)
    version: str = "1"
    kind: AgentKind = AgentKind.AUTO

    def __post_init__(self) -> None:
        """Copy every caller-owned collection into immutable storage."""
        object.__setattr__(
            self,
            "tool_ids",
            _immutable_tuple(
                self.tool_ids,
                field_name="tool_ids",
                error_type=InvalidCapabilityDescriptorError,
            ),
        )
        object.__setattr__(
            self,
            "mcp_server_ids",
            _immutable_tuple(
                self.mcp_server_ids,
                field_name="mcp_server_ids",
                error_type=InvalidCapabilityDescriptorError,
            ),
        )
        object.__setattr__(
            self,
            "sub_agent_ids",
            _immutable_tuple(
                self.sub_agent_ids,
                field_name="sub_agent_ids",
                error_type=InvalidCapabilityDescriptorError,
            ),
        )
        object.__setattr__(
            self,
            "after_agent_callbacks",
            _immutable_callback_tuple(
                self.after_agent_callbacks,
                field_name="after_agent_callbacks",
                error_type=InvalidCapabilityDescriptorError,
            ),
        )
        object.__setattr__(self, "metadata", _immutable_mapping(self.metadata))
        if self.output_schema is not None and self.output_key is None:
            raise InvalidCapabilityDescriptorError(
                f"agent '{self.id}' sets output_schema but no output_key; ADK stores the "
                "coerced structured output at output_key, so both are required together."
            )
        if self.output_schema is not None and (self.tool_ids or self.mcp_server_ids):
            raise InvalidCapabilityDescriptorError(
                f"agent '{self.id}' combines output_schema with tools/MCP servers; "
                "ADK's schema coercion is unreliable on a tool-using turn (the model "
                "emits free-form, often code-fenced, text), so a tool-using agent must "
                "emit a normal text envelope parsed by its after-agent normalizer "
                "instead of declaring output_schema."
            )


@dataclass(frozen=True, slots=True)
class ToolDescriptor:
    """A concrete tool or deferred tool factory and its runtime policies."""

    id: str
    description: str
    tool: ToolLike | None = None
    factory: ToolFactory | None = None
    output_policy: OutputPolicy = OutputPolicy()
    memory_codec_ids: tuple[str, ...] = ()
    callbacks: ToolLifecycleCallbacks = ToolLifecycleCallbacks()
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)
    version: str = "1"

    def __post_init__(self) -> None:
        """Copy every caller-owned collection into immutable storage."""
        object.__setattr__(
            self,
            "memory_codec_ids",
            _immutable_tuple(
                self.memory_codec_ids,
                field_name="memory_codec_ids",
                error_type=InvalidToolDescriptorError,
            ),
        )
        object.__setattr__(self, "metadata", _immutable_mapping(self.metadata))


@dataclass(frozen=True, slots=True)
class StdioTransport:
    """Configuration for a subprocess-backed MCP connection."""

    command: str
    args: tuple[str, ...] = ()
    env: Mapping[str, str] = field(default_factory=dict)
    connect_timeout: float = 120.0

    def __post_init__(self) -> None:
        """Copy subprocess arguments and environment settings."""
        object.__setattr__(
            self,
            "args",
            _immutable_tuple(
                self.args,
                field_name="args",
                error_type=InvalidTransportError,
            ),
        )
        object.__setattr__(self, "env", _immutable_mapping(self.env))


@dataclass(frozen=True, slots=True)
class SseTransport:
    """Configuration for an MCP server-sent-events connection."""

    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    connect_timeout: float = 5.0
    read_timeout: float = 600.0

    def __post_init__(self) -> None:
        """Copy caller-owned request headers."""
        object.__setattr__(self, "headers", _immutable_mapping(self.headers))


@dataclass(frozen=True, slots=True)
class StreamableHttpTransport:
    """Configuration for an MCP streamable HTTP connection."""

    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    connect_timeout: float = 5.0
    read_timeout: float = 600.0
    terminate_on_close: bool = True

    def __post_init__(self) -> None:
        """Copy caller-owned request headers."""
        object.__setattr__(self, "headers", _immutable_mapping(self.headers))


@dataclass(frozen=True, slots=True)
class McpServerDescriptor:
    """A named MCP server and its exposed-tool policy."""

    id: str
    transport: StdioTransport | SseTransport | StreamableHttpTransport
    required: bool = False
    tool_allowlist: tuple[str, ...] = ()
    tool_name_prefix: str | None = None
    header_provider: HeaderProvider | None = None

    def __post_init__(self) -> None:
        """Detach the exposed-tool sequence supplied by callers."""
        object.__setattr__(
            self,
            "tool_allowlist",
            _immutable_tuple(
                self.tool_allowlist,
                field_name="tool_allowlist",
                error_type=InvalidTransportError,
            ),
        )
