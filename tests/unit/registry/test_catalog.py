"""Tests for the immutable AREMA capability catalog."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

import pytest

from arema.registry import (
    AfterToolCallback,
    AgentDescriptor,
    AgentFactory,
    AgentKind,
    BeforeModelCallback,
    BeforeToolCallback,
    CapabilityCatalog,
    CatalogBuilder,
    ContextMode,
    McpServerDescriptor,
    OutputPolicy,
    RuntimeProfile,
    SseTransport,
    StdioTransport,
    StreamableHttpTransport,
    ToolDescriptor,
    ToolErrorCallback,
    ToolFactory,
    ToolLifecycleCallbacks,
    ToolLike,
    ToolMemoryCallback,
)
from arema.registry.errors import (
    CapabilityCycleError,
    CatalogFrozenError,
    DuplicateCapabilityError,
    InvalidCapabilityDescriptorError,
    InvalidRootError,
    InvalidToolDescriptorError,
    InvalidTransportError,
    UnreachableAgentError,
    UnresolvedCapabilityError,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from typing import assert_type

    from google.adk.agents.callback_context import CallbackContext
    from google.adk.models.llm_request import LlmRequest
    from google.adk.models.llm_response import LlmResponse
    from google.adk.tools.base_tool import BaseTool
    from google.adk.tools.tool_context import ToolContext

    from arema.registry.descriptors import JsonValue

    def _sync_before_model(
        _callback_context: CallbackContext,
        _llm_request: LlmRequest,
    ) -> LlmResponse | None:
        raise NotImplementedError

    async def _async_before_model(
        _callback_context: CallbackContext,
        _llm_request: LlmRequest,
    ) -> LlmResponse | None:
        raise NotImplementedError

    def _sync_before_tool(
        _tool: BaseTool,
        _args: dict[str, Any],
        _tool_context: ToolContext,
    ) -> dict[str, Any] | None:
        raise NotImplementedError

    async def _async_before_tool(
        _tool: BaseTool,
        _args: dict[str, Any],
        _tool_context: ToolContext,
    ) -> dict[str, Any] | None:
        raise NotImplementedError

    def _sync_after_tool(
        _tool: BaseTool,
        _args: dict[str, Any],
        _tool_context: ToolContext,
        _tool_response: dict[str, Any],
    ) -> dict[str, Any] | None:
        raise NotImplementedError

    async def _async_tool_error(
        _tool: BaseTool,
        _args: dict[str, Any],
        _tool_context: ToolContext,
        _error: Exception,
    ) -> dict[str, Any] | None:
        raise NotImplementedError

    def _sync_tool_memory(
        _tool: BaseTool,
        _args: dict[str, Any],
        _tool_context: ToolContext,
        _tool_response: dict[str, Any],
    ) -> dict[str, Any] | None:
        raise NotImplementedError

    def _assert_callback_contracts() -> None:
        profile = RuntimeProfile(
            id="typed",
            extra_before_model=(_sync_before_model, _async_before_model),
            extra_before_tool=(_sync_before_tool, _async_before_tool),
            extra_after_tool=(_sync_after_tool,),
        )
        callbacks = ToolLifecycleCallbacks(
            before=(_sync_before_tool,),
            after=(_sync_after_tool,),
            on_error=(_async_tool_error,),
            memory=(_sync_tool_memory,),
        )

        assert_type(profile.extra_before_model, tuple[BeforeModelCallback, ...])
        assert_type(profile.extra_before_tool, tuple[BeforeToolCallback, ...])
        assert_type(profile.extra_after_tool, tuple[AfterToolCallback, ...])
        assert_type(callbacks.before, tuple[BeforeToolCallback, ...])
        assert_type(callbacks.after, tuple[AfterToolCallback, ...])
        assert_type(callbacks.on_error, tuple[ToolErrorCallback, ...])
        assert_type(callbacks.memory, tuple[ToolMemoryCallback, ...])


def _agent_factory(_context: object) -> object:
    raise NotImplementedError


def _concrete_tool() -> object:
    return object()


def _before_model_callback(_callback_context: object, _llm_request: object) -> None:
    return None


def _tool_factory(_context: object) -> ToolLike:
    return _concrete_tool


def agent_descriptor(
    capability_id: str,
    *,
    runtime_profile_id: str = "safe_default",
    tool_ids: tuple[str, ...] = (),
    mcp_server_ids: tuple[str, ...] = (),
    sub_agent_ids: tuple[str, ...] = (),
    metadata: Mapping[str, JsonValue] | None = None,
) -> AgentDescriptor:
    """Build a small agent descriptor for catalog tests."""
    return AgentDescriptor(
        id=capability_id,
        name=capability_id,
        description=f"{capability_id} test agent",
        prompt_id=f"{capability_id}_prompt",
        factory=cast("AgentFactory", _agent_factory),
        runtime_profile_id=runtime_profile_id,
        tool_ids=tool_ids,
        mcp_server_ids=mcp_server_ids,
        sub_agent_ids=sub_agent_ids,
        metadata=metadata or {},
    )


def tool_descriptor(capability_id: str) -> ToolDescriptor:
    """Build a valid concrete tool descriptor for catalog tests."""
    return ToolDescriptor(
        id=capability_id,
        description=f"{capability_id} test tool",
        tool=_concrete_tool,
    )


def valid_builder(*, agent: AgentDescriptor | None = None) -> CatalogBuilder:
    """Build a catalog containing the safe profile and one root agent."""
    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_agent(agent or agent_descriptor("smoke"))
    return builder


def direct_catalog(
    *,
    root_agent_id: str = "smoke",
    runtime_profiles: Mapping[str, RuntimeProfile] | None = None,
    agents: Mapping[str, AgentDescriptor] | None = None,
    tools: Mapping[str, ToolDescriptor] | None = None,
    mcp_servers: Mapping[str, McpServerDescriptor] | None = None,
) -> CapabilityCatalog:
    """Construct a catalog directly with valid defaults for omitted registries."""
    return CapabilityCatalog(
        root_agent_id=root_agent_id,
        runtime_profiles=(
            runtime_profiles
            if runtime_profiles is not None
            else {"safe_default": RuntimeProfile.safe_default()}
        ),
        agents=agents if agents is not None else {"smoke": agent_descriptor("smoke")},
        tools=tools if tools is not None else {},
        mcp_servers=mcp_servers if mcp_servers is not None else {},
    )


def deep_chain_builder(agent_count: int, *, cycle_to: int | None = None) -> CatalogBuilder:
    """Build a deterministic chain, optionally ending with a back edge."""
    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    for index in range(agent_count):
        sub_agent_ids: tuple[str, ...]
        if index + 1 < agent_count:
            sub_agent_ids = (f"agent-{index + 1:04d}",)
        elif cycle_to is not None:
            sub_agent_ids = (f"agent-{cycle_to:04d}",)
        else:
            sub_agent_ids = ()
        builder.add_agent(
            agent_descriptor(
                f"agent-{index:04d}",
                sub_agent_ids=sub_agent_ids,
            )
        )
    return builder


def test_catalog_accepts_one_root_and_empty_capability_registries() -> None:
    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_agent(agent_descriptor("smoke"))
    catalog = builder.freeze(root_agent_id="smoke")
    assert catalog.root_agent_id == "smoke"
    assert tuple(catalog.agents) == ("smoke",)
    assert not catalog.tools
    assert not catalog.mcp_servers


def test_direct_catalog_construction_accepts_valid_immutable_registries() -> None:
    runtime_profiles = {"safe_default": RuntimeProfile.safe_default()}
    agents = {"smoke": agent_descriptor("smoke")}

    catalog = direct_catalog(runtime_profiles=runtime_profiles, agents=agents)
    runtime_profiles.clear()
    agents.clear()

    assert tuple(catalog.runtime_profiles) == ("safe_default",)
    assert tuple(catalog.agents) == ("smoke",)
    with pytest.raises(TypeError):
        cast("dict[str, AgentDescriptor]", catalog.agents)["other"] = agent_descriptor("other")


def test_direct_catalog_construction_rejects_missing_root() -> None:
    with pytest.raises(InvalidRootError, match="missing"):
        direct_catalog(root_agent_id="missing")


def test_direct_catalog_construction_rejects_mismatched_registry_keys() -> None:
    with pytest.raises(InvalidCapabilityDescriptorError, match=r"wrong.*safe_default"):
        direct_catalog(runtime_profiles={"wrong": RuntimeProfile.safe_default()})

    with pytest.raises(InvalidCapabilityDescriptorError, match=r"smoke.*other"):
        direct_catalog(agents={"smoke": agent_descriptor("other")})

    with pytest.raises(InvalidCapabilityDescriptorError, match=r"wrong.*lookup"):
        direct_catalog(tools={"wrong": tool_descriptor("lookup")})

    with pytest.raises(InvalidCapabilityDescriptorError, match=r"wrong.*local"):
        direct_catalog(
            mcp_servers={
                "wrong": McpServerDescriptor(
                    id="local",
                    transport=StdioTransport(command="serve"),
                )
            }
        )


def test_direct_catalog_construction_rejects_invalid_reference() -> None:
    with pytest.raises(UnresolvedCapabilityError, match="missing"):
        direct_catalog(agents={"smoke": agent_descriptor("smoke", tool_ids=("missing",))})


def test_failed_freeze_can_be_repaired_before_successfully_freezing() -> None:
    builder = valid_builder(agent=agent_descriptor("smoke", tool_ids=("missing",)))

    with pytest.raises(UnresolvedCapabilityError, match="missing"):
        builder.freeze("smoke")

    builder.add_tool(tool_descriptor("missing"))
    catalog = builder.freeze("smoke")

    assert tuple(catalog.tools) == ("missing",)
    with pytest.raises(CatalogFrozenError):
        builder.add_tool(tool_descriptor("later"))


def test_catalog_freeze_accepts_positional_root_agent_id() -> None:
    catalog = valid_builder().freeze("smoke")

    assert catalog.root_agent_id == "smoke"


def test_runtime_profile_safe_default_enables_guarded_history_runtime() -> None:
    profile = RuntimeProfile.safe_default()

    assert profile.id == "safe_default"
    assert profile.context_mode is ContextMode.HISTORY
    assert profile.capture_request
    assert profile.throttle_model
    assert profile.retry_model
    assert profile.enforce_turn_limit
    assert profile.enforce_context_budget
    assert profile.record_metrics
    assert profile.guard_tools
    assert profile.record_memory
    assert profile.compact_tool_output


@pytest.mark.parametrize(
    ("profile", "field"),
    [
        (RuntimeProfile(id="custom", context_mode=cast("Any", "history")), "context_mode"),
        (RuntimeProfile(id="custom", capture_request=cast("Any", 1)), "capture_request"),
        (RuntimeProfile(id="custom", throttle_model=cast("Any", "yes")), "throttle_model"),
        (RuntimeProfile(id="custom", retry_model=cast("Any", 1)), "retry_model"),
        (
            RuntimeProfile(id="custom", enforce_turn_limit=cast("Any", "yes")),
            "enforce_turn_limit",
        ),
        (
            RuntimeProfile(id="custom", enforce_context_budget=cast("Any", 1)),
            "enforce_context_budget",
        ),
        (RuntimeProfile(id="custom", record_metrics=cast("Any", "yes")), "record_metrics"),
        (RuntimeProfile(id="custom", guard_tools=cast("Any", 1)), "guard_tools"),
        (RuntimeProfile(id="custom", record_memory=cast("Any", "yes")), "record_memory"),
        (
            RuntimeProfile(id="custom", compact_tool_output=cast("Any", 1)),
            "compact_tool_output",
        ),
    ],
)
def test_catalog_rejects_invalid_runtime_profile_scalar_types(
    profile: RuntimeProfile,
    field: str,
) -> None:
    builder = CatalogBuilder()
    builder.add_runtime_profile(profile)
    builder.add_agent(agent_descriptor("smoke", runtime_profile_id="custom"))

    with pytest.raises(InvalidCapabilityDescriptorError, match=rf"custom.*{field}"):
        builder.freeze("smoke")


@pytest.mark.parametrize(
    ("factory", "error_type", "field"),
    [
        (
            lambda: RuntimeProfile(id="custom", extra_before_model=cast("Any", "callback")),
            InvalidCapabilityDescriptorError,
            "extra_before_model",
        ),
        (
            lambda: RuntimeProfile(id="custom", extra_before_tool=cast("Any", "callback")),
            InvalidCapabilityDescriptorError,
            "extra_before_tool",
        ),
        (
            lambda: RuntimeProfile(id="custom", extra_after_tool=cast("Any", "callback")),
            InvalidCapabilityDescriptorError,
            "extra_after_tool",
        ),
        (
            lambda: agent_descriptor("smoke", tool_ids=cast("Any", "lookup")),
            InvalidCapabilityDescriptorError,
            "tool_ids",
        ),
        (
            lambda: agent_descriptor("smoke", mcp_server_ids=cast("Any", "local")),
            InvalidCapabilityDescriptorError,
            "mcp_server_ids",
        ),
        (
            lambda: agent_descriptor("smoke", sub_agent_ids=cast("Any", "child")),
            InvalidCapabilityDescriptorError,
            "sub_agent_ids",
        ),
        (
            lambda: OutputPolicy(drop_fields=cast("Any", "secret")),
            InvalidToolDescriptorError,
            "drop_fields",
        ),
        (
            lambda: OutputPolicy(preserve_fields=cast("Any", "result")),
            InvalidToolDescriptorError,
            "preserve_fields",
        ),
        (
            lambda: ToolLifecycleCallbacks(before=cast("Any", "callback")),
            InvalidToolDescriptorError,
            "before",
        ),
        (
            lambda: ToolLifecycleCallbacks(after=cast("Any", "callback")),
            InvalidToolDescriptorError,
            "after",
        ),
        (
            lambda: ToolLifecycleCallbacks(on_error=cast("Any", "callback")),
            InvalidToolDescriptorError,
            "on_error",
        ),
        (
            lambda: ToolLifecycleCallbacks(memory=cast("Any", "callback")),
            InvalidToolDescriptorError,
            "memory",
        ),
        (
            lambda: ToolDescriptor(
                id="lookup",
                description="lookup tool",
                tool=_concrete_tool,
                memory_codec_ids=cast("Any", "codec"),
            ),
            InvalidToolDescriptorError,
            "memory_codec_ids",
        ),
        (
            lambda: StdioTransport(command="serve", args=cast("Any", "--stdio")),
            InvalidTransportError,
            "args",
        ),
        (
            lambda: McpServerDescriptor(
                id="local",
                transport=StdioTransport(command="serve"),
                tool_allowlist=cast("Any", "lookup"),
            ),
            InvalidTransportError,
            "tool_allowlist",
        ),
    ],
)
def test_tuple_like_fields_reject_text_before_normalization(
    factory: Callable[[], object],
    error_type: type[Exception],
    field: str,
) -> None:
    with pytest.raises(error_type, match=field):
        factory()


def test_tuple_like_fields_reject_bytes_before_normalization() -> None:
    with pytest.raises(InvalidTransportError, match="args"):
        StdioTransport(command="serve", args=cast("Any", b"--stdio"))


def test_catalog_rejects_duplicate_ids() -> None:
    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_agent(agent_descriptor("smoke"))
    with pytest.raises(DuplicateCapabilityError, match="smoke"):
        builder.add_agent(agent_descriptor("smoke"))


def test_catalog_rejects_duplicate_runtime_profile_ids() -> None:
    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())

    with pytest.raises(DuplicateCapabilityError, match="safe_default"):
        builder.add_runtime_profile(RuntimeProfile.safe_default())


def test_catalog_rejects_duplicate_tool_ids() -> None:
    builder = CatalogBuilder()
    builder.add_tool(tool_descriptor("lookup"))

    with pytest.raises(DuplicateCapabilityError, match="lookup"):
        builder.add_tool(tool_descriptor("lookup"))


def test_catalog_rejects_duplicate_mcp_server_ids() -> None:
    builder = CatalogBuilder()
    descriptor = McpServerDescriptor(id="local", transport=StdioTransport(command="serve"))
    builder.add_mcp_server(descriptor)

    with pytest.raises(DuplicateCapabilityError, match="local"):
        builder.add_mcp_server(descriptor)


def test_catalog_rejects_unresolved_tool_reference() -> None:
    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_agent(agent_descriptor("smoke", tool_ids=("missing",)))
    with pytest.raises(UnresolvedCapabilityError, match="missing"):
        builder.freeze(root_agent_id="smoke")


def test_catalog_rejects_unresolved_mcp_server_reference() -> None:
    builder = valid_builder(agent=agent_descriptor("smoke", mcp_server_ids=("missing",)))

    with pytest.raises(UnresolvedCapabilityError, match="missing"):
        builder.freeze(root_agent_id="smoke")


def test_catalog_rejects_unresolved_sub_agent_reference() -> None:
    builder = valid_builder(agent=agent_descriptor("smoke", sub_agent_ids=("missing",)))

    with pytest.raises(UnresolvedCapabilityError, match="missing"):
        builder.freeze(root_agent_id="smoke")


def test_catalog_rejects_unresolved_runtime_profile_reference() -> None:
    builder = valid_builder(agent=agent_descriptor("smoke", runtime_profile_id="missing"))

    with pytest.raises(UnresolvedCapabilityError, match="missing"):
        builder.freeze(root_agent_id="smoke")


def test_catalog_rejects_agent_cycle() -> None:
    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_agent(agent_descriptor("a", sub_agent_ids=("b",)))
    builder.add_agent(agent_descriptor("b", sub_agent_ids=("a",)))
    with pytest.raises(CapabilityCycleError):
        builder.freeze(root_agent_id="a")


def test_catalog_accepts_deep_agent_chain_without_recursion() -> None:
    builder = deep_chain_builder(1_500)

    catalog = builder.freeze("agent-0000")

    assert len(catalog.agents) == 1_500
    assert catalog.agents["agent-1499"].sub_agent_ids == ()


def test_catalog_reports_deep_agent_cycle_with_useful_path() -> None:
    builder = deep_chain_builder(1_500, cycle_to=750)

    with pytest.raises(CapabilityCycleError) as error:
        builder.freeze("agent-0000")

    message = str(error.value)
    assert "agent-0750 -> agent-0751" in message
    assert "agent-1499 -> agent-0750" in message


def test_catalog_rejects_missing_root() -> None:
    builder = valid_builder()

    with pytest.raises(InvalidRootError, match="missing"):
        builder.freeze(root_agent_id="missing")


def test_catalog_rejects_unreachable_agent() -> None:
    builder = valid_builder()
    builder.add_agent(agent_descriptor("orphan"))

    with pytest.raises(UnreachableAgentError, match="orphan"):
        builder.freeze(root_agent_id="smoke")


def test_catalog_rejects_duplicate_agent_capability_references() -> None:
    tool_builder = valid_builder(agent=agent_descriptor("smoke", tool_ids=("lookup", "lookup")))
    tool_builder.add_tool(tool_descriptor("lookup"))
    with pytest.raises(InvalidCapabilityDescriptorError, match=r"smoke.*tool_ids.*lookup"):
        tool_builder.freeze("smoke")

    mcp_builder = valid_builder(agent=agent_descriptor("smoke", mcp_server_ids=("local", "local")))
    mcp_builder.add_mcp_server(
        McpServerDescriptor(id="local", transport=StdioTransport(command="serve"))
    )
    with pytest.raises(InvalidCapabilityDescriptorError, match=r"smoke.*mcp_server_ids.*local"):
        mcp_builder.freeze("smoke")

    sub_agent_builder = valid_builder(
        agent=agent_descriptor("smoke", sub_agent_ids=("child", "child"))
    )
    sub_agent_builder.add_agent(agent_descriptor("child"))
    with pytest.raises(InvalidCapabilityDescriptorError, match=r"smoke.*sub_agent_ids.*child"):
        sub_agent_builder.freeze("smoke")


@pytest.mark.parametrize(
    ("tool", "field"),
    [
        (
            ToolDescriptor(
                id="lookup",
                description="lookup tool",
                tool=_concrete_tool,
                output_policy=OutputPolicy(drop_fields=("secret", "secret")),
            ),
            "drop_fields",
        ),
        (
            ToolDescriptor(
                id="lookup",
                description="lookup tool",
                tool=_concrete_tool,
                output_policy=OutputPolicy(preserve_fields=("result", "result")),
            ),
            "preserve_fields",
        ),
        (
            ToolDescriptor(
                id="lookup",
                description="lookup tool",
                tool=_concrete_tool,
                memory_codec_ids=("codec", "codec"),
            ),
            "memory_codec_ids",
        ),
    ],
)
def test_catalog_rejects_each_duplicate_tool_identifier_list(
    tool: ToolDescriptor,
    field: str,
) -> None:
    builder = valid_builder()
    builder.add_tool(tool)

    with pytest.raises(InvalidToolDescriptorError, match=rf"lookup.*duplicate.*{field}"):
        builder.freeze("smoke")


def test_catalog_rejects_duplicate_mcp_tool_allowlist() -> None:
    mcp_builder = valid_builder()
    mcp_builder.add_mcp_server(
        McpServerDescriptor(
            id="local",
            transport=StdioTransport(command="serve"),
            tool_allowlist=("lookup", "lookup"),
        )
    )
    with pytest.raises(InvalidTransportError, match=r"local.*tool_allowlist.*lookup"):
        mcp_builder.freeze("smoke")


@pytest.mark.parametrize(
    "descriptor",
    [
        agent_descriptor("smoke", tool_ids=("",)),
        ToolDescriptor(
            id="lookup",
            description="lookup tool",
            tool=_concrete_tool,
            memory_codec_ids=(cast("Any", 1),),
        ),
        McpServerDescriptor(
            id="local",
            transport=StdioTransport(command="serve"),
            tool_allowlist=("",),
        ),
    ],
)
def test_catalog_rejects_invalid_tuple_members(
    descriptor: AgentDescriptor | ToolDescriptor | McpServerDescriptor,
) -> None:
    builder = valid_builder(agent=descriptor if isinstance(descriptor, AgentDescriptor) else None)
    if isinstance(descriptor, ToolDescriptor):
        builder.add_tool(descriptor)
    elif isinstance(descriptor, McpServerDescriptor):
        builder.add_mcp_server(descriptor)

    with pytest.raises(
        (InvalidCapabilityDescriptorError, InvalidToolDescriptorError, InvalidTransportError)
    ):
        builder.freeze("smoke")


@pytest.mark.parametrize(
    ("tool", "factory"),
    [
        (None, None),
        (_concrete_tool, cast("ToolFactory", _tool_factory)),
    ],
    ids=("neither", "both"),
)
def test_catalog_rejects_invalid_tool_source_selection(
    tool: Callable[..., object] | None,
    factory: ToolFactory | None,
) -> None:
    builder = valid_builder()
    builder.add_tool(
        ToolDescriptor(
            id="invalid",
            description="invalid source selection",
            tool=tool,
            factory=factory,
        )
    )

    with pytest.raises(InvalidToolDescriptorError, match="invalid"):
        builder.freeze(root_agent_id="smoke")


@pytest.mark.parametrize(
    "transport",
    [
        StdioTransport(command=""),
        StdioTransport(command="serve", connect_timeout=0),
        SseTransport(url=""),
        SseTransport(url="https://mcp.example.test", connect_timeout=-1),
        SseTransport(url="https://mcp.example.test", read_timeout=0),
        StreamableHttpTransport(url=""),
        StreamableHttpTransport(url="https://mcp.example.test", connect_timeout=0),
        StreamableHttpTransport(url="https://mcp.example.test", read_timeout=-1),
        SseTransport(url="https://mcp.example.test", connect_timeout=float("nan")),
    ],
)
def test_catalog_rejects_invalid_transport_fields(
    transport: StdioTransport | SseTransport | StreamableHttpTransport,
) -> None:
    builder = valid_builder()
    builder.add_mcp_server(McpServerDescriptor(id="invalid", transport=transport))

    with pytest.raises(InvalidTransportError, match="invalid"):
        builder.freeze(root_agent_id="smoke")


@pytest.mark.parametrize(
    ("transport", "field"),
    [
        (StdioTransport(command="serve", connect_timeout=float("inf")), "connect_timeout"),
        (SseTransport(url="https://mcp.example.test", read_timeout=float("inf")), "read_timeout"),
        (
            StreamableHttpTransport(
                url="https://mcp.example.test",
                connect_timeout=float("-inf"),
            ),
            "connect_timeout",
        ),
        (
            StreamableHttpTransport(
                url="https://mcp.example.test",
                read_timeout=float("-inf"),
            ),
            "read_timeout",
        ),
    ],
)
def test_catalog_rejects_non_finite_transport_timeouts(
    transport: StdioTransport | SseTransport | StreamableHttpTransport,
    field: str,
) -> None:
    builder = valid_builder()
    builder.add_mcp_server(McpServerDescriptor(id="invalid", transport=transport))

    with pytest.raises(InvalidTransportError, match=rf"invalid.*{field}"):
        builder.freeze(root_agent_id="smoke")


@pytest.mark.parametrize(
    ("server", "field"),
    [
        (
            McpServerDescriptor(
                id="local",
                transport=StdioTransport(command="serve"),
                required=cast("Any", 1),
            ),
            "required",
        ),
        (
            McpServerDescriptor(
                id="local",
                transport=StreamableHttpTransport(
                    url="https://mcp.example.test",
                    terminate_on_close=cast("Any", 1),
                ),
            ),
            "terminate_on_close",
        ),
    ],
)
def test_catalog_rejects_non_boolean_transport_and_mcp_flags(
    server: McpServerDescriptor,
    field: str,
) -> None:
    builder = valid_builder()
    builder.add_mcp_server(server)

    with pytest.raises(InvalidTransportError, match=rf"local.*{field}"):
        builder.freeze("smoke")


@pytest.mark.parametrize(
    "transport",
    [
        SseTransport(url="ftp://mcp.example.test"),
        SseTransport(url="mcp.example.test"),
        StreamableHttpTransport(url="https:///missing-host"),
        StreamableHttpTransport(url="https://user:secret@mcp.example.test"),
    ],
)
def test_catalog_rejects_unsafe_http_transport_urls(
    transport: SseTransport | StreamableHttpTransport,
) -> None:
    builder = valid_builder()
    builder.add_mcp_server(McpServerDescriptor(id="local", transport=transport))

    with pytest.raises(InvalidTransportError, match=r"local.*URL"):
        builder.freeze("smoke")


@pytest.mark.parametrize(
    "unsafe_character",
    [" ", "\t", "\n", "\r", "\0", "\x1f", "\x7f"],
    ids=("space", "tab", "line-feed", "carriage-return", "nul", "unit-separator", "delete"),
)
def test_catalog_rejects_raw_whitespace_and_ascii_controls_in_http_urls(
    unsafe_character: str,
) -> None:
    builder = valid_builder()
    builder.add_mcp_server(
        McpServerDescriptor(
            id="local",
            transport=SseTransport(url=f"https://mcp.example.test/a{unsafe_character}b"),
        )
    )

    with pytest.raises(InvalidTransportError, match=r"local.*URL"):
        builder.freeze("smoke")


def test_catalog_accepts_http_transport_urls_without_network_validation() -> None:
    builder = valid_builder()
    builder.add_mcp_server(
        McpServerDescriptor(
            id="sse",
            transport=SseTransport(url="http://localhost:8123/events"),
        )
    )
    builder.add_mcp_server(
        McpServerDescriptor(
            id="stream",
            transport=StreamableHttpTransport(url="https://münich.example/v1?tenant=test"),
        )
    )

    catalog = builder.freeze("smoke")

    assert tuple(catalog.mcp_servers) == ("sse", "stream")


@pytest.mark.parametrize(
    ("transport", "field"),
    [
        (StdioTransport(command="bad\0command"), "command"),
        (StdioTransport(command="serve", args=("bad\0arg",)), "args"),
        (StdioTransport(command="serve", env={"BAD\0KEY": "value"}), "environment"),
        (StdioTransport(command="serve", env={"TOKEN": "bad\0value"}), "environment"),
    ],
)
def test_catalog_rejects_nul_before_stdio_subprocess_construction(
    transport: StdioTransport,
    field: str,
) -> None:
    builder = valid_builder()
    builder.add_mcp_server(McpServerDescriptor(id="local", transport=transport))

    with pytest.raises(InvalidTransportError, match=rf"local.*{field}"):
        builder.freeze("smoke")


@pytest.mark.parametrize("key", ["", "BAD=NAME"])
def test_catalog_rejects_invalid_stdio_environment_names(key: str) -> None:
    builder = valid_builder()
    builder.add_mcp_server(
        McpServerDescriptor(
            id="local",
            transport=StdioTransport(command="serve", env={key: "value"}),
        )
    )

    with pytest.raises(InvalidTransportError, match=r"local.*environment"):
        builder.freeze("smoke")


def test_catalog_rejects_non_string_stdio_environment_values() -> None:
    builder = valid_builder()
    builder.add_mcp_server(
        McpServerDescriptor(
            id="local",
            transport=StdioTransport(
                command="serve",
                env=cast("Any", {"TOKEN": 1}),
            ),
        )
    )

    with pytest.raises(InvalidTransportError, match=r"local.*environment.*TOKEN"):
        builder.freeze("smoke")


def test_catalog_accepts_subprocess_compatible_stdio_environment() -> None:
    builder = valid_builder()
    builder.add_mcp_server(
        McpServerDescriptor(
            id="local",
            transport=StdioTransport(
                command="serve",
                env={"1TOKEN": "", "BAD-NAME": "value", "BAD NAME": "also valid"},
            ),
        )
    )

    assert "local" in builder.freeze("smoke").mcp_servers


@pytest.mark.parametrize("name", ["", "Bad Header", "Bad:Header", "X-Ünicode"])
def test_catalog_rejects_invalid_http_header_names(name: str) -> None:
    builder = valid_builder()
    builder.add_mcp_server(
        McpServerDescriptor(
            id="local",
            transport=SseTransport(
                url="https://mcp.example.test",
                headers={name: "value"},
            ),
        )
    )

    with pytest.raises(InvalidTransportError, match=r"local.*header"):
        builder.freeze("smoke")


@pytest.mark.parametrize(
    "value",
    [
        "line\0break",
        "line\rbreak",
        "line\nbreak",
        "line\x01break",
        "line\x1fbreak",
        "line\x7fbreak",
        "café",
        cast("Any", 1),
    ],
)
def test_catalog_rejects_unsafe_http_header_values(value: object) -> None:
    builder = valid_builder()
    builder.add_mcp_server(
        McpServerDescriptor(
            id="local",
            transport=StreamableHttpTransport(
                url="https://mcp.example.test",
                headers=cast("Any", {"X-Trace_ID": value}),
            ),
        )
    )

    with pytest.raises(InvalidTransportError, match=r"local.*header.*X-Trace_ID"):
        builder.freeze("smoke")


def test_catalog_accepts_safe_http_headers_and_tool_prefix() -> None:
    builder = valid_builder()
    builder.add_mcp_server(
        McpServerDescriptor(
            id="local",
            transport=SseTransport(
                url="https://mcp.example.test",
                headers={"X-Trace_ID": "trace\tvalue ~"},
            ),
            tool_allowlist=("lookup-tool",),
            tool_name_prefix="mcp_",
        )
    )

    assert "local" in builder.freeze("smoke").mcp_servers


@pytest.mark.parametrize("prefix", ["bad prefix", "1bad", "bad/prefix"])
def test_catalog_rejects_invalid_mcp_tool_name_prefix(prefix: str) -> None:
    builder = valid_builder()
    builder.add_mcp_server(
        McpServerDescriptor(
            id="local",
            transport=StdioTransport(command="serve"),
            tool_name_prefix=prefix,
        )
    )

    with pytest.raises(InvalidTransportError, match=r"local.*tool_name_prefix"):
        builder.freeze("smoke")


@pytest.mark.parametrize(
    "descriptor",
    [
        RuntimeProfile(id=""),
        agent_descriptor(""),
        McpServerDescriptor(id="", transport=StdioTransport(command="serve")),
    ],
)
def test_catalog_rejects_empty_capability_ids(
    descriptor: RuntimeProfile | AgentDescriptor | McpServerDescriptor,
) -> None:
    builder = CatalogBuilder()
    if isinstance(descriptor, RuntimeProfile):
        builder.add_runtime_profile(descriptor)
        builder.add_runtime_profile(RuntimeProfile.safe_default())
        builder.add_agent(agent_descriptor("smoke"))
    elif isinstance(descriptor, AgentDescriptor):
        builder.add_runtime_profile(RuntimeProfile.safe_default())
        builder.add_agent(descriptor)
    else:
        builder.add_runtime_profile(RuntimeProfile.safe_default())
        builder.add_agent(agent_descriptor("smoke"))
        builder.add_mcp_server(descriptor)

    root_id = "" if isinstance(descriptor, AgentDescriptor) else "smoke"
    with pytest.raises(InvalidCapabilityDescriptorError):
        builder.freeze(root_agent_id=root_id)


@pytest.mark.parametrize(
    "output_policy",
    [
        OutputPolicy(max_chars=0),
        OutputPolicy(max_chars=cast("Any", 1.5)),
        OutputPolicy(max_list_items=-1),
        OutputPolicy(max_list_items=cast("Any", 1.5)),
    ],
)
def test_catalog_rejects_non_positive_output_policy_limits(
    output_policy: OutputPolicy,
) -> None:
    builder = valid_builder()
    builder.add_tool(
        ToolDescriptor(
            id="invalid",
            description="invalid policy",
            tool=_concrete_tool,
            output_policy=output_policy,
        )
    )

    with pytest.raises(InvalidToolDescriptorError, match="invalid"):
        builder.freeze(root_agent_id="smoke")


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_catalog_rejects_non_finite_agent_metadata(value: float) -> None:
    builder = valid_builder(agent=agent_descriptor("smoke", metadata={"score": value}))

    with pytest.raises(InvalidCapabilityDescriptorError, match=r"smoke.*score"):
        builder.freeze("smoke")


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_catalog_rejects_non_finite_tool_metadata(value: float) -> None:
    builder = valid_builder()
    builder.add_tool(
        ToolDescriptor(
            id="lookup",
            description="lookup tool",
            tool=_concrete_tool,
            metadata={"score": value},
        )
    )

    with pytest.raises(InvalidToolDescriptorError, match=r"lookup.*score"):
        builder.freeze("smoke")


def test_catalog_accepts_finite_float_metadata() -> None:
    builder = valid_builder(agent=agent_descriptor("smoke", metadata={"score": 1.25}))
    builder.add_tool(
        ToolDescriptor(
            id="lookup",
            description="lookup tool",
            tool=_concrete_tool,
            metadata={"score": -2.5},
        )
    )

    catalog = builder.freeze("smoke")

    assert catalog.agents["smoke"].metadata["score"] == 1.25
    assert catalog.tools["lookup"].metadata["score"] == -2.5


@pytest.mark.parametrize(
    ("metadata", "match"),
    [
        pytest.param(
            {"engines": {1: "jadx"}},
            r"smoke.*'engines'.*non-string or empty key",
            id="nested-non-string-key",
        ),
        pytest.param(
            {"engines": {"": "jadx"}},
            r"smoke.*'engines'.*non-string or empty key",
            id="nested-empty-key",
        ),
        pytest.param(
            {"engines": {"apk": float("inf")}},
            r"smoke.*'engines\.apk'.*must be finite",
            id="non-finite-nested-in-mapping",
        ),
        pytest.param(
            {"scores": [float("nan")]},
            r"smoke.*'scores\[0\]'.*must be finite",
            id="non-finite-nested-in-sequence",
        ),
        pytest.param(
            {"leaf": object()},
            r"smoke.*'leaf'.*is not a JSON value",
            id="non-json-object-leaf",
        ),
        pytest.param(
            {"leaf": {"a", "b"}},
            r"smoke.*'leaf'.*is not a JSON value",
            id="non-json-set-leaf",
        ),
        pytest.param(
            {"engines": {"apk": b"jadx"}},
            r"smoke.*'engines\.apk'.*is not a JSON value",
            id="non-json-bytes-leaf",
        ),
    ],
)
def test_catalog_rejects_non_json_nested_metadata(
    metadata: Mapping[str, JsonValue], match: str
) -> None:
    # The recursive neutral-core validator underwrites the "a frozen catalog is
    # guaranteed safe to build" invariant: non-JSON metadata must be rejected at
    # every nesting depth, not just at the top level.
    builder = valid_builder(agent=agent_descriptor("smoke", metadata=metadata))

    with pytest.raises(InvalidCapabilityDescriptorError, match=match):
        builder.freeze("smoke")


def test_catalog_accepts_nested_format_engines_metadata() -> None:
    metadata: Mapping[str, JsonValue] = {
        "format_engines": {"apk": "java_decompile", "dex": "java_decompile"},
        "default_engine": "deep_analysis",
    }
    builder = valid_builder(agent=agent_descriptor("smoke", metadata=metadata))

    catalog = builder.freeze("smoke")

    assert catalog.agents["smoke"].metadata["format_engines"] == {
        "apk": "java_decompile",
        "dex": "java_decompile",
    }


def test_catalog_mappings_reject_mutation() -> None:
    builder = valid_builder()
    builder.add_tool(tool_descriptor("lookup"))
    builder.add_mcp_server(
        McpServerDescriptor(id="local", transport=StdioTransport(command="serve"))
    )
    catalog = builder.freeze(root_agent_id="smoke")

    mappings: tuple[Mapping[str, object], ...] = (
        cast("Mapping[str, object]", catalog.runtime_profiles),
        cast("Mapping[str, object]", catalog.agents),
        cast("Mapping[str, object]", catalog.tools),
        cast("Mapping[str, object]", catalog.mcp_servers),
    )
    for mapping in mappings:
        with pytest.raises(TypeError):
            cast("dict[str, object]", mapping)["new"] = object()


def test_descriptor_mappings_are_copied_and_read_only() -> None:
    metadata = {"source": "test"}
    environment = {"TOKEN": "before"}
    headers = {"Authorization": "before"}

    agent = agent_descriptor("smoke", metadata=metadata)
    stdio = StdioTransport(command="serve", env=environment)
    sse = SseTransport(url="https://mcp.example.test", headers=headers)
    http = StreamableHttpTransport(url="https://mcp.example.test", headers=headers)

    metadata["source"] = "after"
    environment["TOKEN"] = "after"
    headers["Authorization"] = "after"

    assert agent.metadata["source"] == "test"
    assert stdio.env["TOKEN"] == "before"
    assert sse.headers["Authorization"] == "before"
    assert http.headers["Authorization"] == "before"
    for mapping in (agent.metadata, stdio.env, sse.headers, http.headers):
        with pytest.raises(TypeError):
            cast("dict[str, object]", mapping)["new"] = object()


def test_descriptor_tuple_fields_are_normalized_and_copied() -> None:
    tool_ids = ["lookup"]
    callbacks: list[BeforeModelCallback] = [_before_model_callback]
    args = ["--stdio"]

    agent = agent_descriptor("smoke", tool_ids=cast("tuple[str, ...]", tool_ids))
    profile = RuntimeProfile(
        id="custom",
        extra_before_model=cast("tuple[BeforeModelCallback, ...]", callbacks),
    )
    transport = StdioTransport(command="serve", args=cast("tuple[str, ...]", args))

    tool_ids.append("later")
    callbacks.append(_before_model_callback)
    args.append("--later")

    assert agent.tool_ids == ("lookup",)
    assert profile.extra_before_model == (_before_model_callback,)
    assert transport.args == ("--stdio",)


def test_builder_rejects_all_mutation_after_freeze() -> None:
    builder = valid_builder()
    catalog = builder.freeze(root_agent_id="smoke")

    mutations = (
        lambda: builder.add_runtime_profile(RuntimeProfile(id="other")),
        lambda: builder.add_agent(agent_descriptor("other")),
        lambda: builder.add_tool(tool_descriptor("other")),
        lambda: builder.add_mcp_server(
            McpServerDescriptor(id="other", transport=StdioTransport(command="serve"))
        ),
        lambda: builder.freeze(root_agent_id="smoke"),
    )
    for mutate in mutations:
        with pytest.raises(CatalogFrozenError):
            mutate()

    assert isinstance(catalog, CapabilityCatalog)


def test_catalog_rejects_agent_referencing_unknown_runtime_profile() -> None:
    builder = valid_builder(agent=agent_descriptor("smoke", runtime_profile_id="ghost_profile"))

    with pytest.raises(UnresolvedCapabilityError, match=r"smoke.*ghost_profile"):
        builder.freeze("smoke")


def test_catalog_exposes_safe_default_in_frozen_runtime_profile_mapping() -> None:
    catalog = valid_builder().freeze("smoke")

    assert "safe_default" in catalog.runtime_profiles
    assert catalog.runtime_profiles["safe_default"] == RuntimeProfile.safe_default()


def test_catalog_runtime_profile_mapping_is_immutable() -> None:
    catalog = valid_builder().freeze("smoke")

    with pytest.raises(TypeError):
        cast("dict[str, RuntimeProfile]", catalog.runtime_profiles)["new"] = RuntimeProfile(
            id="new"
        )


def test_runtime_profile_and_tool_callbacks_default_to_empty_tuples() -> None:
    profile = RuntimeProfile.safe_default()
    callbacks = ToolLifecycleCallbacks()

    assert profile.extra_before_model == ()
    assert profile.extra_before_tool == ()
    assert profile.extra_after_tool == ()
    assert callbacks.before == ()
    assert callbacks.after == ()
    assert callbacks.on_error == ()
    assert callbacks.memory == ()


def test_agent_descriptor_detaches_after_agent_callbacks_and_retains_order() -> None:
    def first(_context: object) -> None:
        pass

    def second(_context: object) -> None:
        pass

    supplied = [first, second]
    descriptor = AgentDescriptor(
        id="smoke",
        name="smoke",
        description="callback test",
        prompt_id="smoke",
        factory=cast("AgentFactory", _agent_factory),
        after_agent_callbacks=cast("Any", supplied),
    )
    supplied.clear()

    assert descriptor.after_agent_callbacks == (first, second)
    assert descriptor.after_agent_callbacks[0] is first
    assert descriptor.after_agent_callbacks[1] is second


def test_agent_descriptor_rejects_text_after_agent_callbacks() -> None:
    with pytest.raises(InvalidCapabilityDescriptorError, match="after_agent_callbacks"):
        AgentDescriptor(
            id="smoke",
            name="smoke",
            description="callback test",
            prompt_id="smoke",
            factory=cast("AgentFactory", _agent_factory),
            after_agent_callbacks=cast("Any", "not-a-callback-sequence"),
        )


@pytest.mark.parametrize(
    "callbacks",
    [
        {_before_model_callback},
        frozenset({_before_model_callback}),
    ],
)
def test_agent_descriptor_rejects_unordered_after_agent_callbacks(callbacks: object) -> None:
    with pytest.raises(InvalidCapabilityDescriptorError, match="after_agent_callbacks"):
        AgentDescriptor(
            id="smoke",
            name="smoke",
            description="callback test",
            prompt_id="smoke",
            factory=cast("AgentFactory", _agent_factory),
            after_agent_callbacks=cast("Any", callbacks),
        )


@pytest.mark.parametrize("invalid_callback", [None, object()])
def test_agent_descriptor_rejects_indexed_non_callable_after_agent_callback(
    invalid_callback: object,
) -> None:
    with pytest.raises(
        InvalidCapabilityDescriptorError,
        match=r"after_agent_callbacks\[1\].*callable",
    ):
        AgentDescriptor(
            id="smoke",
            name="smoke",
            description="callback test",
            prompt_id="smoke",
            factory=cast("AgentFactory", _agent_factory),
            after_agent_callbacks=cast(
                "Any",
                (_before_model_callback, invalid_callback),
            ),
        )


def test_freeze_accepts_composite_root_with_no_prompt() -> None:
    """A prompt-less agent (prompt_id=None) is a valid composite shell root."""
    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_agent(
        AgentDescriptor(
            id="seq_root",
            name="seq_root",
            description="sequential root",
            prompt_id=None,
            factory=cast("AgentFactory", _agent_factory),
            sub_agent_ids=("child",),
        )
    )
    builder.add_agent(agent_descriptor("child"))

    catalog = builder.freeze("seq_root")

    assert catalog.root_agent_id == "seq_root"
    assert catalog.agents["seq_root"].prompt_id is None


@pytest.mark.parametrize(
    "extra",
    [
        {"tool_ids": ("some_tool",)},
        {"mcp_server_ids": ("some_mcp",)},
        {"output_key": "out"},
    ],
)
def test_freeze_rejects_composite_agent_with_llm_only_fields(extra: Mapping[str, object]) -> None:
    """A composite shell (prompt_id=None) must not carry LlmAgent-only fields."""
    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_agent(
        AgentDescriptor(
            id="seq_root",
            name="seq_root",
            description="sequential root",
            prompt_id=None,
            factory=cast("AgentFactory", _agent_factory),
            sub_agent_ids=("child",),
            **extra,  # type: ignore[arg-type]
        )
    )
    builder.add_agent(agent_descriptor("child"))

    with pytest.raises(InvalidCapabilityDescriptorError, match="Composite agent 'seq_root'"):
        builder.freeze("seq_root")


def test_freeze_rejects_composite_agent_with_no_sub_agents() -> None:
    """A composite shell with no children is invalid."""
    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_agent(
        AgentDescriptor(
            id="seq_root",
            name="seq_root",
            description="sequential root",
            prompt_id=None,
            factory=cast("AgentFactory", _agent_factory),
        )
    )

    with pytest.raises(InvalidCapabilityDescriptorError, match="requires at least one sub_agent"):
        builder.freeze("seq_root")


@pytest.mark.parametrize(
    "extra",
    [
        {"prompt_id": "prompt"},
        {"tool_ids": ("some_tool",)},
        {"mcp_server_ids": ("some_mcp",)},
        {"output_key": "out"},
        {"sub_agent_ids": ("child",)},
    ],
)
def test_freeze_rejects_deterministic_leaf_with_incompatible_fields(
    extra: Mapping[str, object],
) -> None:
    fields: dict[str, object] = {
        "id": "gate",
        "name": "gate",
        "description": "deterministic leaf",
        "prompt_id": None,
        "factory": cast("AgentFactory", _agent_factory),
        "kind": AgentKind.DETERMINISTIC,
    }
    fields.update(extra)
    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_agent(AgentDescriptor(**fields))  # type: ignore[arg-type]

    with pytest.raises(InvalidCapabilityDescriptorError, match="Deterministic agent 'gate'"):
        builder.freeze("gate")


@pytest.mark.parametrize(
    ("kind", "prompt_id", "sub_agent_ids"),
    [
        (AgentKind.LLM, None, ()),
        (AgentKind.COMPOSITE, "prompt", ("child",)),
    ],
)
def test_freeze_rejects_explicit_agent_kind_with_incompatible_prompt(
    kind: AgentKind, prompt_id: str | None, sub_agent_ids: tuple[str, ...]
) -> None:
    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_agent(
        AgentDescriptor(
            id="agent",
            name="agent",
            description="agent",
            prompt_id=prompt_id,
            factory=cast("AgentFactory", _agent_factory),
            kind=kind,
            sub_agent_ids=sub_agent_ids,
        )
    )
    if sub_agent_ids:
        builder.add_agent(agent_descriptor("child"))

    with pytest.raises(InvalidCapabilityDescriptorError, match="Agent kind"):
        builder.freeze("agent")
