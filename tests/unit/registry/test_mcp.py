"""Tests for typed, resilient ADK MCP toolset construction."""

from __future__ import annotations

import asyncio
from dataclasses import FrozenInstanceError
from typing import TYPE_CHECKING, cast
from unittest import mock

import pytest
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.mcp_tool.mcp_session_manager import (
    SseConnectionParams,
    StdioConnectionParams,
    StreamableHTTPConnectionParams,
)
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset

from arema.registry import (
    AgentDescriptor,
    CapabilityCatalog,
    McpServerDescriptor,
    RuntimeProfile,
    SseTransport,
    StdioTransport,
    StreamableHttpTransport,
)
from arema.registry import mcp as mcp_module
from arema.registry.errors import InvalidTransportError, MissingEnvironmentValueError
from arema.registry.mcp import (
    McpAvailability,
    McpStatus,
    ResilientMcpToolset,
    _SerializedTool,
    build_mcp_toolset,
)

if TYPE_CHECKING:
    from google.adk.agents import BaseAgent
    from google.adk.agents.readonly_context import ReadonlyContext
    from google.adk.tools.tool_context import ToolContext

    from arema.runtime.agent_factory import AgentBuildContext


def _unused_agent_factory(_context: AgentBuildContext) -> BaseAgent:
    raise NotImplementedError


def optional_sse_descriptor() -> McpServerDescriptor:
    return McpServerDescriptor(
        id="optional",
        transport=SseTransport(url="http://localhost:9000/sse"),
    )


def required_sse_descriptor() -> McpServerDescriptor:
    return McpServerDescriptor(
        id="required",
        transport=SseTransport(url="http://localhost:9000/sse"),
        required=True,
    )


async def _offline(*_args: object, **_kwargs: object) -> list[BaseTool]:
    raise ConnectionError("offline")


def test_streamable_http_descriptor_builds_adk_params() -> None:
    descriptor = McpServerDescriptor(
        id="sample",
        transport=StreamableHttpTransport(url="http://localhost:9000/mcp"),
    )

    toolset = build_mcp_toolset(descriptor)

    assert isinstance(toolset.connection_params, StreamableHTTPConnectionParams)
    assert toolset.connection_params.url == "http://localhost:9000/mcp"
    assert toolset.connection_params.headers is None
    assert toolset.connection_params.timeout == 5.0
    assert toolset.connection_params.sse_read_timeout == 600.0
    assert toolset.connection_params.terminate_on_close is True
    assert toolset.tool_name_prefix is None


def test_stdio_descriptor_builds_exact_adk_params() -> None:
    descriptor = McpServerDescriptor(
        id="stdio",
        transport=StdioTransport(
            command="uv",
            args=("run", "server.py"),
            env={"MODE": "safe"},
            connect_timeout=17.5,
        ),
    )

    toolset = build_mcp_toolset(descriptor)

    assert isinstance(toolset.connection_params, StdioConnectionParams)
    assert toolset.connection_params.timeout == 17.5
    assert toolset.connection_params.server_params.command == "uv"
    assert toolset.connection_params.server_params.args == ["run", "server.py"]
    assert toolset.connection_params.server_params.env == {"MODE": "safe"}


def test_stdio_descriptor_preserves_adk_empty_environment_default() -> None:
    descriptor = McpServerDescriptor(
        id="stdio",
        transport=StdioTransport(command="server"),
    )

    toolset = build_mcp_toolset(descriptor)

    assert isinstance(toolset.connection_params, StdioConnectionParams)
    assert toolset.connection_params.timeout == 120.0
    assert toolset.connection_params.server_params.args == []
    assert toolset.connection_params.server_params.env is None


def test_sse_descriptor_builds_exact_adk_params() -> None:
    descriptor = McpServerDescriptor(
        id="sse",
        transport=SseTransport(
            url="https://example.test/sse",
            headers={"X-Mode": "safe"},
            connect_timeout=2.5,
            read_timeout=45.0,
        ),
    )

    toolset = build_mcp_toolset(descriptor)

    assert isinstance(toolset.connection_params, SseConnectionParams)
    assert toolset.connection_params.url == "https://example.test/sse"
    assert toolset.connection_params.headers == {"X-Mode": "safe"}
    assert toolset.connection_params.timeout == 2.5
    assert toolset.connection_params.sse_read_timeout == 45.0


def test_streamable_http_propagates_terminate_on_close() -> None:
    descriptor = McpServerDescriptor(
        id="http",
        transport=StreamableHttpTransport(
            url="https://example.test/mcp",
            terminate_on_close=False,
        ),
    )

    toolset = build_mcp_toolset(descriptor)

    assert isinstance(toolset.connection_params, StreamableHTTPConnectionParams)
    assert toolset.connection_params.terminate_on_close is False


def test_descriptor_prefix_is_propagated() -> None:
    descriptor = McpServerDescriptor(
        id="prefixed",
        transport=SseTransport(url="http://localhost:9000/sse"),
        tool_name_prefix="remote",
    )

    toolset = build_mcp_toolset(descriptor)

    assert toolset.tool_name_prefix == "remote"


def test_allowlist_uses_adk_tool_filter_and_excludes_other_tools() -> None:
    descriptor = McpServerDescriptor(
        id="filtered",
        transport=SseTransport(url="http://localhost:9000/sse"),
        tool_allowlist=("allowed",),
    )
    allowed = BaseTool(name="allowed", description="allowed")
    excluded = BaseTool(name="excluded", description="excluded")
    readonly_context = cast("ReadonlyContext", None)

    toolset = build_mcp_toolset(descriptor)

    assert toolset.tool_filter == ["allowed"]
    assert toolset._is_tool_selected(allowed, readonly_context)
    assert not toolset._is_tool_selected(excluded, readonly_context)


def test_empty_allowlist_disables_adk_tool_filter() -> None:
    toolset = build_mcp_toolset(optional_sse_descriptor())

    assert toolset.tool_filter is None


def test_stdio_environment_resolves_embedded_and_repeated_placeholders() -> None:
    descriptor = McpServerDescriptor(
        id="stdio-env",
        transport=StdioTransport(
            command="server",
            env={"AUTH": "prefix-${USER}:${TOKEN}:${USER}-suffix"},
        ),
    )

    toolset = build_mcp_toolset(
        descriptor,
        environment={"USER": "agent", "TOKEN": "resolved-token"},
    )

    assert isinstance(toolset.connection_params, StdioConnectionParams)
    assert toolset.connection_params.server_params.env == {
        "AUTH": "prefix-agent:resolved-token:agent-suffix"
    }


def test_http_headers_resolve_embedded_and_multiple_placeholders() -> None:
    descriptor = McpServerDescriptor(
        id="http-headers",
        transport=SseTransport(
            url="https://example.test/sse",
            headers={"Authorization": "Scheme ${USER}:${TOKEN}:${USER}"},
        ),
    )

    toolset = build_mcp_toolset(
        descriptor,
        environment={"USER": "agent", "TOKEN": "resolved-token"},
    )

    assert isinstance(toolset.connection_params, SseConnectionParams)
    assert toolset.connection_params.headers == {
        "Authorization": "Scheme agent:resolved-token:agent"
    }


def test_default_process_environment_is_used_for_substitution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AREMA_MCP_TEST_TOKEN", "from-process-environment")
    descriptor = McpServerDescriptor(
        id="default-env",
        transport=StdioTransport(
            command="server",
            env={"TOKEN": "${AREMA_MCP_TEST_TOKEN}"},
        ),
    )

    toolset = build_mcp_toolset(descriptor)

    assert isinstance(toolset.connection_params, StdioConnectionParams)
    assert toolset.connection_params.server_params.env == {"TOKEN": "from-process-environment"}


def test_non_placeholder_syntax_is_preserved_literally() -> None:
    descriptor = McpServerDescriptor(
        id="literal-env",
        transport=StdioTransport(
            command="server",
            env={
                "SHELL": "$NAME",
                "WINDOWS": "%NAME%",
                "MALFORMED": "${1NAME}",
                "TEXT": "unrelated text",
            },
        ),
    )

    toolset = build_mcp_toolset(descriptor, environment={})

    assert isinstance(toolset.connection_params, StdioConnectionParams)
    assert toolset.connection_params.server_params.env == {
        "SHELL": "$NAME",
        "WINDOWS": "%NAME%",
        "MALFORMED": "${1NAME}",
        "TEXT": "unrelated text",
    }


def test_missing_stdio_environment_placeholder_has_sanitized_context() -> None:
    descriptor = McpServerDescriptor(
        id="missing-stdio",
        transport=StdioTransport(
            command="server",
            env={"AUTH": "prefix-${PRESENT}-${MISSING_TOKEN}"},
        ),
    )

    with pytest.raises(MissingEnvironmentValueError) as caught:
        build_mcp_toolset(descriptor, environment={"PRESENT": "secret-value"})

    message = str(caught.value)
    assert "missing-stdio" in message
    assert "MISSING_TOKEN" in message
    assert "AUTH" in message
    assert "secret-value" not in message
    assert "prefix" not in message


def test_missing_header_placeholder_has_sanitized_context() -> None:
    descriptor = McpServerDescriptor(
        id="missing-header",
        transport=SseTransport(
            url="https://example.test/sse",
            headers={"Authorization": "Bearer ${MISSING_TOKEN}"},
        ),
    )

    with pytest.raises(MissingEnvironmentValueError) as caught:
        build_mcp_toolset(descriptor, environment={"UNRELATED": "secret-value"})

    message = str(caught.value)
    assert "missing-header" in message
    assert "MISSING_TOKEN" in message
    assert "Authorization" in message
    assert "secret-value" not in message
    assert "Bearer" not in message


def test_unsafe_substituted_header_fails_without_exposing_value() -> None:
    descriptor = McpServerDescriptor(
        id="unsafe-header",
        transport=StreamableHttpTransport(
            url="https://example.test/mcp",
            headers={"Authorization": "Bearer ${TOKEN}"},
        ),
    )
    secret = "resolved-secret\nInjected: value"

    with pytest.raises(InvalidTransportError) as caught:
        build_mcp_toolset(descriptor, environment={"TOKEN": secret})

    message = str(caught.value)
    assert "unsafe-header" in message
    assert "Authorization" in message
    assert secret not in message
    assert "resolved-secret" not in message
    assert "Injected" not in message


def test_availability_starts_unknown_and_snapshots_are_frozen() -> None:
    toolset = build_mcp_toolset(optional_sse_descriptor())
    availability = toolset.availability

    assert availability == McpAvailability(status=McpStatus.UNKNOWN)
    field_name = "status"
    with pytest.raises(FrozenInstanceError):
        setattr(availability, field_name, McpStatus.AVAILABLE)


async def test_success_marks_server_available(monkeypatch: pytest.MonkeyPatch) -> None:
    tool = BaseTool(name="working", description="working")

    async def succeed(*_args: object, **_kwargs: object) -> list[BaseTool]:
        return [tool]

    monkeypatch.setattr(McpToolset, "get_tools", succeed)
    toolset = build_mcp_toolset(optional_sse_descriptor())
    initial = toolset.availability

    resolved = await toolset.get_tools()
    # Each resolved tool is a serializing wrapper that preserves the inner tool's
    # name (so ADK still resolves it for execution) and delegates to it.
    assert [t.name for t in resolved] == ["working"]
    assert all(isinstance(t, _SerializedTool) for t in resolved)
    assert toolset.availability == McpAvailability(status=McpStatus.AVAILABLE)
    assert toolset.availability is not initial
    assert initial.status is McpStatus.UNKNOWN


async def test_get_tools_serializes_concurrent_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    """A parallel batch of tool calls must run one at a time against one session.

    ADK dispatches a model turn's function calls concurrently; the wrapper's
    shared per-toolset lock must force them to never overlap, so a stateful MCP
    server (one that tracks a current target) is never hit by two in-flight
    requests at once.
    """
    active = 0
    max_active = 0

    class _StatefulTool(BaseTool):
        def __init__(self, name: str) -> None:
            super().__init__(name=name, description=name)

        async def run_async(self, *, args: dict[str, object], tool_context: object) -> str:
            nonlocal active, max_active
            del args, tool_context  # required by the tool interface, unused here
            active += 1
            max_active = max(max_active, active)
            await asyncio.sleep(0.02)  # hold the "session" so overlap would show
            active -= 1
            return self.name

    tools = [_StatefulTool(f"t{i}") for i in range(5)]

    async def succeed(*_args: object, **_kwargs: object) -> list[BaseTool]:
        return list(tools)

    monkeypatch.setattr(McpToolset, "get_tools", succeed)
    toolset = build_mcp_toolset(optional_sse_descriptor())
    resolved = await toolset.get_tools()

    # Fire every tool at once, exactly as ADK's asyncio.gather would.
    results = await asyncio.gather(
        *(t.run_async(args={}, tool_context=cast("ToolContext", None)) for t in resolved)
    )

    assert sorted(results) == ["t0", "t1", "t2", "t3", "t4"]
    assert max_active == 1, "tool calls to one session must never overlap"


async def test_optional_server_degrades_to_empty_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    toolset = build_mcp_toolset(optional_sse_descriptor())
    monkeypatch.setattr(McpToolset, "get_tools", _offline)

    assert await toolset.get_tools() == []
    assert toolset.availability.status is McpStatus.UNAVAILABLE
    assert toolset.availability.error_type == "ConnectionError"


async def test_optional_server_degrades_when_connect_fails_beside_cancellation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """anyio cancels siblings the moment one task fails, so an optional server that
    cannot connect surfaces a ConnectError beside a CancelledError. It must degrade
    to [], not crash by treating the fallout cancellation as a genuine shutdown."""

    async def fail_with_group(*_args: object, **_kwargs: object) -> list[BaseTool]:
        group = BaseExceptionGroup(
            "task group", [ConnectionRefusedError("refused"), asyncio.CancelledError()]
        )
        raise ConnectionError("Failed to get tools from MCP server") from group

    monkeypatch.setattr(McpToolset, "get_tools", fail_with_group)
    toolset = build_mcp_toolset(optional_sse_descriptor())

    assert await toolset.get_tools() == []
    assert toolset.availability.status is McpStatus.UNAVAILABLE


async def test_required_server_propagates_connection_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    toolset = build_mcp_toolset(required_sse_descriptor())
    monkeypatch.setattr(McpToolset, "get_tools", _offline)

    with pytest.raises(ConnectionError, match="offline"):
        await toolset.get_tools()

    assert toolset.availability.status is McpStatus.UNAVAILABLE
    assert toolset.availability.error_type == "ConnectionError"


async def test_optional_failure_log_is_structured_and_secret_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    logger = mock.Mock()
    secret_header = "secret-header-value"
    secret_env = "secret-env-value"

    async def fail_with_secrets(*_args: object, **_kwargs: object) -> list[BaseTool]:
        raise ConnectionError(f"offline {secret_header} {secret_env}")

    monkeypatch.setattr(McpToolset, "get_tools", fail_with_secrets)
    monkeypatch.setattr(mcp_module, "logger", logger)
    toolset = build_mcp_toolset(optional_sse_descriptor())

    assert await toolset.get_tools() == []
    logger.warning.assert_called_once_with(
        "Optional MCP server unavailable",
        descriptor_id="optional",
        error_type="ConnectionError",
    )
    log_record = repr(logger.mock_calls)
    assert "offline" not in log_record
    assert secret_header not in log_record
    assert secret_env not in log_record


async def test_cancelled_error_always_propagates_without_status_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def cancel(*_args: object, **_kwargs: object) -> list[BaseTool]:
        raise asyncio.CancelledError

    monkeypatch.setattr(McpToolset, "get_tools", cancel)
    toolset = build_mcp_toolset(optional_sse_descriptor())

    with pytest.raises(asyncio.CancelledError):
        await toolset.get_tools()

    assert toolset.availability == McpAvailability(status=McpStatus.UNKNOWN)


async def test_wrapped_cancellation_propagates_without_marking_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The pinned ADK boundary converts failures into ConnectionError via
    # ``raise ConnectionError(...) from e``; a shutdown cancellation therefore
    # reaches this layer wrapped as an ordinary Exception whose cause is a
    # CancelledError. It must propagate, not degrade to "unavailable".
    async def wrapped_cancel(*_args: object, **_kwargs: object) -> list[BaseTool]:
        try:
            raise asyncio.CancelledError
        except asyncio.CancelledError as cancelled:
            raise ConnectionError("shutdown") from cancelled

    monkeypatch.setattr(McpToolset, "get_tools", wrapped_cancel)
    toolset = build_mcp_toolset(optional_sse_descriptor())

    with pytest.raises(ConnectionError, match="shutdown"):
        await toolset.get_tools()

    assert toolset.availability == McpAvailability(status=McpStatus.UNKNOWN)


async def test_grouped_cancellation_cause_propagates_without_marking_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A cancelling anyio task group raises a BaseExceptionGroup (itself a
    # BaseException). If the ADK boundary chains it as the cause of an ordinary
    # Exception, the CancelledError leaf must still be detected and propagated.
    async def grouped_cancel(*_args: object, **_kwargs: object) -> list[BaseTool]:
        group = BaseExceptionGroup("shutdown", [asyncio.CancelledError()])
        raise ConnectionError("wrapped shutdown") from group

    monkeypatch.setattr(McpToolset, "get_tools", grouped_cancel)
    toolset = build_mcp_toolset(optional_sse_descriptor())

    with pytest.raises(ConnectionError, match="wrapped shutdown"):
        await toolset.get_tools()

    assert toolset.availability == McpAvailability(status=McpStatus.UNKNOWN)


def test_build_uses_environment_snapshot_not_live_process_mapping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The builder must resolve against a one-shot snapshot rather than retain a
    # live reference to os.environ.
    monkeypatch.setattr(
        mcp_module.os,
        "environ",
        {"AREMA_SNAPSHOT_TOKEN": "snapshot-value"},
    )
    descriptor = McpServerDescriptor(
        id="snapshot-env",
        transport=StdioTransport(
            command="server",
            env={"TOKEN": "${AREMA_SNAPSHOT_TOKEN}"},
        ),
    )

    toolset = build_mcp_toolset(descriptor)

    assert isinstance(toolset.connection_params, StdioConnectionParams)
    assert toolset.connection_params.server_params.env == {"TOKEN": "snapshot-value"}


def test_invalid_timeout_remains_owned_by_catalog_validation() -> None:
    server = McpServerDescriptor(
        id="bad-timeout",
        transport=SseTransport(
            url="https://example.test/sse",
            read_timeout=0.0,
        ),
    )
    root = AgentDescriptor(
        id="root",
        name="Root",
        description="Root agent",
        prompt_id="root",
        factory=_unused_agent_factory,
        mcp_server_ids=(server.id,),
    )

    with pytest.raises(InvalidTransportError, match=r"bad-timeout.*read_timeout"):
        CapabilityCatalog(
            root_agent_id=root.id,
            runtime_profiles={"safe_default": RuntimeProfile.safe_default()},
            agents={root.id: root},
            tools={},
            mcp_servers={server.id: server},
        )


def test_builder_returns_resilient_toolset_with_required_flag() -> None:
    optional = build_mcp_toolset(optional_sse_descriptor())
    required = build_mcp_toolset(required_sse_descriptor())

    assert isinstance(optional, ResilientMcpToolset)
    assert optional.required is False
    assert required.required is True


# -- _is_cancellation ----------------------------------------------------------


def test_is_cancellation_true_for_genuine_cancelled_error() -> None:
    from arema.registry.mcp import _is_cancellation

    assert _is_cancellation(asyncio.CancelledError()) is True


def test_is_cancellation_false_for_plain_exception() -> None:
    from arema.registry.mcp import _is_cancellation

    assert _is_cancellation(RuntimeError("boom")) is False


def test_is_cancellation_false_for_timeout() -> None:
    """asyncio.wait_for cancels the inner task on timeout, leaving a
    CancelledError in the chain. A timeout is NOT a cancellation."""
    from arema.registry.mcp import _is_cancellation

    inner = asyncio.CancelledError()
    timeout = TimeoutError()
    timeout.__context__ = inner
    assert _is_cancellation(timeout) is False


def test_is_cancellation_false_for_connection_error_wrapping_timeout() -> None:
    """The exact pattern from the r2mcp crash: ADK wraps the TimeoutError in a
    ConnectionError. The CancelledError from wait_for is in the chain but the
    TimeoutError is authoritative — this is a timeout, not a cancellation."""
    from arema.registry.mcp import _is_cancellation

    inner = asyncio.CancelledError()
    timeout = TimeoutError()
    timeout.__context__ = inner
    conn_error = ConnectionError("Failed to get tools from MCP server")
    conn_error.__cause__ = timeout
    assert _is_cancellation(conn_error) is False


def test_is_cancellation_true_for_connection_error_wrapping_genuine_cancel() -> None:
    """A genuine cancellation (not from a timeout) wrapping chain should still
    be detected as a cancellation."""
    from arema.registry.mcp import _is_cancellation

    cancel = asyncio.CancelledError()
    conn_error = ConnectionError("connection lost during shutdown")
    conn_error.__cause__ = cancel
    assert _is_cancellation(conn_error) is True


def test_is_cancellation_false_when_concrete_failure_sits_beside_cancellation() -> None:
    """The anyio pattern: a task group cancels its siblings the moment one task
    fails, so a real connection failure arrives beside a CancelledError with no
    TimeoutError to disambiguate. The concrete failure is authoritative."""
    from arema.registry.mcp import _is_cancellation

    concrete = ConnectionRefusedError("connection refused")  # a real failure (OSError)
    group = BaseExceptionGroup("task group", [concrete, asyncio.CancelledError()])
    conn_error = ConnectionError("Failed to get tools from MCP server")
    conn_error.__cause__ = group
    assert _is_cancellation(conn_error) is False


def test_is_cancellation_true_for_group_of_only_cancellations() -> None:
    """A group carrying only cancellations (a genuine shutdown, nothing else
    wrong) must still propagate."""
    from arema.registry.mcp import _is_cancellation

    group = BaseExceptionGroup("shutdown", [asyncio.CancelledError(), asyncio.CancelledError()])
    conn_error = ConnectionError("connection lost during shutdown")
    conn_error.__cause__ = group
    assert _is_cancellation(conn_error) is True
