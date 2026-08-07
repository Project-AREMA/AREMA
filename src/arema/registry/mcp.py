"""Construct resilient ADK MCP toolsets from validated registry descriptors."""

from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, TypeAlias, assert_never, cast

from google.adk.tools.base_tool import BaseTool
from google.adk.tools.mcp_tool.mcp_session_manager import (
    SseConnectionParams,
    StdioConnectionParams,
    StreamableHTTPConnectionParams,
)
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset
from mcp import StdioServerParameters

from arema.core.logging import get_logger
from arema.registry.descriptors import (
    HeaderProvider,
    McpServerDescriptor,
    SseTransport,
    StdioTransport,
    StreamableHttpTransport,
)
from arema.registry.errors import InvalidTransportError, MissingEnvironmentValueError

if TYPE_CHECKING:
    from collections.abc import Mapping

    from google.adk.agents.readonly_context import ReadonlyContext
    from google.adk.models.llm_request import LlmRequest
    from google.adk.tools.tool_context import ToolContext


logger = get_logger(__name__)

McpConnectionParams: TypeAlias = (
    StdioConnectionParams | SseConnectionParams | StreamableHTTPConnectionParams
)

_ENVIRONMENT_PLACEHOLDER = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", flags=re.ASCII)


class McpStatus(StrEnum):
    """Observed runtime availability of an MCP server."""

    UNKNOWN = "unknown"
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class McpAvailability:
    """One immutable availability observation for an MCP server."""

    status: McpStatus
    error_type: str | None = None


def _is_cancellation(error: BaseException) -> bool:
    """Report whether ``error`` is, wraps, or groups an ``asyncio.CancelledError``.

    The pinned ADK MCP boundary converts underlying failures into a
    ``ConnectionError`` (``raise ConnectionError(...) from e``), so a task
    cancelled during shutdown can reach this layer disguised as an ordinary
    ``Exception`` whose ``__cause__``/``__context__`` chain — or an
    ``ExceptionGroup`` sub-exception — still carries the ``CancelledError``.
    Treating those as availability failures would falsely mark a server
    unavailable, so they must be re-raised instead.

    **Timeout exclusion:** ``asyncio.wait_for`` cancels its inner task on
    timeout, leaving a ``CancelledError`` in the chain below the
    ``TimeoutError``. That ``CancelledError`` is an implementation detail of
    the timeout mechanism, not a genuine cancellation — so a ``TimeoutError``
    anywhere in the chain is authoritative: the error is a timeout (degrade
    gracefully), not a cancellation (propagate).

    **Concrete-failure exclusion:** an ``anyio`` task group cancels its siblings
    as soon as one task fails, so a plain connection failure also arrives with a
    ``CancelledError`` sitting beside the real error — and unlike the timeout
    case there is no ``TimeoutError`` to disambiguate it. A cancellation
    therefore only counts as genuine when *nothing else went wrong*: if the chain
    below the wrapper holds any concrete failure (``httpx.ConnectError``, an
    ``OSError``, anything that is not itself a cancellation or a group), the
    error is that failure and the cancellation is its fallout. The root
    exception is exempt, because the ADK boundary always wraps failures in a
    ``ConnectionError`` — counting the wrapper would make every chain look
    concrete.
    """
    seen: set[int] = set()
    # (exception, is_root) -- only non-root nodes can testify to a concrete failure.
    stack: list[tuple[BaseException | None, bool]] = [(error, True)]
    found_cancellation = False
    found_concrete_failure = False
    while stack:
        current, is_root = stack.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, TimeoutError):
            return False
        if isinstance(current, asyncio.CancelledError):
            found_cancellation = True
        elif not is_root and not isinstance(current, BaseExceptionGroup):
            found_concrete_failure = True
        if isinstance(current, BaseExceptionGroup):
            stack.extend((exception, False) for exception in current.exceptions)
        stack.append((current.__cause__, False))
        stack.append((current.__context__, False))
    return found_cancellation and not found_concrete_failure


class _SerializedTool(BaseTool):
    """Delegate to an inner MCP tool, serializing ``run_async`` under a shared lock.

    ADK dispatches every function call in one model turn concurrently
    (``asyncio.gather`` in ``flows/llm_flows/functions.py``). An MCP server that
    fronts a single stateful backend -- one subprocess, one session cursor --
    cannot serve concurrent in-flight requests over its one session: a call that
    sets server-side state (e.g. selecting the current target) can interleave
    with a later call that depends on it, so the batch fails or corrupts. One
    lock per toolset makes the calls run one at a time against that session,
    exactly as if the model had issued them sequentially (which succeeds). The
    wrapper keeps the inner tool's name, so ADK still resolves it for execution,
    and delegates request-shaping to the inner tool so the declaration the model
    sees is unchanged.
    """

    def __init__(self, inner: BaseTool, lock: asyncio.Lock) -> None:
        super().__init__(
            name=inner.name,
            description=inner.description,
            is_long_running=inner.is_long_running,
            custom_metadata=inner.custom_metadata,
        )
        self._inner = inner
        self._lock = lock

    async def process_llm_request(
        self,
        *,
        tool_context: ToolContext,
        llm_request: LlmRequest,
    ) -> None:
        await self._inner.process_llm_request(
            tool_context=tool_context,
            llm_request=llm_request,
        )

    async def run_async(self, *, args: dict[str, object], tool_context: ToolContext) -> object:
        async with self._lock:
            return await self._inner.run_async(args=args, tool_context=tool_context)


class ResilientMcpToolset(McpToolset):
    """An ADK MCP toolset with required/optional failure semantics."""

    def __init__(
        self,
        *,
        descriptor_id: str,
        required: bool,
        connection_params: McpConnectionParams,
        tool_filter: list[str] | None = None,
        tool_name_prefix: str | None = None,
        header_provider: HeaderProvider | None = None,
    ) -> None:
        super().__init__(
            connection_params=connection_params,
            tool_filter=tool_filter,
            tool_name_prefix=tool_name_prefix,
            header_provider=header_provider,
        )
        self._descriptor_id = descriptor_id
        self.required = required
        self._availability = McpAvailability(status=McpStatus.UNKNOWN)
        # One lock per toolset (i.e. per MCP session) serializes the concurrent
        # tool calls ADK issues for a parallel model turn; created lazily so the
        # toolset can be constructed outside a running event loop.
        self._call_lock: asyncio.Lock | None = None

    @property
    def connection_params(self) -> McpConnectionParams:
        """Return the typed ADK connection parameters used by this toolset."""
        return cast("McpConnectionParams", self._connection_params)

    @property
    def availability(self) -> McpAvailability:
        """Return the latest immutable availability snapshot."""
        return self._availability

    async def get_tools(
        self,
        readonly_context: ReadonlyContext | None = None,
    ) -> list[BaseTool]:
        """Resolve tools, degrading only optional ordinary failures to an empty set."""
        try:
            tools: list[BaseTool] = await super().get_tools(readonly_context)
        except Exception as error:
            if _is_cancellation(error):
                # Cancellation is not an availability signal; propagate it
                # untouched and leave the current status snapshot intact.
                raise
            error_type = type(error).__name__
            self._availability = McpAvailability(
                status=McpStatus.UNAVAILABLE,
                error_type=error_type,
            )
            if self.required:
                raise
            logger.warning(
                "Optional MCP server unavailable",
                descriptor_id=self._descriptor_id,
                error_type=error_type,
            )
            return []

        self._availability = McpAvailability(status=McpStatus.AVAILABLE)
        if self._call_lock is None:
            self._call_lock = asyncio.Lock()
        return [_SerializedTool(tool, self._call_lock) for tool in tools]


def _resolve_environment_placeholders(
    value: str,
    *,
    environment: Mapping[str, str],
    descriptor_id: str,
    field: str,
) -> str:
    def replace(match: re.Match[str]) -> str:
        variable_name = match.group(1)
        try:
            return environment[variable_name]
        except KeyError:
            raise MissingEnvironmentValueError(
                f"MCP server '{descriptor_id}' field '{field}' requires environment variable "
                f"'{variable_name}'"
            ) from None

    return _ENVIRONMENT_PLACEHOLDER.sub(replace, value)


def _resolve_stdio_environment(
    values: Mapping[str, str],
    *,
    environment: Mapping[str, str],
    descriptor_id: str,
) -> dict[str, str] | None:
    resolved: dict[str, str] = {}
    for name, value in values.items():
        field = f"transport environment value for '{name}'"
        resolved_value = _resolve_environment_placeholders(
            value,
            environment=environment,
            descriptor_id=descriptor_id,
            field=field,
        )
        if "\0" in resolved_value:
            raise InvalidTransportError(
                f"MCP server '{descriptor_id}' field '{field}' is unsafe after substitution"
            )
        resolved[name] = resolved_value
    return resolved or None


def _resolve_http_headers(
    values: Mapping[str, str],
    *,
    environment: Mapping[str, str],
    descriptor_id: str,
) -> dict[str, str] | None:
    resolved: dict[str, str] = {}
    for name, value in values.items():
        field = f"transport header '{name}'"
        resolved_value = _resolve_environment_placeholders(
            value,
            environment=environment,
            descriptor_id=descriptor_id,
            field=field,
        )
        if any(
            character != "\t" and not 0x20 <= ord(character) <= 0x7E for character in resolved_value
        ):
            raise InvalidTransportError(
                f"MCP server '{descriptor_id}' field '{field}' is unsafe after substitution"
            )
        resolved[name] = resolved_value
    return resolved or None


def _build_connection_params(
    descriptor: McpServerDescriptor,
    *,
    environment: Mapping[str, str],
) -> McpConnectionParams:
    transport = descriptor.transport
    if isinstance(transport, StdioTransport):
        server_params = StdioServerParameters(
            command=transport.command,
            args=list(transport.args),
            env=_resolve_stdio_environment(
                transport.env,
                environment=environment,
                descriptor_id=descriptor.id,
            ),
        )
        return StdioConnectionParams(
            server_params=server_params,
            timeout=transport.connect_timeout,
        )
    if isinstance(transport, SseTransport):
        return SseConnectionParams(
            url=transport.url,
            headers=_resolve_http_headers(
                transport.headers,
                environment=environment,
                descriptor_id=descriptor.id,
            ),
            timeout=transport.connect_timeout,
            sse_read_timeout=transport.read_timeout,
        )
    if isinstance(transport, StreamableHttpTransport):
        return StreamableHTTPConnectionParams(
            url=transport.url,
            headers=_resolve_http_headers(
                transport.headers,
                environment=environment,
                descriptor_id=descriptor.id,
            ),
            timeout=transport.connect_timeout,
            sse_read_timeout=transport.read_timeout,
            terminate_on_close=transport.terminate_on_close,
        )
    assert_never(transport)


def build_mcp_toolset(
    descriptor: McpServerDescriptor,
    *,
    environment: Mapping[str, str] | None = None,
) -> ResilientMcpToolset:
    """Build a resilient pinned-ADK toolset for one validated descriptor.

    Placeholder substitution reads a one-shot snapshot of the process
    environment taken here at build time, never a live reference to
    ``os.environ``, so later mutations cannot retroactively change resolved
    transport values. Resolved secret values are confined to the ADK
    connection parameters; they are never placed in logs or exception text by
    this layer. (ADK's own MCP boundary may log underlying transport errors,
    but those reference the URL/command, not the resolved header/env values.)
    """
    connection_params = _build_connection_params(
        descriptor,
        environment=dict(os.environ) if environment is None else environment,
    )
    return ResilientMcpToolset(
        descriptor_id=descriptor.id,
        required=descriptor.required,
        connection_params=connection_params,
        tool_filter=list(descriptor.tool_allowlist) or None,
        tool_name_prefix=descriptor.tool_name_prefix,
        header_provider=descriptor.header_provider,
    )
