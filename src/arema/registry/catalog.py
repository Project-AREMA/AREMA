"""Validated construction of immutable AREMA capability catalogs."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from math import isfinite
from types import MappingProxyType
from typing import TYPE_CHECKING, Protocol, TypeVar
from urllib.parse import urlsplit

from google.adk.tools.base_tool import BaseTool
from google.adk.tools.base_toolset import BaseToolset

from arema.registry.descriptors import (
    AgentDescriptor,
    AgentKind,
    ContextMode,
    JsonValue,
    McpServerDescriptor,
    OutputPolicy,
    RuntimeProfile,
    SseTransport,
    StdioTransport,
    StreamableHttpTransport,
    ToolDescriptor,
    ToolLifecycleCallbacks,
)
from arema.registry.errors import (
    CapabilityCycleError,
    CatalogFrozenError,
    CatalogValidationError,
    DuplicateCapabilityError,
    InvalidCapabilityDescriptorError,
    InvalidRootError,
    InvalidToolDescriptorError,
    InvalidTransportError,
    UnreachableAgentError,
    UnresolvedCapabilityError,
)

if TYPE_CHECKING:
    from collections.abc import Callable


class _HasId(Protocol):
    @property
    def id(self) -> str:
        """Return the descriptor's registry identifier."""
        ...


_Descriptor = TypeVar("_Descriptor", bound=_HasId)
_HEADER_NAME = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z", flags=re.ASCII)
_TOOL_NAME_PREFIX = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*\Z")


def _mapping_proxy(mapping: Mapping[str, _Descriptor]) -> Mapping[str, _Descriptor]:
    """Return an immutable copy of a registry mapping."""
    return MappingProxyType(dict(mapping))


@dataclass(frozen=True, slots=True)
class CapabilityCatalog:
    """A fully validated, immutable capability graph."""

    root_agent_id: str
    runtime_profiles: Mapping[str, RuntimeProfile]
    agents: Mapping[str, AgentDescriptor]
    tools: Mapping[str, ToolDescriptor]
    mcp_servers: Mapping[str, McpServerDescriptor]

    def __post_init__(self) -> None:
        """Copy and validate registries for every construction path."""
        object.__setattr__(self, "runtime_profiles", _mapping_proxy(self.runtime_profiles))
        object.__setattr__(self, "agents", _mapping_proxy(self.agents))
        object.__setattr__(self, "tools", _mapping_proxy(self.tools))
        object.__setattr__(self, "mcp_servers", _mapping_proxy(self.mcp_servers))
        _validate_catalog(
            root_agent_id=self.root_agent_id,
            runtime_profiles=self.runtime_profiles,
            agents=self.agents,
            tools=self.tools,
            mcp_servers=self.mcp_servers,
        )


class CatalogBuilder:
    """Collect capability descriptors and freeze them into one validated graph."""

    def __init__(self) -> None:
        self._runtime_profiles: dict[str, RuntimeProfile] = {}
        self._agents: dict[str, AgentDescriptor] = {}
        self._tools: dict[str, ToolDescriptor] = {}
        self._mcp_servers: dict[str, McpServerDescriptor] = {}
        self._frozen = False

    def _ensure_mutable(self) -> None:
        if self._frozen:
            raise CatalogFrozenError("Capability catalog builder is already frozen")

    def _add(
        self,
        registry: dict[str, _Descriptor],
        descriptor: _Descriptor,
        *,
        kind: str,
    ) -> None:
        self._ensure_mutable()
        capability_id = descriptor.id
        if capability_id in registry:
            raise DuplicateCapabilityError(f"Duplicate {kind} capability id '{capability_id}'")
        registry[capability_id] = descriptor

    def add_runtime_profile(self, profile: RuntimeProfile) -> None:
        """Register a runtime profile."""
        self._add(self._runtime_profiles, profile, kind="runtime profile")

    def add_agent(self, agent: AgentDescriptor) -> None:
        """Register an agent descriptor."""
        self._add(self._agents, agent, kind="agent")

    def add_tool(self, tool: ToolDescriptor) -> None:
        """Register a tool descriptor."""
        self._add(self._tools, tool, kind="tool")

    def add_mcp_server(self, server: McpServerDescriptor) -> None:
        """Register an MCP server descriptor."""
        self._add(self._mcp_servers, server, kind="MCP server")

    def freeze(self, root_agent_id: str) -> CapabilityCatalog:
        """Validate the capability graph and make this builder immutable."""
        self._ensure_mutable()
        catalog = CapabilityCatalog(
            root_agent_id=root_agent_id,
            runtime_profiles=_mapping_proxy(self._runtime_profiles),
            agents=_mapping_proxy(self._agents),
            tools=_mapping_proxy(self._tools),
            mcp_servers=_mapping_proxy(self._mcp_servers),
        )
        self._frozen = True
        return catalog


def _validate_catalog(
    *,
    root_agent_id: str,
    runtime_profiles: Mapping[str, RuntimeProfile],
    agents: Mapping[str, AgentDescriptor],
    tools: Mapping[str, ToolDescriptor],
    mcp_servers: Mapping[str, McpServerDescriptor],
) -> None:
    """Validate descriptor registries and their complete agent graph."""
    _validate_registry_keys(runtime_profiles, kind="runtime profile")
    _validate_registry_keys(agents, kind="agent")
    _validate_registry_keys(tools, kind="tool")
    _validate_registry_keys(mcp_servers, kind="MCP server")
    if root_agent_id not in agents:
        raise InvalidRootError(f"Root agent '{root_agent_id}' is not registered")

    for profile in runtime_profiles.values():
        _validate_runtime_profile(profile)
    for agent in agents.values():
        _validate_agent(agent)
    for tool in tools.values():
        _validate_tool(tool)
    for server in mcp_servers.values():
        _validate_mcp_server(server)

    _validate_references(
        agents=agents,
        runtime_profiles=runtime_profiles,
        tools=tools,
        mcp_servers=mcp_servers,
    )
    _validate_acyclic_agents(agents)
    _validate_reachable_agents(agents, root_agent_id=root_agent_id)


def _validate_registry_keys(
    registry: Mapping[str, _Descriptor],
    *,
    kind: str,
) -> None:
    for key, descriptor in registry.items():
        if key != descriptor.id:
            raise InvalidCapabilityDescriptorError(
                f"Registry key '{key}' does not match {kind} descriptor id '{descriptor.id}'"
            )


def _validate_references(
    *,
    agents: Mapping[str, AgentDescriptor],
    runtime_profiles: Mapping[str, RuntimeProfile],
    tools: Mapping[str, ToolDescriptor],
    mcp_servers: Mapping[str, McpServerDescriptor],
) -> None:
    registries: tuple[
        tuple[str, Mapping[str, object], Callable[[AgentDescriptor], tuple[str, ...]]], ...
    ] = (
        ("runtime profile", runtime_profiles, lambda agent: (agent.runtime_profile_id,)),
        ("tool", tools, lambda agent: agent.tool_ids),
        ("MCP server", mcp_servers, lambda agent: agent.mcp_server_ids),
        ("sub-agent", agents, lambda agent: agent.sub_agent_ids),
    )
    for agent in agents.values():
        for kind, registry, references in registries:
            for capability_id in references(agent):
                if capability_id not in registry:
                    raise UnresolvedCapabilityError(
                        f"Agent '{agent.id}' references missing {kind} '{capability_id}'"
                    )


def _validate_acyclic_agents(agents: Mapping[str, AgentDescriptor]) -> None:
    unvisited = 0
    visiting = 1
    visited = 2
    states = dict.fromkeys(agents, unvisited)
    path: list[str] = []
    path_positions: dict[str, int] = {}

    for start_agent_id in agents:
        if states[start_agent_id] != unvisited:
            continue

        states[start_agent_id] = visiting
        path_positions[start_agent_id] = len(path)
        path.append(start_agent_id)
        stack: list[tuple[str, int]] = [(start_agent_id, 0)]

        while stack:
            agent_id, child_index = stack[-1]
            sub_agent_ids = agents[agent_id].sub_agent_ids
            if child_index >= len(sub_agent_ids):
                stack.pop()
                states[agent_id] = visited
                path_positions.pop(agent_id)
                path.pop()
                continue

            sub_agent_id = sub_agent_ids[child_index]
            stack[-1] = (agent_id, child_index + 1)
            state = states[sub_agent_id]
            if state == unvisited:
                states[sub_agent_id] = visiting
                path_positions[sub_agent_id] = len(path)
                path.append(sub_agent_id)
                stack.append((sub_agent_id, 0))
            elif state == visiting:
                cycle_start = path_positions[sub_agent_id]
                cycle = (*path[cycle_start:], sub_agent_id)
                raise CapabilityCycleError(f"Agent dependency cycle detected: {' -> '.join(cycle)}")


def _validate_reachable_agents(
    agents: Mapping[str, AgentDescriptor],
    *,
    root_agent_id: str,
) -> None:
    reachable: set[str] = set()
    pending = [root_agent_id]
    while pending:
        agent_id = pending.pop()
        if agent_id in reachable:
            continue
        reachable.add(agent_id)
        pending.extend(agents[agent_id].sub_agent_ids)

    unreachable = [agent_id for agent_id in agents if agent_id not in reachable]
    if unreachable:
        raise UnreachableAgentError(
            f"Agents unreachable from root '{root_agent_id}': {', '.join(unreachable)}"
        )


def _require_non_empty(
    value: object,
    *,
    field: str,
    capability_id: str,
    error_type: type[CatalogValidationError] = InvalidCapabilityDescriptorError,
) -> None:
    if not isinstance(value, str) or not value.strip():
        raise error_type(f"Capability '{capability_id}' requires a non-empty {field}")


def _require_positive_number(
    value: object,
    *,
    field: str,
    capability_id: str,
    error_type: type[CatalogValidationError],
) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise error_type(f"Capability '{capability_id}' requires a finite positive {field}")
    if not isfinite(value) or value <= 0:
        raise error_type(f"Capability '{capability_id}' requires a finite positive {field}")


def _require_positive_integer(
    value: object,
    *,
    field: str,
    capability_id: str,
    error_type: type[CatalogValidationError],
) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise error_type(f"Capability '{capability_id}' requires a positive integer {field}")


def _validate_string_tuple(
    values: tuple[str, ...],
    *,
    field: str,
    capability_id: str,
    error_type: type[CatalogValidationError] = InvalidCapabilityDescriptorError,
    unique: bool = False,
) -> None:
    seen: set[str] = set()
    for value in values:
        _require_non_empty(
            value,
            field=f"{field} entry",
            capability_id=capability_id,
            error_type=error_type,
        )
        if unique and value in seen:
            raise error_type(f"Capability '{capability_id}' has duplicate {field} entry '{value}'")
        seen.add(value)


def _require_exact_bool(
    value: object,
    *,
    field: str,
    capability_id: str,
    error_type: type[CatalogValidationError],
) -> None:
    if type(value) is not bool:
        raise error_type(f"Capability '{capability_id}' field {field} must be a bool")


def _validate_callbacks(
    callbacks: tuple[object, ...],
    *,
    field: str,
    capability_id: str,
    error_type: type[CatalogValidationError],
) -> None:
    if any(not callable(callback) for callback in callbacks):
        raise error_type(f"Capability '{capability_id}' has a non-callable {field} callback")


def _validate_metadata(
    metadata: Mapping[str, JsonValue],
    *,
    capability_id: str,
    error_type: type[CatalogValidationError],
) -> None:
    for key, value in metadata.items():
        _require_non_empty(
            key,
            field="metadata key",
            capability_id=capability_id,
            error_type=error_type,
        )
        _validate_json_value(value, capability_id=capability_id, field=key, error_type=error_type)


def _validate_json_value(
    value: JsonValue,
    *,
    capability_id: str,
    field: str,
    error_type: type[CatalogValidationError],
) -> None:
    """Validate that ``value`` is a JSON value: a scalar, or a nested mapping
    (str keys) or sequence of the same. Rejects anything else."""
    if value is None or isinstance(value, (str, int)):  # bool is an int subclass
        return
    if isinstance(value, float):
        if not isfinite(value):
            raise error_type(
                f"Capability '{capability_id}' metadata field '{field}' must be finite"
            )
        return
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str) or not key:
                raise error_type(
                    f"Capability '{capability_id}' metadata field '{field}' "
                    "has a non-string or empty key"
                )
            _validate_json_value(
                nested, capability_id=capability_id, field=f"{field}.{key}", error_type=error_type
            )
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            _validate_json_value(
                item, capability_id=capability_id, field=f"{field}[{index}]", error_type=error_type
            )
        return
    raise error_type(f"Capability '{capability_id}' metadata field '{field}' is not a JSON value")


def _validate_runtime_profile(profile: RuntimeProfile) -> None:
    _require_non_empty(profile.id, field="id", capability_id=profile.id)
    if not isinstance(profile.context_mode, ContextMode):
        raise InvalidCapabilityDescriptorError(
            f"Capability '{profile.id}' field context_mode must be a ContextMode"
        )
    boolean_fields = (
        "capture_request",
        "throttle_model",
        "retry_model",
        "enforce_turn_limit",
        "enforce_context_budget",
        "record_metrics",
        "guard_tools",
        "record_memory",
        "compact_tool_output",
        "recover_tool_errors",
    )
    for field in boolean_fields:
        _require_exact_bool(
            getattr(profile, field),
            field=field,
            capability_id=profile.id,
            error_type=InvalidCapabilityDescriptorError,
        )
    callback_fields = (
        ("extra_before_model", profile.extra_before_model),
        ("extra_before_tool", profile.extra_before_tool),
        ("extra_after_tool", profile.extra_after_tool),
    )
    for field, callbacks in callback_fields:
        _validate_callbacks(
            callbacks,
            field=field,
            capability_id=profile.id,
            error_type=InvalidCapabilityDescriptorError,
        )


def _validate_agent(agent: AgentDescriptor) -> None:
    for field in ("id", "name", "description", "runtime_profile_id", "version"):
        _require_non_empty(
            getattr(agent, field),
            field=field,
            capability_id=agent.id,
        )
    if not isinstance(agent.kind, AgentKind):
        raise InvalidCapabilityDescriptorError(
            f"Agent capability '{agent.id}' field kind must be an AgentKind"
        )
    kind = _effective_agent_kind(agent)
    if kind is AgentKind.LLM:
        if agent.prompt_id is None:
            raise InvalidCapabilityDescriptorError(
                f"Agent kind LLM for '{agent.id}' requires a non-empty prompt_id"
            )
        _require_non_empty(agent.prompt_id, field="prompt_id", capability_id=agent.id)
    elif kind is AgentKind.COMPOSITE:
        if agent.prompt_id is not None:
            raise InvalidCapabilityDescriptorError(
                f"Agent kind COMPOSITE for '{agent.id}' requires prompt_id=None"
            )
        _validate_composite_agent(agent)
    elif kind is AgentKind.DETERMINISTIC:
        _validate_deterministic_agent(agent)
    else:  # Defensive: AgentKind membership above protects this branch.
        raise InvalidCapabilityDescriptorError(
            f"Agent capability '{agent.id}' has unsupported agent kind '{kind}'"
        )
    if not callable(agent.factory):
        raise InvalidCapabilityDescriptorError(
            f"Agent capability '{agent.id}' requires a callable factory"
        )
    if agent.output_key is not None:
        _require_non_empty(agent.output_key, field="output_key", capability_id=agent.id)
    _validate_string_tuple(
        agent.tool_ids,
        field="tool_ids",
        capability_id=agent.id,
        unique=True,
    )
    _validate_string_tuple(
        agent.mcp_server_ids,
        field="mcp_server_ids",
        capability_id=agent.id,
        unique=True,
    )
    _validate_string_tuple(
        agent.sub_agent_ids,
        field="sub_agent_ids",
        capability_id=agent.id,
        unique=True,
    )
    _validate_metadata(
        agent.metadata,
        capability_id=agent.id,
        error_type=InvalidCapabilityDescriptorError,
    )


def _effective_agent_kind(agent: AgentDescriptor) -> AgentKind:
    """Resolve AUTO with the prompt-based behavior used by existing descriptors."""
    if agent.kind is AgentKind.AUTO:
        return AgentKind.LLM if agent.prompt_id is not None else AgentKind.COMPOSITE
    return agent.kind


def _validate_composite_agent(agent: AgentDescriptor) -> None:
    """A prompt-less (composite) agent must be a pure orchestration shell.

    Composite agents have no model, instruction, tools, MCP, or own output --
    only ordered sub-agents. Enforcing this at freeze time guarantees a frozen
    catalog is safe to build, and catches a misconfigured shell (or an
    accidentally-blank LlmAgent descriptor) before construction.
    """
    if agent.tool_ids:
        raise InvalidCapabilityDescriptorError(
            f"Composite agent '{agent.id}' (prompt_id=None) must not declare tools; "
            f"found tool_ids={list(agent.tool_ids)}"
        )
    if agent.mcp_server_ids:
        raise InvalidCapabilityDescriptorError(
            f"Composite agent '{agent.id}' (prompt_id=None) must not attach MCP servers; "
            f"found mcp_server_ids={list(agent.mcp_server_ids)}"
        )
    if agent.output_key is not None:
        raise InvalidCapabilityDescriptorError(
            f"Composite agent '{agent.id}' (prompt_id=None) must not set output_key"
        )
    if not agent.sub_agent_ids:
        raise InvalidCapabilityDescriptorError(
            f"Composite agent '{agent.id}' (prompt_id=None) requires at least one sub_agent"
        )


def _validate_deterministic_agent(agent: AgentDescriptor) -> None:
    """Require a promptless leaf with no model, tool, or orchestration inputs."""
    if agent.prompt_id is not None:
        raise InvalidCapabilityDescriptorError(
            f"Deterministic agent '{agent.id}' requires prompt_id=None"
        )
    if agent.prompt_loader is not None:
        raise InvalidCapabilityDescriptorError(
            f"Deterministic agent '{agent.id}' must not set prompt_loader"
        )
    if agent.tool_ids:
        raise InvalidCapabilityDescriptorError(
            f"Deterministic agent '{agent.id}' must not declare tools"
        )
    if agent.mcp_server_ids:
        raise InvalidCapabilityDescriptorError(
            f"Deterministic agent '{agent.id}' must not attach MCP servers"
        )
    if agent.output_key is not None:
        raise InvalidCapabilityDescriptorError(
            f"Deterministic agent '{agent.id}' must not set output_key"
        )
    if agent.sub_agent_ids:
        raise InvalidCapabilityDescriptorError(
            f"Deterministic agent '{agent.id}' must not declare sub_agents"
        )


def _validate_output_policy(policy: OutputPolicy, *, capability_id: str) -> None:
    _require_positive_integer(
        policy.max_chars,
        field="output_policy.max_chars",
        capability_id=capability_id,
        error_type=InvalidToolDescriptorError,
    )
    _require_positive_integer(
        policy.max_list_items,
        field="output_policy.max_list_items",
        capability_id=capability_id,
        error_type=InvalidToolDescriptorError,
    )
    _validate_string_tuple(
        policy.drop_fields,
        field="output_policy.drop_fields",
        capability_id=capability_id,
        error_type=InvalidToolDescriptorError,
        unique=True,
    )
    _validate_string_tuple(
        policy.preserve_fields,
        field="output_policy.preserve_fields",
        capability_id=capability_id,
        error_type=InvalidToolDescriptorError,
        unique=True,
    )


def _validate_tool_callbacks(callbacks: ToolLifecycleCallbacks, *, capability_id: str) -> None:
    callback_fields = (
        ("before", callbacks.before),
        ("after", callbacks.after),
        ("on_error", callbacks.on_error),
        ("memory", callbacks.memory),
    )
    for field, registered_callbacks in callback_fields:
        _validate_callbacks(
            registered_callbacks,
            field=field,
            capability_id=capability_id,
            error_type=InvalidToolDescriptorError,
        )


def _validate_tool(tool: ToolDescriptor) -> None:
    for field in ("id", "description", "version"):
        _require_non_empty(
            getattr(tool, field),
            field=field,
            capability_id=tool.id,
            error_type=InvalidToolDescriptorError,
        )
    if (tool.tool is None) == (tool.factory is None):
        raise InvalidToolDescriptorError(
            f"Tool capability '{tool.id}' requires exactly one of tool or factory"
        )
    if tool.tool is not None and not (
        callable(tool.tool) or isinstance(tool.tool, (BaseTool, BaseToolset))
    ):
        raise InvalidToolDescriptorError(
            f"Tool capability '{tool.id}' has an unsupported concrete tool"
        )
    if tool.factory is not None and not callable(tool.factory):
        raise InvalidToolDescriptorError(f"Tool capability '{tool.id}' requires a callable factory")
    _validate_output_policy(tool.output_policy, capability_id=tool.id)
    _validate_string_tuple(
        tool.memory_codec_ids,
        field="memory_codec_ids",
        capability_id=tool.id,
        error_type=InvalidToolDescriptorError,
        unique=True,
    )
    _validate_tool_callbacks(tool.callbacks, capability_id=tool.id)
    _validate_metadata(
        tool.metadata,
        capability_id=tool.id,
        error_type=InvalidToolDescriptorError,
    )


def _validate_stdio_environment(
    environment: Mapping[str, str],
    *,
    capability_id: str,
) -> None:
    for key, value in environment.items():
        if not isinstance(key, str) or not key or "=" in key or "\0" in key:
            raise InvalidTransportError(
                f"MCP server '{capability_id}' transport environment key '{key}' is invalid"
            )
        if not isinstance(value, str):
            raise InvalidTransportError(
                f"MCP server '{capability_id}' transport environment value for '{key}' "
                "must be a string"
            )
        if "\0" in value:
            raise InvalidTransportError(
                f"MCP server '{capability_id}' transport environment value for '{key}' contains NUL"
            )


def _validate_http_headers(
    headers: Mapping[str, str],
    *,
    capability_id: str,
) -> None:
    for name, value in headers.items():
        if not isinstance(name, str) or _HEADER_NAME.fullmatch(name) is None:
            raise InvalidTransportError(
                f"MCP server '{capability_id}' transport header name '{name}' is invalid"
            )
        if not isinstance(value, str):
            raise InvalidTransportError(
                f"MCP server '{capability_id}' transport header '{name}' value must be a string"
            )
        if any(character != "\t" and not 0x20 <= ord(character) <= 0x7E for character in value):
            raise InvalidTransportError(
                f"MCP server '{capability_id}' transport header '{name}' value must contain "
                "only HTAB or printable ASCII"
            )


def _validate_http_url(url: str, *, capability_id: str) -> None:
    _require_non_empty(
        url,
        field="transport URL",
        capability_id=capability_id,
        error_type=InvalidTransportError,
    )
    if any(
        character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F for character in url
    ):
        raise InvalidTransportError(
            f"MCP server '{capability_id}' transport URL contains whitespace or ASCII controls"
        )
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as error:
        raise InvalidTransportError(
            f"MCP server '{capability_id}' transport URL is invalid: {error}"
        ) from None
    if parsed.scheme.lower() not in {"http", "https"}:
        raise InvalidTransportError(
            f"MCP server '{capability_id}' transport URL must use http or https"
        )
    if not parsed.netloc or hostname is None:
        raise InvalidTransportError(
            f"MCP server '{capability_id}' transport URL requires an authority and host"
        )
    if parsed.username is not None or parsed.password is not None:
        raise InvalidTransportError(
            f"MCP server '{capability_id}' transport URL must not contain credentials"
        )


def _validate_transport(
    transport: StdioTransport | SseTransport | StreamableHttpTransport,
    *,
    capability_id: str,
) -> None:
    if isinstance(transport, StdioTransport):
        _require_non_empty(
            transport.command,
            field="transport command",
            capability_id=capability_id,
            error_type=InvalidTransportError,
        )
        if "\0" in transport.command:
            raise InvalidTransportError(
                f"MCP server '{capability_id}' transport command contains NUL"
            )
        _validate_string_tuple(
            transport.args,
            field="transport args",
            capability_id=capability_id,
            error_type=InvalidTransportError,
        )
        if any("\0" in argument for argument in transport.args):
            raise InvalidTransportError(f"MCP server '{capability_id}' transport args contain NUL")
        _validate_stdio_environment(
            transport.env,
            capability_id=capability_id,
        )
    else:
        _validate_http_url(transport.url, capability_id=capability_id)
        _validate_http_headers(
            transport.headers,
            capability_id=capability_id,
        )
        _require_positive_number(
            transport.read_timeout,
            field="transport read_timeout",
            capability_id=capability_id,
            error_type=InvalidTransportError,
        )
        if isinstance(transport, StreamableHttpTransport):
            _require_exact_bool(
                transport.terminate_on_close,
                field="transport terminate_on_close",
                capability_id=capability_id,
                error_type=InvalidTransportError,
            )
    _require_positive_number(
        transport.connect_timeout,
        field="transport connect_timeout",
        capability_id=capability_id,
        error_type=InvalidTransportError,
    )


def _validate_mcp_server(server: McpServerDescriptor) -> None:
    _require_non_empty(server.id, field="id", capability_id=server.id)
    _require_exact_bool(
        server.required,
        field="required",
        capability_id=server.id,
        error_type=InvalidTransportError,
    )
    if not isinstance(server.transport, (StdioTransport, SseTransport, StreamableHttpTransport)):
        raise InvalidTransportError(f"MCP server '{server.id}' has an unsupported transport")
    _validate_transport(server.transport, capability_id=server.id)
    _validate_string_tuple(
        server.tool_allowlist,
        field="tool_allowlist",
        capability_id=server.id,
        error_type=InvalidTransportError,
        unique=True,
    )
    if server.tool_name_prefix is not None:
        _require_non_empty(
            server.tool_name_prefix,
            field="tool_name_prefix",
            capability_id=server.id,
            error_type=InvalidTransportError,
        )
        if _TOOL_NAME_PREFIX.fullmatch(server.tool_name_prefix) is None:
            raise InvalidTransportError(
                f"MCP server '{server.id}' tool_name_prefix '{server.tool_name_prefix}' is invalid"
            )
