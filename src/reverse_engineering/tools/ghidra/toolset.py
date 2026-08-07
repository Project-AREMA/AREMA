"""Build AREMA function tools from the ghidra-rpc command table.

Each tool is a thin wrapper that shells out via :func:`kubectl_exec` to run a
``ghidra-rpc`` CLI command in the claimed sandbox pod. The binary name is
injected from the case state (stashed by :mod:`prepare_ghidra`) — the agent
never passes it.

Wiring: each :class:`~arema.registry.descriptors.ToolDescriptor` uses
``factory=`` (deferred), mirroring ``prepare_sandbox``. The agent factory calls
the factory with the live :class:`ToolBuildContext` at build time
(:func:`arema.runtime.agent_factory._resolve_tool`), so the namespace always
reflects the real build-time settings rather than whatever was in scope at
composition time.
"""

from __future__ import annotations

import inspect
import json
import re
from typing import TYPE_CHECKING

from google.adk.tools.tool_context import ToolContext  # runtime: passed as annotation value

from arema.core.logging import get_logger
from arema.registry.descriptors import ToolDescriptor
from arema.runtime.sessions import SandboxIdentityError, resolve_sandbox_case_id
from reverse_engineering.runtime.portforward import kubectl_exec
from reverse_engineering.tools.ghidra.commands import GHIDRA_COMMANDS, CliCommandSpec
from reverse_engineering.tools.ghidra.coverage import record_ghidra_result

if TYPE_CHECKING:
    from arema.registry.descriptors import ToolLike
    from arema.runtime.agent_factory import ToolBuildContext

logger = get_logger(__name__)

_PLACEHOLDER_RE = re.compile(r"\{(\w+)\}")
# Populated by prepare_ghidra and read by every tool. Keyed by case id; the value
# holds the pod name, the loaded binary's short_name, the Ghidra project path, and
# the sandbox namespace (needed at release time).
_GHIDRA_CASE_STATE: dict[str, dict[str, str]] = {}


def _placeholders(template: str) -> list[str]:
    """Return the named parameters declared by an ``arg_template``."""
    return _PLACEHOLDER_RE.findall(template)


def _tokenize_arg_template(template: str, values: dict[str, str]) -> list[str]:
    """Tokenize *template* into explicit argv entries.

    Literal text (developer-controlled flags like ``--limit 100``) is
    whitespace-split; each ``{placeholder}`` value is inserted as a single argv
    token so agent-controlled values (function names, regex patterns) are never
    shell-interpreted.
    """
    tokens: list[str] = []
    for i, part in enumerate(_PLACEHOLDER_RE.split(template)):
        if not part:
            continue
        if i % 2 == 0:
            tokens.extend(part.split())
        else:
            value = values.get(part, "")
            if value:
                tokens.append(value)
    return tokens


def _degraded_reason(stdout: str, result_field: str | None) -> str | None:
    """Return a reason if ghidra-rpc's output signals no usable result, else None.

    ghidra-rpc exits 0 with ``ok:true`` even when the decompiler cannot run -- it
    emits an empty ``result.c_code`` / ``result.ops`` (observed when the native
    decompiler binary is missing for the pod's architecture). Surfacing this as
    ``success`` silently hides the failure from the agent, so a non-JSON reply is
    left alone (unintrospectable -- backward compatible) while a JSON reply with
    ``ok:false`` or an empty ``result_field`` is reported as degraded.
    """
    try:
        data = json.loads(stdout)
    except (TypeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    if data.get("ok") is False:
        message = data.get("error") or data.get("message") or "ghidra-rpc returned ok=false"
        return f"ghidra-rpc returned ok=false: {message}"
    if result_field:
        result = data.get("result")
        value = result.get(result_field) if isinstance(result, dict) else None
        if value is None or value == "" or value == [] or value == {}:
            return (
                f"ghidra-rpc returned empty {result_field!r} "
                "(the decompiler produced no output -- check the native decompiler binary)"
            )
    return None


def build_ghidra_tool(context: ToolBuildContext, spec: CliCommandSpec) -> ToolLike:
    """Build one typed ghidra function tool closing over the build-time namespace."""
    namespace = context.settings.sandbox_namespace
    param_names = _placeholders(spec.arg_template)

    def _tool(tool_context: ToolContext, **kwargs: str) -> dict[str, str | bool]:
        try:
            case_id = resolve_sandbox_case_id(tool_context)
        except SandboxIdentityError:
            return {
                "success": False,
                "error_code": "sandbox_identity_unavailable",
                "error": "The sandbox identity is unavailable.",
                "tool": spec.name,
            }
        case_state = _GHIDRA_CASE_STATE.get(case_id)
        if case_state is None:
            return {"success": False, "error": "ghidra not prepared for this case"}
        arg_tokens = _tokenize_arg_template(spec.arg_template, kwargs)
        flag_tokens = spec.extra_flags.split() if spec.extra_flags else []
        argv = [
            "ghidra-rpc",
            spec.subcommand,
            case_state["binary"],
            *arg_tokens,
            *flag_tokens,
            "--project",
            case_state["project"],
        ]
        try:
            stdout = kubectl_exec(argv, namespace, case_state["pod"], timeout=spec.timeout_seconds)
        except Exception as exc:
            logger.warning(
                "ghidra tool failed - returning degraded",
                tool=spec.name,
                error_type=type(exc).__name__,
            )
            return {"success": False, "error": str(exc), "tool": spec.name}
        reason = _degraded_reason(stdout, spec.result_field)
        if reason is not None:
            logger.warning(
                "ghidra tool degraded - decompiler produced no usable output",
                tool=spec.name,
                reason=reason,
            )
            return {
                "success": False,
                "degraded": True,
                "error": reason,
                "output": stdout,
                "tool": spec.name,
            }
        response: dict[str, str | bool] = {"success": True, "output": stdout}
        record_ghidra_result(
            tool_context.state,
            artifact_id=case_state.get("artifact_id", ""),
            tool_name=spec.name,
            response=response,
        )
        return response

    # Give the callable a typed surface ADK can introspect: one parameter per
    # ``{placeholder}`` plus the injected ``tool_context``. The inner ``def``
    # keeps ``**kwargs`` to collect them at call time.
    params = [
        inspect.Parameter(
            "tool_context",
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            annotation=ToolContext,
        )
    ]
    params.extend(
        inspect.Parameter(name, inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=str)
        for name in param_names
    )
    setattr(_tool, "__signature__", inspect.Signature(parameters=params))  # noqa: B010 - mypy has no __signature__ on plain funcs
    _tool.__name__ = spec.name
    _tool.__doc__ = spec.description
    return _tool


def build_ghidra_toolset() -> tuple[ToolDescriptor, ...]:
    """Return one deferred-factory :class:`ToolDescriptor` per ghidra command.

    No context is bound here: each descriptor carries its own ``factory``, which
    the agent factory invokes with the live :class:`ToolBuildContext` at build
    time (matching ``prepare_sandbox``).
    """
    return tuple(
        ToolDescriptor(
            id=spec.name,
            description=spec.description,
            factory=lambda ctx, s=spec: build_ghidra_tool(ctx, s),
            output_policy=spec.output_policy,
        )
        for spec in GHIDRA_COMMANDS
    )
