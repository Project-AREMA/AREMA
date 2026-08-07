"""Build AREMA function tools from the jadx command table.

Each tool shells out via :func:`kubectl_exec` to read the tree ``prepare_jadx``
already decompiled in the claimed pod. The output directory comes from the case
state (stashed by :mod:`prepare_jadx`), so the agent never passes a path.

Mirrors the ghidra toolset's wiring: deferred ``factory=`` descriptors resolved
with the live :class:`ToolBuildContext`, the same case-id resolution
(:func:`arema.runtime.sessions.resolve_sandbox_case_id`), and the same
``inspect.Signature`` synthesis that gives ADK a typed surface. It builds argv
per spec (``cat``/``find``/``grep`` over the decompiled tree) rather than from a
template -- see :mod:`reverse_engineering.tools.jadx.commands` -- and validates a
model-supplied class name (via :func:`_source_path_for`) before any argv is
built.
"""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING

from google.adk.tools.tool_context import ToolContext  # runtime: passed as annotation value

from arema.core.logging import get_logger
from arema.registry.descriptors import ToolDescriptor
from arema.runtime.sessions import SandboxIdentityError, resolve_sandbox_case_id
from reverse_engineering.runtime.portforward import kubectl_exec
from reverse_engineering.tools.jadx.commands import (
    JADX_COMMANDS,
    InvalidClassNameError,
    JadxCommandSpec,
    _source_path_for,
)

if TYPE_CHECKING:
    from arema.registry.descriptors import ToolLike
    from arema.runtime.agent_factory import ToolBuildContext

logger = get_logger(__name__)

# Populated by prepare_jadx, read by every tool. Keyed by case id; holds the pod
# name, the decompilation output dir, the sandbox namespace and the sample format.
_JADX_CASE_STATE: dict[str, dict[str, str]] = {}

# Containers jadx decompiles to sources only. An APK and a JAR are archives and
# get a resources/ tree; a bare DEX is a code file, so jadx writes no such dir.
_FORMATS_WITHOUT_RESOURCES = frozenset({"dex"})


def build_jadx_tool(context: ToolBuildContext, spec: JadxCommandSpec) -> ToolLike:
    """Build one typed jadx function tool closing over the build-time namespace."""
    namespace = context.settings.sandbox_namespace

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
        case_state = _JADX_CASE_STATE.get(case_id)
        if case_state is None:
            return {"success": False, "error": "jadx not prepared for this case"}

        arguments = dict(kwargs)
        if "class_name" in spec.params:
            # A class name becomes a filesystem path, so validate it up front:
            # a hostile value raises before any argv is built or exec runs.
            try:
                arguments["_source_path"] = _source_path_for(
                    case_state, arguments.get("class_name", "")
                )
            except InvalidClassNameError as exc:
                return {"success": False, "error": str(exc), "tool": spec.name}

        argv = list(spec.build_argv(case_state, arguments))
        try:
            stdout = kubectl_exec(
                argv,
                namespace,
                case_state["pod"],
                ok_exit_codes=spec.ok_exit_codes,
            )
        except Exception as exc:
            sample_format = case_state.get("format", "")
            if spec.android_only and sample_format != "apk":
                return {
                    "success": False,
                    "error": (
                        f"{spec.name} reads Android resources, which a "
                        f"{sample_format or 'non-apk'} sample does not carry"
                    ),
                    "tool": spec.name,
                }
            if spec.reads_resources and sample_format in _FORMATS_WITHOUT_RESOURCES:
                return {
                    "success": False,
                    "error": (
                        f"{spec.name} reads the decompiled resources tree, which a "
                        f"{sample_format} sample does not carry -- a bare DEX is code only"
                    ),
                    "tool": spec.name,
                }
            logger.warning(
                "jadx tool failed - returning degraded",
                tool=spec.name,
                error_type=type(exc).__name__,
            )
            return {"success": False, "error": str(exc), "tool": spec.name}

        if not stdout.strip():
            # An empty read is an answer for grep/find, but for `cat` it means the
            # file was not there; either way say so instead of returning success.
            return {
                "success": False,
                "degraded": True,
                "error": f"{spec.name} produced no output",
                "tool": spec.name,
            }
        return {"success": True, "output": stdout}

    # Give the callable a typed surface ADK can introspect: one parameter per
    # ``spec.params`` entry plus the injected ``tool_context``. The inner ``def``
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
        for name in spec.params
    )
    setattr(_tool, "__signature__", inspect.Signature(parameters=params))  # noqa: B010 - mypy has no __signature__ on plain funcs
    _tool.__name__ = spec.name
    _tool.__doc__ = spec.description
    return _tool


def build_jadx_toolset() -> tuple[ToolDescriptor, ...]:
    """Return one deferred-factory :class:`ToolDescriptor` per jadx command.

    No context is bound here: each descriptor carries its own ``factory``, which
    the agent factory invokes with the live :class:`ToolBuildContext` at build
    time (matching the ghidra toolset).
    """
    return tuple(
        ToolDescriptor(
            id=spec.name,
            description=spec.description,
            factory=lambda ctx, s=spec: build_jadx_tool(ctx, s),
            output_policy=spec.output_policy,
        )
        for spec in JADX_COMMANDS
    )
