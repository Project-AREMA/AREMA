"""The prepare_ilspy tool: claim an ILSpy-MCP pod, copy the assembly, open a tunnel.

Mirrors :mod:`prepare_sandbox`'s deferred-factory pattern: a plain function cannot
see :class:`RuntimeServices`, so :func:`build_prepare_ilspy` closes over
``context.services.sandbox`` and ``context.settings.sandbox_namespace`` and
returns the callable ADK injects at call time (named ``prepare_ilspy`` so its
``__name__`` matches the descriptor id, which is required for the
:class:`OutputPolicy` to bind at compaction time).

The deployed pod is a single ``ilspy-mcp`` container on ``:3001``. The claim +
stage + verify + release lifecycle (including re-claiming a fresh pod when a
WarmPool recycles it) is the shared
:mod:`reverse_engineering.runtime.sandbox_session`; one case may hold both the
r2mcp and ILSpy pods under one sandbox key, and ``release_case`` frees every pool
bound to that key at once.

**The ``.dll`` suffix is required, not cosmetic.** ILSpy-MCP resolves an assembly
by file extension: byte-identical assemblies fail to load at ``/app/<sha256>`` and
succeed at ``/app/<sha256>.dll``. The tool copies the artifact to that exact path
and returns it as ``assembly_path`` so the agent never has to construct it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from google.adk.tools.tool_context import (
    ToolContext,  # noqa: TC002 - runtime import: ADK resolves this annotation via get_type_hints
)

from arema.core.logging import get_logger
from arema.registry.descriptors import OutputPolicy, ToolDescriptor
from arema.runtime.sessions import SandboxIdentityError, resolve_sandbox_case_id
from reverse_engineering.artifacts import ArtifactStore, default_artifacts_root
from reverse_engineering.runtime.portforward import default_registry, kubectl_cp, kubectl_exec
from reverse_engineering.runtime.sandbox_session import provision_pod

if TYPE_CHECKING:
    from arema.registry.descriptors import ToolLike
    from arema.runtime.agent_factory import ToolBuildContext

logger = get_logger(__name__)

_ILSPY_POOL = "ilspy-mcp"
_ILSPY_PORT = 3001
_POD_PATH_PREFIX = "/app"
_ASSEMBLY_SUFFIX = ".dll"


def build_prepare_ilspy(context: ToolBuildContext) -> ToolLike:
    """Build the ``prepare_ilspy`` tool closing over the live sandbox executor."""
    executor = context.services.sandbox
    namespace = context.settings.sandbox_namespace

    def prepare_ilspy(artifact_id: str, tool_context: ToolContext) -> dict[str, str | bool]:
        try:
            case_id = resolve_sandbox_case_id(tool_context)
        except SandboxIdentityError:
            return {
                "pod": "",
                "assembly_path": "",
                "ready": False,
                "error_code": "sandbox_identity_unavailable",
                "error": "The sandbox identity is unavailable.",
            }
        assembly_path = f"{_POD_PATH_PREFIX}/{artifact_id}{_ASSEMBLY_SUFFIX}"
        if executor is None:
            return {
                "pod": "",
                "assembly_path": "",
                "ready": False,
                "error": "sandbox executor is not configured",
            }
        local_path = str(ArtifactStore(default_artifacts_root()).path_for(artifact_id))

        def _provision(pod: str) -> dict[str, str | bool]:
            kubectl_cp(local_path, namespace, pod, assembly_path)
            # Verify the pod holds the assembly before declaring ready; if it does
            # not (recycled pod), provision_pod re-claims a fresh one.
            kubectl_exec(["test", "-f", assembly_path], namespace, pod)
            default_registry().open(case_id=case_id, namespace=namespace, pod=pod, port=_ILSPY_PORT)
            return {"pod": pod, "assembly_path": assembly_path, "ready": True}

        try:
            return provision_pod(
                executor=executor,
                case_id=case_id,
                pool=_ILSPY_POOL,
                namespace=namespace,
                provision=_provision,
            )
        except Exception as exc:
            logger.warning(
                "prepare_ilspy failed - returning degraded",
                error_type=type(exc).__name__,
                message=str(exc),
                case_id=case_id,
            )
            return {"pod": "", "assembly_path": "", "ready": False, "error": str(exc)}

    return prepare_ilspy


PREPARE_ILSPY_TOOL = ToolDescriptor(
    id="prepare_ilspy",
    description=(
        "Claim an ilspy-mcp sandbox pod, copy the artifact into "
        "/app/<sha256>.dll, and open a localhost port-forward so the ILSpy MCP "
        "server is reachable. Returns the pod name, the assembly_path to pass to "
        "every ilspy tool, and readiness."
    ),
    factory=build_prepare_ilspy,
    output_policy=OutputPolicy(max_chars=2_000, max_list_items=10),
)
