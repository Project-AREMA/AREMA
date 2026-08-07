"""The prepare_sandbox tool: claim an r2mcp pod, copy the artifact, open a tunnel.

This is a deferred-factory tool: a plain function cannot see ``RuntimeServices``,
so :func:`build_prepare_sandbox` closes over ``context.services.sandbox`` and
``context.settings.sandbox_namespace`` and returns the callable ADK injects at
call time (named ``prepare_sandbox`` so its ``__name__`` matches the descriptor
id, which is required for the ``OutputPolicy`` to bind at compaction time).

The deployed sandbox pod is a single ``r2mcp`` container on ``:8765``. The claim +
stage + verify + release lifecycle -- including re-claiming a fresh pod when a
WarmPool recycles the one it handed out -- lives in
:mod:`reverse_engineering.runtime.sandbox_session`; here the ``provision`` closure
just pushes the artifact via raw ``kubectl cp`` to ``/app/<sha256>``, verifies the
pod holds it, and opens ``kubectl port-forward pod/<name> 8765:8765``.
"""

from __future__ import annotations

import re
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
from reverse_engineering.tools.deobfuscation.state import CURRENT_ARTIFACT_KEY
from reverse_engineering.tools.detect_it_easy import (
    SAMPLE_DIE_KEY,
    SAMPLE_DIE_PROMPT_KEY,
    scan_staged_artifact,
)

if TYPE_CHECKING:
    from arema.registry.descriptors import ToolLike
    from arema.runtime.agent_factory import ToolBuildContext

logger = get_logger(__name__)

_R2MCP_POOL = "radare2-mcp"
_R2MCP_PORT = 8765
_POD_PATH_PREFIX = "/app"
_ARTIFACT_ID_PATTERN = re.compile(r"[0-9a-f]{64}")

__all__ = ["PREPARE_SANDBOX_TOOL", "build_prepare_sandbox"]


def build_prepare_sandbox(context: ToolBuildContext) -> ToolLike:
    """Build the ``prepare_sandbox`` tool closing over the live sandbox executor."""
    executor = context.services.sandbox
    namespace = context.settings.sandbox_namespace

    def prepare_sandbox(artifact_id: str, tool_context: ToolContext) -> dict[str, str | bool]:
        try:
            case_id = resolve_sandbox_case_id(tool_context)
        except SandboxIdentityError:
            return {
                "pod": "",
                "ready": False,
                "error_code": "sandbox_identity_unavailable",
                "error": "The sandbox identity is unavailable.",
            }
        state = getattr(tool_context, "state", None)
        getter = getattr(state, "get", None)
        current = getter(CURRENT_ARTIFACT_KEY, None) if callable(getter) else None
        if current is not None:
            if not _valid_artifact_id(current):
                return {"pod": "", "ready": False, "error": "invalid current artifact state"}
            artifact_id = current
        elif not _valid_artifact_id(artifact_id):
            return {"pod": "", "ready": False, "error": "invalid artifact id"}
        if executor is None:
            return {"pod": "", "ready": False, "error": "sandbox executor is not configured"}
        local_path = str(ArtifactStore(default_artifacts_root()).path_for(artifact_id))
        pod_path = f"{_POD_PATH_PREFIX}/{artifact_id}"

        def _provision(pod: str) -> dict[str, str | bool]:
            kubectl_cp(local_path, namespace, pod, pod_path)
            # Verify the claimed pod is alive AND holds the file before declaring
            # ready; if it doesn't, provision_pod re-claims a fresh pod.
            kubectl_exec(["test", "-f", pod_path], namespace, pod)
            default_registry().open(case_id=case_id, namespace=namespace, pod=pod, port=_R2MCP_PORT)
            # The packer pre-validator rides along here rather than living in its
            # own tool: the bytes are already in this pod and already verified, so
            # the scan is one exec. Running it inside the tool intake MUST call --
            # and stops on -- is also what makes it deterministic; a tool of its
            # own would be back to depending on a model choosing to call it.
            # scan_staged_artifact never raises, so a DIE failure cannot be
            # mistaken for pod trouble and trigger a re-claim.
            die_summary = scan_staged_artifact(namespace, pod, pod_path)
            _record_die_verdict(tool_context, die_summary)
            return {
                "pod": pod,
                "ready": True,
                "artifact_id": artifact_id,
                "file_path": pod_path,
                "packer_scan": die_summary,
            }

        try:
            return provision_pod(
                executor=executor,
                case_id=case_id,
                pool=_R2MCP_POOL,
                namespace=namespace,
                provision=_provision,
            )
        except Exception as exc:
            logger.warning(
                "prepare_sandbox failed - returning degraded",
                error_type=type(exc).__name__,
                message=str(exc),
                case_id=case_id,
            )
            return {"pod": "", "ready": False, "error": str(exc)}

    return prepare_sandbox


def _record_die_verdict(tool_context: ToolContext, summary: str) -> None:
    """Publish the pre-validator verdict for triage, clearing a stale one.

    Always written, including the empty case: this tool re-runs across a session,
    and a verdict left over from an earlier sample would otherwise be cited
    against the current one.
    """
    state = getattr(tool_context, "state", None)
    if not callable(getattr(state, "__setitem__", None)):
        return
    state[SAMPLE_DIE_KEY] = summary  # type: ignore[index]
    state[SAMPLE_DIE_PROMPT_KEY] = summary  # type: ignore[index]


def _valid_artifact_id(value: object) -> bool:
    return isinstance(value, str) and _ARTIFACT_ID_PATTERN.fullmatch(value) is not None


PREPARE_SANDBOX_TOOL = ToolDescriptor(
    id="prepare_sandbox",
    description=(
        "Claim a radare2-mcp sandbox pod, copy the artifact into /app/<sha256>, "
        "open a localhost port-forward so the r2mcp MCP server is reachable, and "
        "run the Detect It Easy packer pre-validator against the staged bytes. "
        "Returns the pod name, readiness, and packer_scan (the packer/protector "
        "DIE named, or empty when it named none or could not run)."
    ),
    factory=build_prepare_sandbox,
    output_policy=OutputPolicy(max_chars=2_000, max_list_items=10),
)
