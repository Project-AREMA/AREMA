"""The prepare_jadx tool: claim a jadx pod, copy the sample, decompile it once.

Mirrors :mod:`prepare_ghidra`'s deferred-factory pattern: a plain function cannot
see :class:`RuntimeServices`, so :func:`build_prepare_jadx` closes over
``context.services.sandbox`` and ``context.settings.sandbox_namespace`` and
returns the callable ADK injects at call time (named ``prepare_jadx`` so its
``__name__`` matches the descriptor id, which the :class:`OutputPolicy` binds on).

jadx is exec-backed rather than MCP-backed, so nothing has to be listening when
ADK resolves this agent's tools -- it can live on the analysis agent itself, next
to the tools that read its output.

The whole decompilation happens here, once: ``jadx --no-imports -d <out>
/app/<sha256>``. jadx reads .apk/.dex/.jar directly -- no unzip step -- and for an
APK also decodes the binary AndroidManifest.xml and the resource table. Every
other jadx tool then just reads files out of ``<out>`` (stashed in the shared case
state so the agent never passes a path). jadx exits ``1`` when some classes failed
but the rest decompiled; a partial tree is still worth analyzing, so that exit is
tolerated. The claim + stage + verify + release lifecycle -- including re-claiming
a fresh pod when a WarmPool recycles the one it handed out -- is the shared
:mod:`reverse_engineering.runtime.sandbox_session`; the decompile itself exercises
the claimed pod and so doubles as the verification.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from google.adk.tools.tool_context import (
    ToolContext,  # noqa: TC002 - runtime import: ADK resolves this annotation via get_type_hints
)

from arema.core.logging import get_logger
from arema.registry.descriptors import OutputPolicy, ToolDescriptor
from arema.runtime.sessions import SandboxIdentityError, resolve_sandbox_case_id
from reverse_engineering.artifacts import ArtifactStore, default_artifacts_root
from reverse_engineering.runtime.portforward import kubectl_cp, kubectl_exec
from reverse_engineering.runtime.sandbox_session import provision_pod, release_case
from reverse_engineering.tools.jadx.toolset import _JADX_CASE_STATE

if TYPE_CHECKING:
    from arema.registry.descriptors import ToolLike
    from arema.runtime.agent_factory import ToolBuildContext

logger = get_logger(__name__)

_JADX_POOL = "jadx"
_POD_PATH_PREFIX = "/app"
# A path inside the sandbox pod, not on the host filesystem.
_OUTPUT_PREFIX = "/tmp/jadx"

# Decompiling a large APK is minutes of CPU, well past kubectl_exec's default.
_DECOMPILE_TIMEOUT_SECONDS = 900
# jadx exits 1 when some classes failed to decompile but the rest succeeded. A
# partial tree is still worth analyzing, so that is not treated as a failure.
_JADX_OK_EXIT_CODES = (0, 1)


def build_prepare_jadx(context: ToolBuildContext) -> ToolLike:
    """Build the ``prepare_jadx`` tool closing over the live sandbox executor."""
    executor = context.services.sandbox
    namespace = context.settings.sandbox_namespace

    def prepare_jadx(
        artifact_id: str, sample_format: str, tool_context: ToolContext
    ) -> dict[str, Any]:
        try:
            case_id = resolve_sandbox_case_id(tool_context)
        except SandboxIdentityError:
            return {
                "pod": "",
                "output_dir": "",
                "ready": False,
                "error_code": "sandbox_identity_unavailable",
                "error": "The sandbox identity is unavailable.",
            }
        if executor is None:
            return {
                "pod": "",
                "output_dir": "",
                "ready": False,
                "error": "sandbox executor is not configured",
            }
        output_dir = f"{_OUTPUT_PREFIX}_{artifact_id}"
        local_path = str(ArtifactStore(default_artifacts_root()).path_for(artifact_id))
        sample_path = f"{_POD_PATH_PREFIX}/{artifact_id}"

        def _provision(pod: str) -> dict[str, Any]:
            kubectl_cp(local_path, namespace, pod, sample_path)
            # The decompile + find exec the claimed pod, so they also verify it is
            # alive: a recycled/empty pod fails here and provision_pod re-claims.
            kubectl_exec(
                ["jadx", "--no-imports", "-d", output_dir, sample_path],
                namespace,
                pod,
                timeout=_DECOMPILE_TIMEOUT_SECONDS,
                ok_exit_codes=_JADX_OK_EXIT_CODES,
            )
            class_listing = kubectl_exec(
                ["find", f"{output_dir}/sources", "-type", "f", "-name", "*.java"],
                namespace,
                pod,
            )
            classes = len([line for line in class_listing.splitlines() if line.strip()])
            if not classes:
                # A genuine empty result (not a recycled pod): return it, do not re-claim.
                return {
                    "pod": pod,
                    "output_dir": output_dir,
                    "ready": False,
                    "error": "jadx produced no decompiled sources",
                }
            _JADX_CASE_STATE[case_id] = {
                "pod": pod,
                "out": output_dir,
                "namespace": namespace,
                "format": sample_format,
            }
            return {"pod": pod, "output_dir": output_dir, "classes": classes, "ready": True}

        try:
            return provision_pod(
                executor=executor,
                case_id=case_id,
                pool=_JADX_POOL,
                namespace=namespace,
                provision=_provision,
            )
        except Exception as exc:
            logger.warning(
                "prepare_jadx failed - returning degraded",
                error_type=type(exc).__name__,
                message=str(exc),
                case_id=case_id,
            )
            return {"pod": "", "output_dir": "", "ready": False, "error": str(exc)}

    return prepare_jadx


def release_jadx_case(case_id: str) -> None:
    """Release one jadx case: drop its cached output state, then the shared scoped
    release (jadx has no daemon to stop, so this only frees the claim).

    Fail-open. Process-exit cleanup is the single ``sandbox_session`` atexit sweep.
    """
    _JADX_CASE_STATE.pop(case_id, None)
    release_case(case_id)


PREPARE_JADX_TOOL = ToolDescriptor(
    id="prepare_jadx",
    description=(
        "Claim a jadx sandbox pod, copy the artifact into /app/<sha256>, and "
        "decompile it in one pass. Pass the sample's format (apk, dex or jar) so "
        "the Android-only tools can explain themselves on a plain JAR. Returns "
        "the pod, the output directory and the decompiled class count."
    ),
    factory=build_prepare_jadx,
    output_policy=OutputPolicy(max_chars=2_000, max_list_items=10),
)
