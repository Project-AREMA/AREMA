"""The prepare_ghidra tool: claim a ghidra pod, copy the artifact, start the daemon, load the binary.

Mirrors :mod:`prepare_sandbox`'s deferred-factory pattern: a plain function
cannot see :class:`RuntimeServices`, so :func:`build_prepare_ghidra` closes over
``context.services.sandbox`` and ``context.settings.sandbox_namespace`` and
returns the callable ADK injects at call time (named ``prepare_ghidra`` so its
``__name__`` matches the descriptor id, which is required for the
:class:`OutputPolicy` to bind at compaction time).

The claimed pod is driven via raw ``kubectl`` (``cp`` to push the artifact,
``exec`` to start the headless daemon and load the binary). ``ghidra-rpc load``
returns the binary's ``short_name``; that name is stashed in the shared case
state (read by every ghidra tool) so the agent never passes it.
"""

from __future__ import annotations

import json
import re
import time
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
from reverse_engineering.tools.deobfuscation.state import CURRENT_ARTIFACT_KEY
from reverse_engineering.tools.ghidra.coverage import record_prepared
from reverse_engineering.tools.ghidra.toolset import _GHIDRA_CASE_STATE

if TYPE_CHECKING:
    from arema.registry.descriptors import ToolLike
    from arema.runtime.agent_factory import ToolBuildContext

logger = get_logger(__name__)

_GHIDRA_POOL = "ghidra-rpc"
_PROJECT_PATH = "/tmp/arema_ghidra.gpr"
# ghidra-rpc v0.2.0 defaults its client socket to 120 seconds unless the load
# request carries ``--analysis-timeout``. Real PE imports can legitimately take
# longer (the regression sample completed in about 277 seconds), so give Ghidra
# a bounded ten-minute analysis budget. ghidra-rpc adds a 30-second socket
# buffer; the outer kubectl deadline must exceed both and retain cleanup margin.
_GHIDRA_ANALYSIS_TIMEOUT_SECONDS = 600
_GHIDRA_LOAD_EXEC_TIMEOUT_SECONDS = 660

# Ghidra's ``load`` runs the full auto-analysis -- the heaviest memory step. The
# sandbox node is shared with other heavy JVM workloads, so a transient contention
# spike can make the kernel SIGKILL it (kubectl exec surfaces exit 137 as a
# RuntimeError). That is environmental, not a deterministic shortfall, so retry the
# start+load sequence, restarting the daemon each time so a half-dead JVM from a
# killed attempt cannot poison the reload. (This is per-pod load retry; claim-level
# re-claim-a-fresh-pod resilience is provided by sandbox_session.provision_pod.)
_LOAD_ATTEMPTS = 3
_LOAD_RETRY_BACKOFF_SECONDS = 15.0
_ARTIFACT_ID_PATTERN = re.compile(r"[0-9a-f]{64}")
_MISSING = object()


def _stop_daemon_quietly(namespace: str, pod: str) -> None:
    """Best-effort daemon stop before a load retry; a stale daemon must not block start."""
    try:
        kubectl_exec(["ghidra-rpc", "stop", "--project", _PROJECT_PATH], namespace, pod)
    except Exception:
        logger.debug("ghidra daemon stop before retry failed - ignoring", exc_info=True)


def _start_daemon_and_load(namespace: str, pod: str, artifact_id: str, case_id: str) -> str:
    """Start the headless daemon and load the binary, retrying transient kills.

    Retries the whole start+load sequence on any :class:`RuntimeError` from
    ``kubectl exec`` (exit 137 from an OOM SIGKILL, or a load timeout under
    contention). See :data:`_LOAD_ATTEMPTS` for the rationale. Raises the last
    error if every attempt fails, letting the caller degrade the stage.
    """
    last_exc: Exception | None = None
    for attempt in range(1, _LOAD_ATTEMPTS + 1):
        try:
            if attempt > 1:
                _stop_daemon_quietly(namespace, pod)
                time.sleep(_LOAD_RETRY_BACKOFF_SECONDS)
            kubectl_exec(
                ["ghidra-rpc", "start", "--project", _PROJECT_PATH, "--headless", "--detach"],
                namespace,
                pod,
            )
            return kubectl_exec(
                [
                    "ghidra-rpc",
                    "load",
                    f"/app/{artifact_id}",
                    "--analysis-timeout",
                    str(_GHIDRA_ANALYSIS_TIMEOUT_SECONDS),
                    "--project",
                    _PROJECT_PATH,
                ],
                namespace,
                pod,
                timeout=_GHIDRA_LOAD_EXEC_TIMEOUT_SECONDS,
            )
        except RuntimeError as exc:
            last_exc = exc
            logger.warning(
                "ghidra start/load attempt failed - retrying",
                attempt=attempt,
                attempts=_LOAD_ATTEMPTS,
                error_type=type(exc).__name__,
                message=str(exc),
                case_id=case_id,
                pod=pod,
            )
    assert last_exc is not None  # loop body sets last_exc before every continue
    raise last_exc


def build_prepare_ghidra(context: ToolBuildContext) -> ToolLike:
    """Build the ``prepare_ghidra`` tool closing over the live sandbox executor."""
    executor = context.services.sandbox
    namespace = context.settings.sandbox_namespace

    def prepare_ghidra(artifact_id: str, tool_context: ToolContext) -> dict[str, Any]:
        try:
            case_id = resolve_sandbox_case_id(tool_context)
        except SandboxIdentityError:
            return {
                "pod": "",
                "binary": "",
                "ready": False,
                "error_code": "sandbox_identity_unavailable",
                "error": "The sandbox identity is unavailable.",
                "artifact_id": artifact_id,
            }
        state = getattr(tool_context, "state", None)
        getter = getattr(state, "get", None)
        canonical = getter(CURRENT_ARTIFACT_KEY, _MISSING) if callable(getter) else _MISSING
        resolved_artifact_id = artifact_id if canonical is _MISSING else canonical
        if (
            not isinstance(resolved_artifact_id, str)
            or _ARTIFACT_ID_PATTERN.fullmatch(resolved_artifact_id) is None
        ):
            return {
                "pod": "",
                "binary": "",
                "ready": False,
                "error": "artifact_id must be a lowercase SHA-256",
            }
        artifact_id = resolved_artifact_id
        existing = _GHIDRA_CASE_STATE.get(case_id)
        if (
            existing is not None
            and existing.get("artifact_id") == artifact_id
            and existing.get("pod")
            and existing.get("binary")
        ):
            record_prepared(state, artifact_id)
            return {
                "pod": existing["pod"],
                "binary": existing["binary"],
                "ready": True,
                "artifact_id": artifact_id,
                "reused": True,
            }
        if executor is None:
            return {
                "pod": "",
                "binary": "",
                "ready": False,
                "error": "sandbox executor is not configured",
                "artifact_id": artifact_id,
            }
        local_path = str(ArtifactStore(default_artifacts_root()).path_for(artifact_id))

        def _provision(pod: str) -> dict[str, Any]:
            # A cp failure means the pod is likely gone -> raise so provision_pod
            # re-claims a fresh pod.
            kubectl_cp(local_path, namespace, pod, f"/app/{artifact_id}")
            try:
                load_out = _start_daemon_and_load(namespace, pod, artifact_id, case_id)
            except RuntimeError as exc:
                # The cp succeeded, so the pod is alive; the load genuinely failed
                # (OOM/timeout after its own same-pod retries). That is an analysis
                # failure, not a recycled pod, so degrade in place rather than making
                # provision_pod re-claim a fresh pod that would only OOM again.
                return {
                    "pod": pod,
                    "binary": "",
                    "ready": False,
                    "error": str(exc),
                    "artifact_id": artifact_id,
                }
            binary_name = artifact_id
            try:
                load_json = json.loads(load_out.strip())
                result = load_json.get("result") if isinstance(load_json, dict) else None
                if isinstance(result, dict):
                    short_name = result.get("short_name")
                    if isinstance(short_name, str) and short_name:
                        binary_name = short_name
            except Exception:
                logger.debug(
                    "ghidra load output was not JSON with a short_name - using artifact_id fallback",
                    exc_info=True,
                )
            _GHIDRA_CASE_STATE[case_id] = {
                "pod": pod,
                "binary": binary_name,
                "project": _PROJECT_PATH,
                "namespace": namespace,
                "artifact_id": artifact_id,
            }
            record_prepared(state, artifact_id)
            return {
                "pod": pod,
                "binary": binary_name,
                "ready": True,
                "artifact_id": artifact_id,
                "reused": False,
            }

        try:
            return provision_pod(
                executor=executor,
                case_id=case_id,
                pool=_GHIDRA_POOL,
                namespace=namespace,
                provision=_provision,
                on_release=_stop_daemon_quietly,  # stop the daemon before the claim is dropped
            )
        except Exception as exc:
            logger.warning(
                "prepare_ghidra failed - returning degraded",
                error_type=type(exc).__name__,
                message=str(exc),
                case_id=case_id,
            )
            return {
                "pod": "",
                "binary": "",
                "ready": False,
                "error": str(exc),
                "artifact_id": artifact_id,
            }

    return prepare_ghidra


def release_ghidra_case(case_id: str) -> None:
    """Release one ghidra case: drop its cached load state, then the shared scoped
    release (which stops the daemon via the ``on_release`` hook and frees the claim).

    Fail-open throughout. Process-exit cleanup is the single ``sandbox_session``
    atexit sweep, which runs the same daemon-stop hook and scoped release.
    """
    _GHIDRA_CASE_STATE.pop(case_id, None)
    release_case(case_id)


PREPARE_GHIDRA_TOOL = ToolDescriptor(
    id="prepare_ghidra",
    description=(
        "Claim a ghidra-rpc sandbox pod, copy the artifact into /app/<sha256>, "
        "start the headless Ghidra daemon, and load the binary. Returns the pod "
        "name, the binary short_name, and readiness."
    ),
    factory=build_prepare_ghidra,
    output_policy=OutputPolicy(max_chars=2_000, max_list_items=10),
)
