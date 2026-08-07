"""Shared sandbox-session lifecycle for the engine ``prepare_*`` tools.

Claiming a warm-pool pod, staging the artifact into it, and preparing its service
is the same dance for every engine (radare2, ghidra, ilspy, jadx). Done per tool
it duplicated four copies of claim+cp, three executor-tracking dicts, three
``release_*_case`` functions and three ``atexit`` handlers -- and left the
recycle-mid-claim resilience in only one of them.

This module centralizes the lifecycle so every engine gets it *for granted*:

- :func:`provision_pod` -- claim a pod, run the engine's provisioning, and on any
  failure release THAT ``(case, pool)`` claim **scoped** (via ``terminate`` -- never
  a namespace-wide delete, so the case's other pods are untouched) and re-claim a
  FRESH pod, up to a bounded number of attempts. A WarmPool can hand out or reclaim
  a pod around the moment of the claim, so a claim + stage that both succeed can
  still leave a later call facing an empty/recycled pod; the engine's ``provision``
  callable verifies the pod really holds the artifact and raises if not, which
  drives the re-claim.
- :func:`release_case` -- scoped, leak-free release of every pod a case holds, plus
  each pod's optional cleanup hook (e.g. the ghidra daemon stop). Never ``--all``.
- :func:`release_case_at_pipeline_end` -- the after-agent callback a domain root
  hangs on its pipeline so claims are released while the process is still healthy.
- one :func:`atexit`-registered sweep, now a BACKSTOP for a crashed or interrupted
  run rather than the normal path.
"""

from __future__ import annotations

import atexit
import contextlib
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, TypeVar

from arema.core.logging import get_logger
from arema.runtime.sandbox.port import SandboxHandle
from arema.runtime.sessions import SessionKeys
from reverse_engineering.runtime.portforward import default_registry

if TYPE_CHECKING:
    from google.adk.agents.callback_context import CallbackContext

    from arema.runtime.sandbox.port import SandboxExecutor

logger = get_logger(__name__)

_T = TypeVar("_T")

RETRY_ATTEMPTS = 3
RETRY_DELAY_SECONDS = 1.0

# A per-pod cleanup hook run at release, given ``(namespace, pod)`` -- e.g. stopping
# the ghidra daemon before the claim is dropped.
ReleaseHook = Callable[[str, str], None]


@dataclass(frozen=True, slots=True)
class _Session:
    executor: SandboxExecutor
    pool: str
    pod: str
    namespace: str
    on_release: ReleaseHook | None


# case_id -> {pool -> session}. One case may hold several pods (radare2 + ilspy).
_SESSIONS: dict[str, dict[str, _Session]] = {}

__all__ = [
    "ReleaseHook",
    "provision_pod",
    "release_all_cases",
    "release_case",
    "release_case_at_pipeline_end",
    "released_pools",
]


def provision_pod(
    *,
    executor: SandboxExecutor,
    case_id: str,
    pool: str,
    namespace: str,
    provision: Callable[[str], _T],
    on_release: ReleaseHook | None = None,
    attempts: int = RETRY_ATTEMPTS,
    delay: float = RETRY_DELAY_SECONDS,
) -> _T:
    """Claim a pod from ``pool`` and run ``provision(pod)``, returning its result.

    ``provision`` does all engine-specific work -- stage the artifact, prepare the
    service (port-forward / daemon load / decompile), and VERIFY the pod actually
    holds the artifact -- and MUST raise if the pod is unusable. On any failure this
    releases the ``(case, pool)`` claim scoped (never a namespace-wide delete, so the
    case's other pods are untouched) and re-claims a FRESH pod, up to ``attempts``.
    The session is registered for :func:`release_case`, with an optional per-pod
    ``on_release`` cleanup hook. Raises the last error if every attempt fails.
    """
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        pod = ""
        try:
            handle = executor.claim(key=case_id, pool=pool)
            pod = handle.backend_id
            result = provision(pod)
            _SESSIONS.setdefault(case_id, {})[pool] = _Session(
                executor=executor, pool=pool, pod=pod, namespace=namespace, on_release=on_release
            )
            return result
        except Exception as exc:
            last_error = exc
            logger.warning(
                "sandbox provision attempt failed; releasing scoped and re-claiming a fresh pod",
                attempt=attempt,
                pool=pool,
                case_id=case_id,
                pod=pod,
                error_type=type(exc).__name__,
                message=str(exc),
            )
            _release_pool_scoped(executor, case_id, pool)
            if attempt < attempts:
                time.sleep(delay)
    assert last_error is not None  # the loop ran at least once
    raise last_error


def _release_pool_scoped(executor: SandboxExecutor, case_id: str, pool: str) -> None:
    """Release ONE ``(case, pool)`` claim scoped -- terminate that specific pod so
    the next claim binds a fresh one, never a namespace-wide delete. Fail-open."""
    with contextlib.suppress(Exception):
        executor.terminate(SandboxHandle(key=case_id, pool=pool, backend_id=""))
    sessions = _SESSIONS.get(case_id)
    if sessions is not None:
        sessions.pop(pool, None)
        if not sessions:
            _SESSIONS.pop(case_id, None)


def release_case(case_id: str) -> None:
    """Release every pod a case holds: run each pod's cleanup hook, close the
    port-forward, and release the executor claims (retrying transient tunnel errors).

    Scoped and leak-free throughout -- a per-analysis teardown never touches another
    in-flight analysis's claims. Fail-open: a swallowed error at teardown leaves a
    claim to be reaped by ``make sandbox-prune`` rather than raising.
    """
    sessions = _SESSIONS.pop(case_id, {})
    for session in sessions.values():
        if session.on_release is not None:
            with contextlib.suppress(Exception):
                session.on_release(session.namespace, session.pod)
    with contextlib.suppress(Exception):
        default_registry().close(case_id)
    # ``release_session(case_id)`` releases every claim the case holds in one call, so
    # invoke it once per distinct executor (there is normally exactly one).
    for executor in {session.executor for session in sessions.values()}:
        _release_session_retrying(executor, case_id)


def _release_session_retrying(executor: SandboxExecutor, case_id: str) -> None:
    """Release a case's executor claims, retrying only transient tunnel errors.

    The executor's own ``terminate`` already falls back to a SCOPED ``kubectl delete
    sandboxclaim <name>`` when its client transport is dead, so there is no
    namespace-wide fallback here: a residual failure leaks one claim (rare) rather
    than deleting other in-flight analyses' claims.
    """
    for _attempt in range(RETRY_ATTEMPTS):
        try:
            executor.release_session(case_id)
            return
        except OSError:
            time.sleep(RETRY_DELAY_SECONDS)
        except Exception:
            return
    logger.warning(
        "sandbox release_session failed after retries; claim may need `make sandbox-prune`",
        case_id=case_id,
    )


def released_pools(case_id: str) -> frozenset[str]:
    """The pools currently held by ``case_id`` (testing/introspection helper)."""
    return frozenset(_SESSIONS.get(case_id, {}))


def release_case_at_pipeline_end(callback_context: CallbackContext) -> None:
    """Release this run's claims when the pipeline ends, not at interpreter exit.

    Hung on a domain root's ``after_agent_callbacks``. Releasing here is not merely
    tidier -- it is the only point at which the executor's OWN client can do the
    release. The ``atexit`` sweep runs during interpreter shutdown, by which time
    the kubernetes client has torn down its transport in its own ``atexit`` handler,
    so every claim failed with ``MaxRetryError`` and fell back to ``kubectl delete``.
    That fallback works, which is exactly why this went unnoticed: cleanup was
    correct while the primary path had never once succeeded.

    Fail-open, like every teardown here: the ``atexit`` sweep remains as the
    backstop for a crashed or interrupted run, and finds nothing after a clean one.
    """
    try:
        state = getattr(callback_context, "state", None)
        getter = getattr(state, "get", None)
        if not callable(getter):
            return
        case_id = getter(SessionKeys.SANDBOX_CASE_ID, None)
    except Exception as exc:
        logger.warning("pipeline-end sandbox release skipped", error_type=type(exc).__name__)
        return
    # A run that claimed nothing never wrote the key; there is nothing to release.
    if isinstance(case_id, str) and case_id.strip():
        release_case(case_id)


def release_all_cases() -> None:
    """Release every still-open case. Registered as the process-exit BACKSTOP.

    After a clean run :func:`release_case_at_pipeline_end` has already emptied
    ``_SESSIONS``, so this finds nothing; it exists for a crashed or interrupted run.
    """
    for case_id in list(_SESSIONS):
        release_case(case_id)


atexit.register(release_all_cases)
