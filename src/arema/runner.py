"""The domain-neutral AREMA runner: executes one query end to end.

:func:`run_single_query` drives one turn of the default (or an injected)
root agent through an ADK runner, using the process-wide (or an injected)
memory service to scope the run. A dedicated
:class:`~arema.memory.models.MemoryScope` is opened before the run and its id,
alongside a generated run id, is seeded into the ADK session state under
:class:`~arema.runtime.sessions.SessionKeys` so every callback the run
triggers can attribute its writes to this call. Scope creation and runner
construction both happen inside one ``try`` block, and both are always
released in the matching ``finally`` -- including when runner construction
itself raises -- so a failed query never leaks an open runner connection or
an open memory scope. The two cleanups are independent: a failure closing
the runner is logged and never prevents the memory scope from also being
closed. Only the query's length is ever logged, never its contents.

The runner and the memory service it scopes a run to are injected together
through one :class:`RunnerFactory` boundary rather than as two independent
parameters. That keeps the run's runner lifecycle and its memory-scope
lifecycle sourced from the same place: the default factory pairs the
process-wide composition's root agent with that same composition's memory
service (built lazily, on first use), and a test fake pairs an in-process
runner double with a hermetic, in-memory-backed memory service -- so an
injected-fake test never touches the SQLite-backed default composition or a
real provider.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol
from uuid import uuid4

from google.adk.runners import InMemoryRunner
from google.genai.types import Part, UserContent

from arema.core.config import get_settings
from arema.core.logging import get_logger
from arema.memory.models import MemoryScope
from arema.runtime.sessions import SessionKeys

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from google.adk.events import Event
    from google.genai.types import Content

    from arema.memory.service import MemoryService

logger = get_logger(__name__)

_ANONYMOUS_USER_PREFIX = "user-"


class SessionLike(Protocol):
    """The minimal shape of an ADK session this runner reads."""

    @property
    def id(self) -> str:
        """Return the session's unique identifier."""
        ...

    @property
    def user_id(self) -> str:
        """Return the user identifier the session was created for."""
        ...


class SessionServiceLike(Protocol):
    """The minimal shape of an ADK session service this runner drives."""

    async def create_session(
        self,
        *,
        app_name: str,
        user_id: str,
        state: dict[str, object] | None = None,
    ) -> SessionLike:
        """Create and return a new session, optionally seeded with state."""
        ...


class RunnerLike(Protocol):
    """The minimal shape of an ADK runner this module drives.

    Satisfied structurally by ``google.adk.runners.InMemoryRunner`` (and any
    other ADK runner) without this module depending on the concrete class, so
    a lightweight test double never has to subclass ADK's runner machinery.
    """

    @property
    def session_service(self) -> SessionServiceLike:
        """Return the runner's session service."""
        ...

    def run_async(
        self,
        *,
        user_id: str,
        session_id: str,
        new_message: Content,
    ) -> AsyncIterator[Event]:
        """Run one turn and stream back the resulting events."""
        ...

    async def close(self) -> None:
        """Release runner resources (sessions, toolsets, connections)."""
        ...


class RunnerFactory(Protocol):
    """Produces a fresh runner, paired with the memory service that scopes it.

    Bundling both behind one callable object -- rather than as two
    independent parameters -- guarantees a run's runner and its memory scope
    are always sourced from the same boundary. Production code never
    constructs this eagerly: the default instance below only imports the
    default composition lazily, inside its methods, so importing this module
    never builds it.
    """

    @property
    def memory_service(self) -> MemoryService:
        """Return the memory service that scopes runs this factory builds."""
        ...

    def __call__(self) -> RunnerLike:
        """Build and return a new runner instance."""
        ...


class _DefaultRunnerFactory:
    """The production :class:`RunnerFactory`, backed by the default composition.

    Every method imports lazily so constructing (or holding a module-level
    reference to) this factory never triggers a build of the default
    composition -- only actually calling it, or reading ``memory_service``,
    does.
    """

    def __call__(self) -> RunnerLike:
        """Build an ``InMemoryRunner`` around the default composition's root agent."""
        from arema.composition import get_default_composition

        settings = get_settings()
        return InMemoryRunner(
            agent=get_default_composition().root_agent, app_name=settings.app_name
        )

    @property
    def memory_service(self) -> MemoryService:
        """Return the default composition's memory service, built on first use."""
        from arema.composition import get_default_composition

        return get_default_composition().memory_service


_default_runner_factory: RunnerFactory = _DefaultRunnerFactory()


def _collect_response_text(event: Event) -> list[str]:
    """Extract the non-empty text parts carried by one ADK event."""
    content = event.content
    if content is None or not content.parts:
        return []
    return [part.text for part in content.parts if part.text]


async def run_single_query(
    query: str,
    *,
    runner_factory: RunnerFactory | None = None,
    user_id: str | None = None,
    case_id: str | None = None,
) -> str:
    """Run one query through a root agent and return its collected text.

    Opens a fresh :class:`~arema.memory.models.MemoryScope` via
    ``runner_factory.memory_service`` and seeds
    :attr:`~arema.runtime.sessions.SessionKeys.RUN_ID` and
    :attr:`~arema.runtime.sessions.SessionKeys.MEMORY_SCOPE_ID` into the ADK
    session state before running. When ``case_id`` is supplied, it is also
    seeded under :attr:`~arema.runtime.sessions.SessionKeys.SANDBOX_CASE_ID`
    so a stable handle (e.g. a sandbox case) can bind to the same value
    across many per-query sessions within one logical interactive session.
    When it is ``None`` the key is omitted entirely, preserving the previous
    state shape for existing callers.

    The scope and the runner are always closed
    in a ``finally`` block -- including when ``runner_factory()`` itself
    raises, when session creation raises, or when the provider raises -- and
    the exception still propagates to the caller after cleanup runs. The
    runner close and the scope close are attempted independently, so one
    failing never skips or masks the other. Only the query's length is
    logged, never its contents.

    ``runner_factory`` defaults to the process-wide default composition,
    resolved lazily; passing a fake exercises this function end to end
    without touching a live provider or the default SQLite-backed store.
    """
    factory = runner_factory if runner_factory is not None else _default_runner_factory
    memory_service = factory.memory_service

    run_id = uuid4().hex
    resolved_user_id = (
        user_id if user_id is not None else f"{_ANONYMOUS_USER_PREFIX}{uuid4().hex[:8]}"
    )

    scope: MemoryScope | None = None
    runner: RunnerLike | None = None
    try:
        scope = memory_service.create_scope(MemoryScope(scope_type="run"))
        logger.info(
            "run_single_query starting",
            query_length=len(query),
            run_id=run_id,
            memory_scope_id=scope.id,
        )

        runner = factory()
        initial_state: dict[str, object] = {
            SessionKeys.RUN_ID: run_id,
            SessionKeys.MEMORY_SCOPE_ID: scope.id,
        }
        if case_id is not None:
            initial_state[SessionKeys.SANDBOX_CASE_ID] = case_id
        session = await runner.session_service.create_session(
            app_name=get_settings().app_name,
            user_id=resolved_user_id,
            state=initial_state,
        )

        response_parts: list[str] = []
        async for event in runner.run_async(
            user_id=session.user_id,
            session_id=session.id,
            new_message=UserContent(parts=[Part(text=query)]),
        ):
            response_parts.extend(_collect_response_text(event))

        response = "\n".join(response_parts)
        logger.info(
            "run_single_query completed",
            response_length=len(response),
            run_id=run_id,
        )
        return response
    except Exception:
        logger.exception("run_single_query failed", run_id=run_id)
        raise
    finally:
        # Each cleanup is independent: a failure in one must never mask the
        # original exception, and must never prevent the other from running.
        if runner is not None:
            try:
                await runner.close()
            except Exception:
                logger.warning("run_single_query runner close failed", run_id=run_id, exc_info=True)
        if scope is not None:
            try:
                memory_service.close_scope(scope.id)
            except Exception:
                logger.warning("run_single_query scope close failed", run_id=run_id, exc_info=True)
