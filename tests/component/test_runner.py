"""Component tests for the domain-neutral AREMA runner.

Every test here injects a fake :class:`~arema.runner.RunnerFactory` that
pairs an in-process runner double with a hermetic, ``InMemoryStore``-backed
:class:`~arema.memory.service.MemoryService` -- never the real SQLite-backed
default composition, and never a live provider.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, NoReturn

import pytest
from google.adk.events import Event
from google.genai.types import Part, UserContent

import arema.runner as runner_module
from arema.core.config import Settings
from arema.memory.backends.memory import InMemoryStore
from arema.memory.service import MemoryService, default_core_codec_registry
from arema.runner import run_single_query
from arema.runtime.sessions import SessionKeys

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Sequence

    from arema.memory.models import MemoryScope


def _text_event(text: str) -> Event:
    """Build a minimal ADK event carrying one text part."""
    return Event(author="model", content=UserContent(parts=[Part(text=text)]))


def _hermetic_memory_service() -> MemoryService:
    """Return a fully in-memory, credential-free memory service for tests."""
    settings = Settings(_env_file=None, llm_provider="ollama", memory_backend="memory")
    service = MemoryService(
        store=InMemoryStore(),
        codecs=default_core_codec_registry(),
        settings=settings,
    )
    service.store.initialize()
    return service


class _RecordingMemoryService(MemoryService):
    """A hermetic :class:`MemoryService` that records every scope it creates.

    Used to assert scope closure when the run never reaches session creation
    (e.g. the runner itself fails to construct), so the test has no other way
    to learn the scope's id.
    """

    def __init__(self) -> None:
        settings = Settings(_env_file=None, llm_provider="ollama", memory_backend="memory")
        store = InMemoryStore()
        store.initialize()
        super().__init__(store=store, codecs=default_core_codec_registry(), settings=settings)
        self.created_scopes: list[MemoryScope] = []

    def create_scope(self, scope: MemoryScope) -> MemoryScope:
        created = super().create_scope(scope)
        self.created_scopes.append(created)
        return created


class _FakeSession:
    """A minimal :class:`~arema.runner.SessionLike` double."""

    def __init__(self, session_id: str, user_id: str) -> None:
        self._id = session_id
        self._user_id = user_id

    @property
    def id(self) -> str:
        return self._id

    @property
    def user_id(self) -> str:
        return self._user_id


class _FakeSessionService:
    """Records every seeded session state for later assertions."""

    def __init__(self) -> None:
        self.created_states: list[dict[str, object]] = []
        self.last_user_id: str | None = None

    async def create_session(
        self,
        *,
        app_name: str,
        user_id: str,
        state: dict[str, object] | None = None,
    ) -> _FakeSession:
        del app_name
        self.last_user_id = user_id
        self.created_states.append(dict(state) if state is not None else {})
        return _FakeSession(f"session-{len(self.created_states)}", user_id)


class _FakeRunner:
    """A minimal :class:`~arema.runner.RunnerLike` double."""

    def __init__(self, factory: _FakeRunnerFactory) -> None:
        self._factory = factory
        self.session_service = _FakeSessionService()
        self.close_called = False

    @property
    def last_user_id(self) -> str | None:
        """Return the user id passed to the most recent ``create_session`` call."""
        return self.session_service.last_user_id

    async def run_async(
        self,
        *,
        user_id: str,
        session_id: str,
        new_message: object,
    ) -> AsyncIterator[Event]:
        del user_id, session_id, new_message
        if self._factory.failure is not None:
            raise self._factory.failure
        for event in self._factory.events:
            yield event

    async def close(self) -> None:
        self.close_called = True
        self._factory.closed = True


class _FakeRunnerFactory:
    """A callable :class:`~arema.runner.RunnerFactory` double.

    Paired with a hermetic, in-memory-backed :class:`MemoryService` so tests
    that inject this factory never touch the real SQLite-backed default
    composition, and tracks every runner it built so tests can inspect what
    each run seeded and whether its scope was closed.
    """

    def __init__(
        self,
        *,
        events: Sequence[Event] | None = None,
        failure: Exception | None = None,
    ) -> None:
        self.closed = False
        self.created = 0
        self.failure = failure
        self.events: list[Event] = (
            list(events) if events is not None else [_text_event("AREMA runtime operational")]
        )
        self.runners: list[_FakeRunner] = []
        self.memory_service = _hermetic_memory_service()

    def __call__(self) -> _FakeRunner:
        self.created += 1
        runner = _FakeRunner(self)
        self.runners.append(runner)
        return runner


class _RecordingLogger:
    """Captures structured log calls without ever printing them."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, object]]] = []

    def info(self, event: str, **kwargs: object) -> None:
        self.calls.append(("info", event, kwargs))

    def exception(self, event: str, **kwargs: object) -> None:
        self.calls.append(("exception", event, kwargs))


@pytest.fixture
def fake_runner_factory() -> _FakeRunnerFactory:
    return _FakeRunnerFactory()


# ---------------------------------------------------------------------------
# Response collection
# ---------------------------------------------------------------------------


async def test_run_single_query_collects_text(fake_runner_factory: _FakeRunnerFactory) -> None:
    response = await run_single_query("hello", runner_factory=fake_runner_factory)

    assert response == "AREMA runtime operational"
    assert fake_runner_factory.closed


async def test_run_single_query_joins_multiple_event_texts() -> None:
    factory = _FakeRunnerFactory(events=[_text_event("first"), _text_event("second")])

    response = await run_single_query("hello", runner_factory=factory)

    assert response == "first\nsecond"


async def test_run_single_query_ignores_events_without_text() -> None:
    contentless_event = Event(author="model", content=None)
    factory = _FakeRunnerFactory(events=[contentless_event, _text_event("only text")])

    response = await run_single_query("hello", runner_factory=factory)

    assert response == "only text"


# ---------------------------------------------------------------------------
# Session state seeding
# ---------------------------------------------------------------------------


async def test_run_single_query_seeds_run_id_and_memory_scope_id(
    fake_runner_factory: _FakeRunnerFactory,
) -> None:
    await run_single_query("hello", runner_factory=fake_runner_factory)

    assert len(fake_runner_factory.runners) == 1
    seeded_state = fake_runner_factory.runners[0].session_service.created_states[0]
    assert isinstance(seeded_state[SessionKeys.RUN_ID], str)
    assert seeded_state[SessionKeys.RUN_ID]
    assert isinstance(seeded_state[SessionKeys.MEMORY_SCOPE_ID], str)
    assert seeded_state[SessionKeys.MEMORY_SCOPE_ID]


async def test_run_single_query_generates_a_user_id_by_default(
    fake_runner_factory: _FakeRunnerFactory,
) -> None:
    await run_single_query("hello", runner_factory=fake_runner_factory)

    assert fake_runner_factory.runners[0].session_service.created_states
    assert fake_runner_factory.runners[0].last_user_id is not None
    assert fake_runner_factory.runners[0].last_user_id.startswith("user-")


async def test_run_single_query_honors_explicit_user_id(
    fake_runner_factory: _FakeRunnerFactory,
) -> None:
    await run_single_query("hello", runner_factory=fake_runner_factory, user_id="operator-1")

    assert fake_runner_factory.runners[0].last_user_id == "operator-1"


async def test_run_single_query_seeds_case_id_when_provided(
    fake_runner_factory: _FakeRunnerFactory,
) -> None:
    await run_single_query("hello", runner_factory=fake_runner_factory, case_id="case-42")

    seeded_state = fake_runner_factory.runners[0].session_service.created_states[0]
    assert seeded_state[SessionKeys.SANDBOX_CASE_ID] == "case-42"


async def test_run_single_query_omits_case_id_key_when_not_provided(
    fake_runner_factory: _FakeRunnerFactory,
) -> None:
    await run_single_query("hello", runner_factory=fake_runner_factory)

    seeded_state = fake_runner_factory.runners[0].session_service.created_states[0]
    assert SessionKeys.SANDBOX_CASE_ID not in seeded_state


# ---------------------------------------------------------------------------
# Memory scope lifecycle
# ---------------------------------------------------------------------------


async def test_run_single_query_creates_one_distinct_scope_per_run(
    fake_runner_factory: _FakeRunnerFactory,
) -> None:
    await run_single_query("first", runner_factory=fake_runner_factory)
    await run_single_query("second", runner_factory=fake_runner_factory)

    assert len(fake_runner_factory.runners) == 2
    scope_ids = [
        runner.session_service.created_states[0][SessionKeys.MEMORY_SCOPE_ID]
        for runner in fake_runner_factory.runners
    ]
    assert len(set(scope_ids)) == 2

    for scope_id in scope_ids:
        assert isinstance(scope_id, str)
        scope = fake_runner_factory.memory_service.get_scope(scope_id)
        assert scope is not None
        assert scope.closed_at is not None


async def test_run_single_query_closes_scope_and_runner_on_success(
    fake_runner_factory: _FakeRunnerFactory,
) -> None:
    await run_single_query("hello", runner_factory=fake_runner_factory)

    assert fake_runner_factory.closed
    assert fake_runner_factory.runners[0].close_called
    scope_id = fake_runner_factory.runners[0].session_service.created_states[0][
        SessionKeys.MEMORY_SCOPE_ID
    ]
    assert isinstance(scope_id, str)
    scope = fake_runner_factory.memory_service.get_scope(scope_id)
    assert scope is not None
    assert scope.closed_at is not None


async def test_run_single_query_closes_scope_and_runner_on_provider_error(
    fake_runner_factory: _FakeRunnerFactory,
) -> None:
    fake_runner_factory.failure = RuntimeError("provider exploded")

    with pytest.raises(RuntimeError, match="provider exploded"):
        await run_single_query("hello", runner_factory=fake_runner_factory)

    assert fake_runner_factory.closed
    assert fake_runner_factory.runners[0].close_called
    scope_id = fake_runner_factory.runners[0].session_service.created_states[0][
        SessionKeys.MEMORY_SCOPE_ID
    ]
    assert isinstance(scope_id, str)
    scope = fake_runner_factory.memory_service.get_scope(scope_id)
    assert scope is not None
    assert scope.closed_at is not None


async def test_run_single_query_closes_scope_when_runner_construction_fails() -> None:
    class _RaisingConstructionFactory:
        """A :class:`~arema.runner.RunnerFactory` double whose ``__call__`` raises.

        Models a real provider-error path: the memory scope has already been
        opened via ``memory_service`` before the runner itself is built, so a
        construction failure must still close that scope.
        """

        def __init__(self) -> None:
            self.memory_service = _RecordingMemoryService()

        def __call__(self) -> NoReturn:
            raise RuntimeError("provider unavailable during construction")

    factory = _RaisingConstructionFactory()

    with pytest.raises(RuntimeError, match="provider unavailable during construction"):
        await run_single_query("hello", runner_factory=factory)

    assert len(factory.memory_service.created_scopes) == 1
    scope_id = factory.memory_service.created_scopes[0].id
    closed_scope = factory.memory_service.get_scope(scope_id)
    assert closed_scope is not None
    assert closed_scope.closed_at is not None


async def test_run_single_query_closes_scope_and_runner_on_session_creation_error() -> None:
    class _RaisingSessionService(_FakeSessionService):
        async def create_session(
            self,
            *,
            app_name: str,
            user_id: str,
            state: dict[str, object] | None = None,
        ) -> _FakeSession:
            del app_name, user_id, state
            raise RuntimeError("session backend unavailable")

    class _RaisingRunner(_FakeRunner):
        def __init__(self, factory: _FakeRunnerFactory) -> None:
            super().__init__(factory)
            self.session_service = _RaisingSessionService()

    class _RaisingRunnerFactory(_FakeRunnerFactory):
        def __call__(self) -> _FakeRunner:
            self.created += 1
            runner = _RaisingRunner(self)
            self.runners.append(runner)
            return runner

    factory = _RaisingRunnerFactory()

    with pytest.raises(RuntimeError, match="session backend unavailable"):
        await run_single_query("hello", runner_factory=factory)

    assert factory.closed
    assert factory.runners[0].close_called


# ---------------------------------------------------------------------------
# Logging discipline
# ---------------------------------------------------------------------------


async def test_run_single_query_logs_length_never_contents(
    monkeypatch: pytest.MonkeyPatch,
    fake_runner_factory: _FakeRunnerFactory,
) -> None:
    recording_logger = _RecordingLogger()
    monkeypatch.setattr(runner_module, "logger", recording_logger)
    secret_query = "super-secret-query-content-not-for-logs"

    await run_single_query(secret_query, runner_factory=fake_runner_factory)

    assert recording_logger.calls
    for _, _, kwargs in recording_logger.calls:
        if "query_length" in kwargs:
            assert kwargs["query_length"] == len(secret_query)
        for value in kwargs.values():
            assert secret_query not in str(value)


# ---------------------------------------------------------------------------
# Default factory wiring
# ---------------------------------------------------------------------------


def test_default_runner_factory_is_the_production_singleton() -> None:
    assert isinstance(runner_module._default_runner_factory, runner_module._DefaultRunnerFactory)
