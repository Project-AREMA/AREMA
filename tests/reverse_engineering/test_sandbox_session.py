"""The shared sandbox-session lifecycle: claim + verify + re-claim, scoped release."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from arema.runtime.sandbox.port import SandboxHandle
from arema.runtime.sessions import SessionKeys
from reverse_engineering.runtime import sandbox_session as ss


class _FakeExecutor:
    """Records claim / terminate / release_session; hands out a fresh pod per claim."""

    def __init__(self, pods: list[str]) -> None:
        self._pods = pods
        self.claimed: list[tuple[str, str]] = []
        self.terminated: list[tuple[str, str]] = []
        self.released: list[str] = []

    def claim(self, *, key: str, pool: str) -> SandboxHandle:
        pod = self._pods[len(self.claimed)]
        self.claimed.append((key, pool))
        return SandboxHandle(key=key, pool=pool, backend_id=pod)

    def terminate(self, handle: SandboxHandle) -> None:
        self.terminated.append((handle.key, handle.pool))

    def release_session(self, key: str) -> None:
        self.released.append(key)


class _RecordingRegistry:
    def __init__(self) -> None:
        self.closed: list[str] = []

    def close(self, case_id: str) -> None:
        self.closed.append(case_id)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch) -> None:
    ss._SESSIONS.clear()
    monkeypatch.setattr(ss.time, "sleep", lambda _s: None)
    monkeypatch.setattr(ss, "default_registry", lambda: _RecordingRegistry())
    yield
    ss._SESSIONS.clear()


def test_provision_happy_path_registers_the_session_and_returns_the_result() -> None:
    ex = _FakeExecutor(["pod-1"])
    result = ss.provision_pod(
        executor=ex,
        case_id="c1",
        pool="radare2-mcp",
        namespace="ns",
        provision=lambda pod: {"pod": pod, "ok": True},
    )
    assert result == {"pod": "pod-1", "ok": True}
    assert ex.claimed == [("c1", "radare2-mcp")]
    assert ex.terminated == []  # no failure -> no scoped release
    assert ss.released_pools("c1") == frozenset({"radare2-mcp"})


def test_provision_reclaims_a_fresh_pod_when_the_first_is_unusable() -> None:
    ex = _FakeExecutor(["pod-1", "pod-2"])
    seen: list[str] = []

    def _provision(pod: str) -> str:
        seen.append(pod)
        if pod == "pod-1":
            raise RuntimeError("file not present in sandbox")
        return pod

    result = ss.provision_pod(
        executor=ex, case_id="c1", pool="radare2-mcp", namespace="ns", provision=_provision
    )
    assert result == "pod-2"
    assert seen == ["pod-1", "pod-2"]
    assert ex.claimed == [("c1", "radare2-mcp"), ("c1", "radare2-mcp")]
    # The bad pod was released SCOPED, per-pool (terminate), never the whole case.
    assert ex.terminated == [("c1", "radare2-mcp")]
    assert ex.released == []  # no per-case release_session during the retry
    assert ss.released_pools("c1") == frozenset({"radare2-mcp"})  # the good pod is tracked


def test_provision_raises_after_exhausting_attempts_and_leaves_nothing_registered() -> None:
    ex = _FakeExecutor([f"pod-{i}" for i in range(ss.RETRY_ATTEMPTS)])

    def _always_fail(_pod: str) -> str:
        raise RuntimeError("pod recycled")

    with pytest.raises(RuntimeError, match="pod recycled"):
        ss.provision_pod(
            executor=ex, case_id="c1", pool="ghidra-rpc", namespace="ns", provision=_always_fail
        )
    assert len(ex.claimed) == ss.RETRY_ATTEMPTS
    assert ex.terminated == [("c1", "ghidra-rpc")] * ss.RETRY_ATTEMPTS  # each scoped-released
    assert ss.released_pools("c1") == frozenset()  # nothing left registered


def test_scoped_retry_release_does_not_disturb_the_cases_other_pool() -> None:
    ex = _FakeExecutor(["r2-pod", "ilspy-bad", "ilspy-good"])
    ss.provision_pod(
        executor=ex, case_id="c1", pool="radare2-mcp", namespace="ns", provision=lambda p: p
    )

    def _ilspy(pod: str) -> str:
        if pod == "ilspy-bad":
            raise RuntimeError("recycled")
        return pod

    ss.provision_pod(executor=ex, case_id="c1", pool="ilspy-mcp", namespace="ns", provision=_ilspy)
    # Only the ilspy pod was terminated on retry; radare2 stays claimed for the case.
    assert ex.terminated == [("c1", "ilspy-mcp")]
    assert ss.released_pools("c1") == frozenset({"radare2-mcp", "ilspy-mcp"})


def test_release_case_runs_hooks_closes_forward_and_releases_scoped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = _RecordingRegistry()
    monkeypatch.setattr(ss, "default_registry", lambda: registry)
    ex = _FakeExecutor(["pod-1"])
    hook_calls: list[tuple[str, str]] = []
    ss.provision_pod(
        executor=ex,
        case_id="c1",
        pool="ghidra-rpc",
        namespace="ns",
        provision=lambda p: p,
        on_release=lambda ns, pod: hook_calls.append((ns, pod)),
    )

    ss.release_case("c1")

    assert hook_calls == [("ns", "pod-1")]  # daemon-stop-style cleanup ran
    assert registry.closed == ["c1"]  # port-forward closed
    assert ex.released == ["c1"]  # scoped per-case release
    assert ss.released_pools("c1") == frozenset()  # untracked


def test_release_case_only_touches_its_own_case() -> None:
    a = _FakeExecutor(["a-pod"])
    b = _FakeExecutor(["b-pod"])
    ss.provision_pod(
        executor=a, case_id="A", pool="radare2-mcp", namespace="ns", provision=lambda p: p
    )
    ss.provision_pod(
        executor=b, case_id="B", pool="radare2-mcp", namespace="ns", provision=lambda p: p
    )

    ss.release_case("A")

    assert a.released == ["A"]
    assert b.released == []  # the other in-flight analysis is untouched
    assert ss.released_pools("B") == frozenset({"radare2-mcp"})


def test_release_session_retries_transient_tunnel_errors_then_gives_up_leaking() -> None:
    import ssl

    calls = {"n": 0}

    class _FlakyExecutor:
        def claim(self, *, key: str, pool: str) -> SandboxHandle:
            return SandboxHandle(key=key, pool=pool, backend_id="pod")

        def release_session(self, key: str) -> None:  # noqa: ARG002
            calls["n"] += 1
            raise ssl.SSLError("tunnel torn down")

    ex = _FlakyExecutor()
    ss.provision_pod(
        executor=ex, case_id="c1", pool="radare2-mcp", namespace="ns", provision=lambda p: p
    )  # type: ignore[arg-type]

    ss.release_case("c1")  # must not raise (fail-open); leaks rather than nuking others

    assert calls["n"] == ss.RETRY_ATTEMPTS  # SSLError is OSError -> retried, never a --all fallback


def test_release_session_does_not_retry_a_non_transient_error() -> None:
    calls = {"n": 0}

    class _BrokenExecutor:
        def claim(self, *, key: str, pool: str) -> SandboxHandle:
            return SandboxHandle(key=key, pool=pool, backend_id="pod")

        def release_session(self, key: str) -> None:  # noqa: ARG002
            calls["n"] += 1
            raise RuntimeError("unexpected")

    ex = _BrokenExecutor()
    ss.provision_pod(
        executor=ex, case_id="c1", pool="radare2-mcp", namespace="ns", provision=lambda p: p
    )  # type: ignore[arg-type]

    ss.release_case("c1")  # must not raise

    assert calls["n"] == 1  # non-transient: no retry


# --- pipeline-end release -----------------------------------------------------


def test_release_at_pipeline_end_releases_the_run_case(monkeypatch: pytest.MonkeyPatch) -> None:
    """Releasing here is the only point the executor's OWN client can do it: the
    atexit sweep runs at interpreter shutdown, after the kubernetes client has
    dropped its transport, so every release failed over to `kubectl delete`."""
    released: list[str] = []
    monkeypatch.setattr(ss, "release_case", released.append)

    ss.release_case_at_pipeline_end(SimpleNamespace(state={SessionKeys.SANDBOX_CASE_ID: "case-1"}))

    assert released == ["case-1"]


@pytest.mark.parametrize(
    "state",
    [{}, {SessionKeys.SANDBOX_CASE_ID: ""}, {SessionKeys.SANDBOX_CASE_ID: "  "}, {"other": "x"}],
)
def test_release_at_pipeline_end_is_a_noop_without_a_case(
    monkeypatch: pytest.MonkeyPatch, state: dict[str, str]
) -> None:
    """A run that claimed nothing never wrote the key."""
    released: list[str] = []
    monkeypatch.setattr(ss, "release_case", released.append)

    ss.release_case_at_pipeline_end(SimpleNamespace(state=state))

    assert released == []


def test_release_at_pipeline_end_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """Teardown must fail open: the atexit sweep is still there to catch the case."""

    class _HostileState:
        def get(self, *_args: object, **_kwargs: object) -> str:
            raise RuntimeError("state exploded")

    monkeypatch.setattr(ss, "release_case", lambda _case: None)

    ss.release_case_at_pipeline_end(SimpleNamespace(state=_HostileState()))


def test_the_pipeline_root_releases_at_its_end() -> None:
    """The wiring, not just the callback: a root without it silently regresses to
    the atexit path, where the primary release can never succeed."""
    from malware_analyst.agents.malware_analyst import MALWARE_ANALYST_DESCRIPTOR

    assert ss.release_case_at_pipeline_end in (MALWARE_ANALYST_DESCRIPTOR.after_agent_callbacks)
