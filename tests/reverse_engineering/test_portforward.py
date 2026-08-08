"""Tests for the kubectl port-forward lifecycle registry and kubectl cp helper.

No real ``kubectl`` is ever invoked: ``subprocess.Popen`` and ``subprocess.run``
are monkeypatched on the portforward module before each exercise.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

import pytest

from reverse_engineering.runtime import portforward

if TYPE_CHECKING:
    from collections.abc import Sequence

# The autouse fixture below stubs ``_wait_for_port_ready`` for every test, so the
# two that exercise the real probe capture it here, before any patching.
_REAL_WAIT = portforward._wait_for_port_ready


class _FakePopen:
    """A minimal stand-in for ``subprocess.Popen`` used by the registry."""

    instances: ClassVar[list[_FakePopen]] = []

    def __init__(self, args: Sequence[str], **_kwargs: Any) -> None:
        self.args = list(args)
        self.terminated = False
        self.waited = False
        type(self).instances.append(self)

    def poll(self) -> int | None:
        return -15 if self.terminated else None

    def terminate(self) -> None:
        self.terminated = True

    def wait(self, timeout: float | None = None) -> int:  # noqa: ARG002
        self.waited = True
        return -15


@pytest.fixture(autouse=True)
def _reset_fake_popen(monkeypatch: pytest.MonkeyPatch) -> Any:
    _FakePopen.instances.clear()
    # The readiness check does a real HTTP request; patch it out for tests. It
    # takes a keyword-only ``attempts``, so the stub must accept it -- the reuse
    # path passes ``attempts=1`` and a two-positional stub would raise there.
    monkeypatch.setattr(portforward, "_wait_for_port_ready", lambda _port, _popen, **_kwargs: True)
    yield
    _FakePopen.instances.clear()


class _FakeCompletedProcess:
    def __init__(self, args: Sequence[str], returncode: int) -> None:
        self.args = list(args)
        self.returncode = returncode
        self.stdout = b""
        self.stderr = b""


def test_open_invokes_kubectl_port_forward_with_correct_args(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(portforward.subprocess, "Popen", _FakePopen)
    registry = portforward.PortForwardRegistry()

    registry.open(case_id="case-1", namespace="ns", pod="pod-a", port=8765)

    assert len(_FakePopen.instances) == 1
    args = _FakePopen.instances[0].args
    assert args == [
        "kubectl",
        "port-forward",
        "pod/pod-a",
        "-n",
        "ns",
        "8765:8765",
    ]


def test_open_is_idempotent_for_same_case(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(portforward.subprocess, "Popen", _FakePopen)
    registry = portforward.PortForwardRegistry()

    registry.open(case_id="case-1", namespace="ns", pod="pod-a", port=8765)
    registry.open(case_id="case-1", namespace="ns", pod="pod-a", port=8765)

    assert len(_FakePopen.instances) == 1


def test_open_distinct_cases_open_distinct_processes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(portforward.subprocess, "Popen", _FakePopen)
    registry = portforward.PortForwardRegistry()

    registry.open(case_id="case-1", namespace="ns", pod="pod-a", port=8765)
    registry.open(case_id="case-2", namespace="ns", pod="pod-b", port=8765)

    assert len(_FakePopen.instances) == 2


def test_two_ports_under_one_case_open_distinct_forwards(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two MCP engines (radare2:8765, ILSpy:3001) coexist under one case: the
    second port must open its own tunnel, not be swallowed as a duplicate."""
    monkeypatch.setattr(portforward.subprocess, "Popen", _FakePopen)
    registry = portforward.PortForwardRegistry()

    registry.open(case_id="case-1", namespace="ns", pod="pod-a", port=8765)
    registry.open(case_id="case-1", namespace="ns", pod="pod-a", port=3001)

    assert len(_FakePopen.instances) == 2


def test_close_drops_every_forward_the_case_holds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(portforward.subprocess, "Popen", _FakePopen)
    registry = portforward.PortForwardRegistry()
    registry.open(case_id="case-1", namespace="ns", pod="pod-a", port=8765)
    registry.open(case_id="case-1", namespace="ns", pod="pod-a", port=3001)

    registry.close("case-1")

    assert all(popen.terminated for popen in _FakePopen.instances)
    assert not registry.has("case-1")


def test_has_reflects_membership(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(portforward.subprocess, "Popen", _FakePopen)
    registry = portforward.PortForwardRegistry()

    assert not registry.has("case-1")
    registry.open(case_id="case-1", namespace="ns", pod="pod-a", port=8765)
    assert registry.has("case-1")


def test_close_terminates_running_forward(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(portforward.subprocess, "Popen", _FakePopen)
    registry = portforward.PortForwardRegistry()
    registry.open(case_id="case-1", namespace="ns", pod="pod-a", port=8765)
    popen = _FakePopen.instances[0]

    registry.close("case-1")

    assert popen.terminated
    assert popen.waited
    assert not registry.has("case-1")


def test_close_is_noop_for_unknown_case(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(portforward.subprocess, "Popen", _FakePopen)
    registry = portforward.PortForwardRegistry()

    registry.close("never-claimed")


def test_close_all_closes_every_registered_case(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(portforward.subprocess, "Popen", _FakePopen)
    registry = portforward.PortForwardRegistry()
    registry.open(case_id="case-1", namespace="ns", pod="pod-a", port=8765)
    registry.open(case_id="case-2", namespace="ns", pod="pod-b", port=8765)

    registry.close_all()

    assert all(p.terminated for p in _FakePopen.instances)
    assert not registry.has("case-1")
    assert not registry.has("case-2")


def test_default_registry_is_lazy_singleton() -> None:
    first = portforward.default_registry()
    second = portforward.default_registry()
    assert first is second


def test_kubectl_cp_invokes_subprocess_run_with_correct_args(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def _fake_run(args: Sequence[str], **_kwargs: Any) -> _FakeCompletedProcess:
        captured["args"] = list(args)
        return _FakeCompletedProcess(args, returncode=0)

    monkeypatch.setattr(portforward.subprocess, "run", _fake_run)

    portforward.kubectl_cp("/local/x", "ns", "pod-a", "/app/abc")

    assert captured["args"][0] == "kubectl"
    assert captured["args"][1] == "cp"
    assert captured["args"][2] == "/local/x"
    assert captured["args"][3] == "ns/pod-a:/app/abc"


def test_kubectl_cp_raises_on_nonzero_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _fake_run(args: Sequence[str], **_kwargs: Any) -> _FakeCompletedProcess:
        return _FakeCompletedProcess(args, returncode=1)

    monkeypatch.setattr(portforward.subprocess, "run", _fake_run)

    with pytest.raises(RuntimeError, match="kubectl cp failed"):
        portforward.kubectl_cp("/local/x", "ns", "pod-a", "/app/abc")


def test_kubectl_exec_accepts_declared_nonzero_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import subprocess

    def _fake_run(cmd: Sequence[str], **_kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(list(cmd), returncode=1, stdout=b"partial", stderr=b"")

    monkeypatch.setattr(portforward.subprocess, "run", _fake_run)

    # exit 1 tolerated when declared:
    assert portforward.kubectl_exec(["jadx"], "ns", "pod", ok_exit_codes=(0, 1)) == "partial"


def test_kubectl_exec_still_raises_on_undeclared_nonzero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import subprocess

    monkeypatch.setattr(
        portforward.subprocess,
        "run",
        lambda cmd, **_kw: subprocess.CompletedProcess(list(cmd), 2, b"", b"boom"),
    )

    with pytest.raises(RuntimeError):
        portforward.kubectl_exec(["x"], "ns", "pod")  # default ok_exit_codes=(0,)


def test_close_escalates_to_kill_on_timeoutexpired(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[Any] = []

    class _EscalatingPopen:
        def __init__(self, args: Sequence[str], **_kwargs: Any) -> None:
            self.args = list(args)
            self.terminated = False
            self.killed = False
            self._wait_calls = 0
            created.append(self)

        def poll(self) -> int | None:
            return None

        def terminate(self) -> None:
            self.terminated = True

        def kill(self) -> None:
            self.killed = True

        def wait(self, timeout: float | None = None) -> int:
            self._wait_calls += 1
            if self._wait_calls == 1:
                raise portforward.subprocess.TimeoutExpired(cmd=self.args, timeout=timeout)
            return -9

    monkeypatch.setattr(portforward.subprocess, "Popen", _EscalatingPopen)
    registry = portforward.PortForwardRegistry()
    registry.open(case_id="case-1", namespace="ns", pod="pod-a", port=8765)
    popen = created[0]

    registry.close("case-1")

    assert popen.terminated
    assert popen.killed
    assert not registry.has("case-1")


# --- pod identity + diagnostics ----------------------------------------------
#
# A forward is identified by its pod, not only by (case, port): sandbox_session
# terminates a pod and re-claims a fresh one whenever provisioning fails, and an
# optional MCP server degrades to ZERO tools rather than raising, so a tunnel left
# pointing at the destroyed pod removes the engine from the agent with no signal.


def test_reopen_with_a_different_pod_replaces_the_tunnel(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(portforward.subprocess, "Popen", _FakePopen)
    registry = portforward.PortForwardRegistry()

    registry.open(case_id="case-1", namespace="ns", pod="pod-a", port=3001)
    registry.open(case_id="case-1", namespace="ns", pod="pod-b", port=3001)

    assert len(_FakePopen.instances) == 2, "the re-claimed pod must get its own tunnel"
    assert _FakePopen.instances[0].terminated, "the tunnel to the dead pod must be reaped"
    assert registry._forwards["case-1", 3001].pod == "pod-b"
    assert "pod/pod-b" in " ".join(_FakePopen.instances[1].args)


def test_reopen_with_the_same_live_pod_is_still_a_no_op(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reconciling must not mean respawning: the common repeat call is free."""
    monkeypatch.setattr(portforward.subprocess, "Popen", _FakePopen)
    registry = portforward.PortForwardRegistry()

    registry.open(case_id="case-1", namespace="ns", pod="pod-a", port=3001)
    registry.open(case_id="case-1", namespace="ns", pod="pod-a", port=3001)

    assert len(_FakePopen.instances) == 1


def test_reopen_replaces_a_forward_whose_process_died(monkeypatch: pytest.MonkeyPatch) -> None:
    """Same pod, but kubectl exited: the tunnel is gone and must be re-established."""
    monkeypatch.setattr(portforward.subprocess, "Popen", _FakePopen)
    registry = portforward.PortForwardRegistry()
    registry.open(case_id="case-1", namespace="ns", pod="pod-a", port=3001)
    _FakePopen.instances[0].terminated = True  # poll() now reports an exit code

    registry.open(case_id="case-1", namespace="ns", pod="pod-a", port=3001)

    assert len(_FakePopen.instances) == 2


def test_failed_open_reaps_the_process_and_reports_kubectl_stderr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unregistered process is invisible to close_all() and would orphan."""

    def _never_ready(_port: int, _popen: object) -> bool:
        return False

    def _popen_writing_stderr(args: Sequence[str], **kwargs: Any) -> _FakePopen:
        # Real kubectl writes straight to the inherited fd; this fake goes through
        # Python's buffer, so flush or os.fstat still reports an empty file.
        kwargs["stderr"].write(b"error: unable to forward port because pod is not running\n")
        kwargs["stderr"].flush()
        return _FakePopen(args, **kwargs)

    monkeypatch.setattr(portforward, "_wait_for_port_ready", _never_ready)
    monkeypatch.setattr(portforward.subprocess, "Popen", _popen_writing_stderr)
    registry = portforward.PortForwardRegistry()

    with pytest.raises(RuntimeError, match="pod is not running"):
        registry.open(case_id="case-1", namespace="ns", pod="pod-a", port=3001)

    assert _FakePopen.instances[0].terminated, "the failed process must not be left running"
    assert not registry.has("case-1")


def test_stderr_tail_is_bounded_and_never_raises() -> None:
    """Diagnostics must not become a payload, nor break a teardown path."""
    import tempfile

    with tempfile.TemporaryFile() as stderr:
        stderr.write(b"x" * (portforward._STDERR_TAIL_BYTES * 3))
        stderr.flush()
        handle = portforward._ForwardHandle(
            popen=_FakePopen(["kubectl"]), pod="pod-a", namespace="ns", stderr=stderr
        )
        assert len(portforward._stderr_tail(handle)) == portforward._STDERR_TAIL_BYTES

    # Closed file: still no exception, just nothing to report.
    assert portforward._stderr_tail(handle) == ""


def test_a_live_forward_that_complained_is_still_reported(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """kubectl logs per-connection faults and keeps running.

    An alive-but-useless tunnel looks identical to a healthy one from outside, and
    costs an optional MCP engine every tool with no other signal, so whatever
    kubectl wrote must be surfaced even though the process survived.
    """
    import tempfile

    monkeypatch.setattr(portforward.subprocess, "Popen", _FakePopen)
    registry = portforward.PortForwardRegistry()
    registry.open(case_id="case-1", namespace="ns", pod="pod-a", port=3001)

    handle = registry._forwards["case-1", 3001]
    # close() owns this file, exactly as it owns the real one.
    handle.stderr = tempfile.TemporaryFile()  # noqa: SIM115
    handle.stderr.write(
        b"E0802 an error occurred forwarding 3001 -> 3001: lost connection to pod\n"
    )
    handle.stderr.flush()

    registry.close("case-1")

    # structlog renders to stdout, so capsys -- not caplog -- sees the record.
    assert "lost connection to pod" in capsys.readouterr().out
    assert _FakePopen.instances[0].terminated


def test_a_clean_forward_stays_silent(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """No complaints, no noise: only a forward that wrote something is reported."""
    monkeypatch.setattr(portforward.subprocess, "Popen", _FakePopen)
    registry = portforward.PortForwardRegistry()
    registry.open(case_id="case-1", namespace="ns", pod="pod-a", port=3001)

    capsys.readouterr()  # drop the "port-forward opened" line from open()
    registry.close("case-1")

    assert capsys.readouterr().out.strip() == ""


# The autouse fixture stubs _wait_for_port_ready for every other test, so the two
# probe tests below need the real one, captured before any patching happens.
_REAL_WAIT_FOR_PORT_READY = portforward._wait_for_port_ready


def test_readiness_probe_closes_its_response(monkeypatch: pytest.MonkeyPatch) -> None:
    """An abandoned probe socket is reset on collection, and kubectl logs that
    reset in the same words a genuinely broken tunnel produces. A healthy forward
    must leave kubectl's stderr empty, so every probe closes its response."""
    closed: list[str] = []

    class _Response:
        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *_exc: object) -> None:
            closed.append("ok")

        def read(self) -> bytes:
            return b""

    monkeypatch.setattr(portforward.urllib.request, "urlopen", lambda *_a, **_k: _Response())
    assert _REAL_WAIT_FOR_PORT_READY(8765, _FakePopen(["kubectl"]))
    assert closed == ["ok"]


def test_readiness_probe_closes_an_http_error_response(monkeypatch: pytest.MonkeyPatch) -> None:
    """The MCP endpoint answers a bare GET with 406; that HTTPError IS the
    response and holds the socket, so it must be closed too."""
    closed: list[str] = []

    def _raise_406(*_a: object, **_k: object) -> None:
        error = portforward.urllib.error.HTTPError(
            url="http://127.0.0.1:8765/mcp", code=406, msg="Not Acceptable", hdrs=None, fp=None
        )
        monkeypatch.setattr(error, "close", lambda: closed.append("ok"), raising=False)
        raise error

    monkeypatch.setattr(portforward.urllib.request, "urlopen", _raise_406)
    assert _REAL_WAIT_FOR_PORT_READY(8765, _FakePopen(["kubectl"]))
    assert closed == ["ok"]


# --- a live process is not a live tunnel --------------------------------------
#
# kubectl port-forward reports per-connection faults on stderr and keeps
# running, so a dead tunnel is indistinguishable from a healthy one by poll()
# alone. Measured across recorded runs: forwards opened at 12:11:25 and the
# engines behind them were unreachable by 12:14:49, processes still alive,
# nothing reopening. Reuse used to return on `same pod + process alive`, so a
# stage calling prepare_* again to repair the tunnel got the same dead one.


def _probe(monkeypatch: pytest.MonkeyPatch, *results: bool) -> list[dict[str, Any]]:
    """Install a probe returning ``results`` in order; record every call."""
    calls: list[dict[str, Any]] = []
    answers = list(results)

    def _fake(port: int, _popen: Any, *, attempts: int = 15) -> bool:
        calls.append({"port": port, "attempts": attempts})
        return answers.pop(0) if answers else True

    monkeypatch.setattr(portforward, "_wait_for_port_ready", _fake)
    return calls


def test_a_reused_forward_is_probed_before_it_is_trusted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(portforward.subprocess, "Popen", _FakePopen)
    calls = _probe(monkeypatch, True, True)
    registry = portforward.PortForwardRegistry()

    registry.open(case_id="c", namespace="ns", pod="pod-a", port=8765)
    registry.open(case_id="c", namespace="ns", pod="pod-a", port=8765)

    # one probe when opening, one when reusing
    assert len(calls) == 2
    assert len(_FakePopen.instances) == 1  # healthy tunnel is kept


def test_the_reuse_probe_makes_one_attempt_not_fifteen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Opening waits for a tunnel to come up and keeps the full budget. Checking
    an existing one is a liveness question with an immediate answer -- retrying
    would spend fifteen seconds establishing what the first failure showed."""
    monkeypatch.setattr(portforward.subprocess, "Popen", _FakePopen)
    calls = _probe(monkeypatch, True, True)
    registry = portforward.PortForwardRegistry()

    registry.open(case_id="c", namespace="ns", pod="pod-a", port=8765)
    registry.open(case_id="c", namespace="ns", pod="pod-a", port=8765)

    assert calls[0]["attempts"] == portforward._FORWARD_READY_RETRIES
    assert calls[1]["attempts"] == 1


def test_a_dead_tunnel_on_a_live_process_is_rebuilt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The bug itself. The process is alive and the pod matches, so the old code
    returned early and handed back a tunnel that no longer forwards."""
    monkeypatch.setattr(portforward.subprocess, "Popen", _FakePopen)
    _probe(monkeypatch, True, False, True)  # open ok, reuse probe fails, rebuild ok
    registry = portforward.PortForwardRegistry()

    registry.open(case_id="c", namespace="ns", pod="pod-a", port=8765)
    first = _FakePopen.instances[0]
    registry.open(case_id="c", namespace="ns", pod="pod-a", port=8765)

    assert first.terminated, "the dead tunnel must be torn down"
    assert len(_FakePopen.instances) == 2, "a fresh tunnel must replace it"


def test_a_rebuild_after_a_failed_probe_gets_the_full_retry_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reuse probe is fast because it is a question; the rebuild that follows
    is an open and must wait for the tunnel like any other."""
    monkeypatch.setattr(portforward.subprocess, "Popen", _FakePopen)
    calls = _probe(monkeypatch, True, False, True)
    registry = portforward.PortForwardRegistry()

    registry.open(case_id="c", namespace="ns", pod="pod-a", port=8765)
    registry.open(case_id="c", namespace="ns", pod="pod-a", port=8765)

    assert [c["attempts"] for c in calls] == [
        portforward._FORWARD_READY_RETRIES,
        1,
        portforward._FORWARD_READY_RETRIES,
    ]


def test_a_failed_probe_is_reported_as_its_own_reason(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Distinguishable in the log from a replaced pod or an exited process --
    a probe failure means the fix fired, and reads as success, not regression."""
    monkeypatch.setattr(portforward.subprocess, "Popen", _FakePopen)
    _probe(monkeypatch, True, False, True)
    registry = portforward.PortForwardRegistry()

    registry.open(case_id="c", namespace="ns", pod="pod-a", port=8765)
    capsys.readouterr()
    registry.open(case_id="c", namespace="ns", pod="pod-a", port=8765)

    assert "probe failed" in capsys.readouterr().out


def test_a_replaced_pod_still_reports_pod_replaced(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The pre-existing reasons must not be swallowed by the new one: a
    different pod is diagnosed as such without ever probing the old tunnel."""
    monkeypatch.setattr(portforward.subprocess, "Popen", _FakePopen)
    calls = _probe(monkeypatch, True, True)
    registry = portforward.PortForwardRegistry()

    registry.open(case_id="c", namespace="ns", pod="pod-a", port=8765)
    capsys.readouterr()
    registry.open(case_id="c", namespace="ns", pod="pod-b", port=8765)

    assert "pod replaced" in capsys.readouterr().out
    assert len(calls) == 2, "a different pod needs no probe of the old tunnel"


def test_an_exited_process_still_reports_process_exited(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(portforward.subprocess, "Popen", _FakePopen)
    _probe(monkeypatch, True, True)
    registry = portforward.PortForwardRegistry()

    registry.open(case_id="c", namespace="ns", pod="pod-a", port=8765)
    _FakePopen.instances[0].terminated = True  # process died on its own
    capsys.readouterr()
    registry.open(case_id="c", namespace="ns", pod="pod-a", port=8765)

    assert "process exited" in capsys.readouterr().out


def test_a_second_engine_on_another_port_is_untouched(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """radare2 on 8765 and ILSpy on 3001 coexist under one case; probing one
    must not disturb the other."""
    monkeypatch.setattr(portforward.subprocess, "Popen", _FakePopen)
    _probe(monkeypatch, True, True, True)
    registry = portforward.PortForwardRegistry()

    registry.open(case_id="c", namespace="ns", pod="pod-a", port=8765)
    registry.open(case_id="c", namespace="ns", pod="pod-b", port=3001)
    registry.open(case_id="c", namespace="ns", pod="pod-a", port=8765)

    assert len(_FakePopen.instances) == 2
    assert not any(p.terminated for p in _FakePopen.instances)


def test_the_probe_stops_at_the_first_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    """attempts bounds retries, not requests: one success returns immediately."""
    seen = {"n": 0}

    class _Resp:
        def __enter__(self) -> Any:
            return self

        def __exit__(self, *_a: object) -> None:
            return None

        def read(self) -> bytes:
            return b""

    def _urlopen(_url: str, timeout: float = 2) -> Any:  # noqa: ARG001
        seen["n"] += 1
        return _Resp()

    monkeypatch.setattr(portforward.urllib.request, "urlopen", _urlopen)

    assert _REAL_WAIT(8765, _FakePopen(["x"]), attempts=15)
    assert seen["n"] == 1


def test_a_probe_of_a_dead_port_is_bounded_by_attempts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reuse path must cost one failed request, not fifteen seconds of them."""
    seen = {"n": 0}

    def _refuse(_url: str, timeout: float = 2) -> Any:  # noqa: ARG001
        seen["n"] += 1
        raise ConnectionRefusedError

    monkeypatch.setattr(portforward.urllib.request, "urlopen", _refuse)
    monkeypatch.setattr(portforward.time, "sleep", lambda _s: None)

    assert not _REAL_WAIT(8765, _FakePopen(["x"]), attempts=1)
    assert seen["n"] == 1


# --- every MCP consumer can establish its own engine --------------------------


def test_every_mcp_consuming_agent_can_prepare_its_engine() -> None:
    """LESSONS_LEARNED #6, applied consistently rather than to half the agents.

    The tunnel is opened twice per run, both at intake, while four agents consume
    those two servers minutes apart. Two of them carried no prepare tool, so they
    depended on a tunnel another agent opened and had no way to repair it -- and
    when it died their whole toolset silently resolved to an empty list.
    """
    from reverse_engineering.agents.dotnet_decompile import DOTNET_DECOMPILE_DESCRIPTOR
    from reverse_engineering.agents.packer_analyst import PACKER_ANALYST_DESCRIPTOR
    from reverse_engineering.agents.retriage import RETRIAGE_DESCRIPTOR
    from reverse_engineering.agents.triage_recon import TRIAGE_RECON_DESCRIPTOR

    prepare_for = {"radare2_mcp": "prepare_sandbox", "ilspy_mcp": "prepare_ilspy"}
    consumers = (
        TRIAGE_RECON_DESCRIPTOR,
        RETRIAGE_DESCRIPTOR,
        PACKER_ANALYST_DESCRIPTOR,
        DOTNET_DECOMPILE_DESCRIPTOR,
    )
    for descriptor in consumers:
        for mcp_id in descriptor.mcp_server_ids:
            needed = prepare_for[mcp_id]
            assert needed in descriptor.tool_ids, (
                f"{descriptor.id} consumes {mcp_id} but cannot call {needed}"
            )
