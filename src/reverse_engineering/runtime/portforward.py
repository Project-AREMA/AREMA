"""kubectl port-forward lifecycle registry and ``kubectl cp`` transfer helper.

The registry owns one long-lived ``kubectl port-forward`` process per
``(case, port)`` so each in-pod MCP server is reachable on its own fixed localhost
port (radare2 on 8765, ILSpy on 3001) even when both run under one case. Both the
port-forward spawn and the ``kubectl cp`` file transfer are thin wrappers around
:mod:`subprocess`; tests monkeypatch ``subprocess.Popen`` / ``subprocess.run``
on this module rather than invoking real ``kubectl``.

**A forward is identified by its pod, not only by ``(case, port)``.** Engines are
claimed through :mod:`sandbox_session`, which terminates a pod and re-claims a
fresh one whenever provisioning fails. A registry that treated any second ``open``
for the same ``(case, port)`` as a no-op would keep pointing at the pod it just
destroyed, and because an optional MCP server degrades to *zero tools* rather than
raising, the engine would vanish from the agent with nothing logged. ``open``
therefore reconciles: same pod and a live process is a no-op; anything else
replaces the tunnel. Every engine added later inherits this.

**Diagnostics are captured, not discarded.** ``kubectl`` explains why a forward
never came up or later died, on stderr. That stream is kept in a temp file per
process (never a pipe -- nothing drains a pipe for a process that lives as long as
the run, so it would eventually block) and its tail is attached to the failure
that made it interesting. Reads use ``os.pread`` so the parent never disturbs the
write offset the child is still using.
"""

from __future__ import annotations

import atexit
import contextlib
import os
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import IO

from arema.core.logging import get_logger

logger = get_logger(__name__)

_TERMINATE_TIMEOUT_SECONDS = 10.0
_FORWARD_READY_RETRIES = 15
_FORWARD_READY_DELAY = 1.0
# Enough for kubectl's "an error occurred forwarding" / "lost connection to pod"
# lines without letting a chatty process turn a log line into a payload.
_STDERR_TAIL_BYTES = 2_000


@dataclass(slots=True)
class _ForwardHandle:
    popen: subprocess.Popen[bytes]
    pod: str
    namespace: str
    stderr: IO[bytes]


def _stderr_tail(handle: _ForwardHandle) -> str:
    """Return the tail of kubectl's stderr, or ``""`` when there is nothing to say.

    ``os.pread`` reads at an absolute offset without moving the file position, so
    this is safe to call while the child is still writing. Diagnostics must never
    be the reason a teardown path raises, so every failure degrades to ``""``.
    """
    try:
        fd = handle.stderr.fileno()
        size = os.fstat(fd).st_size
        if not size:
            return ""
        offset = max(0, size - _STDERR_TAIL_BYTES)
        return os.pread(fd, size - offset, offset).decode(errors="replace").strip()
    except Exception:
        return ""


def _wait_for_port_ready(
    port: int,
    popen: subprocess.Popen[bytes],
    *,
    attempts: int = _FORWARD_READY_RETRIES,
) -> bool:
    """Wait until the MCP server at localhost:<port> responds to HTTP requests.

    ``attempts`` separates the two callers. Opening a tunnel means waiting for
    one to come up, so it keeps the full budget. Checking an existing tunnel is a
    liveness question with an immediate answer, and retrying it would spend
    fifteen seconds establishing what the first failure already showed.

    A TCP connect only proves the port is open — the MCP StreamableHTTP server
    may accept TCP connections before it is ready to handle the initialize
    handshake. This check sends an HTTP GET and treats ANY HTTP response
    (including 400/405/406 error codes) as proof the application layer is up.

    Each probe drains and closes its response. An abandoned socket is reset when
    it is finally collected, and kubectl logs that reset as
    ``error copying from local connection to remote stream: ... connection reset by
    peer`` -- indistinguishable, after the fact, from a tunnel genuinely breaking
    mid-run. Closing cleanly keeps kubectl's stderr empty for a healthy forward, so
    anything found there later is real.
    """
    url = f"http://127.0.0.1:{port}/mcp"
    for _ in range(max(1, attempts)):
        if popen.poll() is not None:
            return False
        try:
            with urllib.request.urlopen(url, timeout=2) as response:  # noqa: S310 - localhost
                response.read()
            return True
        except urllib.error.HTTPError as error:
            # An HTTPError IS the response object; closing it returns the socket
            # instead of leaving it to be reset on collection.
            error.close()
            return True
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(_FORWARD_READY_DELAY)
    return False


class PortForwardRegistry:
    """Owns the long-lived ``kubectl port-forward`` processes, one per ``(case, port)``."""

    def __init__(self) -> None:
        self._forwards: dict[tuple[str, int], _ForwardHandle] = {}

    def open(self, *, case_id: str, namespace: str, pod: str, port: int) -> None:
        """Start a port-forward for ``(case_id, port)`` and block until it forwards.

        Reconciling, not blindly idempotent: an existing forward for this
        ``(case, port)`` is reused only when it points at the SAME pod, its
        process is still alive, **and it still answers**. A different pod (the
        caller re-claimed after a failed provision, and the old pod has been
        terminated), a dead process, or a live process whose tunnel no longer
        forwards all replace it instead of silently keeping a broken one. A
        *different* port for the same case opens its own tunnel, so two MCP
        engines (radare2 on 8765, ILSpy on 3001) coexist under one case.

        The probe is what makes a caller's retry mean anything. Without it this
        method returned early on ``same pod + process alive``, so a stage calling
        ``prepare_*`` again to repair a dead tunnel got an immediate ``return``
        and the same dead tunnel -- while the docstring promised to block until
        it forwards.

        Raises :class:`RuntimeError`, with kubectl's own stderr tail when it wrote
        one, if the tunnel fails to establish.
        """
        existing = self._forwards.get((case_id, port))
        if existing is not None:
            exit_code = existing.popen.poll()
            same_pod = existing.pod == pod
            alive = exit_code is None
            # A live process is not a live tunnel. kubectl reports per-connection
            # faults on stderr and keeps running, so a dead tunnel looks exactly
            # like a healthy one from the outside -- which is why this probes
            # rather than trusting poll(). Measured: forwards opened at 12:11:25
            # and the engines behind them were unreachable by 12:14:49 with the
            # processes still running and nothing reopening them.
            usable = same_pod and alive and _wait_for_port_ready(port, existing.popen, attempts=1)
            if usable:
                return
            logger.warning(
                "replacing a stale port-forward",
                case_id=case_id,
                port=port,
                previous_pod=existing.pod,
                pod=pod,
                reason=(
                    "pod replaced"
                    if not same_pod
                    else "process exited"
                    if not alive
                    else "probe failed"
                ),
                exit_code=exit_code,
                kubectl_stderr=_stderr_tail(existing),
            )
            self._terminate((case_id, port))

        # Deliberately not a context manager: this file outlives the call and is
        # closed with the process it belongs to, in _terminate_handle.
        stderr: IO[bytes] = tempfile.TemporaryFile()  # noqa: SIM115
        popen = subprocess.Popen(
            [
                "kubectl",
                "port-forward",
                f"pod/{pod}",
                "-n",
                namespace,
                f"{port}:{port}",
            ],
            stdout=subprocess.DEVNULL,
            stderr=stderr,
        )
        handle = _ForwardHandle(popen=popen, pod=pod, namespace=namespace, stderr=stderr)
        if not _wait_for_port_ready(port, popen):
            # Reap the process before raising: an unregistered one is invisible to
            # close()/close_all() and would outlive the run as an orphan.
            detail = _stderr_tail(handle)
            self._terminate_handle(handle, case_id=case_id, port=port)
            raise RuntimeError(
                f"port-forward to pod/{pod} -n {namespace} :{port} failed to establish "
                f"after {_FORWARD_READY_RETRIES * _FORWARD_READY_DELAY:.0f}s"
                + (f": {detail}" if detail else "")
            )
        self._forwards[case_id, port] = handle
        logger.info(
            "port-forward opened",
            case_id=case_id,
            pod=pod,
            namespace=namespace,
            port=port,
        )

    def close(self, case_id: str) -> None:
        """Terminate every port-forward held by ``case_id``; swallow errors."""
        for key in [key for key in self._forwards if key[0] == case_id]:
            self._terminate(key)

    def close_all(self) -> None:
        """Terminate every registered port-forward."""
        for key in list(self._forwards):
            self._terminate(key)

    def has(self, case_id: str) -> bool:
        """Return whether ``case_id`` currently has any active port-forward."""
        return any(key[0] == case_id for key in self._forwards)

    def _terminate(self, key: tuple[str, int]) -> None:
        """Terminate and drop one ``(case, port)`` forward, swallowing errors."""
        handle = self._forwards.pop(key, None)
        if handle is None:
            return
        self._terminate_handle(handle, case_id=key[0], port=key[1])

    def _terminate_handle(self, handle: _ForwardHandle, *, case_id: str, port: int) -> None:
        """Reap one forward's process and its stderr capture; never raises.

        Two failures are worth surfacing here, and only one of them kills the
        process. A forward that has ALREADY exited died on its own. But
        ``kubectl port-forward`` also reports *per-connection* faults ("an error
        occurred forwarding", "error copying from remote stream to local
        connection") and **keeps running** -- so a tunnel can be alive and useless,
        which looks identical to a healthy one from the outside. Either way the
        engine's tools silently vanish, because an optional MCP server degrades to
        an empty tool list rather than raising.

        So anything kubectl wrote is reported, whether or not the process survived;
        a clean forward writes nothing and stays silent.
        """
        try:
            exit_code = handle.popen.poll()
            complaints = _stderr_tail(handle)
            if exit_code is not None:
                logger.warning(
                    "port-forward had already exited on its own",
                    case_id=case_id,
                    port=port,
                    pod=handle.pod,
                    exit_code=exit_code,
                    kubectl_stderr=complaints,
                )
            else:
                if complaints:
                    logger.warning(
                        "port-forward reported errors while still running; "
                        "the tunnel may have been serving nothing",
                        case_id=case_id,
                        port=port,
                        pod=handle.pod,
                        kubectl_stderr=complaints,
                    )
                handle.popen.terminate()
                try:
                    handle.popen.wait(timeout=_TERMINATE_TIMEOUT_SECONDS)
                except subprocess.TimeoutExpired:
                    handle.popen.kill()
                    handle.popen.wait(timeout=_TERMINATE_TIMEOUT_SECONDS)
        except Exception as exc:
            logger.warning(
                "port-forward terminate failed - swallowed",
                error_type=type(exc).__name__,
                case_id=case_id,
                port=port,
                pod=handle.pod,
                exc_info=True,
            )
        finally:
            # Releases the temp file; already-closed or already-unlinked is fine.
            with contextlib.suppress(Exception):
                handle.stderr.close()


_default_registry: PortForwardRegistry | None = None


def default_registry() -> PortForwardRegistry:
    """Return the process-wide :class:`PortForwardRegistry`, creating it lazily."""
    global _default_registry
    if _default_registry is None:
        _default_registry = PortForwardRegistry()
    return _default_registry


def kubectl_cp(src: str, namespace: str, pod: str, dest: str) -> None:
    """Copy ``src`` into the pod at ``namespace/pod:dest`` via ``kubectl cp``.

    Raises :class:`RuntimeError` on a nonzero exit or timeout so the fail-open
    caller can surface a clear message without a raw ``CalledProcessError`` /
    ``TimeoutExpired`` leaking out.
    """
    try:
        result = subprocess.run(
            [
                "kubectl",
                "cp",
                src,
                f"{namespace}/{pod}:{dest}",
            ],
            capture_output=True,
            check=False,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("kubectl cp failed: timed out after 120s") from None
    if result.returncode != 0:
        stderr = result.stderr.decode(errors="replace").strip()
        raise RuntimeError(f"kubectl cp failed (exit {result.returncode}): {stderr}")


def kubectl_exec(
    args: list[str],
    namespace: str,
    pod: str,
    *,
    timeout: int = 300,
    ok_exit_codes: tuple[int, ...] = (0,),
) -> str:
    """Run a command inside the pod at ``namespace/pod`` via ``kubectl exec`` (no shell).

    *args* is the tokenized command (e.g. ``["ghidra-rpc", "decompile", binary, func]``).
    No ``sh -c`` — arguments are passed directly to the pod's process, preventing
    shell injection from agent-controlled values. Returns stdout; raises
    :class:`RuntimeError` on timeout or on an exit code not in *ok_exit_codes*.

    *ok_exit_codes* declares which exit codes are tolerated (default ``(0,)``).
    Some tools signal partial-but-usable results with a nonzero code — jadx exits
    ``1`` on a partial decompile, ``grep`` exits ``1`` on no match — so callers
    that expect those pass e.g. ``ok_exit_codes=(0, 1)``.
    """
    try:
        result = subprocess.run(
            [
                "kubectl",
                "exec",
                f"pod/{pod}",
                "-n",
                namespace,
                "--",
                *args,
            ],
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"kubectl exec failed: timed out after {timeout}s") from None
    if result.returncode not in ok_exit_codes:
        stderr = result.stderr.decode(errors="replace").strip()
        raise RuntimeError(f"kubectl exec failed (exit {result.returncode}): {stderr}")
    return result.stdout.decode(errors="replace")


atexit.register(lambda: default_registry().close_all())
