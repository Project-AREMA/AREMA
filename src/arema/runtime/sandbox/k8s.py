"""A Kubernetes-backed :class:`SandboxExecutor` using k8s-agent-sandbox.

``k8s-agent-sandbox`` is an OPTIONAL dependency (the ``sandbox`` extra). It is
imported lazily: only :func:`_load_client` and
:meth:`K8sSandboxExecutor._build_connection_config` touch ``k8s_agent_sandbox``,
so importing this module -- and the rest of AREMA -- never requires the package.
Only constructing a :class:`K8sSandboxExecutor` (and claiming a sandbox) does.

Connection-mode selection matches the connection-config classes that
``k8s-agent-sandbox==0.5.2`` actually exposes: ``SandboxLocalTunnelConnectionConfig``
(kubectl port-forward; the kubeconfig-based developer path) and
``SandboxInClusterConnectionConfig`` (AREMA running inside a pod). There is no
dedicated "kubeconfig" mode -- local tunnel is that path.
``SandboxDirectConnectionConfig`` (explicit ``api_url``) and
``SandboxGatewayConnectionConfig`` (gateway service) exist in the package but are
not wired here because AREMA carries no settings for them yet; that is a follow-up.

The client/sandbox surface is typed against small structural Protocols below so
this module type-checks without forcing the package on the type-checker either.

Pool names come only from settings; this module hardcodes no domain pool.
"""

from __future__ import annotations

import os
import re
import subprocess
from typing import TYPE_CHECKING, Protocol, cast

from arema.core.logging import get_logger
from arema.runtime.sandbox.port import (
    ExecutionResult,
    SandboxError,
    SandboxExecutor,
    SandboxHandle,
)

if TYPE_CHECKING:
    from arema.core.config import Settings

logger = get_logger(__name__)

# Fully qualified so kubectl resolves the CRD unambiguously regardless of any
# other installed resource that shortens to "sandboxclaim".
_SANDBOX_CLAIM_RESOURCE = "sandboxclaim.extensions.agents.x-k8s.io"
_KUBECTL_DELETE_TIMEOUT_SECONDS = 30
_DNS_SUBDOMAIN = re.compile(r"[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?")


class _CommandResult(Protocol):
    """Read-only view of one command run's outcome."""

    exit_code: int
    stdout: str
    stderr: str


class _CommandExecutor(Protocol):
    """The ``sandbox.commands`` surface."""

    def run(self, command: str, *, timeout: int) -> _CommandResult: ...


class _Filesystem(Protocol):
    """The ``sandbox.files`` surface."""

    def write(self, path: str, data: bytes) -> None: ...

    def read(self, path: str) -> bytes: ...


class _Sandbox(Protocol):
    """One live sandbox pod as exposed by ``SandboxClient.create_sandbox``.

    ``_kubectl_delete_claim`` additionally reads ``claim_name`` and ``namespace``
    off the live object (defensively, via ``getattr``) to drive the teardown
    fallback; they are not declared here because the library leaves them unset on
    some code paths, and the fallback must degrade rather than assume them.
    """

    @property
    def commands(self) -> _CommandExecutor: ...

    @property
    def files(self) -> _Filesystem: ...

    def terminate(self) -> None: ...


class _SandboxClient(Protocol):
    """The minimal ``k8s_agent_sandbox.SandboxClient`` surface used here."""

    def create_sandbox(self, *, warmpool: str, namespace: str, **kwargs: object) -> _Sandbox: ...


def _load_client(connection_config: object) -> _SandboxClient:
    """Import the optional client and build it from a connection config.

    The import lives inside the function so the package stays optional: the
    rest of AREMA imports nothing from ``k8s_agent_sandbox``.
    """
    from k8s_agent_sandbox import SandboxClient

    return cast("_SandboxClient", SandboxClient(connection_config=connection_config))


class K8sSandboxExecutor(SandboxExecutor):
    """Claims real sandbox pods per (case key, pool) via k8s-agent-sandbox."""

    def __init__(self, *, settings: Settings) -> None:
        self._namespace = settings.sandbox_namespace
        self._default_pool = settings.sandbox_default_pool
        self._pool_map = dict(settings.sandbox_pool_map)
        self._output_cap = settings.sandbox_output_cap
        self._connection_config = self._build_connection_config(settings)
        self._client = _load_client(self._connection_config)
        # One (handle, live sandbox) per (key, pool); the handle is cached so a
        # repeat claim returns the very same object (identity-stable).
        self._entries: dict[tuple[str, str], tuple[SandboxHandle, _Sandbox]] = {}

    @staticmethod
    def _build_connection_config(settings: Settings) -> object:
        """Pick a real ``k8s_agent_sandbox`` connection config from settings.

        Local tunnel (the kubeconfig-based port-forward path) is the default and
        is also the safe fallback when not running in-cluster. In-cluster is used
        only when local tunnel is disabled AND AREMA itself runs inside a pod
        (``KUBERNETES_SERVICE_HOST`` is set).
        """
        in_cluster = bool(os.environ.get("KUBERNETES_SERVICE_HOST"))
        if settings.sandbox_local_tunnel or not in_cluster:
            from k8s_agent_sandbox.models import SandboxLocalTunnelConnectionConfig

            return SandboxLocalTunnelConnectionConfig()
        from k8s_agent_sandbox.models import SandboxInClusterConnectionConfig

        return SandboxInClusterConnectionConfig()

    def _warmpool_for(self, pool: str) -> str:
        """Resolve a logical pool name to a warmpool via settings, default fallback.

        An unmapped pool falls back to the generic default warmpool, which is
        almost always a misconfiguration for a domain tool (the claim then fails
        against a pool that does not host that tool). Surface it loudly so the
        cause is diagnosable rather than manifesting as a downstream
        "sandbox unavailable".
        """
        if pool not in self._pool_map:
            logger.warning(
                "sandbox pool not in pool map; falling back to default warmpool",
                pool=pool,
                default_warmpool=self._default_pool,
            )
        return self._pool_map.get(pool, self._default_pool)

    def claim(self, *, key: str, pool: str) -> SandboxHandle:
        cached = self._entries.get((key, pool))
        if cached is not None:
            return cached[0]
        try:
            sandbox = self._client.create_sandbox(
                warmpool=self._warmpool_for(pool),
                namespace=self._namespace,
                labels={"app.kubernetes.io/created-by": "arema"},
            )
        except Exception as exc:  # cancellation re-raises naturally (sync calls)
            raise SandboxError(f"k8s sandbox claim failed: {type(exc).__name__}: {exc}") from exc
        # ``backend_id`` is the claimed pod's name so callers (e.g. a domain
        # tool that opens a ``kubectl`` port-forward to a named sidecar) can
        # address the pod directly. k8s-agent-sandbox exposes it as
        # ``sandbox_id``; ``name``/``id()`` are fallbacks for other/fake clients.
        backend_id = (
            getattr(sandbox, "sandbox_id", None)
            or getattr(sandbox, "name", None)
            or str(id(sandbox))
        )
        handle = SandboxHandle(key=key, pool=pool, backend_id=str(backend_id))
        self._entries[(key, pool)] = (handle, sandbox)
        logger.info("k8s sandbox claimed", key=key, pool=pool, namespace=self._namespace)
        return handle

    def _sandbox_for(self, handle: SandboxHandle) -> _Sandbox:
        cached = self._entries.get((handle.key, handle.pool))
        if cached is None:
            raise SandboxError(f"no sandbox claimed for key={handle.key} pool={handle.pool}")
        return cached[1]

    def run(self, handle: SandboxHandle, command: str, *, timeout: float) -> ExecutionResult:
        sandbox = self._sandbox_for(handle)
        try:
            result = sandbox.commands.run(command, timeout=int(timeout))
        except Exception as exc:
            raise SandboxError(f"k8s sandbox run failed: {type(exc).__name__}: {exc}") from exc
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        return ExecutionResult(
            exit_code=result.exit_code,
            stdout=stdout[: self._output_cap],
            stderr=stderr[: self._output_cap],
            truncated=len(stdout) > self._output_cap or len(stderr) > self._output_cap,
        )

    def write_file(self, handle: SandboxHandle, path: str, data: bytes) -> None:
        sandbox = self._sandbox_for(handle)
        try:
            sandbox.files.write(path, data)
        except Exception as exc:
            raise SandboxError(f"k8s sandbox write failed: {type(exc).__name__}: {exc}") from exc

    def read_file(self, handle: SandboxHandle, path: str) -> bytes:
        sandbox = self._sandbox_for(handle)
        try:
            return sandbox.files.read(path)
        except Exception as exc:
            raise SandboxError(f"k8s sandbox read failed: {type(exc).__name__}: {exc}") from exc

    def terminate(self, handle: SandboxHandle) -> None:
        cached = self._entries.pop((handle.key, handle.pool), None)
        if cached is None:
            return
        sandbox = cached[1]
        try:
            sandbox.terminate()
            return
        except Exception as exc:
            # The kube client transport can be dead at interpreter exit: the
            # kubernetes client removes its TLS cert temp files in its own atexit
            # handler, which may run before AREMA's release, so the claim delete
            # fails mid-handshake with an SSL/transport error. Fall back to
            # kubectl, which carries its own transport, so the claim is actually
            # released instead of leaked. Log the error type only -- the full
            # transport traceback is noise at teardown.
            logger.warning(
                "k8s sandbox client terminate failed; falling back to kubectl",
                key=handle.key,
                pool=handle.pool,
                error_type=type(exc).__name__,
            )
        self._kubectl_delete_claim(sandbox)

    def _kubectl_delete_claim(self, sandbox: _Sandbox) -> None:
        """Release a claim via kubectl when the client transport is unavailable.

        Uses the claim identity the sandbox already holds (the library leaves it
        set when its own delete raises). Fails open: an unresolved name, a
        missing kubectl, or a nonzero exit is logged by type and swallowed so
        teardown never raises.
        """
        claim_name = getattr(sandbox, "claim_name", None)
        namespace = getattr(sandbox, "namespace", None) or self._namespace
        if (
            not isinstance(claim_name, str)
            or _DNS_SUBDOMAIN.fullmatch(claim_name) is None
            or not isinstance(namespace, str)
            or _DNS_SUBDOMAIN.fullmatch(namespace) is None
        ):
            logger.warning("kubectl claim delete fallback skipped: unresolved claim identity")
            return
        try:
            result = subprocess.run(
                [
                    "kubectl",
                    "delete",
                    _SANDBOX_CLAIM_RESOURCE,
                    claim_name,
                    "-n",
                    namespace,
                    "--ignore-not-found=true",
                    f"--timeout={_KUBECTL_DELETE_TIMEOUT_SECONDS}s",
                ],
                capture_output=True,
                timeout=_KUBECTL_DELETE_TIMEOUT_SECONDS + 5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            logger.warning("kubectl claim delete fallback failed", error_type=type(exc).__name__)
            return
        if result.returncode != 0:
            logger.warning(
                "kubectl claim delete fallback returned nonzero", returncode=result.returncode
            )
            return
        logger.info("released sandbox claim via kubectl fallback", claim=claim_name)

    def release_session(self, key: str) -> None:
        for identity in [i for i in self._entries if i[0] == key]:
            self.terminate(SandboxHandle(key=identity[0], pool=identity[1], backend_id=""))

    def release_all(self) -> None:
        for identity in list(self._entries):
            self.terminate(SandboxHandle(key=identity[0], pool=identity[1], backend_id=""))
