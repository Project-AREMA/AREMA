"""Kubernetes-only, stateless execution primitives for deobfuscation tools."""

from __future__ import annotations

import re
import shlex
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from math import isfinite
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from arema.runtime.sandbox.k8s import K8sSandboxExecutor
from arema.runtime.sandbox.local import LocalSandboxExecutor
from arema.runtime.sandbox.port import ExecutionResult
from arema.runtime.sessions import SandboxIdentityError, resolve_sandbox_case_id
from reverse_engineering.artifacts import ArtifactStore, default_artifacts_root

if TYPE_CHECKING:
    from collections.abc import Sequence
    from typing import BinaryIO

    from google.adk.tools.tool_context import ToolContext

    from arema.runtime.agent_factory import ToolBuildContext
    from arema.runtime.sandbox.port import SandboxExecutor, SandboxHandle

POOL = "deobfuscation-tools"
# The staged sample's fixed filename inside every work dir. Single source of truth
# for both staging entry points, so the constant and the real path cannot drift.
_INPUT_NAME = "input"
MAX_RECOVERED_BYTES = 512 * 1024 * 1024
MAX_RESULT_BYTES = 32 * 1024 * 1024

_ARTIFACT_ID_PATTERN = re.compile(r"[0-9a-f]{64}")
_TOOL_NAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_WORK_DIR_PATTERN = re.compile(r"/work/[a-z0-9][a-z0-9_-]{0,63}/[0-9a-f]{64}")
_REMOTE_COMPONENT_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_UNSIGNED_DECIMAL_PATTERN = re.compile(r"[0-9]+\n?")
_DNS_LABEL_PATTERN = re.compile(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?")
_REMOTE_KILL_AFTER_SECONDS = 5
_KUBECTL_TRANSPORT_GRACE_SECONDS = 10
_KUBECTL_CP_TIMEOUT_SECONDS = 120
_KUBECTL_DIAGNOSTIC_CAP = 4_096
_PIPE_CHUNK_SIZE = 64 * 1024


class DeobfuscationUnavailable(RuntimeError):
    """Raised when the dedicated Kubernetes sandbox is unavailable."""


class ArtifactInputTooLarge(RuntimeError):
    """Raised when a bounded staging read exceeds its configured input cap."""


@dataclass(frozen=True, slots=True)
class _BoundedProcessResult:
    """Byte-preserving, memory-bounded subprocess output."""

    returncode: int
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool


@dataclass(frozen=True, slots=True)
class StagedArtifact:
    """An immutable artifact staged into its per-tool sandbox work directory."""

    executor: SandboxExecutor
    handle: SandboxHandle
    artifact_id: str
    input_path: str
    work_dir: str
    timeout: float
    namespace: str = ""
    output_cap: int = 65_536
    direct_kubectl: bool = False


@dataclass(frozen=True, slots=True)
class _ClaimedWorkspace:
    """Validated, claimed staging coordinates shared by both stage_* entry points."""

    executor: SandboxExecutor
    handle: SandboxHandle
    work_dir: str
    input_path: str
    direct_kubectl: bool
    namespace: str
    output_cap: int


def _validate_and_resolve(
    context: ToolBuildContext,
    artifact_id: str,
    tool_context: ToolContext,
    *,
    tool_name: str,
) -> tuple[SandboxExecutor, str]:
    """Enforce the k8s-only boundary, validate ids, and resolve the case id -- the
    cheap, pre-I/O, pre-claim checks shared by both stage_* entry points, so the
    security-critical Local-executor guard lives in exactly one place. Runs before
    any file read or pod claim, preserving the "validate before touching anything"
    ordering both entry points rely on.
    """
    if context.settings.sandbox_backend != "k8s":
        raise DeobfuscationUnavailable("sandbox tools require sandbox_backend='k8s'")
    executor = context.services.sandbox
    if executor is None:
        raise DeobfuscationUnavailable("sandbox executor is not configured")
    if isinstance(executor, LocalSandboxExecutor):
        raise DeobfuscationUnavailable(
            "sandbox runtime requires K8sSandboxExecutor; local execution is forbidden"
        )
    if _ARTIFACT_ID_PATTERN.fullmatch(artifact_id) is None:
        raise ValueError("artifact_id must be a lowercase SHA-256")
    if _TOOL_NAME_PATTERN.fullmatch(tool_name) is None:
        raise ValueError("tool_name must be a safe single path component")
    try:
        case_id = resolve_sandbox_case_id(tool_context)
    except SandboxIdentityError as exc:
        raise DeobfuscationUnavailable("sandbox identity unavailable") from exc
    return executor, case_id


def _claim_paths(
    executor: SandboxExecutor,
    case_id: str,
    context: ToolBuildContext,
    *,
    pool: str,
    tool_name: str,
    artifact_id: str,
) -> _ClaimedWorkspace:
    """Claim the case pod and derive the validated staging coordinates -- the
    post-validation, post-read step shared by both stage_* entry points."""
    handle = executor.claim(key=case_id, pool=pool)
    work_dir = f"/work/{tool_name}/{artifact_id}"
    direct_kubectl = isinstance(executor, K8sSandboxExecutor)
    namespace = context.settings.sandbox_namespace
    if direct_kubectl:
        _validate_kubernetes_namespace(namespace)
        _validate_kubernetes_pod(handle.backend_id)
    return _ClaimedWorkspace(
        executor=executor,
        handle=handle,
        work_dir=work_dir,
        input_path=f"{work_dir}/{_INPUT_NAME}",
        direct_kubectl=direct_kubectl,
        namespace=namespace,
        output_cap=context.settings.sandbox_output_cap,
    )


def _run_setup(claimed: _ClaimedWorkspace, command: str) -> None:
    """Run a work-dir prep command, raising a bounded diagnostic on failure."""
    if claimed.direct_kubectl:
        setup = _kubectl_exec_result(
            ["sh", "-c", command],
            claimed.namespace,
            claimed.handle.backend_id,
            timeout=30,
            output_cap=claimed.output_cap,
        )
    else:
        setup = claimed.executor.run(claimed.handle, command, timeout=30)
    if setup.exit_code != 0 or setup.truncated:
        raise RuntimeError(
            "failed to prepare sandbox work directory: " + _bounded_diagnostic(setup)
        )


def _seed_input(claimed: _ClaimedWorkspace, data: bytes) -> None:
    """Write the staged sample bytes to the claimed input path."""
    if claimed.direct_kubectl:
        _kubectl_write_bytes(data, claimed.namespace, claimed.handle.backend_id, claimed.input_path)
    else:
        claimed.executor.write_file(claimed.handle, claimed.input_path, data)


def _input_present(claimed: _ClaimedWorkspace) -> bool:
    """Return whether the staged input already exists (persistent-workspace probe)."""
    argv = ["test", "-f", claimed.input_path]
    if claimed.direct_kubectl:
        result = _kubectl_exec_result(
            argv,
            claimed.namespace,
            claimed.handle.backend_id,
            timeout=30,
            output_cap=claimed.output_cap,
        )
    else:
        result = claimed.executor.run(claimed.handle, shlex.join(argv), timeout=30)
    return result.exit_code == 0


def _assemble_staged(
    claimed: _ClaimedWorkspace, artifact_id: str, run_timeout: int
) -> StagedArtifact:
    """Build the immutable StagedArtifact from claimed coordinates (shared tail)."""
    return StagedArtifact(
        executor=claimed.executor,
        handle=claimed.handle,
        artifact_id=artifact_id,
        input_path=claimed.input_path,
        work_dir=claimed.work_dir,
        timeout=float(run_timeout),
        namespace=claimed.namespace,
        output_cap=claimed.output_cap,
        direct_kubectl=claimed.direct_kubectl,
    )


def stage_artifact(
    context: ToolBuildContext,
    artifact_id: str,
    tool_context: ToolContext,
    *,
    tool_name: str,
    pool: str = POOL,
    max_input_bytes: int | None = None,
) -> StagedArtifact:
    """Claim the case sandbox and copy one validated artifact into a fresh work area.

    ``pool`` defaults to the deobfuscation-tools pool; the dnlib_roundtrip tool
    passes the analysis-workbench pool so it can drive dnlib via dotnet-script.
    """
    executor, case_id = _validate_and_resolve(
        context, artifact_id, tool_context, tool_name=tool_name
    )
    if max_input_bytes is not None and (isinstance(max_input_bytes, bool) or max_input_bytes < 0):
        raise ValueError("max_input_bytes must be nonnegative")
    # Read + size-check the input BEFORE claiming a pod, so an oversize input never
    # wastes a sandbox claim.
    data = _read_artifact_input(
        ArtifactStore(default_artifacts_root()).path_for(artifact_id), max_input_bytes
    )
    claimed = _claim_paths(
        executor, case_id, context, pool=pool, tool_name=tool_name, artifact_id=artifact_id
    )
    _run_setup(claimed, _prepare_work_dir_command(claimed.work_dir))
    _seed_input(claimed, data)
    return _assemble_staged(claimed, artifact_id, context.settings.sandbox_run_timeout)


def stage_persistent_workspace(
    context: ToolBuildContext,
    artifact_id: str,
    tool_context: ToolContext,
    *,
    pool: str,
    tool_name: str,
) -> StagedArtifact:
    """Claim the case sandbox and ensure a PERSISTENT ``/work/<tool>/<sha>`` workspace.

    Unlike :func:`stage_artifact`, which wipes the work directory on every call,
    this prepares it idempotently *without* removing existing files and copies
    the sample in only when it is absent -- so agent-authored scripts and dumps
    survive across repeated executions against the same case.
    """
    executor, case_id = _validate_and_resolve(
        context, artifact_id, tool_context, tool_name=tool_name
    )
    claimed = _claim_paths(
        executor, case_id, context, pool=pool, tool_name=tool_name, artifact_id=artifact_id
    )
    _run_setup(claimed, _prepare_persistent_work_dir_command(claimed.work_dir))
    # Seed the sample only when absent so a persistent workspace is never re-seeded.
    if not _input_present(claimed):
        source = ArtifactStore(default_artifacts_root()).path_for(artifact_id)
        _seed_input(claimed, _read_artifact_input(source, None))
    return _assemble_staged(claimed, artifact_id, context.settings.sandbox_run_timeout)


def _read_artifact_input(source: Path, max_input_bytes: int | None) -> bytes:
    """Read a local input once, applying a cap when the caller supplied one."""
    if max_input_bytes is None:
        return source.read_bytes()
    with source.open("rb") as artifact:
        data = artifact.read(max_input_bytes + 1)
    if len(data) > max_input_bytes:
        raise ArtifactInputTooLarge("artifact input exceeds maximum size")
    return data


def run_argv(staged: StagedArtifact, argv: Sequence[str]) -> ExecutionResult:
    """Run a developer-constructed argv inside the staged artifact sandbox."""
    if staged.direct_kubectl:
        return _kubectl_exec_result(
            list(argv),
            staged.namespace,
            staged.handle.backend_id,
            timeout=staged.timeout,
            output_cap=staged.output_cap,
        )
    return staged.executor.run(staged.handle, shlex.join(argv), timeout=staged.timeout)


def run_argv_to_file(
    staged: StagedArtifact, argv: Sequence[str], output_path: str
) -> ExecutionResult:
    """Run a tokenized command and safely redirect its output to a staged path."""
    _validate_remote_path(staged, output_path, output=True)
    command = f"{shlex.join(argv)} > {shlex.quote(output_path)}"
    if staged.direct_kubectl:
        return _kubectl_exec_result(
            ["sh", "-c", command],
            staged.namespace,
            staged.handle.backend_id,
            timeout=staged.timeout,
            output_cap=staged.output_cap,
        )
    return staged.executor.run(staged.handle, command, timeout=staged.timeout)


def remote_file_size(staged: StagedArtifact, path: str) -> int:
    """Return a staged remote file's byte size without transferring its bytes."""
    _validate_remote_path(staged, path)
    argv = ["stat", "--format=%s", "--", path]
    if staged.direct_kubectl:
        result = _kubectl_exec_result(
            argv,
            staged.namespace,
            staged.handle.backend_id,
            timeout=staged.timeout,
            output_cap=staged.output_cap,
        )
    else:
        result = staged.executor.run(
            staged.handle,
            shlex.join(argv),
            timeout=staged.timeout,
        )
    if result.exit_code != 0 or result.truncated:
        raise RuntimeError("failed to measure remote file")
    if _UNSIGNED_DECIMAL_PATTERN.fullmatch(result.stdout) is None:
        raise RuntimeError("failed to measure remote file")
    return int(result.stdout)


def read_bounded_file(staged: StagedArtifact, path: str, max_bytes: int) -> bytes:
    """Read after a size preflight, enforcing a second cap during transfer."""
    if isinstance(max_bytes, bool) or max_bytes < 0:
        raise ValueError("max_bytes must be nonnegative")
    size = remote_file_size(staged, path)
    if size > max_bytes:
        raise ValueError("remote file exceeds maximum size")
    if staged.direct_kubectl:
        transferred = _kubectl_exec_bytes(
            ["head", "-c", str(max_bytes + 1), "--", path],
            staged.namespace,
            staged.handle.backend_id,
            timeout=staged.timeout,
            output_cap=max_bytes + 1,
        )
        if transferred.returncode != 0 or transferred.stderr_truncated:
            raise RuntimeError("failed to read remote file")
        data = transferred.stdout
        transfer_truncated = transferred.stdout_truncated
    else:
        data = staged.executor.read_file(staged.handle, path)
        transfer_truncated = False
    if transfer_truncated or len(data) != size or len(data) > max_bytes:
        raise RuntimeError("remote file changed during read")
    return data


def read_bounded_prefix(staged: StagedArtifact, path: str, max_bytes: int) -> bytes:
    """Read up to ``max_bytes`` leading bytes of a staged file, byte-accurately.

    Unlike :func:`read_bounded_file` -- which requires the whole file to fit under
    the cap and raises otherwise -- this returns the file's leading ``max_bytes``
    bytes verbatim regardless of the file's true size. It is the primitive behind
    an oversized capture: a bounded inline preview plus a spill of the same bytes
    up to a hard ceiling, with no all-or-nothing failure and no lossy decode.
    """
    if isinstance(max_bytes, bool) or max_bytes < 0:
        raise ValueError("max_bytes must be nonnegative")
    _validate_remote_path(staged, path)
    if not staged.direct_kubectl:
        return staged.executor.read_file(staged.handle, path)[:max_bytes]
    if max_bytes == 0:
        return b""
    transferred = _kubectl_exec_bytes(
        ["head", "-c", str(max_bytes), "--", path],
        staged.namespace,
        staged.handle.backend_id,
        timeout=staged.timeout,
        output_cap=max_bytes,
    )
    if transferred.returncode != 0 or transferred.stderr_truncated:
        raise RuntimeError("failed to read remote file")
    return transferred.stdout[:max_bytes]


def write_staged_file(staged: StagedArtifact, path: str, data: bytes) -> None:
    """Write immutable bytes to a validated path inside the staged work directory.

    Transport-aware, mirroring :func:`run_argv`: the direct ``kubectl`` path used
    by exec-driven pods copies bytes with ``kubectl cp`` (creating the parent
    directory first, since ``cp`` cannot), while the executor path delegates to
    the sandbox's own file transport. ``path`` is validated exactly like a
    redirected-output path -- absolute, normalized, strictly inside the work
    directory, and never the staged input -- so an agent-supplied filename can
    never escape the workspace or clobber the sample.
    """
    _validate_remote_path(staged, path, output=True)
    if staged.direct_kubectl:
        parent = path.rsplit("/", 1)[0]
        setup = _kubectl_exec_result(
            ["mkdir", "-m", "0700", "-p", "--", parent],
            staged.namespace,
            staged.handle.backend_id,
            timeout=staged.timeout,
            output_cap=staged.output_cap,
        )
        if setup.exit_code != 0 or setup.truncated:
            raise RuntimeError(
                "failed to prepare staged write directory: " + _bounded_diagnostic(setup)
            )
        _kubectl_write_bytes(data, staged.namespace, staged.handle.backend_id, path)
    else:
        staged.executor.write_file(staged.handle, path, data)


def _prepare_work_dir_command(work_dir: str) -> str:
    """Build the fixed cleanup/create shell command for an internally derived path."""
    tool_dir = work_dir.rsplit("/", 1)[0]
    check_parent = shlex.join(["test", "!", "-L", tool_dir])
    remove = shlex.join(["rm", "-rf", "--", work_dir])
    create = shlex.join(["mkdir", "-m", "0700", "-p", "--", work_dir])
    return f"{check_parent} && {remove} && {create}"


def _prepare_persistent_work_dir_command(work_dir: str) -> str:
    """Build a create-only command for an internally derived path (no wipe).

    The persistent variant of :func:`_prepare_work_dir_command`: it creates the
    work directory idempotently but never ``rm -rf``s it, so files written by an
    earlier execution survive into the next one.
    """
    tool_dir = work_dir.rsplit("/", 1)[0]
    check_parent = shlex.join(["test", "!", "-L", tool_dir])
    create = shlex.join(["mkdir", "-m", "0700", "-p", "--", work_dir])
    return f"{check_parent} && {create}"


def _bounded_diagnostic(result: ExecutionResult) -> str:
    """Make a bounded, escaped setup diagnostic safe for an exception message."""
    return f"stdout={result.stdout!r}; stderr={result.stderr!r}"[:2000]


def _kubectl_exec_result(
    argv: list[str],
    namespace: str,
    pod: str,
    *,
    timeout: float,
    output_cap: int,
) -> ExecutionResult:
    """Execute argv with remote TERM/KILL deadlines and bounded diagnostics."""
    result = _kubectl_exec_bytes(
        argv,
        namespace,
        pod,
        timeout=timeout,
        output_cap=output_cap,
    )
    stdout = result.stdout.decode(errors="replace")
    stderr = result.stderr.decode(errors="replace")
    return ExecutionResult(
        exit_code=result.returncode,
        stdout=stdout,
        stderr=stderr,
        truncated=result.stdout_truncated or result.stderr_truncated,
    )


def _kubectl_exec_bytes(
    argv: list[str],
    namespace: str,
    pod: str,
    *,
    timeout: float,
    output_cap: int,
) -> _BoundedProcessResult:
    """Execute in a claimed pod while preserving bounded binary stdout."""
    _validate_positive_number(timeout, "timeout")
    _validate_positive_integer(output_cap, "output_cap")
    _validate_kubernetes_namespace(namespace)
    _validate_kubernetes_pod(pod)
    remote_duration = f"{timeout:g}s"
    command = [
        "kubectl",
        "exec",
        f"pod/{pod}",
        "-n",
        namespace,
        "--",
        "timeout",
        "--signal=TERM",
        f"--kill-after={_REMOTE_KILL_AFTER_SECONDS}s",
        remote_duration,
        *argv,
    ]
    outer_timeout = timeout + _REMOTE_KILL_AFTER_SECONDS + _KUBECTL_TRANSPORT_GRACE_SECONDS
    return _run_bounded_process(
        command,
        timeout=outer_timeout,
        stdout_cap=output_cap,
        stderr_cap=output_cap,
    )


def _kubectl_write_bytes(data: bytes, namespace: str, pod: str, path: str) -> None:
    """Copy immutable staged bytes into an exec-only sandbox pod."""
    _validate_kubernetes_namespace(namespace)
    _validate_kubernetes_pod(pod)
    with tempfile.NamedTemporaryFile(prefix="arema-deobf-input-") as source:
        source.write(data)
        source.flush()
        _kubectl_cp(str(source.name), f"{namespace}/{pod}:{path}")


def _kubectl_cp(source: str, destination: str) -> None:
    """Copy one bounded input file with bounded kubectl diagnostics."""
    result = _run_bounded_process(
        ["kubectl", "cp", source, destination],
        timeout=_KUBECTL_CP_TIMEOUT_SECONDS,
        stdout_cap=_KUBECTL_DIAGNOSTIC_CAP,
        stderr_cap=_KUBECTL_DIAGNOSTIC_CAP,
    )
    if result.stdout_truncated or result.stderr_truncated:
        raise RuntimeError("kubectl cp output exceeded diagnostic limit")
    if result.returncode != 0:
        stderr = result.stderr.decode(errors="replace").strip()
        raise RuntimeError(f"kubectl cp failed (exit {result.returncode}): {stderr}")


def _run_bounded_process(
    command: list[str],
    *,
    timeout: float,
    stdout_cap: int,
    stderr_cap: int,
) -> _BoundedProcessResult:
    """Run a local transport process while concurrently draining bounded pipes."""
    _validate_positive_number(timeout, "timeout")
    _validate_positive_integer(stdout_cap, "stdout_cap")
    _validate_positive_integer(stderr_cap, "stderr_cap")
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    captures: list[tuple[bytes, bool] | None] = [None, None]
    errors: list[BaseException] = []

    def drain(index: int, stream: BinaryIO, cap: int) -> None:
        try:
            captures[index] = _drain_bounded_pipe(stream, cap)
        except BaseException as exc:  # pragma: no cover - defensive OS pipe failure
            errors.append(exc)

    threads = [
        threading.Thread(target=drain, args=(0, process.stdout, stdout_cap), daemon=True),
        threading.Thread(target=drain, args=(1, process.stderr, stderr_cap), daemon=True),
    ]
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        returncode = process.wait()
    finally:
        for thread in threads:
            thread.join()
    if errors:
        raise RuntimeError("failed to drain subprocess output") from errors[0]
    if timed_out:
        raise RuntimeError(f"process timed out after {timeout:g}s")
    stdout = captures[0]
    stderr = captures[1]
    if stdout is None or stderr is None:  # pragma: no cover - threads always assign or error
        raise RuntimeError("failed to drain subprocess output")
    return _BoundedProcessResult(
        returncode=returncode,
        stdout=stdout[0],
        stderr=stderr[0],
        stdout_truncated=stdout[1],
        stderr_truncated=stderr[1],
    )


def _drain_bounded_pipe(stream: BinaryIO, cap: int) -> tuple[bytes, bool]:
    retained = bytearray()
    truncated = False
    while chunk := stream.read(_PIPE_CHUNK_SIZE):
        remaining = cap - len(retained)
        if remaining > 0:
            retained.extend(chunk[:remaining])
        if len(chunk) > max(remaining, 0):
            truncated = True
    return bytes(retained), truncated


def _validate_positive_number(value: float, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be positive")
    if not isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be positive")


def _validate_positive_integer(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be positive")


def _validate_kubernetes_namespace(namespace: str) -> None:
    if not isinstance(namespace, str) or _DNS_LABEL_PATTERN.fullmatch(namespace) is None:
        raise ValueError("Kubernetes namespace must be a DNS-1123 label")


def _validate_kubernetes_pod(pod: str) -> None:
    if (
        not isinstance(pod, str)
        or len(pod) > 253
        or any(_DNS_LABEL_PATTERN.fullmatch(label) is None for label in pod.split("."))
    ):
        raise ValueError("Kubernetes pod name must be a DNS-1123 subdomain")


def _validate_remote_path(staged: StagedArtifact, path: str, *, output: bool = False) -> None:
    """Require an absolute normalized file path strictly inside the staged work dir."""
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError("remote path must be an absolute staged file path")
    if _WORK_DIR_PATTERN.fullmatch(staged.work_dir) is None:
        raise ValueError("remote path has an invalid staged work directory")
    candidate = PurePosixPath(path)
    work_dir = PurePosixPath(staged.work_dir)
    if str(candidate) != path or ".." in candidate.parts or candidate == work_dir:
        raise ValueError(
            "remote path must be normalized and strictly inside the staged work directory"
        )
    if not candidate.is_relative_to(work_dir):
        raise ValueError("remote path must be inside the staged work directory")
    relative_parts = candidate.relative_to(work_dir).parts
    if not relative_parts or any(
        _REMOTE_COMPONENT_PATTERN.fullmatch(part) is None for part in relative_parts
    ):
        raise ValueError("remote path must use safe file components")
    if output and path == staged.input_path:
        raise ValueError("remote path must not overwrite staged input")
