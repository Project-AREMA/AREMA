"""The ``run_python`` tool: execute agent-authored Python in the workbench sandbox.

Mirrors the deferred-factory pattern of
:mod:`reverse_engineering.tools.prepare_ilspy`: a plain function cannot see
:class:`RuntimeServices`, so :func:`build_run_python` closes over the live
sandbox executor (via ``context``) and returns the callable ADK injects at call
time. The inner tool is named ``run_python`` so its ``__name__`` matches the
descriptor id, which the :class:`OutputPolicy` requires to bind at compaction
time.

Each call stages the *current* artifact into a persistent ``analysis`` workspace
(reused across calls, so scripts and dumps survive), writes the agent's ``code``
to ``scripts/step_<n>.py``, and runs it under the sandbox timeout/output governor
with ``$INPUT`` and ``$WORKDIR`` exported. The script's stdout is redirected to a
workspace file (``scripts/step_<n>.out``) so the *full, byte-accurate* output is
captured in the pod rather than truncated at the transport cap. The returned
``stdout`` is a bounded prefix of that capture; when the full output overflows the
inline cap it is spilled verbatim to the SHA-256 artifact store so the model
receives a referenceable hash for the unseen overflow instead of losing it
(§4.2/§4.3). ``stderr`` stays inline (bounded) for debugging, and ``truncated``
reports whether *stdout* overflowed -- not an unrelated stderr overflow.
"""

from __future__ import annotations

import dataclasses
import shlex
from typing import TYPE_CHECKING

from google.adk.tools.tool_context import (
    ToolContext,  # noqa: TC002 - runtime import: ADK resolves this annotation via get_type_hints
)

from arema.registry.descriptors import OutputPolicy, ToolDescriptor, ToolLifecycleCallbacks
from reverse_engineering.artifacts import ArtifactStore, default_artifacts_root
from reverse_engineering.tools.deobfuscation.runtime import (
    MAX_RESULT_BYTES,
    read_bounded_prefix,
    remote_file_size,
    run_argv_to_file,
    stage_persistent_workspace,
    write_staged_file,
)
from reverse_engineering.tools.deobfuscation.state import CURRENT_ARTIFACT_KEY
from reverse_engineering.tools.workbench.budget import run_python_budget_guard
from reverse_engineering.tools.workbench.state import (
    RUN_PYTHON_TOOL_NAME,
    WORKBENCH_EXEC_COUNT_KEY,
    WORKBENCH_POOL,
)

if TYPE_CHECKING:
    from arema.registry.descriptors import ToolLike
    from arema.runtime.agent_factory import ToolBuildContext

_TOOL_NAME = "analysis"
_MIN_TIMEOUT_S = 1.0
# Default per-call timeout when the model omits ``timeout_s``. Comfortable for a
# static unpacking script yet still clamped to the backend ceiling in the body.
_DEFAULT_TIMEOUT_S = 60
# The tool bounds its OWN returned dict to this budget so the always-last
# after-tool compactor never silently truncates a value: stdout gets the bulk,
# stderr a slice, leaving headroom for the scalar fields. Anything past the stdout
# budget is spilled verbatim to the artifact store (recoverable by SHA), and the
# spill is gated on this inline budget -- NOT the larger sandbox transport cap --
# so no output the compactor would hide is ever left without a spilled SHA.
_MAX_CHARS = 32_000
_STDOUT_INLINE_CHARS = 24_000
_STDERR_INLINE_CHARS = 6_000
_STDERR_TRUNCATED_MARKER = "\n[stderr truncated]"


def build_run_python(context: ToolBuildContext) -> ToolLike:
    """Build ``run_python`` closing over the live sandbox executor."""

    def run_python(
        code: str, tool_context: ToolContext, timeout_s: int = _DEFAULT_TIMEOUT_S
    ) -> dict[str, object]:
        state = tool_context.state
        getter = getattr(state, "get", None)
        artifact_id = getter(CURRENT_ARTIFACT_KEY) if callable(getter) else None
        if not isinstance(artifact_id, str):
            return {
                "exit_code": 1,
                "stdout": "",
                "stderr": "no current artifact",
                "truncated": False,
                "spilled_artifact_id": "",
            }
        staged = stage_persistent_workspace(
            context, artifact_id, tool_context, pool=WORKBENCH_POOL, tool_name=_TOOL_NAME
        )
        # The agent's requested per-call timeout is honored but clamped to the
        # configured backend ceiling so a single script cannot outlive the
        # sandbox governor.
        timeout = max(_MIN_TIMEOUT_S, min(float(timeout_s), staged.timeout))
        staged = dataclasses.replace(staged, timeout=timeout)

        raw_step = getter(WORKBENCH_EXEC_COUNT_KEY) if callable(getter) else None
        step = raw_step if isinstance(raw_step, int) and not isinstance(raw_step, bool) else 0
        script_path = f"{staged.work_dir}/scripts/step_{step}.py"
        stdout_path = f"{staged.work_dir}/scripts/step_{step}.out"
        write_staged_file(staged, script_path, code.encode())

        command = (
            f"INPUT={shlex.quote(staged.input_path)} "
            f"WORKDIR={shlex.quote(staged.work_dir)} "
            f"python3 {shlex.quote(script_path)}"
        )
        # Redirect the script's stdout to a workspace file so the FULL,
        # byte-accurate output is captured in the pod (the transport otherwise
        # discards everything past the output cap). stderr stays inline.
        result = run_argv_to_file(staged, ["sh", "-c", command], stdout_path)

        stdout_size = remote_file_size(staged, stdout_path)
        # Gate the spill + `truncated` on the tool's own inline stdout budget --
        # what the model can actually see after the compactor bounds the result --
        # not the larger sandbox transport cap. Otherwise stdout in the
        # (_STDOUT_INLINE_CHARS, output_cap] window would be truncated by the
        # compactor with truncated=False and no recoverable spill SHA.
        stdout_overflow = stdout_size > _STDOUT_INLINE_CHARS
        # Read the captured stdout once, byte-accurately, up to a hard ceiling:
        # the inline field is its bounded prefix and the same bytes back the
        # spill, so no lossy decode/re-encode round trip ever reaches the store.
        captured = read_bounded_prefix(staged, stdout_path, min(stdout_size, MAX_RESULT_BYTES))
        stdout_preview = captured[:_STDOUT_INLINE_CHARS].decode(errors="replace")

        spilled = ""
        if stdout_overflow:
            spilled = ArtifactStore(default_artifacts_root()).acquire_bytes(captured)

        # Bound stderr to its own inline slice too, so the returned dict as a whole
        # stays within OutputPolicy.max_chars and the compactor never has to hide a
        # value. stderr is diagnostic, so it is truncated in place (not spilled).
        stderr = result.stderr
        if len(stderr) > _STDERR_INLINE_CHARS:
            stderr = stderr[:_STDERR_INLINE_CHARS] + _STDERR_TRUNCATED_MARKER
        return {
            "exit_code": result.exit_code,
            "stdout": stdout_preview,
            "stderr": stderr,
            "truncated": stdout_overflow,
            "spilled_artifact_id": spilled,
        }

    return run_python


RUN_PYTHON_TOOL = ToolDescriptor(
    id=RUN_PYTHON_TOOL_NAME,
    description=(
        "Run an agent-authored Python script in the sandboxed analysis workbench "
        "(python3 + radare2/r2pipe + pefile/LIEF/pycryptodome) against the current "
        "artifact at $INPUT, writing dumps under $WORKDIR. The workspace persists "
        "across calls, so helper modules and intermediate files survive. Returns "
        "exit_code, a bounded stdout preview, stderr, whether stdout overflowed the "
        "cap, and the SHA-256 of the full stdout spilled to the artifact store when "
        "it did."
    ),
    factory=build_run_python,
    output_policy=OutputPolicy(max_chars=_MAX_CHARS, max_list_items=200),
    # The loop-level half of the §4.5 governor: a before_tool guard on a global
    # per-case counter that caps total executions and short-circuits with a
    # finalize advisory once the cap is reached, so the sandbox is never re-run.
    callbacks=ToolLifecycleCallbacks(before=(run_python_budget_guard,)),
)
