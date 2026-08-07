"""Sandboxed androguard triage of a hostile APK / DEX / JAR sample.

A single androguard pass runs **inside the deobfuscation-tools sandbox pod** --
never in the AREMA process, because the sample is untrusted and androguard parses
it -- via the shared ``stage_artifact -> run_argv`` one-shot pattern (mirroring
:func:`reverse_engineering.tools.deobfuscation.dotnet.build_de4dot_deobfuscate`).
The in-pod ``/opt/androguard_triage.py`` script prints the triage JSON contract
(see :mod:`reverse_engineering.tools.android.report`) to stdout; this tool stages
the artifact, runs the script, and returns the parsed report.

Self-gating: the tool only handles JVM/Android container formats
(:data:`~reverse_engineering.agents.format_router.JVM_FORMATS`). A non-JVM sample
returns a skip result without ever claiming a pod. Fail-open: any staging, pod,
or parse failure degrades to ``{"success": False, "error": ...}`` and never
raises into the run.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from google.adk.tools.tool_context import (
    ToolContext,  # noqa: TC002 - runtime import: ADK resolves this annotation via get_type_hints
)

from arema.registry.descriptors import OutputPolicy, ToolDescriptor
from reverse_engineering.agents.format_router import JVM_FORMATS
from reverse_engineering.tools.acquire_sample import SAMPLE_FORMAT_KEY
from reverse_engineering.tools.deobfuscation.runtime import run_argv, stage_artifact

if TYPE_CHECKING:
    from arema.registry.descriptors import ToolLike
    from arema.runtime.agent_factory import ToolBuildContext

_TOOL_NAME = "android_triage_scan"
_SCRIPT_PATH = "/opt/androguard_triage.py"
# APKs routinely reach tens of MB; cap staging at the same ceiling the .NET path
# uses so an oversized sample is rejected before it wastes a pod claim.
MAX_ANDROID_INPUT_BYTES = 512 * 1024 * 1024


def build_android_triage_scan(context: ToolBuildContext) -> ToolLike:
    """Build the ``android_triage_scan`` tool for the live sandbox runtime."""

    def android_triage_scan(artifact_id: str, tool_context: ToolContext) -> dict[str, object]:
        """Triage an APK/DEX/JAR with androguard inside the deobfuscation sandbox."""
        state = getattr(tool_context, "state", None)
        getter = getattr(state, "get", None)
        sample_format = getter(SAMPLE_FORMAT_KEY) if callable(getter) else None
        if sample_format not in JVM_FORMATS:
            return {
                "success": False,
                "skipped": True,
                "error": f"android_triage_scan handles apk/dex/jar; got {sample_format}",
            }

        try:
            staged = stage_artifact(
                context,
                artifact_id,
                tool_context,
                tool_name=_TOOL_NAME,
                max_input_bytes=MAX_ANDROID_INPUT_BYTES,
            )
            result = run_argv(staged, ["python", _SCRIPT_PATH, staged.input_path])
            if result.exit_code != 0:
                return {
                    "success": False,
                    "error": f"androguard triage exited {result.exit_code}",
                }
            # Gate success on the stdout JSON payload ALONE, never on
            # ``result.truncated``. That flag is ``stdout_truncated or
            # stderr_truncated``, and androguard logs freely to stderr (loguru),
            # so a hostile, noisy sample can blow past the output cap on stderr
            # while producing a perfectly valid report on stdout -- that report
            # must not be discarded. A garbled or stdout-truncated payload is
            # still caught here: json.loads raises and the except degrades
            # fail-open, so the check moves from a coarse volume flag to the
            # actual parse of the only channel that carries the contract.
            report = json.loads(result.stdout)
        except Exception as exc:  # fail-open: a hostile sample must never crash the run
            return {"success": False, "error": str(exc)}
        return {"success": True, "report": report}

    return android_triage_scan


ANDROID_TRIAGE_SCAN_TOOL = ToolDescriptor(
    id="android_triage_scan",
    description=(
        "Triage an Android/JVM sample (apk/dex/jar) with androguard inside the "
        "deobfuscation sandbox: manifest, permissions, exported components, "
        "flags, native libs, URL candidates, and packer detection."
    ),
    factory=build_android_triage_scan,
    output_policy=OutputPolicy(max_chars=8_000, max_list_items=40),
)
