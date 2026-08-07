"""Deterministic dnlib metadata-roundtrip: the first-pass .NET recovery.

de4dot handles obfuscators it recognizes; when it fails or crashes (common on
ConfuserEx variants that mangle the ``#~`` metadata stream), the plain dnlib
load-and-resave frequently repairs the metadata so the assembly loads again. This
tool runs that round-trip with **no model in the loop** -- ``dotnet-script`` drives
a fixed, reviewed ``.csx`` (``/opt/dnlib-roundtrip.csx``) inside the analysis-
workbench pod, whose dnlib + offline dotnet-script the agentic path already uses.

On a successful, changed recovery it admits the result on the shared
``SCRIPTED_RESULT_KEY`` rail with the same shape ``register_unpacked_artifact``
writes (so the gate, evidence, and critic need no dnlib-specific handling) and
records its own outcome at ``DNLIB_ROUNDTRIP_RESULT_KEY`` so the agentic
``dotnet_scripted_recover`` gate escalates only when this deterministic pass did
not recover. Mirrors the guarded de4dot tool's shape and fail-open discipline.
"""

from __future__ import annotations

import math
import struct
from collections import Counter
from typing import TYPE_CHECKING

from google.adk.tools.tool_context import (
    ToolContext,  # noqa: TC002 - ADK resolves annotations at runtime
)

from arema.registry.descriptors import OutputPolicy, ToolDescriptor
from reverse_engineering.artifacts import ArtifactStore, default_artifacts_root
from reverse_engineering.tools.acquire_sample import SAMPLE_FORMAT_KEY, detect_format_bytes
from reverse_engineering.tools.deobfuscation.runtime import (
    MAX_RECOVERED_BYTES,
    ArtifactInputTooLarge,
    DeobfuscationUnavailable,
    read_bounded_file,
    run_argv,
    stage_artifact,
)
from reverse_engineering.tools.deobfuscation.state import (
    CURRENT_ARTIFACT_KEY,
    CURRENT_ARTIFACT_PROMPT_KEY,
    DE4DOT_RESULT_KEY,
    DNLIB_ROUNDTRIP_CALLED_KEY,
    DNLIB_ROUNDTRIP_RESULT_KEY,
    SCRIPTED_RESULT_KEY,
    UPX_PROVENANCE_PROMPT_KEY,
    advance_classification_artifact,
    parse_current_classification,
)
from reverse_engineering.tools.workbench.state import (
    WORKBENCH_EXEC_COUNT_KEY,
    WORKBENCH_MAX_EXECUTIONS,
    WORKBENCH_POOL,
)

if TYPE_CHECKING:
    from arema.registry.descriptors import ToolLike
    from arema.runtime.agent_factory import ToolBuildContext

_TOOL_VERSION = "dnlib-4.4.0"
_METHOD = "dnlib_metadata_roundtrip"
_ROUNDTRIP_CSX = "/opt/dnlib-roundtrip.csx"
_OUTPUT_NAME = "roundtrip.dll"
_MAX_INPUT_BYTES = 512 * 1024 * 1024
_MISSING = object()
_ERROR_MESSAGES = {
    "invalid_classification": "The deobfuscation classification is invalid.",
    "artifact_unavailable": "The artifact is unavailable.",
    "sandbox_unavailable": "The deobfuscation sandbox is unavailable.",
    "output_invalid": "The recovered output is not a valid .NET assembly.",
    "roundtrip_failed": "The dnlib metadata round-trip did not produce a loadable assembly.",
}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in Counter(data).values())


def _de4dot_recovered(raw: object) -> bool:
    return (
        isinstance(raw, dict)
        and raw.get("success") is True
        and raw.get("applicable") is True
        and raw.get("degraded") is False
        and raw.get("changed") is True
    )


def build_dnlib_roundtrip(context: ToolBuildContext) -> ToolLike:
    """Build the ``dnlib_roundtrip`` tool for the live sandbox runtime."""

    def dnlib_roundtrip(tool_context: ToolContext) -> dict[str, object]:
        """Run the deterministic dnlib metadata round-trip on a protected .NET sample."""
        state = tool_context.state
        getter = getattr(state, "get", None)
        if not callable(getter):
            return {"success": False, "applicable": True, "degraded": True, "changed": False}
        cached = getter(DNLIB_ROUNDTRIP_RESULT_KEY, _MISSING)
        called = getter(DNLIB_ROUNDTRIP_CALLED_KEY, _MISSING)
        if called is True and isinstance(cached, dict):
            return dict(cached)
        state[DNLIB_ROUNDTRIP_RESULT_KEY] = None
        state[DNLIB_ROUNDTRIP_CALLED_KEY] = True

        def finish(result: dict[str, object]) -> dict[str, object]:
            state[DNLIB_ROUNDTRIP_RESULT_KEY] = dict(result)
            return dict(result)

        try:
            plan = parse_current_classification(state)
        except ValueError:
            return finish(_degraded("invalid_classification"))
        state[CURRENT_ARTIFACT_PROMPT_KEY] = plan.artifact_id

        # Self-gate: managed (.NET) samples only, and only when neither the
        # deterministic de4dot pass nor a prior scripted pass already recovered.
        if getter(SAMPLE_FORMAT_KEY) != "dotnet":
            return finish(_not_applicable(plan.artifact_id, "not_dotnet"))
        if _de4dot_recovered(getter(DE4DOT_RESULT_KEY)):
            return finish(_not_applicable(plan.artifact_id, "de4dot_recovered"))
        count = getter(WORKBENCH_EXEC_COUNT_KEY)
        if (
            isinstance(count, int)
            and not isinstance(count, bool)
            and count >= WORKBENCH_MAX_EXECUTIONS
        ):
            return finish(_not_applicable(plan.artifact_id, "budget_exhausted"))

        try:
            source_size = (
                ArtifactStore(default_artifacts_root()).path_for(plan.artifact_id).stat().st_size
            )
        except (FileNotFoundError, OSError):
            return finish(_degraded("artifact_unavailable", source_artifact_id=plan.artifact_id))
        if source_size > _MAX_INPUT_BYTES:
            return finish(
                _not_applicable(plan.artifact_id, "input_too_large", source_size=source_size)
            )

        try:
            staged = stage_artifact(
                context,
                plan.artifact_id,
                tool_context,
                tool_name="dnlib_roundtrip",
                pool=WORKBENCH_POOL,
                max_input_bytes=_MAX_INPUT_BYTES,
            )
        except ArtifactInputTooLarge:
            return finish(
                _not_applicable(plan.artifact_id, "input_too_large", source_size=source_size)
            )
        except FileNotFoundError:
            return finish(
                _degraded(
                    "artifact_unavailable",
                    source_artifact_id=plan.artifact_id,
                    source_size=source_size,
                )
            )
        except (DeobfuscationUnavailable, OSError, TimeoutError, ValueError, RuntimeError):
            return finish(
                _degraded(
                    "sandbox_unavailable",
                    source_artifact_id=plan.artifact_id,
                    source_size=source_size,
                )
            )

        output_path = f"{staged.work_dir}/{_OUTPUT_NAME}"
        try:
            result = run_argv(
                staged, ["dotnet-script", _ROUNDTRIP_CSX, "--", staged.input_path, output_path]
            )
        except (OSError, TimeoutError, ValueError, RuntimeError):
            return finish(
                _degraded(
                    "sandbox_unavailable",
                    source_artifact_id=plan.artifact_id,
                    source_size=source_size,
                )
            )
        if result.exit_code != 0:
            return finish(
                _degraded(
                    "roundtrip_failed", source_artifact_id=plan.artifact_id, source_size=source_size
                )
            )

        try:
            recovered = read_bounded_file(staged, output_path, max_bytes=MAX_RECOVERED_BYTES)
        except (FileNotFoundError, OSError, ValueError, RuntimeError):
            return finish(
                _degraded(
                    "output_invalid", source_artifact_id=plan.artifact_id, source_size=source_size
                )
            )
        try:
            recovered_is_dotnet = bool(recovered) and detect_format_bytes(recovered) == "dotnet"
        except struct.error:
            recovered_is_dotnet = False
        if not recovered_is_dotnet:
            return finish(
                _degraded(
                    "output_invalid",
                    source_artifact_id=plan.artifact_id,
                    source_size=source_size,
                    recovered_size=len(recovered),
                )
            )

        try:
            entropy_before = _entropy(
                ArtifactStore(default_artifacts_root()).path_for(plan.artifact_id).read_bytes()
            )
            recovered_artifact_id = ArtifactStore(default_artifacts_root()).acquire_bytes(recovered)
        except (FileNotFoundError, OSError, ValueError, RuntimeError):
            return finish(
                _degraded(
                    "artifact_unavailable",
                    source_artifact_id=plan.artifact_id,
                    source_size=source_size,
                    recovered_size=len(recovered),
                )
            )
        if recovered_artifact_id == plan.artifact_id:
            # A byte-identical resave is not a recovery -- let the agentic path try.
            return finish(_not_applicable(plan.artifact_id, "no_change", source_size=source_size))

        # Admit on the shared scripted-recovery rail (identical shape to
        # register_unpacked_artifact) so the gate/evidence/critic are unchanged.
        state[CURRENT_ARTIFACT_KEY] = recovered_artifact_id
        state[CURRENT_ARTIFACT_PROMPT_KEY] = recovered_artifact_id
        advance_classification_artifact(state, plan, recovered_artifact_id)
        state[UPX_PROVENANCE_PROMPT_KEY] = (
            f"scripted_recover source={plan.artifact_id} "
            f"destination={recovered_artifact_id} method={_METHOD}"
        )
        state[SCRIPTED_RESULT_KEY] = {
            "source_artifact_id": plan.artifact_id,
            "artifact_id": recovered_artifact_id,
            "method": _METHOD,
            "entropy_before": round(entropy_before, 3),
            "entropy_after": round(_entropy(recovered), 3),
            "format": "dotnet",
            "size": len(recovered),
        }
        return finish(
            {
                "success": True,
                "applicable": True,
                "degraded": False,
                "changed": True,
                "source_artifact_id": plan.artifact_id,
                "recovered_artifact_id": recovered_artifact_id,
                "source_size": source_size,
                "recovered_size": len(recovered),
                "method": _METHOD,
                "tool_version": _TOOL_VERSION,
            }
        )

    return dnlib_roundtrip


def _not_applicable(
    source_artifact_id: str, reason: str, *, source_size: int | None = None
) -> dict[str, object]:
    result: dict[str, object] = {
        "success": True,
        "applicable": False,
        "degraded": False,
        "changed": False,
        "reason": reason,
        "source_artifact_id": source_artifact_id,
        "tool_version": _TOOL_VERSION,
    }
    if source_size is not None:
        result["source_size"] = source_size
    return result


def _degraded(
    error_code: str,
    *,
    source_artifact_id: str | None = None,
    source_size: int | None = None,
    recovered_size: int | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {
        "success": False,
        "applicable": True,
        "degraded": True,
        "changed": False,
        "error_code": error_code,
        "error": _ERROR_MESSAGES[error_code],
        "tool_version": _TOOL_VERSION,
    }
    if source_artifact_id is not None:
        result["source_artifact_id"] = source_artifact_id
    if source_size is not None:
        result["source_size"] = source_size
    if recovered_size is not None:
        result["recovered_size"] = recovered_size
    return result


DNLIB_ROUNDTRIP_TOOL = ToolDescriptor(
    id="dnlib_roundtrip",
    description=(
        "Deterministically repair a protected .NET/CLR assembly with a dnlib "
        "metadata round-trip (load + rebuild the metadata tables) inside the "
        "analysis-workbench sandbox. First-pass recovery when de4dot fails."
    ),
    factory=build_dnlib_roundtrip,
    output_policy=OutputPolicy(max_chars=4_000, max_list_items=20),
)
