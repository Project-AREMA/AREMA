"""Sandboxed .NET deobfuscation of protected CLR assemblies via de4dot.

de4dot names a protector only as a side effect of processing it, and it exits 0
having named nothing both for a clean assembly and for a protector it cannot
handle. Those two are reported apart -- ``no_obfuscator`` versus
``protector_unsupported`` with the name -- so nothing downstream can read
"de4dot could not name it" as "the assembly is clean".
"""

from __future__ import annotations

import re
import struct
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
    DE4DOT_CALLED_KEY,
    DE4DOT_RESULT_KEY,
    UPX_PROVENANCE_PROMPT_KEY,
    advance_classification_artifact,
    parse_current_classification,
)
from reverse_engineering.tools.packer_signatures import detect_packer_bytes

if TYPE_CHECKING:
    from arema.registry.descriptors import ToolLike
    from arema.runtime.agent_factory import ToolBuildContext

# Pinned to the exact de4dot-cex release verified in Task 1 (the fork's GitHub
# release tag, images/deobfuscation-tools/Dockerfile's DE4DOT_VERSION arg):
# https://github.com/ViRb3/de4dot-cex/releases/tag/v4.0.0. Prefixed with the
# fork name (vs. upx's bare "5.2.0") because de4dot-cex is a distinct fork of
# upstream de4dot with its own versioning, not the canonical tool.
_TOOL_VERSION = "de4dot-cex-4.0.0"
MAX_DE4DOT_INPUT_BYTES = 512 * 1024 * 1024
_OUTPUT_NAME = "deobfuscated"
_MISSING = object()
# de4dot names the recognized protector on stdout ("Detected <Name> (...)").
# Confirm the exact wording in Task 1's probe; the SUCCESS decision does not rely
# on it alone -- applicability also requires a valid, changed CLR output.
_DETECTED_PATTERN = re.compile(r"Detected\s+(?P<name>.+?)\s*(?:\(|v\d|$)", re.MULTILINE)
_MAX_OBFUSCATOR_CHARS = 100
_ERROR_MESSAGES = {
    "invalid_classification": "The deobfuscation classification is invalid.",
    "artifact_unavailable": "The artifact is unavailable.",
    "sandbox_unavailable": "The deobfuscation sandbox is unavailable.",
    "output_invalid": "The recovered output is not a valid .NET assembly.",
    "de4dot_failed": "de4dot could not process the assembly.",
}


def build_de4dot_deobfuscate(context: ToolBuildContext) -> ToolLike:
    """Build the ``de4dot_deobfuscate`` tool for the live sandbox runtime."""

    def de4dot_deobfuscate(tool_context: ToolContext) -> dict[str, object]:
        """Deobfuscate a protected .NET assembly inside the deobfuscation sandbox."""
        state = tool_context.state
        try:
            cached = _cached_result(state, DE4DOT_CALLED_KEY, DE4DOT_RESULT_KEY)
        except ValueError:
            corrupt = _degraded_result("invalid_classification")
            state[DE4DOT_RESULT_KEY] = dict(corrupt)
            return dict(corrupt)
        if cached is not None:
            return cached
        state[DE4DOT_RESULT_KEY] = None
        state[DE4DOT_CALLED_KEY] = True

        def finish(result: dict[str, object]) -> dict[str, object]:
            state[DE4DOT_RESULT_KEY] = dict(result)
            return dict(result)

        try:
            plan = parse_current_classification(state)
        except ValueError:
            return finish(_degraded_result("invalid_classification"))

        state[CURRENT_ARTIFACT_PROMPT_KEY] = plan.artifact_id

        # Self-gate on the container format decided at intake. Managed-metadata
        # deobfuscation applies only to a .NET/CLR assembly.
        getter = getattr(state, "get", None)
        sample_format = getter(SAMPLE_FORMAT_KEY) if callable(getter) else None
        if sample_format != "dotnet":
            return finish(_not_applicable(plan.artifact_id, "not_dotnet"))

        try:
            source_size = (
                ArtifactStore(default_artifacts_root()).path_for(plan.artifact_id).stat().st_size
            )
        except (FileNotFoundError, OSError):
            return finish(
                _degraded_result("artifact_unavailable", source_artifact_id=plan.artifact_id)
            )
        if source_size > MAX_DE4DOT_INPUT_BYTES:
            return finish(
                _not_applicable(plan.artifact_id, "input_too_large", source_size=source_size)
            )

        try:
            staged = stage_artifact(
                context,
                plan.artifact_id,
                tool_context,
                tool_name="de4dot",
                max_input_bytes=MAX_DE4DOT_INPUT_BYTES,
            )
        except ArtifactInputTooLarge:
            return finish(
                _not_applicable(plan.artifact_id, "input_too_large", source_size=source_size)
            )
        except DeobfuscationUnavailable:
            return finish(
                _degraded_result(
                    "sandbox_unavailable",
                    source_artifact_id=plan.artifact_id,
                    source_size=source_size,
                )
            )
        except FileNotFoundError:
            return finish(
                _degraded_result(
                    "artifact_unavailable",
                    source_artifact_id=plan.artifact_id,
                    source_size=source_size,
                )
            )
        except (OSError, TimeoutError, ValueError, RuntimeError):
            return finish(
                _degraded_result(
                    "sandbox_unavailable",
                    source_artifact_id=plan.artifact_id,
                    source_size=source_size,
                )
            )

        output_path = f"{staged.work_dir}/{_OUTPUT_NAME}"
        try:
            result = run_argv(staged, ["de4dot", staged.input_path, "-o", output_path])
        except (OSError, TimeoutError, ValueError, RuntimeError):
            return finish(
                _degraded_result(
                    "sandbox_unavailable",
                    source_artifact_id=plan.artifact_id,
                    source_size=source_size,
                )
            )
        if result.exit_code != 0 or result.truncated:
            return finish(
                _degraded_result(
                    "de4dot_failed",
                    source_artifact_id=plan.artifact_id,
                    source_size=source_size,
                )
            )

        detected = _DETECTED_PATTERN.search(result.stdout)
        if detected is None:
            # de4dot named nothing. That is "clean" only when nothing else says
            # otherwise: a protector de4dot cannot process exits exactly like an
            # unobfuscated assembly, so the two must not share one reason. When
            # the artifact still carries a watermark, report it by name.
            protector = _named_protector(plan.artifact_id)
            if protector:
                return finish(
                    _not_applicable(
                        plan.artifact_id,
                        "protector_unsupported",
                        source_size=source_size,
                        protector_name=protector,
                    )
                )
            return finish(
                _not_applicable(plan.artifact_id, "no_obfuscator", source_size=source_size)
            )
        obfuscator = detected.group("name").strip()[:_MAX_OBFUSCATOR_CHARS] or "unknown"

        try:
            recovered = read_bounded_file(staged, output_path, max_bytes=MAX_RECOVERED_BYTES)
        except (FileNotFoundError, OSError, ValueError, RuntimeError):
            return finish(
                _degraded_result(
                    "output_invalid",
                    source_artifact_id=plan.artifact_id,
                    source_size=source_size,
                )
            )

        # detect_format_bytes raises struct.error on a malformed/truncated
        # header (e.g. an MZ-prefixed but short output). de4dot output is
        # untrusted input like any other sandbox artifact, so that must
        # degrade through this tool's own output_invalid path -- never
        # escape to the framework-level generic error handler, which would
        # leave DE4DOT_CALLED_KEY True with DE4DOT_RESULT_KEY still None.
        try:
            recovered_is_dotnet = bool(recovered) and detect_format_bytes(recovered) == "dotnet"
        except struct.error:
            recovered_is_dotnet = False
        if not recovered_is_dotnet:
            return finish(
                _degraded_result(
                    "output_invalid",
                    source_artifact_id=plan.artifact_id,
                    source_size=source_size,
                    recovered_size=len(recovered),
                )
            )

        try:
            recovered_artifact_id = ArtifactStore(default_artifacts_root()).acquire_bytes(recovered)
        except (FileNotFoundError, OSError, ValueError, RuntimeError):
            return finish(
                _degraded_result(
                    "artifact_unavailable",
                    source_artifact_id=plan.artifact_id,
                    source_size=source_size,
                    recovered_size=len(recovered),
                )
            )

        changed = recovered_artifact_id != plan.artifact_id
        if not changed:
            # de4dot named an obfuscator but produced byte-identical output: treat as
            # nothing recovered rather than a spurious advance.
            return finish(_not_applicable(plan.artifact_id, "no_change", source_size=source_size))
        state[CURRENT_ARTIFACT_KEY] = recovered_artifact_id
        state[CURRENT_ARTIFACT_PROMPT_KEY] = recovered_artifact_id
        advance_classification_artifact(state, plan, recovered_artifact_id)
        state[UPX_PROVENANCE_PROMPT_KEY] = (
            f"de4dot_deobfuscate source={plan.artifact_id} "
            f"destination={recovered_artifact_id} obfuscator={obfuscator}"
        )
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
                "obfuscator_name": obfuscator,
                "tool_version": _TOOL_VERSION,
            }
        )

    return de4dot_deobfuscate


def _named_protector(artifact_id: str) -> str:
    """Name the protector on the artifact de4dot actually ran on, or return "".

    Deliberately re-reads instead of trusting the ``sample:packer`` decided at
    ingest: by the time de4dot runs, the loop may have peeled an outer layer, so
    the ingest name can describe bytes that are no longer under analysis. An
    unreadable artifact degrades to "" -- this only ever adds a name, never
    blocks a result.
    """
    try:
        source = ArtifactStore(default_artifacts_root()).path_for(artifact_id)
        packer = detect_packer_bytes(source.read_bytes())
    except OSError:
        return ""
    return str(packer["name"]) if packer["detected"] else ""


def _not_applicable(
    source_artifact_id: str,
    reason: str,
    *,
    source_size: int | None = None,
    protector_name: str | None = None,
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
    if protector_name is not None:
        result["protector_name"] = protector_name
    return result


def _degraded_result(
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


def _cached_result(state: object, called_key: str, result_key: str) -> dict[str, object] | None:
    getter = getattr(state, "get", None)
    called = getter(called_key, _MISSING) if callable(getter) else _MISSING
    if called is _MISSING or called is False:
        return None
    if called is not True:
        raise ValueError("invalid de4dot call marker")
    cached = getter(result_key) if callable(getter) else None
    if not isinstance(cached, dict) or not _valid_cached_result(cached):
        raise ValueError("invalid de4dot result cache")
    return dict(cached)


def _valid_cached_result(result: dict[object, object]) -> bool:
    """Validate the locked de4dot response before reusing an in-iteration cache."""
    base = {"success", "applicable", "degraded", "changed", "tool_version"}
    if (
        not isinstance(result.get("success"), bool)
        or not isinstance(result.get("applicable"), bool)
        or not isinstance(result.get("degraded"), bool)
        or not isinstance(result.get("changed"), bool)
        or result.get("tool_version") != _TOOL_VERSION
    ):
        return False
    success, applicable, degraded, changed = (
        result["success"],
        result["applicable"],
        result["degraded"],
        result["changed"],
    )
    if success is False:
        required = base | {"error_code", "error"}
        optional = {"source_artifact_id", "source_size", "recovered_size"}
        if (
            not required <= set(result) <= required | optional
            or applicable is not True
            or degraded is not True
            or changed is not False
        ):
            return False
        code = result["error_code"]
        if (
            not isinstance(code, str)
            or code not in _ERROR_MESSAGES
            or result["error"] != _ERROR_MESSAGES[code]
        ):
            return False
        if "source_artifact_id" in result and not _artifact_id(result["source_artifact_id"]):
            return False
        return all(
            k not in result or _nonnegative_int(result[k])
            for k in ("source_size", "recovered_size")
        )
    if applicable is True:
        expected = base | {
            "source_artifact_id",
            "recovered_artifact_id",
            "source_size",
            "recovered_size",
            "obfuscator_name",
        }
        if set(result) != expected or degraded is not False or changed is not True:
            return False
        if not _artifact_id(result["source_artifact_id"]) or not _artifact_id(
            result["recovered_artifact_id"]
        ):
            return False
        if result["source_artifact_id"] == result["recovered_artifact_id"]:
            return False
        if not isinstance(result["obfuscator_name"], str) or not result["obfuscator_name"]:
            return False
        return _nonnegative_int(result["source_size"]) and _nonnegative_int(
            result["recovered_size"]
        )
    # applicable is False (non_applicable)
    if degraded is not False or changed is not False or success is not True:
        return False
    reason = result.get("reason")
    expected = base | {"reason", "source_artifact_id"}
    if reason in {"input_too_large", "no_obfuscator", "no_change"}:
        expected.add("source_size")
    elif reason == "protector_unsupported":
        expected |= {"source_size", "protector_name"}
    elif reason != "not_dotnet":
        return False
    if set(result) != expected or not _artifact_id(result["source_artifact_id"]):
        return False
    if reason == "protector_unsupported" and not _nonempty_string(result["protector_name"]):
        return False
    return "source_size" not in result or _nonnegative_int(result["source_size"])


def _artifact_id(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _nonnegative_int(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= 0


def _nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value)


DE4DOT_DEOBFUSCATE_TOOL = ToolDescriptor(
    id="de4dot_deobfuscate",
    description="Deobfuscate a protected .NET/CLR assembly with de4dot inside the deobfuscation sandbox.",
    factory=build_de4dot_deobfuscate,
    output_policy=OutputPolicy(max_chars=4_000, max_list_items=20),
)
