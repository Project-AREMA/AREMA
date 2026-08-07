"""Sandboxed recovery of UPX-packed artifacts."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from google.adk.tools.tool_context import (
    ToolContext,  # noqa: TC002 - ADK resolves annotations at runtime
)

from arema.registry.descriptors import OutputPolicy, ToolDescriptor
from reverse_engineering.artifacts import ArtifactStore, default_artifacts_root
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
    UPX_CALLED_KEY,
    UPX_CHANGED_KEY,
    UPX_DEGRADED_KEY,
    UPX_PROVENANCE_PROMPT_KEY,
    UPX_RESULT_KEY,
    advance_classification_artifact,
    parse_current_classification,
)

if TYPE_CHECKING:
    from arema.registry.descriptors import ToolLike
    from arema.runtime.agent_factory import ToolBuildContext


_TOOL_VERSION = "5.2.0"
MAX_UPX_INPUT_BYTES = 512 * 1024 * 1024
_OUTPUT_NAME = "unpacked"
_NOT_PACKED_MARKERS = ("notpackedexception", "not packed by upx")
_MISSING = object()
# The provenance slot (``UPX_PROVENANCE_PROMPT_KEY``) is shared across every
# recovery producer in the deobfuscation loop, not just UPX: ``register.py``'s
# ``scripted_recover source=<sha> destination=<sha> method=<...>`` and
# ``dotnet.py``'s ``de4dot_deobfuscate source=<sha> destination=<sha>
# obfuscator=<...>`` write here too. The stale-provenance guard below runs on
# EVERY upx_unpack call, so this pattern must recognise every internally-generated
# shape (keyed on its destination sha) or a legitimate record from another
# producer would be wiped on the next loop round. ``method=<...>`` /
# ``obfuscator=<...>`` are each a bounded single line (see
# ``register._bounded_method`` and ``dotnet``'s ``_MAX_OBFUSCATOR_CHARS`` cap); a
# fresh upx record has no trailing suffix, so the tail group is optional.
_PROVENANCE_PATTERN = re.compile(
    r"(?:upx_unpack|scripted_recover|de4dot_deobfuscate) "
    r"source=([0-9a-f]{64}) destination=([0-9a-f]{64})"
    r"(?: (?:method|obfuscator)=.*)?"
)
_ERROR_MESSAGES = {
    "invalid_classification": "The deobfuscation classification is invalid.",
    "artifact_unavailable": "The artifact is unavailable.",
    "sandbox_unavailable": "The deobfuscation sandbox is unavailable.",
    "output_invalid": "The recovered output is invalid.",
    "upx_failed": "UPX could not unpack the artifact.",
}


def build_upx_unpack(context: ToolBuildContext) -> ToolLike:
    """Build the ``upx_unpack`` function tool for the live sandbox runtime."""

    def upx_unpack(tool_context: ToolContext) -> dict[str, object]:
        """Unpack a UPX-packed artifact inside the Kubernetes deobfuscation sandbox."""
        state = tool_context.state
        try:
            cached = _cached_result(state, UPX_CALLED_KEY, UPX_RESULT_KEY)
        except ValueError:
            corrupt_result = _degraded_result("invalid_classification")
            state[UPX_CHANGED_KEY] = False
            state[UPX_DEGRADED_KEY] = True
            state[UPX_RESULT_KEY] = dict(corrupt_result)
            return dict(corrupt_result)
        if cached is not None:
            state[UPX_CHANGED_KEY] = cached["changed"]
            state[UPX_DEGRADED_KEY] = cached["degraded"]
            return cached
        state[UPX_RESULT_KEY] = None
        state[UPX_CHANGED_KEY] = False
        state[UPX_DEGRADED_KEY] = False
        state[UPX_CALLED_KEY] = True

        def finish(result: dict[str, object]) -> dict[str, object]:
            state[UPX_RESULT_KEY] = dict(result)
            return dict(result)

        try:
            plan = parse_current_classification(state)
        except ValueError:
            state[UPX_DEGRADED_KEY] = True
            return finish(_degraded_result("invalid_classification"))

        state[CURRENT_ARTIFACT_PROMPT_KEY] = plan.artifact_id
        _discard_stale_provenance(state, plan.artifact_id)
        if not plan.upx:
            return finish(
                {
                    "success": True,
                    "applicable": False,
                    "degraded": False,
                    "changed": False,
                    "reason": "plan_disabled",
                    "source_artifact_id": plan.artifact_id,
                    "tool_version": _TOOL_VERSION,
                }
            )

        try:
            source_size = (
                ArtifactStore(default_artifacts_root()).path_for(plan.artifact_id).stat().st_size
            )
        except (FileNotFoundError, OSError):
            state[UPX_DEGRADED_KEY] = True
            return finish(
                _degraded_result("artifact_unavailable", source_artifact_id=plan.artifact_id)
            )
        if source_size > MAX_UPX_INPUT_BYTES:
            return finish(
                {
                    "success": True,
                    "applicable": False,
                    "degraded": False,
                    "changed": False,
                    "reason": "input_too_large",
                    "source_artifact_id": plan.artifact_id,
                    "source_size": source_size,
                    "tool_version": _TOOL_VERSION,
                }
            )

        try:
            staged = stage_artifact(
                context,
                plan.artifact_id,
                tool_context,
                tool_name="upx",
                max_input_bytes=MAX_UPX_INPUT_BYTES,
            )
        except ArtifactInputTooLarge:
            return finish(
                {
                    "success": True,
                    "applicable": False,
                    "degraded": False,
                    "changed": False,
                    "reason": "input_too_large",
                    "source_artifact_id": plan.artifact_id,
                    "source_size": source_size,
                    "tool_version": _TOOL_VERSION,
                }
            )
        except DeobfuscationUnavailable:
            state[UPX_DEGRADED_KEY] = True
            return finish(
                _degraded_result(
                    "sandbox_unavailable",
                    source_artifact_id=plan.artifact_id,
                    source_size=source_size,
                )
            )
        except FileNotFoundError:
            state[UPX_DEGRADED_KEY] = True
            return finish(
                _degraded_result(
                    "artifact_unavailable",
                    source_artifact_id=plan.artifact_id,
                    source_size=source_size,
                )
            )
        except (OSError, TimeoutError, ValueError, RuntimeError):
            state[UPX_DEGRADED_KEY] = True
            return finish(
                _degraded_result(
                    "sandbox_unavailable",
                    source_artifact_id=plan.artifact_id,
                    source_size=source_size,
                )
            )

        output_path = f"{staged.work_dir}/{_OUTPUT_NAME}"
        try:
            result = run_argv(
                staged,
                ["upx", "-d", "-o", output_path, staged.input_path],
            )
        except (OSError, TimeoutError, ValueError, RuntimeError):
            state[UPX_DEGRADED_KEY] = True
            return finish(
                _degraded_result(
                    "sandbox_unavailable",
                    source_artifact_id=plan.artifact_id,
                    source_size=source_size,
                )
            )

        if any(marker in result.stderr.lower() for marker in _NOT_PACKED_MARKERS):
            return finish(
                {
                    "success": True,
                    "applicable": False,
                    "degraded": False,
                    "changed": False,
                    "reason": "not_packed",
                    "source_artifact_id": plan.artifact_id,
                    "source_size": source_size,
                    "tool_version": _TOOL_VERSION,
                }
            )
        if result.exit_code != 0 or result.truncated:
            state[UPX_DEGRADED_KEY] = True
            return finish(
                _degraded_result(
                    "upx_failed",
                    source_artifact_id=plan.artifact_id,
                    source_size=source_size,
                )
            )

        try:
            recovered = read_bounded_file(staged, output_path, max_bytes=MAX_RECOVERED_BYTES)
        except (FileNotFoundError, OSError, ValueError, RuntimeError):
            state[UPX_DEGRADED_KEY] = True
            return finish(
                _degraded_result(
                    "output_invalid",
                    source_artifact_id=plan.artifact_id,
                    source_size=source_size,
                )
            )

        if not recovered:
            state[UPX_DEGRADED_KEY] = True
            return finish(
                _degraded_result(
                    "output_invalid",
                    source_artifact_id=plan.artifact_id,
                    source_size=source_size,
                    recovered_size=0,
                )
            )

        try:
            recovered_artifact_id = ArtifactStore(default_artifacts_root()).acquire_bytes(recovered)
        except (FileNotFoundError, OSError, ValueError, RuntimeError):
            state[UPX_DEGRADED_KEY] = True
            return finish(
                _degraded_result(
                    "artifact_unavailable",
                    source_artifact_id=plan.artifact_id,
                    source_size=source_size,
                    recovered_size=len(recovered),
                )
            )

        changed = recovered_artifact_id != plan.artifact_id
        state[CURRENT_ARTIFACT_KEY] = recovered_artifact_id
        state[CURRENT_ARTIFACT_PROMPT_KEY] = recovered_artifact_id
        state[UPX_CHANGED_KEY] = changed
        if changed:
            advance_classification_artifact(state, plan, recovered_artifact_id)
            state[UPX_PROVENANCE_PROMPT_KEY] = (
                f"upx_unpack source={plan.artifact_id} destination={recovered_artifact_id}"
            )
        return finish(
            {
                "success": True,
                "applicable": True,
                "degraded": False,
                "changed": changed,
                "source_artifact_id": plan.artifact_id,
                "recovered_artifact_id": recovered_artifact_id,
                "source_size": source_size,
                "recovered_size": len(recovered),
                "tool_version": _TOOL_VERSION,
            }
        )

    return upx_unpack


def _degraded_result(
    error_code: str,
    *,
    source_artifact_id: str | None = None,
    source_size: int | None = None,
    recovered_size: int | None = None,
) -> dict[str, object]:
    """Return a stable, public failure result expected by the loop gate."""
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
    """Return a copied first result, rejecting corrupt duplicate-call state."""
    getter = getattr(state, "get", None)
    called = getter(called_key, _MISSING) if callable(getter) else _MISSING
    if called is _MISSING or called is False:
        return None
    if called is not True:
        raise ValueError("invalid UPX call marker")
    cached = getter(result_key) if callable(getter) else None
    if not isinstance(cached, dict) or not _valid_cached_result(cached):
        raise ValueError("invalid UPX result cache")
    return dict(cached)


def _valid_cached_result(result: dict[object, object]) -> bool:
    """Validate the locked UPX response before reusing an in-iteration cache."""
    base_keys = {
        "success",
        "applicable",
        "degraded",
        "changed",
        "tool_version",
    }
    if (
        not isinstance(result.get("success"), bool)
        or not isinstance(result.get("applicable"), bool)
        or not isinstance(result.get("degraded"), bool)
        or not isinstance(result.get("changed"), bool)
        or result.get("tool_version") != _TOOL_VERSION
    ):
        return False
    success = result["success"]
    applicable = result["applicable"]
    degraded = result["degraded"]
    changed = result["changed"]
    if success is False:
        required = base_keys | {"error_code", "error"}
        optional = {"source_artifact_id", "source_size", "recovered_size"}
        if (
            not required <= set(result) <= required | optional
            or applicable is not True
            or degraded is not True
            or changed is not False
        ):
            return False
        error_code = result["error_code"]
        if (
            not isinstance(error_code, str)
            or error_code not in _ERROR_MESSAGES
            or result["error"] != _ERROR_MESSAGES[error_code]
        ):
            return False
        if "source_artifact_id" in result and not _artifact_id(result["source_artifact_id"]):
            return False
        return all(
            key not in result or _nonnegative_int(result[key])
            for key in ("source_size", "recovered_size")
        )
    elif applicable is True:
        expected = base_keys | {
            "source_artifact_id",
            "recovered_artifact_id",
            "source_size",
            "recovered_size",
        }
        if set(result) != expected or degraded is not False:
            return False
        source_id = result["source_artifact_id"]
        recovered_id = result["recovered_artifact_id"]
        if not _artifact_id(source_id) or not _artifact_id(recovered_id):
            return False
        if not _nonnegative_int(result["source_size"]) or not _nonnegative_int(
            result["recovered_size"]
        ):
            return False
        return changed is (source_id != recovered_id)
    else:
        if degraded is not False or changed is not False or success is not True:
            return False
        reason = result.get("reason")
        expected = base_keys | {"reason", "source_artifact_id"}
        if reason in {"input_too_large", "not_packed"}:
            expected.add("source_size")
        elif reason != "plan_disabled":
            return False
        if set(result) != expected or not _artifact_id(result["source_artifact_id"]):
            return False
        return "source_size" not in result or _nonnegative_int(result["source_size"])


def _artifact_id(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _nonnegative_int(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= 0


def _discard_stale_provenance(state: object, current_artifact_id: str) -> None:
    """Preserve only internally shaped provenance for the canonical destination.

    Recognises every internal recovery-producer shape sharing this slot
    (``upx_unpack`` and ``scripted_recover``); provenance whose destination is the
    current artifact is kept, anything else is wiped so it cannot leak across
    unrelated artifacts.
    """
    getter = getattr(state, "get", None)
    existing = getter(UPX_PROVENANCE_PROMPT_KEY, _MISSING) if callable(getter) else _MISSING
    if existing is _MISSING or existing == "":
        return
    match = _PROVENANCE_PATTERN.fullmatch(existing) if isinstance(existing, str) else None
    if match is None or match.group(2) != current_artifact_id:
        state[UPX_PROVENANCE_PROMPT_KEY] = ""  # type: ignore[index]


UPX_UNPACK_TOOL = ToolDescriptor(
    id="upx_unpack",
    description="Unpack a UPX-packed artifact inside the Kubernetes deobfuscation sandbox.",
    factory=build_upx_unpack,
    output_policy=OutputPolicy(max_chars=4_000, max_list_items=20),
)
