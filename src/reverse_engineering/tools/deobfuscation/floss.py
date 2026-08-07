"""Sandboxed, structured FLOSS string recovery for PE artifacts."""

from __future__ import annotations

import hashlib
import json
import re
from typing import TYPE_CHECKING, cast

from google.adk.tools.tool_context import (
    ToolContext,  # noqa: TC002 - ADK resolves annotations at runtime
)

from arema.registry.descriptors import OutputPolicy, ToolDescriptor
from reverse_engineering.artifacts import ArtifactStore, default_artifacts_root
from reverse_engineering.tools.deobfuscation.runtime import (
    MAX_RESULT_BYTES,
    ArtifactInputTooLarge,
    DeobfuscationUnavailable,
    read_bounded_file,
    run_argv_to_file,
    stage_artifact,
)
from reverse_engineering.tools.deobfuscation.state import (
    FLOSS_CALLED_KEY,
    FLOSS_COUNT_KEY,
    FLOSS_DEGRADED_KEY,
    FLOSS_RESULT_KEY,
    FLOSS_SEEN_FINGERPRINTS_KEY,
    parse_current_classification,
)

if TYPE_CHECKING:
    from pathlib import Path

    from arema.registry.descriptors import ToolLike
    from arema.runtime.agent_factory import ToolBuildContext


MAX_FLOSS_INPUT_BYTES = 16 * 1024 * 1024
MAX_INPUT_BYTES = MAX_FLOSS_INPUT_BYTES
MAX_STRINGS = 200
MAX_SEEN_FINGERPRINTS = 2_000
_TOOL_VERSION = "3.1.1"
_OUTPUT_NAME = "floss.json"
_MISSING = object()
# PE layout: the DOS header holds the PE-header file offset (e_lfanew) at 0x3C, and
# the PE header can never begin inside the 64-byte DOS header.
_PE_LFANEW_OFFSET = 0x3C
_PE_MIN_HEADER_OFFSET = 0x40
_MAX_UNSIGNED_64 = 2**64 - 1
_MIN_SIGNED_64 = -(2**63)
_MAX_SIGNED_64 = 2**63 - 1
_DECODED_ADDRESS_TYPES = frozenset({"STACK", "GLOBAL", "HEAP"})
_COUNTS_EMPTY = {"decoded": 0, "stack": 0, "tight": 0}
_FINGERPRINT_PATTERN = re.compile(r"[0-9a-f]{64}")
_ERROR_MESSAGES = {
    "invalid_classification": "The deobfuscation classification is invalid.",
    "artifact_unavailable": "The artifact is unavailable.",
    "sandbox_unavailable": "The deobfuscation sandbox is unavailable.",
    "result_invalid": "The FLOSS result is invalid.",
    "floss_failed": "FLOSS could not recover strings from the artifact.",
    "invalid_seen_state": "The FLOSS progress state is invalid.",
    "seen_state_overflow": "The FLOSS progress state exceeded its safe bound.",
}


def _is_pe(path: Path) -> bool:
    """Return whether *path* has the minimum unambiguous PE signatures."""
    with path.open("rb") as source:
        if source.read(2) != b"MZ":
            return False
        source.seek(_PE_LFANEW_OFFSET)
        offset_bytes = source.read(4)
        if len(offset_bytes) != 4:
            return False
        pe_offset = int.from_bytes(offset_bytes, "little")
        if pe_offset < _PE_MIN_HEADER_OFFSET:
            return False
        source.seek(pe_offset)
        return source.read(4) == b"PE\0\0"


def build_floss_decode(context: ToolBuildContext) -> ToolLike:
    """Build the ``floss_decode`` function tool for the live sandbox runtime."""

    def floss_decode(tool_context: ToolContext) -> dict[str, object]:
        """Recover PE decoded, stack, and tight strings with Mandiant FLOSS."""
        state = tool_context.state
        try:
            cached = _cached_result(state)
        except ValueError:
            corrupt_result = _degraded_result("invalid_classification")
            state[FLOSS_COUNT_KEY] = 0
            state[FLOSS_DEGRADED_KEY] = True
            state[FLOSS_RESULT_KEY] = dict(corrupt_result)
            return dict(corrupt_result)
        if cached is not None:
            state[FLOSS_COUNT_KEY] = cached["new_count"]
            state[FLOSS_DEGRADED_KEY] = cached["degraded"]
            return cached
        state[FLOSS_RESULT_KEY] = None
        state[FLOSS_COUNT_KEY] = 0
        state[FLOSS_DEGRADED_KEY] = False
        state[FLOSS_CALLED_KEY] = True

        def finish(result: dict[str, object]) -> dict[str, object]:
            state[FLOSS_RESULT_KEY] = dict(result)
            return dict(result)

        try:
            plan = parse_current_classification(state)
        except ValueError:
            state[FLOSS_DEGRADED_KEY] = True
            return finish(_degraded_result("invalid_classification"))

        try:
            seen_fingerprints = _read_seen_fingerprints(state)
        except ValueError:
            state[FLOSS_DEGRADED_KEY] = True
            return finish(
                _degraded_result(
                    "invalid_seen_state",
                    source_artifact_id=plan.artifact_id,
                )
            )

        artifact_id = plan.artifact_id

        try:
            source = ArtifactStore(default_artifacts_root()).path_for(artifact_id)
            source_size = source.stat().st_size
            if source_size > MAX_INPUT_BYTES:
                return finish(
                    _non_applicable(
                        "input_too_large",
                        source_artifact_id=artifact_id,
                        source_size=source_size,
                        format_name="unknown",
                    )
                )
        except (FileNotFoundError, OSError):
            state[FLOSS_DEGRADED_KEY] = True
            return finish(_degraded_result("artifact_unavailable", source_artifact_id=artifact_id))

        # FLOSS eligibility is a deterministic fact -- FLOSS is PE-only -- so it is
        # decided by the actual bytes, never by the classifier LLM's `floss` flag,
        # which intermittently marks a real PE not-floss and used to skip recovery
        # entirely (losing every decoded string).
        try:
            is_pe = _is_pe(source)
        except (FileNotFoundError, OSError):
            state[FLOSS_DEGRADED_KEY] = True
            return finish(
                _degraded_result(
                    "artifact_unavailable",
                    source_artifact_id=artifact_id,
                    source_size=source_size,
                )
            )

        if not is_pe:
            return finish(
                _non_applicable(
                    "not_pe",
                    source_artifact_id=artifact_id,
                    source_size=source_size,
                    format_name="unsupported",
                )
            )

        try:
            staged = stage_artifact(
                context,
                artifact_id,
                tool_context,
                tool_name="floss",
                max_input_bytes=MAX_FLOSS_INPUT_BYTES,
            )
        except ArtifactInputTooLarge:
            return finish(
                _non_applicable(
                    "input_too_large",
                    source_artifact_id=artifact_id,
                    source_size=source_size,
                    format_name="pe",
                )
            )
        except DeobfuscationUnavailable:
            state[FLOSS_DEGRADED_KEY] = True
            return finish(
                _degraded_result(
                    "sandbox_unavailable",
                    source_artifact_id=artifact_id,
                    source_size=source_size,
                    format_name="pe",
                )
            )
        except FileNotFoundError:
            state[FLOSS_DEGRADED_KEY] = True
            return finish(
                _degraded_result(
                    "artifact_unavailable",
                    source_artifact_id=artifact_id,
                    source_size=source_size,
                    format_name="pe",
                )
            )
        except (OSError, TimeoutError, RuntimeError):
            state[FLOSS_DEGRADED_KEY] = True
            return finish(
                _degraded_result(
                    "sandbox_unavailable",
                    source_artifact_id=artifact_id,
                    source_size=source_size,
                    format_name="pe",
                )
            )

        output_path = f"{staged.work_dir}/{_OUTPUT_NAME}"
        try:
            result = run_argv_to_file(
                staged,
                [
                    "floss",
                    "--json",
                    "--only",
                    "decoded",
                    "stack",
                    "tight",
                    "--",
                    staged.input_path,
                ],
                output_path,
            )
        except (OSError, TimeoutError, RuntimeError):
            state[FLOSS_DEGRADED_KEY] = True
            return finish(
                _degraded_result(
                    "sandbox_unavailable",
                    source_artifact_id=artifact_id,
                    source_size=source_size,
                    format_name="pe",
                )
            )

        if result.exit_code != 0 or result.truncated:
            state[FLOSS_DEGRADED_KEY] = True
            return finish(
                _degraded_result(
                    "floss_failed",
                    source_artifact_id=artifact_id,
                    source_size=source_size,
                    format_name="pe",
                )
            )

        try:
            payload = read_bounded_file(staged, output_path, max_bytes=MAX_RESULT_BYTES)
            parsed = json.loads(payload.decode("utf-8"), parse_constant=_reject_json_constant)
            records, counts, truncated = _normalize_result(parsed)
        except (FileNotFoundError, OSError, UnicodeError, ValueError, RuntimeError):
            state[FLOSS_DEGRADED_KEY] = True
            return finish(
                _degraded_result(
                    "result_invalid",
                    source_artifact_id=artifact_id,
                    source_size=source_size,
                    format_name="pe",
                )
            )

        fingerprints = {_record_fingerprint(record) for record in records}
        new_fingerprints = fingerprints - seen_fingerprints
        combined = seen_fingerprints | fingerprints
        if len(combined) > MAX_SEEN_FINGERPRINTS:
            state[FLOSS_DEGRADED_KEY] = True
            return finish(
                _degraded_result(
                    "seen_state_overflow",
                    source_artifact_id=artifact_id,
                    source_size=source_size,
                    format_name="pe",
                )
            )
        new_count = len(new_fingerprints)
        state[FLOSS_SEEN_FINGERPRINTS_KEY] = sorted(combined)
        state[FLOSS_COUNT_KEY] = new_count
        return finish(
            {
                "success": True,
                "applicable": True,
                "degraded": False,
                "source_artifact_id": artifact_id,
                "source_size": source_size,
                "format": "pe",
                "tool_version": _TOOL_VERSION,
                "new_count": new_count,
                "counts": counts,
                "records": records,
                "truncated": truncated,
            }
        )

    return floss_decode


def _cached_result(state: object) -> dict[str, object] | None:
    getter = getattr(state, "get", None)
    called = getter(FLOSS_CALLED_KEY, _MISSING) if callable(getter) else _MISSING
    if called is _MISSING or called is False:
        return None
    if called is not True:
        raise ValueError("invalid FLOSS call marker")
    cached = getter(FLOSS_RESULT_KEY) if callable(getter) else None
    if not isinstance(cached, dict) or not _valid_cached_result(cached):
        raise ValueError("invalid FLOSS result cache")
    return dict(cached)


def _valid_cached_result(result: dict[object, object]) -> bool:
    """Validate the locked FLOSS response before reusing an in-iteration cache."""
    common_keys = {
        "success",
        "applicable",
        "degraded",
        "format",
        "tool_version",
        "new_count",
        "counts",
        "records",
        "truncated",
    }
    new_count = result.get("new_count")
    if (
        not isinstance(result.get("success"), bool)
        or not isinstance(result.get("applicable"), bool)
        or not isinstance(result.get("degraded"), bool)
        or result.get("tool_version") != _TOOL_VERSION
        or not _nonnegative_int(new_count)
        or not isinstance(result.get("truncated"), bool)
    ):
        return False
    counts = result.get("counts")
    if (
        not isinstance(counts, dict)
        or set(counts) != set(_COUNTS_EMPTY)
        or any(not _nonnegative_int(value) for value in counts.values())
    ):
        return False
    records = result.get("records")
    if (
        not isinstance(records, list)
        or len(records) > MAX_STRINGS
        or any(not _valid_public_record(record) for record in records)
        or not isinstance(new_count, int)
        or new_count > len(records)
    ):
        return False
    success = result["success"]
    applicable = result["applicable"]
    degraded = result["degraded"]
    if success is False:
        required = common_keys | {"error_code", "error"}
        optional = {"source_artifact_id", "source_size"}
        if (
            not required <= set(result) <= required | optional
            or applicable is not True
            or degraded is not True
            or result["format"] not in {"unknown", "pe"}
        ):
            return False
        error_code = result["error_code"]
        if (
            not isinstance(error_code, str)
            or error_code not in _ERROR_MESSAGES
            or result["error"] != _ERROR_MESSAGES[error_code]
            or result["new_count"] != 0
            or records
            or counts != _COUNTS_EMPTY
            or result["truncated"] is not False
        ):
            return False
        if "source_artifact_id" in result and not _artifact_id(result["source_artifact_id"]):
            return False
        return "source_size" not in result or _nonnegative_int(result["source_size"])
    elif applicable is True:
        expected = common_keys | {"source_artifact_id", "source_size"}
        if set(result) != expected or degraded is not False or result["format"] != "pe":
            return False
        if not _artifact_id(result["source_artifact_id"]) or not _nonnegative_int(
            result["source_size"]
        ):
            return False
        typed_records = cast("list[dict[str, str]]", records)
        returned_counts = {
            kind: sum(record["type"] == kind for record in typed_records) for kind in _COUNTS_EMPTY
        }
        if any(returned_counts[kind] > counts[kind] for kind in _COUNTS_EMPTY):
            return False
        total_count = sum(counts.values())
        if result["truncated"] is not (total_count > MAX_STRINGS):
            return False
        if len(records) != min(total_count, MAX_STRINGS):
            return False
        unique_records = len({_record_fingerprint(record) for record in typed_records})
        return isinstance(new_count, int) and new_count <= unique_records
    else:
        if degraded is not False or success is not True:
            return False
        reason = result.get("reason")
        expected = common_keys | {"reason", "source_artifact_id"}
        expected_format: set[str]
        if reason == "plan_disabled":
            expected_format = {"unknown"}
        elif reason == "input_too_large":
            expected.add("source_size")
            expected_format = {"unknown", "pe"}
        elif reason == "not_pe":
            expected.add("source_size")
            expected_format = {"unsupported"}
        else:
            return False
        if (
            set(result) != expected
            or result["format"] not in expected_format
            or not _artifact_id(result["source_artifact_id"])
            or result["new_count"] != 0
            or records
            or counts != _COUNTS_EMPTY
            or result["truncated"] is not False
        ):
            return False
        return "source_size" not in result or _nonnegative_int(result["source_size"])


def _valid_public_record(record: object) -> bool:
    return (
        isinstance(record, dict)
        and set(record) == {"type", "string", "encoding", "function", "location"}
        and record.get("type") in {"decoded", "stack", "tight"}
        and all(
            _nonempty_string(record.get(key))
            for key in ("string", "encoding", "function", "location")
        )
    )


def _artifact_id(value: object) -> bool:
    return isinstance(value, str) and _FINGERPRINT_PATTERN.fullmatch(value) is not None


def _nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _nonnegative_int(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= 0


def _reject_json_constant(constant: str) -> None:
    """Reject JSON extensions that Python's parser otherwise accepts."""
    raise ValueError(f"invalid JSON constant: {constant}")


def _non_applicable(
    reason: str,
    *,
    source_artifact_id: str,
    format_name: str,
    source_size: int | None = None,
) -> dict[str, object]:
    """Return a stable, empty result for inputs FLOSS does not process."""
    result: dict[str, object] = {
        "success": True,
        "applicable": False,
        "degraded": False,
        "reason": reason,
        "source_artifact_id": source_artifact_id,
        "format": format_name,
        "tool_version": _TOOL_VERSION,
        "new_count": 0,
        "counts": dict(_COUNTS_EMPTY),
        "records": [],
        "truncated": False,
    }
    if source_size is not None:
        result["source_size"] = source_size
    return result


def _degraded_result(
    error_code: str,
    *,
    source_artifact_id: str | None = None,
    source_size: int | None = None,
    format_name: str = "unknown",
) -> dict[str, object]:
    """Return a stable public failure result without backend diagnostics."""
    result: dict[str, object] = {
        "success": False,
        "applicable": True,
        "degraded": True,
        "error_code": error_code,
        "error": _ERROR_MESSAGES[error_code],
        "format": format_name,
        "tool_version": _TOOL_VERSION,
        "new_count": 0,
        "counts": dict(_COUNTS_EMPTY),
        "records": [],
        "truncated": False,
    }
    if source_artifact_id is not None:
        result["source_artifact_id"] = source_artifact_id
    if source_size is not None:
        result["source_size"] = source_size
    return result


def _read_seen_fingerprints(state: object) -> set[str]:
    getter = getattr(state, "get", None)
    raw = getter(FLOSS_SEEN_FINGERPRINTS_KEY, _MISSING) if callable(getter) else _MISSING
    if raw is _MISSING:
        return set()
    if not isinstance(raw, list) or len(raw) > MAX_SEEN_FINGERPRINTS:
        raise ValueError("invalid FLOSS fingerprint state")
    if any(
        not isinstance(value, str) or _FINGERPRINT_PATTERN.fullmatch(value) is None for value in raw
    ):
        raise ValueError("invalid FLOSS fingerprint state")
    values = set(raw)
    if len(values) != len(raw):
        raise ValueError("invalid FLOSS fingerprint state")
    return values


def _record_fingerprint(record: dict[str, str]) -> str:
    encoded = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _normalize_result(payload: object) -> tuple[list[dict[str, str]], dict[str, int], bool]:
    """Validate FLOSS JSON and return deterministic, bounded public records."""
    if not isinstance(payload, dict):
        raise ValueError("FLOSS result must be an object")
    _validate_metadata(_require_object(payload, "metadata"))
    _require_object(payload, "analysis")
    strings = _require_object(payload, "strings")
    raw_groups = {
        "decoded": _require_list(strings, "decoded_strings"),
        "stack": _require_list(strings, "stack_strings"),
        "tight": _require_list(strings, "tight_strings"),
    }
    normalized: list[dict[str, str]] = []
    totals: dict[str, int] = {}
    for kind in ("decoded", "stack", "tight"):
        total = 0
        for record in raw_groups[kind]:
            text, encoding, function, location = _validate_record(kind, record)
            total += 1
            if len(normalized) < MAX_STRINGS:
                normalized.append(_public_record(kind, text, encoding, function, location))
        totals[kind] = total
    return normalized, totals, sum(totals.values()) > MAX_STRINGS


def _require_object(data: dict[object, object], key: str) -> dict[object, object]:
    value = data.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"FLOSS result {key} must be an object")
    return value


def _require_list(data: dict[object, object], key: str) -> list[object]:
    value = data.get(key)
    if not isinstance(value, list):
        raise ValueError(f"FLOSS result {key} must be a list")
    return value


def _validate_record(kind: str, record: object) -> tuple[str, str, int, int]:
    if not isinstance(record, dict):
        raise ValueError("FLOSS string record must be an object")
    text = _require_nonempty_string(record, "string")
    encoding = _require_nonempty_string(record, "encoding")
    if kind == "decoded":
        _require_uint64(record, "address")
        if _require_string(record, "address_type") not in _DECODED_ADDRESS_TYPES:
            raise ValueError("FLOSS decoded address_type is invalid")
        function = _require_uint64(record, "decoding_routine")
        location = _require_uint64(record, "decoded_at")
    else:
        function = _require_uint64(record, "function")
        location = _require_uint64(record, "program_counter")
        if kind == "stack":
            _require_uint64(record, "stack_pointer")
            _require_uint64(record, "original_stack_pointer")
            _require_uint64(record, "offset")
            _require_int64(record, "frame_offset")
        elif kind == "tight" and "frame_offset" in record:
            _require_int64(record, "frame_offset")
    return text, encoding, function, location


def _public_record(
    kind: str, text: str, encoding: str, function: int, location: int
) -> dict[str, str]:
    """Format one validated record for the bounded public response."""
    return {
        "type": kind,
        "string": text,
        "encoding": encoding,
        "function": f"0x{function:x}",
        "location": f"0x{location:x}",
    }


def _require_string(record: dict[object, object], key: str) -> str:
    value = record.get(key)
    if not isinstance(value, str):
        raise ValueError(f"FLOSS record {key} must be a string")
    return value


def _require_nonempty_string(record: dict[object, object], key: str) -> str:
    value = _require_string(record, key)
    if not value.strip():
        raise ValueError(f"FLOSS record {key} must not be empty")
    return value


def _validate_metadata(metadata: dict[object, object]) -> None:
    """Validate the stable FLOSS metadata fields before trusting a result."""
    _require_nonempty_string(metadata, "file_path")
    version = _require_string(metadata, "version")
    if version != _TOOL_VERSION:
        # Pinned to the exact version shipped in the sandbox image; surface the
        # mismatch so an image bump is diagnosable, not a silent total degrade.
        raise ValueError(
            f"FLOSS metadata version {version!r} is unsupported (expected {_TOOL_VERSION})"
        )
    _require_uint64(metadata, "imagebase")


def _require_uint64(record: dict[object, object], key: str) -> int:
    value = record.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_UNSIGNED_64:
        raise ValueError(f"FLOSS record {key} must be an unsigned 64-bit integer")
    return value


def _require_int64(record: dict[object, object], key: str) -> int:
    value = record.get(key)
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not _MIN_SIGNED_64 <= value <= _MAX_SIGNED_64
    ):
        raise ValueError(f"FLOSS record {key} must be a signed 64-bit integer")
    return value


FLOSS_DECODE_TOOL = ToolDescriptor(
    id="floss_decode",
    description="Recover PE decoded, stack, and tight strings with Mandiant FLOSS.",
    factory=build_floss_decode,
    output_policy=OutputPolicy(max_chars=50_000, max_list_items=200),
)
