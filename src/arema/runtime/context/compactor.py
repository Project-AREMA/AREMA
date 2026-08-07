"""Descriptor-driven, tool-agnostic compaction of completed tool responses.

Layer 1 of context management: every tool's response is bounded before it
enters the run's conversation history. Unlike name-keyed compaction, the
rules applied to a given tool's output come entirely from its
``OutputPolicy`` -- the runtime never needs a hardcoded table of tool names
to know what to strip, bound, or protect.
"""

from __future__ import annotations

import json
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, cast

from arema.core.logging import get_logger
from arema.registry.descriptors import AfterToolCallback, OutputPolicy

if TYPE_CHECKING:
    from collections.abc import Mapping

    from google.adk.tools.base_tool import BaseTool
    from google.adk.tools.tool_context import ToolContext

logger = get_logger(__name__)

# Policy applied when a completed tool has no registered OutputPolicy.
_SAFE_DEFAULT_POLICY = OutputPolicy()

# Marker left behind wherever a value was shortened. Deliberately generic --
# this module has no notion of a "full results" retrieval tool to point at.
_TRUNCATION_HINT = "[truncated]"

# How much of an oversized string/list/dict to keep as a preview before the
# hint. Kept short so the largest-value-first pass in `_deep_truncate`
# converges quickly even for very tight `max_chars` budgets.
_PREVIEW_ITEMS = 3
_PREVIEW_CHARS = 40

# Safety cap on `_deep_truncate` iterations. In practice the loop converges
# (or gives up because nothing more can shrink) in far fewer passes.
_MAX_DEEP_TRUNCATE_PASSES = 50


def compact_response(response: dict[str, object], policy: OutputPolicy) -> dict[str, object]:
    """Bound a completed tool response to the shape allowed by *policy*.

    Applies, in order and without mutating *response*:

    1. Recursive field dropping -- every key in ``policy.drop_fields`` is
       removed wherever it appears in the tree, unless it is also listed in
       ``policy.preserve_fields``.
    2. Bounded list truncation -- every list in the tree (again, excluding
       ``policy.preserve_fields``) is capped at ``policy.max_list_items``.
    3. Largest-value-first deep truncation -- if the response is still
       larger than ``policy.max_chars``, the single largest reachable value
       is shortened, repeatedly, until it fits or no further shrinking is
       possible.
    """
    dropped = _drop_fields(response, policy.drop_fields, policy.preserve_fields)
    bounded = _bound_lists(dropped, policy.max_list_items, policy.preserve_fields)
    return _deep_truncate(bounded, policy.max_chars, policy.preserve_fields)


# ---------------------------------------------------------------------------
# Stage 1: recursive field dropping
# ---------------------------------------------------------------------------


def _strip(
    value: object,
    drop_fields: tuple[str, ...],
    preserve_fields: tuple[str, ...],
) -> object:
    if isinstance(value, dict):
        return {
            key: _strip(item, drop_fields, preserve_fields)
            for key, item in value.items()
            if key in preserve_fields or key not in drop_fields
        }
    if isinstance(value, list):
        return [_strip(item, drop_fields, preserve_fields) for item in value]
    return value


def _drop_fields(
    response: dict[str, object],
    drop_fields: tuple[str, ...],
    preserve_fields: tuple[str, ...],
) -> dict[str, object]:
    if not drop_fields:
        return dict(response)
    # `_strip` preserves dict-ness for a dict input; the tree it walks is the
    # response itself, which is always a top-level dict here.
    return cast("dict[str, object]", _strip(response, drop_fields, preserve_fields))


# ---------------------------------------------------------------------------
# Stage 2: bounded list truncation
# ---------------------------------------------------------------------------


def _bound(
    value: object,
    max_list_items: int,
    preserve_fields: tuple[str, ...],
) -> object:
    if isinstance(value, dict):
        return {
            key: item if key in preserve_fields else _bound(item, max_list_items, preserve_fields)
            for key, item in value.items()
        }
    if isinstance(value, list):
        bounded_items = [_bound(item, max_list_items, preserve_fields) for item in value]
        return bounded_items[:max_list_items]
    return value


def _bound_lists(
    response: dict[str, object],
    max_list_items: int,
    preserve_fields: tuple[str, ...],
) -> dict[str, object]:
    # `_bound` preserves dict-ness for a dict input; see `_drop_fields`.
    return cast("dict[str, object]", _bound(response, max_list_items, preserve_fields))


# ---------------------------------------------------------------------------
# Stage 3: largest-value-first deep truncation
# ---------------------------------------------------------------------------

_PathSegment = str | int


def _serialized_size(value: object) -> int:
    try:
        return len(json.dumps(value, default=str))
    except (TypeError, ValueError):
        return 0


def _collect_candidates(
    node: object, path: tuple[_PathSegment, ...]
) -> list[tuple[tuple[_PathSegment, ...], int]]:
    """Recursively gather (path, serialised size) for every reachable node."""
    candidates: list[tuple[tuple[_PathSegment, ...], int]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            child_path = (*path, key)
            candidates.append((child_path, _serialized_size(value)))
            candidates.extend(_collect_candidates(value, child_path))
    elif isinstance(node, list):
        for index, item in enumerate(node):
            child_path = (*path, index)
            candidates.append((child_path, _serialized_size(item)))
            candidates.extend(_collect_candidates(item, child_path))
    return candidates


def _get_at(root: dict[str, object], path: tuple[_PathSegment, ...]) -> object:
    node: object = root
    for segment in path:
        # Branches kept separate (not combined via `or`) so mypy can narrow
        # `node`'s type per-branch; combining them loses that narrowing.
        if isinstance(node, dict) and isinstance(segment, str):  # noqa: SIM114
            node = node[segment]
        elif isinstance(node, list) and isinstance(segment, int):
            node = node[segment]
        else:  # pragma: no cover - defensive; paths are always well-formed
            raise KeyError(segment)
    return node


def _set_at(root: dict[str, object], path: tuple[_PathSegment, ...], value: object) -> None:
    parent = _get_at(root, path[:-1]) if len(path) > 1 else root
    last = path[-1]
    if isinstance(parent, dict) and isinstance(last, str):  # noqa: SIM114
        parent[last] = value
    elif isinstance(parent, list) and isinstance(last, int):
        parent[last] = value
    else:  # pragma: no cover - defensive; paths are always well-formed
        raise KeyError(last)


def _truncate_value(value: object) -> tuple[object, bool]:
    """Return ``(new_value, changed)``.

    ``changed=False`` signals a true fixed point: truncating *value* again
    would produce an identical result, so the caller should stop trying.
    """
    if isinstance(value, list):
        if not value:
            return value, False
        candidate: object = (
            [_TRUNCATION_HINT]
            if len(value) <= _PREVIEW_ITEMS
            else [*value[:_PREVIEW_ITEMS], _TRUNCATION_HINT]
        )
        return (candidate, True) if candidate != value else (value, False)

    if isinstance(value, dict):
        if not value:
            return value, False
        keys = list(value.keys())
        candidate_dict: dict[str, object] = (
            {key: value[key] for key in keys[:_PREVIEW_ITEMS]} if len(keys) > _PREVIEW_ITEMS else {}
        )
        candidate_dict["_truncated"] = _TRUNCATION_HINT
        return (candidate_dict, True) if candidate_dict != value else (value, False)

    if isinstance(value, str):
        if len(value) <= _PREVIEW_CHARS:
            candidate_str = _TRUNCATION_HINT
        else:
            candidate_str = value[:_PREVIEW_CHARS] + " " + _TRUNCATION_HINT
        return (candidate_str, True) if candidate_str != value else (value, False)

    return value, False


def _deep_truncate(
    response: dict[str, object],
    max_chars: int,
    preserve_fields: tuple[str, ...],
) -> dict[str, object]:
    """Iteratively shrink the largest reachable value until *response*
    serialises within *max_chars*, or no further truncation is possible.
    """
    data: dict[str, object] = dict(response)

    for _ in range(_MAX_DEEP_TRUNCATE_PASSES):
        if _serialized_size(data) <= max_chars:
            break

        candidates = _collect_candidates(data, ())
        if not candidates:
            break

        candidates.sort(key=lambda candidate: candidate[1], reverse=True)

        made_progress = False
        for path, _size in candidates:
            if any(str(segment) in preserve_fields for segment in path):
                continue

            value = _get_at(data, path)
            new_value, changed = _truncate_value(value)
            if not changed:
                continue

            _set_at(data, path, new_value)
            made_progress = True
            break

        if not made_progress:
            break

    return data


# ---------------------------------------------------------------------------
# after_tool_callback factory
# ---------------------------------------------------------------------------


def make_output_compactor(
    policy_by_tool_id: Mapping[str, OutputPolicy],
) -> AfterToolCallback:
    """Build an after-tool callback that compacts responses per-tool policy.

    Looks up the completed tool's name in the immutable *policy_by_tool_id*
    mapping (copied at construction time, so later mutation of the caller's
    mapping has no effect). Tools without a registered policy fall back to
    the safe default policy (``OutputPolicy()``).
    """
    policies: Mapping[str, OutputPolicy] = MappingProxyType(dict(policy_by_tool_id))

    def _compact_tool_output(
        tool: BaseTool,
        args: dict[str, Any],
        tool_context: ToolContext,
        tool_response: dict[str, Any],
    ) -> dict[str, Any] | None:
        del args, tool_context  # policy lookup only needs the tool's identity
        if not isinstance(tool_response, dict):
            return None

        policy = policies.get(tool.name, _SAFE_DEFAULT_POLICY)
        try:
            return compact_response(tool_response, policy)
        except Exception:
            logger.warning("failed to compact tool output", tool=tool.name, exc_info=True)
            return None

    return _compact_tool_output
