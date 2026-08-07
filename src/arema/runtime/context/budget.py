"""Before-model context-budget enforcement for AREMA agent runs.

Layer 2 of context management: before every LLM call, ``enforce_context_budget``
estimates how much of the configured token budget the pending request already
occupies and progressively compacts older turns as that occupancy rises
through the warning, hard, and critical pressure tiers.

Layer 3 (folded into the same pass): when compacting tool results alone is
insufficient, old plain-text model output (verbose reasoning) is truncated
too, preserving the run's most recent working context.

If even the most aggressive compaction cannot bring the estimate back under
the critical threshold, the run has no safe way to continue -- it stops
cleanly, records a checkpoint in session state, and returns an ``LlmResponse``
explaining why, instead of submitting a request that risks exceeding the
provider's real context window.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from google.adk.models.llm_response import LlmResponse
from google.genai import types as genai_types

from arema.core.config import Settings, get_settings
from arema.core.logging import get_logger

if TYPE_CHECKING:
    from collections.abc import Sequence

    from google.adk.agents.callback_context import CallbackContext
    from google.adk.models.llm_request import LlmRequest
    from google.genai.types import Content, Part

logger = get_logger(__name__)

# Marker prefixing an already-compacted tool result, so repeated passes over
# the same content never re-summarise (or double-count) it.
_COMPACTED_MARKER = "[Compacted]"

# Suffix appended to a truncated model-text part. Doubles as the idempotence
# marker: a part already ending in this suffix is left alone on later passes.
_TRUNCATION_SUFFIX = "\n\n[... truncated by context budget ...]"

# Model text shorter than this is always preserved in full, regardless of
# pressure tier (below CRITICAL). CRITICAL halves this floor.
_TEXT_TRUNCATE_MIN_LENGTH = 500
_TEXT_TRUNCATE_PREFIX_CHARS = 200

# Session-state key under which a hard-limit checkpoint is recorded.
CHECKPOINT_STATE_KEY = "context_budget:checkpoint"


class ContextPressure(StrEnum):
    """Severity tiers for how full the context window is."""

    NORMAL = "normal"
    WARNING = "warning"
    HARD = "hard"
    CRITICAL = "critical"


def estimate_tokens(contents: Sequence[Content]) -> int:
    """Estimate the token footprint of *contents*.

    Serialises every content item -- including plain text, function-call
    arguments, and function responses -- to JSON (falling back to ``str()``
    for provider objects the encoder cannot handle directly) and divides the
    character count by four. This is a deterministic, dependency-free proxy
    for BPE token counts that stays within a reasonable margin of true
    tokenizer output across providers.
    """
    try:
        return len(json.dumps(list(contents), default=str)) // 4
    except Exception:
        logger.warning("failed to estimate context tokens", exc_info=True)
        return 0


def classify_pressure(ratio: float, settings: Settings | None = None) -> ContextPressure:
    """Classify a token-budget occupancy ratio into a pressure tier."""
    settings = settings or get_settings()
    if ratio >= settings.context_critical_ratio:
        return ContextPressure.CRITICAL
    if ratio >= settings.context_hard_ratio:
        return ContextPressure.HARD
    if ratio >= settings.context_warning_ratio:
        return ContextPressure.WARNING
    return ContextPressure.NORMAL


@dataclass(frozen=True, slots=True)
class _PreservationLevel:
    """How much recent history a given pressure tier keeps untouched."""

    tool_preserve: int
    model_turns_preserve: int
    text_min_length: int
    text_prefix_chars: int


def _preservation_level(pressure: ContextPressure, settings: Settings) -> _PreservationLevel:
    """Compute preservation counts for *pressure*, tightening as it worsens.

    WARNING uses the configured defaults. HARD halves both preservation
    counts (floored at 1). CRITICAL keeps only the single most recent tool
    result and model turn, and also halves the text-truncation floor so
    shorter reasoning text becomes eligible for truncation too.
    """
    if pressure is ContextPressure.CRITICAL:
        return _PreservationLevel(
            tool_preserve=1,
            model_turns_preserve=1,
            text_min_length=max(200, _TEXT_TRUNCATE_MIN_LENGTH // 2),
            text_prefix_chars=max(100, _TEXT_TRUNCATE_PREFIX_CHARS // 2),
        )
    if pressure is ContextPressure.HARD:
        return _PreservationLevel(
            tool_preserve=max(1, settings.context_preserve_recent_tools // 2),
            model_turns_preserve=max(1, settings.context_preserve_recent_model_turns // 2),
            text_min_length=_TEXT_TRUNCATE_MIN_LENGTH,
            text_prefix_chars=_TEXT_TRUNCATE_PREFIX_CHARS,
        )
    return _PreservationLevel(
        tool_preserve=settings.context_preserve_recent_tools,
        model_turns_preserve=settings.context_preserve_recent_model_turns,
        text_min_length=_TEXT_TRUNCATE_MIN_LENGTH,
        text_prefix_chars=_TEXT_TRUNCATE_PREFIX_CHARS,
    )


def _iter_parts(content: Content) -> tuple[Part, ...]:
    parts = getattr(content, "parts", None)
    return tuple(parts) if parts else ()


def _has_function_response(content: Content) -> bool:
    return any(
        getattr(part, "function_response", None) is not None for part in _iter_parts(content)
    )


def _has_model_text(content: Content) -> bool:
    for part in _iter_parts(content):
        has_text = getattr(part, "text", None) is not None
        has_func_response = getattr(part, "function_response", None) is not None
        has_func_call = getattr(part, "function_call", None) is not None
        if has_text and not has_func_response and not has_func_call:
            return True
    return False


def _already_compacted(response: object) -> bool:
    if isinstance(response, str):
        return response.startswith(_COMPACTED_MARKER)
    if isinstance(response, dict):
        result = response.get("result")
        return isinstance(result, str) and result.startswith(_COMPACTED_MARKER)
    return False


def _serialize_response(response: object) -> str:
    if isinstance(response, str):
        return response
    try:
        return json.dumps(response, default=str)
    except (TypeError, ValueError):
        return ""


def _summarize_tool_result(response_text: str) -> str:
    """Build a short, tool-agnostic summary for a compacted marker message.

    Looks for generic ``*_count`` integer fields first (e.g. ``item_count``,
    ``record_count``); falls back to counting top-level list fields; falls
    back to an error snippet; falls back to a bare "completed" marker. None
    of this depends on any specific tool's response shape.
    """
    try:
        data = json.loads(response_text)
    except (json.JSONDecodeError, TypeError):
        return "completed"

    if not isinstance(data, dict):
        return "completed"

    parts = [
        f"{value} {key[: -len('_count')].replace('_', ' ')}"
        for key, value in sorted(data.items())
        if key.endswith("_count") and isinstance(value, int) and not isinstance(value, bool)
    ]

    if not parts:
        parts = [
            f"{len(value)} {key}" for key, value in sorted(data.items()) if isinstance(value, list)
        ]

    error = data.get("error")
    if error:
        parts.append(f"error: {str(error)[:80]}")

    return ", ".join(parts) if parts else "completed"


def _compact_old_tool_results(contents: Sequence[Content], preserve_recent: int) -> int:
    """Replace old function-response payloads with a short compacted summary.

    Walks *contents* for items carrying a function-response part and, for
    every one older than the most recent *preserve_recent*, overwrites the
    response with a short marker message. Already-compacted results are
    skipped, making repeated calls idempotent.

    Returns the number of tool results compacted on this call.
    """
    tool_result_indices = [
        index for index, content in enumerate(contents) if _has_function_response(content)
    ]

    if preserve_recent >= len(tool_result_indices):
        return 0

    compacted_count = 0
    for index in tool_result_indices[:-preserve_recent]:
        for part in _iter_parts(contents[index]):
            func_response = getattr(part, "function_response", None)
            if func_response is None:
                continue

            response = getattr(func_response, "response", None)
            if response is None or _already_compacted(response):
                continue

            display_name = getattr(func_response, "name", None) or "tool"
            summary = _summarize_tool_result(_serialize_response(response))
            compact_message = f"{_COMPACTED_MARKER} {display_name} completed. {summary}."

            if isinstance(response, dict):
                func_response.response = {"result": compact_message}
            else:
                func_response.response = compact_message

            compacted_count += 1
            logger.debug("compacted old tool result", tool=display_name)

    return compacted_count


def _compact_old_model_text(
    contents: Sequence[Content],
    preserve_recent_turns: int,
    min_length: int,
    prefix_chars: int,
) -> int:
    """Truncate old plain-text model output, preserving recent turns.

    Only ``role == "model"`` content items with a text-only part (no
    function-call or function-response siblings) are eligible; user messages
    and tool activity are never touched. Already-truncated parts are
    skipped, making repeated calls idempotent.

    Returns the number of parts truncated on this call.
    """
    model_text_indices = [
        index
        for index, content in enumerate(contents)
        if getattr(content, "role", None) == "model" and _has_model_text(content)
    ]

    if preserve_recent_turns >= len(model_text_indices):
        return 0

    truncated_count = 0
    for index in model_text_indices[:-preserve_recent_turns]:
        for part in _iter_parts(contents[index]):
            if getattr(part, "function_response", None) is not None:
                continue
            if getattr(part, "function_call", None) is not None:
                continue

            text = getattr(part, "text", None)
            if not isinstance(text, str) or len(text) <= min_length:
                continue
            if text.endswith(_TRUNCATION_SUFFIX):
                continue

            part.text = text[:prefix_chars] + _TRUNCATION_SUFFIX
            truncated_count += 1
            logger.debug("truncated old model text part", content_index=index)

    return truncated_count


def _write_checkpoint(
    callback_context: CallbackContext,
    *,
    tokens: int,
    budget: int,
    ratio: float,
) -> None:
    """Record a hard-limit checkpoint in session state. Fails open."""
    state = callback_context.state
    if state is None:
        return
    try:
        state[CHECKPOINT_STATE_KEY] = {
            "tokens": tokens,
            "budget": budget,
            "ratio": round(ratio, 3),
        }
    except Exception:
        logger.warning("failed to write context-budget checkpoint state", exc_info=True)


def _checkpoint_response(tokens: int, budget: int) -> LlmResponse:
    """Build the terminal response returned at unrecoverable critical pressure."""
    return LlmResponse(
        content=genai_types.Content(
            role="model",
            parts=[
                genai_types.Part(
                    text=(
                        "[Run stopped: estimated context usage "
                        f"({tokens} tokens) remains at or above the critical "
                        f"threshold of the configured budget ({budget} tokens) "
                        "even after compaction. A checkpoint was recorded "
                        "before the limit was exceeded.]"
                    )
                )
            ],
        )
    )


async def enforce_context_budget(
    callback_context: CallbackContext,
    llm_request: LlmRequest,
) -> LlmResponse | None:
    """Before-model callback that enforces the configured context-token budget.

    Compacts older tool results and, if that is not enough, older model text
    as pressure rises through the warning, hard, and critical tiers. If the
    critical tier is still occupied after the most aggressive compaction,
    stops the run cleanly and returns an explanatory ``LlmResponse`` instead
    of submitting an oversized request.

    Returns ``None`` to let the run proceed normally.
    """
    settings = get_settings()
    contents = llm_request.contents
    if not contents:
        return None

    budget = settings.context_budget_tokens
    estimated_tokens = estimate_tokens(contents)
    pressure = classify_pressure(estimated_tokens / budget, settings)

    if pressure is ContextPressure.NORMAL:
        return None

    level = _preservation_level(pressure, settings)

    logger.info(
        "context budget pressure detected",
        pressure=pressure.value,
        estimated_tokens=estimated_tokens,
        budget=budget,
    )

    tool_compacted = _compact_old_tool_results(contents, preserve_recent=level.tool_preserve)
    tokens_after_tools = estimate_tokens(contents)

    text_compacted = 0
    if tokens_after_tools / budget >= settings.context_warning_ratio:
        text_compacted = _compact_old_model_text(
            contents,
            preserve_recent_turns=level.model_turns_preserve,
            min_length=level.text_min_length,
            prefix_chars=level.text_prefix_chars,
        )

    final_tokens = estimate_tokens(contents)
    final_ratio = final_tokens / budget
    final_pressure = classify_pressure(final_ratio, settings)

    if tool_compacted or text_compacted:
        logger.info(
            "context budget compaction complete",
            tool_results_compacted=tool_compacted,
            model_turns_compacted=text_compacted,
            tokens_before=estimated_tokens,
            tokens_after=final_tokens,
        )

    if final_pressure is not ContextPressure.CRITICAL:
        return None

    logger.warning(
        "context budget exhausted after compaction - stopping run",
        estimated_tokens=final_tokens,
        budget=budget,
        ratio=round(final_ratio, 3),
    )
    _write_checkpoint(callback_context, tokens=final_tokens, budget=budget, ratio=final_ratio)
    return _checkpoint_response(final_tokens, budget)
