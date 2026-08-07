"""Thrash detector for the run_python deep-agentic loop.

A weaker model tends to re-run the SAME dead approach (same tool, same error)
instead of pivoting, burning the per-case execution budget. This module turns
each run_python outcome into a stable ``approach|failure`` signature; a Monitor
(after_tool) counts consecutive repeats and an Advisor (before_model) injects a
one-time pivot directive once the streak reaches the strike threshold. A strike
accrues only when BOTH halves repeat, so varying flags that still hit the same
crash strikes (real thrash) while a genuinely different failure resets (progress).
"""

from __future__ import annotations

import hashlib
import re
from typing import TYPE_CHECKING

from arema.core.logging import get_logger
from arema.runtime.callbacks._llm_request import append_to_system_instruction
from reverse_engineering.tools.deobfuscation.state import CURRENT_ARTIFACT_KEY
from reverse_engineering.tools.workbench.state import (
    RUN_PYTHON_TOOL_NAME,
    THRASH_ARTIFACT_KEY,
    THRASH_REPEAT_COUNT_KEY,
    THRASH_SIGNATURE_KEY,
    THRASH_STRIKE_THRESHOLD,
)

if TYPE_CHECKING:
    from google.adk.agents.callback_context import CallbackContext
    from google.adk.models.llm_request import LlmRequest
    from google.adk.models.llm_response import LlmResponse
    from google.adk.tools.base_tool import BaseTool
    from google.adk.tools.tool_context import ToolContext

logger = get_logger(__name__)

# Ordered most-specific/heaviest first: a script that shells out to several tools
# is labeled by the one that most defines the attempt. Word-boundary anchored so
# a comment mentioning "mono" in prose does not misclassify a pure-python run.
_APPROACH_PATTERNS: tuple[tuple[str, str], ...] = (
    ("de4dot", r"\bde4dot\b"),
    ("ilspycmd", r"\bilspycmd\b"),
    ("dotnet-script", r"\bdotnet[-_ ]script\b"),
    ("mono", r"\bmono\b"),
    ("radare2", r"\b(?:radare2|r2pipe|r2)\b"),
)

# A .NET/CLR or Python exception class: a capitalized name ending Error/Exception.
_EXCEPTION_RE = re.compile(r"\b([A-Z][A-Za-z0-9_]*(?:Error|Exception))\b")


def classify_approach(code: str) -> str:
    """Return a coarse label for the dominant tool the script invokes."""
    for label, pattern in _APPROACH_PATTERNS:
        if re.search(pattern, code):
            return label
    return "python"


def classify_failure(exit_code: object, stderr: str) -> str:
    """Return a stable failure token, or "" when the run succeeded.

    A zero exit is progress (no failure). Otherwise prefer the named exception
    class (the LAST match: Python tracebacks put it last, and .NET stderr stacks
    name no other Error/Exception token below the header line). With no
    recognizable exception, fall back to a STABLE, OPAQUE hash of the first
    stderr line -- never the raw text -- then a generic nonzero-exit marker.
    """
    code = exit_code if isinstance(exit_code, int) and not isinstance(exit_code, bool) else 1
    if code == 0:
        return ""
    matches: list[str] = _EXCEPTION_RE.findall(stderr or "")
    if matches:
        return matches[-1]  # regex-constrained identifier: injection-safe + informative
    first_line = next((line.strip() for line in (stderr or "").splitlines() if line.strip()), "")
    if not first_line:
        return "nonzero_exit"
    # No recognizable exception class. Return a STABLE, OPAQUE token derived from the
    # first line, NEVER the raw text: the Advisor renders the failure token into the
    # model's system instruction (which the SanitizationMembrane never sees), so raw
    # sample-influenceable stderr must never surface there. Same stderr -> same token,
    # so repeat detection still works.
    digest = hashlib.blake2s(first_line.encode("utf-8", "replace"), digest_size=4).hexdigest()
    return f"err:{digest}"


def thrash_signature(code: str, exit_code: object, stderr: str) -> str:
    """Return the ``approach|failure`` signature, or "" for a successful run."""
    failure = classify_failure(exit_code, stderr)
    if not failure:
        return ""
    return f"{classify_approach(code)}|{failure}"


def _int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _str(value: object) -> str:
    return value if isinstance(value, str) else ""


def record_run_python_thrash(
    tool: BaseTool,
    args: dict[str, object],
    tool_context: ToolContext,
    tool_response: dict[str, object],
) -> dict[str, object] | None:
    """after_tool Monitor: track consecutive identical run_python failures.

    Self-scoped to run_python; returns ``None`` (never transforms the response).
    Resets on progress (a successful run, or the loop advancing to a new layer).
    Fail-open.
    """
    try:
        if getattr(tool, "name", "") != RUN_PYTHON_TOOL_NAME:
            return None
        state = tool_context.state
        getter = getattr(state, "get", None)
        setter = getattr(state, "__setitem__", None)
        if not callable(getter) or not callable(setter):
            return None
        # A new artifact means the loop peeled a layer; the old streak is stale.
        current_artifact = _str(getter(CURRENT_ARTIFACT_KEY))
        if current_artifact != _str(getter(THRASH_ARTIFACT_KEY)):
            setter(THRASH_ARTIFACT_KEY, current_artifact)
            setter(THRASH_SIGNATURE_KEY, "")
            setter(THRASH_REPEAT_COUNT_KEY, 0)
        code = args.get("code", "") if isinstance(args, dict) else ""
        response = tool_response if isinstance(tool_response, dict) else {}
        signature = thrash_signature(
            _str(code), response.get("exit_code"), _str(response.get("stderr"))
        )
        if not signature:  # success -> progress, clear the streak
            setter(THRASH_SIGNATURE_KEY, "")
            setter(THRASH_REPEAT_COUNT_KEY, 0)
            return None
        if signature == _str(getter(THRASH_SIGNATURE_KEY)):
            setter(THRASH_REPEAT_COUNT_KEY, _int(getter(THRASH_REPEAT_COUNT_KEY)) + 1)
        else:
            setter(THRASH_SIGNATURE_KEY, signature)
            setter(THRASH_REPEAT_COUNT_KEY, 1)
        return None
    except Exception:
        logger.warning("record_run_python_thrash failed - continuing", exc_info=True)
        return None


def advise_on_thrash(
    callback_context: CallbackContext,
    llm_request: LlmRequest,
) -> LlmResponse | None:
    """before_model Advisor: inject a pivot directive on a repeated dead approach.

    Fires once the same-approach/same-failure streak reaches the strike threshold.
    Names only what recon OBSERVED (approach + failure) and points to technique
    CLASSES, never a sample-specific answer. Returns ``None`` (never short-circuits
    the model). Fail-open. Follows the turn_limit precedent of appending to the
    system instruction; this happens only during active thrashing, so KV-cache
    churn is rare.
    """
    try:
        state = callback_context.state
        getter = getattr(state, "get", None)
        if not callable(getter):
            return None
        count = _int(getter(THRASH_REPEAT_COUNT_KEY))
        if count < THRASH_STRIKE_THRESHOLD:
            return None
        approach, _, failure = _str(getter(THRASH_SIGNATURE_KEY)).partition("|")
        append_to_system_instruction(
            llm_request,
            (
                f"\n\n[STOP — REPEATED FAILURE: '{approach or 'this approach'}' has "
                f"failed {count}x in a row with the same error "
                f"({failure or 'no progress'}).]\n"
                f"That approach is exhausted for the current artifact. Do NOT run "
                f"'{approach or 'it'}' again. Pivot to a DIFFERENT technique: attack "
                "a different layer, use a different tool, or attack at a different "
                "abstraction (e.g. run the sample's own loader end-to-end instead of "
                "invoking a low-level routine directly). If you have genuinely "
                "exhausted your options, register the deepest valid artifact you "
                "recovered and stop.\n"
            ),
        )
        logger.info("thrash advisory injected", approach=approach, failure=failure, count=count)
        return None
    except Exception:
        logger.warning("advise_on_thrash failed - continuing", exc_info=True)
        return None
