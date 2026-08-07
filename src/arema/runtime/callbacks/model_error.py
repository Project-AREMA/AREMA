"""On-model-error callback that survives malformed-JSON tool-call arguments.

Some models occasionally emit syntactically invalid JSON in a tool call's
``arguments`` field (single-quoted keys, trailing commas, Python literals).
ADK parses that JSON with no error handling, so a ``JSONDecodeError`` would
otherwise abort the whole run. :func:`recover_model_json_error` intercepts
that specific error and returns a recovery ``LlmResponse`` instructing the
model to retry with valid JSON; every other error type passes through.

The recovery message is sanitized: it never echoes the raw malformed document
or its repaired form, so secrets in tool arguments cannot leak back into the
conversation. The repair helpers are stdlib-only and side-effect free.
"""

from __future__ import annotations

import json
import re
from json import JSONDecodeError
from typing import TYPE_CHECKING

from google.adk.models.llm_response import LlmResponse
from google.genai import types as genai_types

from arema.core.logging import get_logger
from arema.runtime.callbacks.roles import ROLE_RECOVER_MODEL_ERROR, with_role

if TYPE_CHECKING:
    from google.adk.agents.callback_context import CallbackContext
    from google.adk.models.llm_request import LlmRequest

logger = get_logger(__name__)

# A single-quoted string token, tolerating escaped inner single quotes.
_SINGLE_QUOTED_STRING = re.compile(r"(?<!\\)'((?:[^'\\]|\\.)*)'")
# A trailing comma immediately before a closing brace or bracket.
_TRAILING_COMMA = re.compile(r",\s*([}\]])")
# Python-style ``key="value"`` / ``key='value'`` kwargs inside an object.
_PYTHON_KWARG = re.compile(r'(?<=[{,])\s*(\w+)\s*=\s*"([^"]*?)"')
_PYTHON_KWARG_SINGLE = re.compile(r"(?<=[{,])\s*(\w+)\s*=\s*'([^']*?)'")

_RECOVERY_TEXT = (
    "My previous tool call contained invalid JSON (for example single-quoted "
    "keys, trailing commas, or Python literals). Please retry the same tool "
    "call using strictly valid JSON: double-quoted keys and string values, no "
    "trailing commas, and no Python-style literals."
)


def _replace_single_quoted(match: re.Match[str]) -> str:
    inner = match.group(1)
    inner = inner.replace('\\"', "__DQ__")
    inner = inner.replace('"', '\\"')
    inner = inner.replace("__DQ__", '\\"')
    inner = inner.replace("\\'", "'")
    return f'"{inner}"'


def _repair_json(raw: str) -> str | None:
    """Best-effort repair of common malformed-JSON patterns.

    Returns a valid-JSON string when repair succeeds, else ``None``. Never
    raises. This is a pure function with no side effects.
    """
    try:
        json.loads(raw)
        return raw
    except JSONDecodeError:
        pass

    candidate = _PYTHON_KWARG.sub(r' "\1": "\2"', raw)
    candidate = _PYTHON_KWARG_SINGLE.sub(r' "\1": "\2"', candidate)
    candidate = _SINGLE_QUOTED_STRING.sub(_replace_single_quoted, candidate)
    candidate = _TRAILING_COMMA.sub(r"\1", candidate)

    try:
        json.loads(candidate)
        return candidate
    except JSONDecodeError as error:
        position = getattr(error, "pos", 0)
        if position:
            truncated = candidate[:position].rstrip().rstrip(",")
            if truncated.endswith("}"):
                try:
                    json.loads(truncated)
                    return truncated
                except JSONDecodeError:
                    return None
        return None


@with_role(ROLE_RECOVER_MODEL_ERROR)
def recover_model_json_error(
    callback_context: CallbackContext,
    llm_request: LlmRequest,
    error: Exception,
) -> LlmResponse | None:
    """Recover from a ``JSONDecodeError`` in tool-call arguments.

    Returns a sanitized recovery ``LlmResponse`` for ``JSONDecodeError`` so the
    run continues; returns ``None`` for any other error so ADK re-raises it.
    """
    del llm_request
    if not isinstance(error, JSONDecodeError):
        return None

    agent_name = getattr(callback_context, "agent_name", "unknown")
    malformed = error.doc if isinstance(getattr(error, "doc", None), str) else ""
    repaired = _repair_json(malformed) if malformed else None

    logger.warning(
        "recovered from malformed tool-call JSON",
        agent=agent_name,
        repairable=repaired is not None,
        malformed_length=len(malformed),
    )

    return LlmResponse(
        content=genai_types.Content(
            role="model",
            parts=[genai_types.Part(text=_RECOVERY_TEXT)],
        ),
    )
