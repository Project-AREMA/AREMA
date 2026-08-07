"""The single robust boundary for turning model-produced text into JSON.

LLMs routinely wrap JSON in Markdown code fences (```json ... ```), add leading
or trailing prose, or emit minor malformations (trailing commas). A strict
``json.loads`` fails on all of these, and because several agents combine tool use
with structured output, their final turn is free-form text -- so fenced output is
the norm, not the exception. This module is the ONE place that knows how model
output actually arrives: reject oversized input outright, strip a code fence,
then decode strictly (rejecting the ``NaN``/``Infinity`` JSON constants). Only if
that fails does it fall back to ``json_repair`` -- a DELIBERATE second-layer
salvage layer, both for the minor malformation models routinely produce
(trailing commas and the like) and for fences the anchored stripper below
deliberately does not touch (e.g. a fence wrapped in surrounding prose). Every
site that decodes model output must route through this function; never call
``json.loads`` on model text directly.
"""

from __future__ import annotations

import json
import re

from json_repair import repair_json

# Mirrors the larger of the two raw-JSON ceilings in
# ``src/reverse_engineering/evidence_envelope.py`` (``MAX_RAW_CRITIC_JSON_CHARS``,
# itself ``MAX_RAW_EVIDENCE_JSON_CHARS * 3``). Duplicated here as a literal rather
# than imported: ``evidence_envelope`` is meant to import THIS module, so an
# import the other way would create a cycle. Keep the two in sync by hand if
# either bound changes.
MAX_MODEL_JSON_CHARS = 67_780_116

# Matches a whole-string Markdown code fence with an optional ```json info
# string. Deliberately anchored (``\A...\Z``, via ``.match``, not ``.search``):
# requiring the fence to span the ENTIRE string means it can never false-match a
# ``` sequence embedded inside a JSON string value (e.g. a finding quoting a code
# block) -- an unanchored search matches the FIRST ``` it finds, which silently
# truncates such payloads. The body group is greedy (``.*``, not ``.*?``) so it
# extends to the LAST ``\n``` `` in the string, i.e. the wrapper's real closing
# fence: a valid JSON string can never contain a literal newline-backtick-
# backtick-backtick sequence (a JSON string's newlines are always the two-char
# escape ``\n``), so greedy matching here is always correct, never overreaching
# into the wrapper's content. Prose surrounding the fence (leading/trailing text
# outside the anchors) is NOT handled here -- it falls through to the
# ``json_repair`` salvage layer below instead.
_FENCE_RE = re.compile(r"\A\s*```[^\n`]*\n(?P<body>.*)\n```\s*\Z", re.DOTALL)


def _reject_json_constant(value: str) -> object:
    """Reject ``NaN``/``Infinity``/``-Infinity`` -- never valid, DoS-adjacent."""
    raise ValueError(f"JSON constant {value!r} is not permitted")


def _strip_code_fence(text: str) -> str:
    match = _FENCE_RE.match(text)
    return match.group("body").strip() if match else text.strip()


def loads_model_json(raw: object, *, max_chars: int = MAX_MODEL_JSON_CHARS) -> object:
    """Decode JSON from untrusted model text, tolerating fences and minor malformation.

    Returns ``raw`` unchanged when it is not a ``str`` (an earlier stage already
    parsed it). Rejects text longer than ``max_chars`` before any fence-stripping
    or decoding -- this boundary owns its own size cap rather than trusting
    callers to size-gate first, so an oversized payload can never reach the
    comparatively slow ``json_repair`` fallback. Strips a Markdown code fence,
    decodes strictly with constant rejection, and only on failure repairs via
    ``json_repair`` -- re-decoding the repaired string so constant rejection
    still applies. Raises ``ValueError`` when the text is too long or
    unrecoverable.
    """
    if not isinstance(raw, str):
        return raw
    if len(raw) > max_chars:
        raise ValueError(f"model JSON text exceeds the {max_chars}-character maximum")
    text = _strip_code_fence(raw)
    try:
        return json.loads(text, parse_constant=_reject_json_constant)
    except ValueError:
        repaired = repair_json(text)
        if not repaired or repaired == '""':
            raise
        return json.loads(repaired, parse_constant=_reject_json_constant)
