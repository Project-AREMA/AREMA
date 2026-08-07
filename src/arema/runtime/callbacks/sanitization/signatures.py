"""Curated prompt-injection signatures redacted from untrusted-origin text.

Each entry is a compiled, case-insensitive regex matching a common
prompt-injection directive. Genuine tool output contains none of these, so it
passes through unchanged (lossless for real evidence). The list is
intentionally small and extensible.

Caveat: natural-language substrings embedded in tool output (e.g.
``"subsystem:"``) may be over-redacted -- acceptable for a fail-safe denylist.
"""

from __future__ import annotations

import re

REDACTED = "[REDACTED: instruction-like text]"

PROMPT_INJECTION_SIGNATURES: tuple[re.Pattern[str], ...] = (
    re.compile(r"ignore\s+(?:all\s+|previous\s+|prior\s+)?instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+(?:now\s+)?(?:a|an|the)\b", re.IGNORECASE),
    re.compile(r"system\s*:", re.IGNORECASE),
    re.compile(r"\bACT\s+AS\b", re.IGNORECASE),
    re.compile(r"new\s+instructions\s*:", re.IGNORECASE),
    re.compile(r"disregard\s+(?:the\s+)?above", re.IGNORECASE),
    re.compile(r"reveal\s+(?:your\s+)?(?:system\s+prompt|instructions)", re.IGNORECASE),
)


def redact_signatures(text: str) -> str:
    """Replace every prompt-injection match in *text* with the redaction marker."""
    for signature in PROMPT_INJECTION_SIGNATURES:
        text = signature.sub(REDACTED, text)
    return text
