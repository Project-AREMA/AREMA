"""Sanitization framework: structural defense on untrusted-origin tool output.

Promoted to the neutral core so every domain can reuse it. A domain supplies
only the *configuration* (which tool names are untrusted-origin) via
:func:`make_sanitizing_after_tool`; the framing + redaction mechanism and the
pluggable :class:`OutputSanitizer` protocol live here.
"""

from arema.runtime.callbacks.sanitization.membrane import make_sanitizing_after_tool
from arema.runtime.callbacks.sanitization.protocol import (
    OutputSanitizer,
    PassthroughSanitizer,
)
from arema.runtime.callbacks.sanitization.signatures import (
    PROMPT_INJECTION_SIGNATURES,
    REDACTED,
    redact_signatures,
)
from arema.runtime.callbacks.sanitization.structural import StructuralSanitizer

__all__ = [
    "OutputSanitizer",
    "PASSTHROUGH_SANITIZER",
    "PROMPT_INJECTION_SIGNATURES",
    "PassthroughSanitizer",
    "REDACTED",
    "StructuralSanitizer",
    "make_sanitizing_after_tool",
    "redact_signatures",
]

PASSTHROUGH_SANITIZER = PassthroughSanitizer()
