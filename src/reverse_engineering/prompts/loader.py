"""Package-relative loading of reverse_engineer agent prompts (mirrors arema.prompts.loader).

Prompts ship as ``.md`` files inside the ``reverse_engineering.prompts`` package.
Loading them through :func:`importlib.resources.files` (rather than a filesystem
path relative to this module) means the loader keeps working when AREMA is
installed as a wheel and executed outside the source tree. The error type is
reused from the neutral core so callers handle one ``PromptNotFoundError``.
"""

from __future__ import annotations

from importlib.resources import files

from arema.prompts.loader import PromptNotFoundError

_PROMPT_PACKAGE = "reverse_engineering.prompts"
_PROMPT_SUFFIX = ".md"


def _require_simple_id(prompt_id: str) -> str:
    """Reject empty or path-like identifiers before touching the package."""
    if not prompt_id or not prompt_id.strip():
        raise PromptNotFoundError("prompt id must be a non-empty name")
    if any(separator in prompt_id for separator in ("/", "\\")) or prompt_id in {".", ".."}:
        raise PromptNotFoundError(f"prompt id '{prompt_id}' must be a bare resource name")
    return prompt_id


def load_domain_prompt(prompt_id: str) -> str:
    """Return the UTF-8 text of the packaged ``<prompt_id>.md`` reverse_engineer prompt.

    Raises :class:`PromptNotFoundError` for an invalid identifier or a missing
    resource so a composition failure names the offending prompt rather than
    surfacing a bare lookup error.
    """
    resource = files(_PROMPT_PACKAGE).joinpath(f"{_require_simple_id(prompt_id)}{_PROMPT_SUFFIX}")
    try:
        return resource.read_text(encoding="utf-8")
    except (FileNotFoundError, IsADirectoryError) as error:
        raise PromptNotFoundError(f"prompt '{prompt_id}' is not packaged") from error
