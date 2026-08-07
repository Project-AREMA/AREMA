"""Package-relative loading of greeter prompts (mirrors arema.prompts.loader)."""

from __future__ import annotations

from importlib.resources import files

from arema.prompts.loader import PromptNotFoundError

_PROMPT_PACKAGE = "greeter_agent.prompts"
_PROMPT_SUFFIX = ".md"


def _require_simple_id(prompt_id: str) -> str:
    if not prompt_id or not prompt_id.strip():
        raise PromptNotFoundError("prompt id must be a non-empty name")
    if any(separator in prompt_id for separator in ("/", "\\")) or prompt_id in {".", ".."}:
        raise PromptNotFoundError(f"prompt id '{prompt_id}' must be a bare resource name")
    return prompt_id


def load_greeter_prompt(prompt_id: str) -> str:
    """Return the UTF-8 text of the packaged ``<prompt_id>.md`` greeter prompt."""
    resource = files(_PROMPT_PACKAGE).joinpath(f"{_require_simple_id(prompt_id)}{_PROMPT_SUFFIX}")
    try:
        return resource.read_text(encoding="utf-8")
    except (FileNotFoundError, IsADirectoryError) as error:
        raise PromptNotFoundError(f"prompt '{prompt_id}' is not packaged") from error
