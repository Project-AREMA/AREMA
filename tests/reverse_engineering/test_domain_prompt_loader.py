"""Unit tests for the reverse_engineer domain prompt loader.

The loader resolves packaged ``.md`` prompts from the ``reverse_engineering.prompts``
package, reusing :class:`PromptNotFoundError` from the neutral core so callers
handle a single error type for both packages.
"""

from __future__ import annotations

import pytest

from arema.prompts.loader import PromptNotFoundError
from reverse_engineering.prompts.loader import load_domain_prompt

_PROMPT_MARKERS = {
    "sample_intake": "acquire_sample",
    "triage_recon": "open-then-analyze",
    "report_generator": "Limitations",
}


@pytest.mark.parametrize("prompt_id", ["sample_intake", "triage_recon", "report_generator"])
def test_load_domain_prompt_resolves_each_agent_prompt(prompt_id: str) -> None:
    text = load_domain_prompt(prompt_id)

    assert text.strip()
    assert _PROMPT_MARKERS[prompt_id] in text


def test_sample_intake_descriptor_carries_the_ingest_tools() -> None:
    from reverse_engineering.agents.sample_intake import SAMPLE_INTAKE_DESCRIPTOR

    assert SAMPLE_INTAKE_DESCRIPTOR.prompt_id == "sample_intake"
    assert SAMPLE_INTAKE_DESCRIPTOR.tool_ids == (
        "acquire_sample",
        "acquire_sample_by_hash",
        "prepare_sandbox",
        "prepare_ilspy",
    )
    assert SAMPLE_INTAKE_DESCRIPTOR.factory.__name__ == "build_llm_agent"


def test_load_domain_prompt_raises_for_missing_id() -> None:
    with pytest.raises(PromptNotFoundError):
        load_domain_prompt("does_not_exist")


@pytest.mark.parametrize("bad_id", ["foo/bar", "foo\\bar", "..", ".", ""])
def test_load_domain_prompt_rejects_path_like_ids(bad_id: str) -> None:
    with pytest.raises(PromptNotFoundError):
        load_domain_prompt(bad_id)
