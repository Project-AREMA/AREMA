"""The re_deep_agentic profile wires the thrash detector and only dotnet_analyst uses it."""

from __future__ import annotations

from reverse_engineering.agents.dotnet_analyst import DOTNET_ANALYST_DESCRIPTOR
from reverse_engineering.profiles import RE_DEEP_AGENTIC_PROFILE, RE_GUARDED_PROFILE
from reverse_engineering.tools.workbench.thrash import (
    advise_on_thrash,
    record_run_python_thrash,
)


def test_monitor_precedes_the_sanitizer():
    after = RE_DEEP_AGENTIC_PROFILE.extra_after_tool
    assert after[0] is record_run_python_thrash  # reads raw stderr before sanitization
    # the re_guarded sanitizer(s) are preserved, after the monitor
    assert after[1:] == RE_GUARDED_PROFILE.extra_after_tool


def test_advisor_is_in_before_model():
    assert advise_on_thrash in RE_DEEP_AGENTIC_PROFILE.extra_before_model


def test_profile_id_is_distinct():
    assert RE_DEEP_AGENTIC_PROFILE.id == "re_deep_agentic"
    assert RE_GUARDED_PROFILE.id == "re_guarded"  # unchanged


def test_dotnet_analyst_uses_the_deep_profile():
    assert DOTNET_ANALYST_DESCRIPTOR.runtime_profile_id == "re_deep_agentic"
