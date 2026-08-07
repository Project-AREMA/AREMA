"""The report reaches disk, where its diagram can actually be drawn.

ADK's developer web UI bundles ngx-markdown with ``mermaid: false`` in both its
parse and render defaults and ships no mermaid library, so the execution diagram
displays as a fenced code block however correct it is. That is a vendored
dependency. Writing the report to a file is the fix: Markdown renders the diagram
in VS Code and on GitHub, offline.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from malware_analyst.agents.malware_report_generator import (
    MALWARE_REPORT_GENERATOR_DESCRIPTOR,
)
from reverse_engineering.reporting.settings import SUPPORTED_FORMATS, ReportSettings
from reverse_engineering.reporting.writer import (
    REPORT_PATHS_KEY,
    REPORT_TEXT_KEY,
    render_html,
    report_writer_callback,
    write_report,
)
from reverse_engineering.tools.deobfuscation.state import CURRENT_ARTIFACT_KEY

if TYPE_CHECKING:
    from pathlib import Path

    import pytest

ARTIFACT = "1595d92fb580ab1264b533c3504863062bf47d8ce61e838c64179b904f2a6d23"
STAMP = datetime(2026, 8, 4, 19, 32, 42, tzinfo=UTC)

REPORT = """**Verdict: MALICIOUS**
VirusTotal flags 52/76.

## 2. Execution Flow

```mermaid
flowchart TD
    n0["SmartAssembly-packed stub (scripted_recover)"]
    n0 --> n1
```

## 3. What the binary does

It unpacks an inner assembly.
"""


class _State(dict[str, object]):
    """Duck-typed ADK State stand-in, deliberately not a State subclass."""


class _Context:
    def __init__(self, state: _State) -> None:
        self.state = state


def _settings(tmp_path: Path, formats: str = "md,html") -> ReportSettings:
    return ReportSettings(report_output_dir=str(tmp_path), report_formats=formats)


def _off() -> ReportSettings:
    return ReportSettings(report_output_dir="", report_formats="md,html")


# --- disabled unless configured ------------------------------------------------


def test_no_output_directory_writes_nothing() -> None:
    assert write_report(REPORT, artifact_id=ARTIFACT, settings=_off()) == ()


def test_no_usable_format_writes_nothing(tmp_path: Path) -> None:
    """A legacy value naming only unimplemented formats disables the writer
    rather than producing an empty directory."""
    settings = _settings(tmp_path, formats="docx,pdf")

    assert not settings.enabled
    assert write_report(REPORT, artifact_id=ARTIFACT, settings=settings) == ()


def test_an_empty_report_writes_nothing(tmp_path: Path) -> None:
    assert write_report("   \n ", artifact_id=ARTIFACT, settings=_settings(tmp_path)) == ()


def test_a_legacy_format_list_writes_what_it_can(tmp_path: Path) -> None:
    """.env.example has shipped `json,md,html,docx` since the legacy domain.
    Naming a format this writer cannot produce must not fail the run."""
    settings = _settings(tmp_path, formats="json,md,html,docx")

    assert settings.formats == ("md", "html")
    assert len(write_report(REPORT, artifact_id=ARTIFACT, settings=settings)) == 2


# --- what gets written ---------------------------------------------------------


def test_both_formats_are_written(tmp_path: Path) -> None:
    paths = write_report(
        REPORT, artifact_id=ARTIFACT, settings=_settings(tmp_path), timestamp=STAMP
    )

    assert len(paths) == len(SUPPORTED_FORMATS)
    assert {p.rsplit(".", 1)[-1] for p in paths} == {"md", "html"}


def test_the_markdown_is_written_verbatim(tmp_path: Path) -> None:
    """The writer formats a container, never edits a word inside."""
    paths = write_report(
        REPORT, artifact_id=ARTIFACT, settings=_settings(tmp_path, "md"), timestamp=STAMP
    )

    assert (tmp_path / "20260804T193242Z_1595d92fb580.md").read_text() == REPORT
    assert len(paths) == 1


def test_the_filename_carries_the_time_and_the_digest(tmp_path: Path) -> None:
    """A directory of reports should sort by time and grep by sample without
    opening any of them."""
    (path,) = write_report(
        REPORT, artifact_id=ARTIFACT, settings=_settings(tmp_path, "md"), timestamp=STAMP
    )

    assert "20260804T193242Z" in path
    assert ARTIFACT[:12] in path


def test_a_missing_artifact_id_still_writes(tmp_path: Path) -> None:
    (path,) = write_report(
        REPORT, artifact_id="", settings=_settings(tmp_path, "md"), timestamp=STAMP
    )

    assert path.endswith("20260804T193242Z.md")


def test_the_output_directory_is_created(tmp_path: Path) -> None:
    nested = tmp_path / "reports" / "2026"

    assert write_report(REPORT, artifact_id=ARTIFACT, settings=_settings(nested, "md"))
    assert nested.is_dir()


def test_a_tilde_in_the_path_is_expanded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    settings = ReportSettings(report_output_dir="~/reports", report_formats="md")

    assert settings.directory == tmp_path / "reports"


# --- the HTML wrapper ----------------------------------------------------------


def test_the_html_lifts_the_diagram_out_for_mermaid_to_draw() -> None:
    out = render_html(REPORT, stem="s")

    assert '<pre class="mermaid">' in out
    assert "flowchart TD" in out
    assert "mermaid.esm.min.mjs" in out


def test_the_html_escapes_report_text() -> None:
    """The report contains attacker-derived strings from the sample."""
    out = render_html("A URL: <script>alert(1)</script> and &amp;", stem="s")

    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out


def test_the_html_states_its_network_dependency() -> None:
    """The mermaid library loads from a CDN. That limitation is stated on the
    page rather than discovered by someone opening it offline."""
    out = render_html(REPORT, stem="s")

    assert "needs network access" in out
    assert "renders it offline" in out


def test_a_report_without_a_diagram_still_renders() -> None:
    out = render_html("## Summary\n\nNo diagram here.", stem="s")

    assert "No diagram here." in out
    assert 'class="mermaid"' not in out


def test_multiple_diagrams_are_each_lifted() -> None:
    doubled = REPORT + "\n```mermaid\nflowchart LR\n  a --> b\n```\n"

    assert render_html(doubled, stem="s").count('<pre class="mermaid">') == 2


# --- the callback --------------------------------------------------------------


def test_the_callback_writes_and_publishes_the_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "reverse_engineering.reporting.writer.get_report_settings", lambda: _settings(tmp_path)
    )
    state = _State({REPORT_TEXT_KEY: REPORT, CURRENT_ARTIFACT_KEY: ARTIFACT})

    report_writer_callback(_Context(state))  # type: ignore[arg-type]

    assert len(state[REPORT_PATHS_KEY]) == 2
    assert list(tmp_path.iterdir())


def test_the_callback_is_quiet_when_there_is_no_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "reverse_engineering.reporting.writer.get_report_settings", lambda: _settings(tmp_path)
    )
    state = _State({CURRENT_ARTIFACT_KEY: ARTIFACT})

    report_writer_callback(_Context(state))  # type: ignore[arg-type]

    assert REPORT_PATHS_KEY not in state


def test_an_unwritable_directory_does_not_fail_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The report has already been delivered on screen by the time this runs."""
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x")
    monkeypatch.setattr(
        "reverse_engineering.reporting.writer.get_report_settings",
        lambda: _settings(blocker / "sub"),
    )
    state = _State({REPORT_TEXT_KEY: REPORT, CURRENT_ARTIFACT_KEY: ARTIFACT})

    report_writer_callback(_Context(state))  # type: ignore[arg-type]

    assert state[REPORT_PATHS_KEY] == []


def test_a_hostile_state_does_not_raise() -> None:
    class _Hostile:
        def get(self, *_args: object) -> object:
            raise RuntimeError("boom")

        def __setitem__(self, *_args: object) -> None:
            raise RuntimeError("boom")

    report_writer_callback(_Context(_Hostile()))  # type: ignore[arg-type]


# --- the wiring ----------------------------------------------------------------


def test_the_report_generator_publishes_its_text_and_writes_it() -> None:
    """It renders text rather than evidence, so without an output_key the report
    never reaches session state and the writer has nothing to read."""
    descriptor = MALWARE_REPORT_GENERATOR_DESCRIPTOR

    assert descriptor.output_key == REPORT_TEXT_KEY
    assert report_writer_callback in descriptor.after_agent_callbacks


def test_the_report_state_key_is_identifier_safe() -> None:
    """A colon would make it unreadable from a prompt, and a later stage may
    want to quote the report."""
    assert REPORT_TEXT_KEY.isidentifier()
