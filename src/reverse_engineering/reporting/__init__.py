"""Persist the finished report where a human can actually read it.

The pipeline renders a Markdown report containing a mermaid execution diagram.
ADK's developer web UI cannot draw it: it bundles ``ngx-markdown`` with
``mermaid: false`` in both its parse and render defaults and ships no mermaid
library, so the diagram shows as a fenced code block. That is a vendored
dependency, and patching ``site-packages`` is not a fix.

Writing the report to disk is. A ``.md`` file renders the diagram in VS Code and
on GitHub with no dependencies and no network, and an ``.html`` file opens in any
browser. Both are also the artifact an analyst actually wants at the end of a
case, which the transcript never was.
"""

from __future__ import annotations

from reverse_engineering.reporting.settings import (
    ReportSettings,
    clear_report_settings_cache,
    get_report_settings,
)
from reverse_engineering.reporting.writer import (
    REPORT_PATHS_KEY,
    render_html,
    report_writer_callback,
    write_report,
)

__all__ = [
    "REPORT_PATHS_KEY",
    "ReportSettings",
    "clear_report_settings_cache",
    "get_report_settings",
    "render_html",
    "report_writer_callback",
    "write_report",
]
