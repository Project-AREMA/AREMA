"""Write the finished report to disk, as Markdown and as HTML.

Runs as an after-agent callback on the report generator, so it sees exactly what
the model produced and adds nothing to it. The report is written verbatim: this
module formats a container around it and never edits a word inside.

Fail-open throughout. A report that cannot be written to disk is still a report
the user just read on screen, so an unwritable directory or a read-only volume
logs and returns rather than failing a run that has already done all its work.

The HTML wrapper loads mermaid from a CDN. That is a real limitation and it is
stated rather than hidden: **the ``.html`` needs network access at view time to
draw the diagram; the ``.md`` does not and is the offline-safe artifact.** The
alternative was vendoring a megabyte of JavaScript into the repository to render
one diagram, which is a worse trade for a file the user opens in a browser that
already has internet.
"""

from __future__ import annotations

import html
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from arema.core.logging import get_logger
from reverse_engineering.reporting.settings import get_report_settings
from reverse_engineering.tools.deobfuscation.state import CURRENT_ARTIFACT_KEY

if TYPE_CHECKING:
    from google.adk.agents.callback_context import CallbackContext

    from reverse_engineering.reporting.settings import ReportSettings

logger = get_logger(__name__)

# Where the written paths are published, so a later stage or the CLI can tell the
# user where the report went.
REPORT_PATHS_KEY = "report:paths"

# The state key the report generator's own output lands in.
REPORT_TEXT_KEY = "malware_report_markdown"

_MERMAID_BLOCK = re.compile(r"```mermaid\n(.*?)```", re.DOTALL)

_HTML_TEMPLATE = """<!doctype html>
<meta charset="utf-8">
<title>AREMA report {stem}</title>
<style>
 body {{ max-width: 60rem; margin: 2rem auto; padding: 0 1rem;
        font: 16px/1.6 system-ui, sans-serif; }}
 pre {{ overflow-x: auto; background: #f6f8fa; padding: 1rem; border-radius: 6px; }}
 .mermaid {{ background: #f6f8fa; padding: 1rem; border-radius: 6px; }}
 .note {{ color: #666; font-size: 0.85em; }}
</style>
<p class="note">Rendered from {stem}.md. The diagram needs network access to
draw; the Markdown file renders it offline in VS Code or on GitHub.</p>
{body}
<script type="module">
 import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs";
 mermaid.initialize({{ startOnLoad: true }});
</script>
"""

__all__ = [
    "REPORT_PATHS_KEY",
    "REPORT_TEXT_KEY",
    "render_html",
    "report_writer_callback",
    "write_report",
]


def render_html(markdown: str, *, stem: str) -> str:
    """Wrap the report in minimal HTML, with mermaid blocks left drawable.

    The report body is escaped and shown in a ``<pre>``: this is a viewer, not a
    Markdown engine, and rendering headings would mean shipping a parser to
    reformat text that is already readable. Only the mermaid fences are lifted
    out, because a diagram is the one part that is unreadable as source.
    """
    parts: list[str] = []
    cursor = 0
    for match in _MERMAID_BLOCK.finditer(markdown):
        before = markdown[cursor : match.start()]
        if before.strip():
            parts.append(f"<pre>{html.escape(before)}</pre>")
        parts.append(f'<pre class="mermaid">{html.escape(match.group(1))}</pre>')
        cursor = match.end()
    tail = markdown[cursor:]
    if tail.strip():
        parts.append(f"<pre>{html.escape(tail)}</pre>")
    return _HTML_TEMPLATE.format(stem=html.escape(stem), body="\n".join(parts))


def write_report(
    markdown: str,
    *,
    artifact_id: str,
    settings: ReportSettings | None = None,
    timestamp: datetime | None = None,
) -> tuple[str, ...]:
    """Write the report in every configured format. Returns the paths written.

    Empty when reports are disabled, when there is nothing to write, or when the
    write failed -- all three are recoverable, and none is worth failing a run
    that already produced its answer.
    """
    resolved = settings if settings is not None else get_report_settings()
    if not resolved.enabled or not markdown.strip():
        return ()

    stamp = (timestamp or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
    # The digest prefix makes a directory of reports sortable by time and
    # greppable by sample without opening any of them.
    stem = f"{stamp}_{artifact_id[:12]}" if artifact_id else stamp

    written: list[str] = []
    try:
        directory = resolved.directory
        directory.mkdir(parents=True, exist_ok=True)
        for fmt in resolved.formats:
            path = directory / f"{stem}.{fmt}"
            body = markdown if fmt == "md" else render_html(markdown, stem=stem)
            path.write_text(body, encoding="utf-8")
            written.append(str(path))
    except OSError as error:
        logger.warning(
            "report could not be written",
            error_type=type(error).__name__,
            written=len(written),
        )
        return tuple(written)

    logger.info("report written", paths=len(written), directory=str(resolved.directory))
    return tuple(written)


def report_writer_callback(callback_context: CallbackContext) -> None:
    """After-agent callback: persist the report the generator just produced.

    Returns ``None`` unconditionally so later callbacks still run, and swallows
    everything: the report has already been delivered on screen by the time this
    runs, so nothing here is worth raising over.
    """
    try:
        state = callback_context.state
        getter = getattr(state, "get", None)
        setter = getattr(state, "__setitem__", None)
        if not callable(getter) or not callable(setter):
            return
        markdown = getter(REPORT_TEXT_KEY)
        if not isinstance(markdown, str):
            return
        artifact_id = getter(CURRENT_ARTIFACT_KEY)
        paths = write_report(
            markdown, artifact_id=artifact_id if isinstance(artifact_id, str) else ""
        )
        setter(REPORT_PATHS_KEY, list(paths))
    except Exception as error:  # a written report is a bonus, never a dependency
        logger.warning("report writer failed", error_type=type(error).__name__)
