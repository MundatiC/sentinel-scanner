"""Render a Postmortem as Markdown. Text that may come from attackers is neutralised on the way out."""

from __future__ import annotations

import re
from datetime import datetime

from jinja2 import Environment, PackageLoader, StrictUndefined

from sentinel_scanner.models import utc_now
from sentinel_scanner.report.models import TODO, Postmortem


def _escape_html(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def inline(value: object) -> str:
    """For a table cell or list item: HTML-escaped, on one line, with | made harmless."""
    text = _escape_html(str(value))
    text = re.sub(r"\s*\n\s*", " ", text).strip()
    return text.replace("|", "\\|")


def block(value: object) -> str:
    """For paragraphs: HTML-escaped, but line breaks are kept."""
    return _escape_html(str(value)).strip()


def stamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S")


def render_markdown(postmortem: Postmortem, *, generated: datetime | None = None) -> str:
    """Why escape HTML? Report text can include alert titles, usernames and log lines that an
    attacker controls. Many Markdown viewers render raw HTML, so `<script>` must stay inert text."""
    env = Environment(
        loader=PackageLoader("sentinel_scanner.report", "templates"),
        autoescape=False,  # noqa: S701  Markdown, not HTML: escaping is done explicitly by the filters above
        undefined=StrictUndefined,  # a typo in the template fails loudly instead of printing nothing
        keep_trailing_newline=True,
        trim_blocks=False,
    )
    env.filters.update(inline=inline, block=block, stamp=stamp)
    template = env.get_template("postmortem.md.j2")
    output = template.render(
        pm=postmortem,
        timeline=postmortem.sorted_timeline(),
        todo=TODO,
        generated=generated or utc_now(),
    )
    return re.sub(r"\n{3,}", "\n\n", output)
