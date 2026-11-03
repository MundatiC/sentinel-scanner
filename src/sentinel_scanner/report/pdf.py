"""PDF output with fpdf2 (pure Python: no system libraries needed).

Limitation: only the built-in Helvetica font is used, which covers Latin-1. Characters outside it
(emoji, CJK, some typographic quotes) are replaced, so use the Markdown output when you need them.
"""

from __future__ import annotations

from datetime import datetime

from fpdf import FPDF
from fpdf.enums import XPos, YPos

from sentinel_scanner.models import utc_now
from sentinel_scanner.report.models import TODO, Postmortem

_REPLACEMENTS = {
    "‘": "'", "’": "'", "“": '"', "”": '"', "–": "-", "—": "-",
    "…": "...", "•": "-", " ": " ", "\t": "    ",
}  # fmt: skip
PLACEHOLDER = TODO.strip("_")


def latin1(value: object) -> str:
    """Make text safe for the core PDF fonts. Never raises."""
    text = str(value)
    for old, new in _REPLACEMENTS.items():
        text = text.replace(old, new)
    return text.encode("latin-1", "replace").decode("latin-1")


class _Report(FPDF):
    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120)
        self.cell(0, 8, f"Page {self.page_no()}/{{nb}}", align="C")


def _stamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S")


def render_pdf(postmortem: Postmortem, *, generated: datetime | None = None) -> bytes:
    pdf = _Report(format="A4")
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.set_title(latin1(f"Post-mortem: {postmortem.title}"))
    pdf.set_creator("sentinel-scanner")
    pdf.alias_nb_pages()
    pdf.add_page()
    width = pdf.epw

    def heading(text: str) -> None:
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(20, 60, 90)
        pdf.cell(0, 8, latin1(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(0)

    def paragraph(text: str) -> None:
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(
            width, 5.5, latin1(text.strip() or PLACEHOLDER), new_x=XPos.LMARGIN, new_y=YPos.NEXT
        )

    def bullets(items: list[str]) -> None:
        pdf.set_font("Helvetica", "", 10)
        if not items:
            paragraph("")
        for item in items:
            pdf.multi_cell(width, 5.5, latin1(f"- {item}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_font("Helvetica", "B", 18)
    pdf.multi_cell(
        width, 9, latin1(f"Post-mortem: {postmortem.title}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT
    )
    pdf.ln(2)

    meta = [("Severity", postmortem.severity), ("Status", postmortem.status)]
    if postmortem.owner:
        meta.append(("Owner", postmortem.owner))
    for label, moment in (
        ("Started", postmortem.started_at),
        ("Detected", postmortem.detected_at),
        ("Resolved", postmortem.resolved_at),
    ):
        if moment:
            meta.append((label, _stamp(moment)))
    for label, span in (
        ("Time to detect", postmortem.time_to_detect()),
        ("Time to resolve", postmortem.time_to_resolve()),
    ):
        if span:
            meta.append((label, span))
    for label, text in meta:
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(38, 6, latin1(label))
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, latin1(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    heading("Summary")
    paragraph(postmortem.summary)
    heading("Impact")
    paragraph(postmortem.impact)

    heading("Timeline")
    entries = postmortem.sorted_timeline()
    if entries:
        pdf.set_font("Helvetica", "", 9)
        with pdf.table(col_widths=(34, 22, 124), text_align="LEFT", line_height=5) as table:
            header = table.row()
            for title in ("Time (UTC)", "Type", "What happened"):
                header.cell(title)
            for entry in entries:
                row = table.row()
                row.cell(_stamp(entry.time))
                row.cell(latin1(entry.kind))
                suffix = f" ({entry.author})" if entry.author else ""
                row.cell(latin1(entry.description + suffix))
    else:
        paragraph("")

    heading("Detection")
    paragraph(postmortem.detection)
    heading("Root cause")
    paragraph(postmortem.root_cause)
    heading("Response")
    paragraph(postmortem.response)
    heading("What went well")
    bullets(postmortem.went_well)
    heading("Lessons learned")
    bullets(postmortem.lessons)

    heading("Action items")
    if postmortem.action_items:
        pdf.set_font("Helvetica", "", 9)
        with pdf.table(col_widths=(100, 40, 40), text_align="LEFT", line_height=5) as table:
            header = table.row()
            for title in ("Action", "Owner", "Due"):
                header.cell(title)
            for item in postmortem.action_items:
                row = table.row()
                row.cell(latin1(item.description))
                row.cell(latin1(item.owner))
                row.cell(str(item.due or "not set"))
    else:
        paragraph("")

    pdf.ln(4)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(120)
    pdf.cell(0, 5, f"Generated by sentinel-scanner on {_stamp(generated or utc_now())}")
    return bytes(pdf.output())
