"""Turns scan results into terminal tables or JSON."""

from __future__ import annotations

import json

from rich.console import Console
from rich.table import Table
from rich.text import Text

from sentinel_scanner.models import ScanResult, Severity

COLORS = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


def render_table(
    result: ScanResult,
    console: Console,
    errors: dict[str, str] | None = None,
    notes: list[str] | None = None,
) -> None:
    """Pretty table for humans. Everything is wrapped in Text() so that text which came from the
    target (header values etc.) can never be interpreted as terminal markup."""
    findings = sorted(result.findings, key=lambda f: (-f.severity.rank, f.check_id))
    console.print(f"\nScan of [bold]{Text(result.target)}[/bold]")

    if findings:
        table = Table(show_lines=False)
        table.add_column("Severity")
        table.add_column("Check")
        table.add_column("Finding", overflow="fold")
        for finding in findings:
            table.add_row(
                Text(finding.severity.value, style=COLORS[finding.severity]),
                Text(finding.check_id),
                Text(finding.title),
            )
        console.print(table)
    else:
        console.print("[green]No findings.[/green]")

    counts = result.counts()
    summary = "  ".join(f"{name}: {count}" for name, count in counts.items() if count)
    console.print(f"Summary: {summary or 'nothing to report'}")
    for note in notes or []:
        console.print(Text(f"- {note}", style="dim"))
    for check, message in (errors or {}).items():
        console.print(Text(f"! check '{check}' could not run: {message}", style="yellow"))


def render_json(
    result: ScanResult, errors: dict[str, str] | None = None, notes: list[str] | None = None
) -> str:
    payload = {
        **result.to_api(),
        "counts": result.counts(),
        "errors": errors or {},
        "notes": notes or [],
    }
    return json.dumps(payload, indent=2)
