"""Command line interface. `--help` is generated from the function signatures below."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated

import typer
from rich.console import Console

from sentinel_scanner import __version__
from sentinel_scanner.checks import REGISTRY
from sentinel_scanner.config import load_settings
from sentinel_scanner.http import PoliteClient, TargetError, validate_target
from sentinel_scanner.models import Severity
from sentinel_scanner.output import render_json, render_table
from sentinel_scanner.scan import run_scan

app = typer.Typer(
    help="Defensive security scanner and log analyzer for the Sentinel platform.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)

OWNERSHIP_REFUSAL = """\
[bold red]Refusing to scan.[/bold red]

Sentinel Scanner only tests systems [bold]you own or have written permission to test[/bold].
Scanning someone else's system without permission may be illegal.

If you are authorised, confirm it explicitly by adding [bold]--i-own-this[/bold]."""

EXIT_REFUSED = (
    2  # same code used for any usage error, so scripts can tell "did not run" from "found problems"
)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"sentinel-scan {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """Sentinel Scanner."""


class OutputFormat(StrEnum):
    table = "table"
    json = "json"


EXIT_FINDINGS = 1  # findings at or above --fail-on were reported (useful in CI)
EXIT_UNREACHABLE = 3  # no check could run, e.g. the site is down


def _parse_checks(raw: str) -> list[str]:
    names = [part.strip().lower() for part in raw.split(",") if part.strip()]
    unknown = [name for name in names if name not in REGISTRY]
    if unknown or not names:
        err_console.print(
            f"[red]Unknown check(s):[/red] {', '.join(unknown) or raw!r}. Available: {', '.join(REGISTRY)}"
        )
        raise typer.Exit(code=EXIT_REFUSED)
    return list(dict.fromkeys(names))  # remove duplicates, keep order


@app.command()
def web(
    target: Annotated[
        str, typer.Argument(help="Base URL of the site to scan, e.g. https://my-site.example")
    ],
    i_own_this: Annotated[
        bool,
        typer.Option(
            "--i-own-this",
            help="REQUIRED. Confirms you own the target or have permission to test it.",
        ),
    ] = False,
    checks: Annotated[
        str, typer.Option(help=f"Comma-separated checks to run. Available: {', '.join(REGISTRY)}")
    ] = ",".join(REGISTRY),
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Output format.")
    ] = OutputFormat.table,
    fail_on: Annotated[
        Severity, typer.Option(help="Exit with code 1 if any finding is at least this severe.")
    ] = Severity.HIGH,
    insecure_tls: Annotated[
        bool,
        typer.Option(
            "--insecure-tls",
            help="Do not verify the certificate for the header/cookie/file checks (self-signed test "
            "servers). The TLS check still reports the invalid certificate.",
        ),
    ] = False,
) -> None:
    """Scan a website you own for common security misconfigurations (read-only).

    Exit codes: 0 ok, 1 findings at/above --fail-on, 2 refused or bad usage, 3 target unreachable.
    """
    # The guard runs FIRST, before anything else, including before the target is even parsed.
    if not i_own_this:
        err_console.print(OWNERSHIP_REFUSAL)
        raise typer.Exit(code=EXIT_REFUSED)

    try:
        base_url = validate_target(target)
    except TargetError as exc:
        err_console.print(f"[red]Invalid target:[/red] {exc}")
        raise typer.Exit(code=EXIT_REFUSED) from exc
    check_names = _parse_checks(checks)

    settings = load_settings()
    with PoliteClient(
        delay=settings.request_delay, timeout=settings.timeout, verify_tls=not insecure_tls
    ) as client:
        outcome = run_scan(base_url, check_names, client)

    if output_format is OutputFormat.json:
        typer.echo(render_json(outcome.result, outcome.errors))
    else:
        render_table(outcome.result, console, outcome.errors)

    if outcome.nothing_ran:
        raise typer.Exit(code=EXIT_UNREACHABLE)
    if any(f.severity.rank >= fail_on.rank for f in outcome.result.findings):
        raise typer.Exit(code=EXIT_FINDINGS)
