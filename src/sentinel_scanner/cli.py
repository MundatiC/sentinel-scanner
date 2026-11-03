"""Command line interface. `--help` is generated from the function signatures below."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Console

from sentinel_scanner import __version__
from sentinel_scanner.config import load_settings
from sentinel_scanner.http import TargetError, validate_target

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
    insecure_tls: Annotated[
        bool,
        typer.Option(
            "--insecure-tls",
            help="Do not verify the target's TLS certificate (self-signed test servers).",
        ),
    ] = False,
) -> None:
    """Scan a website you own for common security misconfigurations (read-only)."""
    # The guard runs FIRST, before anything else, including before the target is even parsed.
    if not i_own_this:
        err_console.print(OWNERSHIP_REFUSAL)
        raise typer.Exit(code=EXIT_REFUSED)

    try:
        base_url = validate_target(target)
    except TargetError as exc:
        err_console.print(f"[red]Invalid target:[/red] {exc}")
        raise typer.Exit(code=EXIT_REFUSED) from exc

    settings = load_settings()
    console.print(f"Target confirmed as yours: [bold]{base_url}[/bold]")
    console.print(
        f"(request delay {settings.request_delay}s, timeout {settings.timeout}s, "
        f"TLS verify: {not insecure_tls})"
    )
    console.print("[yellow]No checks are installed yet.[/yellow]")
