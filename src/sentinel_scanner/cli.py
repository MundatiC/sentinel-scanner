"""Command line interface. `--help` is generated from the function signatures below."""

from __future__ import annotations

import json
import uuid
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from sentinel_scanner import __version__
from sentinel_scanner.api_client import ApiClient, ApiError, ConfigError
from sentinel_scanner.checks import REGISTRY
from sentinel_scanner.config import Settings, load_settings
from sentinel_scanner.deps.osv import OsvClient, OsvError
from sentinel_scanner.deps.parsers import DepsError
from sentinel_scanner.deps.scan import scan_dependencies
from sentinel_scanner.http import PoliteClient, TargetError, target_path, validate_target
from sentinel_scanner.logs.detectors import (
    BruteForceDetector,
    Detection,
    InjectionDetector,
    keep_relevant,
)
from sentinel_scanner.logs.events import default_source, detections_to_events
from sentinel_scanner.logs.parsers import LogType, ParseStats, read_records
from sentinel_scanner.models import ScanResult, Severity, iso
from sentinel_scanner.output import render_json, render_table
from sentinel_scanner.report.models import Postmortem, ReportError, from_incident, load_yaml
from sentinel_scanner.report.pdf import render_pdf
from sentinel_scanner.report.render import render_markdown
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
EXIT_SEND_FAILED = 4  # results were produced but could not be delivered to sentinel-api


def _api_client_or_exit(settings: Settings) -> ApiClient:
    """Build the API client BEFORE doing any work, so `--send` fails fast if it cannot succeed."""
    if settings.api_key is None:
        err_console.print(
            "[red]--send needs SENTINEL_API_KEY.[/red] Set it in the environment or a .env file "
            "(it is deliberately not a command-line option)."
        )
        raise typer.Exit(code=EXIT_REFUSED)
    try:
        return ApiClient(settings.api_url, settings.api_key, timeout=settings.timeout)
    except ConfigError as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=EXIT_REFUSED) from exc


def _send_scan(api: ApiClient, result: ScanResult) -> int:
    """Deliver a scan. Returns 0 on success or EXIT_SEND_FAILED. Messages go to stderr so that
    `--format json` output on stdout stays machine-readable."""
    try:
        sent = api.send_scan(result)
    except ApiError as exc:
        err_console.print(f"[red]Could not send results: {exc}[/red]")
        return EXIT_SEND_FAILED
    finally:
        api.close()
    err_console.print(
        f"[green]Sent to Sentinel[/green] (scan {sent.get('id')}, "
        f"{sent.get('criticalEvents', 0)} critical event(s) raised)"
    )
    return 0


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
    send: Annotated[
        bool,
        typer.Option("--send", help="Send the results to sentinel-api (needs SENTINEL_API_KEY)."),
    ] = False,
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

    Exit codes: 0 ok, 1 findings at/above --fail-on, 2 refused or bad usage, 3 target unreachable,
    4 results could not be sent.
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
    api = _api_client_or_exit(settings) if send else None
    with PoliteClient(
        delay=settings.request_delay, timeout=settings.timeout, verify_tls=not insecure_tls
    ) as client:
        outcome = run_scan(base_url, check_names, client, start_path=target_path(target))

    if output_format is OutputFormat.json:
        typer.echo(render_json(outcome.result, outcome.errors, outcome.notes))
    else:
        render_table(outcome.result, console, outcome.errors, outcome.notes)

    if outcome.nothing_ran:
        raise typer.Exit(code=EXIT_UNREACHABLE)
    # Deliver results before exiting, so a "findings" exit code never skips the upload.
    send_failed = _send_scan(api, outcome.result) if api else 0
    if any(f.severity.rank >= fail_on.rank for f in outcome.result.findings):
        raise typer.Exit(code=EXIT_FINDINGS)
    raise typer.Exit(code=send_failed)


@app.command()
def deps(
    path: Annotated[
        Path,
        typer.Argument(
            help="A lockfile (requirements.txt, package-lock.json, poetry.lock) or a project folder."
        ),
    ],
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Output format.")
    ] = OutputFormat.table,
    fail_on: Annotated[
        Severity, typer.Option(help="Exit with code 1 if any finding is at least this severe.")
    ] = Severity.HIGH,
    send: Annotated[
        bool,
        typer.Option("--send", help="Send the results to sentinel-api (needs SENTINEL_API_KEY)."),
    ] = False,
) -> None:
    """Check your project's dependencies for known vulnerabilities using the OSV database.

    Only local files are read. Package names and versions (nothing else) are sent to api.osv.dev.
    Exit codes: 0 ok, 1 findings at/above --fail-on, 2 bad usage, 3 OSV unreachable, 4 not sent.
    """
    settings = load_settings()
    api = _api_client_or_exit(settings) if send else None
    osv = OsvClient(timeout=settings.timeout)
    try:
        result, notes = scan_dependencies(path, osv)
    except DepsError as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=EXIT_REFUSED) from exc
    except OsvError as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=EXIT_UNREACHABLE) from exc
    finally:
        osv.close()

    if output_format is OutputFormat.json:
        typer.echo(render_json(result, errors={}, notes=notes))
    else:
        render_table(result, console, notes=notes)

    send_failed = _send_scan(api, result) if api else 0
    if any(f.severity.rank >= fail_on.rank for f in result.findings):
        raise typer.Exit(code=EXIT_FINDINGS)
    raise typer.Exit(code=send_failed)


def _render_detections(detections: list[Detection], stats: ParseStats) -> None:
    from rich.table import Table
    from rich.text import Text

    console.print(
        f"\nRead {stats.lines} lines: {stats.parsed} understood, {stats.skipped} skipped"
        + (
            f" ({stats.first:%Y-%m-%d %H:%M} to {stats.last:%Y-%m-%d %H:%M} UTC)"
            if stats.first and stats.last
            else ""
        )
    )
    if not detections:
        console.print("[green]No suspicious activity detected.[/green]")
        return
    table = Table()
    for column in ("Severity", "Type", "IP", "Count", "First seen (UTC)", "Detail"):
        table.add_column(column, overflow="fold")
    for d in detections:
        kind = "brute force" if d.kind == "brute_force" else f"injection ({d.category})"
        detail = f"users: {', '.join(d.users)}" if d.kind == "brute_force" else (d.sample or "")
        table.add_row(
            Text(d.severity.value), Text(kind), Text(d.ip), str(d.count),
            f"{d.first_seen:%Y-%m-%d %H:%M:%S}", Text(detail),
        )  # fmt: skip
    console.print(table)


@app.command()
def logs(
    file: Annotated[
        Path,
        typer.Argument(exists=True, dir_okay=False, readable=True, help="Log file to analyse."),
    ],
    log_type: Annotated[
        LogType,
        typer.Option(
            "--type", help="nginx/apache = 'combined' access log, auth = sshd in auth.log."
        ),
    ],
    threshold: Annotated[
        int, typer.Option(min=2, help="Failed logins from one IP that count as brute force.")
    ] = 5,
    window: Annotated[int, typer.Option(min=1, help="Brute-force time window in seconds.")] = 60,
    year: Annotated[
        int | None,
        typer.Option(
            help="Year of auth.log lines (syslog timestamps have none). Default: this year."
        ),
    ] = None,
    source: Annotated[
        str | None,
        typer.Option(
            help="Source name attached to events sent to the API. Default: log:<file name>."
        ),
    ] = None,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Output format.")
    ] = OutputFormat.table,
    send: Annotated[
        bool,
        typer.Option(
            "--send", help="Send detected events to sentinel-api (needs SENTINEL_API_KEY)."
        ),
    ] = False,
    max_events: Annotated[
        int, typer.Option(min=1, help="Maximum number of events to send.")
    ] = 5000,
) -> None:
    """Analyse a LOCAL log file for brute-force logins and injection attempts (detection only).

    Nothing is sent anywhere unless you pass --send, and then only the detected events
    (including the request path of injection attempts) go to YOUR Sentinel API, which raises the alerts.
    Timestamps without a timezone are treated as UTC.
    Exit codes: 0 nothing found, 1 detections found, 4 events could not be sent.
    """
    settings = load_settings()
    api = _api_client_or_exit(settings) if send else None

    stats = ParseStats()
    # Stream the file and keep only what a detector can use: memory must not grow with the size of the log.
    records = list(keep_relevant(read_records(file, log_type, stats, year=year)))
    detections = BruteForceDetector(threshold, window).detect(records)
    if log_type is not LogType.auth:
        detections += InjectionDetector().detect(records)
    detections.sort(key=lambda d: d.first_seen)

    if output_format is OutputFormat.json:
        typer.echo(
            json.dumps(
                {
                    "file": file.name,
                    "stats": {
                        "lines": stats.lines,
                        "parsed": stats.parsed,
                        "skipped": stats.skipped,
                    },
                    "detections": [
                        {
                            "kind": d.kind,
                            "ip": d.ip,
                            "count": d.count,
                            "severity": d.severity.value,
                            "category": d.category,
                            "users": d.users,
                            "sample": d.sample,
                            "firstSeen": iso(d.first_seen),
                            "lastSeen": iso(d.last_seen),
                        }  # fmt: skip
                        for d in detections
                    ],
                },
                indent=2,
            )
        )
    else:
        _render_detections(detections, stats)

    send_failed = 0
    if api:
        events, dropped = detections_to_events(
            detections, source or default_source(file.name), max_events
        )
        if dropped:
            err_console.print(
                f"[yellow]{dropped} event(s) not sent (limit --max-events {max_events}).[/yellow]"
            )
        try:
            accepted = api.send_events(events) if events else 0
            err_console.print(f"[green]Sent {accepted} event(s) to Sentinel.[/green]")
        except ApiError as exc:
            err_console.print(
                f"[red]Could not send events ({exc.accepted} accepted before failing): {exc}[/red]"
            )
            send_failed = EXIT_SEND_FAILED
        finally:
            api.close()

    if detections:
        raise typer.Exit(code=EXIT_FINDINGS)
    raise typer.Exit(code=send_failed)


def _fetch_incident(incident_id: str, settings: Settings) -> Postmortem:
    try:
        uuid.UUID(incident_id)  # also guarantees the id is safe to place in a URL path
    except ValueError as exc:
        err_console.print("[red]--incident-id must be a UUID.[/red]")
        raise typer.Exit(code=EXIT_REFUSED) from exc
    api = _api_client_or_exit(settings)
    try:
        return from_incident(api.get_incident(incident_id))
    except ApiError as exc:
        err_console.print(f"[red]Could not fetch the incident: {exc}[/red]")
        raise typer.Exit(code=EXIT_UNREACHABLE) from exc
    except ReportError as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=EXIT_REFUSED) from exc
    finally:
        api.close()


@app.command()
def postmortem(
    out: Annotated[Path, typer.Option("--out", help="Markdown file to write, e.g. report.md")],
    timeline: Annotated[
        Path | None,
        typer.Option(exists=True, dir_okay=False, readable=True, help="YAML timeline file."),
    ] = None,
    incident_id: Annotated[
        str | None,
        typer.Option(
            help="Fetch this incident from sentinel-api (needs SENTINEL_API_KEY with incidents:read)."
        ),
    ] = None,
    pdf: Annotated[
        bool, typer.Option("--pdf", help="Also write a PDF next to the Markdown file.")
    ] = False,
    force: Annotated[
        bool, typer.Option("--force", help="Overwrite existing output files.")
    ] = False,
) -> None:
    """Generate an incident post-mortem report (Markdown, optionally PDF).

    Give exactly one source: --timeline FILE (see examples/incident.yaml) or --incident-id UUID.
    Fields the source does not contain are left as clearly marked TODOs for the team to complete.
    """
    if (timeline is None) == (incident_id is None):
        err_console.print("[red]Give exactly one of --timeline or --incident-id.[/red]")
        raise typer.Exit(code=EXIT_REFUSED)

    pdf_path = out.with_suffix(".pdf")
    targets = [out, *([pdf_path] if pdf else [])]
    existing = [str(path) for path in targets if path.exists()]
    if existing and not force:
        err_console.print(
            f"[red]Refusing to overwrite {', '.join(existing)}.[/red] Use --force to replace."
        )
        raise typer.Exit(code=EXIT_REFUSED)

    try:
        report = (
            load_yaml(timeline) if timeline else _fetch_incident(str(incident_id), load_settings())
        )
    except ReportError as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=EXIT_REFUSED) from exc

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_markdown(report), encoding="utf-8")
    console.print(f"Wrote [bold]{out}[/bold]")
    if pdf:
        pdf_path.write_bytes(render_pdf(report))
        console.print(f"Wrote [bold]{pdf_path}[/bold]")
