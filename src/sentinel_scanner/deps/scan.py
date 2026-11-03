"""Ties parsing and OSV together into a ScanResult the CLI and API client can use."""

from __future__ import annotations

import re
from pathlib import Path

from sentinel_scanner import __version__
from sentinel_scanner.deps.osv import OsvClient, lookup
from sentinel_scanner.deps.parsers import parse_path
from sentinel_scanner.models import ScanResult, utc_now


def project_target(path: Path) -> str:
    """Dependency scans have no website, so the 'target' is local://<project-name>."""
    base = path.resolve()
    name = base.name if base.is_dir() else base.parent.name
    return "local://" + (re.sub(r"[^A-Za-z0-9._-]", "-", name).strip("-") or "project")


def scan_dependencies(path: Path, osv: OsvClient) -> tuple[ScanResult, list[str]]:
    """Returns the result and human-readable notes (skipped packages, truncated lookups)."""
    started = utc_now()
    parsed = parse_path(path)
    findings, notes = lookup(osv, parsed.dependencies) if parsed.dependencies else ([], [])
    result = ScanResult(
        target=project_target(path),
        scanner_version=__version__,
        started_at=started,
        finished_at=utc_now(),
        findings=findings,
    )
    summary = [f"Checked {len(parsed.dependencies)} packages from {', '.join(parsed.files)}"]
    summary += [f"Skipped: {item}" for item in parsed.skipped]
    return result, summary + notes
