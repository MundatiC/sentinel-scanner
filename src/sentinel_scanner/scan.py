"""Runs the selected checks against one target and collects the results."""

from __future__ import annotations

import ssl
from dataclasses import dataclass, field

import httpx

from sentinel_scanner import __version__
from sentinel_scanner.checks import REGISTRY
from sentinel_scanner.checks.base import ScanContext
from sentinel_scanner.http import PoliteClient
from sentinel_scanner.models import ScanResult, utc_now


@dataclass
class ScanOutcome:
    result: ScanResult
    # check name -> why it could not run (e.g. the site was unreachable). Not a finding: it is a
    # limitation of THIS scan, and the user must know the check did not actually run.
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def nothing_ran(self) -> bool:
        return bool(self.errors) and len(self.errors) == self.checks_attempted

    checks_attempted: int = 0


def run_scan(
    base_url: str,
    check_names: list[str],
    client: PoliteClient,
    ssl_context: ssl.SSLContext | None = None,
) -> ScanOutcome:
    started = utc_now()
    ctx = ScanContext(base_url=base_url, client=client, ssl_context=ssl_context)
    findings = []
    errors: dict[str, str] = {}

    for name in check_names:
        check = REGISTRY[name]()
        try:
            findings.extend(check.run(ctx))
        except (httpx.HTTPError, OSError) as exc:
            # One failing check (e.g. a timeout) must not stop the others.
            errors[name] = f"{type(exc).__name__}: {exc}"[:300]

    result = ScanResult(
        target=base_url,
        scanner_version=__version__,
        started_at=started,
        finished_at=utc_now(),
        findings=findings,
    )
    return ScanOutcome(result=result, errors=errors, checks_attempted=len(check_names))
