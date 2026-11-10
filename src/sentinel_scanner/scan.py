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
    # Caveats about THIS scan (wrong URL, blocked by a WAF) that the reader must see next to the results.
    notes: list[str] = field(default_factory=list)


def _target_notes(ctx: ScanContext) -> list[str]:
    """Say so when the results describe an error page or a block page instead of the real site."""
    try:
        page = ctx.home().final
    except (httpx.HTTPError, OSError):
        return []  # unreachable targets are already reported through the checks' errors
    headers = page.headers
    behind_cloudflare = "cloudflare" in headers.get("server", "").lower() or "cf-ray" in headers
    if page.status in {403, 429, 503} and (behind_cloudflare or "cf-mitigated" in headers):
        return [
            f"Cloudflare answered HTTP {page.status}: the scanner was probably blocked or challenged, "
            "so this result is INCONCLUSIVE. Ask the site owner to allow the scanner's User-Agent (staging) and re-run."
        ]
    if page.status >= 400:
        return [
            f"The start page returned HTTP {page.status}, so the findings describe an error page, "
            "not your site. Check the URL (a project site needs its full path, e.g. https://user.github.io/repo/)."
        ]
    if 300 <= page.status < 400:
        return [
            f"The start page redirected (HTTP {page.status}) somewhere the scanner will not follow."
        ]
    return []


def run_scan(
    base_url: str,
    check_names: list[str],
    client: PoliteClient,
    ssl_context: ssl.SSLContext | None = None,
    start_path: str = "/",
) -> ScanOutcome:
    started = utc_now()
    ctx = ScanContext(
        base_url=base_url, client=client, ssl_context=ssl_context, start_path=start_path
    )
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
        target=base_url if start_path == "/" else base_url + start_path,
        scanner_version=__version__,
        started_at=started,
        finished_at=utc_now(),
        findings=findings,
    )
    return ScanOutcome(
        result=result,
        errors=errors,
        checks_attempted=len(check_names),
        notes=_target_notes(ctx) if len(errors) < len(check_names) else [],
    )
