"""Client for the OSV vulnerability database (https://google.github.io/osv.dev/api/).

Privacy note: this sends package NAMES and VERSIONS (nothing else) to api.osv.dev.
Flow: one batch call per 500 packages returns vulnerability IDs; then one GET per unique ID
fetches the details (summary, severity, fixed versions).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import httpx

from sentinel_scanner import __version__
from sentinel_scanner.deps.cvss import cvss3_base_score, score_to_severity
from sentinel_scanner.deps.parsers import Dependency, normalize_pypi
from sentinel_scanner.models import Category, Finding, Severity

OSV_URL = "https://api.osv.dev"
BATCH_SIZE = 500
MAX_PAGES = 20
MAX_DETAIL_LOOKUPS = 300
SAFE_VULN_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,100}$")

_DB_SEVERITY = {
    "LOW": Severity.LOW,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


class OsvError(RuntimeError):
    """OSV could not be reached or returned something we cannot understand."""


@dataclass
class Vuln:
    id: str
    summary: str = ""
    details: str = ""
    aliases: list[str] = field(default_factory=list)
    severity: Severity | None = None
    references: list[str] = field(default_factory=list)
    raw_affected: list[dict[str, Any]] = field(default_factory=list)


class OsvClient:
    def __init__(
        self, base_url: str = OSV_URL, *, timeout: float = 15.0, client: httpx.Client | None = None
    ):
        self._base = base_url.rstrip("/")
        self._client = client or httpx.Client(
            timeout=timeout, headers={"User-Agent": f"Sentinel-Scanner/{__version__}"}
        )

    def close(self) -> None:
        self._client.close()

    def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        try:
            response = self._client.request(method, self._base + path, **kwargs)
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPError as exc:
            raise OsvError(f"OSV request failed: {exc}") from exc
        except ValueError as exc:
            raise OsvError("OSV returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise OsvError("OSV returned an unexpected response")
        return data

    def query_batch(self, dependencies: list[Dependency]) -> dict[Dependency, list[str]]:
        """Map each dependency to the IDs of the vulnerabilities that affect it."""
        found: dict[Dependency, list[str]] = {}
        for start in range(0, len(dependencies), BATCH_SIZE):
            chunk = dependencies[start : start + BATCH_SIZE]
            pending = {index: None for index in range(len(chunk))}  # index -> next page token
            ids: dict[int, list[str]] = {index: [] for index in range(len(chunk))}

            for _page in range(MAX_PAGES):
                if not pending:
                    break
                order = list(pending)
                queries = []
                for index in order:
                    dep = chunk[index]
                    query: dict[str, Any] = {
                        "package": {"name": dep.name, "ecosystem": dep.ecosystem},
                        "version": dep.version,
                    }
                    if pending[index]:
                        query["page_token"] = pending[index]
                    queries.append(query)

                results = self._request("POST", "/v1/querybatch", json={"queries": queries}).get(
                    "results"
                )
                if not isinstance(results, list) or len(results) != len(queries):
                    raise OsvError("OSV returned a different number of results than queries")

                pending = {}
                for index, result in zip(order, results, strict=True):
                    result = result if isinstance(result, dict) else {}
                    ids[index] += [
                        v["id"]
                        for v in result.get("vulns", [])
                        if isinstance(v, dict) and "id" in v
                    ]
                    if result.get("next_page_token"):
                        pending[index] = result["next_page_token"]

            for index, dep in enumerate(chunk):
                if ids[index]:
                    found[dep] = list(dict.fromkeys(ids[index]))
        return found

    def get_vuln(self, vuln_id: str) -> Vuln:
        # The id came from a network response: validate it before using it in a URL path.
        if not SAFE_VULN_ID.match(vuln_id):
            raise OsvError(f"Refusing to look up suspicious vulnerability id {vuln_id[:40]!r}")
        return parse_vuln(self._request("GET", f"/v1/vulns/{vuln_id}"))


def _severity_of(data: dict[str, Any]) -> Severity | None:
    db = data.get("database_specific")
    if isinstance(db, dict) and isinstance(db.get("severity"), str):
        mapped = _DB_SEVERITY.get(db["severity"].upper())
        if mapped:
            return mapped
    for entry in data.get("severity", []) or []:
        if isinstance(entry, dict) and str(entry.get("type", "")).startswith("CVSS_V3"):
            score = cvss3_base_score(str(entry.get("score", "")))
            if score is not None:
                return score_to_severity(score)
    return None


def parse_vuln(data: dict[str, Any]) -> Vuln:
    refs = [
        r["url"]
        for r in data.get("references", [])
        if isinstance(r, dict)
        and isinstance(r.get("url"), str)
        and r["url"].startswith(("https://", "http://"))
    ]
    return Vuln(
        id=str(data.get("id", "")),
        summary=str(data.get("summary", ""))[:300],
        details=str(data.get("details", ""))[:1500],
        aliases=[a for a in data.get("aliases", []) if isinstance(a, str)][:5],
        severity=_severity_of(data),
        references=refs[:10],
        raw_affected=[a for a in data.get("affected", []) if isinstance(a, dict)],
    )


def fixed_versions(vuln: Vuln, dependency: Dependency) -> list[str]:
    fixed: list[str] = []
    for affected in vuln.raw_affected:
        package = affected.get("package", {})
        name = str(package.get("name", ""))
        if package.get("ecosystem") != dependency.ecosystem:
            continue
        if dependency.ecosystem == "PyPI":
            name = normalize_pypi(name)
        if name != dependency.name:
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    fixed.append(event["fixed"])
    return sorted(set(fixed))[:5]


def build_findings(
    matches: dict[Dependency, list[str]], vulns: dict[str, Vuln | None]
) -> list[Finding]:
    """One finding per (package version, vulnerability)."""
    findings: list[Finding] = []
    for dep, ids in matches.items():
        for vuln_id in ids:
            vuln = vulns.get(vuln_id)
            severity = (vuln.severity if vuln else None) or Severity.MEDIUM
            fixes = fixed_versions(vuln, dep) if vuln else []
            title = f"{dep.name} {dep.version} has a known vulnerability: {(vuln.summary if vuln else '') or vuln_id}"
            remediation = (
                f"Upgrade {dep.name} to {' or '.join(fixes)} (or later)."
                if fixes
                else f"Check {vuln_id} for a fixed version, upgrade {dep.name}, or remove it if unused."
            )
            findings.append(
                Finding(
                    check_id=f"deps.{vuln_id}",
                    category=Category.DEPENDENCIES,
                    severity=severity,
                    title=title[:300],
                    description=(
                        vuln.details
                        if vuln and vuln.details
                        else f"{vuln_id} affects {dep.name} {dep.version}."
                    )[:1500],
                    remediation=remediation,
                    evidence={
                        "package": dep.name,
                        "version": dep.version,
                        "ecosystem": dep.ecosystem,
                        "vulnerability": vuln_id,
                        "aliases": vuln.aliases if vuln else [],
                        "fixedVersions": fixes,
                        "lockfile": dep.source,
                        **({} if vuln and vuln.severity else {"severityUnknown": True}),
                    },
                    references=(vuln.references if vuln else [])[:10]
                    or [f"https://osv.dev/vulnerability/{vuln_id}"],
                )
            )
    return findings


def lookup(client: OsvClient, dependencies: list[Dependency]) -> tuple[list[Finding], list[str]]:
    """Full pipeline. Returns (findings, notes) where notes explain anything that was skipped."""
    notes: list[str] = []
    matches = client.query_batch(dependencies)
    unique_ids = list(dict.fromkeys(i for ids in matches.values() for i in ids))
    vulns: dict[str, Vuln | None] = {}
    for vuln_id in unique_ids[:MAX_DETAIL_LOOKUPS]:
        vulns[vuln_id] = client.get_vuln(vuln_id)
    if len(unique_ids) > MAX_DETAIL_LOOKUPS:
        notes.append(
            f"{len(unique_ids) - MAX_DETAIL_LOOKUPS} vulnerabilities were reported without details "
            f"(limit of {MAX_DETAIL_LOOKUPS} detail lookups)"
        )
    return build_findings(matches, vulns), notes
