"""Exposed sensitive files.

SAFETY RULES (they matter more than the feature):
  * a fixed, short list of well-known paths: no wordlists, no guessing, no crawling
  * a hit needs a CONTENT SIGNATURE, not just "200 OK" (many sites answer 200 for any path)
  * at most 1 KB of a file is ever read
  * we keep only the status, size and SHA-256 of that prefix as evidence. NEVER the content:
    finding a leaked .env must not mean copying its secrets into our reports.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass

from sentinel_scanner.checks.base import ScanContext
from sentinel_scanner.models import Category, Finding, Severity

OWASP = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"


def _matches(pattern: str, flags: int = 0) -> Callable[[bytes], bool]:
    regex = re.compile(pattern.encode(), flags)
    return lambda body: bool(regex.search(body))


def _starts(*prefixes: bytes) -> Callable[[bytes], bool]:
    return lambda body: body.startswith(prefixes)


@dataclass(frozen=True)
class Target:
    path: str
    check_id: str
    severity: Severity
    title: str
    what: str
    signature: Callable[[bytes], bool]


TARGETS: tuple[Target, ...] = (
    Target(
        "/.env",
        "files.env_exposed",
        Severity.CRITICAL,
        "Environment file (.env) is publicly readable",
        "Environment files normally contain database passwords and API keys.",
        _matches(r"^[A-Z][A-Z0-9_]{2,}\s*=", re.MULTILINE),
    ),
    Target(
        "/.git/HEAD",
        "files.git_exposed",
        Severity.CRITICAL,
        "Git repository (.git) is publicly readable",
        "Anyone can download the full source code and its history, including committed secrets.",
        _starts(b"ref:"),
    ),
    Target(
        "/.aws/credentials",
        "files.aws_credentials_exposed",
        Severity.CRITICAL,
        "AWS credentials file is publicly readable",
        "It contains cloud access keys.",
        _matches(r"aws_access_key_id", re.IGNORECASE),
    ),
    Target(
        "/id_rsa",
        "files.private_key_exposed",
        Severity.CRITICAL,
        "SSH/TLS private key is publicly readable",
        "A private key lets an attacker impersonate you or log in to your servers.",
        _matches(r"-----BEGIN (OPENSSH|RSA|EC|DSA)? ?PRIVATE KEY-----"),
    ),
    Target(
        "/backup.sql",
        "files.sql_dump_exposed",
        Severity.CRITICAL,
        "Database dump is publicly readable",
        "SQL dumps contain your users' data.",
        _matches(
            r"(CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump)", re.IGNORECASE
        ),
    ),
    Target(
        "/dump.sql",
        "files.sql_dump_exposed",
        Severity.CRITICAL,
        "Database dump is publicly readable",
        "SQL dumps contain your users' data.",
        _matches(
            r"(CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump)", re.IGNORECASE
        ),
    ),
    Target(
        "/database.sql",
        "files.sql_dump_exposed",
        Severity.CRITICAL,
        "Database dump is publicly readable",
        "SQL dumps contain your users' data.",
        _matches(
            r"(CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump)", re.IGNORECASE
        ),
    ),
    Target(
        "/backup.zip",
        "files.backup_archive_exposed",
        Severity.HIGH,
        "Backup archive is publicly downloadable",
        "Backups usually contain source code, configuration and data.",
        _starts(b"PK\x03\x04"),
    ),
    Target(
        "/site.zip",
        "files.backup_archive_exposed",
        Severity.HIGH,
        "Backup archive is publicly downloadable",
        "Backups usually contain source code, configuration and data.",
        _starts(b"PK\x03\x04"),
    ),
    Target(
        "/backup.tar.gz",
        "files.backup_archive_exposed",
        Severity.HIGH,
        "Backup archive is publicly downloadable",
        "Backups usually contain source code, configuration and data.",
        _starts(b"\x1f\x8b"),
    ),
    Target(
        "/.htpasswd",
        "files.htpasswd_exposed",
        Severity.HIGH,
        "Password file (.htpasswd) is publicly readable",
        "It contains password hashes that can be cracked offline.",
        _matches(r"^[^:\s]+:(\$|\{SHA\}|[A-Za-z0-9./]{13})", re.MULTILINE),
    ),
    Target(
        "/phpinfo.php",
        "files.phpinfo_exposed",
        Severity.MEDIUM,
        "phpinfo() page is publicly accessible",
        "It reveals versions, paths and configuration useful to attackers.",
        _matches(r"(phpinfo\(\)|PHP Version)"),
    ),
    Target(
        "/server-status",
        "files.server_status_exposed",
        Severity.MEDIUM,
        "Apache server-status page is publicly accessible",
        "It reveals live requests, client IPs and internal URLs.",
        _matches(r"Apache Server Status"),
    ),
    Target(
        "/.DS_Store",
        "files.ds_store_exposed",
        Severity.LOW,
        "macOS .DS_Store file is publicly readable",
        "It lists the names of files in the directory, including ones not meant to be public.",
        _starts(b"\x00\x00\x00\x01Bud1"),
    ),
)


class ExposedFilesCheck:
    name = "files"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        reported: set[str] = set()
        for target in TARGETS:
            if target.check_id in reported:
                continue  # one finding per kind of problem is enough
            response = ctx.client.fetch(ctx.base_url + target.path, max_bytes=1024)
            if response.status != 200 or not target.signature(response.body):
                continue
            reported.add(target.check_id)
            findings.append(
                Finding(
                    check_id=target.check_id,
                    category=Category.EXPOSED_FILES,
                    severity=target.severity,
                    title=target.title,
                    description=f"{target.what} It was returned to an unauthenticated request.",
                    remediation="Remove the file from the web root, block access to it in the web server, "
                    "and rotate any secret it contained.",
                    evidence={
                        "path": target.path,
                        "status": response.status,
                        "bytesRead": len(response.body),
                        # A fingerprint, so you can tell whether the file changed, without keeping its content.
                        "sha256OfFirst1KB": hashlib.sha256(response.body).hexdigest(),
                    },
                    references=[OWASP],
                )
            )
        return findings
