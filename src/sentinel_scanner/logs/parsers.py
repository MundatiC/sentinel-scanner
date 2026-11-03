"""Turn raw log lines into normalised records. Handles nginx/Apache 'combined' logs and sshd auth.log.

Logs are untrusted text (an attacker controls much of what ends up in them), so parsing is strict:
lines that do not match are counted and skipped, long lines are cut, and IPs are validated.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path

MAX_LINE_CHARS = 8192


class LogType(StrEnum):
    nginx = "nginx"
    apache = "apache"
    auth = "auth"


class Kind(StrEnum):
    REQUEST = "request"  # a web request
    AUTH_FAILURE = "auth_failure"  # a failed login (sshd)
    AUTH_SUCCESS = "auth_success"


@dataclass(frozen=True)
class LogRecord:
    time: datetime  # always timezone-aware (UTC when the log has no timezone)
    ip: str
    kind: Kind
    line: int
    user: str | None = None
    method: str | None = None
    target: str | None = None  # the raw request target: path + query string
    status: int | None = None


@dataclass
class ParseStats:
    lines: int = 0
    parsed: int = 0
    skipped: int = 0
    first: datetime | None = field(default=None)
    last: datetime | None = field(default=None)

    def seen(self, when: datetime) -> None:
        self.first = when if self.first is None or when < self.first else self.first
        self.last = when if self.last is None or when > self.last else self.last


def valid_ip(value: str) -> str | None:
    """Return the normalised IP, or None. Anything that is not a real IP is never trusted."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


# ---------------------------------------------------------------------------------------------
# nginx / Apache "combined" format:
#   203.0.113.5 - frank [10/Oct/2023:13:55:36 +0000] "GET /path?q=1 HTTP/1.1" 200 2326 "ref" "agent"
# ---------------------------------------------------------------------------------------------
_COMBINED = re.compile(
    r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "
    r'"(?P<request>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<size>\S+)'
)
_REQUEST = re.compile(r"^(?P<method>[A-Z]{3,10}) (?P<target>\S+)(?: HTTP/\S+)?$")


def parse_combined_line(line: str, number: int) -> LogRecord | None:
    match = _COMBINED.match(line)
    if not match:
        return None
    ip = valid_ip(match["ip"])
    if ip is None:
        return None
    try:
        when = datetime.strptime(match["time"], "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC)
    except ValueError:
        return None
    request = _REQUEST.match(match["request"])
    return LogRecord(
        time=when,
        ip=ip,
        kind=Kind.REQUEST,
        line=number,
        method=request["method"] if request else None,
        target=request["target"] if request else match["request"][:500],
        status=int(match["status"]),
    )


# ---------------------------------------------------------------------------------------------
# sshd lines in /var/log/auth.log (syslog) or journald exports:
#   Oct 10 13:55:36 host sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 22 ssh2
#   2023-10-10T13:55:36.123456+00:00 host sshd[1234]: Accepted publickey for alice from 198.51.100.7 port 4022
# ---------------------------------------------------------------------------------------------
_SYSLOG_TIME = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<clock>\d{2}:\d{2}:\d{2}) "
)
_ISO_TIME = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s"
)
_SSHD = re.compile(
    r"sshd(?:\[\d+\])?: (?P<result>Failed|Accepted) (?P<method>password|publickey|keyboard-interactive/pam)"
    r" for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+"
)


def _auth_time(line: str, year: int, now: datetime) -> datetime | None:
    iso = _ISO_TIME.match(line)
    if iso:
        try:
            return datetime.fromisoformat(iso["ts"].replace("Z", "+00:00")).astimezone(UTC)
        except ValueError:
            return None
    syslog = _SYSLOG_TIME.match(line)
    if not syslog:
        return None
    try:
        when = datetime.strptime(
            f"{year} {syslog['mon']} {syslog['day']} {syslog['clock']}", "%Y %b %d %H:%M:%S"
        ).replace(tzinfo=UTC)
    except ValueError:
        return None
    # Syslog has no year. A date far in the future therefore means "last year" (a log that crosses New Year).
    return when.replace(year=year - 1) if when > now + timedelta(days=1) else when


def parse_auth_line(line: str, number: int, year: int, now: datetime) -> LogRecord | None:
    match = _SSHD.search(line)
    if not match:
        return None
    ip = valid_ip(match["ip"])
    when = _auth_time(line, year, now)
    if ip is None or when is None:
        return None
    return LogRecord(
        time=when,
        ip=ip,
        kind=Kind.AUTH_FAILURE if match["result"] == "Failed" else Kind.AUTH_SUCCESS,
        line=number,
        user=match["user"][:100],
    )


def read_records(
    path: Path,
    log_type: LogType,
    stats: ParseStats,
    *,
    year: int | None = None,
    now: datetime | None = None,
) -> Iterator[LogRecord]:
    """Stream records from a file line by line (so huge logs do not fill memory)."""
    now = now or datetime.now(UTC)
    year = year or now.year
    with path.open(encoding="utf-8", errors="replace") as handle:
        for number, raw in enumerate(handle, start=1):
            stats.lines += 1
            line = raw.rstrip("\n")[:MAX_LINE_CHARS]
            if not line.strip():
                stats.lines -= 1
                continue
            record = (
                parse_auth_line(line, number, year, now)
                if log_type is LogType.auth
                else parse_combined_line(line, number)
            )
            if record is None:
                stats.skipped += 1
                continue
            stats.parsed += 1
            stats.seen(record.time)
            yield record
