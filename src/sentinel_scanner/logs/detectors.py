"""Detectors turn normalised log records into 'detections' (things worth an analyst's attention)."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Literal

from sentinel_scanner.logs.parsers import Kind, LogRecord
from sentinel_scanner.logs.patterns import match_signatures
from sentinel_scanner.models import Severity

MAX_EVENTS_PER_DETECTION = 1000


@dataclass
class Detection:
    kind: Literal["brute_force", "injection"]
    ip: str
    count: int
    first_seen: datetime
    last_seen: datetime
    severity: Severity
    category: str | None = None  # injection: sqli / xss / traversal / cmdi
    users: list[str] = field(default_factory=list)  # brute force: usernames that were tried
    sample: str | None = None  # injection: a (truncated) example request target
    records: list[LogRecord] = field(default_factory=list, repr=False)


def _is_failed_login(record: LogRecord) -> bool:
    # sshd "Failed password" lines, or web requests answered with 401 Unauthorized.
    return record.kind is Kind.AUTH_FAILURE or (
        record.kind is Kind.REQUEST and record.status == 401
    )


def keep_relevant(records: Iterable[LogRecord]) -> Iterator[LogRecord]:
    """Pass through only the records a detector can use: failed logins and requests that match an attack
    signature. Everything else (the vast majority of a real access log) is dropped as it streams by, so
    memory stays flat however big the file is. Detectors give the same answer with or without this filter."""
    for record in records:
        if _is_failed_login(record) or record.kind is Kind.REQUEST and record.target and match_signatures(record.target):
            yield record


class BruteForceDetector:
    """At least `threshold` failed logins from one IP inside any `window_seconds` window.

    This is the SAME rule the Sentinel API ships by default (5 failures in 60 s per IP), so you
    can compare what the scanner sees in a log file with what the API alerts on.
    """

    def __init__(self, threshold: int = 5, window_seconds: int = 60) -> None:
        if threshold < 2 or window_seconds < 1:
            raise ValueError("threshold must be >= 2 and window_seconds >= 1")
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)

    def detect(self, records: Iterable[LogRecord]) -> list[Detection]:
        by_ip: dict[str, list[LogRecord]] = defaultdict(list)
        for record in records:
            if _is_failed_login(record):
                by_ip[record.ip].append(record)

        detections: list[Detection] = []
        for ip, failures in by_ip.items():
            failures.sort(key=lambda r: r.time)
            detections += self._detect_for_ip(ip, failures)
        return sorted(detections, key=lambda d: d.first_seen)

    def _detect_for_ip(self, ip: str, failures: list[LogRecord]) -> list[Detection]:
        # Sliding window: mark every failure that belongs to some window holding >= threshold failures.
        in_burst = [False] * len(failures)
        left = 0
        for right, record in enumerate(failures):
            while record.time - failures[left].time > self.window:
                left += 1
            if right - left + 1 >= self.threshold:
                for index in range(left, right + 1):
                    in_burst[index] = True

        # Consecutive marked failures form one burst = one detection. A burst also ends where the
        # pause between two failures is longer than the window, even if both are marked: they then
        # belong to two separate attacks, not one.
        detections: list[Detection] = []
        start: int | None = None
        for index in range(len(failures) + 1):
            flagged = index < len(failures) and in_burst[index]
            continues = (
                flagged
                and start is not None
                and failures[index].time - failures[index - 1].time <= self.window
            )
            if start is not None and not continues:
                detections.append(self._burst(ip, failures[start:index]))
                start = None
            if flagged and start is None:
                start = index
        return detections

    @staticmethod
    def _burst(ip: str, run: list[LogRecord]) -> Detection:
        return Detection(
            kind="brute_force",
            ip=ip,
            count=len(run),
            first_seen=run[0].time,
            last_seen=run[-1].time,
            severity=Severity.HIGH,
            users=list(dict.fromkeys(r.user for r in run if r.user))[:10],
            records=run[:MAX_EVENTS_PER_DETECTION],
        )


class InjectionDetector:
    """Requests whose URL contains a known injection pattern (SQLi, XSS, path traversal, command chaining)."""

    def detect(self, records: Iterable[LogRecord]) -> list[Detection]:
        grouped: dict[tuple[str, str], list[tuple[LogRecord, Severity]]] = defaultdict(list)
        for record in records:
            if record.kind is not Kind.REQUEST or not record.target:
                continue
            for signature in match_signatures(record.target):
                grouped[(record.ip, signature.category)].append((record, signature.severity))

        detections: list[Detection] = []
        for (ip, category), hits in grouped.items():
            hits.sort(key=lambda hit: hit[0].time)
            records = [hit[0] for hit in hits]
            detections.append(
                Detection(
                    kind="injection",
                    ip=ip,
                    count=len(records),
                    first_seen=records[0].time,
                    last_seen=records[-1].time,
                    severity=max((hit[1] for hit in hits), key=lambda s: s.rank),
                    category=category,
                    sample=(records[0].target or "")[:200],
                    records=records[:MAX_EVENTS_PER_DETECTION],
                )
            )
        return sorted(detections, key=lambda d: d.first_seen)
