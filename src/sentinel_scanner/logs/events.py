"""Convert detections into the event payloads sentinel-api ingests."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from sentinel_scanner.logs.detectors import Detection
from sentinel_scanner.logs.parsers import LogRecord
from sentinel_scanner.logs.patterns import match_signatures
from sentinel_scanner.models import Severity, iso, utc_now

LOGIN_FAILED = "auth.login_failed"
INJECTION_ATTEMPT = "http.injection_attempt"


def default_source(filename: str) -> str:
    """The API requires a short source name; derive one from the file name."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "-", filename).strip("-")
    return f"log:{cleaned or 'file'}"[:100]


def _event_time(record: LogRecord, now: datetime) -> str:
    # The API refuses timestamps from the future, which can happen if a log's clock is ahead.
    return iso(min(record.time, now))


def detection_to_events(detection: Detection, source: str) -> list[dict[str, Any]]:
    now = utc_now()
    events: list[dict[str, Any]] = []
    for record in detection.records:
        if detection.kind == "brute_force":
            who = f" for {record.user}" if record.user else ""
            event: dict[str, Any] = {
                "type": LOGIN_FAILED,
                "severity": Severity.MEDIUM.value,
                "source": source,
                "ip": record.ip,
                "message": f"Failed login{who} from {record.ip}",
                "metadata": {"detector": "sentinel-scanner", "logLine": record.line},
            }
            if record.user:
                event["actor"] = record.user
        else:
            labels = [
                s.label
                for s in match_signatures(record.target or "")
                if s.category == detection.category
            ]
            label = labels[0] if labels else str(detection.category)
            event = {
                "type": INJECTION_ATTEMPT,
                "severity": detection.severity.value,
                "source": source,
                "ip": record.ip,
                "message": f"{label} pattern in request: {(record.target or '')[:200]}",
                "metadata": {
                    "detector": "sentinel-scanner",
                    "category": detection.category,
                    "method": record.method,
                    "status": record.status,
                    "logLine": record.line,
                },
            }
        event["occurredAt"] = _event_time(record, now)
        events.append(event)
    return events


def detections_to_events(
    detections: list[Detection], source: str, limit: int
) -> tuple[list[dict[str, Any]], int]:
    """Returns (events to send, how many were dropped because of the limit)."""
    events: list[dict[str, Any]] = []
    for detection in detections:
        events += detection_to_events(detection, source)
    dropped = max(0, len(events) - limit)
    return events[:limit], dropped
