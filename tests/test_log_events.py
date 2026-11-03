from datetime import UTC, datetime, timedelta
from pathlib import Path

from sentinel_scanner.logs.detectors import BruteForceDetector, InjectionDetector
from sentinel_scanner.logs.events import default_source, detections_to_events
from sentinel_scanner.logs.parsers import LogType, ParseStats, read_records

FIXTURES = Path(__file__).parent / "fixtures"


def records(name: str, log_type: LogType):  # type: ignore[no-untyped-def]
    return list(
        read_records(
            FIXTURES / name,
            log_type,
            ParseStats(),
            year=2023,
            now=datetime(2023, 10, 20, tzinfo=UTC),
        )
    )


def test_brute_force_events_match_the_api_ingest_schema() -> None:
    detections = BruteForceDetector(5, 60).detect(records("auth.log", LogType.auth))
    events, dropped = detections_to_events(detections, "log:auth.log", 100)
    assert dropped == 0
    assert len(events) == 5
    first = events[0]
    assert first["type"] == "auth.login_failed"
    assert first["severity"] == "MEDIUM"
    assert first["ip"] == "203.0.113.9"
    assert first["actor"] == "root"
    assert first["source"] == "log:auth.log"
    assert first["occurredAt"] == "2023-10-10T13:55:01.000Z"
    assert set(first) <= {
        "type",
        "severity",
        "source",
        "actor",
        "ip",
        "message",
        "metadata",
        "occurredAt",
    }


def test_injection_events_carry_category_and_the_request() -> None:
    detections = InjectionDetector().detect(records("access.log", LogType.nginx))
    events, _ = detections_to_events(detections, "log:access.log", 100)
    by_category = {e["metadata"]["category"]: e for e in events}
    assert set(by_category) == {"sqli", "xss", "traversal"}
    sqli = by_category["sqli"]
    assert sqli["type"] == "http.injection_attempt"
    assert sqli["severity"] == "HIGH"
    assert "UNION SELECT" in sqli["message"]
    assert sqli["ip"] == "198.51.100.9"
    assert by_category["xss"]["severity"] == "MEDIUM"


def test_event_limit_drops_the_rest_and_says_so() -> None:
    detections = BruteForceDetector(5, 60).detect(records("auth.log", LogType.auth))
    events, dropped = detections_to_events(detections, "log:auth.log", 3)
    assert (len(events), dropped) == (3, 2)


def test_timestamps_in_the_future_are_clamped_to_now() -> None:
    from sentinel_scanner.logs.detectors import Detection
    from sentinel_scanner.logs.parsers import Kind, LogRecord
    from sentinel_scanner.models import Severity

    future = datetime.now(UTC) + timedelta(days=30)
    record = LogRecord(time=future, ip="203.0.113.1", kind=Kind.AUTH_FAILURE, line=1, user="x")
    detection = Detection(
        "brute_force", "203.0.113.1", 1, future, future, Severity.HIGH, records=[record]
    )
    [event] = detections_to_events([detection], "s", 10)[0]
    sent = datetime.fromisoformat(event["occurredAt"].replace("Z", "+00:00"))
    assert sent <= datetime.now(UTC)


def test_default_source_is_api_safe() -> None:
    assert default_source("auth.log") == "log:auth.log"
    assert default_source("my file (1).log") == "log:my-file--1-.log"
    assert len(default_source("x" * 500)) <= 100
