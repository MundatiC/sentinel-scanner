from datetime import UTC, datetime

from sentinel_scanner.models import Category, Finding, ScanResult, Severity, iso


def finding(severity: Severity = Severity.MEDIUM) -> Finding:
    return Finding(
        check_id="headers.hsts_missing",
        category=Category.HEADERS,
        severity=severity,
        title="HSTS missing",
        description="d",
        remediation="r",
    )


def test_finding_serialises_to_the_api_shape() -> None:
    data = finding().to_api()
    assert data["checkId"] == "headers.hsts_missing"
    assert data["category"] == "HEADERS"
    assert data["severity"] == "MEDIUM"
    assert data["references"] == []


def test_scan_counts_and_api_payload() -> None:
    start = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)
    scan = ScanResult(
        target="https://example.com",
        scanner_version="0.1.0",
        started_at=start,
        finished_at=start,
        findings=[finding(Severity.HIGH), finding(Severity.HIGH), finding(Severity.LOW)],
    )
    assert scan.counts() == {"INFO": 0, "LOW": 1, "MEDIUM": 0, "HIGH": 2, "CRITICAL": 0}
    payload = scan.to_api()
    assert payload["startedAt"] == "2026-01-01T10:00:00.000Z"
    assert len(payload["findings"]) == 3


def test_iso_always_ends_in_z() -> None:
    assert iso(datetime(2026, 5, 4, 3, 2, 1, 123000, tzinfo=UTC)) == "2026-05-04T03:02:01.123Z"


def test_severity_ordering() -> None:
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.INFO.rank
