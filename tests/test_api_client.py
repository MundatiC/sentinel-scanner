import json
from datetime import UTC, datetime

import httpx
import pytest
from pydantic import SecretStr

from sentinel_scanner.api_client import ApiClient, ApiError, ConfigError, check_api_url
from sentinel_scanner.models import Category, Finding, ScanResult, Severity

KEY = "snt_deadbeef_" + "A" * 43


def client(handler, url: str = "http://localhost:4000") -> ApiClient:  # type: ignore[no-untyped-def]
    return ApiClient(url, SecretStr(KEY), transport=httpx.MockTransport(handler))


def scan() -> ScanResult:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    finding = Finding(
        check_id="headers.hsts_missing", category=Category.HEADERS, severity=Severity.MEDIUM,
        title="t", description="d", remediation="r",
    )  # fmt: skip
    return ScanResult(
        target="https://example.com",
        scanner_version="0.1.0",
        started_at=now,
        finished_at=now,
        findings=[finding],
    )


class TestCheckApiUrl:
    @pytest.mark.parametrize(
        "url",
        [
            "https://sentinel.example.com",
            "https://sentinel.example.com/",
            "http://localhost:4000",
            "http://127.0.0.1:4000",
            "http://[::1]:4000",
            "http://api:4000",  # docker-compose service name
            "http://10.0.0.5:4000",  # private network
            "http://192.168.1.10:4000",
        ],
    )
    def test_allowed(self, url: str) -> None:
        assert check_api_url(url) == url.rstrip("/")

    @pytest.mark.parametrize(
        "url",
        [
            "http://sentinel.example.com",
            "http://8.8.8.8:4000",
            "http://[2606:4700::1111]:4000",
            "ftp://x",
            "localhost:4000",
            "",
        ],
    )
    def test_rejected(self, url: str) -> None:
        with pytest.raises(ConfigError):
            check_api_url(url)


class TestRequests:
    def test_send_scan_posts_the_api_payload_with_the_key_header(self) -> None:
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(201, json={"id": "abc", "criticalEvents": 0})

        result = client(handler).send_scan(scan())
        assert result["id"] == "abc"
        request = seen[0]
        assert (request.method, request.url.path) == ("POST", "/api/v1/ingest/scans")
        assert request.headers["x-api-key"] == KEY
        assert json.loads(request.content)["findings"][0]["checkId"] == "headers.hsts_missing"

    def test_send_events_splits_into_batches_of_500(self) -> None:
        sizes: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            n = len(json.loads(request.content)["events"])
            sizes.append(n)
            return httpx.Response(201, json={"accepted": n})

        events = [{"type": "auth.login_failed"}] * 1200
        assert client(handler).send_events(events) == 1200
        assert sizes == [500, 500, 200]

    def test_a_failure_in_a_later_batch_reports_how_many_were_accepted(self) -> None:
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 2:
                return httpx.Response(
                    429,
                    json={
                        "error": {"code": "RATE_LIMITED", "message": "slow down", "requestId": "r1"}
                    },
                )
            return httpx.Response(201, json={"accepted": 500})

        with pytest.raises(ApiError) as caught:
            client(handler).send_events([{"type": "x"}] * 1100)
        assert caught.value.accepted == 500
        assert "RATE_LIMITED" in str(caught.value)

    def test_get_incident(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/api/v1/export/incidents/abc"
            return httpx.Response(200, json={"incident": {"id": "abc", "title": "T"}})

        assert client(handler).get_incident("abc")["title"] == "T"

    def test_error_messages_use_the_api_error_shape_and_never_leak_the_key(self) -> None:
        body = {
            "error": {"code": "UNAUTHORIZED", "message": "Invalid API key", "requestId": "req-1"}
        }
        with pytest.raises(ApiError) as caught:
            client(lambda r: httpx.Response(401, json=body)).send_scan(scan())
        message = str(caught.value)
        assert "401" in message and "Invalid API key" in message and "req-1" in message
        assert KEY not in message

    def test_non_json_errors_are_handled(self) -> None:
        with pytest.raises(ApiError, match="502"):
            client(lambda r: httpx.Response(502, text="<html>Bad gateway</html>")).send_scan(scan())

    def test_network_errors_become_api_errors_without_details_that_could_leak(self) -> None:
        def down(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError(f"cannot connect with {KEY}")

        with pytest.raises(ApiError) as caught:
            client(down).send_scan(scan())
        assert KEY not in str(caught.value)

    def test_unexpected_incident_payload(self) -> None:
        with pytest.raises(ApiError, match="unexpected"):
            client(lambda r: httpx.Response(200, json={"nope": 1})).get_incident("abc")

    def test_constructor_refuses_an_unsafe_url(self) -> None:
        with pytest.raises(ConfigError):
            ApiClient("http://sentinel.example.com", SecretStr(KEY))
