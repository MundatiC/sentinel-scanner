import json
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from sentinel_scanner.api_client import ApiClient
from sentinel_scanner.cli import EXIT_FINDINGS, EXIT_REFUSED, EXIT_SEND_FAILED, app
from sentinel_scanner.models import Category, Finding, ScanResult, Severity, utc_now
from sentinel_scanner.scan import ScanOutcome

FIXTURES = Path(__file__).parent / "fixtures"
runner = CliRunner()
KEY = "snt_deadbeef_" + "A" * 43


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for name in ("SENTINEL_API_URL", "SENTINEL_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)  # so a developer's real .env file is never picked up


Handler = Callable[[httpx.Request], httpx.Response]


def configure(monkeypatch: pytest.MonkeyPatch, handler: Handler) -> list[httpx.Request]:
    """Point the CLI at a fake Sentinel API and return the list of requests it received."""
    seen: list[httpx.Request] = []

    def recording(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    monkeypatch.setenv("SENTINEL_API_URL", "http://localhost:4000")
    monkeypatch.setenv("SENTINEL_API_KEY", KEY)
    real = ApiClient
    monkeypatch.setattr(
        "sentinel_scanner.cli.ApiClient",
        lambda url, key, **kw: real(url, key, transport=httpx.MockTransport(recording), **kw),
    )
    return seen


def ok(request: httpx.Request) -> httpx.Response:
    if request.url.path.endswith("/ingest/events"):
        return httpx.Response(201, json={"accepted": len(json.loads(request.content)["events"])})
    return httpx.Response(201, json={"id": "scan-1", "criticalEvents": 0})


class TestLogsCommand:
    def test_auth_log_brute_force(self) -> None:
        result = runner.invoke(
            app, ["logs", str(FIXTURES / "auth.log"), "--type", "auth", "--year", "2023"]
        )
        assert result.exit_code == EXIT_FINDINGS
        assert "brute force" in result.output
        assert "203.0.113.9" in result.output
        assert "root" in result.output

    def test_web_log_finds_brute_force_and_injections(self) -> None:
        result = runner.invoke(
            app, ["logs", str(FIXTURES / "access.log"), "--type", "nginx", "--format", "json"]
        )
        data = json.loads(result.output)
        kinds = {(d["kind"], d["category"]) for d in data["detections"]}
        assert kinds == {
            ("brute_force", None),
            ("injection", "sqli"),
            ("injection", "xss"),
            ("injection", "traversal"),
        }
        assert data["stats"] == {"lines": 10, "parsed": 9, "skipped": 1}
        assert result.exit_code == EXIT_FINDINGS

    def test_clean_log_exits_zero(self, tmp_path: Path) -> None:
        clean = tmp_path / "clean.log"
        clean.write_text(
            '198.51.100.7 - - [10/Oct/2023:13:56:00 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "x"\n'
        )
        result = runner.invoke(app, ["logs", str(clean), "--type", "apache"])
        assert result.exit_code == 0
        assert "No suspicious activity" in result.output

    def test_threshold_and_window_options(self) -> None:
        args = ["logs", str(FIXTURES / "auth.log"), "--type", "auth", "--year", "2023"]
        assert runner.invoke(app, [*args, "--threshold", "6"]).exit_code == 0
        assert runner.invoke(app, [*args, "--threshold", "5", "--window", "5"]).exit_code == 0

    def test_missing_file_is_a_usage_error(self, tmp_path: Path) -> None:
        assert (
            runner.invoke(app, ["logs", str(tmp_path / "nope.log"), "--type", "nginx"]).exit_code
            == 2
        )

    def test_nothing_is_sent_without_send(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen = configure(monkeypatch, ok)
        runner.invoke(app, ["logs", str(FIXTURES / "auth.log"), "--type", "auth", "--year", "2023"])
        assert seen == []


class TestSend:
    def test_logs_send_posts_events_with_the_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen = configure(monkeypatch, ok)
        result = runner.invoke(
            app,
            [
                "logs",
                str(FIXTURES / "auth.log"),
                "--type",
                "auth",
                "--year",
                "2023",
                "--send",
                "--source",
                "web1",
            ],
        )
        assert result.exit_code == EXIT_FINDINGS  # detections still decide the exit code
        assert "Sent 5 event(s)" in result.output
        request = seen[0]
        assert request.url.path == "/api/v1/ingest/events"
        assert request.headers["x-api-key"] == KEY
        events = json.loads(request.content)["events"]
        assert len(events) == 5
        assert {e["source"] for e in events} == {"web1"}

    def test_send_without_a_key_fails_before_doing_any_work(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SENTINEL_API_URL", "http://localhost:4000")
        result = runner.invoke(
            app, ["logs", str(FIXTURES / "auth.log"), "--type", "auth", "--send"]
        )
        assert result.exit_code == EXIT_REFUSED
        assert "SENTINEL_API_KEY" in result.output
        assert "Read " not in result.output  # no analysis was done

    def test_send_refuses_an_unsafe_api_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SENTINEL_API_URL", "http://sentinel.example.com")
        monkeypatch.setenv("SENTINEL_API_KEY", KEY)
        result = runner.invoke(
            app, ["logs", str(FIXTURES / "auth.log"), "--type", "auth", "--send"]
        )
        assert result.exit_code == EXIT_REFUSED
        assert "unencrypted" in result.output
        assert KEY not in result.output

    def test_send_failure_is_reported_but_results_are_still_printed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        configure(
            monkeypatch,
            lambda r: httpx.Response(
                401, json={"error": {"code": "UNAUTHORIZED", "message": "Invalid API key"}}
            ),
        )
        clean = tmp_path / "clean.log"
        clean.write_text("")
        result = runner.invoke(
            app, ["logs", str(FIXTURES / "access.log"), "--type", "nginx", "--send"]
        )
        assert "brute force" in result.output  # table was shown first
        assert "Could not send events" in result.output
        assert KEY not in result.output
        assert result.exit_code == EXIT_FINDINGS

    def test_send_failure_exit_code_when_no_detections(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        configure(monkeypatch, lambda r: httpx.Response(500))
        file = tmp_path / "x.log"
        file.write_text(
            '198.51.100.7 - - [10/Oct/2023:13:56:00 +0000] "GET / HTTP/1.1" 200 1 "-" "x"\n'
        )
        # nothing detected -> nothing to send -> success
        assert runner.invoke(app, ["logs", str(file), "--type", "nginx", "--send"]).exit_code == 0

    def test_max_events_limits_what_is_sent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen = configure(monkeypatch, ok)
        result = runner.invoke(
            app,
            [
                "logs",
                str(FIXTURES / "auth.log"),
                "--type",
                "auth",
                "--year",
                "2023",
                "--send",
                "--max-events",
                "2",
            ],
        )
        assert len(json.loads(seen[0].content)["events"]) == 2
        assert "3 event(s) not sent" in result.output

    def test_web_send_delivers_the_scan(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen = configure(monkeypatch, ok)
        finding = Finding(check_id="headers.csp_missing", category=Category.HEADERS, severity=Severity.MEDIUM,
                          title="t", description="d", remediation="r")  # fmt: skip
        monkeypatch.setattr(
            "sentinel_scanner.cli.run_scan",
            lambda base_url, *a, **k: ScanOutcome(
                ScanResult(
                    target=base_url,
                    scanner_version="t",
                    started_at=utc_now(),
                    finished_at=utc_now(),
                    findings=[finding],
                ),
                checks_attempted=1,
            ),
        )
        result = runner.invoke(app, ["web", "https://example.com", "--i-own-this", "--send"])
        assert result.exit_code == 0
        assert "Sent to Sentinel" in result.output
        assert seen[0].url.path == "/api/v1/ingest/scans"
        assert json.loads(seen[0].content)["findings"][0]["checkId"] == "headers.csp_missing"

    def test_web_send_failure_exit_code(self, monkeypatch: pytest.MonkeyPatch) -> None:
        configure(monkeypatch, lambda r: httpx.Response(500))
        monkeypatch.setattr(
            "sentinel_scanner.cli.run_scan",
            lambda base_url, *a, **k: ScanOutcome(
                ScanResult(
                    target=base_url,
                    scanner_version="t",
                    started_at=utc_now(),
                    finished_at=utc_now(),
                ),
                checks_attempted=1,
            ),
        )
        result = runner.invoke(app, ["web", "https://example.com", "--i-own-this", "--send"])
        assert result.exit_code == EXIT_SEND_FAILED

    def test_web_send_json_output_stays_valid_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        configure(monkeypatch, ok)
        monkeypatch.setattr(
            "sentinel_scanner.cli.run_scan",
            lambda base_url, *a, **k: ScanOutcome(
                ScanResult(
                    target=base_url,
                    scanner_version="t",
                    started_at=utc_now(),
                    finished_at=utc_now(),
                ),
                checks_attempted=1,
            ),
        )
        runner_split = CliRunner()
        result = runner_split.invoke(
            app, ["web", "https://example.com", "--i-own-this", "--send", "--format", "json"]
        )
        # status messages go to stderr, so stdout is pure JSON
        assert json.loads(result.stdout)["target"] == "https://example.com"
