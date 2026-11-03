import json

import httpx
import pytest
from typer.testing import CliRunner

from conftest import SECURE_HEADERS
from sentinel_scanner.cli import EXIT_FINDINGS, EXIT_REFUSED, EXIT_UNREACHABLE, app
from sentinel_scanner.http import PoliteClient
from sentinel_scanner.scan import run_scan

runner = CliRunner()


def patched_client(handler: httpx.MockTransport, monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the CLI use a fake network instead of the real one."""
    real = PoliteClient

    def factory(**kwargs: object) -> PoliteClient:
        kwargs["delay"] = 0
        return real(transport=handler, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr("sentinel_scanner.cli.PoliteClient", factory)


def site(headers: dict[str, str] | None = None) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, headers=headers or {})
        return httpx.Response(404)

    return httpx.MockTransport(handler)


class TestRunScan:
    def test_collects_findings_from_selected_checks(self) -> None:
        client = PoliteClient(delay=0, transport=site())
        outcome = run_scan("https://example.com", ["headers", "cookies"], client)
        assert outcome.errors == {}
        assert any(f.check_id == "headers.csp_missing" for f in outcome.result.findings)
        assert outcome.result.target == "https://example.com"

    def test_one_failing_check_does_not_stop_the_others(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/":
                return httpx.Response(200)
            raise httpx.ConnectError("boom")

        client = PoliteClient(delay=0, transport=httpx.MockTransport(handler))
        outcome = run_scan("https://example.com", ["files", "headers"], client)
        assert "files" in outcome.errors
        assert outcome.result.findings  # headers still ran
        assert not outcome.nothing_ran

    def test_unreachable_target_means_nothing_ran(self) -> None:
        def down(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("down")

        client = PoliteClient(delay=0, transport=httpx.MockTransport(down))
        outcome = run_scan("https://example.com", ["headers", "cookies"], client)
        assert outcome.nothing_ran
        assert set(outcome.errors) == {"headers", "cookies"}


class TestWebCommand:
    def test_table_output_and_exit_code_for_findings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        patched_client(site(), monkeypatch)
        result = runner.invoke(
            app, ["web", "https://example.com", "--i-own-this", "--checks", "headers"]
        )
        assert "headers.csp_missing" in result.output
        assert "Summary" in result.output
        assert result.exit_code == 0  # only MEDIUM/LOW findings and the default threshold is HIGH

    def test_fail_on_threshold(self, monkeypatch: pytest.MonkeyPatch) -> None:
        patched_client(site(), monkeypatch)
        result = runner.invoke(
            app,
            [
                "web",
                "https://example.com",
                "--i-own-this",
                "--checks",
                "headers",
                "--fail-on",
                "MEDIUM",
            ],
        )
        assert result.exit_code == EXIT_FINDINGS

    def test_clean_site(self, monkeypatch: pytest.MonkeyPatch) -> None:
        patched_client(site(SECURE_HEADERS), monkeypatch)
        result = runner.invoke(
            app,
            [
                "web",
                "https://example.com",
                "--i-own-this",
                "--checks",
                "headers",
                "--fail-on",
                "INFO",
            ],
        )
        assert result.exit_code == 0
        assert "No findings" in result.output

    def test_json_output_matches_the_api_payload(self, monkeypatch: pytest.MonkeyPatch) -> None:
        patched_client(site(), monkeypatch)
        result = runner.invoke(
            app,
            [
                "web",
                "https://example.com",
                "--i-own-this",
                "--checks",
                "headers",
                "--format",
                "json",
            ],
        )
        data = json.loads(result.output)
        assert data["target"] == "https://example.com"
        assert data["findings"][0]["checkId"].startswith("headers.")
        assert data["counts"]["MEDIUM"] >= 1
        assert data["startedAt"].endswith("Z")

    def test_unknown_check_is_a_usage_error(self) -> None:
        result = runner.invoke(
            app, ["web", "https://example.com", "--i-own-this", "--checks", "headers,exploit"]
        )
        assert result.exit_code == EXIT_REFUSED
        assert "Unknown check" in result.output

    def test_unreachable_exit_code(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def down(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("down")

        patched_client(httpx.MockTransport(down), monkeypatch)
        result = runner.invoke(
            app, ["web", "https://example.com", "--i-own-this", "--checks", "headers"]
        )
        assert result.exit_code == EXIT_UNREACHABLE
        assert "could not run" in result.output

    def test_terminal_markup_from_the_target_is_not_interpreted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        patched_client(site({"server": "evil/1.0 [bold red]PWNED[/bold red]"}), monkeypatch)
        result = runner.invoke(
            app, ["web", "https://example.com", "--i-own-this", "--checks", "headers"]
        )
        assert result.exit_code == 0
