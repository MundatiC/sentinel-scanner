import json

import httpx
import pytest
from typer.testing import CliRunner

from conftest import SECURE_HEADERS
from sentinel_scanner.cli import EXIT_FINDINGS, EXIT_REFUSED, EXIT_UNREACHABLE, app
from sentinel_scanner.http import PoliteClient, target_path
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


class TestTargetPathAndNotes:
    def test_target_path_defaults_to_root_and_ignores_query(self) -> None:
        assert target_path("https://example.com") == "/"
        assert target_path("https://example.com/Mundati/?x=1#top") == "/Mundati/"

    def test_start_path_is_the_page_checked_and_shown_in_the_target(self) -> None:
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.url.path)
            return httpx.Response(200, headers=SECURE_HEADERS)

        client = PoliteClient(delay=0, transport=httpx.MockTransport(handler))
        outcome = run_scan("https://example.com", ["headers"], client, start_path="/Mundati/")
        assert seen == ["/Mundati/"]
        assert outcome.result.target == "https://example.com/Mundati/"
        assert outcome.notes == []

    def test_error_page_gets_a_wrong_url_note(self) -> None:
        client = PoliteClient(delay=0, transport=httpx.MockTransport(lambda r: httpx.Response(404)))
        outcome = run_scan("https://example.com", ["headers"], client)
        assert len(outcome.notes) == 1 and "HTTP 404" in outcome.notes[0]

    def test_cloudflare_block_is_reported_as_inconclusive(self) -> None:
        blocked = httpx.Response(403, headers={"server": "cloudflare", "cf-ray": "abc"})
        client = PoliteClient(delay=0, transport=httpx.MockTransport(lambda r: blocked))
        outcome = run_scan("https://example.com", ["headers"], client)
        assert len(outcome.notes) == 1 and "INCONCLUSIVE" in outcome.notes[0]

    def test_cli_prints_the_note(self, monkeypatch: pytest.MonkeyPatch) -> None:
        patched_client(httpx.MockTransport(lambda r: httpx.Response(404)), monkeypatch)
        result = runner.invoke(
            app, ["web", "https://example.com/nope/", "--i-own-this", "--checks", "headers"]
        )
        assert "https://example.com/nope/" in result.output
        assert "returned HTTP 404" in result.output


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
