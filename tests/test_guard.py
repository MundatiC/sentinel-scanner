"""The most important tests in this repo: the scanner must refuse to run without --i-own-this."""

import pytest
from typer.testing import CliRunner

from sentinel_scanner.cli import EXIT_REFUSED, app
from sentinel_scanner.models import ScanResult, utc_now
from sentinel_scanner.scan import ScanOutcome

runner = CliRunner()


def test_refuses_without_ownership_flag() -> None:
    result = runner.invoke(app, ["web", "https://example.com"])
    assert result.exit_code == EXIT_REFUSED
    assert "Refusing to scan" in result.output
    assert "--i-own-this" in result.output


def test_refuses_before_even_validating_the_target() -> None:
    # An invalid target must not be reported INSTEAD of the ownership refusal.
    result = runner.invoke(app, ["web", "not a url"])
    assert result.exit_code == EXIT_REFUSED
    assert "Refusing to scan" in result.output


def test_runs_with_ownership_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    called: list[str] = []

    def fake_scan(base_url: str, *_args: object, **_kwargs: object) -> ScanOutcome:
        called.append(base_url)
        result = ScanResult(
            target=base_url, scanner_version="t", started_at=utc_now(), finished_at=utc_now()
        )
        return ScanOutcome(result=result, checks_attempted=1)

    monkeypatch.setattr("sentinel_scanner.cli.run_scan", fake_scan)
    result = runner.invoke(app, ["web", "https://example.com", "--i-own-this"])
    assert result.exit_code == 0
    assert called == ["https://example.com"]


def test_nothing_is_scanned_when_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("a scan was started without --i-own-this")

    monkeypatch.setattr("sentinel_scanner.cli.run_scan", explode)
    monkeypatch.setattr("sentinel_scanner.cli.PoliteClient", explode)
    assert runner.invoke(app, ["web", "https://example.com"]).exit_code == EXIT_REFUSED


def test_rejects_non_http_targets_even_with_the_flag() -> None:
    for bad in ["ftp://example.com", "file:///etc/passwd", "javascript:alert(1)", "example.com"]:
        result = runner.invoke(app, ["web", bad, "--i-own-this"])
        assert result.exit_code == EXIT_REFUSED, bad
        assert "Invalid target" in result.output


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "sentinel-scan" in result.output


def test_api_key_is_not_a_command_line_option() -> None:
    result = runner.invoke(
        app, ["web", "https://example.com", "--i-own-this", "--api-key", "secret"]
    )
    assert result.exit_code != 0
