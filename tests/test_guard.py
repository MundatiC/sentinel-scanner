"""The most important tests in this repo: the scanner must refuse to run without --i-own-this."""

from typer.testing import CliRunner

from sentinel_scanner.cli import EXIT_REFUSED, app

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


def test_runs_with_ownership_flag() -> None:
    result = runner.invoke(app, ["web", "https://example.com", "--i-own-this"])
    assert result.exit_code == 0
    assert "https://example.com" in result.output


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
