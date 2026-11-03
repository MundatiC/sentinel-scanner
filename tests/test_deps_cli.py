import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sentinel_scanner.cli import EXIT_FINDINGS, EXIT_REFUSED, EXIT_UNREACHABLE, app
from sentinel_scanner.deps.osv import OsvError
from sentinel_scanner.deps.scan import project_target
from sentinel_scanner.models import Category, Finding, Severity

runner = CliRunner()


class FakeOsv:
    """Stands in for the OSV client so CLI tests never touch the network."""

    def __init__(
        self, findings: list[Finding] | None = None, error: str | None = None, **_: object
    ) -> None:
        self._findings, self._error = findings or [], error

    def close(self) -> None: ...


def vuln_finding(severity: Severity) -> Finding:
    return Finding(
        check_id="deps.GHSA-x",
        category=Category.DEPENDENCIES,
        severity=severity,
        title="requests 2.19.0 has a known vulnerability",
        description="d",
        remediation="r",
    )


def patch_lookup(
    monkeypatch: pytest.MonkeyPatch, findings: list[Finding], error: str | None = None
) -> None:
    monkeypatch.setattr("sentinel_scanner.cli.OsvClient", FakeOsv)

    def fake_lookup(_client: object, _deps: object) -> tuple[list[Finding], list[str]]:
        if error:
            raise OsvError(error)
        return findings, []

    monkeypatch.setattr("sentinel_scanner.deps.scan.lookup", fake_lookup)


def project(tmp_path: Path) -> Path:
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\ndjango>=4\n")
    return tmp_path


def test_reports_findings_and_notes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    patch_lookup(monkeypatch, [vuln_finding(Severity.HIGH)])
    result = runner.invoke(app, ["deps", str(project(tmp_path))])
    assert "deps.GHSA-x" in result.output
    assert "Checked 1 packages" in result.output
    assert "django" in result.output  # reported as skipped (not pinned)
    assert result.exit_code == EXIT_FINDINGS


def test_clean_project_exits_zero(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    patch_lookup(monkeypatch, [])
    result = runner.invoke(app, ["deps", str(project(tmp_path))])
    assert result.exit_code == 0
    assert "No findings" in result.output


def test_fail_on_threshold(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    patch_lookup(monkeypatch, [vuln_finding(Severity.MEDIUM)])
    assert runner.invoke(app, ["deps", str(project(tmp_path))]).exit_code == 0
    assert (
        runner.invoke(app, ["deps", str(project(tmp_path)), "--fail-on", "MEDIUM"]).exit_code
        == EXIT_FINDINGS
    )


def test_json_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    patch_lookup(monkeypatch, [vuln_finding(Severity.CRITICAL)])
    result = runner.invoke(app, ["deps", str(project(tmp_path)), "--format", "json"])
    data = json.loads(result.output)
    assert data["findings"][0]["category"] == "DEPENDENCIES"
    assert data["target"].startswith("local://")
    assert data["counts"]["CRITICAL"] == 1
    assert any("Skipped" in n for n in data["notes"])


def test_osv_unreachable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    patch_lookup(monkeypatch, [], error="OSV request failed: no route")
    result = runner.invoke(app, ["deps", str(project(tmp_path))])
    assert result.exit_code == EXIT_UNREACHABLE
    assert "OSV request failed" in result.output


def test_bad_path_is_a_usage_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["deps", str(tmp_path / "missing")])
    assert result.exit_code == EXIT_REFUSED


def test_no_network_call_when_there_is_nothing_to_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "requirements.txt").write_text("django>=4\n")
    monkeypatch.setattr("sentinel_scanner.cli.OsvClient", FakeOsv)

    def boom(*_a: object) -> None:
        raise AssertionError("OSV must not be queried when there are no pinned packages")

    monkeypatch.setattr("sentinel_scanner.deps.scan.lookup", boom)
    assert runner.invoke(app, ["deps", str(tmp_path)]).exit_code == 0


def test_project_target_naming(tmp_path: Path) -> None:
    folder = tmp_path / "My App!"
    folder.mkdir()
    assert project_target(folder) == "local://My-App"
    (folder / "requirements.txt").write_text("")
    assert project_target(folder / "requirements.txt") == "local://My-App"
