import re
from datetime import UTC, date, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sentinel_scanner.cli import EXIT_REFUSED, EXIT_UNREACHABLE, app
from sentinel_scanner.report.models import (
    ActionItem,
    Postmortem,
    ReportError,
    TimelineEntry,
    from_incident,
    load_yaml,
)
from sentinel_scanner.report.pdf import latin1, render_pdf
from sentinel_scanner.report.render import block, inline, render_markdown

EXAMPLE = Path(__file__).parent.parent / "examples" / "incident.yaml"
GENERATED = datetime(2026, 3, 3, 12, 0, 0, tzinfo=UTC)
runner = CliRunner()


def t(hour: int, minute: int = 0) -> datetime:
    return datetime(2026, 3, 2, hour, minute, tzinfo=UTC)


def sample() -> Postmortem:
    return Postmortem(
        title="Login attack",
        severity="HIGH",
        started_at=t(9, 58),
        detected_at=t(10, 3),
        resolved_at=t(11, 20),
        summary="Summary text",
        timeline=[
            TimelineEntry(time=t(11), description="second", kind="ACTION"),
            TimelineEntry(
                time=t(10), description="first", kind="DETECTION", author="a@example.com"
            ),
        ],
        action_items=[ActionItem(description="Fix it", owner="Caleb", due=date(2026, 4, 1))],
    )


class TestModels:
    def test_computed_durations(self) -> None:
        pm = sample()
        assert pm.time_to_detect() == "5m"
        assert pm.time_to_resolve() == "1h 17m"
        assert pm.duration() == "1h"

    def test_durations_are_none_when_data_is_missing_or_backwards(self) -> None:
        pm = Postmortem(title="x", detected_at=t(11), resolved_at=t(10))
        assert pm.time_to_resolve() is None
        assert pm.time_to_detect() is None
        assert pm.duration() is None

    def test_naive_times_are_read_as_utc(self) -> None:
        entry = TimelineEntry(time=datetime(2026, 1, 1, 10, 0), description="x")
        assert entry.time.tzinfo is UTC

    def test_timeline_is_sorted_by_time(self) -> None:
        assert [e.description for e in sample().sorted_timeline()] == ["first", "second"]


class TestLoadYaml:
    def test_the_bundled_example_loads(self) -> None:
        pm = load_yaml(EXAMPLE)
        assert pm.title.startswith("Brute-force")
        assert len(pm.timeline) == 5
        assert pm.action_items[0].due == date(2026, 3, 16)

    @pytest.mark.parametrize(
        ("content", "message"),
        [
            ("title: [unclosed", "not valid YAML"),
            ("- just\n- a list", "mapping"),
            ("severity: HIGH", "title"),  # title is required
            ("title: x\nsurprise: 1", "surprise"),  # unknown keys are rejected, not ignored
            ("title: x\ntimeline:\n  - time: not-a-date\n    description: d", "time"),
            (
                "title: x\ntimeline:\n  - time: 2026-01-01T00:00:00Z\n    description: ''",
                "description",
            ),
        ],
    )
    def test_invalid_files_give_a_clear_error(
        self, tmp_path: Path, content: str, message: str
    ) -> None:
        file = tmp_path / "bad.yaml"
        file.write_text(content)
        with pytest.raises(ReportError, match=message):
            load_yaml(file)

    def test_yaml_cannot_execute_code(self, tmp_path: Path) -> None:
        file = tmp_path / "evil.yaml"
        file.write_text(
            "title: !!python/object/apply:os.system ['echo pwned > /tmp/pwned-by-yaml']\n"
        )
        with pytest.raises(ReportError):
            load_yaml(file)
        assert not Path("/tmp/pwned-by-yaml").exists()  # noqa: S108

    def test_oversized_files_are_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("sentinel_scanner.report.models.MAX_YAML_BYTES", 10)
        file = tmp_path / "big.yaml"
        file.write_text("title: " + "x" * 100)
        with pytest.raises(ReportError, match="larger than"):
            load_yaml(file)


class TestFromIncident:
    INCIDENT = {
        "id": "abc",
        "title": "Brute force on login",
        "severity": "HIGH",
        "status": "RESOLVED",
        "summary": "Investigated.",
        "createdAt": "2026-03-02T10:03:30.000Z",
        "resolvedAt": "2026-03-02T11:20:00.000Z",
        "timeline": [
            {
                "occurredAt": "2026-03-02T10:03:30.000Z",
                "kind": "STATUS_CHANGE",
                "body": "Incident opened",
                "author": {"email": "a@example.com"},
            },
            {
                "occurredAt": "2026-03-02T10:15:00.000Z",
                "kind": "NOTE",
                "body": "Blocked the IP",
                "author": None,
            },
        ],
        "alerts": [
            {
                "title": "Brute-force: 1.2.3.4",
                "severity": "HIGH",
                "ruleName": "Brute-force login attempts",
                "eventCount": 12,
            }
        ],
    }

    def test_maps_the_api_shape(self) -> None:
        pm = from_incident(self.INCIDENT)
        assert (pm.title, pm.severity, pm.status) == ("Brute force on login", "HIGH", "RESOLVED")
        assert pm.detected_at == datetime(2026, 3, 2, 10, 3, 30, tzinfo=UTC)
        assert pm.time_to_resolve() == "1h 16m"
        assert [e.kind for e in pm.timeline] == ["STATUS_CHANGE", "NOTE"]
        assert pm.timeline[0].author == "a@example.com"
        assert "Brute-force login attempts" in pm.detection
        assert "12 events" in pm.detection

    def test_missing_pieces_become_todos_in_the_report(self) -> None:
        markdown = render_markdown(from_incident(self.INCIDENT), generated=GENERATED)
        assert (
            markdown.count("To be completed by the incident team") >= 4
        )  # impact, root cause, response, lessons...

    @pytest.mark.parametrize("broken", [{}, {"title": "x"}, {"title": "x", "createdAt": "garbage"}])
    def test_malformed_incidents_are_reported_not_crashed_on(
        self, broken: dict[str, object]
    ) -> None:
        with pytest.raises(ReportError, match="could not be understood"):
            from_incident(broken)


class TestMarkdown:
    def test_contains_every_fixed_section_in_order(self) -> None:
        markdown = render_markdown(sample(), generated=GENERATED)
        headings = re.findall(r"^## (.+)$", markdown, re.MULTILINE)
        assert headings == [
            "Summary", "Impact", "Timeline", "Detection", "Root cause", "Response",
            "What went well", "Lessons learned", "Action items",
        ]  # fmt: skip

    def test_renders_metadata_timeline_and_actions(self) -> None:
        markdown = render_markdown(sample(), generated=GENERATED)
        assert "# Post-mortem: Login attack" in markdown
        assert "| **Time to detect** | 5m |" in markdown
        assert markdown.index("| first") < markdown.index("| second")  # chronological
        assert "_(a@example.com)_" in markdown
        assert "| Fix it | Caleb | 2026-04-01 |" in markdown
        assert "Generated by sentinel-scanner on 2026-03-03 12:00:00" in markdown

    def test_empty_sections_are_marked_todo(self) -> None:
        markdown = render_markdown(Postmortem(title="Bare"), generated=GENERATED)
        assert markdown.count("To be completed by the incident team") == 9

    def test_hostile_text_is_neutralised(self) -> None:
        evil = "<script>alert(1)</script> | injected | cell\n## fake heading <img src=x onerror=alert(1)>"
        pm = Postmortem(
            title=evil, summary=evil, detection=evil, went_well=[evil],
            timeline=[TimelineEntry(time=t(10), description=evil, kind="<b>x</b>", author="<i>a</i>")],
            action_items=[ActionItem(description=evil, owner=evil)],
        )  # fmt: skip
        markdown = render_markdown(pm, generated=GENERATED)
        assert "<script" not in markdown
        assert "<img" not in markdown
        assert "<b>" not in markdown
        assert "&lt;script&gt;" in markdown
        # a pipe or newline in a table cell must not create extra columns or rows
        timeline_rows = [
            line for line in markdown.splitlines() if line.startswith("| 2026-03-02 10:00:00")
        ]
        assert len(timeline_rows) == 1
        assert timeline_rows[0].count("\\|") >= 2
        assert "\n## fake heading" not in markdown.split("## Timeline")[1].split("## Detection")[0]

    def test_filters(self) -> None:
        assert inline("a|b\nc") == "a\\|b c"
        assert block("<b>x</b>\ny") == "&lt;b&gt;x&lt;/b&gt;\ny"

    def test_the_template_ships_with_the_package(self) -> None:
        template = (
            Path(__file__).parent.parent
            / "src"
            / "sentinel_scanner"
            / "report"
            / "templates"
            / "postmortem.md.j2"
        )
        assert template.is_file()


class TestPdf:
    def test_produces_a_pdf(self) -> None:
        data = render_pdf(sample(), generated=GENERATED)
        assert data.startswith(b"%PDF-")
        assert data.rstrip().endswith(b"%%EOF")
        assert len(data) > 1500

    def test_empty_report_and_unicode_do_not_crash(self) -> None:
        assert render_pdf(Postmortem(title="Bare"), generated=GENERATED).startswith(b"%PDF-")
        weird = Postmortem(
            title="Café incident \U0001f525 “quoted” — 日本語", summary="• bullet\ttab"
        )
        assert render_pdf(weird, generated=GENERATED).startswith(b"%PDF-")

    def test_a_long_timeline_spans_several_pages(self) -> None:
        pm = Postmortem(
            title="Long",
            timeline=[
                TimelineEntry(time=t(10), description=f"Entry number {i} " + "word " * 30)
                for i in range(120)
            ],
        )
        data = render_pdf(pm, generated=GENERATED)
        assert len(re.findall(rb"/Type\s*/Page\b", data)) >= 3

    def test_latin1_helper_never_raises(self) -> None:
        assert latin1("café") == "café"
        assert latin1("“hi” — \U0001f525") == '"hi" - ?'


class TestCli:
    def test_timeline_to_markdown_and_pdf(self, tmp_path: Path) -> None:
        out = tmp_path / "reports" / "pm.md"
        result = runner.invoke(
            app, ["postmortem", "--timeline", str(EXAMPLE), "--out", str(out), "--pdf"]
        )
        assert result.exit_code == 0, result.output
        assert "# Post-mortem: Brute-force attack" in out.read_text()
        assert out.with_suffix(".pdf").read_bytes().startswith(b"%PDF-")

    def test_exactly_one_source_is_required(self, tmp_path: Path) -> None:
        out = tmp_path / "pm.md"
        assert runner.invoke(app, ["postmortem", "--out", str(out)]).exit_code == EXIT_REFUSED
        both = [
            "postmortem",
            "--timeline",
            str(EXAMPLE),
            "--incident-id",
            "11111111-1111-4111-8111-111111111111",
            "--out",
            str(out),
        ]
        assert runner.invoke(app, both).exit_code == EXIT_REFUSED

    def test_refuses_to_overwrite_without_force(self, tmp_path: Path) -> None:
        out = tmp_path / "pm.md"
        out.write_text("precious")
        result = runner.invoke(app, ["postmortem", "--timeline", str(EXAMPLE), "--out", str(out)])
        assert result.exit_code == EXIT_REFUSED
        assert out.read_text() == "precious"
        assert (
            runner.invoke(
                app, ["postmortem", "--timeline", str(EXAMPLE), "--out", str(out), "--force"]
            ).exit_code
            == 0
        )

    def test_pdf_target_is_also_protected(self, tmp_path: Path) -> None:
        out = tmp_path / "pm.md"
        out.with_suffix(".pdf").write_text("precious")
        result = runner.invoke(
            app, ["postmortem", "--timeline", str(EXAMPLE), "--out", str(out), "--pdf"]
        )
        assert result.exit_code == EXIT_REFUSED
        assert not out.exists()

    def test_invalid_yaml_is_a_usage_error(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("title: [")
        result = runner.invoke(
            app, ["postmortem", "--timeline", str(bad), "--out", str(tmp_path / "pm.md")]
        )
        assert result.exit_code == EXIT_REFUSED
        assert "not valid YAML" in result.output

    @pytest.mark.parametrize("bad_id", ["not-a-uuid", "../../etc/passwd", "1; DROP TABLE"])
    def test_incident_id_must_be_a_uuid(
        self, tmp_path: Path, bad_id: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SENTINEL_API_KEY", "x")
        result = runner.invoke(
            app, ["postmortem", "--incident-id", bad_id, "--out", str(tmp_path / "pm.md")]
        )
        assert result.exit_code == EXIT_REFUSED
        assert "UUID" in result.output

    def test_incident_from_the_api(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import httpx

        from sentinel_scanner.api_client import ApiClient

        def handler(request: httpx.Request) -> httpx.Response:
            assert (
                request.url.path == "/api/v1/export/incidents/11111111-1111-4111-8111-111111111111"
            )
            return httpx.Response(200, json={"incident": TestFromIncident.INCIDENT})

        monkeypatch.setenv("SENTINEL_API_URL", "http://localhost:4000")
        monkeypatch.setenv("SENTINEL_API_KEY", "snt_deadbeef_" + "A" * 43)
        real = ApiClient
        monkeypatch.setattr(
            "sentinel_scanner.cli.ApiClient",
            lambda u, k, **kw: real(u, k, transport=httpx.MockTransport(handler), **kw),
        )
        out = tmp_path / "pm.md"
        result = runner.invoke(
            app,
            [
                "postmortem",
                "--incident-id",
                "11111111-1111-4111-8111-111111111111",
                "--out",
                str(out),
            ],
        )
        assert result.exit_code == 0, result.output
        assert "Brute force on login" in out.read_text()

    def test_api_failure_exit_code(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import httpx

        from sentinel_scanner.api_client import ApiClient

        monkeypatch.setenv("SENTINEL_API_URL", "http://localhost:4000")
        monkeypatch.setenv("SENTINEL_API_KEY", "snt_deadbeef_" + "A" * 43)
        real = ApiClient
        monkeypatch.setattr(
            "sentinel_scanner.cli.ApiClient",
            lambda u, k, **kw: real(
                u,
                k,
                transport=httpx.MockTransport(
                    lambda r: httpx.Response(
                        404, json={"error": {"code": "NOT_FOUND", "message": "Incident not found"}}
                    )
                ),
                **kw,
            ),
        )
        result = runner.invoke(
            app,
            [
                "postmortem",
                "--incident-id",
                "11111111-1111-4111-8111-111111111111",
                "--out",
                str(tmp_path / "pm.md"),
            ],
        )
        assert result.exit_code == EXIT_UNREACHABLE
        assert "404 NOT_FOUND" in result.output
