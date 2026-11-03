"""The shape of a post-mortem, and loaders for its two sources (YAML file, Sentinel API incident)."""

from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

MAX_YAML_BYTES = 1024 * 1024
TODO = "_To be completed by the incident team._"


class ReportError(ValueError):
    """The input cannot be turned into a report. The message is safe to show to the user."""


def _utc(value: datetime) -> datetime:
    # A time without a timezone is read as UTC, so every time in a report is comparable.
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class TimelineEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    time: datetime
    description: str = Field(min_length=1, max_length=2000)
    kind: str = Field(default="EVENT", max_length=40)  # DETECTION, ACTION, NOTE...: a free label
    author: str | None = Field(default=None, max_length=254)

    _normalise = field_validator("time")(_utc)


class ActionItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str = Field(min_length=1, max_length=1000)
    owner: str = Field(default="unassigned", max_length=100)
    due: date | None = None


class Postmortem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=200)
    severity: str = Field(default="UNKNOWN", max_length=20)
    status: str = Field(default="RESOLVED", max_length=20)
    owner: str | None = Field(default=None, max_length=100)
    summary: str = ""
    impact: str = ""
    detection: str = ""
    root_cause: str = ""
    response: str = ""
    started_at: datetime | None = None  # when the problem actually began
    detected_at: datetime | None = None  # when we noticed
    resolved_at: datetime | None = None
    timeline: list[TimelineEntry] = Field(default_factory=list, max_length=2000)
    went_well: list[str] = Field(default_factory=list, max_length=100)
    lessons: list[str] = Field(default_factory=list, max_length=100)
    action_items: list[ActionItem] = Field(default_factory=list, max_length=100)

    _normalise = field_validator("started_at", "detected_at", "resolved_at")(
        lambda value: _utc(value) if value else value
    )

    def sorted_timeline(self) -> list[TimelineEntry]:
        return sorted(self.timeline, key=lambda entry: entry.time)

    def time_to_detect(self) -> str | None:
        return _span(self.started_at, self.detected_at)

    def time_to_resolve(self) -> str | None:
        return _span(self.detected_at, self.resolved_at)

    def duration(self) -> str | None:
        times = [e.time for e in self.timeline]
        return _span(min(times), max(times)) if len(times) > 1 else None


def _span(start: datetime | None, end: datetime | None) -> str | None:
    if not start or not end or end < start:
        return None
    seconds = int((end - start).total_seconds())
    days, rest = divmod(seconds, 86_400)
    hours, rest = divmod(rest, 3_600)
    minutes = rest // 60
    parts = [
        f"{days}d" if days else "",
        f"{hours}h" if hours else "",
        f"{minutes}m" if minutes or not seconds else "",
    ]
    return " ".join(p for p in parts if p) or "under a minute"


def load_yaml(path: Path) -> Postmortem:
    """Read a timeline file. Uses safe_load: a YAML file must never be able to run code."""
    try:
        if path.stat().st_size > MAX_YAML_BYTES:
            raise ReportError(f"{path.name} is larger than 1 MB")
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ReportError(f"Cannot read {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ReportError(f"{path.name} is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ReportError(f"{path.name} must contain a YAML mapping (title, timeline, ...)")
    try:
        return Postmortem.model_validate(data)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()[:5]
        )
        raise ReportError(f"{path.name} is invalid: {problems}") from exc


def from_incident(incident: dict[str, Any]) -> Postmortem:
    """Build a post-mortem from an incident exported by sentinel-api (GET /export/incidents/:id)."""
    try:
        timeline = [
            TimelineEntry(
                time=datetime.fromisoformat(str(e["occurredAt"]).replace("Z", "+00:00")),
                kind=str(e.get("kind", "NOTE")),
                description=str(e["body"])[:2000] or "(empty)",
                author=(e.get("author") or {}).get("email"),
            )
            for e in incident.get("timeline", [])
        ]
        alerts = incident.get("alerts", [])
        created = datetime.fromisoformat(str(incident["createdAt"]).replace("Z", "+00:00"))
        resolved_raw = incident.get("resolvedAt")
        detection = ""
        if alerts:
            lines = [
                f"- {a.get('title', 'alert')} ({a.get('severity', '?')}, rule: {a.get('ruleName', '?')}, "
                f"{a.get('eventCount', 0)} events)"
                for a in alerts
            ]
            detection = "Sentinel raised these alerts:\n" + "\n".join(lines)
        return Postmortem(
            title=str(incident["title"])[:200],
            severity=str(incident.get("severity", "UNKNOWN")),
            status=str(incident.get("status", "OPEN")),
            summary=str(incident.get("summary", "")),
            detection=detection,
            detected_at=created,  # the incident was opened when someone noticed the problem
            resolved_at=datetime.fromisoformat(str(resolved_raw).replace("Z", "+00:00"))
            if resolved_raw
            else None,
            timeline=timeline,
        )
    except (KeyError, ValueError, TypeError, ValidationError) as exc:
        raise ReportError(
            f"The incident returned by the API could not be understood: {type(exc).__name__}"
        ) from exc
