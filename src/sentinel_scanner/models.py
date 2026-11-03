"""Data shapes shared by every check. They mirror the sentinel-api ingest schemas."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """Same five levels in every Sentinel repo."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


class Category(StrEnum):
    HEADERS = "HEADERS"
    COOKIES = "COOKIES"
    TLS = "TLS"
    EXPOSED_FILES = "EXPOSED_FILES"
    DEPENDENCIES = "DEPENDENCIES"


class Finding(BaseModel):
    """One problem a check discovered."""

    model_config = ConfigDict(frozen=True)

    check_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]+$", max_length=100)
    category: Category
    severity: Severity
    title: str = Field(max_length=300)
    description: str = Field(max_length=5000)
    remediation: str = Field(max_length=5000)
    evidence: dict[str, Any] = Field(default_factory=dict)
    references: list[str] = Field(default_factory=list, max_length=10)

    def to_api(self) -> dict[str, Any]:
        """The JSON the API expects (camelCase keys)."""
        return {
            "checkId": self.check_id,
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
        }


def utc_now() -> datetime:
    return datetime.now(UTC)


def iso(value: datetime) -> str:
    """ISO-8601 with a trailing Z, which is what the API's zod schema accepts."""
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class ScanResult(BaseModel):
    """Everything one scan produced."""

    target: str
    scanner_version: str
    started_at: datetime
    finished_at: datetime
    findings: list[Finding] = Field(default_factory=list)

    def counts(self) -> dict[str, int]:
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def to_api(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "scannerVersion": self.scanner_version,
            "startedAt": iso(self.started_at),
            "finishedAt": iso(self.finished_at),
            "findings": [finding.to_api() for finding in self.findings],
        }
