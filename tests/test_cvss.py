import pytest

from sentinel_scanner.deps.cvss import cvss3_base_score, score_to_severity
from sentinel_scanner.models import Severity


# Reference values from the FIRST CVSS v3.1 specification / NVD calculator.
@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_known_scores(vector: str, score: float) -> None:
    assert cvss3_base_score(vector) == score


@pytest.mark.parametrize(
    "vector",
    [
        "",
        "garbage",
        "CVSS:4.0/AV:N",
        "CVSS:3.1/AV:N/AC:L",
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ],
)
def test_invalid_vectors_return_none(vector: str) -> None:
    assert cvss3_base_score(vector) is None


@pytest.mark.parametrize(
    ("score", "severity"),
    [
        (10.0, Severity.CRITICAL),
        (9.0, Severity.CRITICAL),
        (8.9, Severity.HIGH),
        (7.0, Severity.HIGH),
        (6.9, Severity.MEDIUM),
        (4.0, Severity.MEDIUM),
        (3.9, Severity.LOW),
        (0.1, Severity.LOW),
        (0.0, Severity.INFO),
    ],
)
def test_score_to_severity(score: float, severity: Severity) -> None:
    assert score_to_severity(score) is severity
