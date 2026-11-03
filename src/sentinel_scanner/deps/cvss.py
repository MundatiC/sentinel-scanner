"""CVSS v3.x base score from a vector string, so OSV records without a ready-made severity still get one.

Formula from the FIRST CVSS v3.1 specification, section 7.1.
"""

from __future__ import annotations

import math

from sentinel_scanner.models import Severity

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}


def _roundup(value: float) -> float:
    """CVSS 'round up to one decimal', done on integers to avoid floating point surprises."""
    as_int = round(value * 100_000)
    if as_int % 10_000 == 0:
        return as_int / 100_000.0
    return (math.floor(as_int / 10_000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    """Returns the base score (0.0-10.0), or None if the vector is not a valid CVSS v3 vector."""
    if not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    try:
        metrics = dict(part.split(":", 1) for part in vector.split("/")[1:])
        scope_changed = {"U": False, "C": True}[metrics["S"]]
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[metrics["PR"]]
        iss = 1 - (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
        exploitability = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * pr * _UI[metrics["UI"]]
    except (KeyError, ValueError):
        return None

    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    raw = 1.08 * (impact + exploitability) if scope_changed else impact + exploitability
    return _roundup(min(raw, 10.0))


def score_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO
