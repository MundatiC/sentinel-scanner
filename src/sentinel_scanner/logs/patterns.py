"""Attack signatures used by the injection detector.

Every pattern says what it recognises and why. Important limits to understand:
  * these are HEURISTICS for spotting probes in logs, not a security filter: they will miss
    cleverly obfuscated payloads and may rarely flag harmless requests
  * they run on the URL-decoded request target (decoded twice, to catch double encoding)
  * they are only ever MATCHED against log text. Nothing is sent anywhere or executed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote

from sentinel_scanner.models import Severity


@dataclass(frozen=True)
class Signature:
    category: str
    severity: Severity
    label: str
    regex: re.Pattern[str]


def _sig(category: str, severity: Severity, label: str, pattern: str) -> Signature:
    return Signature(category, severity, label, re.compile(pattern, re.IGNORECASE))


SIGNATURES: tuple[Signature, ...] = (
    # --- SQL injection -----------------------------------------------------------------------
    # UNION SELECT: the classic way to read other tables through a vulnerable query.
    _sig("sqli", Severity.HIGH, "UNION SELECT", r"\bunion\b[\s/*+()]*(?:all\b[\s/*+()]*)?select\b"),
    # Tautologies such as ' OR 1=1 or " AND 5=5: make a WHERE clause always true.
    _sig(
        "sqli",
        Severity.HIGH,
        "boolean tautology",
        r"['\")\s]\s*(?:or|and)\s+['\"]?(\d+)['\"]?\s*=\s*['\"]?\1\b",
    ),
    # ' OR 'a'='a style tautologies.
    _sig("sqli", Severity.HIGH, "string tautology", r"'\s*(?:or|and)\s*'[^']*'\s*=\s*'"),
    # Stacked queries: a quote then a semicolon then another statement.
    _sig(
        "sqli",
        Severity.HIGH,
        "stacked query",
        r"['\"];\s*(?:drop|select|insert|update|delete|alter|create|truncate)\b",
    ),
    # Time-based blind injection: the attacker measures how long the database takes to answer.
    _sig(
        "sqli",
        Severity.HIGH,
        "time-based blind",
        r"\b(?:sleep\s*\(\s*\d+|benchmark\s*\(|pg_sleep\s*\(|waitfor\s+delay)",
    ),
    # Reading the database's own catalogue to map tables and columns.
    _sig(
        "sqli",
        Severity.HIGH,
        "schema enumeration",
        r"\binformation_schema\b|\bsqlite_master\b|\bpg_catalog\b",
    ),
    # --- Cross-site scripting (XSS) ----------------------------------------------------------
    _sig("xss", Severity.MEDIUM, "<script> tag", r"<\s*script\b"),
    # Inline event handlers such as onerror= / onload=, used when <script> is filtered.
    _sig(
        "xss",
        Severity.MEDIUM,
        "inline event handler",
        r"\bon(?:error|load|mouseover|focus|click|toggle|animationstart)\s*=",
    ),
    _sig("xss", Severity.MEDIUM, "javascript: URL", r"javascript\s*:"),
    # Other tags that can carry script when injected into HTML.
    _sig(
        "xss",
        Severity.MEDIUM,
        "script-carrying tag",
        r"<\s*(?:svg|iframe|img|body|object|embed)\b[^>]*",
    ),
    # --- Path traversal ----------------------------------------------------------------------
    # ../ climbs out of the web root. Encoded forms (%2e%2e%2f) are decoded before matching.
    _sig(
        "traversal", Severity.HIGH, "directory traversal", r"(?:\.\.[/\\]){1,}|[/\\]\.\.(?:[/\\]|$)"
    ),
    # Well-known files attackers try to read once they can traverse.
    _sig(
        "traversal",
        Severity.HIGH,
        "sensitive file probe",
        r"/etc/(?:passwd|shadow)\b|\bwin\.ini\b|\bboot\.ini\b",
    ),
    # --- Command injection -------------------------------------------------------------------
    # A shell separator followed by a common command: ;cat /etc/x   |whoami   `id`   $(id)
    _sig(
        "cmdi",
        Severity.HIGH,
        "shell command chaining",
        r"(?:;|\||&&|`|\$\()\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|netcat|bash|sh|powershell)\b",
    ),
)

MAX_DECODE_ROUNDS = 2


def decode_target(raw: str) -> str:
    """URL-decode up to twice, because attackers double-encode (%252e) to slip past naive filters."""
    value = raw
    for _ in range(MAX_DECODE_ROUNDS):
        decoded = unquote(value, errors="replace")
        if decoded == value:
            break
        value = decoded
    return value


def match_signatures(target: str) -> list[Signature]:
    """All signatures matching a request target, at most one per category."""
    text = decode_target(target)
    hits: dict[str, Signature] = {}
    for signature in SIGNATURES:
        if signature.category not in hits and signature.regex.search(text):
            hits[signature.category] = signature
    return list(hits.values())
