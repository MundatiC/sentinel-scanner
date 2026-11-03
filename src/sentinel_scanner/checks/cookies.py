"""Cookie flags. We only ever look at cookie NAMES and attributes, never at cookie values."""

from __future__ import annotations

from dataclasses import dataclass, field

from sentinel_scanner.checks.base import ScanContext, short
from sentinel_scanner.models import Category, Finding, Severity

MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies"
SESSIONISH = ("sess", "sid", "token", "auth", "jwt", "login", "user", "csrf")


@dataclass
class ParsedCookie:
    name: str
    secure: bool = False
    httponly: bool = False
    samesite: str | None = None
    attributes: dict[str, str] = field(default_factory=dict)

    @property
    def looks_sensitive(self) -> bool:
        return any(word in self.name.lower() for word in SESSIONISH)


def parse_set_cookie(header: str) -> ParsedCookie | None:
    """Parse one Set-Cookie header line. The cookie VALUE is deliberately discarded."""
    parts = [p.strip() for p in header.split(";")]
    name, sep, _value = parts[0].partition("=")
    if not sep or not name.strip():
        return None
    cookie = ParsedCookie(name=short(name.strip()))
    for attr in parts[1:]:
        key, _, value = attr.partition("=")
        key = key.strip().lower()
        if key == "secure":
            cookie.secure = True
        elif key == "httponly":
            cookie.httponly = True
        elif key == "samesite":
            cookie.samesite = value.strip().lower()
    return cookie


def _finding(
    check_id: str,
    severity: Severity,
    title: str,
    description: str,
    remediation: str,
    names: list[str],
) -> Finding:
    return Finding(
        check_id=check_id,
        category=Category.COOKIES,
        severity=severity,
        title=title,
        description=description,
        remediation=remediation,
        evidence={"cookies": sorted(names)},  # names only, never values
        references=[MDN],
    )


class CookiesCheck:
    name = "cookies"

    def run(self, ctx: ScanContext) -> list[Finding]:
        page = ctx.home()
        raw = [*page.first.headers.get_list("set-cookie")]
        if page.final is not page.first:
            raw += page.final.headers.get_list("set-cookie")
        cookies = [c for c in (parse_set_cookie(line) for line in raw) if c]
        findings: list[Finding] = []

        no_secure = [c.name for c in cookies if not c.secure]
        if no_secure:
            findings.append(
                _finding(
                    "cookies.no_secure",
                    Severity.MEDIUM,
                    "Cookies set without the Secure flag",
                    "Without Secure, the browser also sends these cookies over plain HTTP, where anyone on the network can read them.",
                    "Add the Secure attribute to every cookie.",
                    no_secure,
                )
            )

        no_httponly = [c for c in cookies if not c.httponly]
        if no_httponly:
            severity = (
                Severity.MEDIUM if any(c.looks_sensitive for c in no_httponly) else Severity.LOW
            )
            findings.append(
                _finding(
                    "cookies.no_httponly",
                    severity,
                    "Cookies set without the HttpOnly flag",
                    "JavaScript can read these cookies, so a single XSS bug can steal them (for session cookies: account takeover).",
                    "Add HttpOnly to every cookie that JavaScript does not need to read.",
                    [c.name for c in no_httponly],
                )
            )

        no_samesite = [c.name for c in cookies if c.samesite is None]
        if no_samesite:
            findings.append(
                _finding(
                    "cookies.no_samesite",
                    Severity.LOW,
                    "Cookies set without a SameSite attribute",
                    "Without SameSite the cookie may be sent on cross-site requests, which enables CSRF attacks.",
                    "Add SameSite=Lax (or Strict) unless the cookie must be sent cross-site.",
                    no_samesite,
                )
            )

        none_insecure = [c.name for c in cookies if c.samesite == "none" and not c.secure]
        if none_insecure:
            findings.append(
                _finding(
                    "cookies.samesite_none_insecure",
                    Severity.MEDIUM,
                    "SameSite=None cookies without Secure",
                    "SameSite=None sends the cookie on every cross-site request; browsers require Secure with it, "
                    "so these cookies are either rejected or sent insecurely.",
                    "Add Secure, or use SameSite=Lax/Strict.",
                    none_insecure,
                )
            )

        return findings
