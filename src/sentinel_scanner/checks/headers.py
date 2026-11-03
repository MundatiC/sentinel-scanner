"""Security response headers. Reads headers the server already sends; nothing is attacked."""

from __future__ import annotations

import re

from sentinel_scanner.checks.base import ScanContext, short
from sentinel_scanner.models import Category, Finding, Severity

MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"
OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"
HSTS_MIN_SECONDS = 15_552_000  # 180 days


def _finding(
    check_id: str,
    severity: Severity,
    title: str,
    description: str,
    remediation: str,
    reference: str,
    evidence: dict[str, object] | None = None,
) -> Finding:
    return Finding(
        check_id=check_id,
        category=Category.HEADERS,
        severity=severity,
        title=title,
        description=description,
        remediation=remediation,
        evidence=evidence or {},
        references=[reference, OWASP_HEADERS],
    )


def _csp_directive(csp: str, name: str) -> str | None:
    for part in csp.split(";"):
        tokens = part.strip().split()
        if tokens and tokens[0].lower() == name:
            return " ".join(tokens[1:])
    return None


class HeadersCheck:
    name = "headers"

    def run(self, ctx: ScanContext) -> list[Finding]:
        final = ctx.home().final
        h = final.headers
        findings: list[Finding] = []

        csp = h.get("content-security-policy")
        if csp is None:
            findings.append(
                _finding(
                    "headers.csp_missing",
                    Severity.MEDIUM,
                    "Content-Security-Policy header is missing",
                    "Without a CSP the browser will run any script injected into a page (XSS), "
                    "so a single injection bug becomes much more damaging.",
                    "Send a Content-Security-Policy, starting strict (default-src 'self') and loosening only as needed.",
                    MDN + "Content-Security-Policy",
                )
            )
        else:
            script_src = (
                _csp_directive(csp, "script-src") or _csp_directive(csp, "default-src") or ""
            )
            risky = [
                t for t in ("'unsafe-inline'", "'unsafe-eval'", "*") if t in script_src.split()
            ]
            if risky:
                findings.append(
                    _finding(
                        "headers.csp_unsafe",
                        Severity.LOW,
                        "Content-Security-Policy allows unsafe script sources",
                        f"The script policy allows {', '.join(risky)}, which largely cancels the protection a CSP gives against XSS.",
                        "Remove unsafe-inline/unsafe-eval; use nonces or hashes for the scripts you need.",
                        MDN + "Content-Security-Policy/script-src",
                        {"scriptSrc": short(script_src)},
                    )
                )

        if ctx.scheme == "https" or final.url.startswith("https://"):
            hsts = h.get("strict-transport-security")
            if hsts is None:
                findings.append(
                    _finding(
                        "headers.hsts_missing",
                        Severity.MEDIUM,
                        "Strict-Transport-Security (HSTS) header is missing",
                        "Without HSTS a browser can be tricked into using plain HTTP on first contact, "
                        "exposing the session to a network attacker.",
                        "Send Strict-Transport-Security: max-age=31536000; includeSubDomains once HTTPS works everywhere.",
                        MDN + "Strict-Transport-Security",
                    )
                )
            else:
                match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
                max_age = int(match.group(1)) if match else 0
                if max_age < HSTS_MIN_SECONDS:
                    findings.append(
                        _finding(
                            "headers.hsts_weak",
                            Severity.LOW,
                            "HSTS max-age is too short",
                            f"max-age is {max_age} seconds; at least {HSTS_MIN_SECONDS} (180 days) is recommended.",
                            "Increase max-age to at least one year (31536000).",
                            MDN + "Strict-Transport-Security",
                            {"value": short(hsts)},
                        )
                    )

        nosniff = h.get("x-content-type-options", "")
        if nosniff.lower().strip() != "nosniff":
            findings.append(
                _finding(
                    "headers.nosniff_missing",
                    Severity.LOW,
                    "X-Content-Type-Options: nosniff is missing",
                    "Browsers may guess a file's type and execute content that was served as something harmless.",
                    "Send X-Content-Type-Options: nosniff on all responses.",
                    MDN + "X-Content-Type-Options",
                )
            )

        frame_ancestors = _csp_directive(csp, "frame-ancestors") if csp else None
        if "x-frame-options" not in h and frame_ancestors is None:
            findings.append(
                _finding(
                    "headers.clickjacking",
                    Severity.MEDIUM,
                    "Page can be embedded in other sites (clickjacking)",
                    "Neither X-Frame-Options nor a CSP frame-ancestors directive is set, so another site can "
                    "frame this page and trick users into clicking on it.",
                    "Send Content-Security-Policy: frame-ancestors 'none' (or 'self'), or X-Frame-Options: DENY.",
                    MDN + "X-Frame-Options",
                )
            )

        if "referrer-policy" not in h:
            findings.append(
                _finding(
                    "headers.referrer_policy_missing",
                    Severity.LOW,
                    "Referrer-Policy header is missing",
                    "Full URLs (which can contain tokens or ids) may be sent to other sites when users follow links.",
                    "Send Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
                    MDN + "Referrer-Policy",
                )
            )

        if "permissions-policy" not in h:
            findings.append(
                _finding(
                    "headers.permissions_policy_missing",
                    Severity.INFO,
                    "Permissions-Policy header is missing",
                    "Powerful browser features (camera, microphone, geolocation) are not explicitly restricted.",
                    "Send a Permissions-Policy that disables features the site does not use.",
                    MDN + "Permissions-Policy",
                )
            )

        server = h.get("server", "")
        if re.search(r"\d+\.\d+", server) or "/" in server:
            findings.append(
                _finding(
                    "headers.server_version",
                    Severity.LOW,
                    "Server header reveals software and version",
                    "Exact versions help attackers pick known exploits for your stack.",
                    "Remove the version (e.g. nginx: server_tokens off; Apache: ServerTokens Prod).",
                    MDN + "Server",
                    {"server": short(server)},
                )
            )

        if "x-powered-by" in h:
            findings.append(
                _finding(
                    "headers.x_powered_by",
                    Severity.LOW,
                    "X-Powered-By header reveals the technology in use",
                    "It tells attackers which framework to target, and serves no purpose for users.",
                    "Remove the header (Express: app.disable('x-powered-by'); PHP: expose_php = Off).",
                    MDN + "X-Powered-By",
                    {"xPoweredBy": short(h["x-powered-by"])},
                )
            )

        return findings
