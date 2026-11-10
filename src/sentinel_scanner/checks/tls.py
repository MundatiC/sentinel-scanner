"""TLS configuration. Uses only the standard library: every step is a plain handshake you can read."""

from __future__ import annotations

import socket
import ssl
import warnings
from urllib.parse import urlsplit

import httpx

from sentinel_scanner.checks.base import ScanContext, short
from sentinel_scanner.models import Category, Finding, Severity

TLS_REF = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security"
WEAK_CIPHER_WORDS = ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "MD5", "ANON")
REDIRECT_STATUSES = {301, 302, 307, 308}


def _finding(
    check_id: str,
    severity: Severity,
    title: str,
    description: str,
    remediation: str,
    evidence: dict[str, object] | None = None,
) -> Finding:
    return Finding(
        check_id=check_id,
        category=Category.TLS,
        severity=severity,
        title=title,
        description=description,
        remediation=remediation,
        evidence=evidence or {},
        references=[TLS_REF],
    )


def is_old_protocol(version: str | None) -> bool:
    """TLS 1.0 / 1.1 (and the SSL versions) are deprecated (RFC 8996)."""
    return version in {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def is_weak_cipher(name: str | None) -> bool:
    return bool(name) and any(word in name.upper() for word in WEAK_CIPHER_WORDS)  # type: ignore[union-attr]


def _handshake(
    host: str, port: int, context: ssl.SSLContext, timeout: float
) -> tuple[str | None, str | None, dict]:  # type: ignore[type-arg]
    with (
        socket.create_connection((host, port), timeout=timeout) as sock,
        context.wrap_socket(sock, server_hostname=host) as tls,
    ):
        cipher = tls.cipher()
        return tls.version(), cipher[0] if cipher else None, tls.getpeercert() or {}


def _unverified_context() -> ssl.SSLContext:
    """A context that does not validate the certificate. ONLY used to read the protocol/cipher
    negotiated with a server whose certificate has already failed verification (and been reported)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # noqa: S502
    return context


def _legacy_probe_context() -> ssl.SSLContext | None:
    """A context that offers ONLY TLS 1.0/1.1. If the server completes the handshake, it still
    supports deprecated protocols. This is a normal handshake attempt: no data is sent."""
    context = _unverified_context()
    try:
        # Python warns that these versions are deprecated: that is exactly why we probe for them.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = ssl.TLSVersion.TLSv1  # noqa: S503
            context.maximum_version = ssl.TLSVersion.TLSv1_1  # noqa: S503
        context.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return (
            None  # this Python/OpenSSL build cannot speak the old protocols: nothing to probe with
        )
    return context


class TlsCheck:
    name = "tls"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        if ctx.scheme == "https":
            findings += self.check_certificate_and_protocol(ctx)
            findings += self.check_legacy_protocols(ctx)
        findings += self.check_https_redirect(ctx)
        return findings

    def check_certificate_and_protocol(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        verifying = ctx.ssl_context or ssl.create_default_context()
        timeout = ctx.client.timeout
        version: str | None
        cipher: str | None
        try:
            version, cipher, cert = _handshake(ctx.hostname, ctx.port, verifying, timeout)
        except ssl.SSLCertVerificationError as exc:
            findings.append(
                _finding(
                    "tls.cert_invalid",
                    Severity.HIGH,
                    "TLS certificate failed validation",
                    f"Browsers will warn users or refuse to connect. Reason: {short(exc.verify_message or str(exc))}.",
                    "Install a valid certificate from a trusted CA (e.g. Let's Encrypt) that matches the hostname and has not expired.",
                    {"reason": short(exc.verify_message or str(exc)), "code": exc.verify_code},
                )
            )
            # Still collect protocol info, without trusting the certificate.
            try:
                version, cipher, cert = _handshake(
                    ctx.hostname, ctx.port, _unverified_context(), timeout
                )
            except (OSError, ssl.SSLError):
                return findings
        except (OSError, ssl.SSLError):
            return findings  # cannot connect on TLS at all: reported as a scan error by the caller

        if is_old_protocol(version):
            findings.append(
                _finding(
                    "tls.old_protocol",
                    Severity.HIGH,
                    f"Server negotiated a deprecated protocol ({version})",
                    "TLS 1.0 and 1.1 are deprecated and have known weaknesses.",
                    "Disable everything below TLS 1.2; prefer TLS 1.3.",
                    {"version": version},
                )
            )
        if is_weak_cipher(cipher):
            findings.append(
                _finding(
                    "tls.weak_cipher",
                    Severity.HIGH,
                    "Server negotiated a weak cipher suite",
                    f"The cipher {cipher} is considered broken or too weak.",
                    "Restrict the server to modern AEAD cipher suites (AES-GCM, ChaCha20-Poly1305).",
                    {"cipher": cipher},
                )
            )

        not_after = cert.get("notAfter")
        if isinstance(not_after, str):
            days_left = int((ssl.cert_time_to_seconds(not_after) - _now()) // 86_400)
            if days_left < 30:
                findings.append(
                    _finding(
                        "tls.cert_expiring",
                        Severity.HIGH if days_left < 7 else Severity.MEDIUM,
                        f"TLS certificate expires in {days_left} days",
                        "An expired certificate takes the site down for every user until it is renewed.",
                        "Renew the certificate and automate renewal (e.g. certbot / ACME).",
                        {"daysLeft": days_left, "notAfter": not_after},
                    )
                )
        return findings

    def check_legacy_protocols(self, ctx: ScanContext) -> list[Finding]:
        context = _legacy_probe_context()
        if context is None:
            return []
        try:
            version, _cipher, _cert = _handshake(
                ctx.hostname, ctx.port, context, ctx.client.timeout
            )
        except (OSError, ssl.SSLError, ValueError):
            return []  # handshake refused: the server does NOT accept old protocols (good)
        return [
            _finding(
                "tls.legacy_protocol_supported",
                Severity.HIGH,
                "Server still accepts TLS 1.0/1.1",
                "Deprecated protocols can be forced by an attacker in a downgrade attack.",
                "Set the minimum protocol version to TLS 1.2.",
                {"negotiated": version},
            )
        ]

    def check_https_redirect(self, ctx: ScanContext) -> list[Finding]:
        """Does plain HTTP lead users to HTTPS? Only checked on the default ports."""
        parts = urlsplit(ctx.base_url)
        if (parts.scheme == "https" and parts.port not in (None, 443)) or (
            parts.scheme == "http" and parts.port not in (None, 80)
        ):
            return []
        # Same page the user asked about: on a project site (user.github.io/repo/) the root is a 404.
        http_url = f"http://{ctx.hostname}{ctx.start_path}"
        try:
            response = ctx.client.fetch(http_url, max_bytes=1)
        except (httpx.HTTPError, OSError):
            return []  # nothing listens on port 80: that is fine
        location = response.headers.get("location", "")
        if response.status in REDIRECT_STATUSES and location.lower().startswith("https://"):
            return []
        served = "served over plain HTTP with no redirect to HTTPS"
        return [
            _finding(
                "tls.no_https_redirect",
                Severity.MEDIUM if ctx.scheme == "https" else Severity.HIGH,
                "HTTP does not redirect to HTTPS",
                f"The site is {served}, so users who type the address without https:// are exposed to eavesdropping.",
                "Redirect all HTTP requests to HTTPS (301/308) and enable HSTS.",
                {"status": response.status, "location": short(location)},
            )
        ]


def _now() -> float:
    import time

    return time.time()
