"""TLS tests run against REAL local TLS servers using throwaway certificates (trustme)."""

from __future__ import annotations

import socket
import ssl
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import trustme

from conftest import make_ctx
from sentinel_scanner.checks.base import ScanContext
from sentinel_scanner.checks.tls import TlsCheck, is_old_protocol, is_weak_cipher
from sentinel_scanner.http import PoliteClient
from sentinel_scanner.models import Severity


@contextmanager
def tls_server(
    hostnames: tuple[str, ...] = ("localhost", "127.0.0.1"),
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> Iterator[ScanContext]:
    """A tiny TLS server on a random local port, plus a ScanContext that trusts its CA."""
    ca = trustme.CA()
    cert = ca.issue_cert(*hostnames, not_before=not_before, not_after=not_after)
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert.configure_cert(server_ctx)

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(0.2)
    port = listener.getsockname()[1]
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except (TimeoutError, OSError):
                continue
            try:
                with server_ctx.wrap_socket(conn, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                pass  # a client that rejects our certificate aborts the handshake: expected

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    client_ctx = ssl.create_default_context()
    ca.configure_trust(client_ctx)
    client = PoliteClient(delay=0, timeout=3)
    try:
        yield ScanContext(
            base_url=f"https://localhost:{port}", client=client, ssl_context=client_ctx
        )
    finally:
        stop.set()
        thread.join(timeout=2)
        listener.close()
        client.close()


def ids(findings: list) -> set[str]:  # type: ignore[type-arg]
    return {f.check_id for f in findings}


def test_valid_certificate_and_modern_protocol_have_no_findings() -> None:
    with tls_server() as ctx:
        assert TlsCheck().check_certificate_and_protocol(ctx) == []


def test_untrusted_certificate_is_reported() -> None:
    with tls_server() as ctx:
        ctx.ssl_context = None  # use the system trust store: our throwaway CA is not in it
        findings = TlsCheck().check_certificate_and_protocol(ctx)
    assert "tls.cert_invalid" in ids(findings)
    invalid = next(f for f in findings if f.check_id == "tls.cert_invalid")
    assert invalid.severity is Severity.HIGH


def test_hostname_mismatch_is_reported() -> None:
    with tls_server(hostnames=("other.example",)) as ctx:
        findings = TlsCheck().check_certificate_and_protocol(ctx)
    assert "tls.cert_invalid" in ids(findings)
    reason = next(f for f in findings if f.check_id == "tls.cert_invalid").evidence["reason"]
    assert "match" in str(reason).lower()


def test_expired_certificate_is_reported() -> None:
    now = datetime.now(UTC)
    with tls_server(not_before=now - timedelta(days=90), not_after=now - timedelta(days=1)) as ctx:
        findings = TlsCheck().check_certificate_and_protocol(ctx)
    invalid = next(f for f in findings if f.check_id == "tls.cert_invalid")
    assert "expired" in str(invalid.evidence["reason"]).lower()


@pytest.mark.parametrize(("days", "severity"), [(20, Severity.MEDIUM), (3, Severity.HIGH)])
def test_certificate_expiring_soon(days: int, severity: Severity) -> None:
    now = datetime.now(UTC)
    with tls_server(
        not_before=now - timedelta(days=60), not_after=now + timedelta(days=days, hours=1)
    ) as ctx:
        findings = TlsCheck().check_certificate_and_protocol(ctx)
    expiring = next(f for f in findings if f.check_id == "tls.cert_expiring")
    assert expiring.severity is severity
    assert expiring.evidence["daysLeft"] == days


def test_a_modern_server_does_not_accept_legacy_protocols() -> None:
    with tls_server() as ctx:
        assert TlsCheck().check_legacy_protocols(ctx) == []


def test_unreachable_tls_is_not_a_finding() -> None:
    # Nothing listening: the check returns quietly and the scan layer reports the connection error.
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    ctx = make_ctx(lambda r: httpx.Response(200), f"https://localhost:{port}")
    assert TlsCheck().check_certificate_and_protocol(ctx) == []


class TestProtocolHelpers:
    @pytest.mark.parametrize(
        ("version", "old"),
        [
            ("TLSv1", True),
            ("TLSv1.1", True),
            ("SSLv3", True),
            ("TLSv1.2", False),
            ("TLSv1.3", False),
            (None, False),
        ],
    )
    def test_old_protocol(self, version: str | None, old: bool) -> None:
        assert is_old_protocol(version) is old

    @pytest.mark.parametrize(
        ("cipher", "weak"),
        [
            ("RC4-SHA", True),
            ("DES-CBC3-SHA", True),
            ("TLS_AES_256_GCM_SHA384", False),
            (None, False),
        ],
    )
    def test_weak_cipher(self, cipher: str | None, weak: bool) -> None:
        assert is_weak_cipher(cipher) is weak


class TestHttpsRedirect:
    def test_http_redirecting_to_https_is_fine(self) -> None:
        ctx = make_ctx(lambda r: httpx.Response(301, headers={"location": "https://example.com/"}))
        assert TlsCheck().check_https_redirect(ctx) == []

    def test_http_served_without_redirect_is_flagged(self) -> None:
        ctx = make_ctx(lambda r: httpx.Response(200))
        findings = TlsCheck().check_https_redirect(ctx)
        assert ids(findings) == {"tls.no_https_redirect"}
        assert findings[0].severity is Severity.MEDIUM

    def test_redirect_to_another_http_url_is_flagged(self) -> None:
        ctx = make_ctx(lambda r: httpx.Response(301, headers={"location": "http://example.com/x"}))
        assert ids(TlsCheck().check_https_redirect(ctx)) == {"tls.no_https_redirect"}

    def test_plain_http_target_is_more_severe(self) -> None:
        ctx = make_ctx(lambda r: httpx.Response(200), "http://example.com")
        assert TlsCheck().check_https_redirect(ctx)[0].severity is Severity.HIGH

    def test_redirect_is_checked_on_the_start_path_not_the_site_root(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/app/":
                return httpx.Response(301, headers={"location": "https://example.com/app/"})
            return httpx.Response(404)  # the root of a project site is a 404 with no redirect

        ctx = make_ctx(handler)
        ctx.start_path = "/app/"
        assert TlsCheck().check_https_redirect(ctx) == []

    def test_port_80_closed_is_fine(self) -> None:
        def refuse(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        assert TlsCheck().check_https_redirect(make_ctx(refuse)) == []

    def test_custom_ports_are_skipped(self) -> None:
        def boom(request: httpx.Request) -> httpx.Response:
            raise AssertionError("must not make a request")

        assert TlsCheck().check_https_redirect(make_ctx(boom, "https://example.com:8443")) == []

    def test_plain_http_target_skips_certificate_checks(self) -> None:
        # run() on an http:// target only does the redirect check (no TLS to inspect)
        ctx = make_ctx(lambda r: httpx.Response(200), "http://example.com")
        assert ids(TlsCheck().run(ctx)) == {"tls.no_https_redirect"}
