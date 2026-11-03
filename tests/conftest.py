from __future__ import annotations

from collections.abc import Callable

import httpx

from sentinel_scanner.checks.base import ScanContext
from sentinel_scanner.http import PoliteClient

Handler = Callable[[httpx.Request], httpx.Response]

SECURE_HEADERS = {
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=()",
}


def make_ctx(handler: Handler, base_url: str = "https://example.com") -> ScanContext:
    """A scan context whose HTTP traffic is answered by `handler`: no real network is used."""
    client = PoliteClient(delay=0, transport=httpx.MockTransport(handler))
    return ScanContext(base_url=base_url, client=client)


def respond(status: int = 200, headers: dict[str, str] | None = None, body: bytes = b"") -> Handler:
    return lambda request: httpx.Response(status, headers=headers, content=body)
