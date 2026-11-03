"""The ONLY way the scanner talks to a target.

It enforces the scanner's ground rules in one place, so no individual check can break them:
  * read-only: only GET and HEAD are possible
  * polite: a pause between requests, one request at a time, a timeout on each
  * honest: an identifying User-Agent
  * bounded: at most `max_bytes` of any response body are read
  * http/https targets only
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from sentinel_scanner import __version__

USER_AGENT = f"Sentinel-Scanner/{__version__} (authorized self-assessment)"
ALLOWED_METHODS = frozenset({"GET", "HEAD"})
DEFAULT_MAX_BYTES = 1024


class TargetError(ValueError):
    """The target URL is not something we are willing to scan."""


def validate_target(raw: str) -> str:
    """Return a normalised base URL (no path, query or credentials) or raise TargetError."""
    parts = urlsplit(raw.strip())
    if parts.scheme not in {"http", "https"}:
        raise TargetError("Target must start with http:// or https://")
    if not parts.hostname:
        raise TargetError("Target has no hostname")
    if parts.username or parts.password:
        raise TargetError("Do not put credentials in the target URL")
    host = parts.hostname
    if ":" in host:  # IPv6 literal needs brackets again
        host = f"[{host}]"
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{host}{port}"


@dataclass(frozen=True)
class Fetched:
    """What we kept from one response. The body is only ever a short prefix."""

    url: str
    status: int
    headers: httpx.Headers
    body: bytes


class PoliteClient:
    def __init__(
        self,
        *,
        delay: float = 0.5,
        timeout: float = 10.0,
        verify_tls: bool = True,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._delay = delay
        self._last_request = 0.0
        self._client = httpx.Client(
            headers={"User-Agent": USER_AGENT},
            timeout=timeout,
            verify=verify_tls,
            # We want to SEE redirects (HTTP -> HTTPS), not follow them silently.
            follow_redirects=False,
            transport=transport,
        )

    def __enter__(self) -> PoliteClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def _wait_turn(self) -> None:
        wait = self._delay - (time.monotonic() - self._last_request)
        if wait > 0:
            time.sleep(wait)
        self._last_request = time.monotonic()

    def fetch(
        self, url: str, *, method: str = "GET", max_bytes: int = DEFAULT_MAX_BYTES
    ) -> Fetched:
        """Request `url`. Returns a response with a body capped at `max_bytes`."""
        method = method.upper()
        if method not in ALLOWED_METHODS:
            raise ValueError(f"Method {method} is not allowed: the scanner is read-only")
        if urlsplit(url).scheme not in {"http", "https"}:
            raise TargetError("Only http and https URLs can be requested")

        self._wait_turn()
        with self._client.stream(method, url) as response:
            body = b""
            if method == "GET":
                for chunk in response.iter_bytes():
                    body += chunk
                    if len(body) >= max_bytes:
                        body = body[:max_bytes]
                        break  # stop downloading: we never need more than a prefix
            return Fetched(
                url=url, status=response.status_code, headers=response.headers, body=body
            )
