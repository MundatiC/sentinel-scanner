"""What every check shares: a context (the client + cached home page) and a common interface."""

from __future__ import annotations

import ssl
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import urljoin, urlsplit

from sentinel_scanner.http import Fetched, PoliteClient
from sentinel_scanner.models import Finding

MAX_REDIRECTS = 3
TRUNCATE = 200


def short(value: str) -> str:
    """Header values come from the target, so we cap how much of them we ever keep."""
    return value if len(value) <= TRUNCATE else value[:TRUNCATE] + "..."


@dataclass
class HomePage:
    first: Fetched  # the very first response (may be a redirect)
    final: Fetched  # the response after following same-host redirects


@dataclass
class ScanContext:
    base_url: str
    client: PoliteClient
    # Tests inject a context that trusts a throwaway CA; in real use the system trust store is used.
    ssl_context: ssl.SSLContext | None = None
    _home: HomePage | None = field(default=None, repr=False)

    @property
    def scheme(self) -> str:
        return urlsplit(self.base_url).scheme

    @property
    def hostname(self) -> str:
        return urlsplit(self.base_url).hostname or ""

    @property
    def port(self) -> int:
        parts = urlsplit(self.base_url)
        return parts.port or (443 if parts.scheme == "https" else 80)

    def home(self) -> HomePage:
        """Fetch "/" once and share it between checks, so we send as few requests as possible."""
        if self._home is None:
            first = self.client.fetch(self.base_url + "/")
            final = first
            for _ in range(MAX_REDIRECTS):
                location = final.headers.get("location")
                if final.status not in {301, 302, 303, 307, 308} or not location:
                    break
                nxt = urljoin(final.url, location)
                # Only follow redirects that stay on the same host: never wander to other sites.
                if urlsplit(nxt).hostname != self.hostname or urlsplit(nxt).scheme not in {
                    "http",
                    "https",
                }:
                    break
                final = self.client.fetch(nxt)
            self._home = HomePage(first=first, final=final)
        return self._home


class Check(Protocol):
    name: str

    def run(self, ctx: ScanContext) -> list[Finding]: ...
