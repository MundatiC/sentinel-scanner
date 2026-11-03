"""Registry of the available checks. Add a new check here and it becomes selectable with --checks."""

from __future__ import annotations

from sentinel_scanner.checks.base import Check
from sentinel_scanner.checks.cookies import CookiesCheck
from sentinel_scanner.checks.exposed_files import ExposedFilesCheck
from sentinel_scanner.checks.headers import HeadersCheck
from sentinel_scanner.checks.tls import TlsCheck

REGISTRY: dict[str, type[Check]] = {
    "headers": HeadersCheck,
    "cookies": CookiesCheck,
    "tls": TlsCheck,
    "files": ExposedFilesCheck,
}
