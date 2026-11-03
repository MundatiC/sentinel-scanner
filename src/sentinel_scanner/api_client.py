"""Sends results to sentinel-api and reads incidents back. Uses an API key from the environment."""

from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlsplit

import httpx
from pydantic import SecretStr

from sentinel_scanner import __version__
from sentinel_scanner.models import ScanResult

MAX_EVENTS_PER_REQUEST = 500  # the API rejects bigger batches


class ConfigError(ValueError):
    """Bad configuration (for example an unsafe API URL)."""


class ApiError(RuntimeError):
    """The API refused a request or could not be reached."""

    def __init__(self, message: str, accepted: int = 0) -> None:
        super().__init__(message)
        self.accepted = accepted  # events accepted before the failure (batches are sent in chunks)


def check_api_url(url: str) -> str:
    """The API key travels in a header, so it must not cross the internet in clear text.

    http:// is accepted only for loopback addresses and single-label hostnames such as the
    docker-compose service name `api`. Anything else must be https://.
    """
    parts = urlsplit(url)
    host = parts.hostname or ""
    if parts.scheme not in {"http", "https"} or not host:
        raise ConfigError("SENTINEL_API_URL must be an http(s) URL")
    if parts.scheme == "https":
        return url.rstrip("/")

    try:
        # An IP address is judged AS an IP: private/loopback networks are fine, public ones are not.
        # (Checked first because an IPv6 literal contains no dots and would look like a service name.)
        address = ipaddress.ip_address(host)
        internal = address.is_loopback or address.is_private
    except ValueError:
        # A hostname: "localhost" or a single label such as the compose service "api" is internal.
        internal = host == "localhost" or "." not in host
    if internal:
        return url.rstrip("/")
    raise ConfigError(
        f"SENTINEL_API_URL uses plain http:// for {host}: the API key would be sent unencrypted. Use https://."
    )


class ApiClient:
    def __init__(
        self,
        base_url: str,
        api_key: SecretStr | str,
        *,
        timeout: float = 10.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        key = api_key.get_secret_value() if isinstance(api_key, SecretStr) else api_key
        self._base = check_api_url(base_url) + "/api/v1"
        self._client = httpx.Client(
            headers={"X-API-Key": key, "User-Agent": f"Sentinel-Scanner/{__version__}"},
            timeout=timeout,
            transport=transport,
        )

    def close(self) -> None:
        self._client.close()

    def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        try:
            response = self._client.request(method, self._base + path, **kwargs)
        except httpx.HTTPError as exc:
            raise ApiError(f"Could not reach the Sentinel API: {type(exc).__name__}") from exc
        if response.is_success:
            try:
                data = response.json() if response.content else {}
            except ValueError as exc:
                raise ApiError("The Sentinel API returned invalid JSON") from exc
            return data if isinstance(data, dict) else {}
        raise ApiError(_describe_error(response))

    def send_scan(self, scan: ScanResult) -> dict[str, Any]:
        return self._request("POST", "/ingest/scans", json=scan.to_api())

    def send_events(self, events: list[dict[str, Any]]) -> int:
        """Send events in batches of 500. Returns how many the API accepted."""
        accepted = 0
        for start in range(0, len(events), MAX_EVENTS_PER_REQUEST):
            chunk = events[start : start + MAX_EVENTS_PER_REQUEST]
            try:
                result = self._request("POST", "/ingest/events", json={"events": chunk})
            except ApiError as exc:
                raise ApiError(str(exc), accepted=accepted) from exc
            accepted += int(result.get("accepted", len(chunk)))
        return accepted

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        data = self._request("GET", f"/export/incidents/{incident_id}")
        incident = data.get("incident")
        if not isinstance(incident, dict):
            raise ApiError("The Sentinel API returned an unexpected incident payload")
        return incident


def _describe_error(response: httpx.Response) -> str:
    """Build an error message from the API's standard error shape. Never echoes request headers."""
    code, message, request_id = "", "", ""
    try:
        error = response.json().get("error", {})
        code, message, request_id = (
            str(error.get(k, ""))[:200] for k in ("code", "message", "requestId")
        )
    except (ValueError, AttributeError):
        pass
    detail = f"{code}: {message}".strip(": ") or response.reason_phrase
    suffix = f" (request {request_id})" if request_id else ""
    return f"Sentinel API answered {response.status_code} {detail}{suffix}"
