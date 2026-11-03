import httpx
import pytest

from sentinel_scanner.http import PoliteClient, TargetError, validate_target


def make_client(handler: httpx.MockTransport | None = None, **kwargs: object) -> PoliteClient:
    transport = handler or httpx.MockTransport(lambda request: httpx.Response(200, text="hello"))
    return PoliteClient(delay=0, transport=transport, **kwargs)  # type: ignore[arg-type]


class TestValidateTarget:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("https://example.com", "https://example.com"),
            ("https://example.com/some/path?x=1", "https://example.com"),
            ("http://localhost:3000/", "http://localhost:3000"),
            ("  https://example.com  ", "https://example.com"),
            ("http://[::1]:8080/x", "http://[::1]:8080"),
        ],
    )
    def test_normalises(self, raw: str, expected: str) -> None:
        assert validate_target(raw) == expected

    @pytest.mark.parametrize(
        "raw",
        [
            "ftp://example.com",
            "file:///etc/passwd",
            "example.com",
            "https://",
            "",
            "javascript:alert(1)",
        ],
    )
    def test_rejects(self, raw: str) -> None:
        with pytest.raises(TargetError):
            validate_target(raw)

    def test_rejects_credentials_in_url(self) -> None:
        with pytest.raises(TargetError, match="credentials"):
            validate_target("https://user:pass@example.com")


class TestPoliteClient:
    def test_only_get_and_head_are_allowed(self) -> None:
        with make_client() as client:
            for method in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"]:
                with pytest.raises(ValueError, match="read-only"):
                    client.fetch("https://example.com", method=method)

    def test_sends_an_honest_user_agent(self) -> None:
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.headers["user-agent"])
            return httpx.Response(200)

        with make_client(httpx.MockTransport(handler)) as client:
            client.fetch("https://example.com")
        assert seen[0].startswith("Sentinel-Scanner/")
        assert "authorized self-assessment" in seen[0]

    def test_body_is_capped(self) -> None:
        big = httpx.MockTransport(lambda request: httpx.Response(200, content=b"x" * 100_000))
        with make_client(big) as client:
            result = client.fetch("https://example.com", max_bytes=1024)
        assert len(result.body) == 1024

    def test_head_requests_have_no_body(self) -> None:
        with make_client() as client:
            assert client.fetch("https://example.com", method="HEAD").body == b""

    def test_redirects_are_reported_not_followed(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(301, headers={"location": "https://example.com/"})

        with make_client(httpx.MockTransport(handler)) as client:
            result = client.fetch("http://example.com")
        assert result.status == 301
        assert result.headers["location"] == "https://example.com/"

    def test_refuses_non_http_urls(self) -> None:
        with make_client() as client, pytest.raises(TargetError):
            client.fetch("file:///etc/passwd")

    def test_waits_between_requests(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sleeps: list[float] = []
        monkeypatch.setattr("sentinel_scanner.http.time.sleep", sleeps.append)
        transport = httpx.MockTransport(lambda request: httpx.Response(200))
        with PoliteClient(delay=0.5, transport=transport) as client:
            client.fetch("https://example.com")
            client.fetch("https://example.com")
        assert sleeps
        assert 0 < sleeps[-1] <= 0.5
