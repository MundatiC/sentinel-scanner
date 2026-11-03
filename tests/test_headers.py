import httpx

from conftest import SECURE_HEADERS, make_ctx, respond
from sentinel_scanner.checks.headers import HeadersCheck
from sentinel_scanner.models import Severity


def run(headers: dict[str, str], base_url: str = "https://example.com") -> dict[str, Severity]:
    findings = HeadersCheck().run(make_ctx(respond(headers=headers), base_url))
    return {f.check_id: f.severity for f in findings}


def test_a_well_configured_site_has_no_findings() -> None:
    assert run(SECURE_HEADERS) == {}


def test_a_bare_site_gets_the_expected_findings() -> None:
    found = run({})
    assert found["headers.csp_missing"] is Severity.MEDIUM
    assert found["headers.hsts_missing"] is Severity.MEDIUM
    assert found["headers.nosniff_missing"] is Severity.LOW
    assert found["headers.clickjacking"] is Severity.MEDIUM
    assert found["headers.referrer_policy_missing"] is Severity.LOW
    assert found["headers.permissions_policy_missing"] is Severity.INFO


def test_hsts_is_not_demanded_on_plain_http() -> None:
    assert "headers.hsts_missing" not in run({}, "http://example.com")


def test_short_hsts_max_age_is_flagged() -> None:
    found = run({**SECURE_HEADERS, "strict-transport-security": "max-age=300"})
    assert found == {"headers.hsts_weak": Severity.LOW}


def test_unsafe_csp_is_flagged() -> None:
    csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
    assert run({**SECURE_HEADERS, "content-security-policy": csp}) == {
        "headers.csp_unsafe": Severity.LOW
    }


def test_wildcard_script_src_is_flagged() -> None:
    csp = "script-src *; frame-ancestors 'none'"
    assert "headers.csp_unsafe" in run({**SECURE_HEADERS, "content-security-policy": csp})


def test_frame_ancestors_in_csp_satisfies_clickjacking_protection() -> None:
    assert "headers.clickjacking" not in run(SECURE_HEADERS)


def test_x_frame_options_satisfies_clickjacking_protection() -> None:
    headers = {k: v for k, v in SECURE_HEADERS.items() if k != "content-security-policy"}
    assert "headers.clickjacking" not in run({**headers, "x-frame-options": "DENY"})


def test_server_version_and_powered_by_leaks() -> None:
    found = run({**SECURE_HEADERS, "server": "nginx/1.18.0", "x-powered-by": "Express"})
    assert found["headers.server_version"] is Severity.LOW
    assert found["headers.x_powered_by"] is Severity.LOW
    assert "headers.server_version" not in run({**SECURE_HEADERS, "server": "cloudflare"})


def test_follows_same_host_redirect_and_judges_the_final_page() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(302, headers={"location": "/home"})
        return httpx.Response(200, headers=SECURE_HEADERS)

    assert HeadersCheck().run(make_ctx(handler)) == []


def test_does_not_follow_redirects_to_other_hosts() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(302, headers={"location": "https://other.example/"})

    HeadersCheck().run(make_ctx(handler))
    assert calls == ["https://example.com/"]


def test_evidence_values_are_truncated() -> None:
    long = "nginx/1.0 " + "A" * 1000
    findings = HeadersCheck().run(make_ctx(respond(headers={"server": long})))
    server = next(f for f in findings if f.check_id == "headers.server_version")
    assert len(server.evidence["server"]) < 300


def test_the_homepage_is_fetched_only_once_per_scan() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(200)

    ctx = make_ctx(handler)
    HeadersCheck().run(ctx)
    HeadersCheck().run(ctx)
    assert calls == ["/"]
