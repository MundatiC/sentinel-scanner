import httpx

from conftest import make_ctx
from sentinel_scanner.checks.cookies import CookiesCheck, parse_set_cookie
from sentinel_scanner.models import Finding, Severity


def run(*cookie_lines: str) -> dict[str, Finding]:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers=[("set-cookie", line) for line in cookie_lines])

    return {f.check_id: f for f in CookiesCheck().run(make_ctx(handler))}


def test_parser_reads_flags_and_discards_the_value() -> None:
    cookie = parse_set_cookie("sid=SECRETVALUE; Path=/; Secure; HttpOnly; SameSite=Lax")
    assert cookie is not None
    assert (cookie.name, cookie.secure, cookie.httponly, cookie.samesite) == (
        "sid",
        True,
        True,
        "lax",
    )
    assert "SECRETVALUE" not in repr(cookie)


def test_parser_ignores_garbage() -> None:
    assert parse_set_cookie("no-equals-sign") is None
    assert parse_set_cookie("=novalue") is None


def test_a_hardened_cookie_has_no_findings() -> None:
    assert run("sid=abc; Secure; HttpOnly; SameSite=Strict") == {}


def test_missing_flags_are_reported_once_each_with_cookie_names() -> None:
    found = run("sid=abc", "theme=dark")
    assert found["cookies.no_secure"].evidence == {"cookies": ["sid", "theme"]}
    assert set(found) == {"cookies.no_secure", "cookies.no_httponly", "cookies.no_samesite"}


def test_session_like_cookie_without_httponly_is_medium_others_low() -> None:
    assert (
        run("sessionid=abc; Secure; SameSite=Lax")["cookies.no_httponly"].severity
        is Severity.MEDIUM
    )
    assert run("theme=dark; Secure; SameSite=Lax")["cookies.no_httponly"].severity is Severity.LOW


def test_samesite_none_without_secure() -> None:
    found = run("sid=abc; HttpOnly; SameSite=None")
    assert found["cookies.samesite_none_insecure"].severity is Severity.MEDIUM


def test_cookie_values_never_reach_the_findings() -> None:
    found = run("sessionid=SUPER-SECRET-TOKEN-123")
    assert "SUPER-SECRET-TOKEN-123" not in repr([f.model_dump() for f in found.values()])


def test_no_cookies_no_findings() -> None:
    assert run() == {}
