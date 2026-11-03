import json

import httpx

from conftest import make_ctx
from sentinel_scanner.checks.exposed_files import TARGETS, ExposedFilesCheck
from sentinel_scanner.models import Finding, Severity

LEAKED_LINE = "DB_PASSWORD=hunter2-very-secret"


def run(
    files: dict[str, bytes], default_status: int = 404, default_body: bytes = b""
) -> tuple[list[Finding], list[tuple[str, str]]]:
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        if request.url.path in files:
            return httpx.Response(200, content=files[request.url.path])
        return httpx.Response(default_status, content=default_body)

    return ExposedFilesCheck().run(make_ctx(handler)), seen


def test_finds_an_exposed_env_file_without_keeping_its_content() -> None:
    findings, _ = run({"/.env": f"APP_ENV=prod\n{LEAKED_LINE}\n".encode()})
    assert [f.check_id for f in findings] == ["files.env_exposed"]
    assert findings[0].severity is Severity.CRITICAL
    dumped = json.dumps([f.model_dump(mode="json") for f in findings])
    assert "hunter2" not in dumped  # the secret must never be copied into a report
    evidence = findings[0].evidence
    assert evidence["path"] == "/.env"
    assert len(evidence["sha256OfFirst1KB"]) == 64


def test_git_exposure() -> None:
    findings, _ = run({"/.git/HEAD": b"ref: refs/heads/main\n"})
    assert findings[0].check_id == "files.git_exposed"


def test_a_soft_404_page_is_not_a_false_positive() -> None:
    # Many sites answer 200 with the SAME HTML for every URL. Without a content signature we ignore it.
    findings, _ = run({}, default_status=200, default_body=b"<html><body>Welcome!</body></html>")
    assert findings == []


def test_a_404_with_matching_content_is_ignored() -> None:
    findings, _ = run({}, default_status=404, default_body=b"ref: refs/heads/main")
    assert findings == []


def test_signatures_for_other_files() -> None:
    findings, _ = run(
        {
            "/backup.sql": b"-- MySQL dump 10.13\nCREATE TABLE users (",
            "/backup.zip": b"PK\x03\x04rest",
            "/phpinfo.php": b"<title>phpinfo()</title>",
            "/id_rsa": b"-----BEGIN OPENSSH PRIVATE KEY-----\n",
        }
    )
    assert {f.check_id for f in findings} == {
        "files.sql_dump_exposed",
        "files.backup_archive_exposed",
        "files.phpinfo_exposed",
        "files.private_key_exposed",
    }


def test_one_finding_per_kind_even_if_several_paths_match() -> None:
    dump = b"INSERT INTO users VALUES (1)"
    findings, _ = run({"/backup.sql": dump, "/dump.sql": dump, "/database.sql": dump})
    assert [f.check_id for f in findings] == ["files.sql_dump_exposed"]


def test_only_get_requests_to_a_fixed_list_of_paths() -> None:
    _, seen = run({})
    assert {method for method, _ in seen} == {"GET"}
    assert {path for _, path in seen} == {t.path for t in TARGETS}


def test_reads_at_most_one_kilobyte() -> None:
    big = b"ref: " + b"x" * 100_000
    findings, _ = run({"/.git/HEAD": big})
    assert findings[0].evidence["bytesRead"] == 1024
