"""OSV client tests.

NOTE: these use hand-written fixtures that follow OSV's documented request/response schema
(https://google.github.io/osv.dev/api/). They were NOT recorded from the live API, because the
development sandbox could not reach api.osv.dev. Run `sentinel-scan deps` against a real lockfile
once to confirm the live behaviour.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from sentinel_scanner.deps.osv import (
    OsvClient,
    OsvError,
    build_findings,
    fixed_versions,
    lookup,
    parse_vuln,
)
from sentinel_scanner.deps.parsers import Dependency
from sentinel_scanner.models import Severity

REQUESTS = Dependency("requests", "2.19.0", "PyPI", "requirements.txt")
LODASH = Dependency("lodash", "4.17.20", "npm", "package-lock.json")
CLEAN = Dependency("flask", "3.0.0", "PyPI", "requirements.txt")

GHSA_RECORD = {
    "id": "GHSA-aaaa-bbbb-cccc",
    "summary": "Requests leaks credentials on redirect",
    "details": "A longer description of the problem.",
    "aliases": ["CVE-2018-18074"],
    "database_specific": {"severity": "HIGH"},
    "affected": [
        {
            "package": {"name": "requests", "ecosystem": "PyPI"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}],
        }
    ],
    "references": [
        {"type": "WEB", "url": "https://github.com/psf/requests/issues/1"},
        {"url": "javascript:alert(1)"},
    ],
}


def client_for(handler: Any) -> OsvClient:
    return OsvClient(client=httpx.Client(transport=httpx.MockTransport(handler)))


def json_response(data: object, status: int = 200) -> httpx.Response:
    return httpx.Response(status, json=data)


class TestQueryBatch:
    def test_maps_dependencies_to_vulnerability_ids_in_order(self) -> None:
        seen: list[dict[str, Any]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            seen.append(body)
            return json_response(
                {
                    "results": [
                        {"vulns": [{"id": "GHSA-1"}, {"id": "CVE-2"}]},
                        {},
                        {"vulns": [{"id": "GHSA-3"}]},
                    ]
                }
            )

        found = client_for(handler).query_batch([REQUESTS, CLEAN, LODASH])
        assert found == {REQUESTS: ["GHSA-1", "CVE-2"], LODASH: ["GHSA-3"]}
        assert seen[0]["queries"][0] == {
            "package": {"name": "requests", "ecosystem": "PyPI"},
            "version": "2.19.0",
        }
        assert seen[0]["queries"][2]["package"] == {"name": "lodash", "ecosystem": "npm"}

    def test_follows_pagination_tokens(self) -> None:
        calls: list[dict[str, Any]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            calls.append(body)
            if "page_token" not in body["queries"][0]:
                return json_response(
                    {"results": [{"vulns": [{"id": "A"}], "next_page_token": "tok"}]}
                )
            return json_response({"results": [{"vulns": [{"id": "B"}]}]})

        assert client_for(handler).query_batch([REQUESTS]) == {REQUESTS: ["A", "B"]}
        assert calls[1]["queries"][0]["page_token"] == "tok"  # noqa: S105 (pagination token, not a password)

    def test_large_inputs_are_split_into_batches(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("sentinel_scanner.deps.osv.BATCH_SIZE", 2)
        sizes: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            n = len(json.loads(request.content)["queries"])
            sizes.append(n)
            return json_response({"results": [{}] * n})

        deps = [Dependency(f"p{i}", "1.0", "PyPI", "r") for i in range(5)]
        client_for(handler).query_batch(deps)
        assert sizes == [2, 2, 1]

    def test_mismatched_result_count_is_an_error(self) -> None:
        with pytest.raises(OsvError, match="different number"):
            client_for(lambda r: json_response({"results": []})).query_batch([REQUESTS])

    def test_http_errors_become_osv_errors(self) -> None:
        with pytest.raises(OsvError, match="failed"):
            client_for(lambda r: httpx.Response(503)).query_batch([REQUESTS])

    def test_network_errors_become_osv_errors(self) -> None:
        def down(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("no route")

        with pytest.raises(OsvError, match="failed"):
            client_for(down).query_batch([REQUESTS])

    def test_invalid_json_is_an_osv_error(self) -> None:
        with pytest.raises(OsvError, match="invalid JSON"):
            client_for(lambda r: httpx.Response(200, content=b"<html>")).query_batch([REQUESTS])


class TestGetVuln:
    def test_fetches_and_parses(self) -> None:
        paths: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            paths.append(request.url.path)
            return json_response(GHSA_RECORD)

        vuln = client_for(handler).get_vuln("GHSA-aaaa-bbbb-cccc")
        assert paths == ["/v1/vulns/GHSA-aaaa-bbbb-cccc"]
        assert vuln.severity is Severity.HIGH

    @pytest.mark.parametrize(
        "bad", ["../../etc/passwd", "a/b", "id?x=1", "id with space", "", "x" * 101]
    )
    def test_suspicious_ids_are_never_requested(self, bad: str) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise AssertionError("no request should be made")

        with pytest.raises(OsvError, match="suspicious"):
            client_for(handler).get_vuln(bad)


class TestParseVuln:
    def test_severity_from_database_specific(self) -> None:
        for raw, expected in [
            ("MODERATE", Severity.MEDIUM),
            ("critical", Severity.CRITICAL),
            ("LOW", Severity.LOW),
        ]:
            assert (
                parse_vuln({"id": "x", "database_specific": {"severity": raw}}).severity is expected
            )

    def test_severity_from_cvss_vector_when_no_label(self) -> None:
        data = {
            "id": "x",
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
            ],
        }
        assert parse_vuln(data).severity is Severity.CRITICAL

    def test_unknown_severity_is_none(self) -> None:
        assert parse_vuln({"id": "x"}).severity is None
        assert (
            parse_vuln(
                {"id": "x", "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"}]}
            ).severity
            is None
        )

    def test_only_http_references_are_kept_and_text_is_truncated(self) -> None:
        vuln = parse_vuln({**GHSA_RECORD, "details": "d" * 5000})
        assert vuln.references == ["https://github.com/psf/requests/issues/1"]
        assert len(vuln.details) == 1500


class TestFindings:
    def test_builds_a_finding_with_fix_advice(self) -> None:
        vuln = parse_vuln(GHSA_RECORD)
        assert fixed_versions(vuln, REQUESTS) == ["2.20.0"]
        [finding] = build_findings(
            {REQUESTS: ["GHSA-aaaa-bbbb-cccc"]}, {"GHSA-aaaa-bbbb-cccc": vuln}
        )
        assert finding.check_id == "deps.GHSA-aaaa-bbbb-cccc"
        assert finding.severity is Severity.HIGH
        assert "requests 2.19.0" in finding.title
        assert "2.20.0" in finding.remediation
        assert finding.evidence["package"] == "requests"
        assert finding.evidence["aliases"] == ["CVE-2018-18074"]
        assert finding.category.value == "DEPENDENCIES"

    def test_unknown_severity_defaults_to_medium_and_is_marked(self) -> None:
        vuln = parse_vuln({"id": "OSV-1", "summary": "bad"})
        [finding] = build_findings({LODASH: ["OSV-1"]}, {"OSV-1": vuln})
        assert finding.severity is Severity.MEDIUM
        assert finding.evidence["severityUnknown"] is True
        assert finding.references == ["https://osv.dev/vulnerability/OSV-1"]

    def test_fixed_versions_only_for_the_matching_package(self) -> None:
        vuln = parse_vuln(GHSA_RECORD)
        assert fixed_versions(vuln, LODASH) == []

    def test_pypi_names_are_compared_normalised(self) -> None:
        record = {
            "id": "x",
            "affected": [
                {
                    "package": {"name": "Flask_Login", "ecosystem": "PyPI"},
                    "ranges": [{"events": [{"fixed": "0.6.0"}]}],
                }
            ],
        }
        dep = Dependency("flask-login", "0.5.0", "PyPI", "r")
        assert fixed_versions(parse_vuln(record), dep) == ["0.6.0"]


class TestLookup:
    def test_end_to_end_with_a_fake_osv(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/v1/querybatch":
                return json_response({"results": [{"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"}]}, {}]})
            return json_response(GHSA_RECORD)

        findings, notes = lookup(client_for(handler), [REQUESTS, CLEAN])
        assert [f.check_id for f in findings] == ["deps.GHSA-aaaa-bbbb-cccc"]
        assert notes == []

    def test_one_detail_lookup_per_unique_vulnerability(self) -> None:
        lookups: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/v1/querybatch":
                return json_response(
                    {"results": [{"vulns": [{"id": "SHARED"}]}, {"vulns": [{"id": "SHARED"}]}]}
                )
            lookups.append(request.url.path)
            return json_response({"id": "SHARED", "summary": "s"})

        findings, _ = lookup(client_for(handler), [REQUESTS, LODASH])
        assert lookups == ["/v1/vulns/SHARED"]
        assert len(findings) == 2  # the same vulnerability affects two packages

    def test_detail_lookup_limit_is_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("sentinel_scanner.deps.osv.MAX_DETAIL_LOOKUPS", 1)

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/v1/querybatch":
                return json_response({"results": [{"vulns": [{"id": "A"}, {"id": "B"}]}]})
            return json_response(
                {"id": "A", "summary": "s", "database_specific": {"severity": "LOW"}}
            )

        findings, notes = lookup(client_for(handler), [REQUESTS])
        assert len(findings) == 2
        assert any("without details" in n for n in notes)
