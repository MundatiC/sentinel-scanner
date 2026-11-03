from datetime import UTC, datetime, timedelta

import pytest

from sentinel_scanner.logs.detectors import BruteForceDetector, InjectionDetector
from sentinel_scanner.logs.parsers import Kind, LogRecord
from sentinel_scanner.logs.patterns import decode_target, match_signatures
from sentinel_scanner.models import Severity

T0 = datetime(2023, 10, 10, 13, 0, 0, tzinfo=UTC)


def failure(
    seconds: float, ip: str = "203.0.113.5", user: str | None = "root", line: int = 1
) -> LogRecord:
    return LogRecord(
        time=T0 + timedelta(seconds=seconds), ip=ip, kind=Kind.AUTH_FAILURE, line=line, user=user
    )


def request(
    target: str, ip: str = "198.51.100.9", status: int = 200, seconds: float = 0
) -> LogRecord:
    return LogRecord(
        time=T0 + timedelta(seconds=seconds),
        ip=ip,
        kind=Kind.REQUEST,
        line=1,
        method="GET",
        target=target,
        status=status,
    )


class TestBruteForce:
    def test_five_failures_in_a_minute_is_a_detection(self) -> None:
        found = BruteForceDetector(5, 60).detect([failure(s) for s in (0, 10, 20, 30, 40)])
        assert len(found) == 1
        assert (found[0].ip, found[0].count, found[0].kind, found[0].severity) == (
            "203.0.113.5",
            5,
            "brute_force",
            Severity.HIGH,
        )

    def test_four_failures_is_not(self) -> None:
        assert BruteForceDetector(5, 60).detect([failure(s) for s in (0, 10, 20, 30)]) == []

    def test_slow_guessing_never_reaches_the_threshold_inside_the_window(self) -> None:
        # one failure every 20 s for 5 minutes: never 5 within any 60 s window? 3 per minute -> no.
        assert BruteForceDetector(5, 60).detect([failure(s) for s in range(0, 300, 20)]) == []

    def test_window_boundary_is_inclusive(self) -> None:
        assert len(BruteForceDetector(5, 60).detect([failure(s) for s in (0, 15, 30, 45, 60)])) == 1
        assert BruteForceDetector(5, 60).detect([failure(s) for s in (0, 15, 30, 45, 61)]) == []

    def test_ips_are_counted_separately(self) -> None:
        records = [failure(s, ip="203.0.113.1") for s in (0, 1, 2)] + [
            failure(s, ip="203.0.113.2") for s in (0, 1, 2)
        ]
        assert BruteForceDetector(5, 60).detect(records) == []

    def test_separate_bursts_from_the_same_ip_are_separate_detections(self) -> None:
        records = [failure(s) for s in range(0, 10)] + [failure(s) for s in range(1000, 1010)]
        found = BruteForceDetector(5, 60).detect(records)
        assert [d.count for d in found] == [10, 10]
        assert found[0].last_seen < found[1].first_seen

    def test_unsorted_input_is_handled(self) -> None:
        records = [failure(s) for s in (40, 0, 30, 10, 20)]
        assert len(BruteForceDetector(5, 60).detect(records)) == 1

    def test_collects_the_usernames_tried(self) -> None:
        users = ["root", "admin", "test", "root", "oracle"]
        found = BruteForceDetector(5, 60).detect([failure(i, user=u) for i, u in enumerate(users)])
        assert found[0].users == ["root", "admin", "test", "oracle"]

    def test_web_401_responses_count_as_failed_logins(self) -> None:
        records = [request("/login", ip="203.0.113.5", status=401, seconds=s) for s in range(5)]
        assert len(BruteForceDetector(5, 60).detect(records)) == 1
        ok = [request("/login", ip="203.0.113.5", status=200, seconds=s) for s in range(5)]
        assert BruteForceDetector(5, 60).detect(ok) == []

    def test_successful_logins_are_ignored(self) -> None:
        ok = [
            LogRecord(time=T0, ip="203.0.113.5", kind=Kind.AUTH_SUCCESS, line=1, user="alice")
        ] * 10
        assert BruteForceDetector(5, 60).detect(ok) == []

    @pytest.mark.parametrize(("threshold", "window"), [(1, 60), (5, 0)])
    def test_rejects_silly_settings(self, threshold: int, window: int) -> None:
        with pytest.raises(ValueError, match="threshold"):
            BruteForceDetector(threshold, window)


class TestSignatures:
    @pytest.mark.parametrize(
        ("target", "category"),
        [
            ("/p?id=1' UNION SELECT username,password FROM users--", "sqli"),
            ("/p?id=1%20union%20all%20select%201,2", "sqli"),
            ("/p?id=1' OR 1=1--", "sqli"),
            ("/p?u=admin' or 'a'='a", "sqli"),
            ("/p?id=1' AND SLEEP(5)--", "sqli"),
            ("/p?q=information_schema.tables", "sqli"),
            ("/s?q=<script>alert(1)</script>", "xss"),
            ("/s?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "xss"),
            ("/s?q=<img src=x onerror=alert(1)>", "xss"),
            ("/s?u=javascript:alert(1)", "xss"),
            ("/download?file=../../../etc/passwd", "traversal"),
            ("/download?file=..%2f..%2f..%2fetc%2fpasswd", "traversal"),
            ("/download?file=%252e%252e%252f%252e%252e%252fwin.ini", "traversal"),  # double encoded
            ("/ping?host=8.8.8.8;cat /etc/passwd", "cmdi"),
            ("/ping?host=8.8.8.8|whoami", "cmdi"),
            ("/ping?host=$(id)", "cmdi"),
        ],
    )
    def test_detects(self, target: str, category: str) -> None:
        assert category in {s.category for s in match_signatures(target)}

    @pytest.mark.parametrize(
        "target",
        [
            "/",
            "/products?id=42&sort=price",
            "/search?q=union+station",  # the word 'union' alone is harmless
            "/blog/how-to-select-a-laptop",
            "/files/report..final.pdf",  # two dots but no traversal
            "/api/users?name=O'Brien",
            "/img/photo.jpg",
            "/docs/or-and-not.html",
        ],
    )
    def test_ignores_normal_requests(self, target: str) -> None:
        assert match_signatures(target) == []

    def test_one_signature_per_category(self) -> None:
        hits = match_signatures("/p?id=1' UNION SELECT 1 -- ' OR 1=1")
        assert [s.category for s in hits] == ["sqli"]

    def test_decoding_is_bounded_and_safe(self) -> None:
        assert decode_target("%2520") == " "  # two layers of encoding are removed...
        assert decode_target("%252520") == "%20"  # ...but never more than two
        assert decode_target("a%zz") == "a%zz"  # invalid escapes survive


class TestInjectionDetector:
    def test_groups_by_ip_and_category(self) -> None:
        records = [
            request("/p?id=1' UNION SELECT 1", seconds=0),
            request("/p?id=1' OR 1=1", seconds=5),
            request("/s?q=<script>x</script>", seconds=10),
            request("/home", seconds=11),
            request("/p?id=1' UNION SELECT 1", ip="198.51.100.77", seconds=20),
        ]
        found = InjectionDetector().detect(records)
        summary = {(d.ip, d.category): d.count for d in found}
        assert summary == {
            ("198.51.100.9", "sqli"): 2,
            ("198.51.100.9", "xss"): 1,
            ("198.51.100.77", "sqli"): 1,
        }
        sqli = next(d for d in found if d.category == "sqli" and d.ip == "198.51.100.9")
        assert sqli.severity is Severity.HIGH
        assert sqli.first_seen == T0
        assert len(sqli.records) == 2

    def test_auth_records_are_ignored(self) -> None:
        assert InjectionDetector().detect([failure(0)]) == []

    def test_sample_is_truncated(self) -> None:
        long = "/p?id=1' UNION SELECT " + "A" * 5000
        assert len(InjectionDetector().detect([request(long)])[0].sample or "") == 200


class TestKeepRelevant:
    def test_drops_ordinary_traffic_and_keeps_only_what_detectors_use(self) -> None:
        from sentinel_scanner.logs.detectors import keep_relevant

        boring = [request(f"/products/{i}", seconds=i) for i in range(1000)]
        wanted = [request("/p?id=1' UNION SELECT 1"), request("/login", status=401), failure(0)]
        kept = list(keep_relevant([*boring, *wanted]))
        assert kept == wanted  # a thousand harmless requests leave nothing behind

    def test_detections_are_identical_with_and_without_the_filter(self) -> None:
        from sentinel_scanner.logs.detectors import keep_relevant

        records = [
            *[failure(s) for s in (0, 5, 10, 15, 20)],
            request("/p?id=1' OR 1=1--", seconds=3),
            request("/s?q=<script>x</script>", seconds=4),
            *[request(f"/page/{i}", seconds=i) for i in range(200)],
            LogRecord(time=T0, ip="203.0.113.5", kind=Kind.AUTH_SUCCESS, line=1, user="alice"),
        ]

        def summary(rs: list[LogRecord]):  # type: ignore[no-untyped-def]
            found = BruteForceDetector(5, 60).detect(rs) + InjectionDetector().detect(rs)
            return sorted((d.kind, d.ip, d.category, d.count) for d in found)

        assert summary(list(keep_relevant(records))) == summary(records)
