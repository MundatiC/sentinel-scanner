from datetime import UTC, datetime
from pathlib import Path

import pytest

from sentinel_scanner.logs.parsers import (
    Kind,
    LogType,
    ParseStats,
    parse_auth_line,
    parse_combined_line,
    read_records,
    valid_ip,
)

FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime(2023, 10, 20, tzinfo=UTC)


class TestCombinedFormat:
    def test_parses_a_normal_line(self) -> None:
        line = '203.0.113.5 - frank [10/Oct/2023:13:55:36 +0200] "GET /a/b?x=1 HTTP/1.1" 200 2326 "-" "agent"'
        record = parse_combined_line(line, 7)
        assert record is not None
        assert (record.ip, record.method, record.target, record.status, record.line) == (
            "203.0.113.5", "GET", "/a/b?x=1", 200, 7,
        )  # fmt: skip
        assert record.time == datetime(2023, 10, 10, 11, 55, 36, tzinfo=UTC)  # converted to UTC
        assert record.kind is Kind.REQUEST

    def test_ipv6_clients(self) -> None:
        record = parse_combined_line(
            '2001:db8::1 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 1', 1
        )
        assert record is not None
        assert record.ip == "2001:db8::1"

    def test_malformed_request_is_kept_with_a_truncated_target(self) -> None:
        line = '203.0.113.5 - - [10/Oct/2023:13:55:36 +0000] "\\x16\\x03\\x01garbage" 400 0 "-" "-"'
        record = parse_combined_line(line, 1)
        assert record is not None
        assert record.method is None
        assert record.status == 400

    @pytest.mark.parametrize(
        "line",
        [
            "not a log line",
            '999.1.1.1 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 1',  # not an IP
            'evil<script> - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 1',  # IP field is text
            '203.0.113.5 - - [31/Feb/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 1',  # impossible date
            "",
        ],
    )
    def test_rejects_bad_lines(self, line: str) -> None:
        assert parse_combined_line(line, 1) is None


class TestAuthFormat:
    def test_failed_password_for_valid_and_invalid_users(self) -> None:
        line = "Oct 10 13:55:03 web1 sshd[1002]: Failed password for invalid user admin from 203.0.113.9 port 40002 ssh2"
        record = parse_auth_line(line, 1, 2023, NOW)
        assert record is not None
        assert (record.kind, record.user, record.ip) == (Kind.AUTH_FAILURE, "admin", "203.0.113.9")
        assert record.time == datetime(2023, 10, 10, 13, 55, 3, tzinfo=UTC)

    def test_accepted_login(self) -> None:
        line = "Oct 10 13:56:30 web1 sshd[1007]: Accepted publickey for alice from 198.51.100.7 port 51111 ssh2"
        record = parse_auth_line(line, 1, 2023, NOW)
        assert record is not None
        assert record.kind is Kind.AUTH_SUCCESS

    def test_iso_timestamps_with_timezone(self) -> None:
        line = "2023-10-10T13:55:36.123456+02:00 web1 sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2"
        record = parse_auth_line(line, 1, 2023, NOW)
        assert record is not None
        assert record.time == datetime(2023, 10, 10, 11, 55, 36, 123456, tzinfo=UTC)

    def test_a_december_line_read_in_january_belongs_to_last_year(self) -> None:
        line = (
            "Dec 31 23:59:00 web1 sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2"
        )
        now = datetime(2024, 1, 2, tzinfo=UTC)
        record = parse_auth_line(line, 1, 2024, now)
        assert record is not None
        assert record.time.year == 2023

    def test_invalid_user_notice_lines_are_not_counted_as_failures(self) -> None:
        # "Invalid user" is a separate notice for the SAME attempt that "Failed password" already reports.
        assert (
            parse_auth_line(
                "Oct 10 13:55:05 web1 sshd[1]: Invalid user admin from 203.0.113.9 port 1",
                1,
                2023,
                NOW,
            )
            is None
        )

    @pytest.mark.parametrize(
        "line",
        [
            "Oct 10 14:10:00 web1 CRON[2000]: session opened for user root",
            "garbage",
            "Oct 10 13:55:03 web1 sshd[1]: Failed password for root from not-an-ip port 22 ssh2",
        ],
    )
    def test_ignores_unrelated_or_invalid_lines(self, line: str) -> None:
        assert parse_auth_line(line, 1, 2023, NOW) is None


class TestReadRecords:
    def test_reads_a_whole_file_and_counts_skipped_lines(self) -> None:
        stats = ParseStats()
        records = list(read_records(FIXTURES / "access.log", LogType.nginx, stats))
        assert stats.parsed == len(records) == 9
        assert stats.skipped == 1  # the "this line is not a log line" line
        assert stats.first == datetime(2023, 10, 10, 13, 55, 1, tzinfo=UTC)
        assert stats.last == datetime(2023, 10, 10, 13, 57, 3, tzinfo=UTC)

    def test_auth_file(self) -> None:
        stats = ParseStats()
        records = list(read_records(FIXTURES / "auth.log", LogType.auth, stats, year=2023, now=NOW))
        assert [r.kind for r in records].count(Kind.AUTH_FAILURE) == 5
        assert [r.kind for r in records].count(Kind.AUTH_SUCCESS) == 1

    def test_overlong_lines_are_cut_and_binary_garbage_does_not_crash(self, tmp_path: Path) -> None:
        file = tmp_path / "weird.log"
        file.write_bytes(b"\xff\xfe\x00 garbage\n" + b"A" * 50_000 + b"\n")
        stats = ParseStats()
        assert list(read_records(file, LogType.nginx, stats)) == []
        assert stats.skipped == 2


def test_valid_ip() -> None:
    assert valid_ip("203.0.113.5") == "203.0.113.5"
    assert valid_ip("2001:DB8::1") == "2001:db8::1"
    assert valid_ip("<script>") is None
    assert valid_ip("300.1.1.1") is None
