import json
from pathlib import Path

import pytest

from sentinel_scanner.deps.parsers import (
    DepsError,
    normalize_pypi,
    parse_package_lock,
    parse_path,
    parse_poetry_lock,
    parse_requirements,
)


def write(tmp_path: Path, name: str, content: str) -> Path:
    file = tmp_path / name
    file.write_text(content)
    return file


def names(result) -> set[tuple[str, str]]:  # type: ignore[no-untyped-def]
    return {(d.name, d.version) for d in result.dependencies}


class TestRequirements:
    def test_pinned_versions_comments_extras_markers_and_hashes(self, tmp_path: Path) -> None:
        file = write(
            tmp_path,
            "requirements.txt",
            "# a comment\n"
            "requests==2.19.0  # inline comment\n"
            "Flask_SQLAlchemy==3.0.0\n"
            "uvicorn[standard]==0.30.0\n"
            "pywin32==306 ; sys_platform == 'win32'\n"
            "cryptography==42.0.0 \\\n    --hash=sha256:abc123\n"
            "-r other.txt\n"
            "--index-url https://example.com/simple\n"
            "\n",
        )
        result = parse_requirements(file)
        assert names(result) == {
            ("requests", "2.19.0"),
            ("flask-sqlalchemy", "3.0.0"),
            ("uvicorn", "0.30.0"),
            ("pywin32", "306"),
            ("cryptography", "42.0.0"),
        }

    def test_unpinned_requirements_are_skipped_and_reported(self, tmp_path: Path) -> None:
        file = write(
            tmp_path, "requirements.txt", "django>=4.0\nnumpy\nflask==2.*\nrequests==2.0.0\n"
        )
        result = parse_requirements(file)
        assert names(result) == {("requests", "2.0.0")}
        assert len(result.skipped) == 3
        assert any("django" in item for item in result.skipped)

    def test_duplicates_are_collapsed(self, tmp_path: Path) -> None:
        file = write(tmp_path, "requirements.txt", "requests==2.0.0\nRequests==2.0.0\n")
        assert len(parse_requirements(file).dependencies) == 1

    def test_pypi_name_normalisation(self) -> None:
        assert normalize_pypi("Flask_SQLAlchemy.Extra") == "flask-sqlalchemy-extra"


class TestPackageLock:
    def test_v3_lockfile(self, tmp_path: Path) -> None:
        lock = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "my-app", "version": "1.0.0"},
                "node_modules/lodash": {"version": "4.17.20"},
                "node_modules/@types/node": {"version": "20.1.0"},
                "node_modules/a/node_modules/lodash": {"version": "3.10.1"},
                "node_modules/mylib": {"link": True, "resolved": "../mylib"},
                "packages/workspace": {"version": "0.0.1"},
            },
        }
        result = parse_package_lock(write(tmp_path, "package-lock.json", json.dumps(lock)))
        assert names(result) == {
            ("lodash", "4.17.20"),
            ("@types/node", "20.1.0"),
            ("lodash", "3.10.1"),
        }
        assert {d.ecosystem for d in result.dependencies} == {"npm"}

    def test_v1_lockfile_with_nested_dependencies(self, tmp_path: Path) -> None:
        lock = {
            "lockfileVersion": 1,
            "dependencies": {
                "express": {"version": "4.17.1", "dependencies": {"qs": {"version": "6.7.0"}}}
            },
        }
        result = parse_package_lock(write(tmp_path, "package-lock.json", json.dumps(lock)))
        assert names(result) == {("express", "4.17.1"), ("qs", "6.7.0")}

    def test_invalid_json(self, tmp_path: Path) -> None:
        with pytest.raises(DepsError, match="not valid JSON"):
            parse_package_lock(write(tmp_path, "package-lock.json", "{nope"))

    def test_unexpected_structure(self, tmp_path: Path) -> None:
        with pytest.raises(DepsError, match="unexpected structure"):
            parse_package_lock(write(tmp_path, "package-lock.json", "[1, 2]"))


class TestPoetryLock:
    def test_packages_and_non_pypi_sources(self, tmp_path: Path) -> None:
        content = (
            '[[package]]\nname = "Requests"\nversion = "2.31.0"\n\n'
            '[[package]]\nname = "internal-lib"\nversion = "0.1.0"\n[package.source]\ntype = "git"\n'
        )
        result = parse_poetry_lock(write(tmp_path, "poetry.lock", content))
        assert names(result) == {("requests", "2.31.0")}
        assert any("internal-lib" in item for item in result.skipped)

    def test_invalid_toml(self, tmp_path: Path) -> None:
        with pytest.raises(DepsError, match="not valid TOML"):
            parse_poetry_lock(write(tmp_path, "poetry.lock", "[[package"))


class TestParsePath:
    def test_directory_with_several_lockfiles(self, tmp_path: Path) -> None:
        write(tmp_path, "requirements.txt", "requests==2.0.0\n")
        write(
            tmp_path,
            "package-lock.json",
            json.dumps({"packages": {"node_modules/x": {"version": "1.0.0"}}}),
        )
        result = parse_path(tmp_path)
        assert result.files == ["requirements.txt", "package-lock.json"]
        assert len(result.dependencies) == 2

    def test_single_file(self, tmp_path: Path) -> None:
        assert (
            len(parse_path(write(tmp_path, "requirements-dev.txt", "pytest==8.0.0\n")).dependencies)
            == 1
        )

    def test_errors(self, tmp_path: Path) -> None:
        with pytest.raises(DepsError, match="does not exist"):
            parse_path(tmp_path / "nope")
        with pytest.raises(DepsError, match="No supported lockfile"):
            parse_path(tmp_path)
        with pytest.raises(DepsError, match="Unsupported file"):
            parse_path(write(tmp_path, "Gemfile.lock", "x"))

    def test_oversized_file_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("sentinel_scanner.deps.parsers.MAX_FILE_BYTES", 10)
        with pytest.raises(DepsError, match="larger than"):
            parse_requirements(write(tmp_path, "requirements.txt", "requests==2.0.0\n" * 5))
