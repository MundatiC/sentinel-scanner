"""Read the exact package versions out of lockfiles. Pure local file parsing: no network here."""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

MAX_FILE_BYTES = (
    10 * 1024 * 1024
)  # a lockfile bigger than 10 MB is not plausible: refuse to load it


class DepsError(ValueError):
    """The path cannot be scanned (missing, unsupported, unreadable or too large)."""


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str
    ecosystem: str  # the names OSV uses: "PyPI", "npm"
    source: str  # the lockfile it came from


@dataclass
class ParseResult:
    dependencies: list[Dependency] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)  # things we could not check, with the reason
    files: list[str] = field(default_factory=list)


def normalize_pypi(name: str) -> str:
    """PEP 503 normalisation: Flask_SQLAlchemy -> flask-sqlalchemy."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _read(path: Path) -> str:
    if path.stat().st_size > MAX_FILE_BYTES:
        raise DepsError(f"{path.name} is larger than {MAX_FILE_BYTES // 1024 // 1024} MB")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise DepsError(f"Cannot read {path.name}: {exc}") from exc


_REQ_LINE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*(?P<version>[A-Za-z0-9][A-Za-z0-9.!+_-]*)\s*$"
)
_REQ_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")


def parse_requirements(path: Path) -> ParseResult:
    """requirements.txt. Only exact pins (`name==1.2.3`) can be checked: a range like `>=1.0`
    does not say which version is actually installed."""
    result = ParseResult(files=[path.name])
    text = _read(path).replace("\\\n", " ")  # join lines continued with a backslash (--hash=...)
    seen: set[tuple[str, str]] = set()
    for raw in text.splitlines():
        line = raw.split(" #")[0].split(";")[0].strip()  # drop comments and environment markers
        line = re.sub(r"\s--hash=\S+", "", line).strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            continue  # pip options such as -r other.txt or --index-url
        match = _REQ_LINE.match(line)
        if match and not match["version"].endswith(".*"):
            key = (normalize_pypi(match["name"]), match["version"])
            if key not in seen:
                seen.add(key)
                result.dependencies.append(Dependency(key[0], key[1], "PyPI", path.name))
            continue
        name = _REQ_NAME.match(line)
        result.skipped.append(
            f"{name.group(0) if name else line[:40]} (version is not pinned with ==)"
        )
    return result


def parse_package_lock(path: Path) -> ParseResult:
    """npm package-lock.json (lockfileVersion 1, 2 and 3)."""
    result = ParseResult(files=[path.name])
    try:
        data = json.loads(_read(path))
    except json.JSONDecodeError as exc:
        raise DepsError(f"{path.name} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise DepsError(f"{path.name} has an unexpected structure")

    found: dict[tuple[str, str], None] = {}

    def add(name: str, version: object) -> None:
        if isinstance(version, str) and name:
            found[(name, version)] = None

    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfileVersion 2 / 3
        for key, info in packages.items():
            if not key or not isinstance(info, dict) or info.get("link"):
                continue  # "" is the root project; links are local workspaces
            if "node_modules/" not in key:
                continue
            add(info.get("name") or key.rsplit("node_modules/", 1)[-1], info.get("version"))
    else:  # lockfileVersion 1: nested "dependencies"

        def walk(deps: object) -> None:
            if not isinstance(deps, dict):
                return
            for name, info in deps.items():
                if isinstance(info, dict):
                    add(name, info.get("version"))
                    walk(info.get("dependencies"))

        walk(data.get("dependencies"))

    result.dependencies = [Dependency(n, v, "npm", path.name) for n, v in found]
    return result


def parse_poetry_lock(path: Path) -> ParseResult:
    result = ParseResult(files=[path.name])
    try:
        data = tomllib.loads(_read(path))
    except tomllib.TOMLDecodeError as exc:
        raise DepsError(f"{path.name} is not valid TOML: {exc}") from exc
    for pkg in data.get("package", []):
        name, version = pkg.get("name"), pkg.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        if pkg.get("source", {}).get("type") in {"git", "directory", "file", "url"}:
            result.skipped.append(f"{name} (installed from a non-PyPI source)")
            continue
        result.dependencies.append(Dependency(normalize_pypi(name), version, "PyPI", path.name))
    return result


Parser = Callable[[Path], ParseResult]


def _parser_for(path: Path) -> Parser | None:
    name = path.name.lower()
    if name.startswith("requirements") and name.endswith(".txt"):
        return parse_requirements
    if name == "package-lock.json":
        return parse_package_lock
    if name == "poetry.lock":
        return parse_poetry_lock
    return None


def parse_path(path: Path) -> ParseResult:
    """A lockfile, or a directory containing one or more of the supported lockfiles."""
    if not path.exists():
        raise DepsError(f"{path} does not exist")
    if path.is_file():
        parser = _parser_for(path)
        if parser is None:
            raise DepsError(
                f"Unsupported file {path.name}. Supported: requirements.txt, package-lock.json, poetry.lock"
            )
        return parser(path)

    combined = ParseResult()
    for candidate in ("requirements.txt", "package-lock.json", "poetry.lock"):
        file = path / candidate
        if file.is_file():
            parser = _parser_for(file)
            if parser is None:  # cannot happen: the candidate names above are all supported
                continue
            one = parser(file)
            combined.dependencies += one.dependencies
            combined.skipped += one.skipped
            combined.files += one.files
    if not combined.files:
        raise DepsError(f"No supported lockfile found in {path}")
    return combined
