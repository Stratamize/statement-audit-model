#!/usr/bin/env python3
"""Fail-closed Git and remote-tag provenance for statement-audit releases."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit


SOURCE_REPOSITORY = "https://github.com/Stratamize/statement-audit-model"
SEMVER_PATTERN = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
OBJECT_ID_PATTERN = re.compile(r"^[0-9a-f]{40,64}$")
GIT_TIMEOUT_SECONDS = 10


@dataclass(frozen=True)
class ProvenanceResult:
    publication_ready: bool
    release_state: str
    head_commit: str | None
    failure_codes: tuple[str, ...]


def _run_git(root: Path, *args: str, text: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=text,
        encoding="utf-8" if text else None,
        timeout=GIT_TIMEOUT_SECONDS,
        check=False,
    )


def _normalized_origin(value: str) -> str | None:
    value = value.strip()
    if not value:
        return None
    if re.match(r"^[A-Za-z]:[\\/]", value) or value.startswith(("/", "\\\\")):
        try:
            return str(Path(value).resolve(strict=False)).rstrip("\\/").casefold()
        except (OSError, RuntimeError):
            return None
    if value.startswith("git@github.com:"):
        value = "https://github.com/" + value.removeprefix("git@github.com:")
    elif value.startswith("ssh://git@github.com/"):
        value = "https://github.com/" + value.removeprefix("ssh://git@github.com/")

    parsed = urlsplit(value)
    if parsed.scheme:
        if parsed.scheme != "https" or parsed.hostname != "github.com":
            return None
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            return None
        path = parsed.path.rstrip("/")
        if path.endswith(".git"):
            path = path[:-4]
        if not path or path.count("/") != 2:
            return None
        return f"https://github.com{path}".casefold()

    try:
        path = Path(value).resolve(strict=False)
    except (OSError, RuntimeError):
        return None
    return str(path).rstrip("\\/").casefold()


def _parse_semver(value: str) -> tuple[int, int, int] | None:
    match = SEMVER_PATTERN.fullmatch(value)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def _canonical_files(files: Iterable[str]) -> tuple[str, ...] | None:
    canonical: list[str] = []
    for name in files:
        if not isinstance(name, str) or not name:
            return None
        path = Path(name)
        if path.is_absolute() or ".." in path.parts or path.as_posix() != name:
            return None
        canonical.append(name)
    if len(canonical) != len(set(canonical)):
        return None
    return tuple(canonical)


def _remote_versions(output: str) -> dict[tuple[int, int, int], tuple[str, str]] | None:
    versions: dict[tuple[int, int, int], tuple[str, str]] = {}
    for line in output.splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) != 2 or not OBJECT_ID_PATTERN.fullmatch(parts[0]):
            return None
        prefix = "refs/tags/v"
        if not parts[1].startswith(prefix):
            return None
        raw_version = parts[1][len(prefix) :]
        parsed = _parse_semver(raw_version)
        if parsed is None or parsed in versions:
            return None
        versions[parsed] = (raw_version, parts[0])
    return versions


def inspect_repository(
    root: Path | str,
    version: str,
    *,
    files: Iterable[str],
    expected_origin: str = SOURCE_REPOSITORY,
) -> ProvenanceResult:
    """Inspect a committed candidate without trusting candidate-provided URLs."""

    root = Path(root).resolve()
    failures: list[str] = []
    release_state = "unknown"
    head_commit: str | None = None
    canonical_files = _canonical_files(files)
    parsed_version = _parse_semver(version)
    if parsed_version is None:
        failures.append("version_invalid")
    if canonical_files is None:
        failures.append("declared_files_invalid")
        canonical_files = ()

    try:
        top = _run_git(root, "rev-parse", "--show-toplevel")
    except (OSError, subprocess.TimeoutExpired):
        top = None
    if top is None or top.returncode != 0:
        failures.append("git_metadata_missing")
        return ProvenanceResult(False, release_state, None, tuple(failures))
    try:
        discovered_root = Path(top.stdout.strip()).resolve()
    except (OSError, RuntimeError):
        discovered_root = Path()
    if discovered_root != root:
        failures.append("git_root_mismatch")

    try:
        head = _run_git(root, "rev-parse", "--verify", "HEAD^{commit}")
    except (OSError, subprocess.TimeoutExpired):
        head = None
    if (
        head is None
        or head.returncode != 0
        or not OBJECT_ID_PATTERN.fullmatch(head.stdout.strip())
    ):
        failures.append("head_commit_missing")
    else:
        head_commit = head.stdout.strip()

    try:
        status = _run_git(
            root, "status", "--porcelain=v1", "--untracked-files=all", "-z", text=False
        )
    except (OSError, subprocess.TimeoutExpired):
        status = None
    if status is None or status.returncode != 0 or status.stdout:
        failures.append("working_tree_dirty")

    committed_files_ready = bool(canonical_files) and head_commit is not None
    if committed_files_ready:
        for name in canonical_files:
            tracked = _run_git(root, "ls-files", "--error-unmatch", "--", name)
            tagged_bytes = _run_git(root, "show", f"HEAD:{name}", text=False)
            path = root / name
            try:
                matches = (
                    tracked.returncode == 0
                    and tagged_bytes.returncode == 0
                    and path.is_file()
                    and not path.is_symlink()
                    and tagged_bytes.stdout == path.read_bytes()
                )
            except OSError:
                matches = False
            if not matches:
                committed_files_ready = False
                break
    if not committed_files_ready:
        failures.append("committed_tree_mismatch")

    try:
        origin = _run_git(root, "remote", "get-url", "origin")
    except (OSError, subprocess.TimeoutExpired):
        origin = None
    observed_origin = (
        _normalized_origin(origin.stdout.strip())
        if origin is not None and origin.returncode == 0
        else None
    )
    trusted_origin = _normalized_origin(expected_origin)
    if observed_origin is None or trusted_origin is None or observed_origin != trusted_origin:
        failures.append("origin_untrusted")

    try:
        remote = _run_git(root, "ls-remote", "--tags", "--refs", "origin", "refs/tags/v*")
    except (OSError, subprocess.TimeoutExpired):
        remote = None
    versions = (
        _remote_versions(remote.stdout)
        if remote is not None and remote.returncode == 0
        else None
    )
    if versions is None:
        failures.append("remote_tags_unavailable")

    if parsed_version is not None and versions is not None:
        remote_current = versions.get(parsed_version)
        tag_name = f"v{version}"
        local_tag = _run_git(root, "rev-parse", "--verify", f"refs/tags/{tag_name}")
        local_object = local_tag.stdout.strip() if local_tag.returncode == 0 else None

        if remote_current is not None:
            release_state = "tagged"
            remote_object = remote_current[1]
            if local_object is None:
                failures.append("local_release_tag_missing")
            elif local_object != remote_object:
                failures.append("remote_tag_mismatch")
            else:
                peeled = _run_git(
                    root, "rev-parse", "--verify", f"refs/tags/{tag_name}^{{commit}}"
                )
                peeled_commit = peeled.stdout.strip() if peeled.returncode == 0 else None
                if peeled_commit != head_commit:
                    failures.append("tagged_head_mismatch")
        else:
            release_state = "new"
            if local_object is not None:
                failures.append("local_unpublished_tag")
            highest = max(versions) if versions else None
            if highest is not None and parsed_version <= highest:
                failures.append("version_not_monotonic")

    unique_failures = tuple(dict.fromkeys(failures))
    return ProvenanceResult(
        publication_ready=not unique_failures,
        release_state=release_state,
        head_commit=head_commit,
        failure_codes=unique_failures,
    )
