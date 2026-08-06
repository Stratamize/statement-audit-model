#!/usr/bin/env python3
"""Bounded, non-executing attestation of public statement-audit release bytes."""

from __future__ import annotations

import hashlib
import io
import json
import re
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


TITLE = "Stratamize Statement Audit Model"
CANONICAL_URL = "https://stratamize.com/statement-audit/"
SOURCE_REPOSITORY = "https://github.com/Stratamize/statement-audit-model"
HTTP_TIMEOUT_SECONDS = 5
MAX_JSON_BYTES = 1024 * 1024
MAX_ARCHIVE_BYTES = 10 * 1024 * 1024
MAX_RELEASE_FILE_COUNT = 256
MAX_RELEASE_FILE_BYTES = 5 * 1024 * 1024
MAX_RELEASE_TOTAL_BYTES = 8 * 1024 * 1024
VERSION_ID_PATTERN = re.compile(
    r"^https://stratamize\.com/statement-audit/releases/"
    r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$"
)
PRODUCT_ID = "https://stratamize.com/statement-audit"
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
OBJECT_ID_PATTERN = re.compile(r"^[0-9a-f]{40,64}$")
EXACT_HOSTS = {
    "api.github.com",
    "github.com",
}
TRUSTED_HOST_SUFFIXES = (
    ".githubusercontent.com",
)


@dataclass(frozen=True)
class AttestationResult:
    verified: bool
    failure_codes: tuple[str, ...]
    archive_sha256: str | None
    github_release_url: str | None


def _validate_url(url: str) -> str:
    if not isinstance(url, str):
        raise ValueError("url_invalid")
    parsed = urlsplit(url)
    hostname = (parsed.hostname or "").casefold()
    trusted = hostname in EXACT_HOSTS or any(
        hostname.endswith(suffix) for suffix in TRUSTED_HOST_SUFFIXES
    )
    if (
        parsed.scheme != "https"
        or not trusted
        or parsed.username
        or parsed.password
        or parsed.port not in (None, 443)
        or parsed.fragment
    ):
        raise ValueError("url_untrusted")
    return url


class _SafeRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _validate_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class HttpTransport:
    """HTTPS-only transport with redirect revalidation and response byte caps."""

    def __init__(self):
        self._opener = build_opener(_SafeRedirectHandler())

    def _open(
        self,
        url: str,
        *,
        max_bytes: int,
        accept: str = "application/json, application/octet-stream;q=0.9, */*;q=0.1",
    ) -> tuple[bytes, str]:
        _validate_url(url)
        if not isinstance(max_bytes, int) or max_bytes <= 0:
            raise ValueError("response_limit_invalid")
        request = Request(
            url,
            headers={
                "Accept": accept,
                "User-Agent": "Stratamize-release-attestation/1.0",
            },
        )
        with self._opener.open(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            final_url = _validate_url(response.geturl())
            content_length = response.headers.get("Content-Length")
            if content_length is not None and int(content_length) > max_bytes:
                raise ValueError("response_too_large")
            payload = response.read(max_bytes + 1)
        if len(payload) > max_bytes:
            raise ValueError("response_too_large")
        return payload, final_url

    def get_bytes(self, url: str, *, max_bytes: int) -> bytes:
        return self._open(url, max_bytes=max_bytes)[0]

    def get_json(self, url: str, *, max_bytes: int) -> dict[str, Any]:
        payload = self.get_bytes(url, max_bytes=max_bytes)
        document = json.loads(payload.decode("utf-8", errors="strict"))
        if not isinstance(document, dict):
            raise ValueError("json_root_invalid")
        return document


def _valid_member_name(name: str, prefix: str) -> str | None:
    if not isinstance(name, str) or "\\" in name or "\x00" in name:
        return None
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not name.startswith(prefix):
        return None
    relative = name[len(prefix) :]
    if not relative or relative.endswith("/"):
        return None
    relative_path = PurePosixPath(relative)
    if relative_path.as_posix() != relative or ".." in relative_path.parts:
        return None
    return relative


def _archive_matches_release(
    root: Path, manifest: dict[str, Any], archive_bytes: bytes
) -> bool:
    names = manifest.get("files")
    version = manifest.get("version")
    if (
        not isinstance(names, list)
        or not all(isinstance(name, str) and name for name in names)
        or len(names) != len(set(names))
        or not isinstance(version, str)
    ):
        return False
    prefix = f"stratamize-statement-audit-{version}/"
    observed: dict[str, zipfile.ZipInfo] = {}
    folded: set[str] = set()
    total_bytes = 0
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            if len(archive.infolist()) > MAX_RELEASE_FILE_COUNT + 32:
                return False
            for info in archive.infolist():
                if info.is_dir():
                    continue
                relative = _valid_member_name(info.filename, prefix)
                if relative is None or relative in observed or relative.casefold() in folded:
                    return False
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    return False
                if info.file_size > MAX_RELEASE_FILE_BYTES:
                    return False
                total_bytes += info.file_size
                if total_bytes > MAX_RELEASE_TOTAL_BYTES:
                    return False
                observed[relative] = info
                folded.add(relative.casefold())
            if set(observed) != set(names):
                return False
            root_resolved = root.resolve()
            for name, info in observed.items():
                candidate = (root / name).resolve()
                candidate.relative_to(root_resolved)
                if (
                    not candidate.is_file()
                    or candidate.is_symlink()
                    or archive.read(info) != candidate.read_bytes()
                ):
                    return False
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError):
        return False
    return True


def attest_public_release(
    root: Path | str,
    manifest: dict[str, Any],
    *,
    expected_commit: str,
    transport: HttpTransport | Any | None = None,
) -> AttestationResult:
    """Verify the public GitHub release archive bytes without executing them.

    The declared Stratamize repository is not yet registered; until it exists
    every real attestation fails closed with ``github_release_invalid``.
    """

    root = Path(root).resolve()
    transport = transport or HttpTransport()
    failures: list[str] = []
    archive_sha256: str | None = None
    github_release_url: str | None = None

    try:
        version = manifest["version"]
        version_id = manifest["version_id"]
        product_id = manifest["product_id"]
        release_date = manifest["release_date"]
        source_release = manifest["source_release"]
        if not (
            manifest.get("title") == TITLE
            and isinstance(version, str)
            and isinstance(version_id, str)
            and VERSION_ID_PATTERN.fullmatch(version_id)
            and version_id == f"{PRODUCT_ID}/releases/{version}"
            and product_id == PRODUCT_ID
            and manifest.get("canonical_url") == CANONICAL_URL
            and source_release == f"{SOURCE_REPOSITORY}/releases/tag/v{version}"
            and manifest.get("license") == "CC-BY-4.0"
            and isinstance(release_date, str)
        ):
            raise ValueError("identity")
    except (KeyError, TypeError, ValueError):
        return AttestationResult(False, ("manifest_identity_invalid",), None, None)
    if not isinstance(expected_commit, str) or not OBJECT_ID_PATTERN.fullmatch(
        expected_commit
    ):
        return AttestationResult(False, ("expected_commit_invalid",), None, None)

    zip_name = f"stratamize-statement-audit-model-v{version}.zip"
    sidecar_name = "release-archive.sha256"
    github_api = (
        "https://api.github.com/repos/Stratamize/"
        f"statement-audit-model/releases/tags/v{version}"
    )
    github_prefix = (
        "https://github.com/Stratamize/statement-audit-model/"
        f"releases/download/v{version}/"
    )

    archive_bytes: bytes | None = None
    sidecar_bytes: bytes | None = None
    try:
        github = transport.get_json(github_api, max_bytes=MAX_JSON_BYTES)
        assets = github.get("assets")
        if not (
            github.get("tag_name") == f"v{version}"
            and github.get("draft") is False
            and github.get("prerelease") is False
            and github.get("html_url") == source_release
            and isinstance(assets, list)
        ):
            raise ValueError("identity")
        by_name = {
            item.get("name"): item for item in assets if isinstance(item, dict)
        }
        if set(by_name) != {zip_name, sidecar_name}:
            raise ValueError("assets")
        zip_asset = by_name[zip_name]
        sidecar_asset = by_name[sidecar_name]
        if zip_asset.get("browser_download_url") != github_prefix + zip_name:
            raise ValueError("zip_url")
        if sidecar_asset.get("browser_download_url") != github_prefix + sidecar_name:
            raise ValueError("sidecar_url")
        archive_bytes = transport.get_bytes(
            github_prefix + zip_name, max_bytes=MAX_ARCHIVE_BYTES
        )
        sidecar_bytes = transport.get_bytes(
            github_prefix + sidecar_name, max_bytes=1024
        )
        archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()
        sidecar_sha256 = hashlib.sha256(sidecar_bytes).hexdigest()
        if not (
            zip_asset.get("size") == len(archive_bytes)
            and zip_asset.get("digest") == f"sha256:{archive_sha256}"
            and sidecar_asset.get("size") == len(sidecar_bytes)
            and sidecar_asset.get("digest") == f"sha256:{sidecar_sha256}"
            and sidecar_bytes
            == f"{archive_sha256}  {zip_name}\n".encode("utf-8")
        ):
            failures.append("github_archive_digest_mismatch")
        github_release_url = source_release
    except (KeyError, OSError, TypeError, UnicodeError, ValueError, json.JSONDecodeError):
        failures.append("github_release_invalid")

    if archive_bytes is None or not _archive_matches_release(root, manifest, archive_bytes):
        failures.append("release_archive_invalid")

    unique_failures = tuple(dict.fromkeys(failures))
    return AttestationResult(
        verified=not unique_failures,
        failure_codes=unique_failures,
        archive_sha256=archive_sha256,
        github_release_url=github_release_url,
    )
