#!/usr/bin/env python3
"""Build the deterministic publication zip and SHA-256 sidecar.

The archive layout must match what ``tools/public_release_attestation.py``
verifies: every manifest file under the member prefix
``stratamize-statement-audit-<version>/``, an asset named
``stratamize-statement-audit-model-v<version>.zip``, and a sidecar
``release-archive.sha256`` containing ``<sha256>  <zip name>\\n``.

Archive bytes are a pure function of the declared manifest and the declared
file bytes. Member timestamps are pinned to the manifest release date, members
are stored uncompressed so the output never depends on the linked zlib build,
and each member declares a POSIX regular file with mode 0644 created on a Unix
host so the same tree produces the same digest on every platform.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import stat
import zipfile
from datetime import date
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MAX_FILE_COUNT = 256
MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024


def _safe_inventory(
    root: Path, manifest: dict[str, Any]
) -> tuple[str, list[str], tuple[int, int, int, int, int, int]]:
    """Return the version, ordered member names, and pinned member timestamp.

    Every declared name must be a relative, canonical, non-traversing POSIX
    path that resolves to a regular file inside the release root. The symlink
    test runs on the unresolved path: ``Path.resolve()`` follows links, so a
    check made after resolution can never observe one.
    """

    version = manifest.get("version")
    names = manifest.get("files")
    release_date = manifest.get("release_date")
    if (
        not isinstance(version, str)
        or not isinstance(names, list)
        or not names
        or len(names) > MAX_FILE_COUNT
        or not all(isinstance(name, str) and name for name in names)
        or len(names) != len(set(names))
        or not isinstance(release_date, str)
    ):
        raise ValueError("release_manifest_invalid")
    parsed_date = date.fromisoformat(release_date)
    timestamp = (parsed_date.year, parsed_date.month, parsed_date.day, 0, 0, 0)
    root_resolved = root.resolve()
    total = 0
    for name in names:
        relative = PurePosixPath(name)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or relative.as_posix() != name
        ):
            raise ValueError("release_path_invalid")
        candidate = root.joinpath(*relative.parts)
        if candidate.is_symlink() or not candidate.is_file():
            raise ValueError("release_file_invalid")
        resolved = candidate.resolve()
        resolved.relative_to(root_resolved)
        size = resolved.stat().st_size
        if size > MAX_FILE_BYTES:
            raise ValueError("release_file_too_large")
        total += size
        if total > MAX_TOTAL_BYTES:
            raise ValueError("release_total_too_large")
    return version, sorted(names, key=str.casefold), timestamp


def build_archive_bytes(root: Path | str, manifest: dict[str, Any]) -> bytes:
    """Return a byte-reproducible, uncompressed ZIP of declared release files."""

    root = Path(root).resolve()
    version, names, timestamp = _safe_inventory(root, manifest)
    prefix = f"stratamize-statement-audit-{version}/"
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in names:
            info = zipfile.ZipInfo(prefix + name, date_time=timestamp)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, (root / name).read_bytes())
    return output.getvalue()


def build_release_archive(root: Path = ROOT) -> tuple[Path, Path, str]:
    root = Path(root).resolve()
    manifest = json.loads(
        (root / "RELEASE-MANIFEST.json").read_text(encoding="utf-8")
    )
    if not isinstance(manifest, dict):
        raise ValueError("release_manifest_invalid")
    archive_bytes = build_archive_bytes(root, manifest)
    zip_name = f"stratamize-statement-audit-model-v{manifest['version']}.zip"

    dist = root / "dist"
    dist.mkdir(exist_ok=True)
    zip_path = dist / zip_name
    zip_path.write_bytes(archive_bytes)

    digest = hashlib.sha256(archive_bytes).hexdigest()
    sidecar_path = dist / "release-archive.sha256"
    sidecar_path.write_text(
        f"{digest}  {zip_name}\n", encoding="utf-8", newline="\n"
    )
    return zip_path, sidecar_path, digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    zip_path, sidecar_path, digest = build_release_archive(ROOT)
    print(zip_path)
    print(sidecar_path)
    print(f"sha256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
