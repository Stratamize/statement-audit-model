#!/usr/bin/env python3
"""Rebuild or verify the deterministic SHA-256 release manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
RELEASE_MANIFEST = ROOT / "RELEASE-MANIFEST.json"
CHECKSUM_MANIFEST = ROOT / "checksums.txt"


def expected_content(root: Path = ROOT) -> str:
    manifest = json.loads(
        (root / "RELEASE-MANIFEST.json").read_text(encoding="utf-8")
    )
    names = manifest.get("files")
    if not isinstance(names, list) or len(names) != len(set(names)):
        raise ValueError("Release manifest file inventory must be a unique list.")
    checksum_names = sorted(set(names) - {"checksums.txt"})
    root_resolved = root.resolve()
    lines = []
    for name in checksum_names:
        relative = PurePosixPath(name)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or relative.as_posix() != name
        ):
            raise ValueError("Release manifest contains an unsafe path.")
        # Test the unresolved path: Path.resolve() follows symlinks, so a
        # symlink test made after resolution can never observe one and a link
        # to another in-tree file would be checksummed under the link's name.
        path = root.joinpath(*relative.parts)
        if path.is_symlink() or not path.is_file():
            raise ValueError("Release manifest contains an unavailable file.")
        resolved = path.resolve()
        resolved.relative_to(root_resolved)
        digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
        lines.append(f"{digest} {name}")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args()

    try:
        expected = expected_content(ROOT)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        print("Unable to build checksums from the release manifest.")
        return 2

    if args.check:
        try:
            current = CHECKSUM_MANIFEST.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            current = ""
        if current != expected:
            print("checksums.txt is stale")
            return 1
        print("checksums.txt is current")
        return 0

    CHECKSUM_MANIFEST.write_text(expected, encoding="utf-8", newline="\n")
    print("checksums.txt updated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
