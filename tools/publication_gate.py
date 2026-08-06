#!/usr/bin/env python3
"""Fail-closed publication gate for the statement-audit release package."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import unicodedata
from dataclasses import asdict, dataclass
from datetime import date
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from release_provenance import inspect_repository  # noqa: E402
from public_release_attestation import attest_public_release  # noqa: E402


GATE_VERSION = "2.1.0"
VERSION_ID_PATTERN = re.compile(
    r"^https://stratamize\.com/statement-audit/releases/"
    r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$"
)
PRODUCT_ID = "https://stratamize.com/statement-audit"
SEMVER_PATTERN = re.compile(r"^[1-9]\d*\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$")
RELEASE_TITLE = "Stratamize Statement Audit Model"
CANONICAL_URL = "https://stratamize.com/statement-audit/"
SOURCE_REPOSITORY = "https://github.com/Stratamize/statement-audit-model"
LICENSE_ID = "CC-BY-4.0"
MAX_RELEASE_FILE_COUNT = 256
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_RELEASE_FILE_BYTES = 5 * 1024 * 1024
MAX_RELEASE_TOTAL_BYTES = 8 * 1024 * 1024
# Must stay in sync with .gitignore: every directory ignored by git is runtime-only
# and must never be counted as an undeclared release file when the tree is inspected
# without .git (an extracted release archive). ".git" itself is not in .gitignore.
# tests/test_publication_gate.py asserts this equivalence so the two cannot drift.
RUNTIME_ONLY_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "dist",
    "__pycache__",
    "venv",
}
SECRET_PATTERN = re.compile(
    r"(?:-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    r"\bAKIA[0-9A-Z]{16}\b|"
    r"\bAIza[0-9A-Za-z_-]{35}\b|"
    r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b|"
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b|"
    r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b|"
    r"\bsk-ant-[A-Za-z0-9_-]{20,}\b|"
    r"\bya29\.[A-Za-z0-9_-]{20,}\b|"
    r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b|"
    r"\b(?:sk|hf)_[A-Za-z0-9_-]{20,}\b)",
    re.I,
)
REQUIRED_RELEASE_ASSETS = {
    ".gitattributes",
    ".gitignore",
    "CHANGELOG.md",
    "CITATION.cff",
    "checksums.txt",
    "codemeta.json",
    "DATA_DICTIONARY.md",
    "examples/payment-statement-audit-example.json",
    "LICENSE.md",
    "llms.txt",
    "METHODOLOGY.md",
    "NOTICE.md",
    "payment-statement-audit-template.csv",
    "README.md",
    "RELEASE-MANIFEST.json",
    "requirements-service.txt",
    "requirements-validation.txt",
    "ruff.toml",
    "schema/payment-statement-audit.schema.json",
    "SECURITY.md",
    "service/app.py",
    "start-service.ps1",
    "test-vectors/manifest.json",
    "tests/test_audit_validator.py",
    "tests/test_publication_gate.py",
    "tests/test_public_release_attestation.py",
    "tests/test_release_assets.py",
    "tests/test_release_provenance.py",
    "tests/test_service.py",
    "tools/build_release_archive.py",
    "tools/public_release_attestation.py",
    "tools/publication_gate.py",
    "tools/release_provenance.py",
    "tools/update_checksums.py",
    "tools/validate_audit.py",
    "validation-report.json",
}


def _run_candidate_corpus(root: Path) -> dict[str, Any]:
    result = subprocess.run(
        [sys.executable, str(root / "tools/validate_audit.py"), "--corpus"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=20,
    )
    if result.returncode != 0:
        raise RuntimeError("candidate_validator_failed")
    report = json.loads(result.stdout)
    if not isinstance(report, dict):
        raise ValueError("candidate_validator_report")
    return report


def _run_candidate_regression_suite(root: Path) -> bool:
    result = subprocess.run(
        [sys.executable, str(root / "tests/test_audit_validator.py"), "-q"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )
    return result.returncode == 0


@dataclass(frozen=True)
class GateCheck:
    code: str
    status: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def _check(code: str, passed: bool, success: str, failure: str) -> GateCheck:
    return GateCheck(code, "pass" if passed else "fail", success if passed else failure)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _contains_unsafe_text_control(value: str) -> bool:
    return any(
        character not in "\t\n\r" and unicodedata.category(character) in {"Cc", "Cf"}
        for character in value
    )


def _load_manifest(root: Path) -> dict[str, Any]:
    manifest_path = root / "RELEASE-MANIFEST.json"
    if manifest_path.is_symlink() or manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
        raise ValueError("manifest_size")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("manifest_root")
    return manifest


def _manifest_identity_is_trusted(manifest: dict[str, Any]) -> bool:
    title = manifest.get("title")
    version = manifest.get("version")
    schema_version = manifest.get("schema_version")
    release_date = manifest.get("release_date")
    version_id = manifest.get("version_id")
    product_id = manifest.get("product_id")
    canonical_url = manifest.get("canonical_url")
    source_release = manifest.get("source_release")
    license_id = manifest.get("license")
    values = (
        title,
        version,
        schema_version,
        release_date,
        version_id,
        product_id,
        canonical_url,
        source_release,
        license_id,
    )
    if not all(isinstance(value, str) and value for value in values):
        return False
    try:
        parsed_date = date.fromisoformat(release_date)
    except ValueError:
        return False
    return (
        title == RELEASE_TITLE
        and bool(SEMVER_PATTERN.fullmatch(version))
        and bool(SEMVER_PATTERN.fullmatch(schema_version))
        and parsed_date.isoformat() == release_date
        and bool(VERSION_ID_PATTERN.fullmatch(version_id))
        and version_id == f"{PRODUCT_ID}/releases/{version}"
        and product_id == PRODUCT_ID
        and version_id != product_id
        and canonical_url == CANONICAL_URL
        and source_release == f"{SOURCE_REPOSITORY}/releases/tag/v{version}"
        and license_id == LICENSE_ID
    )


def _discover_release_files(root: Path) -> set[str] | None:
    git_executable = shutil.which("git")
    try:
        result = (
            subprocess.run(
                [
                    git_executable,
                    "-C",
                    str(root),
                    "ls-files",
                    "--cached",
                    "--others",
                    "--exclude-standard",
                    "-z",
                ],
                capture_output=True,
                timeout=10,
            )
            if git_executable
            else None
        )
    except (OSError, subprocess.TimeoutExpired):
        result = None
    if result is not None and result.returncode == 0:
        try:
            names = result.stdout.decode("utf-8", errors="strict").split("\0")
        except UnicodeError:
            return None
        return {name.replace("\\", "/") for name in names if name}

    try:
        discovered: set[str] = set()
        for path in root.rglob("*"):
            relative = path.relative_to(root)
            if any(part in RUNTIME_ONLY_DIRECTORIES for part in relative.parts):
                continue
            if path.is_file() or path.is_symlink():
                discovered.add(relative.as_posix())
        return discovered
    except OSError:
        return None


def _matches_existing_release_tag(
    root: Path, manifest: dict[str, Any], names: list[str]
) -> bool:
    version = manifest.get("version")
    git_executable = shutil.which("git")
    if not isinstance(version, str) or not git_executable:
        return False
    tag = f"refs/tags/v{version}"
    try:
        tag_check = subprocess.run(
            [git_executable, "-C", str(root), "rev-parse", "--verify", tag],
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if tag_check.returncode != 0:
        # A new version has no tag until the candidate passes this prepublication gate.
        return True
    for name in names:
        try:
            tagged = subprocess.run(
                [git_executable, "-C", str(root), "show", f"{tag}:{name}"],
                capture_output=True,
                timeout=10,
            )
            if tagged.returncode != 0 or tagged.stdout != (root / name).read_bytes():
                return False
        except (OSError, subprocess.TimeoutExpired):
            return False
    return True


def _safe_file_paths(root: Path, names: list[str]) -> tuple[list[Path], bool]:
    root_resolved = root.resolve()
    paths: list[Path] = []
    seen_paths: set[Path] = set()
    safe = True
    for name in names:
        if not isinstance(name, str) or not name:
            safe = False
            continue
        relative_path = Path(name)
        if (
            relative_path.is_absolute()
            or ".." in relative_path.parts
            or relative_path.as_posix() != name
        ):
            safe = False
            continue
        logical_path = root
        symlinked_component = False
        for part in relative_path.parts:
            logical_path /= part
            if logical_path.is_symlink():
                symlinked_component = True
                break
        if symlinked_component:
            safe = False
            continue
        candidate = logical_path.resolve()
        try:
            candidate.relative_to(root_resolved)
        except ValueError:
            safe = False
            continue
        if candidate in seen_paths:
            safe = False
            continue
        seen_paths.add(candidate)
        paths.append(candidate)
    return paths, safe and len(paths) == len(names)


def _parse_checksums(path: Path) -> dict[str, str]:
    checksums: dict[str, str] = {}
    if not path.is_file():
        return checksums
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return checksums
    for line in lines:
        if not line.strip():
            continue
        parts = line.strip().split(maxsplit=1)
        if len(parts) != 2 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            return {}
        if parts[1] in checksums:
            return {}
        checksums[parts[1]] = parts[0]
    return checksums


def _pinned_dependencies(path: Path) -> dict[str, str]:
    pins: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return pins
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("==", maxsplit=1)
        if len(parts) != 2 or not all(parts):
            return {}
        pins[parts[0]] = parts[1]
    return pins


def _identity_matches(root: Path, manifest: dict[str, Any]) -> bool:
    title = manifest.get("title")
    version = manifest.get("version")
    schema_version = manifest.get("schema_version")
    release_date = manifest.get("release_date")
    version_id = manifest.get("version_id")
    product_id = manifest.get("product_id")
    canonical_url = manifest.get("canonical_url")
    license_id = manifest.get("license")
    identity_values = (
        title,
        version,
        schema_version,
        release_date,
        version_id,
        product_id,
        canonical_url,
        license_id,
    )
    if not all(isinstance(value, str) for value in identity_values):
        return False
    release_url = manifest.get("source_release")

    if not isinstance(release_url, str):
        return False

    try:
        codemeta = json.loads((root / "codemeta.json").read_text(encoding="utf-8"))
        citation = (root / "CITATION.cff").read_text(encoding="utf-8")
        schema = json.loads(
            (root / "schema/payment-statement-audit.schema.json").read_text(
                encoding="utf-8"
            )
        )
        example = json.loads(
            (root / "examples/payment-statement-audit-example.json").read_text(
                encoding="utf-8"
            )
        )
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False

    if not all(
        isinstance(document, dict)
        for document in (codemeta, schema, example)
    ):
        return False

    codemeta_same_as = set(codemeta.get("sameAs", []))
    if not (
        codemeta.get("name") == title
        and codemeta.get("version") == version
        and codemeta.get("datePublished") == release_date
        and codemeta.get("identifier") == version_id
        and codemeta.get("url") == canonical_url
        and version_id in codemeta_same_as
        and product_id in codemeta_same_as
        and example.get("schema_version") == schema_version
        and schema.get("properties", {}).get("schema_version", {}).get("const")
        == schema_version
        and re.search(rf'(?m)^title: "{re.escape(title)}"$', citation)
        and re.search(rf"(?m)^version: {re.escape(version)}$", citation)
        and re.search(rf"(?m)^date-released: {re.escape(release_date)}$", citation)
        and re.search(rf'(?m)^    value: "{re.escape(version_id)}"$', citation)
        and re.search(rf'(?m)^url: "{re.escape(canonical_url)}"$', citation)
        and re.search(rf"(?m)^license: {re.escape(license_id)}$", citation)
    ):
        return False

    identity_files = (
        "README.md",
        "llms.txt",
    )
    for name in identity_files:
        text = (root / name).read_text(encoding="utf-8")
        if version not in text or version_id not in text or release_url not in text:
            return False
    return True


def build_publication_report(
    root: Path | str = ROOT, *, mode: str = "candidate"
) -> dict[str, Any]:
    if mode not in {"package", "candidate", "published"}:
        raise ValueError("unsupported publication mode")
    root = Path(root).resolve()
    try:
        manifest = _load_manifest(root)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        manifest_path = root / "RELEASE-MANIFEST.json"
        digest = _sha256(manifest_path) if manifest_path.is_file() else None
        check = GateCheck(
            "manifest_read",
            "fail",
            "Release manifest is missing, unreadable, malformed, or not a JSON object.",
        )
        return {
            "gate_version": GATE_VERSION,
            "mode": mode,
            "release_version": None,
            "status": "blocked",
            "check_count": 1,
            "failed_check_count": 1,
            "checks": [check.to_dict()],
            "manifest_sha256": digest,
        }
    raw_names = manifest.get("files", [])
    names = raw_names if isinstance(raw_names, list) else []
    names_are_valid = (
        isinstance(raw_names, list)
        and all(isinstance(name, str) and name for name in names)
        and len(names) == len(set(names))
    )
    paths, safe_paths = _safe_file_paths(root, names)
    discovered_files = _discover_release_files(root)
    checks: list[GateCheck] = []

    checks.append(
        _check(
            "manifest_inventory",
            names_are_valid
            and len(names) >= 20
            and safe_paths
            and discovered_files == set(names)
            and all(path.is_file() and not path.is_symlink() for path in paths),
            "Release inventory is explicit, unique, contained, and complete.",
            "Release inventory is missing, duplicated, unsafe, or incomplete.",
        )
    )

    checks.append(
        _check(
            "manifest_identity",
            _manifest_identity_is_trusted(manifest),
            "Release name, versions, date, identifier pair, license, and canonical source identity are trusted.",
            "Release identity is missing, malformed, inconsistent, or points outside trusted publication surfaces.",
        )
    )

    release_sizes_are_safe = safe_paths and len(paths) <= MAX_RELEASE_FILE_COUNT
    if release_sizes_are_safe:
        try:
            sizes = [path.stat().st_size for path in paths]
            release_sizes_are_safe = (
                all(size <= MAX_RELEASE_FILE_BYTES for size in sizes)
                and sum(sizes) <= MAX_RELEASE_TOTAL_BYTES
            )
        except OSError:
            release_sizes_are_safe = False
    checks.append(
        _check(
            "release_size_limits",
            release_sizes_are_safe,
            "Release file count and per-file and aggregate byte sizes are bounded.",
            "Release file count or byte size exceeds the publication safety limits.",
        )
    )

    checks.append(
        _check(
            "required_release_assets",
            names_are_valid and REQUIRED_RELEASE_ASSETS.issubset(set(names)),
            "Every security-critical schema, validator, test, metadata, and integrity asset is declared.",
            "One or more security-critical release assets is absent from the manifest.",
        )
    )

    version_id = manifest.get("version_id")
    product_id = manifest.get("product_id")
    checks.append(
        _check(
            "version_id_declared",
            isinstance(version_id, str)
            and bool(VERSION_ID_PATTERN.fullmatch(version_id))
            and version_id != product_id,
            "A syntactically valid, distinct Stratamize version identifier is declared.",
            "A syntactically valid, distinct Stratamize version identifier is not declared.",
        )
    )

    try:
        identity_matches = release_sizes_are_safe and _identity_matches(root, manifest)
    except (
        AttributeError,
        OSError,
        UnicodeError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ):
        identity_matches = False
    checks.append(
        _check(
            "release_identity",
            identity_matches,
            "Version, identifier, schema, citation, and source-release identities agree.",
            "Version, identifier, schema, citation, or source-release identities disagree.",
        )
    )

    checksums = _parse_checksums(root / "checksums.txt")
    expected_checksum_files = set(names) - {"checksums.txt"} if names_are_valid else set()
    checksum_valid = (
        safe_paths
        and release_sizes_are_safe
        and set(checksums) == expected_checksum_files
    )
    if checksum_valid:
        try:
            checksum_valid = all(
                (root / name).is_file() and _sha256(root / name) == digest
                for name, digest in checksums.items()
            )
        except OSError:
            checksum_valid = False
    checks.append(
        _check(
            "release_checksums",
            checksum_valid,
            "SHA-256 manifest exactly covers and matches every release file.",
            "SHA-256 manifest is incomplete, stale, malformed, or mismatched.",
        )
    )

    try:
        lf_only = safe_paths and release_sizes_are_safe and all(
            b"\r\n" not in path.read_bytes() for path in paths if path.is_file()
        )
    except OSError:
        lf_only = False
    checks.append(
        _check(
            "lf_portability",
            lf_only,
            "All release text assets use reproducible LF line endings.",
            "One or more release assets contain noncanonical CRLF line endings.",
        )
    )

    utf8_assets = safe_paths and release_sizes_are_safe
    if utf8_assets:
        for path in paths:
            try:
                path.read_text(encoding="utf-8", errors="strict")
            except (OSError, UnicodeError):
                utf8_assets = False
    checks.append(
        _check(
            "utf8_text_assets",
            utf8_assets,
            "Every declared release asset is strict UTF-8 text.",
            "One or more declared release assets is unreadable as strict UTF-8 text.",
        )
    )

    try:
        public_text = (
            "\n".join(path.read_text(encoding="utf-8") for path in paths)
            if release_sizes_are_safe
            else ""
        )
        safe_public_text = (
            safe_paths
            and release_sizes_are_safe
            and not SECRET_PATTERN.search(public_text)
            and not _contains_unsafe_text_control(public_text)
        )
    except (UnicodeError, OSError):
        safe_public_text = False
    checks.append(
        _check(
            "public_content_safety",
            safe_public_text,
            "Public files contain no credential signatures or unsafe text controls.",
            "Public files contain a credential signature or unsafe text control.",
        )
    )

    static_ready = all(check.status == "pass" for check in checks)
    provenance_ready = mode == "package"
    if mode != "package":
        provenance = None
        if static_ready and names_are_valid:
            try:
                provenance = inspect_repository(
                    root,
                    str(manifest.get("version", "")),
                    files=names,
                    expected_origin=SOURCE_REPOSITORY,
                )
            except (OSError, TypeError, ValueError, subprocess.TimeoutExpired):
                provenance = None
        provenance_ready = bool(provenance and provenance.publication_ready)
        checks.append(
            _check(
                "repository_provenance",
                provenance_ready,
                "The candidate is a clean committed tree with authoritative remote tag provenance.",
                "Git metadata, committed-tree, origin, remote-tag, or version provenance is not publication-ready.",
            )
        )

    execution_ready = static_ready and provenance_ready
    try:
        corpus_report = (
            _run_candidate_corpus(root) if execution_ready else {"status": "fail"}
        )
        corpus_ready = execution_ready and (
            corpus_report.get("status") == "pass"
            and corpus_report.get("validator_version") == manifest.get("version")
        )
    except (
        OSError,
        UnicodeError,
        ValueError,
        RuntimeError,
        json.JSONDecodeError,
        subprocess.TimeoutExpired,
    ):
        corpus_report = {"status": "fail"}
        corpus_ready = False
    checks.append(
        _check(
            "corpus_validation",
            corpus_ready,
            "All valid and invalid synthetic vectors produce expected results.",
            "The synthetic validation corpus did not run safely or reproduce expected results.",
        )
    )

    try:
        candidate_regressions_ready = execution_ready and (
            _run_candidate_regression_suite(root)
        )
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        candidate_regressions_ready = False
    checks.append(
        _check(
            "candidate_regression_suite",
            candidate_regressions_ready,
            "The candidate validator passes its bounded behavioral regression suite.",
            "The candidate validator regression suite did not run safely, failed, or timed out.",
        )
    )

    dependency_lock = (
        _pinned_dependencies(root / "requirements-validation.txt")
        if execution_ready
        else {}
    )
    checks.append(
        _check(
            "dependency_lock",
            corpus_ready
            and dependency_lock == corpus_report.get("dependency_versions"),
            "Validation runtime and all transitive dependencies are exactly pinned.",
            "Validation dependency pins are incomplete or differ from the tested runtime.",
        )
    )

    validation_report_path = root / "validation-report.json"
    validation_report_matches = False
    if release_sizes_are_safe and validation_report_path.is_file() and corpus_ready:
        try:
            published_report = json.loads(
                validation_report_path.read_text(encoding="utf-8")
            )
            validation_report_matches = published_report == corpus_report
        except (UnicodeError, OSError, json.JSONDecodeError):
            pass
    checks.append(
        _check(
            "validation_report",
            validation_report_matches,
            "Published validation report exactly matches a fresh corpus run.",
            "Published validation report is missing, stale, or inconsistent.",
        )
    )

    if mode == "published":
        attestation_ready = False
        if all(check.status == "pass" for check in checks):
            try:
                attestation_ready = attest_public_release(
                    root,
                    manifest,
                    expected_commit=provenance.head_commit,
                ).verified
            except (OSError, TypeError, ValueError):
                attestation_ready = False
        checks.append(
            _check(
                "public_release_attestation",
                attestation_ready,
                "Public GitHub release artifacts match the tagged release.",
                "Public release attestation is unavailable or did not match the tagged release.",
            )
        )

    serialized = [check.to_dict() for check in checks]
    failed = sum(check["status"] == "fail" for check in serialized)
    if failed:
        status = "blocked"
    elif mode == "package":
        status = "valid"
    elif mode == "candidate":
        status = "ready"
    else:
        status = "verified"
    return {
        "gate_version": GATE_VERSION,
        "mode": mode,
        "release_version": manifest.get("version"),
        "status": status,
        "check_count": len(serialized),
        "failed_check_count": failed,
        "checks": serialized,
        "manifest_sha256": _sha256(root / "RELEASE-MANIFEST.json"),
    }


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify that the statement-audit package is safe to publish."
    )
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument(
        "--mode",
        choices=("package", "candidate", "published"),
        default="candidate",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    report = build_publication_report(ROOT, mode=args.mode)
    if args.as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            f"{report['mode'].upper()} {report['status'].upper()}: "
            f"{report['failed_check_count']} failed check(s)"
        )
        for check in report["checks"]:
            print(f"- {check['status'].upper()} {check['code']}: {check['message']}")
    return 0 if report["status"] != "blocked" else 1


if __name__ == "__main__":
    raise SystemExit(main())
