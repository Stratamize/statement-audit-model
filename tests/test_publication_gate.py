import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
GATE_PATH = ROOT / "tools/publication_gate.py"
MANIFEST_PATH = ROOT / "RELEASE-MANIFEST.json"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PublicationGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not GATE_PATH.is_file():
            raise AssertionError("tools/publication_gate.py is required")
        cls.gate = load_module(GATE_PATH, "publication_gate")

    def test_release_manifest_has_one_explicit_versioned_identity(self):
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertEqual("1.1.0", manifest["version"])
        self.assertEqual("1.1.0", manifest["schema_version"])
        self.assertEqual(
            "https://stratamize.com/statement-audit", manifest["product_id"]
        )
        self.assertEqual(
            "https://stratamize.com/statement-audit/",
            manifest["canonical_url"],
        )
        self.assertTrue(manifest["source_release"].endswith("/releases/tag/v1.1.0"))
        self.assertEqual(len(manifest["files"]), len(set(manifest["files"])))
        self.assertGreaterEqual(len(manifest["files"]), 20)

    def test_gate_is_fail_closed_until_every_release_condition_is_satisfied(self):
        report = self.gate.build_publication_report(ROOT)
        self.assertIn(report["status"], {"blocked", "valid", "ready", "verified"})
        self.assertEqual("candidate", report["mode"])
        self.assertEqual(report["check_count"], len(report["checks"]))
        self.assertEqual(
            report["failed_check_count"],
            sum(check["status"] == "fail" for check in report["checks"]),
        )
        self.assertIn("corpus_validation", {check["code"] for check in report["checks"]})
        self.assertIn("dependency_lock", {check["code"] for check in report["checks"]})
        self.assertIn("utf8_text_assets", {check["code"] for check in report["checks"]})
        self.assertIn(
            "repository_provenance", {check["code"] for check in report["checks"]}
        )
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        if manifest["version_id"] is None:
            self.assertEqual("blocked", report["status"])
            self.assertIn(
                "version_id_declared",
                {check["code"] for check in report["checks"] if check["status"] == "fail"},
            )

    def test_tagless_tree_is_blocked_in_default_candidate_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release"
            shutil.copytree(ROOT, candidate, ignore=shutil.ignore_patterns(".git"))

            report = self.gate.build_publication_report(candidate)

        checks = {check["code"]: check["status"] for check in report["checks"]}
        self.assertEqual("candidate", report["mode"])
        self.assertEqual("blocked", report["status"])
        self.assertEqual("fail", checks["repository_provenance"])

    def test_tagless_tree_can_be_package_valid_but_never_publication_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release"
            shutil.copytree(ROOT, candidate, ignore=shutil.ignore_patterns(".git"))

            report = self.gate.build_publication_report(candidate, mode="package")

        self.assertEqual("package", report["mode"])
        self.assertEqual("valid", report["status"])
        self.assertNotIn(
            "repository_provenance", {check["code"] for check in report["checks"]}
        )

    def test_provenance_failure_prevents_candidate_validator_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release"
            shutil.copytree(ROOT, candidate, ignore=shutil.ignore_patterns(".git"))
            validator = candidate / "tools/validate_audit.py"
            validator.write_text(
                "from pathlib import Path\n"
                "Path('candidate-validator-executed.marker').write_text('executed')\n"
                "raise SystemExit(1)\n",
                encoding="utf-8",
            )
            subprocess.run(
                [sys.executable, "tools/update_checksums.py", "--write"],
                cwd=candidate,
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )

            report = self.gate.build_publication_report(candidate)

            self.assertEqual("blocked", report["status"])
            self.assertFalse((candidate / "candidate-validator-executed.marker").exists())

    def test_cli_package_mode_uses_package_validity_language(self):
        result = subprocess.run(
            [sys.executable, str(GATE_PATH), "--mode", "package", "--json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        report = json.loads(result.stdout)
        self.assertEqual("package", report["mode"])
        self.assertEqual("valid", report["status"])
        self.assertEqual(0, result.returncode)

    def test_published_mode_requires_and_reports_external_attestation(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release"
            shutil.copytree(ROOT, candidate, ignore=shutil.ignore_patterns(".git"))
            with mock.patch.object(
                self.gate,
                "inspect_repository",
                return_value=SimpleNamespace(
                    publication_ready=True, head_commit="a" * 40
                ),
            ), mock.patch.object(
                self.gate,
                "attest_public_release",
                return_value=SimpleNamespace(verified=True),
            ) as attestor:
                report = self.gate.build_publication_report(candidate, mode="published")

        checks = {check["code"]: check["status"] for check in report["checks"]}
        self.assertEqual("verified", report["status"])
        self.assertEqual("pass", checks["public_release_attestation"])
        attestor.assert_called_once()

    def test_published_mode_blocks_when_external_attestation_disagrees(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release"
            shutil.copytree(ROOT, candidate, ignore=shutil.ignore_patterns(".git"))
            with mock.patch.object(
                self.gate,
                "inspect_repository",
                return_value=SimpleNamespace(
                    publication_ready=True, head_commit="a" * 40
                ),
            ), mock.patch.object(
                self.gate,
                "attest_public_release",
                return_value=SimpleNamespace(verified=False),
            ):
                report = self.gate.build_publication_report(candidate, mode="published")

        checks = {check["code"]: check["status"] for check in report["checks"]}
        self.assertEqual("blocked", report["status"])
        self.assertEqual("fail", checks["public_release_attestation"])

    def test_gate_report_contains_hashes_and_no_file_contents(self):
        report = self.gate.build_publication_report(ROOT)
        rendered = json.dumps(report, sort_keys=True)
        self.assertIn("manifest_sha256", report)
        self.assertRegex(report["manifest_sha256"], r"^[0-9a-f]{64}$")
        self.assertNotIn("4111 1111", rendered)
        self.assertNotIn("CVV 123", rendered)
        for check in report["checks"]:
            self.assertEqual(
                {"code", "status", "message"}, set(check), "gate checks must stay value-free"
            )

    def test_cli_exit_code_matches_release_readiness(self):
        result = subprocess.run(
            [sys.executable, str(GATE_PATH), "--json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        report = json.loads(result.stdout)
        expected = 0 if report["status"] == "ready" else 1
        self.assertEqual(expected, result.returncode)

    def test_checksum_tool_verifies_the_exact_manifest_without_rewriting(self):
        result = subprocess.run(
            [sys.executable, "tools/update_checksums.py", "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual("checksums.txt is current\n", result.stdout)

    def test_gate_scans_every_declared_asset_for_common_secret_signatures(self):
        signatures = (
            "AKIA" + "IOSFODNN7EXAMPLE",
            "sk-proj-" + ("A" * 32),
            "sk-ant-" + ("B" * 32),
            "ya29." + ("C" * 32),
        )
        for signature in signatures:
            with self.subTest(prefix=signature[:7]):
                with tempfile.TemporaryDirectory() as directory:
                    candidate = Path(directory) / "release"
                    shutil.copytree(ROOT, candidate)
                    with (candidate / "LICENSE.md").open(
                        "a", encoding="utf-8"
                    ) as handle:
                        handle.write("\n" + signature + "\n")

                    report = self.gate.build_publication_report(candidate)
                    checks = {
                        check["code"]: check["status"] for check in report["checks"]
                    }
                    self.assertEqual("fail", checks["public_content_safety"])
                    self.assertEqual("blocked", report["status"])

    def test_gate_executes_the_validator_from_the_candidate_release(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release"
            shutil.copytree(ROOT, candidate)
            (candidate / "tools/validate_audit.py").write_text(
                'raise RuntimeError("tampered validator")\n', encoding="utf-8"
            )

            report = self.gate.build_publication_report(candidate)
            checks = {check["code"]: check["status"] for check in report["checks"]}
            self.assertEqual("fail", checks["corpus_validation"])
            self.assertEqual("blocked", report["status"])

    def test_gate_requires_every_security_critical_release_asset(self):
        critical_assets = (
            "tools/public_release_attestation.py",
            "tools/publication_gate.py",
            "tools/release_provenance.py",
            "tests/test_public_release_attestation.py",
            "tests/test_release_provenance.py",
        )
        for critical_asset in critical_assets:
            with self.subTest(critical_asset=critical_asset):
                with tempfile.TemporaryDirectory() as directory:
                    candidate = Path(directory) / "release"
                    shutil.copytree(ROOT, candidate)
                    manifest_path = candidate / "RELEASE-MANIFEST.json"
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    manifest["files"].remove(critical_asset)
                    manifest_path.write_text(
                        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
                    )

                    report = self.gate.build_publication_report(candidate)
                    checks = {
                        check["code"]: check["status"] for check in report["checks"]
                    }
                    self.assertEqual("fail", checks["required_release_assets"])
                    self.assertEqual("blocked", report["status"])

    def test_gate_blocks_an_undeclared_regular_file_in_the_release_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release"
            shutil.copytree(ROOT, candidate)
            (candidate / "undeclared-public-payload.txt").write_text(
                "This file is not covered by the manifest or checksums.\n",
                encoding="utf-8",
            )

            report = self.gate.build_publication_report(candidate)
            checks = {check["code"]: check["status"] for check in report["checks"]}
            self.assertEqual("fail", checks["manifest_inventory"])
            self.assertEqual("blocked", report["status"])

    def test_gate_blocks_an_oversized_declared_text_asset(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release"
            shutil.copytree(ROOT, candidate)
            oversized_name = "oversized-public-payload.txt"
            (candidate / oversized_name).write_bytes(b"x" * (5 * 1024 * 1024 + 1))
            manifest_path = candidate / "RELEASE-MANIFEST.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["files"].append(oversized_name)
            manifest_path.write_text(
                json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
            )
            subprocess.run(
                [sys.executable, "tools/update_checksums.py", "--write"],
                cwd=candidate,
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )

            report = self.gate.build_publication_report(candidate)
            checks = {check["code"]: check["status"] for check in report["checks"]}
            self.assertEqual("fail", checks["release_size_limits"])
            self.assertEqual("blocked", report["status"])

    def test_gate_runs_the_candidate_validator_regression_suite(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release"
            shutil.copytree(ROOT, candidate)
            validator_path = candidate / "tools/validate_audit.py"
            validator = validator_path.read_text(encoding="utf-8")
            validator = validator.replace(
                '_EMAIL = re.compile(r"\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b", re.I)',
                '_EMAIL = re.compile(r"$^")',
            )
            self.assertIn('_EMAIL = re.compile(r"$^")', validator)
            validator_path.write_text(validator, encoding="utf-8")

            corpus = subprocess.run(
                [sys.executable, "tools/validate_audit.py", "--corpus"],
                cwd=candidate,
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
            (candidate / "validation-report.json").write_text(
                corpus.stdout, encoding="utf-8"
            )
            subprocess.run(
                [sys.executable, "tools/update_checksums.py", "--write"],
                cwd=candidate,
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )

            report = self.gate.build_publication_report(candidate)
            checks = {check["code"]: check["status"] for check in report["checks"]}
            self.assertEqual("fail", checks["candidate_regression_suite"])
            self.assertEqual("blocked", report["status"])

    def test_gate_rejects_untrusted_manifest_identity_even_when_metadata_agrees(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release"
            shutil.copytree(ROOT, candidate)
            manifest_path = candidate / "RELEASE-MANIFEST.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            old_product_id = manifest["product_id"]
            manifest["product_id"] = "not-an-identifier"
            manifest_path.write_text(
                json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
            )

            codemeta_path = candidate / "codemeta.json"
            codemeta = json.loads(codemeta_path.read_text(encoding="utf-8"))
            codemeta["sameAs"] = [
                value.replace(old_product_id, "not-an-identifier")
                for value in codemeta["sameAs"]
            ]
            codemeta_path.write_text(
                json.dumps(codemeta, indent=2) + "\n", encoding="utf-8"
            )
            subprocess.run(
                [sys.executable, "tools/update_checksums.py", "--write"],
                cwd=candidate,
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )

            report = self.gate.build_publication_report(candidate)
            checks = {check["code"]: check["status"] for check in report["checks"]}
            self.assertEqual("fail", checks["manifest_identity"])
            self.assertEqual("blocked", report["status"])

    def test_gate_blocks_changes_masquerading_as_an_existing_release_tag(self):
        tag_check = subprocess.run(
            ["git", "rev-parse", "--verify", "refs/tags/v1.0.0"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        if tag_check.returncode != 0:
            self.skipTest("v1.0.0 tag is required for the immutability regression")

        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release"
            shutil.copytree(ROOT, candidate)
            with (candidate / "README.md").open("a", encoding="utf-8") as handle:
                handle.write("\nUndisclosed rewrite of an immutable release.\n")
            subprocess.run(
                [sys.executable, "tools/update_checksums.py", "--write"],
                cwd=candidate,
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )

            manifest = json.loads(
                (candidate / "RELEASE-MANIFEST.json").read_text(encoding="utf-8")
            )
            manifest["version"] = "1.0.0"
            self.assertFalse(
                self.gate._matches_existing_release_tag(
                    candidate, manifest, manifest["files"]
                )
            )

    def test_gate_returns_a_structured_block_for_a_malformed_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release"
            shutil.copytree(ROOT, candidate)
            (candidate / "RELEASE-MANIFEST.json").write_text(
                "{not-json", encoding="utf-8"
            )

            report = self.gate.build_publication_report(candidate)
            self.assertEqual("blocked", report["status"])
            self.assertEqual("manifest_read", report["checks"][0]["code"])
            self.assertEqual("fail", report["checks"][0]["status"])

    def test_manifest_traversal_is_blocked_without_reading_outside_release(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            candidate = parent / "release"
            shutil.copytree(ROOT, candidate)
            (parent / "outside.txt").write_text(
                "AKIA" + "IOSFODNN7EXAMPLE", encoding="utf-8"
            )
            manifest_path = candidate / "RELEASE-MANIFEST.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["files"].append("../outside.txt")
            manifest_path.write_text(
                json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
            )

            paths, safe = self.gate._safe_file_paths(candidate, manifest["files"])
            self.assertFalse(safe)
            self.assertNotIn((parent / "outside.txt").resolve(), paths)
            report = self.gate.build_publication_report(candidate)
            checks = {check["code"]: check["status"] for check in report["checks"]}
            self.assertEqual("blocked", report["status"])
            self.assertEqual("fail", checks["manifest_inventory"])
            self.assertEqual("fail", checks["public_content_safety"])

    def test_manifest_rejects_noncanonical_aliases_of_the_same_file(self):
        paths, safe = self.gate._safe_file_paths(
            ROOT, ["README.md", "./README.md"]
        )
        self.assertFalse(safe)
        self.assertEqual([ROOT / "README.md"], paths)

    def test_gate_blocks_a_missing_identity_asset_without_throwing(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release"
            shutil.copytree(ROOT, candidate)
            (candidate / "README.md").unlink()

            report = self.gate.build_publication_report(candidate)
            checks = {check["code"]: check["status"] for check in report["checks"]}
            self.assertEqual("blocked", report["status"])
            self.assertEqual("fail", checks["manifest_inventory"])
            self.assertEqual("fail", checks["release_identity"])

    def test_gate_blocks_non_utf8_integrity_metadata_without_throwing(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release"
            shutil.copytree(ROOT, candidate)
            (candidate / "checksums.txt").write_bytes(b"\xff\xfe\x00")

            report = self.gate.build_publication_report(candidate)
            checks = {check["code"]: check["status"] for check in report["checks"]}
            self.assertEqual("blocked", report["status"])
            self.assertEqual("fail", checks["release_checksums"])
            self.assertEqual("fail", checks["utf8_text_assets"])

    def test_gate_rejects_an_artifact_beneath_a_symlinked_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            candidate = parent / "release"
            shutil.copytree(ROOT, candidate)
            target = candidate / "real-assets"
            target.mkdir()
            (target / "nested.txt").write_text("safe", encoding="utf-8")
            alias = candidate / "alias"
            try:
                os.symlink(target, alias, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlinks unavailable: {exc}")

            paths, safe = self.gate._safe_file_paths(
                candidate, ["alias/nested.txt"]
            )
            self.assertFalse(safe)
            self.assertEqual([], paths)

    def test_release_identity_includes_publication_date(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release"
            shutil.copytree(ROOT, candidate)
            metadata_path = candidate / "codemeta.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["datePublished"] = "1900-01-01"
            metadata_path.write_text(
                json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
            )
            subprocess.run(
                [sys.executable, "tools/update_checksums.py", "--write"],
                cwd=candidate,
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )

            report = self.gate.build_publication_report(candidate)
            checks = {check["code"]: check["status"] for check in report["checks"]}
            self.assertEqual("blocked", report["status"])
            self.assertEqual("fail", checks["release_identity"])
            self.assertEqual("pass", checks["release_checksums"])

    def test_non_object_identity_documents_block_without_throwing(self):
        identity_files = (
            "codemeta.json",
            "schema/payment-statement-audit.schema.json",
            "examples/payment-statement-audit-example.json",
        )
        for filename in identity_files:
            with self.subTest(filename=filename):
                with tempfile.TemporaryDirectory() as directory:
                    candidate = Path(directory) / "release"
                    shutil.copytree(ROOT, candidate)
                    (candidate / filename).write_text("[]\n", encoding="utf-8")
                    subprocess.run(
                        [sys.executable, "tools/update_checksums.py", "--write"],
                        cwd=candidate,
                        check=True,
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                    )

                    report = self.gate.build_publication_report(candidate)
                    checks = {
                        check["code"]: check["status"] for check in report["checks"]
                    }
                    self.assertEqual("blocked", report["status"])
                    self.assertEqual("fail", checks["release_identity"])

    def test_runtime_only_directories_stay_in_sync_with_gitignore(self):
        ignored_directories = set()
        for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines():
            entry = line.strip()
            if not entry or entry.startswith(("#", "!")) or not entry.endswith("/"):
                continue
            ignored_directories.add(entry.rstrip("/").lstrip("/"))

        self.assertIn("dist", ignored_directories)
        # ".git" is never listed in .gitignore but is always runtime-only.
        self.assertEqual(
            ignored_directories | {".git"}, self.gate.RUNTIME_ONLY_DIRECTORIES
        )

    def test_built_release_archive_is_never_discovered_as_a_release_file(self):
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory) / "release"
            (tree / "dist").mkdir(parents=True)
            (tree / "dist/statement-audit-model.zip").write_bytes(b"PK\x05\x06")
            (tree / "dist/release-archive.sha256").write_text("0\n", encoding="utf-8")
            (tree / "tools").mkdir()
            (tree / "tools/validate_audit.py").write_text("", encoding="utf-8")

            # Force the no-git fallback: an extracted release archive has no .git,
            # so discovery must fall back to rglob and still exclude dist/.
            with mock.patch.object(self.gate.shutil, "which", return_value=None):
                discovered = self.gate._discover_release_files(tree)

        self.assertEqual({"tools/validate_audit.py"}, discovered)


if __name__ == "__main__":
    unittest.main()
