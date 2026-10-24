import base64
import hashlib
import json
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TITLE = "Stratamize Statement Audit Model"
CANONICAL_URL = "https://stratamize.com/statement-audit/"
REPOSITORY_URL = "https://github.com/Stratamize/statement-audit-model"
VERSION = "1.1.0"
SCHEMA_VERSION = "1.1.0"
RELEASE_DATE = "2026-08-06"
PRODUCT_ID = "https://stratamize.com/statement-audit"
VERSION_ID = f"{PRODUCT_ID}/releases/{VERSION}"
RELEASE_URL = f"{REPOSITORY_URL}/releases/tag/v{VERSION}"
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


def git_metadata_is_available():
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    except OSError:
        return False
    return result.returncode == 0 and result.stdout.strip() == "true"


def portable_release_inventory():
    files = set()
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        if any(part in RUNTIME_ONLY_DIRECTORIES for part in relative.parts):
            continue
        if path.is_file() or path.is_symlink():
            files.add(relative.as_posix())
    return files


class ReleaseAssetTests(unittest.TestCase):
    def test_codemeta_describes_the_same_dataset(self):
        metadata = json.loads((ROOT / "codemeta.json").read_text(encoding="utf-8"))

        self.assertEqual(metadata["@type"], "Dataset")
        self.assertEqual(metadata["name"], TITLE)
        self.assertEqual(metadata["version"], VERSION)
        self.assertEqual(metadata["datePublished"], RELEASE_DATE)
        self.assertEqual(metadata["license"], "https://creativecommons.org/licenses/by/4.0/")
        self.assertEqual(metadata["url"], CANONICAL_URL)
        self.assertEqual(metadata["codeRepository"], REPOSITORY_URL)
        self.assertEqual(metadata["creator"]["name"], "Stratamize LLC")
        self.assertEqual(metadata["publisher"]["name"], "Stratamize LLC")
        self.assertTrue(metadata["isAccessibleForFree"])
        self.assertEqual(metadata["identifier"], VERSION_ID)
        self.assertIn(VERSION_ID, metadata["sameAs"])
        self.assertIn(PRODUCT_ID, metadata["sameAs"])

    def test_citation_metadata_matches_release(self):
        citation = (ROOT / "CITATION.cff").read_text(encoding="utf-8")

        self.assertRegex(citation, rf'(?m)^title: "{re.escape(TITLE)}"$')
        self.assertRegex(citation, rf"(?m)^version: {re.escape(VERSION)}$")
        self.assertRegex(citation, rf"(?m)^date-released: {re.escape(RELEASE_DATE)}$")
        self.assertIn(f'url: "{CANONICAL_URL}"', citation)
        self.assertIn(f'repository-code: "{REPOSITORY_URL}"', citation)
        self.assertIn(f'    value: "{VERSION_ID}"', citation)
        self.assertRegex(citation, r"(?m)^type: dataset$")
        self.assertRegex(citation, r"(?m)^license: CC-BY-4\.0$")

    def test_notice_declares_stratamize_authorship_and_is_upstream_clean(self):
        notice = (ROOT / "NOTICE.md").read_text(encoding="utf-8")

        self.assertIn("Stratamize LLC", notice)
        self.assertIn(TITLE, notice)
        self.assertIn(CANONICAL_URL, notice)
        self.assertIn("CC BY 4.0", notice)
        self.assertIn("https://creativecommons.org/licenses/by/4.0/", notice)

        lowered = notice.lower()
        for forbidden in (
            # Retired partner name, base64-encoded so the guard does not spell it.
            base64.b64decode("bGlmdGVk").decode(),
            "zenodo",
            "doi.org",
            "kaggle",
            "hugging face",
            "huggingface",
            "software heritage",
            "softwareheritage",
            "payment-processing-resources",
        ):
            self.assertNotIn(forbidden, lowered)

    def test_schema_and_synthetic_example_are_internally_consistent(self):
        schema = json.loads(
            (ROOT / "schema/payment-statement-audit.schema.json").read_text(
                encoding="utf-8"
            )
        )
        example = json.loads(
            (ROOT / "examples/payment-statement-audit-example.json").read_text(
                encoding="utf-8"
            )
        )

        for field in schema["required"]:
            self.assertIn(field, example)
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(schema["title"], TITLE)
        self.assertAlmostEqual(
            example["effective_rate"],
            example["total_processing_fees"] / example["card_volume"],
            places=6,
        )
        self.assertTrue(
            any("synthetic" in note.lower() for note in example["review_notes"])
        )
        self.assertEqual(SCHEMA_VERSION, example["schema_version"])

    def test_checksums_cover_every_declared_release_file(self):
        manifest = json.loads(
            (ROOT / "RELEASE-MANIFEST.json").read_text(encoding="utf-8")
        )
        expected_files = set(manifest["files"]) - {"checksums.txt"}
        checksum_lines = (ROOT / "checksums.txt").read_text(encoding="utf-8").splitlines()
        checksums = {}
        for line in checksum_lines:
            digest, filename = re.split(r"\s+", line.strip(), maxsplit=1)
            checksums[filename] = digest

        self.assertEqual(set(checksums), expected_files)
        for filename, expected_digest in checksums.items():
            actual_digest = hashlib.sha256((ROOT / filename).read_bytes()).hexdigest()
            self.assertEqual(expected_digest, actual_digest)

    def test_release_manifest_covers_every_repository_asset(self):
        manifest = json.loads(
            (ROOT / "RELEASE-MANIFEST.json").read_text(encoding="utf-8")
        )
        if git_metadata_is_available():
            result = subprocess.run(
                [
                    "git",
                    "ls-files",
                    "--cached",
                    "--others",
                    "--exclude-standard",
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
            repository_files = {
                line.replace("\\", "/")
                for line in result.stdout.splitlines()
                if line
            }
        else:
            repository_files = portable_release_inventory()
        self.assertEqual(repository_files, set(manifest["files"]))

    def test_release_files_are_pinned_to_lf_by_git(self):
        manifest = json.loads(
            (ROOT / "RELEASE-MANIFEST.json").read_text(encoding="utf-8")
        )
        release_files = manifest["files"]
        if git_metadata_is_available():
            result = subprocess.run(
                ["git", "check-attr", "eol", "--", *release_files],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )

            observed = {
                line.split(": ", maxsplit=2)[0]: line.split(": ", maxsplit=2)[2]
                for line in result.stdout.splitlines()
            }
            self.assertEqual(observed, {filename: "lf" for filename in release_files})
        else:
            for filename in release_files:
                with self.subTest(filename=filename):
                    self.assertNotIn(b"\r\n", (ROOT / filename).read_bytes())

    def test_readme_presents_the_versioned_release_and_canonical_citation(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        self.assertIn("## Versioned release", readme)
        self.assertIn(f"v{VERSION}", readme)
        self.assertIn("August 6, 2026", readme)
        self.assertIn(CANONICAL_URL, readme)
        self.assertIn("CITATION.cff", readme)
        self.assertIn(VERSION_ID, readme)
        self.assertNotIn("VERSION_ID_PLACEHOLDER", readme)

    def test_ai_summary_exposes_the_persistent_identifier(self):
        llms = (ROOT / "llms.txt").read_text(encoding="utf-8")

        self.assertIn(VERSION_ID, llms)
        self.assertIn(RELEASE_URL, llms)


if __name__ == "__main__":
    unittest.main()
