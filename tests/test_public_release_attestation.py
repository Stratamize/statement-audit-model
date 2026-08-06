import hashlib
import importlib.util
import io
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ATTESTATION_PATH = ROOT / "tools/public_release_attestation.py"
TITLE = "Stratamize Statement Audit Model"
CANONICAL_URL = "https://stratamize.com/statement-audit/"
SOURCE_REPOSITORY = "https://github.com/Stratamize/statement-audit-model"
PRODUCT_ID = "https://stratamize.com/statement-audit"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FakeTransport:
    def __init__(self, *, json_values, byte_values):
        self.json_values = json_values
        self.byte_values = byte_values

    def get_json(self, url, *, max_bytes):
        del max_bytes
        return self.json_values[url]

    def get_bytes(self, url, *, max_bytes):
        value = self.byte_values[url]
        if len(value) > max_bytes:
            raise ValueError("response_too_large")
        return value


class PublicReleaseAttestationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not ATTESTATION_PATH.is_file():
            raise AssertionError("tools/public_release_attestation.py is required")
        cls.attestation = load_module(ATTESTATION_PATH, "public_release_attestation")

    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        (self.root / "README.md").write_text("verified release\n", encoding="utf-8")
        self.manifest = {
            "title": TITLE,
            "version": "1.1.0",
            "release_date": "2026-08-06",
            "version_id": f"{PRODUCT_ID}/releases/1.1.0",
            "product_id": PRODUCT_ID,
            "canonical_url": CANONICAL_URL,
            "source_release": f"{SOURCE_REPOSITORY}/releases/tag/v1.1.0",
            "license": "CC-BY-4.0",
            "files": ["README.md"],
        }

    def tearDown(self):
        self.temporary_directory.cleanup()

    def make_zip(self, members=None):
        members = members or {"README.md": (self.root / "README.md").read_bytes()}
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, value in members.items():
                archive.writestr(f"stratamize-statement-audit-1.1.0/{name}", value)
        return output.getvalue()

    def make_transport(self, archive=None):
        archive = archive or self.make_zip()
        digest = hashlib.sha256(archive).hexdigest()
        zip_name = "stratamize-statement-audit-model-v1.1.0.zip"
        sidecar_name = "release-archive.sha256"
        github_zip = (
            f"https://github.com/Stratamize/statement-audit-model/"
            f"releases/download/v1.1.0/{zip_name}"
        )
        github_sidecar = (
            "https://github.com/Stratamize/statement-audit-model/"
            f"releases/download/v1.1.0/{sidecar_name}"
        )
        sidecar = f"{digest}  {zip_name}\n".encode()
        github = {
            "tag_name": "v1.1.0",
            "draft": False,
            "prerelease": False,
            "html_url": self.manifest["source_release"],
            "assets": [
                {
                    "name": zip_name,
                    "size": len(archive),
                    "digest": f"sha256:{digest}",
                    "browser_download_url": github_zip,
                },
                {
                    "name": sidecar_name,
                    "size": len(sidecar),
                    "digest": f"sha256:{hashlib.sha256(sidecar).hexdigest()}",
                    "browser_download_url": github_sidecar,
                },
            ],
        }
        expected_commit = "b" * 40
        transport = FakeTransport(
            json_values={
                "https://api.github.com/repos/Stratamize/statement-audit-model/releases/tags/v1.1.0": github,
            },
            byte_values={
                github_zip: archive,
                github_sidecar: sidecar,
            },
        )
        return transport, digest, expected_commit

    def test_matching_github_artifacts_verify(self):
        transport, digest, expected_commit = self.make_transport()

        result = self.attestation.attest_public_release(
            self.root,
            self.manifest,
            transport=transport,
            expected_commit=expected_commit,
        )

        self.assertTrue(result.verified, result.failure_codes)
        self.assertEqual((), result.failure_codes)
        self.assertEqual(digest, result.archive_sha256)
        self.assertEqual(self.manifest["source_release"], result.github_release_url)

    def test_digest_mismatch_blocks_attestation(self):
        transport, _, expected_commit = self.make_transport()
        github_url = next(
            url for url in transport.byte_values if url.startswith("https://github.com")
            and url.endswith(".zip")
        )
        transport.byte_values[github_url] += b"tampered"

        result = self.attestation.attest_public_release(
            self.root,
            self.manifest,
            transport=transport,
            expected_commit=expected_commit,
        )

        self.assertFalse(result.verified)
        self.assertIn("github_archive_digest_mismatch", result.failure_codes)

    def test_manifest_identity_drift_blocks_before_any_request(self):
        transport, _, expected_commit = self.make_transport()
        drifted = dict(self.manifest)
        drifted["version_id"] = f"{PRODUCT_ID}/releases/9.9.9"

        result = self.attestation.attest_public_release(
            self.root,
            drifted,
            transport=transport,
            expected_commit=expected_commit,
        )

        self.assertFalse(result.verified)
        self.assertEqual(("manifest_identity_invalid",), result.failure_codes)

    def test_zip_traversal_and_duplicate_aliases_are_rejected(self):
        cases = {
            "traversal": {
                "README.md": b"verified release\n",
                "../outside.txt": b"outside",
            },
            "case_alias": {
                "README.md": b"verified release\n",
                "readme.md": b"alias",
            },
        }
        for name, members in cases.items():
            with self.subTest(name=name):
                archive = self.make_zip(members)
                transport, _, expected_commit = self.make_transport(archive)
                result = self.attestation.attest_public_release(
                    self.root,
                    self.manifest,
                    transport=transport,
                    expected_commit=expected_commit,
                )
                self.assertFalse(result.verified)
                self.assertIn("release_archive_invalid", result.failure_codes)

    def test_http_transport_rejects_untrusted_or_insecure_hosts_before_request(self):
        transport = self.attestation.HttpTransport()
        for url in (
            "http://github.com/Stratamize/example",
            "https://github.com.evil.invalid/payload",
            "https://evil.invalid/payload",
        ):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    transport.get_bytes(url, max_bytes=1024)


if __name__ == "__main__":
    unittest.main()
