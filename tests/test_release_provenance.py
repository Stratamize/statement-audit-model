import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROVENANCE_PATH = ROOT / "tools/release_provenance.py"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def run_git(cwd: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


class RepositoryProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not PROVENANCE_PATH.is_file():
            raise AssertionError("tools/release_provenance.py is required")
        cls.provenance = load_module(PROVENANCE_PATH, "release_provenance")

    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary_directory.name)

    def tearDown(self):
        self.temporary_directory.cleanup()

    def create_remote(self) -> Path:
        remote = self.base / "remote.git"
        seed = self.base / "seed"
        run_git(self.base, "init", "--bare", str(remote))
        run_git(remote, "symbolic-ref", "HEAD", "refs/heads/main")
        run_git(self.base, "init", "-b", "main", str(seed))
        run_git(seed, "config", "user.name", "Release Test")
        run_git(seed, "config", "user.email", "release-test@example.invalid")
        run_git(seed, "config", "core.autocrlf", "false")
        (seed / "README.md").write_text("release\n", encoding="utf-8")
        run_git(seed, "add", "README.md")
        run_git(seed, "commit", "-m", "initial release")
        run_git(seed, "tag", "-a", "v1.1.2", "-m", "v1.1.2")
        run_git(seed, "remote", "add", "origin", str(remote))
        run_git(seed, "push", "-u", "origin", "main")
        run_git(seed, "push", "origin", "v1.1.2")
        return remote

    def clone_remote(self, remote: Path, *, no_tags: bool = False) -> Path:
        clone = self.base / ("clone-no-tags" if no_tags else "clone")
        args = ["-c", "core.autocrlf=false", "clone"]
        if no_tags:
            args.append("--no-tags")
        args.extend([str(remote), str(clone)])
        run_git(self.base, *args)
        run_git(clone, "config", "user.name", "Release Test")
        run_git(clone, "config", "user.email", "release-test@example.invalid")
        run_git(clone, "config", "core.autocrlf", "false")
        return clone

    def inspect(self, root: Path, version: str, remote: Path):
        return self.provenance.inspect_repository(
            root,
            version,
            files=("README.md",),
            expected_origin=str(remote.resolve()),
        )

    def test_tagless_release_cannot_be_publication_ready(self):
        candidate = self.base / "release"
        candidate.mkdir()
        (candidate / "README.md").write_text("altered release\n", encoding="utf-8")

        result = self.provenance.inspect_repository(
            candidate,
            "1.1.2",
            files=("README.md",),
            expected_origin="https://github.com/Stratamize/statement-audit-model",
        )

        self.assertFalse(result.publication_ready)
        self.assertIn("git_metadata_missing", result.failure_codes)

    def test_existing_remote_tag_missing_locally_is_not_treated_as_new(self):
        remote = self.create_remote()
        clone = self.clone_remote(remote, no_tags=True)

        result = self.inspect(clone, "1.1.2", remote)

        self.assertFalse(result.publication_ready)
        self.assertIn("local_release_tag_missing", result.failure_codes)

    def test_dirty_tracked_candidate_is_blocked(self):
        remote = self.create_remote()
        clone = self.clone_remote(remote)
        (clone / "README.md").write_text("dirty\n", encoding="utf-8")

        result = self.inspect(clone, "1.1.2", remote)

        self.assertFalse(result.publication_ready)
        self.assertIn("working_tree_dirty", result.failure_codes)

    def test_untracked_candidate_asset_is_blocked(self):
        remote = self.create_remote()
        clone = self.clone_remote(remote)
        (clone / "undeclared.txt").write_text("untracked\n", encoding="utf-8")

        result = self.inspect(clone, "1.1.2", remote)

        self.assertFalse(result.publication_ready)
        self.assertIn("working_tree_dirty", result.failure_codes)

    def test_local_and_remote_release_tag_mismatch_is_blocked(self):
        remote = self.create_remote()
        clone = self.clone_remote(remote)
        (clone / "README.md").write_text("second commit\n", encoding="utf-8")
        run_git(clone, "add", "README.md")
        run_git(clone, "commit", "-m", "second commit")
        run_git(clone, "tag", "-f", "v1.1.2")

        result = self.inspect(clone, "1.1.2", remote)

        self.assertFalse(result.publication_ready)
        self.assertIn("remote_tag_mismatch", result.failure_codes)

    def test_lower_untagged_version_is_blocked_by_highest_remote_release(self):
        remote = self.create_remote()
        clone = self.clone_remote(remote, no_tags=True)

        result = self.inspect(clone, "1.1.1", remote)

        self.assertFalse(result.publication_ready)
        self.assertIn("version_not_monotonic", result.failure_codes)

    def test_newer_untagged_version_can_pass_repository_provenance(self):
        remote = self.create_remote()
        clone = self.clone_remote(remote, no_tags=True)

        result = self.inspect(clone, "1.1.3", remote)

        self.assertTrue(result.publication_ready, result.failure_codes)
        self.assertEqual("new", result.release_state)
        self.assertEqual((), result.failure_codes)

    def test_untrusted_origin_is_blocked(self):
        remote = self.create_remote()
        clone = self.clone_remote(remote)

        result = self.provenance.inspect_repository(
            clone,
            "1.1.2",
            files=("README.md",),
            expected_origin="https://github.com/Stratamize/statement-audit-model",
        )

        self.assertFalse(result.publication_ready)
        self.assertIn("origin_untrusted", result.failure_codes)

    def test_exact_annotated_release_tag_and_clean_tree_pass(self):
        remote = self.create_remote()
        clone = self.clone_remote(remote)

        result = self.inspect(clone, "1.1.2", remote)

        self.assertTrue(result.publication_ready, result.failure_codes)
        self.assertEqual("tagged", result.release_state)
        self.assertRegex(result.head_commit or "", r"^[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
