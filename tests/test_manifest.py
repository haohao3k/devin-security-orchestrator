import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from devin_guard.manifest import check_candidate_paths, snapshot


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name)
        self.git("init", "-q")
        self.git("config", "user.name", "Fixture User")
        self.git("config", "user.email", "fixture@example.invalid")
        (self.path / "app.py").write_text("print('fixture')\n")
        self.git("add", "app.py")
        self.git("commit", "-qm", "fixture")

    def tearDown(self):
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.path), *args], check=True,
                              capture_output=True, text=True).stdout.strip()

    def test_pins_commit_not_dirty_working_tree(self):
        first = snapshot(self.path, "HEAD", {"runtime": "fixture-v1"})
        (self.path / "app.py").write_text("changed but not committed\n")
        self.assertEqual(first, snapshot(self.path, "HEAD", {"runtime": "fixture-v1"}))
        self.git("add", "app.py")
        self.git("commit", "-qm", "changed")
        second = snapshot(self.path, "HEAD", {"runtime": "fixture-v1"})
        self.assertNotEqual(first["context"]["tree_sha"], second["context"]["tree_sha"])

    def test_environment_is_part_of_context(self):
        a = snapshot(self.path, "HEAD", {"runtime": "v1"})
        b = snapshot(self.path, "HEAD", {"runtime": "v2"})
        self.assertNotEqual(a["context"]["environment_digest"], b["context"]["environment_digest"])

    def test_rejects_option_and_empty_environment(self):
        with self.assertRaises(ValueError):
            snapshot(self.path, "--help", {"runtime": "fixture"})
        with self.assertRaises(ValueError):
            snapshot(self.path, "HEAD", {})

    def test_candidate_must_exist_in_snapshot(self):
        commit = self.git("rev-parse", "HEAD")
        check_candidate_paths(self.path, commit, [{"path": "app.py"}])
        for path in ("../secret", "/etc/passwd", "missing.py"):
            with self.assertRaises(ValueError):
                check_candidate_paths(self.path, commit, [{"path": path}])
