import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from devin_guard.cli import main
from devin_guard.demo import run_demo
from devin_guard.state import StateStore


class CLITests(unittest.TestCase):
    def test_demo_uses_real_persistence_but_no_live_provider(self):
        result = run_demo()
        self.assertEqual(result["mode"], "offline_simulation")
        self.assertEqual(result["live_devin_calls"], 0)
        self.assertEqual(result["mock_http_requests"], ["POST", "GET"])
        self.assertTrue(result["same_context_reuses_investigation_after_db_reopen"])
        self.assertTrue(result["changed_tree_creates_new_investigation"])
        self.assertEqual(result["gate_before_independent_receipt"], "blocked")
        self.assertEqual(result["changed_tree_gate"], "blocked")
        self.assertFalse(result["release_authorized"])

    def test_gate_exits_nonzero_for_empty_unassessed_scope(self):
        with tempfile.TemporaryDirectory() as temp:
            url = "sqlite:///" + str(Path(temp) / "state.db")
            store = StateStore(url)
            store.initialize()
            run = store.plan_run("test/repo", 1, "a" * 40, [],
                                 {"tree_sha": "b" * 40, "environment_digest": "c" * 64,
                                  "policy_version": "v1"})
            store.close()
            with contextlib.redirect_stdout(io.StringIO()) as output:
                code = main(["--db", url, "gate", run["run_id"]])
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(output.getvalue())["decision"], "blocked")

    def test_score_command_is_wired(self):
        root = Path(__file__).resolve().parent.parent
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = main(["score", "--labels", str(root / "examples/evaluation/toy-labels.jsonl"),
                         "--predictions", str(root / "examples/evaluation/toy-predictions.jsonl")])
        self.assertEqual(code, 0)
        self.assertIn("recall", json.loads(output.getvalue()))
