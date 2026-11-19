"""Independent regression cases found during pre-publication review."""

import copy
import time
import unittest

import httpx
from fastapi.testclient import TestClient

from devin_guard.api import create_app
from devin_guard.devin import DevinClient
from devin_guard.state import StateStore
from devin_guard.worker import Worker


class ReviewRegressionTests(unittest.TestCase):
    def setUp(self):
        self.store = StateStore("sqlite:///:memory:")
        self.store.initialize()
        self.control = "c" * 40
        self.verifier = "v" * 40
        self.client = TestClient(
            create_app(self.store, self.control, self.verifier),
            raise_server_exceptions=False,
        )
        self.plan = {
            "repository": "example/service",
            "pr_number": 1,
            "commit_sha": "a" * 40,
            "context": {
                "tree_sha": "b" * 40,
                "environment_digest": "c" * 64,
                "policy_version": "review-v1",
            },
            "candidates": [{
                "cwe": "CWE-79", "path": "app.py", "symbol": "render_profile",
                "description": "Check whether the display_name field is escaped.",
            }],
        }

    def tearDown(self):
        self.client.close()
        self.store.close()

    def test_run_response_redacts_nested_worker_lease_tokens(self):
        run = self.store.plan_run(**self.plan)
        claimed = self.store.claim("private-worker")
        response = self.client.get(
            f"/v1/runs/{run['run_id']}",
            headers={"Authorization": "Bearer " + self.control},
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("lease_token", response.json()["investigations"][0])
        self.assertNotIn(claimed["lease_token"], response.text)

    def test_changed_hypothesis_does_not_reuse_dismissed_other_hypothesis(self):
        original = self.store.plan_run(**self.plan)
        claimed = self.store.claim("worker")
        self.store.begin_dispatch(claimed["id"], claimed["lease_token"], time.time() + 60)
        self.store.attach_session(claimed["id"], claimed["lease_token"], "devin-test")
        self.store.finish(
            claimed["id"], claimed["lease_token"], "needs_review",
            {"summary": "The display_name field is escaped; no claim about bio."},
        )
        job = self.store.get_investigation(claimed["id"])
        receipt = {
            "commit_sha": job["commit_sha"], "context_digest": job["context_digest"],
            "artifact_sha256": "d" * 64, "method": "independent-test-fixture",
        }
        self.store.verify(job["id"], "dismissed", receipt, "test-reviewer")
        next_plan = copy.deepcopy(self.plan)
        next_plan["pr_number"] = 2
        next_plan["candidates"][0]["description"] = "Check whether the bio field is escaped."
        newer = self.store.plan_run(**next_plan)
        self.assertNotEqual(original["investigation_ids"], newer["investigation_ids"])
        self.assertEqual(self.store.gate(newer["run_id"])["decision"], "blocked")

    def test_unknown_running_detail_stops_remote_job_before_abandoning_it(self):
        calls = []

        def provider(request):
            calls.append(request.method)
            if request.method == "DELETE":
                return httpx.Response(204)
            return httpx.Response(200, json={
                "session_id": "devin-test",
                "status": "running",
                "status_detail": "new_unrecognized_provider_activity",
            })

        self.store.plan_run(**self.plan)
        with DevinClient("org-test", "test-key", transport=httpx.MockTransport(provider),
                         timeout_seconds=1) as devin:
            worker = Worker(self.store, devin, "review-worker", wall_clock_seconds=30,
                            poll_interval=1, lease_seconds=10)
            result = worker.run_once()
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(calls.count("POST"), 1)
        self.assertIn("DELETE", calls)

    def test_malformed_non_ascii_authorization_is_unauthorized_not_server_error(self):
        response = self.client.post(
            "/v1/runs", json=self.plan,
            headers=[(b"authorization", b"Bearer \xff")],
        )
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
