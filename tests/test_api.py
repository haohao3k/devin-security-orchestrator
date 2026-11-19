import hashlib
import unittest

from fastapi.testclient import TestClient

from devin_guard.api import create_app
from devin_guard.state import StateStore


class APITests(unittest.TestCase):
    def setUp(self):
        self.store = StateStore("sqlite:///:memory:")
        self.store.initialize()
        self.control = "c" * 40
        self.verifier = "v" * 40
        self.client = TestClient(create_app(self.store, self.control, self.verifier, "test-verifier"))
        self.payload = {"repository": "test/repo", "pr_number": 1, "commit_sha": "a" * 40,
                        "context": {"tree_sha": "b" * 40, "environment_digest": "c" * 64,
                                    "policy_version": "v1"},
                        "candidates": [{"cwe": "CWE-79", "path": "app.py", "symbol": "render"}]}

    def tearDown(self):
        self.client.close()
        self.store.close()

    def headers(self, token=None):
        return {"Authorization": "Bearer " + (token or self.control)}

    def test_anonymous_cannot_plan(self):
        self.assertEqual(self.client.post("/v1/runs", json=self.payload).status_code, 401)

    def test_model_cannot_supply_extra_authority(self):
        payload = dict(self.payload, status="dismissed")
        self.assertEqual(self.client.post("/v1/runs", json=payload, headers=self.headers()).status_code, 422)

    def test_controller_cannot_verify(self):
        run = self.client.post("/v1/runs", json=self.payload, headers=self.headers()).json()
        job = run["investigation_ids"][0]
        response = self.client.post(f"/v1/investigations/{job}/verify", headers=self.headers(),
                                    json={"verdict": "dismissed", "evidence": {}})
        self.assertEqual(response.status_code, 401)
        gate = self.client.get(f"/v1/runs/{run['run_id']}/gate", headers=self.headers()).json()
        self.assertEqual(gate["decision"], "blocked")

    def test_verifier_role_is_separate(self):
        response = self.client.post("/v1/runs", json=self.payload, headers=self.headers(self.verifier))
        self.assertEqual(response.status_code, 401)

    def test_rejects_same_or_missing_role_tokens(self):
        with self.assertRaises(ValueError):
            create_app(self.store, self.control, self.control)
        with self.assertRaises(ValueError):
            create_app(self.store, "", self.verifier)

    def test_invalid_path_rejected_at_store_boundary(self):
        self.payload["candidates"][0]["path"] = "../../etc/passwd"
        response = self.client.post("/v1/runs", json=self.payload, headers=self.headers())
        self.assertEqual(response.status_code, 409)
