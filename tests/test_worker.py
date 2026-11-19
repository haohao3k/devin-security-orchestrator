import json
import unittest
from unittest.mock import patch

import httpx

from devin_guard.devin import DevinClient
from devin_guard.state import StateStore
from devin_guard.worker import Worker, build_analysis_prompt


def analysis(verdict="candidate", *, unresolved=None):
    return {
        "verdict": verdict, "summary": "Scoped static trace; requires verification.",
        "locations": [{"path": "src/api.py", "line": 12, "reason": "Input reaches this call."}],
        "evidence": [{"kind": "static_trace", "detail": "Reviewed source, checks, and sink."}],
        "unresolved_paths": unresolved or [],
    }


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.now = 1800000000.0
        self.clock = lambda: self.now
        self.time_patch = patch("devin_guard.state.time.time", self.clock)
        self.time_patch.start()
        self.addCleanup(self.time_patch.stop)
        self.store = StateStore("sqlite:///:memory:")
        self.store.initialize()
        self.addCleanup(self.store.close)
        run = self.store.plan_run(
            "owner/repo", 21, "a" * 40,
            [{"cwe": "CWE-89", "path": "src/api.py", "symbol": "query", "source": "request", "sink": "database", "description": "Investigate query construction."}],
            {"tree_sha": "b" * 40, "environment_digest": "c" * 64, "policy_version": "policy-v1"},
            "trace-v1",
        )
        self.job_id = run["investigation_ids"][0]
        self.calls = []

    def worker(self, handler, **kwargs):
        def track(request):
            self.calls.append(request)
            return handler(request)

        client = DevinClient("org-test", "cog_mock_only", transport=httpx.MockTransport(track))
        self.addCleanup(client.close)
        return Worker(self.store, client, "worker-test", clock=self.clock, **kwargs)

    @staticmethod
    def response(status="running", detail="working", output=None):
        return httpx.Response(200, json={
            "session_id": "devin-one", "status": status, "status_detail": detail,
            "structured_output": output, "acus_consumed": 0.25,
        })

    def test_checkpoint_release_restart_reuses_session_and_fixed_deadline(self):
        worker = self.worker(lambda request: self.response(output=analysis()), wall_clock_seconds=90, poll_interval=10)
        with patch("time.sleep", side_effect=AssertionError("run_once must not sleep")):
            first = worker.run_once()
        self.assertEqual([r.method for r in self.calls], ["POST", "GET"])
        self.assertEqual(first["status"], "running")
        self.assertEqual(first["deadline_at"], self.now + 90)
        self.assertIsNone(first["lease_token"])
        self.assertEqual(first["next_poll_at"], self.now + 10)
        self.assertEqual(first["result"]["analysis"]["verdict"], "candidate")
        self.assertEqual(first["result"]["verification_status"], "unverified")
        self.assertIsNone(worker.run_once())
        self.now += 10
        replacement = self.worker(lambda request: self.response(detail="finished", output=analysis()))
        second = replacement.run_once()
        self.assertEqual([r.method for r in self.calls], ["POST", "GET", "GET"])
        self.assertEqual(second["status"], "needs_review")
        self.assertEqual(second["deadline_at"], first["deadline_at"])
        self.assertEqual(second["attempt"], 1)
        self.assertEqual(second["session_id"], "devin-one")
        self.assertIsNone(second["verification"])

    def test_no_finding_still_requires_independent_review(self):
        worker = self.worker(lambda request: self.response(detail="finished", output=analysis("no_finding")))
        result = worker.run_once()
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(result["result"]["verification_status"], "unverified")
        self.assertIsNone(result["verified_by"])

    def test_suspended_budget_is_incomplete_even_with_negative_output(self):
        worker = self.worker(lambda request: self.response("suspended", "usage_limit_exceeded", analysis("no_finding")))
        result = worker.run_once()
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["result"]["reason"], "provider_stopped_without_completion")

    def test_deadline_terminates_without_polling_or_extending_budget(self):
        worker = self.worker(lambda request: self.response(), wall_clock_seconds=30, poll_interval=10)
        first = worker.run_once()
        self.now += 31
        result = worker.run_once()
        self.assertEqual(result["deadline_at"], first["deadline_at"])
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["result"]["reason"], "wall_clock_deadline")
        self.assertEqual(result["result"]["termination_request"], "accepted")
        self.assertEqual([r.method for r in self.calls], ["POST", "GET", "DELETE"])

    def test_failed_termination_never_turns_timeout_into_success(self):
        def handler(request):
            return httpx.Response(503) if request.method == "DELETE" else self.response()

        worker = self.worker(handler, wall_clock_seconds=10)
        worker.run_once()
        self.now += 11
        result = worker.run_once()
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["result"]["termination_request"], "failed_or_unknown")

    def test_create_timeout_is_quarantined_without_repeat_post(self):
        def handler(request):
            raise httpx.ReadTimeout("may be accepted", request=request)

        worker = self.worker(handler)
        result = worker.run_once()
        self.assertEqual(result["status"], "dispatch_unknown")
        self.now += 1000
        self.assertIsNone(worker.run_once())
        self.assertEqual([r.method for r in self.calls], ["POST"])

    def test_transient_poll_failure_is_retried_without_resubmitting(self):
        failed = False

        def handler(request):
            nonlocal failed
            if request.method == "GET" and not failed:
                failed = True
                raise httpx.ReadTimeout("temporary", request=request)
            return self.response(detail="finished", output=analysis())

        worker = self.worker(handler)
        first = worker.run_once()
        self.assertEqual(first["status"], "running")
        self.assertIn("poll_error", first["result"])
        self.now += 10
        self.assertEqual(worker.run_once()["status"], "needs_review")
        self.assertEqual([r.method for r in self.calls], ["POST", "GET", "GET"])

    def test_invalid_nonfinal_output_does_not_end_job_but_invalid_final_does(self):
        worker = self.worker(lambda request: self.response(output={"broken": True}))
        first = worker.run_once()
        self.assertEqual(first["status"], "running")
        self.assertFalse(first["result"]["structured_output_valid"])
        self.now += 10
        final = self.worker(lambda request: self.response(detail="finished", output={"broken": True})).run_once()
        self.assertEqual(final["status"], "incomplete")
        self.assertEqual(final["result"]["reason"], "invalid_final_structured_output")

    def test_unresolved_context_prevents_completed_negative(self):
        worker = self.worker(lambda request: self.response(detail="finished", output=analysis("no_finding", unresolved=["src/dynamic.py"])))
        result = worker.run_once()
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["result"]["analysis"]["unresolved_paths"], ["src/dynamic.py"])

    def test_waiting_for_approval_is_not_silently_bypassed(self):
        worker = self.worker(lambda request: self.response(detail="waiting_for_approval"))
        result = worker.run_once()
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["result"]["reason"], "provider_requires_input_or_approval")
        self.assertEqual([r.method for r in self.calls], ["POST", "GET", "DELETE"])

    def test_dispatch_crash_gap_never_replays_create(self):
        job = self.store.claim("crashed-worker", now=self.now)
        self.store.begin_dispatch(job["id"], job["lease_token"], self.now + 900)
        self.now += 61
        worker = self.worker(lambda request: self.fail("must not send provider request"))
        self.assertIsNone(worker.run_once())
        self.assertEqual(self.store.get_investigation(self.job_id)["status"], "dispatch_unknown")
        self.assertEqual(self.calls, [])

    def test_late_create_response_after_lease_loss_requests_termination(self):
        def handler(request):
            if request.method == "POST":
                self.now += 121
            return self.response()

        worker = self.worker(handler)
        self.assertEqual(worker.run_once()["status"], "lease_lost")
        self.assertEqual([r.method for r in self.calls], ["POST", "DELETE"])
        self.assertIsNone(worker.run_once())
        self.assertEqual(self.store.get_investigation(self.job_id)["status"], "dispatch_unknown")

    def test_prompt_binds_commit_and_keeps_agent_out_of_verification(self):
        job = self.store.get_investigation(self.job_id)
        prompt = build_analysis_prompt(job)
        self.assertIn(job["commit_sha"], prompt)
        self.assertIn(job["context"]["tree_sha"], prompt)
        self.assertIn("Never invent a CVE", prompt)
        self.assertIn("Do not modify source or tests", prompt)
        self.assertIn("untrusted evidence", prompt)
        self.assertIn("Runtime validation is performed by a separately controlled verifier", prompt)
        # The create body also binds a single repo and uses a stable identifier.
        worker = self.worker(lambda request: self.response())
        worker.run_once()
        payload = json.loads(self.calls[0].content)
        self.assertEqual(payload["repos"], ["owner/repo"])
        self.assertIn("job:" + self.job_id, payload["tags"])


if __name__ == "__main__":
    unittest.main()
