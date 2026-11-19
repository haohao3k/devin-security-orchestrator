"""Behavioral state-machine tests; optional PostgreSQL parity via TEST_POSTGRES_URL."""
from __future__ import annotations

import copy
import hashlib
import os
import tempfile
import threading
import time
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from devin_guard.state import LeaseConflict, NotFoundError, StateError, StateStore, TransitionError


CANDIDATE = {
    "cwe": "CWE-89", "path": "service/query.py", "symbol": "lookup",
    "source": "request.query", "sink": "db.execute", "description": "Review parameterization",
}
CONTEXT = {"tree_sha": "a" * 40, "environment_digest": "b" * 64, "policy_version": "policy-v1"}


def postgres_schema_url(database_url: str, schema: str) -> str:
    parts = urlsplit(database_url)
    query = [(key, value) for key, value in parse_qsl(parts.query) if key != "options"]
    query.append(("options", "-c search_path=" + schema))
    # libpq URIs use percent escapes, not HTML form encoding: a literal '+' is
    # not decoded into a space and would become the option '+search_path'.
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(query, quote_via=quote), parts.fragment))


class PostgreSQLURLTests(unittest.TestCase):
    def test_schema_options_are_decoded_correctly_by_libpq_without_a_server(self):
        try:
            from psycopg.conninfo import conninfo_to_dict
        except ImportError:
            self.skipTest("install psycopg to exercise its real libpq URI parser")
        url = postgres_schema_url(
            "postgresql://tester:placeholder@localhost/testdb?connect_timeout=3&options=obsolete",
            "guard_test_regression",
        )
        params = conninfo_to_dict(url)
        self.assertEqual(params["options"], "-c search_path=guard_test_regression")
        self.assertEqual(params["connect_timeout"], "3")


class StoreBehavior:
    def plan(self, **changes):
        args = dict(repository="example/service", pr_number=1, commit_sha="c" * 40,
                    candidates=[copy.deepcopy(CANDIDATE)], context=copy.deepcopy(CONTEXT))
        args.update(changes)
        return self.store.plan_run(**args)

    def running(self):
        plan = self.plan()
        job = self.store.claim("worker-a")
        self.store.begin_dispatch(job["id"], job["lease_token"], time.time() + 300)
        self.store.attach_session(job["id"], job["lease_token"], "devin-test-session")
        return plan, self.store.get_investigation(job["id"])

    def reviewed(self):
        plan, job = self.running()
        self.store.finish(job["id"], job["lease_token"], "needs_review", {"verdict": "no_finding"})
        return plan, self.store.get_investigation(job["id"])

    def receipt(self, job):
        return {"commit_sha": job["commit_sha"], "context_digest": job["context_digest"],
                "artifact_sha256": hashlib.sha256(b"independent fixture evidence").hexdigest(),
                "method": "test-fixture-only"}

    def test_identity_is_stable_across_prs_and_commits_with_identical_tree(self):
        first = self.plan()
        second = self.plan(pr_number=99, commit_sha="d" * 40)
        self.assertEqual(first["investigation_ids"], second["investigation_ids"])
        self.assertEqual(second["reused"], 1)
        self.assertEqual(self.store.get_run(second["run_id"])["commit_sha"], "d" * 40)
        self.assertEqual(self.store.get_investigation(first["investigation_ids"][0])["commit_sha"], "c" * 40)

    def test_code_environment_policy_and_analyzer_changes_invalidate_cache(self):
        first = self.plan()
        changed = []
        for key, value in (("tree_sha", "e" * 40), ("environment_digest", "f" * 64), ("policy_version", "policy-v2")):
            context = dict(CONTEXT, **{key: value})
            changed.append(self.plan(context=context))
        changed.append(self.plan(analysis_version="trace-v2"))
        original = self.store.get_investigation(first["investigation_ids"][0])
        for item in changed:
            self.assertNotEqual(first["investigation_ids"], item["investigation_ids"])
            other = self.store.get_investigation(item["investigation_ids"][0])
            self.assertEqual(original["fingerprint"], other["fingerprint"])
            self.assertNotEqual(original["context_digest"], other["context_digest"])

    def test_duplicate_seeds_create_one_job(self):
        plan = self.plan(candidates=[CANDIDATE, CANDIDATE])
        self.assertEqual(len(plan["investigation_ids"]), 1)
        self.assertEqual(len(self.store.get_run(plan["run_id"])["investigations"]), 1)

    def test_new_hypothesis_does_not_inherit_previous_dismissal(self):
        _, job = self.reviewed()
        self.store.verify(job["id"], "dismissed", self.receipt(job), "independent-ci")
        changed = dict(CANDIDATE, description="Review a different input and authorization assumption")
        second = self.plan(pr_number=2, candidates=[changed])
        fresh = self.store.get_investigation(second["investigation_ids"][0])
        self.assertEqual(fresh["fingerprint"], job["fingerprint"])
        self.assertNotEqual(fresh["context_digest"], job["context_digest"])
        self.assertEqual(second["reused"], 0)
        self.assertEqual(self.store.gate(second["run_id"])["decision"], "blocked")

    def test_claim_is_atomic_between_independent_connections(self):
        self.plan()
        other = StateStore(self.url)
        other.initialize()
        barrier = threading.Barrier(2)
        def claim(store):
            barrier.wait()
            return store.claim("concurrent-worker")
        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(claim, (self.store, other)))
            self.assertEqual(sum(result is not None for result in results), 1)
        finally:
            other.close()

    def test_live_lease_cannot_be_claimed_twice_even_with_same_worker_id(self):
        self.plan()
        job = self.store.claim("worker")
        self.assertIsNotNone(job)
        self.assertIsNone(self.store.claim("worker"))

    def test_session_cap_is_atomic_between_independent_connections(self):
        self.plan(candidates=[CANDIDATE, dict(CANDIDATE, symbol="another_lookup")])
        self.store.close()
        self.store = StateStore(self.url, max_active_sessions=1)
        other = StateStore(self.url, max_active_sessions=1)
        barrier = threading.Barrier(2)
        def claim(store):
            barrier.wait()
            return store.claim("concurrent-worker")
        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(claim, (self.store, other)))
            self.assertEqual(sum(result is not None for result in results), 1)
        finally:
            other.close()

    def test_running_session_can_be_polled_when_cap_is_full(self):
        self.store.close()
        self.store = StateStore(self.url, max_active_sessions=1)
        self.plan(candidates=[CANDIDATE, dict(CANDIDATE, symbol="another_lookup")])
        job = self.store.claim("worker-a")
        self.store.begin_dispatch(job["id"], job["lease_token"], time.time() + 300)
        self.store.attach_session(job["id"], job["lease_token"], "devin-existing")
        self.assertIsNone(self.store.claim("worker-b"))
        self.store.release(job["id"], job["lease_token"], delay_seconds=0)
        polled = self.store.claim("worker-b")
        self.assertEqual(polled["id"], job["id"])
        self.assertEqual(polled["session_id"], "devin-existing")
        self.assertEqual(polled["attempt"], 1)

    def test_ambiguous_dispatch_retains_admission_slot(self):
        self.store.close()
        self.store = StateStore(self.url, max_active_sessions=1)
        self.plan(candidates=[CANDIDATE, dict(CANDIDATE, symbol="another_lookup")])
        job = self.store.claim("worker-a")
        self.store.begin_dispatch(job["id"], job["lease_token"], time.time() + 300)
        self.assertIsNone(self.store.claim("worker-b", now=job["lease_until"] + 1))
        self.assertEqual(self.store.get_investigation(job["id"])["status"], "dispatch_unknown")

    def test_accepted_termination_requires_reconciliation_before_retry(self):
        _, job = self.running()
        self.store.finish(job["id"], job["lease_token"], "incomplete",
                          {"reason": "wall_clock_deadline", "termination_request": "accepted"})
        with self.assertRaisesRegex(TransitionError, "termination is unconfirmed"):
            self.store.retry(job["id"])

    def test_uncertain_termination_retains_admission_slot(self):
        self.store.close()
        self.store = StateStore(self.url, max_active_sessions=1)
        self.plan(candidates=[CANDIDATE, dict(CANDIDATE, symbol="another_lookup")])
        job = self.store.claim("worker-a")
        self.store.begin_dispatch(job["id"], job["lease_token"], time.time() + 300)
        self.store.attach_session(job["id"], job["lease_token"], "devin-uncertain")
        self.store.finish(job["id"], job["lease_token"], "incomplete",
                          {"reason": "wall_clock_deadline", "termination_request": "failed_or_unknown"})
        with self.assertRaises(TransitionError):
            self.store.retry(job["id"])
        self.assertIsNone(self.store.claim("worker-b"))

    def test_expired_claim_is_fenced_and_reclaimed_without_dispatch(self):
        self.plan()
        start = time.time()
        first = self.store.claim("worker-a", lease_seconds=60, now=start)
        second = self.store.claim("worker-b", lease_seconds=60, now=start + 61)
        self.assertEqual(first["id"], second["id"])
        self.assertNotEqual(first["lease_token"], second["lease_token"])
        self.assertEqual(second["attempt"], 1)
        with self.assertRaises(LeaseConflict):
            self.store.begin_dispatch(first["id"], first["lease_token"], time.time() + 300)

    def test_crash_during_dispatch_is_ambiguous_and_never_reposted(self):
        self.plan()
        job = self.store.claim("worker-a")
        self.store.begin_dispatch(job["id"], job["lease_token"], time.time() + 300)
        self.assertIsNone(self.store.claim("worker-b", now=job["lease_until"] + 1))
        self.assertEqual(self.store.get_investigation(job["id"])["status"], "dispatch_unknown")
        with self.assertRaises(LeaseConflict):
            self.store.attach_session(job["id"], job["lease_token"], "orphan-session")
        with self.assertRaises(TransitionError):
            self.store.retry(job["id"])

    def test_running_job_recovers_original_session_and_deadline(self):
        _, job = self.running()
        recovered = self.store.claim("worker-b", now=job["lease_until"] + 1)
        self.assertEqual(recovered["session_id"], job["session_id"])
        self.assertEqual(recovered["deadline_at"], job["deadline_at"])
        self.assertEqual(recovered["attempt"], job["attempt"])
        with self.assertRaises(LeaseConflict):
            self.store.finish(job["id"], job["lease_token"], "needs_review", {"verdict": "no_finding"})

    def test_release_defers_poll_without_losing_session(self):
        _, job = self.running()
        now = time.time()
        self.store.release(job["id"], job["lease_token"], delay_seconds=10, now=now)
        self.assertIsNone(self.store.claim("worker-b", now=now + 9))
        resumed = self.store.claim("worker-b", now=now + 11)
        self.assertEqual(resumed["session_id"], job["session_id"])
        self.assertEqual(resumed["attempt"], 1)
        with self.assertRaises(LeaseConflict):
            self.store.heartbeat(job["id"], job["lease_token"])

    def test_checkpoint_survives_connection_restart_and_is_not_verified(self):
        plan, job = self.running()
        self.store.checkpoint(job["id"], job["lease_token"], {"checked": ["query.lookup"], "remaining": ["auth.scope"]})
        self.store.release(job["id"], job["lease_token"], delay_seconds=0)
        self.store.close()
        self.store = StateStore(self.url)
        self.store.initialize()
        saved = self.store.get_investigation(job["id"])
        self.assertEqual(saved["result"]["remaining"], ["auth.scope"])
        self.assertEqual(saved["status"], "running")
        self.assertEqual(self.store.gate(plan["run_id"])["decision"], "blocked")
        self.assertIn("checkpoint", [event["event_type"] for event in self.store.list_events(job["id"])])

    def test_agent_cannot_self_approve(self):
        plan, job = self.running()
        with self.assertRaises(StateError):
            self.store.finish(job["id"], job["lease_token"], "dismissed", {"verdict": "no_finding"})
        self.store.finish(job["id"], job["lease_token"], "needs_review", {"verdict": "no_finding"})
        self.assertEqual(self.store.gate(plan["run_id"])["decision"], "blocked")

    def test_empty_and_incomplete_runs_never_pass(self):
        empty = self.plan(candidates=[])
        self.assertEqual(self.store.gate(empty["run_id"])["decision"], "blocked")
        plan, job = self.running()
        self.store.finish(job["id"], job["lease_token"], "incomplete", {"reason": "deadline"})
        self.assertEqual(self.store.gate(plan["run_id"])["decision"], "blocked")
        again = self.plan(pr_number=2)
        self.assertEqual(again["reused"], 1)
        self.assertIsNone(self.store.claim("worker-b"))
        self.assertEqual(self.store.gate(again["run_id"])["decision"], "blocked")

    def test_verification_is_bound_to_exact_evidence_context(self):
        plan, job = self.reviewed()
        for evidence in ({}, dict(self.receipt(job), commit_sha="d" * 40), dict(self.receipt(job), context_digest="0" * 64)):
            with self.assertRaises(StateError):
                self.store.verify(job["id"], "dismissed", evidence, "independent-ci")
        self.store.verify(job["id"], "dismissed", self.receipt(job), "independent-ci")
        gate = self.store.gate(plan["run_id"])
        self.assertEqual(gate["decision"], "pass")
        self.assertEqual(gate["scope"], "submitted_candidates_only")
        self.assertFalse(gate["release_authorized"])
        with self.assertRaises(TransitionError):
            self.store.verify(job["id"], "confirmed", self.receipt(job), "another-verifier")

    def test_verified_results_reuse_without_lying_about_original_commit(self):
        _, job = self.reviewed()
        self.store.verify(job["id"], "dismissed", self.receipt(job), "independent-ci")
        next_run = self.plan(pr_number=2, commit_sha="d" * 40)
        self.assertEqual(self.store.gate(next_run["run_id"])["decision"], "pass")
        cached = self.store.get_run(next_run["run_id"])["investigations"][0]
        self.assertEqual(cached["verification"]["commit_sha"], "c" * 40)

    def test_confirmed_finding_fails_gate(self):
        plan, job = self.reviewed()
        self.store.verify(job["id"], "confirmed", self.receipt(job), "independent-ci")
        self.assertEqual(self.store.gate(plan["run_id"])["decision"], "fail")

    def test_explicit_retry_preserves_prior_attempt_evidence(self):
        _, job = self.running()
        self.store.finish(job["id"], job["lease_token"], "incomplete", {"reason": "timeout", "partial": "auth traced"})
        self.store.retry(job["id"])
        retry = self.store.claim("worker-b")
        self.assertEqual(retry["attempt"], 2)
        self.assertIsNone(retry["session_id"])
        self.assertIsNone(retry["deadline_at"])
        events = self.store.list_events(job["id"])
        self.assertTrue(any(e["payload"].get("result", {}).get("partial") == "auth traced" for e in events))
        self.store.finish(retry["id"], retry["lease_token"], "failed", {"reason": "test failure"})
        with self.assertRaises(TransitionError):
            self.store.retry(job["id"], max_attempts=2)

    def test_invalid_input_is_rejected_before_storage(self):
        cases = [dict(commit_sha="main"), dict(repository="../../oops"), dict(context={}),
                 dict(candidates=[dict(CANDIDATE, path="../../secrets")]),
                 dict(candidates=[dict(CANDIDATE, cwe="CVE-made-up")]),
                 dict(pr_number=True)]
        for change in cases:
            with self.assertRaises(StateError, msg=str(change)):
                self.plan(**change)
        with self.assertRaises(NotFoundError):
            self.store.get_investigation("missing")
        with self.assertRaises(StateError):
            StateStore(self.url, max_active_sessions=0)


class SQLiteStateTests(StoreBehavior, unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.url = "sqlite:///" + self.tmp.name + "/state.db"
        self.store = StateStore(self.url)
        self.store.initialize()

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()


@unittest.skipUnless(os.environ.get("TEST_POSTGRES_URL"), "set TEST_POSTGRES_URL for real PostgreSQL parity tests")
class PostgreSQLStateTests(StoreBehavior, unittest.TestCase):
    def setUp(self):
        import psycopg
        from psycopg import sql
        self.admin = psycopg.connect(os.environ["TEST_POSTGRES_URL"], autocommit=True)
        self.schema = "guard_test_" + uuid.uuid4().hex
        self.admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(self.schema)))
        self.url = postgres_schema_url(os.environ["TEST_POSTGRES_URL"], self.schema)
        self.store = StateStore(self.url)
        self.store.initialize()

    def tearDown(self):
        from psycopg import sql
        self.store.close()
        self.admin.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(self.schema)))
        self.admin.close()


if __name__ == "__main__":
    unittest.main()
