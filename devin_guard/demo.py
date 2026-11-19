"""Offline demonstration: real database/worker, explicitly simulated provider."""
from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

import httpx

from .devin import DevinClient
from .state import StateStore
from .worker import Worker


def run_demo() -> dict:
    calls: list[str] = []
    output = {
        "verdict": "no_finding", "summary": "Synthetic demonstration only.",
        "locations": [{"path": "app.py", "line": 1, "reason": "Toy fixture location."}],
        "evidence": [{"kind": "toy", "detail": "This is not a real vulnerability investigation."}],
        "unresolved_paths": [],
    }

    def provider(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        return httpx.Response(200, json={
            "session_id": "devin-demo", "status": "running", "status_detail": "finished",
            "structured_output": output, "acus_consumed": 0,
        })

    with tempfile.TemporaryDirectory(prefix="devin-guard-demo-") as temp:
        url = "sqlite:///" + str(Path(temp) / "state.db")
        store = StateStore(url)
        store.initialize()
        candidate = {"cwe": "CWE-79", "path": "app.py", "symbol": "render",
                     "source": "request.name", "sink": "html_response",
                     "description": "Synthetic fixture for the state lifecycle."}
        context = {"tree_sha": "b" * 40, "environment_digest": "c" * 64, "policy_version": "demo-v1"}
        first = store.plan_run("example/toy", 1, "a" * 40, [candidate], context)
        client = DevinClient("org-demo", "demo-not-a-real-key", transport=httpx.MockTransport(provider))
        worker = Worker(store, client, "offline-demo")
        job = worker.run_once()
        unverified_gate = store.gate(first["run_id"])
        # The demo's verifier is a fixture, not independent real security work.
        receipt = {"commit_sha": job["commit_sha"], "context_digest": job["context_digest"],
                   "artifact_sha256": hashlib.sha256(b"synthetic demonstration receipt").hexdigest(),
                   "method": "simulated_verifier_for_demo_only"}
        store.verify(job["id"], "dismissed", receipt, "synthetic-demo-verifier")
        store.close()
        # Actually reopen the database to demonstrate persistence across runs.
        store = StateStore(url)
        store.initialize()
        same = store.plan_run("example/toy", 2, "d" * 40, [candidate], context)
        changed = store.plan_run("example/toy", 3, "e" * 40, [candidate],
                                 dict(context, tree_sha="f" * 40))
        report = {
            "mode": "offline_simulation", "live_devin_calls": 0,
            "mock_http_requests": calls, "first_analysis_status": job["status"],
            "gate_before_independent_receipt": unverified_gate["decision"],
            "same_context_reuses_investigation_after_db_reopen":
                first["investigation_ids"] == same["investigation_ids"],
            "gate_after_synthetic_receipt": store.gate(same["run_id"])["decision"],
            "changed_tree_creates_new_investigation":
                first["investigation_ids"] != changed["investigation_ids"],
            "changed_tree_gate": store.gate(changed["run_id"])["decision"],
            "release_authorized": False,
        }
        client.close()
        store.close()
        return report
