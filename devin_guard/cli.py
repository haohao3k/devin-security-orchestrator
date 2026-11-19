"""Local CLI; GitHub mutations and live remediation are not implemented here."""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from pathlib import Path

from .demo import run_demo
from .devin import DevinClient, DevinError
from .evaluation import score_files
from .manifest import check_candidate_paths, snapshot
from .state import StateError, StateStore
from .worker import Worker


def _read(path: str):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _print(value) -> None:
    print(json.dumps(value, sort_keys=True, indent=2, allow_nan=False))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Persistent Devin security investigation control plane")
    root.add_argument("--db", default=os.getenv("DATABASE_URL", "sqlite:///state/guard.db"))
    root.add_argument("--max-active-sessions", type=int, default=4)
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="initialize database schema")
    commands.add_parser("demo", help="offline simulated provider; no credentials or spending")
    plan = commands.add_parser("plan", help="plan supplied candidates at an immutable Git commit")
    plan.add_argument("--repo", required=True, help="local Git checkout path")
    plan.add_argument("--repository", required=True, help="GitHub owner/repo")
    plan.add_argument("--ref", default="HEAD")
    plan.add_argument("--pr", required=True, type=int)
    plan.add_argument("--candidates", required=True, help="JSON array of explicitly scoped hypotheses")
    plan.add_argument("--environment", required=True, help="JSON external runtime/dependency manifest")
    plan.add_argument("--policy-version", default="review-v1")
    plan.add_argument("--analysis-version", default="trace-v1")
    worker = commands.add_parser("worker", help="LIVE Devin API execution; can consume account credits")
    worker.add_argument("--loop", action="store_true", help="run until interrupted; otherwise one scheduling step")
    worker.add_argument("--worker-id", default=socket.gethostname() + ":" + str(os.getpid()))
    worker.add_argument("--wall-seconds", type=float, default=900)
    worker.add_argument("--max-acu", type=int, default=5)
    worker.add_argument("--poll-seconds", type=float, default=10)
    for name, identifier in (("run", "run_id"), ("gate", "run_id"),
                             ("job", "job_id"), ("events", "job_id"), ("retry", "job_id")):
        command = commands.add_parser(name)
        command.add_argument(identifier)
    score = commands.add_parser("score", help="score independently adjudicated JSONL predictions")
    score.add_argument("--labels", required=True)
    score.add_argument("--predictions", required=True)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    store = None
    client = None
    try:
        if args.command == "demo":
            _print(run_demo())
            return 0
        if args.command == "score":
            _print(score_files(args.labels, args.predictions))
            return 0
        store = StateStore(args.db, max_active_sessions=args.max_active_sessions)
        store.initialize()
        if args.command == "init":
            _print({"initialized": True, "backend": store.backend})
        elif args.command == "plan":
            manifest = snapshot(args.repo, args.ref, _read(args.environment), args.policy_version)
            candidates = _read(args.candidates)
            if not isinstance(candidates, list) or any(not isinstance(c, dict) for c in candidates):
                raise ValueError("candidates must be a JSON array of objects")
            check_candidate_paths(args.repo, manifest["commit_sha"], candidates)
            _print(store.plan_run(args.repository, args.pr, manifest["commit_sha"], candidates,
                                  manifest["context"], args.analysis_version))
        elif args.command == "worker":
            client = DevinClient(os.getenv("DEVIN_ORG_ID", ""), os.getenv("DEVIN_API_KEY", ""))
            worker = Worker(store, client, args.worker_id, args.wall_seconds, args.max_acu, args.poll_seconds)
            while True:
                result = worker.run_once()
                # Print a concise lifecycle signal, never credentials or lease tokens.
                _print({"id": result["id"], "status": result["status"]} if result else {"status": "idle"})
                if not args.loop:
                    break
                time.sleep(1)
        elif args.command == "run":
            result = store.get_run(args.run_id)
            for job in result["investigations"]:
                job.pop("lease_token", None)
            _print(result)
        elif args.command == "gate":
            result = store.gate(args.run_id)
            _print(result)
            return 0 if result["decision"] == "pass" else 1
        elif args.command == "job":
            result = store.get_investigation(args.job_id)
            result.pop("lease_token", None)
            _print(result)
        elif args.command == "events":
            _print(store.list_events(args.job_id))
        elif args.command == "retry":
            result = store.retry(args.job_id)
            result.pop("lease_token", None)
            _print(result)
        return 0
    except (ValueError, OSError, DevinError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    finally:
        if client is not None:
            client.close()
        if store is not None:
            store.close()
