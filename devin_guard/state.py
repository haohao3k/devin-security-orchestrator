"""Persistent, fenced investigation jobs. The database is the source of truth.

SQLite is the local/demo backend; PostgreSQL uses the same state machine with
row-level locking. Neither backend treats an agent's verdict as verification.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any, Iterator


class StateError(ValueError):
    """Invalid state-store request."""


class NotFoundError(StateError):
    """The requested persisted object does not exist."""


class LeaseConflict(StateError):
    """The worker no longer owns a live lease."""


class TransitionError(StateError):
    """The requested state transition is not permitted."""


def _json(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise StateError("value must be finite, JSON-serializable data") from exc


def _digest(value: Any) -> str:
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _text(value: Any, name: str, max_length: int = 1024) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise StateError(f"{name} must be a nonempty string of at most {max_length} characters")
    return value


def _hex(value: Any, size: int, name: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(rf"[0-9a-fA-F]{{{size}}}", value):
        raise StateError(f"{name} must be a {size}-character hexadecimal digest")
    return value.lower()


def _clock(value: float | None = None) -> float:
    value = time.time() if value is None else value
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
        raise StateError("time must be finite")
    return float(value)


def _duration(value: float, name: str = "lease_seconds", allow_zero: bool = False) -> float:
    value = _clock(value)
    if value < 0 or (value == 0 and not allow_zero) or value > 86400:
        raise StateError(f"{name} must be {'nonnegative' if allow_zero else 'positive'} and <= 86400")
    return value


class StateStore:
    """Small synchronous DB-API store; create one per worker/service process.

    ``initialize`` is explicit. A store serializes access to its own connection;
    database locks arbitrate independent processes and connections.
    """

    def __init__(self, database_url: str = "sqlite:///state.db", max_active_sessions: int = 4) -> None:
        if not isinstance(max_active_sessions, int) or isinstance(max_active_sessions, bool) or not 1 <= max_active_sessions <= 1000:
            raise StateError("max_active_sessions must be an integer between 1 and 1000")
        self.database_url = database_url
        self.max_active_sessions = max_active_sessions
        self._lock = threading.RLock()
        if database_url.startswith("sqlite:///"):
            self.backend = "sqlite"
            path = database_url[len("sqlite:///"):]
            if not path or "?" in path or "#" in path:
                raise StateError("use a plain SQLite file URL or sqlite:///:memory:")
            if path != ":memory:":
                Path(path).parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(path, timeout=30, isolation_level=None, check_same_thread=False)
            self._db.row_factory = sqlite3.Row
            self._db.execute("PRAGMA foreign_keys = ON")
            self._db.execute("PRAGMA busy_timeout = 30000")
            self._db.execute("PRAGMA journal_mode = WAL")
        elif database_url.startswith(("postgresql://", "postgres://")):
            self.backend = "postgres"
            try:
                import psycopg
                from psycopg.rows import dict_row
            except ImportError as exc:
                raise StateError("PostgreSQL requires psycopg[binary]>=3.2,<4") from exc
            self._db = psycopg.connect(database_url, autocommit=True, row_factory=dict_row)
        else:
            raise StateError("DATABASE_URL must start with sqlite:/// or postgresql://")

    def _execute(self, query: str, params: tuple = ()):
        return self._db.execute(query if self.backend == "sqlite" else query.replace("?", "%s"), params)

    @contextmanager
    def _tx(self) -> Iterator[None]:
        with self._lock:
            self._execute("BEGIN IMMEDIATE" if self.backend == "sqlite" else "BEGIN")
            try:
                yield
            except BaseException:
                self._execute("ROLLBACK")
                raise
            else:
                self._execute("COMMIT")

    def initialize(self) -> None:
        event_id = "INTEGER PRIMARY KEY AUTOINCREMENT" if self.backend == "sqlite" else "BIGSERIAL PRIMARY KEY"
        statements = [
            "CREATE TABLE IF NOT EXISTS guard_schema (id INTEGER PRIMARY KEY, version INTEGER NOT NULL)",
            """CREATE TABLE IF NOT EXISTS guard_runs (
                id TEXT PRIMARY KEY, repository TEXT NOT NULL, pr_number INTEGER NOT NULL,
                commit_sha TEXT NOT NULL, context_json TEXT NOT NULL,
                analysis_version TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL)""",
            """CREATE TABLE IF NOT EXISTS guard_investigations (
                id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, context_digest TEXT NOT NULL,
                repository TEXT NOT NULL, commit_sha TEXT NOT NULL, candidate_json TEXT NOT NULL,
                context_json TEXT NOT NULL, analysis_version TEXT NOT NULL, status TEXT NOT NULL,
                lease_token TEXT, lease_until DOUBLE PRECISION, session_id TEXT,
                deadline_at DOUBLE PRECISION, attempt INTEGER NOT NULL DEFAULT 0,
                result_json TEXT, verification_json TEXT, verified_by TEXT,
                created_at DOUBLE PRECISION NOT NULL, updated_at DOUBLE PRECISION NOT NULL,
                UNIQUE(fingerprint, context_digest))""",
            """CREATE TABLE IF NOT EXISTS guard_run_jobs (
                run_id TEXT NOT NULL REFERENCES guard_runs(id),
                investigation_id TEXT NOT NULL REFERENCES guard_investigations(id),
                PRIMARY KEY(run_id, investigation_id))""",
            f"""CREATE TABLE IF NOT EXISTS guard_events (
                id {event_id}, investigation_id TEXT NOT NULL REFERENCES guard_investigations(id),
                event_type TEXT NOT NULL, payload_json TEXT NOT NULL,
                created_at DOUBLE PRECISION NOT NULL)""",
            "CREATE INDEX IF NOT EXISTS guard_jobs_ready ON guard_investigations(status, lease_until, created_at)",
            "CREATE INDEX IF NOT EXISTS guard_events_job ON guard_events(investigation_id, id)",
        ]
        with self._tx():
            for statement in statements:
                self._execute(statement)
            self._execute("INSERT INTO guard_schema(id, version) VALUES(1, 1) ON CONFLICT(id) DO NOTHING")
            row = self._execute("SELECT version FROM guard_schema WHERE id = 1").fetchone()
            if row["version"] != 1:
                raise StateError("unsupported database schema version; refusing to run")

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _event(self, job_id: str, event_type: str, payload: dict, now: float) -> None:
        self._execute(
            "INSERT INTO guard_events(investigation_id, event_type, payload_json, created_at) VALUES(?, ?, ?, ?)",
            (job_id, event_type, _json(payload), now),
        )

    def _raw_job(self, job_id: str, *, lock: bool = False) -> dict:
        suffix = " FOR UPDATE" if lock and self.backend == "postgres" else ""
        row = self._execute("SELECT * FROM guard_investigations WHERE id = ?" + suffix, (job_id,)).fetchone()
        if row is None:
            raise NotFoundError(f"investigation not found: {job_id}")
        return dict(row)

    @staticmethod
    def _job(row: dict) -> dict:
        out = dict(row)
        for field in ("candidate", "context", "result", "verification"):
            raw = out.pop(field + "_json", None)
            out[field] = json.loads(raw) if raw is not None else None
        return out

    @staticmethod
    def _remote_unresolved(row: dict) -> bool:
        """A cancellation request, even accepted, is not proof of termination."""
        if row["status"] != "incomplete" or not row["session_id"]:
            return False
        try:
            result = json.loads(row["result_json"] or "{}")
        except (TypeError, ValueError):
            return True
        if not isinstance(result, dict):
            return True
        return result.get("termination_request") in ("accepted", "failed_or_unknown")

    def _lease(self, job_id: str, token: str, states: tuple[str, ...], now: float | None = None) -> dict:
        now = _clock(now)
        row = self._raw_job(job_id, lock=True)
        if not isinstance(token, str) or not row["lease_token"] or not hmac.compare_digest(row["lease_token"], token):
            raise LeaseConflict("lease token is stale or absent")
        if row["lease_until"] is None or row["lease_until"] <= now:
            raise LeaseConflict("lease expired")
        if row["status"] not in states:
            raise TransitionError(f"cannot mutate {row['status']} as {states}")
        return row

    def plan_run(self, repository: str, pr_number: int, commit_sha: str,
                 candidates: list[dict], context: dict, analysis_version: str = "trace-v1") -> dict:
        if not isinstance(repository, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise StateError("repository must be owner/name")
        if any(part in (".", "..") for part in repository.split("/")):
            raise StateError("invalid repository")
        if not isinstance(pr_number, int) or isinstance(pr_number, bool) or pr_number < 0:
            raise StateError("pr_number must be a nonnegative integer (0 means scheduled/manual)")
        commit_sha = _hex(commit_sha, 40, "commit_sha")
        analysis_version = _text(analysis_version, "analysis_version", 200)
        if not isinstance(context, dict):
            raise StateError("context must be an object")
        context = dict(context)
        context["tree_sha"] = _hex(context.get("tree_sha"), 40, "context.tree_sha")
        context["environment_digest"] = _hex(context.get("environment_digest"), 64, "context.environment_digest")
        _text(context.get("policy_version"), "context.policy_version", 200)
        if len(_json(context)) > 1_000_000:
            raise StateError("context is too large")
        if not isinstance(candidates, list) or len(candidates) > 1000:
            raise StateError("candidates must be a list of at most 1000 entries")
        normalized: list[dict] = []
        for candidate in candidates:
            if not isinstance(candidate, dict):
                raise StateError("candidate must be an object")
            cwe = candidate.get("cwe")
            if not isinstance(cwe, str) or not re.fullmatch(r"CWE-[1-9][0-9]*", cwe):
                raise StateError("candidate.cwe must be CWE-<number>")
            path = _text(candidate.get("path"), "candidate.path")
            if PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts or "\\" in path:
                raise StateError("candidate.path must be a safe repository-relative path")
            symbol = _text(candidate.get("symbol"), "candidate.symbol")
            item = {"cwe": cwe, "path": path, "symbol": symbol}
            for key, limit in (("source", 2048), ("sink", 2048), ("description", 16384)):
                value = candidate.get(key, "")
                if not isinstance(value, str) or len(value) > limit:
                    raise StateError(f"candidate.{key} must be a string of at most {limit} characters")
                item[key] = value
            normalized.append(item)
        now = _clock()
        run_id = "run-" + uuid.uuid4().hex
        investigation_ids: list[str] = []
        reused = 0
        with self._tx():
            self._execute(
                "INSERT INTO guard_runs(id, repository, pr_number, commit_sha, context_json, analysis_version, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)",
                (run_id, repository, pr_number, commit_sha, _json(context), analysis_version, now),
            )
            for candidate in normalized:
                identity = {key: candidate[key] for key in ("cwe", "path", "symbol", "source", "sink")}
                fingerprint = _digest({"repository": repository.lower(), "candidate": identity})
                # Stable finding identity is not sufficient to reuse evidence:
                # a different question about the same symbol is new work.
                context_digest = _digest({"context": context, "analysis_version": analysis_version,
                                          "candidate": candidate})
                new_id = "inv-" + uuid.uuid4().hex
                cursor = self._execute(
                    """INSERT INTO guard_investigations(
                        id, fingerprint, context_digest, repository, commit_sha, candidate_json,
                        context_json, analysis_version, status, created_at, updated_at)
                        VALUES(?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?)
                        ON CONFLICT(fingerprint, context_digest) DO NOTHING""",
                    (new_id, fingerprint, context_digest, repository, commit_sha, _json(candidate),
                     _json(context), analysis_version, now, now),
                )
                inserted = cursor.rowcount == 1
                row = self._execute(
                    "SELECT id, status FROM guard_investigations WHERE fingerprint = ? AND context_digest = ?",
                    (fingerprint, context_digest),
                ).fetchone()
                job_id = row["id"]
                if job_id in investigation_ids:
                    continue
                investigation_ids.append(job_id)
                self._execute("INSERT INTO guard_run_jobs(run_id, investigation_id) VALUES(?, ?)", (run_id, job_id))
                if inserted:
                    self._event(job_id, "planned", {"run_id": run_id, "commit_sha": commit_sha}, now)
                else:
                    reused += 1
                    self._event(job_id, "linked", {"run_id": run_id, "commit_sha": commit_sha, "status": row["status"]}, now)
        return {"run_id": run_id, "investigation_ids": investigation_ids, "reused": reused}

    def claim(self, worker_id: str, lease_seconds: float = 60, now: float | None = None) -> dict | None:
        worker_id = _text(worker_id, "worker_id", 200)
        lease_seconds, now = _duration(lease_seconds), _clock(now)
        skip_lock = " FOR UPDATE SKIP LOCKED" if self.backend == "postgres" else ""
        with self._tx():
            # Serialize admission/counting across PostgreSQL workers. SQLite's
            # BEGIN IMMEDIATE already holds the corresponding database writer lock.
            if self.backend == "postgres":
                self._execute("SELECT id FROM guard_schema WHERE id = 1 FOR UPDATE").fetchone()
            # A crash after POST could have created a paid remote session. Never
            # pretend a missing local session_id proves that POST did not happen.
            stale = self._execute(
                "SELECT id FROM guard_investigations WHERE status = 'dispatching' AND lease_until <= ?" + skip_lock,
                (now,),
            ).fetchall()
            for row in stale:
                self._execute(
                    "UPDATE guard_investigations SET status = 'dispatch_unknown', lease_token = NULL, lease_until = NULL, updated_at = ? WHERE id = ?",
                    (now, row["id"]),
                )
                self._event(row["id"], "dispatch_unknown", {"reason": "dispatch lease expired before session_id was persisted"}, now)
            row = self._execute(
                """SELECT * FROM guard_investigations WHERE (status = 'claimed' AND lease_until <= ?)
                    OR (status = 'running' AND session_id IS NOT NULL AND lease_until <= ?)
                    ORDER BY created_at, id LIMIT 1""" + skip_lock,
                (now, now),
            ).fetchone()
            if row is None:
                active = self._execute(
                    "SELECT COUNT(*) AS n FROM guard_investigations WHERE status IN ('claimed', 'dispatching', 'running', 'dispatch_unknown')"
                ).fetchone()["n"]
                incomplete = self._execute(
                    "SELECT status, session_id, result_json FROM guard_investigations WHERE status = 'incomplete' AND session_id IS NOT NULL"
                ).fetchall()
                active += sum(self._remote_unresolved(dict(item)) for item in incomplete)
                if active >= self.max_active_sessions:
                    return None
                row = self._execute(
                    "SELECT * FROM guard_investigations WHERE status = 'queued' ORDER BY created_at, id LIMIT 1" + skip_lock
                ).fetchone()
            if row is None:
                return None
            row = dict(row)
            token = uuid.uuid4().hex
            status = "running" if row["session_id"] else "claimed"
            attempt = row["attempt"] + (1 if row["status"] == "queued" else 0)
            self._execute(
                "UPDATE guard_investigations SET status = ?, lease_token = ?, lease_until = ?, attempt = ?, updated_at = ? WHERE id = ?",
                (status, token, now + lease_seconds, attempt, now, row["id"]),
            )
            self._event(row["id"], "claimed", {"worker_id": worker_id, "attempt": attempt, "resumed": bool(row["session_id"])}, now)
            return self._job(self._raw_job(row["id"]))

    def begin_dispatch(self, job_id: str, lease_token: str, deadline_at: float) -> None:
        now, deadline_at = _clock(), _clock(deadline_at)
        if deadline_at <= now:
            raise StateError("deadline_at must be in the future")
        with self._tx():
            row = self._lease(job_id, lease_token, ("claimed",), now)
            if row["session_id"] is not None:
                raise TransitionError("job already has a session")
            self._execute(
                "UPDATE guard_investigations SET status = 'dispatching', deadline_at = ?, updated_at = ? WHERE id = ?",
                (deadline_at, now, job_id),
            )
            self._event(job_id, "dispatch_started", {"deadline_at": deadline_at}, now)

    def attach_session(self, job_id: str, lease_token: str, session_id: str) -> None:
        session_id, now = _text(session_id, "session_id", 300), _clock()
        with self._tx():
            self._lease(job_id, lease_token, ("dispatching",), now)
            self._execute(
                "UPDATE guard_investigations SET status = 'running', session_id = ?, updated_at = ? WHERE id = ?",
                (session_id, now, job_id),
            )
            self._event(job_id, "session_attached", {"session_id": session_id}, now)

    def heartbeat(self, job_id: str, lease_token: str, lease_seconds: float = 60, now: float | None = None) -> None:
        lease_seconds, now = _duration(lease_seconds), _clock(now)
        with self._tx():
            self._lease(job_id, lease_token, ("claimed", "dispatching", "running"), now)
            self._execute("UPDATE guard_investigations SET lease_until = ?, updated_at = ? WHERE id = ?", (now + lease_seconds, now, job_id))

    def release(self, job_id: str, lease_token: str, delay_seconds: float = 10, now: float | None = None) -> None:
        """Release a running job until its next poll; never resubmit its POST."""
        delay_seconds, now = _duration(delay_seconds, "delay_seconds", allow_zero=True), _clock(now)
        with self._tx():
            self._lease(job_id, lease_token, ("running",), now)
            self._execute(
                "UPDATE guard_investigations SET lease_token = NULL, lease_until = ?, updated_at = ? WHERE id = ?",
                (now + delay_seconds, now, job_id),
            )
            self._event(job_id, "poll_deferred", {"next_poll_at": now + delay_seconds}, now)

    def checkpoint(self, job_id: str, lease_token: str, result: dict, now: float | None = None) -> None:
        """Persist partial progress without making it verified or terminal."""
        if not isinstance(result, dict) or not result:
            raise StateError("checkpoint must be a nonempty object")
        result_json, now = _json(result), _clock(now)
        if len(result_json) > 2_000_000:
            raise StateError("checkpoint is too large")
        with self._tx():
            self._lease(job_id, lease_token, ("running",), now)
            self._execute(
                "UPDATE guard_investigations SET result_json = ?, updated_at = ? WHERE id = ?",
                (result_json, now, job_id),
            )
            self._event(job_id, "checkpoint", {"result": result}, now)

    def finish(self, job_id: str, lease_token: str, status: str, result: dict) -> None:
        allowed = ("needs_review", "incomplete", "failed", "dispatch_unknown")
        if status not in allowed:
            raise StateError(f"finish status must be one of {allowed}; workers cannot verify findings")
        if not isinstance(result, dict) or not result:
            raise StateError("result must be a nonempty object")
        result_json, now = _json(result), _clock()
        if len(result_json) > 2_000_000:
            raise StateError("result is too large")
        states = ("running",) if status == "needs_review" else ("claimed", "dispatching", "running")
        with self._tx():
            self._lease(job_id, lease_token, states, now)
            self._execute(
                "UPDATE guard_investigations SET status = ?, result_json = ?, lease_token = NULL, lease_until = NULL, updated_at = ? WHERE id = ?",
                (status, result_json, now, job_id),
            )
            self._event(job_id, "analysis_finished", {"status": status, "result": result}, now)

    def verify(self, job_id: str, verdict: str, evidence: dict, verified_by: str) -> dict:
        """Trusted verifier boundary; API must authenticate it separately.

        Receipt shape/binding validation does not establish that its contents are
        true. Only the trusted verifier, never a Devin worker, calls this method.
        """
        if verdict not in ("confirmed", "dismissed"):
            raise StateError("verification verdict must be confirmed or dismissed")
        verified_by = _text(verified_by, "verified_by", 200)
        if not isinstance(evidence, dict) or not evidence:
            raise StateError("verification requires an evidence receipt")
        _text(evidence.get("method"), "evidence.method", 1000)
        _hex(evidence.get("artifact_sha256"), 64, "evidence.artifact_sha256")
        now = _clock()
        with self._tx():
            row = self._raw_job(job_id, lock=True)
            if row["status"] != "needs_review":
                raise TransitionError("only needs_review investigations can be independently verified")
            if evidence.get("commit_sha") != row["commit_sha"] or evidence.get("context_digest") != row["context_digest"]:
                raise StateError("verification receipt does not match source commit and analysis context")
            receipt_json = _json(evidence)
            if len(receipt_json) > 2_000_000:
                raise StateError("verification receipt is too large")
            self._execute(
                "UPDATE guard_investigations SET status = ?, verification_json = ?, verified_by = ?, updated_at = ? WHERE id = ?",
                (verdict, receipt_json, verified_by, now, job_id),
            )
            self._event(job_id, "verified", {"verdict": verdict, "verified_by": verified_by, "evidence": evidence}, now)
            return self._job(self._raw_job(job_id))

    def retry(self, job_id: str, max_attempts: int = 3) -> dict:
        if not isinstance(max_attempts, int) or isinstance(max_attempts, bool) or not 1 <= max_attempts <= 10:
            raise StateError("max_attempts must be between 1 and 10")
        now = _clock()
        with self._tx():
            row = self._raw_job(job_id, lock=True)
            if row["status"] not in ("incomplete", "failed"):
                raise TransitionError("only incomplete/failed jobs may retry; ambiguous dispatch requires reconciliation")
            if self._remote_unresolved(row):
                raise TransitionError("remote termination is unconfirmed; reconcile the existing session before retrying")
            if row["attempt"] >= max_attempts:
                raise TransitionError("attempt budget exhausted")
            self._execute(
                "UPDATE guard_investigations SET status = 'queued', session_id = NULL, deadline_at = NULL, lease_token = NULL, lease_until = NULL, result_json = NULL, updated_at = ? WHERE id = ?",
                (now, job_id),
            )
            self._event(job_id, "retry_requested", {"previous_status": row["status"], "previous_session_id": row["session_id"], "previous_attempt": row["attempt"]}, now)
            return self._job(self._raw_job(job_id))

    def get_investigation(self, job_id: str) -> dict:
        with self._lock:
            job = self._job(self._raw_job(job_id))
            event = self._execute("SELECT event_type, created_at FROM guard_events WHERE investigation_id = ? ORDER BY id DESC LIMIT 1", (job_id,)).fetchone()
            job["last_event"] = dict(event) if event else None
            job["next_poll_at"] = job["lease_until"] if job["status"] == "running" and job["lease_token"] is None else None
            return job

    def get_run(self, run_id: str) -> dict:
        with self._lock:
            row = self._execute("SELECT * FROM guard_runs WHERE id = ?", (run_id,)).fetchone()
            if row is None:
                raise NotFoundError(f"run not found: {run_id}")
            run = dict(row)
            run["context"] = json.loads(run.pop("context_json"))
            rows = self._execute(
                "SELECT i.* FROM guard_investigations i JOIN guard_run_jobs j ON i.id = j.investigation_id WHERE j.run_id = ? ORDER BY i.id",
                (run_id,),
            ).fetchall()
            run["investigations"] = [self._job(dict(item)) for item in rows]
            return run

    def list_events(self, job_id: str) -> list[dict]:
        with self._lock:
            self._raw_job(job_id)
            rows = self._execute("SELECT * FROM guard_events WHERE investigation_id = ? ORDER BY id", (job_id,)).fetchall()
            events = []
            for row in rows:
                item = dict(row)
                item["payload"] = json.loads(item.pop("payload_json"))
                events.append(item)
            return events

    def gate(self, run_id: str) -> dict:
        run = self.get_run(run_id)
        jobs = run["investigations"]
        confirmed = [job["id"] for job in jobs if job["status"] == "confirmed"]
        pending = [job["id"] for job in jobs if job["status"] not in ("confirmed", "dismissed")]
        if confirmed:
            decision, reason = "fail", "independently confirmed vulnerabilities remain"
        elif not jobs:
            decision, reason = "blocked", "no investigation coverage; an empty candidate list is not proof of a clean scan"
        elif pending:
            decision, reason = "blocked", "investigations require completion or independent verification"
        else:
            decision, reason = "pass", "all submitted candidates were independently dismissed"
        return {
            "run_id": run_id, "repository": run["repository"], "commit_sha": run["commit_sha"],
            "decision": decision, "reason": reason, "scope": "submitted_candidates_only",
            "release_authorized": False, "confirmed": confirmed, "pending": pending,
        }
