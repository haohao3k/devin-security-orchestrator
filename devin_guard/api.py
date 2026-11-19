"""Authenticated control API. Devin never receives either API role token."""
from __future__ import annotations

import hmac
import os
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from .state import NotFoundError, StateError, StateStore


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Candidate(StrictModel):
    cwe: str = Field(pattern=r"^CWE-[1-9][0-9]*$", max_length=32)
    path: str = Field(min_length=1, max_length=1024)
    symbol: str = Field(min_length=1, max_length=1024)
    source: str = Field(default="", max_length=2048)
    sink: str = Field(default="", max_length=2048)
    description: str = Field(default="", max_length=16384)


class Context(StrictModel):
    tree_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    environment_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_version: str = Field(min_length=1, max_length=200)


class RunRequest(StrictModel):
    repository: str = Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", max_length=256)
    pr_number: int = Field(ge=0)
    commit_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    candidates: list[Candidate] = Field(max_length=1000)
    context: Context
    analysis_version: str = Field(default="trace-v1", min_length=1, max_length=200)


class VerificationRequest(StrictModel):
    verdict: Literal["confirmed", "dismissed"]
    evidence: dict


def create_app(store: StateStore, control_token: str, verifier_token: str,
               verifier_id: str = "independent-security-reviewer") -> FastAPI:
    if any(not isinstance(t, str) or len(t) < 32 for t in (control_token, verifier_token)):
        raise ValueError("CONTROL_TOKEN and VERIFIER_TOKEN must each have at least 32 characters")
    if hmac.compare_digest(control_token, verifier_token):
        raise ValueError("controller and verifier credentials must be different")
    if not verifier_id.strip():
        raise ValueError("VERIFIER_ID must be nonempty")
    app = FastAPI(title="Devin Security Orchestrator", version="0.1.0")

    def authenticate(expected: str):
        def dependency(authorization: str | None = Header(default=None)) -> None:
            if authorization is None or not hmac.compare_digest(
                authorization.encode("utf-8"), ("Bearer " + expected).encode("utf-8")
            ):
                raise HTTPException(status_code=401, detail="Invalid credential")
        return dependency

    control = authenticate(control_token)
    verifier = authenticate(verifier_token)

    def reader(authorization: str | None = Header(default=None)) -> None:
        supplied = (authorization or "").encode("utf-8")
        permitted = [hmac.compare_digest(supplied, ("Bearer " + token).encode("utf-8"))
                     for token in (control_token, verifier_token)]
        if not any(permitted):
            raise HTTPException(status_code=401, detail="Invalid credential")

    @app.exception_handler(StateError)
    async def state_error(_: Request, exc: StateError):
        return JSONResponse(status_code=404 if isinstance(exc, NotFoundError) else 409,
                            content={"detail": str(exc)})

    @app.get("/healthz")
    def health():
        return {"status": "ok", "version": "0.1.0"}

    @app.post("/v1/runs", dependencies=[Depends(control)], status_code=201)
    def plan(body: RunRequest):
        # This is a trusted planner interface, not a public webhook. The planner
        # must compute the tree/environment manifest from the reviewed checkout.
        return store.plan_run(**body.model_dump())

    @app.get("/v1/runs/{run_id}", dependencies=[Depends(reader)])
    def get_run(run_id: str):
        run = store.get_run(run_id)
        for job in run["investigations"]:
            job.pop("lease_token", None)
        return run

    @app.get("/v1/runs/{run_id}/gate", dependencies=[Depends(reader)])
    def get_gate(run_id: str):
        return store.gate(run_id)

    @app.get("/v1/investigations/{job_id}", dependencies=[Depends(reader)])
    def get_job(job_id: str):
        job = store.get_investigation(job_id)
        job.pop("lease_token", None)
        return job

    @app.get("/v1/investigations/{job_id}/events", dependencies=[Depends(reader)])
    def get_events(job_id: str):
        return store.list_events(job_id)

    @app.post("/v1/investigations/{job_id}/retry", dependencies=[Depends(control)])
    def retry(job_id: str):
        return store.retry(job_id)

    @app.post("/v1/investigations/{job_id}/verify", dependencies=[Depends(verifier)])
    def verify(job_id: str, body: VerificationRequest):
        # Caller identity comes from server configuration, never from the agent.
        return store.verify(job_id, body.verdict, body.evidence, verifier_id)

    return app


def create_app_from_env() -> FastAPI:
    store = StateStore(os.getenv("DATABASE_URL", "sqlite:///state/guard.db"))
    store.initialize()
    return create_app(store, os.getenv("CONTROL_TOKEN", ""), os.getenv("VERIFIER_TOKEN", ""),
                      os.getenv("VERIFIER_ID", "independent-security-reviewer"))
