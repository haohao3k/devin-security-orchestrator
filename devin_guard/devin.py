"""Small, deliberately non-retrying adapter for the official Devin v3 API.

Transport injection is for tests. The credential destination is fixed; callers
cannot supply a base URL, and redirects/environment proxies are disabled.
"""
from __future__ import annotations

import copy
import json
import math
import re
from pathlib import PurePosixPath
from typing import Any, Mapping

import httpx
from jsonschema import Draft7Validator


API_BASE = "https://api.devin.ai/v3"
_ORG_ID = re.compile(r"org-[A-Za-z0-9_-]{1,200}\Z")
_SESSION_ID = re.compile(r"devin-[A-Za-z0-9_-]{1,200}\Z")
_JOB_ID = re.compile(r"[A-Za-z0-9_-]{1,200}\Z")
_REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_SESSION_STATUSES = {"new", "claimed", "running", "exit", "error", "suspended", "resuming"}

ANALYSIS_RESULT_SCHEMA: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "additionalProperties": False,
    "required": ["verdict", "summary", "locations", "evidence", "unresolved_paths"],
    "properties": {
        "verdict": {"enum": ["candidate", "no_finding", "incomplete"]},
        "summary": {"type": "string", "minLength": 1, "maxLength": 16000},
        "locations": {
            "type": "array", "maxItems": 200,
            "items": {
                "type": "object", "additionalProperties": False,
                "required": ["path", "line", "reason"],
                "properties": {
                    "path": {"type": "string", "minLength": 1, "maxLength": 1024},
                    "line": {"type": "integer", "minimum": 1},
                    "reason": {"type": "string", "minLength": 1, "maxLength": 8000},
                },
            },
        },
        "evidence": {
            "type": "array", "maxItems": 200,
            "items": {
                "type": "object", "additionalProperties": False,
                "required": ["kind", "detail"],
                "properties": {
                    "kind": {"type": "string", "minLength": 1, "maxLength": 200},
                    "detail": {"type": "string", "minLength": 1, "maxLength": 8000},
                },
            },
        },
        "unresolved_paths": {
            "type": "array", "maxItems": 200,
            "items": {"type": "string", "minLength": 1, "maxLength": 1024},
        },
    },
    "allOf": [{
        "if": {"properties": {"verdict": {"enum": ["candidate", "no_finding"]}}},
        "then": {"properties": {"evidence": {"minItems": 1}, "locations": {"minItems": 1}}},
    }],
}
_RESULT_VALIDATOR = Draft7Validator(ANALYSIS_RESULT_SCHEMA)


class DevinError(RuntimeError):
    """Provider failure, with a message safe to log (no response body/token)."""


class DispatchUnknown(DevinError):
    """POST may have created a charged session. Never blindly submit it again."""


class DevinAPIError(DevinError):
    def __init__(self, message: str, *, status_code: int | None = None,
                 retryable: bool = False) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.retryable = retryable


class InvalidAnalysisResult(DevinError):
    """Structured output is absent, malformed, or outside the agreed contract."""


def validate_analysis_result(value: Any) -> dict[str, Any]:
    """Validate structure only; this does not verify any security claim."""
    if next(_RESULT_VALIDATOR.iter_errors(value), None) is not None:
        raise InvalidAnalysisResult("structured output does not satisfy the analysis schema")
    if len(json.dumps(value, ensure_ascii=True)) > 500_000:
        raise InvalidAnalysisResult("structured output exceeds the local evidence size limit")
    for location in value["locations"]:
        path = location["path"]
        if (PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts
                or "\\" in path or re.match(r"^[A-Za-z]:", path)
                or any(ord(char) < 32 for char in path)):
            raise InvalidAnalysisResult("analysis locations must use repository-relative paths")
    return copy.deepcopy(value)


def normalize_session_status(session: Mapping[str, Any]) -> str:
    """Return active, completed, blocked, or incomplete without equating stop to success."""
    status, detail = session.get("status"), session.get("status_detail")
    # A running VM can contain an already finished agent turn.
    if status in {"running", "exit"} and detail == "finished":
        return "completed"
    if status == "running" and detail in {"waiting_for_user", "waiting_for_approval"}:
        return "blocked"
    if status in {"new", "claimed", "resuming"}:
        return "active"
    if status == "running" and detail in {None, "working"}:
        return "active"
    # Includes suspended usage/quota limits, error, an unexplained exit, and
    # unknown future status combinations. None can establish completion.
    return "incomplete"


class DevinClient:
    """Organization-scoped Devin Cloud API client; one HTTP attempt per method."""

    def __init__(self, org_id: str, api_key: str, *,
                 transport: httpx.BaseTransport | None = None,
                 timeout_seconds: float = 10.0) -> None:
        if not isinstance(org_id, str) or not _ORG_ID.fullmatch(org_id):
            raise ValueError("org_id must be an org- identifier, not a URL or path")
        if (not isinstance(api_key, str) or not api_key.strip()
                or any(ord(char) < 33 or ord(char) > 126 for char in api_key)):
            raise ValueError("api_key must be a nonempty ASCII credential without whitespace")
        if (isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float))
                or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 30):
            raise ValueError("timeout_seconds must be positive and at most 30")
        self.org_id = org_id
        self.timeout_seconds = float(timeout_seconds)
        self._http = httpx.Client(
            base_url=API_BASE + "/", transport=transport,
            headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
            timeout=httpx.Timeout(self.timeout_seconds),
            follow_redirects=False, trust_env=False,
        )

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "DevinClient":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def _path(self, session_id: str | None = None) -> str:
        path = f"organizations/{self.org_id}/sessions"
        if session_id is not None:
            if not isinstance(session_id, str) or not _SESSION_ID.fullmatch(session_id):
                raise ValueError("session_id must be a devin- identifier")
            path += "/" + session_id
        return path

    def _request(self, method: str, path: str, *, payload: dict | None = None,
                 creating: bool = False) -> httpx.Response:
        try:
            response = self._http.request(method, path, json=payload)
        except httpx.RequestError:
            if creating:
                raise DispatchUnknown("create request transport failed; acceptance is unknown") from None
            raise DevinAPIError("provider request transport failed", retryable=True) from None
        code = response.status_code
        if not 200 <= code < 300:
            # A timeout response or gateway/server failure can follow a committed
            # create. A redirect is also ambiguous; never forward credentials.
            if creating and (code >= 500 or code == 408 or 300 <= code < 400):
                raise DispatchUnknown(f"create returned HTTP {code}; acceptance is unknown")
            raise DevinAPIError(f"provider returned HTTP {code}", status_code=code,
                                retryable=(not creating and (code >= 500 or code in {408, 429})))
        return response

    @staticmethod
    def _session_json(response: httpx.Response, *, creating: bool = False,
                      expected_session_id: str | None = None) -> dict[str, Any]:
        try:
            if len(response.content) > 2_000_000:
                raise ValueError
            value = response.json()
            if not isinstance(value, dict):
                raise ValueError
            sid = value.get("session_id")
            if not isinstance(sid, str) or not _SESSION_ID.fullmatch(sid):
                raise ValueError
            if value.get("status") not in _SESSION_STATUSES:
                raise ValueError
            if expected_session_id is not None and sid != expected_session_id:
                raise ValueError
            detail = value.get("status_detail")
            if detail is not None and not isinstance(detail, str):
                raise ValueError
        except (ValueError, TypeError):
            if creating:
                raise DispatchUnknown("create response is malformed; acceptance is unknown") from None
            raise DevinAPIError("provider session response is malformed", retryable=False) from None
        return value

    def create_session(self, prompt: str, max_acu_limit: int,
                       repos: list[str], job_id: str) -> dict[str, Any]:
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("prompt must be nonempty")
        if not isinstance(max_acu_limit, int) or isinstance(max_acu_limit, bool) or max_acu_limit <= 0:
            raise ValueError("max_acu_limit must be a positive integer")
        if (not isinstance(repos, list) or not repos
                or any(not isinstance(repo, str) or not _REPO.fullmatch(repo)
                       or any(part in {".", ".."} for part in repo.split("/")) for repo in repos)):
            raise ValueError("repos must contain owner/name repository identifiers")
        if not isinstance(job_id, str) or not _JOB_ID.fullmatch(job_id):
            raise ValueError("job_id must be a stable identifier")
        payload = {
            "prompt": prompt, "max_acu_limit": max_acu_limit, "repos": repos,
            "tags": ["devin-guard", f"job:{job_id}"],
            "resumable": True, "memory_enabled": False,
            "structured_output_required": True,
            "structured_output_schema": copy.deepcopy(ANALYSIS_RESULT_SCHEMA),
        }
        response = self._request("POST", self._path(), payload=payload, creating=True)
        return self._session_json(response, creating=True)

    def get_session(self, session_id: str) -> dict[str, Any]:
        response = self._request("GET", self._path(session_id))
        return self._session_json(response, expected_session_id=session_id)

    def cancel_session(self, session_id: str) -> None:
        """Request documented DELETE termination; a 2xx is not a no-charge guarantee."""
        self._request("DELETE", self._path(session_id))
