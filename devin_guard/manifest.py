"""Capture immutable Git inputs without executing repository code."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path, PurePosixPath


def _git(repository: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repository), *args], check=True, capture_output=True,
            text=True, timeout=30,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise ValueError("Unable to read the requested Git snapshot") from exc
    return result.stdout.strip()


def snapshot(repository_path: str | Path, ref: str, environment: dict,
             policy_version: str = "review-v1") -> dict:
    """Return commit+tree identifiers and an explicit external-environment digest.

    This deliberately uses the ENTIRE tree: a partial dependency map is not a
    valid reason to reuse a security verdict. Working-tree edits are not inputs.
    The caller must describe external dependencies/runtime in ``environment``.
    """
    if not isinstance(ref, str) or not ref or ref.startswith("-") or "\x00" in ref:
        raise ValueError("ref must be a Git reference or commit, not an option")
    if not isinstance(environment, dict) or not environment:
        raise ValueError("an explicit, nonempty environment manifest is required")
    if not isinstance(policy_version, str) or not policy_version.strip():
        raise ValueError("policy_version is required")
    repo = Path(repository_path).resolve(strict=True)
    commit = _git(repo, "rev-parse", "--verify", "--end-of-options", ref + "^{commit}")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("this version supports SHA-1 Git repositories only")
    tree = _git(repo, "rev-parse", "--verify", commit + "^{tree}")
    payload = json.dumps(environment, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return {
        "commit_sha": commit,
        "context": {
            "tree_sha": tree,
            "environment_digest": hashlib.sha256(payload.encode()).hexdigest(),
            "policy_version": policy_version,
        },
    }


def check_candidate_paths(repository_path: str | Path, commit_sha: str,
                          candidates: list[dict]) -> None:
    """Require every candidate to refer to a tracked blob at the pinned commit."""
    if not re.fullmatch(r"[0-9a-f]{40}", commit_sha):
        raise ValueError("commit_sha must be a full lowercase SHA")
    repo = Path(repository_path).resolve(strict=True)
    for candidate in candidates:
        path = candidate.get("path")
        if not isinstance(path, str) or not path or "\x00" in path or "\\" in path:
            raise ValueError("invalid candidate path")
        if PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts:
            raise ValueError("candidate path must stay in the repository")
        if _git(repo, "cat-file", "-t", commit_sha + ":" + path) != "blob":
            raise ValueError("candidate path must identify a tracked file")
