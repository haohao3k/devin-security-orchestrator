# Devin integration: implementation and limits

This adapter uses the official organization-scoped Devin Cloud v3 API. The
provider behavior has been tested with `httpx.MockTransport`; no live Devin
session, real repository vulnerability evaluation, or production deployment was
performed. The tests establish orchestration behavior, not detection accuracy.

## Provider contract

| Operation | Endpoint | Implemented behavior |
| --- | --- | --- |
| Create | `POST /v3/organizations/{org_id}/sessions` | One request only; persist a dispatch marker first. |
| Observe | `GET /v3/organizations/{org_id}/sessions/{devin_id}` | Poll one session once per worker invocation. |
| Terminate | `DELETE /v3/organizations/{org_id}/sessions/{devin_id}` | Best-effort request on deadline or blocking state. |

The client always sends credentials to `https://api.devin.ai/v3`; callers cannot
override that URL. It rejects path-like organization/session IDs, disables HTTP
redirects and environment-proxy discovery, and omits provider response bodies
from error messages. The injected HTTP transport is a trusted test seam, not an
application setting. A production deployment needing a proxy must deliberately
review and add that support; this starter does not inherit proxy environment
variables.

Creation includes `max_acu_limit`, one repository, stable `job:<id>` tags,
`resumable: true`, `memory_enabled: false`, and the required
`structured_output_schema`. The tags support reconciliation; they **do not make
the provider API idempotent**. `max_acu_limit` is a compute budget, not a timer.
The worker persists its own absolute deadline before making the creation call.

The result schema requires:

```json
{
  "verdict": "candidate",
  "summary": "A scoped static-analysis hypothesis requiring verification.",
  "locations": [{"path": "src/api.py", "line": 12, "reason": "Input reaches this call."}],
  "evidence": [{"kind": "static_trace", "detail": "Describe the exact checked path and guards."}],
  "unresolved_paths": []
}
```

Other verdicts are `no_finding` and `incomplete`. Candidate and negative verdicts
must provide at least one code location and evidence item. Schema validity does
not establish that a cited line exists, a trace is correct, or a vulnerability
is real. Both candidate and negative results end in `needs_review`, never a
verified or release-authorized state. Any unresolved path ends in `incomplete`.

## One scheduling step

`Worker.run_once()` is synchronous Python around an asynchronous provider job.
It claims at most one investigation, creates a session only for a new job, and
makes at most one GET. It never contains a sleep loop. Each provider request has
a configured HTTP timeout; a scheduler should call the worker repeatedly.

For an active session it stores the provider status, usage when available, and
valid partial structured output as an unverified checkpoint. Invalid partial
output is recorded as such and does not stop a still-running session. The worker
releases its lease until the next poll. Another process can pick up the same
stored session ID and deadline. A process restart does not reset the deadline,
increment the analysis attempt, or submit a new session.

The worker heartbeats before provider operations, and every state mutation uses
a fenced lease token. The default lease is 120 seconds and the HTTP timeout is
10 seconds. A genuinely stalled call can still outlive its lease; fencing stops
that worker from committing late results. If a successful create response
arrives after its lease expired, the worker requests termination of that newly
identified session and leaves reconciliation to the durable state machine.

## Failure semantics

| Observation | Local outcome |
| --- | --- |
| `running` plus `status_detail=finished`, valid final output | `needs_review`, with independent verification still required. |
| `suspended`, quota/credit exhaustion, error, unexplained exit | `incomplete`; never a clean scan. |
| Waiting for user input or action approval | `incomplete`, with a termination request; approvals are not bypassed. |
| Final structured output malformed or missing | `incomplete`. |
| Active session, transient GET failure or HTTP 429 | Checkpoint and defer; retry GET later within the original deadline. |
| POST timeout, transport failure, HTTP 5xx/408, redirect, or malformed success | `dispatch_unknown`; never automatically retry POST. |
| Explicit POST rejection such as HTTP 401/403/422/429 | `failed`; no automatic POST retry. |
| Crash after dispatch marker but before session ID is saved | Expired dispatch lease becomes `dispatch_unknown`. |
| Absolute deadline exceeded | `incomplete`; request documented DELETE termination if the ID is known. |

A successful DELETE response records `termination_request=accepted`. This is
not proof of immediate process termination or zero further charges. A failed
request records `failed_or_unknown` and requires operator follow-up. If the
session ID is unknown, the worker cannot stop it: inspect the Devin account using
the job tag, reconcile the actual external session, and resolve the record
before authorizing any new charged attempt. Automatic reconciliation and
automatic job splitting are not implemented in this starter.

The persisted deadline is enforced when a worker next runs; it is not a remote
kill timer. If all workers are down, no process is available to send DELETE.
Keep the scheduler supervised and monitor overdue jobs and unknown dispatches.
HTTP timeouts are also transport phase limits, not an end-to-end service SLA.

## Analysis boundaries and permissions

The prompt pins repository, commit, full tree, environment digest, policy
version, analysis version, and one CWE hypothesis. It requests static
source-to-sink reasoning, contrary evidence, concrete locations, and explicit
missing context. It forbids invented CVE identifiers, source edits, executing
repository code, child sessions, merges, and deployment. It treats repository
content and scanner text as untrusted data.

These prompt instructions are not a security sandbox. Before live use, enforce
read-only repository permissions, a restricted Devin service-user role,
appropriate network and execution policy, and no production credentials in the
actual provider environment. Passing `repos` scopes task context; this code does
not claim that it is an authorization boundary. The supplied environment digest
is an analysis input, not an attestation that Devin booted that exact image.
Independent verification must check source/environment binding and evidence.

No deployment gate may treat a schema-valid agent response or a static trace as
a proof. A separate trusted verifier owns confirmation/dismissal. This starter
does not implement an exploit runner, patched-code deployment, or a guarantee
that huge repositories are completely covered. Repository candidate generation
and broad coverage remain outside the provider adapter.

## Official references checked for this implementation

- [Create Session](https://docs.devin.ai/api-reference/v3/sessions/post-organizations-sessions): request fields and response shape.
- [Get Session](https://docs.devin.ai/api-reference/v3/sessions/get-organizations-session): session status/detail and structured output.
- [Terminate Session](https://docs.devin.ai/api-reference/v3/sessions/delete-organizations-sessions): DELETE termination endpoint.
- [Common Flows](https://docs.devin.ai/api-reference/common-flows): asynchronous creation and polling.

Documentation was checked on 2026-11-19. No universal numeric rate/concurrency
allowance or exactly-once creation guarantee is assumed. Set concurrency from
the actual account entitlement and monitor HTTP 429s and compute consumption.
