# Devin Security Orchestrator

A working control-plane prototype for bounded security investigations using Devin.
It persists investigation state, deduplicates equivalent work across PRs, tracks
asynchronous Devin sessions, and requires a separate verifier before accepting a verdict.

**Status: v0.1.** The state machine, API adapter, authenticated control API, CLI,
offline demo, and evaluation scorer are implemented. Live Devin behavior and real
vulnerability-detection performance have **not** been benchmarked. Strix integration,
automated fixes, and production release enforcement are on the [roadmap](ROADMAP.md).
The [claim ledger](docs/claims.md) maps the original architecture claims to code or planned work.

## Run it

Python 3.11+ is required; the locked environment and CI use Python 3.12.

```bash
git clone https://github.com/haohao3k/devin-security-orchestrator.git
cd devin-security-orchestrator
python -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r requirements.lock
python -m devin_guard demo
python scripts/run_tests.py
```

The demo makes **zero real Devin requests**. It runs the real worker and database
against `httpx.MockTransport`, closes and reopens the database, and demonstrates:

- An agent's `no_finding` result remains `needs_review`; the gate stays blocked.
- A synthetic verifier receipt dismisses the example hypothesis.
- A second PR with the identical source tree/context reuses the existing investigation.
- A changed tree creates a new investigation and blocks the new run.

The demo prints `mode: offline_simulation` and `release_authorized: false`.
Its synthetic verdict is not security evidence about any real application.

## What exists today

| Capability | Implementation | Boundary |
|---|---|---|
| Persistent state | SQLite and PostgreSQL in `state.py` | PostgreSQL parity tests require a real database; CI provisions one. |
| Cross-PR deduplication | Stable finding fingerprint plus context digest | Reuse requires the entire Git tree, hypothesis, environment, policy, and analysis version to match. |
| Bounded concurrent work | Transactional admission cap, leases and fencing | Every worker must use the same configured cap. Unresolved dispatch/cancellation reserves capacity. |
| Devin integration | Official v3 session create, poll, structured results and terminate requests | Transport tests use mocked HTTP; live credentials are required for a real session. |
| Restart recovery | Persisted session ID, absolute deadline and partial evidence checkpoints | Existing remote sessions resume polling; new-session continuation from past evidence is roadmap. |
| Independent verification | Separate controller/verifier credentials; receipts bound to commit and context | A trusted verifier supplies the evidence. Automatic reproduction and receipt signing are roadmap. |
| Gate | `pass`, `fail`, or `blocked`; CLI returns nonzero for fail/blocked | Scope is only the submitted candidates. It never authorizes a production release. |
| Evaluation | JSONL scorer with false-alert, recall, timeout and cost accounting | Included cases are synthetic; no OWASP, PrimeVul, or private-PR scores are claimed. |

## How state reuse works

Finding identity excludes the PR number and commit SHA:

```python
fingerprint = sha256(repository + cwe + path + symbol + source + sink)
context_digest = sha256(full_tree + environment + policy + analysis_version + hypothesis)
```

The implementation uses canonical JSON, not ambiguous string concatenation.
One unique `(fingerprint, context_digest)` identifies the investigation; multiple
PR runs can link it. Evidence keeps its original commit even when a later commit
has the identical tree. Different hypotheses about the same function do not share
a dismissal. Incomplete/failed work remains blocking, rather than becoming cached success.

**The current invalidation policy is deliberately conservative:** any tracked-file
change invalidates reuse, including changes unrelated to the hypothesis. Selective
dependency-aware reuse needs a trustworthy dependency graph and is not implemented.
The explicit environment manifest must identify external runtime/dependency/configuration
changes that Git cannot capture. The trusted planner is responsible for its completeness.

## Job lifecycle

```mermaid
flowchart TD
  P["Pinned candidate"] --> Q["Queued"]
  Q --> D["Persist dispatch intent"]
  D --> R["Persist session ID and poll"]
  D --> U["Unknown dispatch: block"]
  R --> C["Checkpoint and release lease"]
  C --> R
  R --> I["Timeout or insufficient evidence: incomplete"]
  R --> V["Needs independent review"]
  V --> F["Confirmed: fail"]
  V --> N["Dismissed: scoped pass"]
```

A POST timeout can mean a paid Devin session exists even if its ID was lost.
The worker records `dispatch_unknown` and will not blindly resubmit. A deadline
causes a termination request and an incomplete result; accepted cancellation is
not proof of shutdown. Such unresolved jobs keep their capacity slot and require
operator reconciliation, which is explicitly on the roadmap.

## Plan a real investigation

The initial version takes hypotheses from a trusted operator or CI planner.
Automatic scanner discovery and public GitHub webhook ingestion are not wired in yet.

```bash
python -m devin_guard init
python -m devin_guard plan \
  --repo . \
  --repository haohao3k/devin-security-orchestrator \
  --ref HEAD \
  --pr 1 \
  --candidates examples/candidates.json \
  --environment examples/environment.json
```

The planner resolves an immutable commit/tree and verifies candidate paths exist
in it. It does not execute the repository. The example candidate targets the safe
`examples/toy_app.py` fixture; replace both input files for your own repository.
The example environment is illustrative, not a description of your deployment.

Set `DEVIN_ORG_ID` and `DEVIN_API_KEY` through your environment or secret manager,
then run a live scheduling step:

```bash
python -m devin_guard worker --max-acu 5 --wall-seconds 900
```

This command **can consume Devin account credits**. `--loop` polls continuously;
without it, the worker performs one bounded scheduling step. `max_acu_limit` is the
provider compute limit. The wall-clock deadline is enforced by this scheduler when
it runs; it is not an always-on remote kill switch. Provider availability, account
permissions and quotas still apply. Keep a worker running for timely deadline handling.

```bash
python -m devin_guard job INV_ID
python -m devin_guard events INV_ID
python -m devin_guard run RUN_ID
python -m devin_guard gate RUN_ID
```

Live analysis is read-only by instruction and asks Devin to trace one hypothesis,
inspect callers/callees and guards, cite code locations, and report missing context.
Those instructions are **not access controls**. Configure a read-only Devin service
identity and restricted environment before using real repositories. Do not give
Devin database credentials, controller/verifier tokens, or production access.

## Control API and verifier boundary

Generate **different** random controller and verifier tokens, each at least 32 characters.
Provide them as `CONTROL_TOKEN` and `VERIFIER_TOKEN`; never commit populated `.env` files.
Start a local API server:

```bash
python -m uvicorn devin_guard.api:create_app_from_env --factory --host 127.0.0.1 --port 8080
```

| Endpoint | Credential | Purpose |
|---|---|---|
| `POST /v1/runs` | Controller | Submit an authenticated plan and trusted input manifest. |
| `GET /v1/runs/{id}` | Controller or verifier | Inspect the run and investigations. |
| `GET /v1/runs/{id}/gate` | Controller or verifier | Obtain the scoped gate decision. |
| `GET /v1/investigations/{id}` | Controller or verifier | Inspect evidence and state; lease tokens are removed. |
| `GET /v1/investigations/{id}/events` | Controller or verifier | Read the persisted event history. |
| `POST /v1/investigations/{id}/retry` | Controller | Explicitly retry eligible failures within the attempt budget. |
| `POST /v1/investigations/{id}/verify` | Verifier | Independently confirm or dismiss a completed investigation. |

Verification request shape:

```json
{
  "verdict": "dismissed",
  "evidence": {
    "commit_sha": "exact investigated commit SHA",
    "context_digest": "exact stored investigation context digest",
    "artifact_sha256": "SHA-256 of the independently reviewed evidence artifact",
    "method": "description of the independent review or reproduction"
  }
}
```

The store validates digest formats and bindings, and records the server-configured
`VERIFIER_ID`. It does **not** fetch or authenticate the artifact itself. The separate
verifier is a trust boundary, not proof that an exploit was reproduced. A controller
credential cannot approve a finding, and neither an agent result nor valid JSON
can pass the gate alone. Direct database/CLI access is an administrative capability.

## PostgreSQL and tests

The default local backend is SQLite. Use PostgreSQL by supplying `DATABASE_URL`:

```bash
export DATABASE_URL='postgresql://USER:PASSWORD@HOST/DATABASE'
python -m devin_guard init
```

For integration tests, point `TEST_POSTGRES_URL` at a **dedicated test database**:

```bash
export TEST_POSTGRES_URL='postgresql://USER:PASSWORD@HOST/TEST_DATABASE'
python scripts/run_tests.py --require-postgres
```

The PostgreSQL tests create/drop uniquely named schemas. Without this variable,
those tests are explicitly skipped. GitHub Actions runs the same suite with an
ephemeral PostgreSQL service. Tests exercise cache invalidation, concurrent claims,
fenced leases, ambiguous dispatch, restart recovery, cancellation uncertainty,
role separation, and gate failures. Test output is saved to `artifacts/test-report.json`.

Application event history has no update/delete API; database administrators can
still alter it. Tamper-evident signatures, retention controls, TLS deployment,
tenant isolation and production operations are not claimed by this prototype.

## Evaluation

```bash
python -m devin_guard score \
  --labels examples/evaluation/toy-labels.jsonl \
  --predictions examples/evaluation/toy-predictions.jsonl
```

This exercises the scorer, not Devin accuracy. Positive-case timeouts count as missed
detections; incomplete safe cases do not become true negatives. Wrong-root findings
are false alerts and cannot rescue a missed target. Empty denominators produce `null`.
Independent adjudication must map evidence to hidden labels; the scorer does not
authenticate findings. See [evaluation protocol](docs/evaluation.md).

## Next work

See [ROADMAP.md](ROADMAP.md) for acceptance criteria and [docs/claims.md](docs/claims.md)
for the status of every proposed component. The next gate is a small live Devin smoke
run with external permissions enforced, followed by a real held-out evaluation.
There are no published detection benchmarks for this project yet.

## References

- [Devin API session creation](https://docs.devin.ai/api-reference/v3/sessions/post-organizations-sessions)
- [Devin session status](https://docs.devin.ai/api-reference/v3/sessions/get-organizations-session)
- [Devin integration boundaries](docs/devin-integration.md)
- [State and evidence semantics](docs/state.md)
- [OWASP Benchmark](https://owasp.org/www-project-benchmark/) — planned evaluation source.
- [PrimeVul](https://github.com/DLVulDet/PrimeVul) — planned paired-function evaluation source.
- [Strix](https://github.com/usestrix/strix) — planned sandbox testing adapter.

MIT licensed. This repository is an independent integration project.
