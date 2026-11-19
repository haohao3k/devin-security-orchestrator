# Claim-to-code ledger

This ledger distinguishes what the v0.1 repository implements from what the
earlier architecture proposed. **Implemented** means executable code exists;
it does not mean a live Devin account, production deployment, or external
benchmark has been exercised.

Local tests cover the SQLite state machine, API boundaries, evaluator behavior,
and mocked Devin HTTP interactions. PostgreSQL support and parity tests exist;
an actual PostgreSQL run must be reported separately from skipped tests. No
live Devin accuracy, throughput, scale, or cost result is claimed here.

| Earlier claim | Current code or behavior | Remaining work |
| --- | --- | --- |
| Devin bots are central to security investigation | [`devin.py`](../devin_guard/devin.py) and [`worker.py`](../devin_guard/worker.py) create and observe one scoped analysis session per investigation | Live provider smoke test and deployed account permissions; autonomous fleet planning remains P0/P1 |
| Async sessions avoid holding one request open for the whole analysis | Creation returns a session identity; subsequent worker invocations poll the persisted ID | A live smoke run and operational supervision; no guarantee that any repository finishes within a fixed time |
| Jobs have compute and wall-clock budgets | `max_acu_limit`, a persisted absolute deadline, per-request HTTP timeouts, and a configured active-session cap | Cross-job cost policy, usage reconciliation, and verified remote termination; a local deadline is not a provider-side kill timer |
| Oversized work is split and requeued | Explicit bounded retries exist for eligible failed/incomplete work | Automatic splitting, parent/child coverage aggregation, and partition budgets are P1 |
| State and memory live outside the model | [`state.py`](../devin_guard/state.py) persists runs, investigations, sessions, results, receipts, and events using SQLite or PostgreSQL | Deployment, backup/restore, retention, and operational monitoring are P0 |
| Unique jobs prevent duplicate concurrent investigations | Unique finding/context identity, atomic claims, admission control, and fenced leases | Provider-side exactly-once creation is not claimed; ambiguous POSTs require reconciliation |
| Findings survive across PRs | Stable finding fingerprints exclude PR number and commit ID; new runs can link existing evidence | Evidence is reused only under the documented context rules, not merely because the CWE/path looks familiar |
| Relevant dependency changes invalidate memory | Whole Git tree, explicit environment digest, policy version, analysis version, and complete candidate content bind the current cache | Selective dependency/call-graph invalidation across different trees is P1; even unrelated tracked-file changes invalidate v0.1 results |
| Different hypotheses do not inherit each other's dismissal | Complete normalized candidate content, including its description, enters the evidence-context digest | Semantic equivalence/deduplication of differently worded hypotheses remains P1 |
| Progress survives process restarts | Partial structured output and provider status are checkpointed; another worker resumes the same stored session ID/deadline | Supplying old checkpoints to a **new** Devin session is P0; this version does not claim cross-session reasoning continuity |
| Timeouts never become a clean scan | Incomplete, failed, ambiguous, unverified, and empty-candidate runs block the candidate gate | Remote-session reconciliation and full scan-coverage aggregation remain P0/P1 |
| Unknown dispatch is handled safely | Persist dispatch intent before POST; ambiguous outcomes become `dispatch_unknown` and cannot automatically retry | Reviewed operator attach/resolve workflow and provider reconciliation are P0 |
| Accepted cancellation proves the session stopped | **Not claimed.** An uncertain cancellation retains an admission slot and blocks retries | Confirm actual provider termination and release the slot through an audited resolution workflow, P0 |
| Devin cannot approve its own findings | Workers finish as unverified; [`api.py`](../devin_guard/api.py) separates controller and verifier credentials; verifier-only callers can read evidence without planner write authority | Strong deployment identities, credential isolation, and a real independent verification system are P0/P2 |
| Findings and dismissals require evidence | A verifier receipt binds commit, context digest, artifact hash, method, and verifier identity | Fetching and validating the artifact, checking actual trace/location correctness, and independent reproduction are P0/P2 |
| Immutable evidence provides an audit trail | Application methods append events and preserve original evidence context | Cryptographic tamper evidence, storage retention locks, and defenses against a privileged database editor are P0 |
| The release gate is deterministic | `StateStore.gate()` returns `pass`, `fail`, or `blocked` for the supplied candidates and always `release_authorized: false` | Complete scan manifests, required GitHub checks, production policy, and artifact-bound release authorization are P3 |
| OPA enforces release policy | Not integrated; the current scoped gate is Python code | OPA input contract, policy tests, exceptions, and deployment enforcement are P3 |
| Strix performs dynamic/adversarial testing | No Strix adapter or runner is included | Authorized isolated Strix execution, evidence capture, and versioned integration are P2 |
| Semgrep, CodeQL, and Trivy generate findings | The trusted planner accepts candidate records; no scanner is launched or ingested automatically | Scanner adapters, SARIF/structured result ingestion, provenance, and coverage records are P1 |
| Devin fixes vulnerabilities, writes tests, and opens remediation PRs | The implemented prompt requests static read-only investigation only | Remediation branches, patch generation, tests, PR creation, and independent patch review are P2 |
| Another agent independently validates fixes | No patch-validation agent or exploit/reproduction runner exists | Verifier-controlled baseline/patched execution and independent diff review are P2 |
| The system is protected from prompt injection/tool misuse | Prompt instructions treat source, comments, and task data as untrusted; API outputs remain unverified | Prompts are not enforcement. Provider permissions, execution/network controls, and adversarial validation are P0/P2 |
| Agents have no direct merge or production access | This starter has no merge/deploy code and does not provide production credentials to Devin | The actual Devin/GitHub account permissions must still be restricted and verified before live use, P0 |
| GitHub PR events trigger investigation automatically | A trusted-planner HTTP API and Git snapshot helpers exist | Authenticated webhook ingestion, delivery deduplication, repository allowlists, and superseded-run handling are P1 |
| Benchmarks show it avoids fake vulnerabilities | [`evaluation.py`](../devin_guard/evaluation.py) scores independently prepared labels/predictions; fixtures are explicitly synthetic | Actual OWASP Benchmark, PrimeVul, private-PR runs, independent adjudication, repeated trials, and measured results are P1 |
| Evaluation reports precision, recall, false alarms, timeouts, and cost | The offline scorer computes these from submitted data and reports denominators/abstentions | Live usage reconciliation, result collection, and confidence intervals remain P0/P1; arbitrary inputs do not become verified measurements |
| A context/security graph preserves architectural relationships | Whole-tree/environment manifests exist; there is no security graph | Call/dependency graph construction and validated impact analysis are P1; architecture/runtime relationships extend into P3 |
| Runtime/SIEM findings reopen affected work | No runtime connector is implemented | Authorized event ingestion, artifact mapping, and evidence-backed reopening are P3 |
| Temporal, Redis, and Kubernetes provide orchestration infrastructure | Not integrated; the current worker uses database state and externally scheduled invocations | Evaluate and implement only when the operating requirements justify them, P3 |
| The entire AIDLC is autonomously protected | **Not implemented or claimed by v0.1.** This is an investigation/control-plane starter | Requirements/threat-model review, agent/tool governance, discovery, remediation, release, and runtime stages require later work |

## Evidence boundaries

A passing project test demonstrates a behavior of this implementation. A mocked
provider response demonstrates how the adapter reacts to that response. Neither
establishes that Devin correctly analyzed a real repository.

A schema-valid result is an unverified claim. A well-formed verifier receipt is
an authenticated assertion, not an execution oracle. A `pass` scoped to submitted
candidates is not evidence that all vulnerabilities were discovered or that a
build is safe to deploy.

The [roadmap](../ROADMAP.md) gives acceptance criteria for each unfinished stage.
The [state specification](state.md), [Devin integration notes](devin-integration.md),
and [evaluation protocol](evaluation.md) document the implemented boundaries in
more detail.
