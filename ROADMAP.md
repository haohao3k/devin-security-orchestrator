# Roadmap

This repository is a **v0.1 implementation starter**. It currently supplies a
persistent investigation state machine, a Devin API adapter, a bounded worker,
an authenticated control API, a candidate-scoped verification gate, and an
offline evaluation scorer. It is not a deployed autonomous security platform.

The [claim-to-code ledger](docs/claims.md) maps the architecture discussed before
this repository existed to working code and unfinished work. Items below have
acceptance criteria, not delivery-date promises.

## P0 — Establish a trustworthy live operating loop

- [ ] **Run and document an authorized live Devin smoke test.** Use an owned test
  repository and a pinned commit. Record provider creation/poll/termination
  behavior, actual usage, the local deadline, and the final unverified result.
  Publish sanitized execution evidence. Mock HTTP tests do not satisfy this.
- [ ] **Enforce provider permissions outside the prompt.** Configure and test a
  read-only repository identity, restricted service-user permissions, denied
  production access, and an appropriate execution/network policy. Confirm that
  forbidden writes and child-session creation fail at the permission boundary.
  Passing `repos` or telling the model to behave is insufficient.
- [ ] **Reconcile ambiguous dispatch and uncertain termination.** Add a reviewed
  operator workflow that binds a discovered remote session to its persisted job,
  confirms its actual state, and records evidence before releasing an admission
  slot or authorizing another charged attempt. Exercise crashes before/after
  POST and accepted-but-unconfirmed DELETE responses. Never resolve ambiguity
  by blindly replaying creation.
- [ ] **Resume partial work into a new session.** Export scoped checkpoints,
  reviewed evidence references, and unresolved paths from prior attempt events;
  validate that their context still matches before adding them to a new prompt.
  Existing restart recovery only resumes polling the same remote session.
- [ ] **Operate the scheduler and database reliably.** Add health monitoring for
  overdue work, slot exhaustion, stale leases, and provider throttling; test
  restart and backup/restore procedures. Set the same active-session limit across
  every worker. Reconcile local records with provider usage and billing.
- [ ] **Strengthen evidence and service identity boundaries.** Retrieve verifier
  artifacts and verify their digests; add scoped service identities, credential
  rotation, retention controls, and tamper-evident evidence storage. Current API
  role tokens and append-only application events do not prevent a database
  administrator from altering records.

**Exit condition:** the owned-repository smoke run is reproducible, credentials
are constrained, interrupted sessions are accounted for, and independent review
is required before a candidate can be dismissed. No production release authority
is enabled at this stage.

## P1 — Add discovery, bounded scopes, and real evaluation

- [ ] **Integrate candidate discovery.** Add version-pinned Semgrep and CodeQL
  adapters with structured result ingestion, stable candidate identities, and
  explicit scan-completion records. Integrate Trivy separately for dependency
  and artifact findings. Record scanner versions, rule packs, supported
  languages, skipped paths, and analysis failures in the evidence context.
- [ ] **Implement GitHub event intake.** Verify webhook signatures, authorize the
  repository, deduplicate deliveries, bind the exact PR head/base, and supersede
  obsolete runs. The current `/v1/runs` endpoint is for a trusted planner; it is
  not a GitHub webhook receiver.
- [ ] **Build dependency-aware invalidation.** Construct and validate source,
  call, configuration, and external-dependency footprints. Preserve
  cross-module edges. Reuse a verdict across different Git trees only when the
  relevant footprint is proven unchanged; otherwise fall back to today's
  whole-tree invalidation.
- [ ] **Split investigations within explicit budgets.** Add a planner that
  partitions oversized hypotheses, preserves shared dependencies and unresolved
  edges, caps the total parent/child budget, and aggregates every required child
  before completion. Current jobs are bounded; they are not automatically split.
- [ ] **Collect real benchmark runs.** Implement licensed, versioned OWASP
  Benchmark and PrimeVul adapters plus authorized private held-out PRs. Keep
  labels/CVE metadata outside the bot workspace. Compare pinned baselines on the
  same inputs, independently adjudicate root causes, and report precision,
  recall, false alerts, abstentions, timeouts, cost, and uncertainty. The supplied
  toy scorer fixtures are not benchmark results.

**Exit condition:** known-positive and expected-safe cases run through discovery
and investigation with an explicit coverage manifest, independent scoring, and
measured budget/completion behavior. Large-repository coverage is reported rather
than inferred from a successful worker invocation.

## P2 — Add Strix, remediation, and independent validation

- [ ] **Integrate Strix through an isolated runner.** Pin a reviewed upstream
  version; target only owned application copies; use restricted network access,
  disposable identities, bounded resources, and a durable execution record.
  The Strix runner must return evidence tied to the same source/environment
  context. No Strix adapter or pentest execution exists in v0.1.
- [ ] **Build an independent verification oracle.** Reproduce supported findings
  in disposable environments using verifier-owned tests and fixtures. Separate
  static review from dynamic reproduction and preserve execution artifacts.
  A well-formed receipt or an AI-generated test alone is not a proof.
- [ ] **Add a Devin remediation lane.** Start from an independently confirmed
  finding, create a scoped patch and regression tests on a branch, and open a PR.
  Enforce file/write restrictions and keep verifier credentials, release
  configuration, and protected tests outside that lane's authority.
- [ ] **Challenge and review patches independently.** Check the original
  vulnerability before/after the patch, test for regressions and introduced
  behavior, and review the full diff. A second Devin session can supply another
  opinion but cannot provide the sole approval for the first session's work.

**Exit condition:** a controlled vulnerable fixture is independently confirmed,
patched, revalidated against verifier-controlled checks, and presented as a PR
with evidence. Automatic merge and production deployment remain disabled.

## P3 — Connect release governance and runtime feedback

- [ ] **Publish required GitHub security checks.** Bind decisions to the exact
  current commit, complete scan manifest, and verifier evidence; reject stale,
  missing, or partial results. Configure branch protection separately and verify
  that agents cannot edit or bypass the required policy.
- [ ] **Bind release decisions to built artifacts.** Record provenance, SBOM,
  image/artifact digests, and independent verification for the artifact actually
  deployed. Test commit/artifact mismatch and post-review change handling.
- [ ] **Add OPA policy evaluation.** Specify and test the policy input contract,
  exception workflow, and failure behavior. The current Python candidate gate
  is not an OPA integration or an authorization to release.
- [ ] **Add runtime/SIEM feedback.** Map authorized runtime findings, dependency
  advisories, and configuration changes to deployed artifacts and relevant
  investigations. Require evidence before reopening, suppressing, or resolving
  findings; test stale and duplicate events.
- [ ] **Extend coverage to design and AI-agent governance.** Link approved
  requirements and threat models to explicit security acceptance criteria;
  inventory agent/MCP tools and identities; enforce and test their allowed
  actions. Record which lifecycle stages and trust boundaries are actually
  covered before describing the system as protection for the entire AIDLC.
- [ ] **Evaluate deployment-scale components when justified.** Temporal for
  more complex durable workflows, Redis for measured queue/cache needs, and
  Kubernetes for worker isolation and scheduling remain optional architecture
  work. Introduce each with failure tests and an explicit operational benefit;
  none is a dependency or deployed capability today.

**Exit condition:** required checks and deployment policy enforce complete,
independently verified evidence for the exact deployed artifact. This milestone
requires a separate deployment and access-control review; passing the current
candidate gate does not satisfy it.
