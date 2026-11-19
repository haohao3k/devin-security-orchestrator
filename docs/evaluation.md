# Evaluation: implemented scorer, future benchmark runs

## Current status

Implemented: an offline JSONL scorer, malformed-input checks, timeout accounting,
and unit tests. The examples contain hand-written toy fixtures. **No Devin
benchmark has been run, and this repository reports no measured detection
accuracy.** The scorer is plumbing for a future evaluation, not proof that the
agent finds vulnerabilities.

The scorer does not call Devin or another model. It does not execute proof inputs,
review source code, or verify a report's line number. Its inputs must be prepared
and adjudicated independently of the investigating bot.

## Input boundary

Two files enter the evaluator:

1. **Labels**, kept outside the bot workspace. Each row identifies one target
   vulnerability or one expected-safe case.
2. **Predictions**, collected from completed or interrupted runs and mapped to
   target identities by an independent evaluator.

Example label:

```json
{"case_id":"case-17","vulnerable":true,"root_cause_id":"tenant-authorization-boundary"}
```

Example prediction format, shown with placeholder evidence:

```json
{
  "case_id": "case-17",
  "status": "completed",
  "findings": [{
    "root_cause_id": "tenant-authorization-boundary",
    "path": "src/accounts.py",
    "line": 42,
    "evidence": "Independent evaluator's reference to reviewed trace or reproduction artifact"
  }],
  "cost_usd": 0.0,
  "duration_seconds": 30.0
}
```

Both files use **one JSON object per line**; the expanded example above only
illustrates fields. Prediction status is `completed`, `incomplete`, or `error`.
Each finding requires nonempty `root_cause_id`, `path`, and `evidence` strings and
a positive integer `line`. Costs and durations must be finite, nonnegative
numbers. The example cost is a placeholder, not a Devin price or measurement.

**A bot cannot award itself a correct `root_cause_id`.** An independent evaluator
maps its raw explanation, affected location, and evidence to the hidden target.
Arbitrary self-asserted matches are not valid evaluation inputs. For runnable
cases, the evaluator should use independently executed reproduction checks.
For cases without an executable oracle, record reviewed static evidence and the
reviewer's decision. Keep that distinction in the report.

The current label schema does not contain an expected source location. Location
correctness must therefore be adjudicated before scoring. Automatic trace and
location matching is on the roadmap.

When `root_cause_id` is omitted from a positive label, any completed finding
counts as a classification hit. The output exposes the number of these
`classification_only_cases`; such scores cannot support claims of correct
root-cause identification. A release-quality experiment should provide target
identities for every positive case.

## Exact scoring rules

| Output | Definition |
| --- | --- |
| `tp` | Vulnerable cases with a completed report containing the expected root cause; at most one credit per case |
| `fn` | Every other vulnerable case, including missing predictions, errors, timeouts, and wrong-root reports |
| `fp` | Expected-safe cases containing at least one reported finding, even if the run is incomplete |
| `tn` | Expected-safe cases completed without findings |
| `false_alerts` | Individual findings on safe cases, plus findings with the wrong root cause on vulnerable cases |
| `precision` | `tp / (tp + false_alerts)`: alert precision that penalizes invented extra findings |
| `case_precision` | `tp / (tp + fp)`: conventional case precision, which alone does not penalize extra wrong-root reports |
| `recall` | `tp / positive_cases`: end-to-end recall; every labeled positive remains in the denominator |
| `false_positive_rate` | `fp / (fp + tn)`; incomplete safe cases without findings are excluded as unresolved |
| `completion_rate` | Completed cases divided by all labeled cases |
| `cost_per_true_positive` | Reported total cost divided by credited target detections |

An incomplete safe case without alerts is an **abstention**, not a true negative.
The output includes `abstained_safe_cases` and the exact FPR denominator. FPR must
always be published alongside completion and abstention counts; a system cannot
earn a clean result simply by stopping work. Matching findings from incomplete
positive runs are recorded as `unconfirmed_matching_alerts`, without TP credit.
Repeated correct findings yield no extra TP credit and are counted separately.

Undefined ratios are JSON `null`, not zero or one. Runtime p50/p95 use linear
interpolation over submitted observations, including interrupted runs. Missing
predictions have unknown cost and duration, so they are excluded from those
totals and counted explicitly; those totals may therefore be incomplete.

The evaluator rejects duplicate labels, duplicate predictions, unknown case IDs,
malformed findings, invalid status values, and nonfinite or negative numeric
inputs. Costs should come from reconciled provider usage records and a recorded
pricing policy, not an estimate invented by the agent. This repository has no
live billing reconciliation integration yet.

## Running the scorer

From Python:

```python
from devin_guard.evaluation import score_files

report = score_files("private-labels.jsonl", "adjudicated-predictions.jsonl")
```

Run its tests without extra test libraries:

```sh
python -m unittest discover -s tests -p 'test_evaluation.py' -v
```

The [toy fixtures](../examples/evaluation/README.md) exercise a correct finding,
a false alarm, a missed vulnerability, a timeout, and missing work. They verify
scoring behavior only.

## Roadmap: datasets and collection harness

| Dataset or work | Intended purpose | What remains |
| --- | --- | --- |
| [OWASP Benchmark](https://owasp.org/projects/benchmark) | Labeled vulnerable and safe web-application test cases; false-alarm diagnostics | Pin a release/commit, review license, build a runnable harness, hide expected-result files, and collect actual runs |
| [PrimeVul](https://github.com/DLVulDet/PrimeVul) | Vulnerable/patched C/C++ function pairs and subtle root-cause distinctions | Pin a dataset release, review provenance/license, import held-out pairs, separate metadata from inputs, independently adjudicate reports |
| Private held-out repository snapshots and PRs | Evaluate cross-file context, real workflow cost, and generalization beyond public examples | Obtain authorized snapshots, curate target labels and safe controls, isolate the test set from tuning, and collect repeated runs |
| Raw-output adjudication | Convert untrusted agent reports into defensible scorer inputs | Build an independent evidence/reproduction pipeline and reviewer workflow |
| Live cost and trace capture | Measure budget, timeout, and cache behavior | Reconcile Devin usage, preserve execution receipts, and record uncached/cached cohorts separately |

OWASP documents expected results for true and false findings. PrimeVul documents
paired vulnerable/patched functions and supplies vulnerability and commit
metadata. Those metadata fields can reveal the answer and must stay on the
evaluator side. Neither dataset is bundled here.

Public benchmarks may have been seen during model training. Hiding the labels
does not remove memorization risk. Keep related vulnerable/patched samples and
near-duplicates in the same split, split by repository before tuning, and use
private holdouts as the primary generalization check. A patched function is
negative for the **targeted flaw**, not a proof that the entire project has no
other vulnerabilities. Newly reported issues need independent adjudication
instead of being silently scored as known true positives.

Compare the same snapshots and intended vulnerability categories with a pinned
Semgrep baseline, documenting language support, rule pack, exclusions, compute
limits, and pipeline inputs. Report the complete bot pipeline separately from
the incremental contribution of Devin if Semgrep supplies candidate findings.
Do not compare a function-only dataset to a fully built repository pipeline
without describing that change in context. Publish thresholds before the final
holdout run; include per-category results, abstentions, and uncertainty intervals.

Benchmark adapters, dataset execution, repeated live runs, independent dynamic
verification, statistical intervals, and benchmark leaderboards remain roadmap
items. No result produced from the toy fixtures substantiates those claims.
