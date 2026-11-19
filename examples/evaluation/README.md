# Toy scorer fixtures

These six invented labels and five invented predictions test the accounting
code. They are **not** samples from OWASP Benchmark or PrimeVul, are **not** Devin
outputs, and do not measure this project's detection accuracy. The costs and
durations are arbitrary fixture values, not measured API charges or timings.

The deliberately missing sixth prediction tests that an absent run remains
incomplete instead of becoming a clean result. One positive times out and another
reports the wrong root cause; both remain missed target vulnerabilities.

Run from the repository root:

```sh
python -c 'import json; from devin_guard.evaluation import score_files; print(json.dumps(score_files("examples/evaluation/toy-labels.jsonl", "examples/evaluation/toy-predictions.jsonl"), indent=2))'
```

Keep `toy-labels.jsonl` on the evaluator side. Even in a future real benchmark,
the bot must never receive the answer file or vulnerability metadata revealing
the target.
