"""Offline scoring against independently curated labels.

This module evaluates submitted predictions. It does not run Devin, inspect code,
reproduce a vulnerability, or establish that an agent's evidence is true.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a nonempty string")
    return value


def _number(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be a finite nonnegative number")
    try:
        number = float(value)
    except (OverflowError, ValueError) as exc:
        raise ValueError(f"{field} must be a finite nonnegative number") from exc
    if not math.isfinite(number) or number < 0:
        raise ValueError(f"{field} must be a finite nonnegative number")
    return number


def _ratio(numerator: int | float, denominator: int | float) -> float | None:
    return numerator / denominator if denominator else None


def _percentile(values: list[float], fraction: float) -> float | None:
    """Linearly interpolate ordered observations, without requiring numpy."""
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _indexed(records: list[dict[str, Any]], kind: str) -> dict[str, dict[str, Any]]:
    if not isinstance(records, list):
        raise ValueError(f"{kind} must be a list of objects")
    indexed: dict[str, dict[str, Any]] = {}
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ValueError(f"{kind}[{index}] must be an object")
        case_id = _text(record.get("case_id"), f"{kind}[{index}].case_id")
        if case_id in indexed:
            raise ValueError(f"duplicate {kind} case_id: {case_id}")
        indexed[case_id] = record
    return indexed


def _validate_label(label: dict[str, Any]) -> None:
    if not isinstance(label.get("vulnerable"), bool):
        raise ValueError(f"{label['case_id']}: vulnerable must be a boolean")
    if "root_cause_id" in label:
        _text(label["root_cause_id"], f"{label['case_id']}.root_cause_id")


def _validate_prediction(prediction: dict[str, Any]) -> None:
    case_id = prediction["case_id"]
    if prediction.get("status") not in ("completed", "incomplete", "error"):
        raise ValueError(f"{case_id}: invalid prediction status")
    if not isinstance(prediction.get("findings"), list):
        raise ValueError(f"{case_id}: findings must be a list")
    _number(prediction.get("cost_usd"), f"{case_id}.cost_usd")
    _number(prediction.get("duration_seconds"), f"{case_id}.duration_seconds")
    for index, finding in enumerate(prediction["findings"]):
        prefix = f"{case_id}.findings[{index}]"
        if not isinstance(finding, dict):
            raise ValueError(f"{prefix} must be an object")
        for key in ("root_cause_id", "path", "evidence"):
            _text(finding.get(key), f"{prefix}.{key}")
        if (
            isinstance(finding.get("line"), bool)
            or not isinstance(finding.get("line"), int)
            or finding["line"] < 1
        ):
            raise ValueError(f"{prefix}.line must be a positive integer")


def score_cases(
    labels: list[dict[str, Any]], predictions: list[dict[str, Any]]
) -> dict[str, Any]:
    """Score one target vulnerability per labeled case.

    ``precision`` is alert precision: credited target detections divided by
    credited detections plus false alerts. ``case_precision`` is the conventional
    TP/(TP+FP) case metric. Wrong-root-cause alerts on vulnerable cases lower the
    former and count as a missed target if no correct completed finding exists.

    Incomplete positive cases are FN. Incomplete negative cases without alerts
    are abstentions, never TN; they are excluded from the FPR denominator.
    """
    truth = _indexed(labels, "labels")
    submitted = _indexed(predictions, "predictions")
    for label in truth.values():
        _validate_label(label)
    for case_id, prediction in submitted.items():
        if case_id not in truth:
            raise ValueError(f"unknown prediction case_id: {case_id}")
        _validate_prediction(prediction)

    counts = {
        "tp": 0,
        "fp": 0,
        "tn": 0,
        "fn": 0,
        "completed_cases": 0,
        "incomplete_cases": 0,
        "error_cases": 0,
        "missing_predictions": 0,
        "abstained_safe_cases": 0,
        "false_alerts": 0,
        "duplicate_correct_alerts": 0,
        "unconfirmed_matching_alerts": 0,
        "total_alerts": 0,
        "classification_only_cases": 0,
    }
    positive_cases = sum(label["vulnerable"] for label in truth.values())
    costs: list[float] = []
    durations: list[float] = []

    for case_id, label in truth.items():
        prediction = submitted.get(case_id)
        if prediction is None:
            counts["missing_predictions"] += 1
            prediction = {"status": "incomplete", "findings": []}
        else:
            costs.append(_number(prediction["cost_usd"], f"{case_id}.cost_usd"))
            durations.append(
                _number(prediction["duration_seconds"], f"{case_id}.duration_seconds")
            )
        status = prediction["status"]
        status_key = "error_cases" if status == "error" else f"{status}_cases"
        counts[status_key] += 1
        findings = prediction["findings"]
        counts["total_alerts"] += len(findings)

        if not label["vulnerable"]:
            counts["false_alerts"] += len(findings)
            if findings:
                counts["fp"] += 1
            elif status == "completed":
                counts["tn"] += 1
            else:
                counts["abstained_safe_cases"] += 1
            continue

        expected_root = label.get("root_cause_id")
        if expected_root is None:
            counts["classification_only_cases"] += 1
        matching = sum(
            expected_root is None or finding["root_cause_id"] == expected_root
            for finding in findings
        )
        counts["false_alerts"] += len(findings) - matching
        if status == "completed" and matching:
            counts["tp"] += 1
            counts["duplicate_correct_alerts"] += matching - 1
        else:
            counts["fn"] += 1
            counts["unconfirmed_matching_alerts"] += matching

    try:
        total_cost = math.fsum(costs)
        total_duration = math.fsum(durations)
    except OverflowError as exc:
        raise ValueError("aggregate cost or duration is not finite") from exc
    if not math.isfinite(total_cost) or not math.isfinite(total_duration):
        raise ValueError("aggregate cost or duration is not finite")
    alert_denominator = counts["tp"] + counts["false_alerts"]
    case_precision_denominator = counts["tp"] + counts["fp"]
    fpr_denominator = counts["fp"] + counts["tn"]

    return {
        "schema_version": 1,
        "case_count": len(truth),
        "positive_cases": positive_cases,
        "negative_cases": len(truth) - positive_cases,
        **counts,
        "precision": _ratio(counts["tp"], alert_denominator),
        "precision_unit": "credited_target_detections_vs_false_alerts",
        "precision_denominator": alert_denominator,
        "case_precision": _ratio(counts["tp"], case_precision_denominator),
        "case_precision_denominator": case_precision_denominator,
        "recall": _ratio(counts["tp"], positive_cases),
        "recall_denominator": positive_cases,
        "false_positive_rate": _ratio(counts["fp"], fpr_denominator),
        "false_positive_rate_denominator": fpr_denominator,
        "completion_rate": _ratio(counts["completed_cases"], len(truth)),
        "total_cost_usd": total_cost,
        "cost_per_true_positive": _ratio(total_cost, counts["tp"]),
        "total_duration_seconds": total_duration,
        "runtime_observations": len(durations),
        "runtime_p50_seconds": _percentile(durations, 0.50),
        "runtime_p95_seconds": _percentile(durations, 0.95),
        "notes": [
            "Submitted evidence is not independently verified by this scorer.",
            "Incomplete positives are missed targets; incomplete safe/no-alert cases are abstentions.",
            "Labels without root_cause_id support classification-only scoring, not root-cause validation.",
            "Missing predictions have unknown cost/runtime and are excluded from those totals.",
        ],
    }


def _read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except (json.JSONDecodeError, ValueError) as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON") from exc
            if not isinstance(record, dict):
                raise ValueError(f"{path}:{line_number}: expected a JSON object")
            records.append(record)
    return records


def score_files(labels_path: str | Path, predictions_path: str | Path) -> dict[str, Any]:
    """Load evaluator-only JSONL labels and separately collected predictions."""
    return score_cases(_read_jsonl(labels_path), _read_jsonl(predictions_path))
