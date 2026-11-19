import copy
import json
import tempfile
import unittest
from pathlib import Path

from devin_guard.evaluation import score_cases, score_files


def label(case_id="case-1", vulnerable=True, root_cause_id="target"):
    result = {"case_id": case_id, "vulnerable": vulnerable}
    if root_cause_id is not None:
        result["root_cause_id"] = root_cause_id
    return result


def finding(root_cause_id="target"):
    return {
        "root_cause_id": root_cause_id,
        "path": "src/example.py",
        "line": 12,
        "evidence": "Toy evaluator-adjudicated evidence; not a Devin output.",
    }


def prediction(case_id="case-1", findings=None, status="completed", cost=1, duration=10):
    return {
        "case_id": case_id,
        "status": status,
        "findings": [] if findings is None else findings,
        "cost_usd": cost,
        "duration_seconds": duration,
    }


class EvaluationTests(unittest.TestCase):
    def test_confusion_matrix_and_cost(self):
        labels = [label("tp"), label("fn"), label("fp", False), label("tn", False)]
        predictions = [
            prediction("tp", [finding()], duration=10),
            prediction("fn", duration=20),
            prediction("fp", [finding()], duration=30),
            prediction("tn", duration=40),
        ]
        result = score_cases(labels, predictions)
        self.assertEqual([result[x] for x in ("tp", "fn", "fp", "tn")], [1, 1, 1, 1])
        self.assertEqual(result["precision"], 0.5)
        self.assertEqual(result["recall"], 0.5)
        self.assertEqual(result["false_positive_rate"], 0.5)
        self.assertEqual(result["false_positive_rate_denominator"], 2)
        self.assertEqual(result["cost_per_true_positive"], 4)
        self.assertEqual(result["runtime_p50_seconds"], 25)
        self.assertAlmostEqual(result["runtime_p95_seconds"], 38.5)

    def test_wrong_root_cause_is_false_alert_and_missed_target(self):
        result = score_cases([label()], [prediction(findings=[finding("wrong-root")])])
        self.assertEqual(result["tp"], 0)
        self.assertEqual(result["fn"], 1)
        self.assertEqual(result["false_alerts"], 1)
        self.assertEqual(result["fp"], 0)  # FP is a per-safe-case measure.
        self.assertEqual(result["precision"], 0)

    def test_extra_false_alert_reduces_precision_even_with_correct_detection(self):
        result = score_cases(
            [label()],
            [prediction(findings=[finding(), finding(), finding("invented")])],
        )
        self.assertEqual(result["tp"], 1)
        self.assertEqual(result["false_alerts"], 1)
        self.assertEqual(result["duplicate_correct_alerts"], 1)
        self.assertEqual(result["precision"], 0.5)
        self.assertEqual(result["case_precision"], 1)

    def test_incomplete_matching_report_is_not_a_completed_detection(self):
        result = score_cases(
            [label()], [prediction(findings=[finding()], status="incomplete")]
        )
        self.assertEqual(result["tp"], 0)
        self.assertEqual(result["fn"], 1)
        self.assertEqual(result["unconfirmed_matching_alerts"], 1)
        self.assertEqual(result["recall"], 0)

    def test_timeout_on_safe_case_is_never_counted_clean(self):
        result = score_cases([label(vulnerable=False)], [prediction(status="incomplete")])
        self.assertEqual(result["tn"], 0)
        self.assertEqual(result["abstained_safe_cases"], 1)
        self.assertIsNone(result["false_positive_rate"])
        self.assertEqual(result["false_positive_rate_denominator"], 0)

    def test_incomplete_safe_case_with_alert_is_still_a_false_alarm(self):
        result = score_cases(
            [label(vulnerable=False)],
            [prediction(status="incomplete", findings=[finding()])],
        )
        self.assertEqual(result["fp"], 1)
        self.assertEqual(result["false_alerts"], 1)
        self.assertEqual(result["false_positive_rate"], 1)

    def test_missing_positive_counts_in_end_to_end_recall(self):
        result = score_cases(
            [label("hit"), label("missing"), label("unknown-safe", False)],
            [prediction("hit", findings=[finding()])],
        )
        self.assertEqual(result["recall"], 0.5)
        self.assertEqual(result["fn"], 1)
        self.assertEqual(result["incomplete_cases"], 2)
        self.assertEqual(result["missing_predictions"], 2)
        self.assertEqual(result["runtime_observations"], 1)
        self.assertEqual(result["abstained_safe_cases"], 1)
        self.assertAlmostEqual(result["completion_rate"], 1 / 3)

    def test_error_is_reported_and_positive_is_missed(self):
        result = score_cases([label()], [prediction(status="error")])
        self.assertEqual(result["error_cases"], 1)
        self.assertEqual(result["fn"], 1)
        self.assertEqual(result["incomplete_cases"], 0)

    def test_no_labels_has_null_ratios_not_a_perfect_score(self):
        result = score_cases([], [])
        for metric in (
            "precision", "recall", "false_positive_rate", "completion_rate",
            "cost_per_true_positive", "runtime_p50_seconds", "runtime_p95_seconds",
        ):
            self.assertIsNone(result[metric])

    def test_unknown_or_duplicate_identifiers_rejected(self):
        cases = [
            ([label()], [prediction("unknown")]),
            ([label(), label()], []),
            ([label()], [prediction(), prediction()]),
        ]
        for labels, predictions in cases:
            with self.subTest(labels=labels, predictions=predictions):
                with self.assertRaises(ValueError):
                    score_cases(labels, predictions)

    def test_invalid_numbers_rejected(self):
        for value in (float("nan"), float("inf"), -1, "1", True, None, 10**1000):
            for field in ("cost_usd", "duration_seconds"):
                with self.subTest(value=str(value)[:20], field=field):
                    record = prediction()
                    record[field] = value
                    with self.assertRaises(ValueError):
                        score_cases([label()], [record])

    def test_non_boolean_label_and_bad_findings_rejected(self):
        for invalid in (0, 1, "false", None):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    score_cases([label(vulnerable=invalid)], [])
        mutations = [
            {"line": 0}, {"line": True}, {"line": 1.5},
            {"evidence": ""}, {"path": " "}, {"root_cause_id": None},
        ]
        for mutation in mutations:
            record = finding()
            record.update(mutation)
            with self.subTest(mutation=mutation):
                with self.assertRaises(ValueError):
                    score_cases([label()], [prediction(findings=[record])])

    def test_aggregate_numeric_overflow_rejected(self):
        with self.assertRaisesRegex(ValueError, "aggregate"):
            score_cases(
                [label("a"), label("b")],
                [prediction("a", cost=1e308), prediction("b", cost=1e308)],
            )

    def test_invalid_status_and_record_types_rejected(self):
        for records in ({}, ["invalid"], [{"case_id": " "}]):
            with self.subTest(records=records):
                with self.assertRaises(ValueError):
                    score_cases(records, [])
        with self.assertRaises(ValueError):
            score_cases([label()], [prediction(status="stopped")])
        bad = prediction()
        bad["findings"] = None
        with self.assertRaises(ValueError):
            score_cases([label()], [bad])

    def test_optional_root_cause_is_explicitly_classification_only(self):
        result = score_cases(
            [label(root_cause_id=None)], [prediction(findings=[finding("anything")])]
        )
        self.assertEqual(result["tp"], 1)
        self.assertEqual(result["classification_only_cases"], 1)

    def test_input_records_not_mutated(self):
        labels, predictions = [label()], [prediction(findings=[finding()])]
        before = copy.deepcopy((labels, predictions))
        score_cases(labels, predictions)
        self.assertEqual((labels, predictions), before)

    def test_jsonl_reading_and_invalid_json(self):
        with tempfile.TemporaryDirectory() as directory:
            labels_path = Path(directory) / "labels.jsonl"
            predictions_path = Path(directory) / "predictions.jsonl"
            labels_path.write_text(json.dumps(label()) + "\n\n", encoding="utf-8")
            predictions_path.write_text(json.dumps(prediction()) + "\n", encoding="utf-8")
            self.assertEqual(score_files(labels_path, predictions_path)["fn"], 1)
            predictions_path.write_text("{broken}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "predictions.jsonl:1"):
                score_files(labels_path, predictions_path)

    def test_toy_fixture_is_wired_without_claiming_devin_accuracy(self):
        root = Path(__file__).resolve().parents[1]
        result = score_files(
            root / "examples/evaluation/toy-labels.jsonl",
            root / "examples/evaluation/toy-predictions.jsonl",
        )
        self.assertEqual(result["case_count"], 6)
        self.assertEqual(result["tp"], 1)
        self.assertEqual(result["false_alerts"], 2)
        self.assertEqual(result["missing_predictions"], 1)


if __name__ == "__main__":
    unittest.main()
