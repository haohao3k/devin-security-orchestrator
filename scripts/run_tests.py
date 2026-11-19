"""Write an honest, reproducible test report. No live Devin API requests."""
import argparse
import json
import os
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

parser = argparse.ArgumentParser()
parser.add_argument("--require-postgres", action="store_true")
args = parser.parse_args()
if args.require_postgres and not os.getenv("TEST_POSTGRES_URL"):
    parser.error("--require-postgres requires a dedicated TEST_POSTGRES_URL")

started = time.monotonic()
suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
result = unittest.TextTestRunner(verbosity=2).run(suite)
report = {
    "tests_run": result.testsRun,
    "passed": result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped),
    "failures": len(result.failures), "errors": len(result.errors),
    "skipped": len(result.skipped), "duration_seconds": round(time.monotonic() - started, 3),
    "postgres_requested": bool(os.getenv("TEST_POSTGRES_URL")),
    "live_devin_calls": 0,
    "note": "Orchestration tests and synthetic fixtures; not vulnerability detection results.",
}
output = ROOT / "artifacts" / "test-report.json"
output.parent.mkdir(exist_ok=True)
output.write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report, indent=2))
raise SystemExit(0 if result.wasSuccessful() and not (args.require_postgres and result.skipped) else 1)
