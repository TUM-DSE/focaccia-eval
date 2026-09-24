import csv
import hashlib
import tempfile
import unittest
from pathlib import Path

from diagnostic_partial import (
    EvaluationError,
    baseline_rows,
    require_artifact_hash,
    require_known_fatal_signal,
)


class FatalDiagnosticEligibilityTests(unittest.TestCase):
    def report(self, *, signal="SIGILL", pc=0x401169, delivery=None):
        if delivery is None:
            delivery = {
                "attempted": True,
                "state": "exited",
                "known_terminated": True,
                "termination_signal": 4,
                "exit_status": None,
            }
        return {
            "terminal_reason": {
                "kind": "signal",
                "signal": signal,
                "pc": pc,
                "delivery": delivery,
            },
            "validation": {
                "entries": [
                    {
                        "pc": pc,
                        "errors": [
                            {
                                "severity": "confirmed",
                                "code": "unexpected-guest-signal",
                                "subject": signal,
                            }
                        ],
                    }
                ]
            },
        }

    def test_known_fatal_signal_is_diagnostic_not_semantic_completion(self):
        evidence = require_known_fatal_signal(self.report(), "SIGILL", 0x401169)
        self.assertTrue(evidence["actualEmulatedProgramEnd"])
        self.assertTrue(evidence["expectedCrashLocalized"])
        self.assertFalse(evidence["semanticCompletion"])
        self.assertFalse(evidence["nativeFinalActionsReached"])

    def test_debugger_stop_without_process_death_is_rejected(self):
        report = self.report(
            delivery={
                "attempted": False,
                "state": None,
                "known_terminated": False,
                "termination_signal": None,
                "exit_status": None,
            }
        )
        with self.assertRaisesRegex(EvaluationError, "lacks matching fatal"):
            require_known_fatal_signal(report, "SIGILL", 0x401169)

    def test_wrong_signal_or_fault_pc_is_rejected(self):
        with self.assertRaisesRegex(EvaluationError, "Expected localized"):
            require_known_fatal_signal(
                self.report(signal="SIGSEGV"), "SIGILL", 0x401169
            )
        with self.assertRaisesRegex(EvaluationError, "Expected localized"):
            require_known_fatal_signal(self.report(pc=0x401170), "SIGILL", 0x401169)

    def test_native_baseline_must_be_positive_unique_and_passed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "results.csv"
            with path.open("w", newline="") as stream:
                writer = csv.writer(stream)
                writer.writerow(
                    [
                        "benchmark",
                        "mode",
                        "component",
                        "seconds",
                        "iteration",
                        "status",
                        "detail",
                    ]
                )
                writer.writerow(
                    ["1832422", "native", "execution", "0.25", 0, "passed", ""]
                )
            self.assertEqual(baseline_rows(path), {"1832422": 0.25})
            with path.open("a", newline="") as stream:
                csv.writer(stream).writerow(
                    ["1832422", "native", "execution", "0.5", 1, "passed", ""]
                )
            with self.assertRaisesRegex(EvaluationError, "invalid or duplicated"):
                baseline_rows(path)

    def test_binary_and_oracle_provenance_hashes_are_mandatory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact"
            path.write_bytes(b"bound artifact")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            require_artifact_hash(path, digest, "oracle")
            with self.assertRaisesRegex(
                EvaluationError, "oracle artifact hash mismatch"
            ):
                require_artifact_hash(path, "0" * 64, "oracle")
            with self.assertRaisesRegex(
                EvaluationError, "binary artifact hash mismatch"
            ):
                require_artifact_hash(path, None, "binary")


if __name__ == "__main__":
    unittest.main()
