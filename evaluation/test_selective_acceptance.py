"""Selective admission uses retained report shapes, not success-looking CSV rows.

Fixtures retain every error/diagnostic and the trace/replay summaries from
adelaide-applications-optimized-001; only successful entries and replay records
are omitted to keep them small. They are not new runtime acceptance evidence.
"""

import csv
import hashlib
import json
import tempfile
import unittest
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from unittest import mock

import evaluation
import plots
import test_evaluation


FIXTURES = Path(__file__).parent / "fixtures/selective-acceptance"
CONTRACTS = {
    "curl": ([4447644, 4447649], "CF"),
    "lua": ([4203790, 4203794], "R8"),
    "sqlite": ([4286785, 4286790], "RAX"),
}


def report_for(name):
    return json.loads((FIXTURES / f"{name}.json").read_text())


class SelectiveAcceptanceTests(unittest.TestCase):
    def test_whole_run_execution_is_separate_from_semantic_completion(self):
        report = report_for("lua")
        report["completion"] = {
            "scope": "whole-program",
            "expected_completion_available": True,
            "observed_completion_available": True,
            "ordinary_prefix_complete": False,
            "final_live_boundary_bound": True,
            "terminal_action": "match",
            "terminal_outcome": "mismatch",
            "complete": False,
            "full_run_timing_eligible": False,
        }
        evidence = evaluation.require_whole_program_experiment_execution(
            report, expected_bug_localized=True
        )
        self.assertTrue(evidence["executionCompleted"])
        self.assertTrue(evidence["timingEligible"])
        self.assertFalse(evidence["allTransitionsValidated"])
        self.assertFalse(evidence["referenceCorrectnessEstablished"])
        with self.assertRaises(evaluation.EvaluationError):
            evaluation._require_whole_program_completion(report)

    def test_whole_run_execution_rejects_abort_unknown_terminal_and_missing_bug(self):
        base = report_for("lua")
        base["completion"] = {
            "scope": "whole-program",
            "expected_completion_available": True,
            "observed_completion_available": True,
            "ordinary_prefix_complete": False,
            "final_live_boundary_bound": True,
            "terminal_action": "match",
            "terminal_outcome": "match",
            "complete": False,
            "full_run_timing_eligible": False,
        }
        mutations = []
        aborted = deepcopy(base)
        aborted["status"] = "replay-error"
        mutations.append(aborted)
        unknown = deepcopy(base)
        unknown["completion"]["terminal_action"] = "incomplete"
        mutations.append(unknown)
        truncated = deepcopy(base)
        truncated["trace"]["state_count"] = truncated["trace"]["transform_count"]
        mutations.append(truncated)
        for report in mutations:
            with self.assertRaises(evaluation.EvaluationError):
                evaluation.require_whole_program_experiment_execution(
                    report, expected_bug_localized=True
                )
        with self.assertRaises(evaluation.EvaluationError):
            evaluation.require_whole_program_experiment_execution(
                base, expected_bug_localized=False
            )

    def test_whole_run_expected_signal_is_independent_terminal_evidence(self):
        report = report_for("lua")
        report["completion"] = {
            "scope": "whole-program",
            "expected_completion_available": False,
            "observed_completion_available": False,
            "ordinary_prefix_complete": False,
            "final_live_boundary_bound": False,
            "terminal_action": "incomplete",
            "terminal_outcome": "incomplete",
            "complete": False,
            "full_run_timing_eligible": False,
        }
        report["terminal_reason"] = {
            "kind": "signal",
            "signal": "SIGILL",
            "pc": 0x401169,
        }
        with self.assertRaises(evaluation.EvaluationError):
            evaluation.require_whole_program_experiment_execution(
                report, expected_bug_localized=True
            )
        evidence = evaluation.require_whole_program_experiment_execution(
            report,
            expected_bug_localized=True,
            expected_terminal_signal_localized=True,
        )
        self.assertTrue(evidence["executionCompleted"])
        self.assertFalse(evidence["allTransitionsValidated"])

    def test_retained_reports_and_independent_gap_mutations(self):
        for name, (bounds, subject) in CONTRACTS.items():
            report = report_for(name)
            with self.subTest(name=name):
                evaluation.require_selective_application_acceptance(
                    report, "mismatch", bounds, subject
                )
        # Incompleteness is retained and disqualifies a correctness claim, but
        # does not erase a completed experiment or its intended detection.
        self.assertFalse(report_for("lua")["trace"]["complete"])
        clean = report_for("curl")
        mutations = []
        for expected in (None, [], {}, True):
            with (
                self.subTest(expected=expected),
                self.assertRaises(evaluation.EvaluationError),
            ):
                evaluation.require_selective_application_acceptance(
                    clean, expected, *CONTRACTS["curl"]
                )
        for field in ("diagnostics", "diagnostic_counts", "severity_counts", "entries"):
            item = deepcopy(clean)
            del item["validation"][field]
            mutations.append(item)
        for key, value in (
            ("complete", False),
            ("terminal_reached", False),
            ("state_count", clean["trace"]["transform_count"]),
        ):
            item = deepcopy(clean)
            item["trace"][key] = value
            mutations.append(item)
        for error in (
            {"severity": "incomplete", "code": "unresolved-symbolic-value"},
            {"severity": "confirmed", "code": "memory-content-mismatch"},
            {"severity": "possible", "code": "register-content-mismatch"},
        ):
            item = deepcopy(clean)
            item["validation"]["entries"][0]["errors"].append(error)
            mutations.append(item)
        for field, value in (
            ("diagnostics", [{"severity": "incomplete", "code": "register-read"}]),
            ("diagnostic_counts", {"incomplete": 1}),
            ("severity_counts", {"confirmed": 1, "incomplete": 1}),
            ("severity_counts", {"confirmed": True}),
        ):
            item = deepcopy(clean)
            item["validation"][field] = value
            mutations.append(item)
        item = deepcopy(clean)
        item["validation"]["entries"].append(
            {
                "transition_range": [1, 2],
                "errors": deepcopy(item["validation"]["entries"][0]["errors"]),
            }
        )
        mutations.append(item)
        malformed = [*mutations[:4], mutations[5], mutations[6], mutations[13]]
        for index, item in enumerate(malformed):
            with (
                self.subTest(malformed_or_truncated=index),
                self.assertRaises(evaluation.EvaluationError),
            ):
                evaluation.require_selective_application_acceptance(
                    item, "mismatch", *CONTRACTS["curl"]
                )
        # Additional confirmed findings and unconfirmed comparisons remain
        # report evidence and do not invalidate timing/detection eligibility.
        additional = [mutations[4], *mutations[7:13], mutations[14]]
        for index, item in enumerate(additional):
            with self.subTest(additional_report=index):
                evaluation.require_selective_application_acceptance(
                    item, "mismatch", *CONTRACTS["curl"]
                )
        # Bounded trigger witnesses retain their separate localization contract.
        self.assertTrue(
            evaluation._expected_register_mismatch(
                mutations[-1], *CONTRACTS["curl"][0], "CF"
            )
        )

    def test_reference_requires_clean_complete_evidence_too(self):
        report = report_for("curl")
        report["status"] = "accepted"
        with self.assertRaises(evaluation.EvaluationError):
            evaluation.require_selective_application_acceptance(report, "accepted")
        report["validation"]["entries"][0]["errors"] = []
        report["validation"]["severity_counts"] = {}
        evaluation.require_selective_application_acceptance(report, "accepted")
        report["validation"]["diagnostic_counts"] = {"incomplete": 1}
        with self.assertRaises(evaluation.EvaluationError):
            evaluation.require_selective_application_acceptance(report, "accepted")

    def test_actual_evaluator_path_does_not_emit_timings_for_stale_passes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = evaluation.load_config(
                test_evaluation.EvaluationTests()._gdb_trigger_configuration(root)
            )
            artifact = root / "artifact"
            artifact.write_bytes(b"fixture")
            for name, (bounds, subject) in CONTRACTS.items():
                with self.subTest(application=name):
                    directory = root / name
                    directory.mkdir()
                    for filename in (
                        "run-manifest.json",
                        "replay-preflight.json",
                        "profile.json",
                    ):
                        (directory / filename).write_text("{}")
                    (directory / "validation.json").write_text(
                        json.dumps(report_for(name))
                    )
                    artifacts = evaluation.NativeApplicationArtifacts(
                        artifact,
                        artifact,
                        artifact,
                        artifact,
                        (),
                        "msgpack",
                        {"stopAddress": bounds[1]},
                    )
                    case = replace(
                        config.emulator_cases["qemu-test"],
                        kind="application",
                        trace_mode="selective",
                        expected_validation="mismatch",
                        expected_mismatch_source_symbol="injection",
                        expected_mismatch_subject=subject,
                    )
                    with (
                        mock.patch.object(
                            evaluation,
                            "_native_application_artifacts",
                            return_value=artifacts,
                        ),
                        mock.patch.object(
                            evaluation,
                            "_prepare_qemu_application",
                            return_value=evaluation.PreparedApplication(
                                root, (), None, None, None, False, False
                            ),
                        ),
                        mock.patch.object(
                            evaluation, "_free_loopback_port", return_value=1234
                        ),
                        mock.patch.object(evaluation, "ManagedProcess"),
                        mock.patch.object(evaluation, "_wait_for_listener"),
                        mock.patch.object(
                            evaluation,
                            "run_process",
                            return_value=mock.Mock(returncode=0, output=""),
                        ),
                        mock.patch.object(
                            evaluation,
                            "read_symbols",
                            return_value={"injection": bounds[0]},
                        ),
                        mock.patch.object(
                            evaluation, "_qemu_profile_rows", return_value=([], {})
                        ) as timings,
                    ):

                        def consume():
                            return evaluation._evaluate_qemu_application(
                                config,
                                case,
                                config.emulators[case.emulator],
                                root / "qemu",
                                root,
                                0,
                                directory,
                            )

                        _, metadata, passed = consume()
                        self.assertTrue(passed)
                        self.assertEqual(metadata["expectedMismatchRange"], bounds)
                        self.assertEqual(
                            metadata["reportSha256"],
                            evaluation._sha256(directory / "validation.json"),
                        )
                        evidence = metadata["selectiveEvidence"]
                        self.assertTrue(evidence["timingEligible"])
                        self.assertFalse(evidence["referenceCorrectnessEstablished"])
                        self.assertEqual(
                            evidence["allTransitionsValidated"], name != "lua"
                        )
                        self.assertGreaterEqual(evidence["confirmedFindingCount"], 1)
                        self.assertEqual(timings.call_count, 1)

    def test_plot_ingestion_rechecks_reports_and_blocks_csv_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            system = root / "emulated/qemu/aarch64-linux"
            system.mkdir(parents=True)
            profile = system / "profile.json"
            profile.write_text(
                json.dumps(
                    {
                        "schema": "focaccia-qemu-validation-profile-v1",
                        "status": "passed",
                        "timings": {
                            "executionSeconds": 1,
                            "tracingSeconds": 2,
                            "validationSeconds": 3,
                            "serializationSeconds": 4,
                            "totalSeconds": 10,
                        },
                    }
                )
            )
            cases = {}
            rows = []
            for name, (bounds, subject) in CONTRACTS.items():
                report = system / f"{name}.json"
                report.write_text(json.dumps(report_for(name)))
                cases[name] = {
                    "kind": "application",
                    "status": "passed",
                    "benchmark": name,
                    "emulator": "qemu-test",
                    "iterations": [
                        {
                            "profile": "profile.json",
                            "profileSha256": evaluation._sha256(profile),
                            "report": report.name,
                            "reportSha256": evaluation._sha256(report),
                            "expectedValidation": "mismatch",
                            "expectedMismatchRange": bounds,
                            "expectedMismatchSubject": subject,
                        }
                    ],
                }
                for component, seconds in zip(
                    (
                        "execution",
                        "tracing",
                        "validation",
                        "serialization",
                        "total",
                        "unexpected",
                    ),
                    (1, 2, 3, 4, 10, 99),
                ):
                    rows.append([name, "qemu-test", component, seconds, 0, "passed"])
                rows.append([name, "qemu-other", "execution", 99, 20, "passed"])
            with (system / "results.csv").open("w") as stream:
                writer = csv.writer(stream)
                writer.writerow(
                    ["benchmark", "mode", "component", "seconds", "iteration", "status"]
                )
                writer.writerows(rows)
            metadata = {
                "schema": plots.EMULATED_METADATA_SCHEMA,
                "role": "qemu",
                "system": "aarch64-linux",
                "cases": cases,
            }
            (system / "metadata.json").write_text(json.dumps(metadata))
            data = plots.load_measurements(root)
            self.assertEqual(data.get("curl", "qemu-test", "total"), 10)
            for name in CONTRACTS:
                self.assertIsNone(data.get(name, "qemu-test", "unexpected"))
                self.assertIsNone(data.get(name, "qemu-other", "execution"))
                self.assertIn(name, data.modes)
            # No validation report, no sample, even with a valid passed profile.
            (system / "curl.json").unlink()
            self.assertNotIn("curl", plots.load_measurements(root).modes)

    def test_legacy_curl_uses_guest_symbols_not_observed_error_location(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "report.json"
            report.write_text(json.dumps(report_for("curl")))
            binary = root / "curl"
            binary.write_bytes(b"hash-bound ELF fixture")
            bounds, _ = CONTRACTS["curl"]
            encoded = {
                "report": report.name,
                "binary": binary.name,
                "binarySha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "native": {"stopAddress": bounds[1]},
                "expectedValidation": "mismatch",
            }
            with mock.patch.object(
                plots,
                "read_symbols",
                return_value={"focaccia_injection_curl_2175": bounds[0]},
            ) as symbols:
                self.assertTrue(
                    plots._selective_application_evidence(root, encoded, "curl", None)
                )
                symbols.assert_called_once()
            with mock.patch.object(
                plots, "read_symbols", return_value={"focaccia_injection_curl_2175": 1}
            ):
                self.assertFalse(
                    plots._selective_application_evidence(root, encoded, "curl", None)
                )
            binary.write_bytes(b"changed")
            with mock.patch.object(plots, "read_symbols") as symbols:
                self.assertFalse(
                    plots._selective_application_evidence(root, encoded, "curl", None)
                )
                symbols.assert_not_called()


if __name__ == "__main__":
    unittest.main()
