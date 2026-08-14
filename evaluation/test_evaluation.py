from __future__ import annotations

import csv
import json
import platform
import stat
import sys
import tempfile
import unittest
from contextlib import chdir
from pathlib import Path
from unittest import mock

import evaluation


class EvaluationTests(unittest.TestCase):
    def test_machine_names_are_normalized(self):
        self.assertEqual(evaluation.normalize_machine("AMD64"), "x86_64")
        self.assertEqual(evaluation.normalize_machine("arm64"), "aarch64")
        with self.assertRaisesRegex(evaluation.EvaluationError, "Unsupported"):
            evaluation.normalize_machine("mips64")

    def test_emulator_output_must_be_pre_realized(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            emulator_output = Path(temporary_directory) / "emulator-output"
            emulator_output.mkdir()
            variant = evaluation.EmulatorVariant(
                identifier="test-emulator",
                backend="qemu-gdb",
                output=emulator_output,
                version="1.0",
            )

            self.assertEqual(evaluation._emulator_output(variant), emulator_output)
            missing = evaluation.EmulatorVariant(
                identifier="missing-emulator",
                backend="qemu-gdb",
                output=emulator_output / "missing",
                version="1.0",
            )
            with self.assertRaisesRegex(evaluation.EvaluationError, "does not exist"):
                evaluation._emulator_output(missing)

    def test_native_trace_format_defaults_to_msgpack(self):
        parser = evaluation.make_argument_parser()
        default = parser.parse_args(["--config", "config.json", "--output", "run"])
        explicit = parser.parse_args(
            [
                "--config",
                "config.json",
                "--output",
                "run",
                "--trace-format",
                "json",
            ]
        )

        self.assertEqual(default.trace_format, "msgpack")
        self.assertEqual(explicit.trace_format, "json")
        self.assertFalse(default.skip_unmatched)

    def test_unmatched_skipping_is_explicitly_opt_in(self):
        parser = evaluation.make_argument_parser()
        enabled = parser.parse_args(
            [
                "--config",
                "config.json",
                "--input",
                "run",
                "--skip-unmatched",
            ]
        )

        self.assertTrue(enabled.skip_unmatched)

    def test_crash_mismatch_requires_exact_signal_and_fault_pc(self):
        report = {
            "terminal_reason": {
                "kind": "signal",
                "signal": "SIGSEGV",
                "pc": 0x401014,
            },
            "validation": {
                "entries": [
                    {
                        "pc": 0x401014,
                        "errors": [
                            {
                                "severity": "confirmed",
                                "code": "unexpected-guest-signal",
                                "subject": "SIGSEGV",
                            }
                        ],
                    }
                ]
            },
        }

        self.assertTrue(evaluation._expected_guest_signal(report, "SIGSEGV", 0x401014))
        self.assertFalse(evaluation._expected_guest_signal(report, "SIGILL", 0x401014))
        self.assertFalse(evaluation._expected_guest_signal(report, "SIGSEGV", 0x401015))
        report["terminal_reason"] = None
        self.assertFalse(evaluation._expected_guest_signal(report, "SIGSEGV", 0x401014))

    def test_application_mismatch_requires_exact_localized_classification(self):
        expected = {
            "validation": {
                "entries": [
                    {
                        "transition_range": [0x43DD9C, 0x43DDA1],
                        "errors": [
                            {
                                "severity": "confirmed",
                                "code": "register-content-mismatch",
                                "subject": "CF",
                            }
                        ],
                    }
                ]
            }
        }

        self.assertTrue(
            evaluation._expected_application_mismatch(
                expected, 0x43DD9C, 0x43DDA1, "CF"
            )
        )
        self.assertFalse(
            evaluation._expected_application_mismatch(
                expected, 0x413F8D, 0x413F90, "OF"
            )
        )
        unrelated = {
            "validation": {
                "entries": [
                    {
                        "transition_range": [0x413F8D, 0x413F90],
                        "errors": [
                            {
                                "severity": "confirmed",
                                "code": "register-content-mismatch",
                                "subject": "OF",
                            }
                        ],
                    }
                ]
            }
        }
        self.assertFalse(
            evaluation._expected_application_mismatch(
                unrelated, 0x43DD9C, 0x43DDA1, "CF"
            )
        )

    def test_reference_acceptance_requires_complete_terminal_trace(self):
        complete = {
            "trace": {
                "available": True,
                "complete": True,
                "state_count": 12,
                "transform_count": 11,
                "terminal_reached": True,
            }
        }
        evaluation._require_complete_terminal_trace(complete)

        for trace in (
            {},
            {"available": False},
            {
                "available": True,
                "complete": False,
                "state_count": 12,
                "transform_count": 11,
                "terminal_reached": True,
            },
            {
                "available": True,
                "complete": True,
                "state_count": 11,
                "transform_count": 11,
                "terminal_reached": True,
            },
            {
                "available": True,
                "complete": True,
                "state_count": 12,
                "transform_count": 11,
                "terminal_reached": False,
            },
        ):
            with (
                self.subTest(trace=trace),
                self.assertRaises(evaluation.EvaluationError),
            ):
                evaluation._require_complete_terminal_trace({"trace": trace})

    def test_component_timings_require_complete_profile(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            profile = Path(temporary_directory) / "profile.json"
            profile.write_text(
                json.dumps(
                    {
                        "status": "passed",
                        "timings": {
                            "concreteSeconds": 1.25,
                            "symbolicSeconds": 2.5,
                            "validationSeconds": 0.125,
                            "traceSeconds": 7.0,
                            "serializationSeconds": 11.0,
                        },
                    }
                )
            )
            self.assertEqual(
                evaluation.load_component_timings(profile),
                {
                    "concrete": 1.25,
                    "symbolic": 2.5,
                    "validation": 0.125,
                    "trace": 7.0,
                    "serialization": 11.0,
                },
            )
            profile.write_text(
                json.dumps(
                    {
                        "status": "passed",
                        "timings": {
                            "concreteSeconds": 1.25,
                            "symbolicSeconds": 2.5,
                        },
                    }
                )
            )
            with self.assertRaisesRegex(evaluation.EvaluationError, "timing fields"):
                evaluation.load_component_timings(profile)

    def test_native_capture_timeout_allows_large_trace_serialization(self):
        self.assertEqual(evaluation.CAPTURE_TIMEOUT_SECONDS, 120 * 60)

    def test_run_process_uses_requested_timeout(self):
        timeout = evaluation.subprocess.TimeoutExpired(
            ("fixture",),
            3600,
            output="partial output",
        )
        with mock.patch.object(
            evaluation.subprocess,
            "run",
            side_effect=timeout,
        ) as run:
            result = evaluation.run_process(("fixture",), timeout_seconds=3600)

        self.assertEqual(result.returncode, 124)
        self.assertIn("Timed out after 3600 seconds", result.output)
        self.assertEqual(run.call_args.kwargs["timeout"], 3600)

    def test_native_role_collects_baseline_trace_and_component_times(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            binary = self._write_executable(root / "trigger", "#!/bin/sh\nexit 0\n")
            nm = self._write_executable(
                root / "nm",
                "#!/bin/sh\n"
                "printf '%s\\n' '0000000000401000 T focaccia_trace_start' "
                "'0000000000401010 T focaccia_trace_stop'\n",
            )
            capture = self._fake_capture(root / "capture")
            config = self._write_config(
                root,
                capture=capture,
                nm=nm,
                rr=capture,
                triggers={"test": {"binary": str(binary), "expectedStatus": 0}},
            )
            output = root / "run"

            result = evaluation.main(("--config", str(config), "--output", str(output)))

            self.assertEqual(result, 0)
            system_directory = output / "native" / self._current_system()
            self.assertTrue((system_directory / "oracles/test-0.trace").is_file())
            self.assertEqual(
                (system_directory / "binaries/reproducer-test").read_bytes(),
                binary.read_bytes(),
            )
            metadata = json.loads((system_directory / "metadata.json").read_text())
            self.assertEqual(metadata["status"], "passed")
            self.assertEqual(metadata["scope"], "triggers")
            iteration_metadata = metadata["cases"]["test"]["iterations"][0]
            self.assertEqual(iteration_metadata["binary"], "binaries/reproducer-test")
            self.assertEqual(len(iteration_metadata["binarySha256"]), 64)
            self.assertEqual(iteration_metadata["startAddress"], 0x401000)
            self.assertEqual(iteration_metadata["stopAddress"], 0x401010)
            self.assertEqual(iteration_metadata["profile"], "profiles/test-0.json")
            self.assertEqual(len(iteration_metadata["profileSha256"]), 64)
            self.assertEqual(iteration_metadata["traceFormat"], "msgpack")
            self.assertEqual(iteration_metadata["traceSeconds"], 7.0)
            self.assertEqual(iteration_metadata["serializationSeconds"], 11.0)
            capture_log = (system_directory / "logs/test-0-capture.log").read_text()
            self.assertIn("--start-address 0x401000", capture_log)
            self.assertIn("--profile-report", capture_log)
            self.assertIn("--out-type msgpack", capture_log)
            with (system_directory / "results.csv").open(newline="") as result_file:
                rows = list(csv.DictReader(result_file))
            self.assertEqual(
                {(row["mode"], row["component"]) for row in rows},
                {
                    ("native", "execution"),
                    ("native-cross-validated", "concrete"),
                    ("native-cross-validated", "symbolic"),
                    ("native-cross-validated", "validation"),
                    ("native-cross-validated", "total"),
                },
            )
            self.assertTrue(all(row["status"] == "passed" for row in rows))
            total = next(row for row in rows if row["component"] == "total")
            self.assertEqual(float(total["seconds"]), 7.0)

    def test_native_runs_append_disjoint_cases_and_reject_reruns(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            first = self._write_executable(root / "first", "#!/bin/sh\nexit 0\n")
            second = self._write_executable(root / "second", "#!/bin/sh\nexit 0\n")
            nm = self._write_executable(
                root / "nm",
                "#!/bin/sh\n"
                "printf '%s\\n' '0000000000401000 T focaccia_trace_start' "
                "'0000000000401010 T focaccia_trace_stop'\n",
            )
            capture = self._fake_capture(root / "capture")
            rr = self._fake_rr(root / "rr")
            output = root / "run"
            first_config = self._write_config(
                root,
                capture=capture,
                nm=nm,
                rr=rr,
                triggers={"first": {"binary": str(first), "expectedStatus": 0}},
            )
            self.assertEqual(
                evaluation.main(
                    ("--config", str(first_config), "--output", str(output))
                ),
                0,
            )
            second_config = self._write_config(
                root,
                capture=capture,
                nm=nm,
                rr=rr,
                triggers={"second": {"binary": str(second), "expectedStatus": 0}},
            )
            system_directory = output / "native" / self._current_system()
            previous_metadata = json.loads(
                (system_directory / "metadata.json").read_text()
            )
            previous_metadata["cases"]["first"]["status"] = "failed"
            previous_metadata["status"] = "failed"
            (system_directory / "metadata.json").write_text(
                json.dumps(previous_metadata)
            )

            self.assertEqual(
                evaluation.main(
                    ("--config", str(second_config), "--output", str(output))
                ),
                0,
            )

            metadata = json.loads((system_directory / "metadata.json").read_text())
            self.assertEqual(set(metadata["cases"]), {"first", "second"})
            self.assertEqual(metadata["status"], "failed")
            with (system_directory / "results.csv").open(newline="") as result_file:
                rows = list(csv.DictReader(result_file))
            self.assertEqual({row["benchmark"] for row in rows}, {"first", "second"})
            self.assertEqual(
                evaluation.main(
                    ("--config", str(second_config), "--output", str(output))
                ),
                2,
            )
            unchanged = json.loads((system_directory / "metadata.json").read_text())
            self.assertEqual(unchanged, metadata)

    def test_emulated_runs_append_disjoint_cases(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            emulator_output = root / "qemu"
            (emulator_output / "bin").mkdir(parents=True)
            self._write_executable(
                emulator_output / "bin/qemu-x86_64", "#!/bin/sh\nexit 0\n"
            )
            variant = evaluation.EmulatorVariant(
                identifier="qemu-test",
                backend="qemu-gdb",
                output=emulator_output,
                version="1",
            )
            unused = root / "unused"
            common = {
                "kind": "trigger",
                "guest_system": "x86_64-linux",
                "emulator": "qemu-test",
                "program": "bin/qemu-x86_64",
                "expected_validation": "mismatch",
            }
            first = evaluation.EmulatorCase(
                identifier="qemu-first", trigger="first", **common
            )
            second = evaluation.EmulatorCase(
                identifier="qemu-second", trigger="second", **common
            )

            def config(case: evaluation.EmulatorCase) -> evaluation.EvaluationConfig:
                return evaluation.EvaluationConfig(
                    role="qemu",
                    system=self._current_system(),
                    capture_program=unused,
                    nm_program=unused,
                    rr_program=unused,
                    http_server_program=unused,
                    offline_validator_program=unused,
                    validate_qemu_program=unused,
                    replay_manifest_program=unused,
                    replay_preflight_program=unused,
                    triggers={},
                    applications={},
                    emulators={"qemu-test": variant},
                    emulator_cases={case.identifier: case},
                )

            def result_for(benchmark: str):
                return (
                    [
                        evaluation.result_row(
                            benchmark,
                            "qemu-test",
                            "total",
                            1.0,
                            0,
                            "passed",
                        )
                    ],
                    {},
                    True,
                )

            with mock.patch.object(
                evaluation, "_evaluate_qemu_trigger", return_value=result_for("first")
            ):
                self.assertEqual(
                    evaluation.run_emulated(config(first), root, (), (), 1), 0
                )
            system_directory = root / "emulated" / "qemu" / self._current_system()
            legacy_metadata = json.loads(
                (system_directory / "metadata.json").read_text()
            )
            del legacy_metadata["cases"]["qemu-first"]["benchmark"]
            legacy_metadata["cases"]["qemu-first"]["status"] = "failed"
            legacy_metadata["status"] = "failed"
            (system_directory / "metadata.json").write_text(json.dumps(legacy_metadata))
            with mock.patch.object(
                evaluation,
                "_evaluate_qemu_trigger",
                return_value=result_for("second"),
            ):
                self.assertEqual(
                    evaluation.run_emulated(config(second), root, (), (), 1), 0
                )

            metadata = json.loads((system_directory / "metadata.json").read_text())
            self.assertEqual(set(metadata["cases"]), {"qemu-first", "qemu-second"})
            self.assertEqual(metadata["status"], "failed")
            with (system_directory / "results.csv").open(newline="") as result_file:
                rows = list(csv.DictReader(result_file))
            self.assertEqual({row["benchmark"] for row in rows}, {"first", "second"})

    def test_native_selective_application_records_rr_and_uses_main_bound(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            binary = self._write_executable(
                root / "sqlite-injected",
                "#!/bin/sh\ncat >/dev/null\nexit 0\n",
            )
            reference = self._write_executable(
                root / "sqlite-reference", "#!/bin/sh\nexit 0\n"
            )
            workload = root / "workload.sql"
            workload.write_text("select 1;\n")
            nm = self._write_executable(
                root / "nm",
                "#!/bin/sh\n"
                "printf '%s\\n' '0000000000402000 T main' "
                "'0000000000402100 T focaccia_trace_stop_sqlite'\n",
            )
            capture = self._fake_capture(root / "capture")
            rr = self._fake_rr(root / "rr")
            config = self._write_config(
                root,
                capture=capture,
                nm=nm,
                rr=rr,
                applications={
                    "sqlite": {
                        "referenceBinary": str(reference),
                        "injectedBinary": str(binary),
                        "workload": str(workload),
                        "workloadKind": "sqlite",
                        "expectedStatus": 0,
                        "startSymbol": "main",
                        "stopSymbol": "focaccia_trace_stop_sqlite",
                    }
                },
            )
            output = root / "run"

            result = evaluation.main(
                (
                    "--config",
                    str(config),
                    "--output",
                    str(output),
                    "--case",
                    "sqlite",
                )
            )

            system_directory = output / "native" / self._current_system()
            metadata = json.loads((system_directory / "metadata.json").read_text())
            with (system_directory / "results.csv").open(newline="") as result_file:
                diagnostic_rows = list(csv.DictReader(result_file))
            self.assertEqual(result, 0, {"metadata": metadata, "rows": diagnostic_rows})
            self.assertEqual(metadata["scope"], "triggers-and-applications")
            application_metadata = metadata["cases"]["sqlite"]["iterations"][0]
            self.assertEqual(application_metadata["startAddress"], 0x402000)
            self.assertEqual(application_metadata["stopAddress"], 0x402100)
            self.assertEqual(application_metadata["argv"], ["evaluation.db"])
            self.assertTrue((system_directory / "rr/sqlite-0/events").is_file())
            self.assertTrue(
                (system_directory / "oracles/sqlite-0-selective.trace").is_file()
            )
            self.assertEqual(
                application_metadata["profile"],
                "profiles/sqlite-0-selective.json",
            )
            self.assertEqual(len(application_metadata["profileSha256"]), 64)
            self.assertEqual(application_metadata["traceFormat"], "msgpack")
            self.assertEqual(application_metadata["traceSeconds"], 7.0)
            self.assertEqual(application_metadata["serializationSeconds"], 11.0)
            capture_log = (system_directory / "logs/sqlite-0-capture.log").read_text()
            self.assertIn("--start-address 0x402000", capture_log)
            self.assertIn("--profile-report", capture_log)
            self.assertIn("--out-type msgpack", capture_log)
            self.assertNotIn("--cross-validate", capture_log)
            with (system_directory / "results.csv").open(newline="") as result_file:
                rows = list(csv.DictReader(result_file))
            self.assertEqual(
                {(row["mode"], row["component"]) for row in rows},
                {
                    ("native", "execution"),
                    ("native-rr", "record"),
                    ("native-selective", "concrete"),
                    ("native-selective", "symbolic"),
                    ("native-selective", "validation"),
                    ("native-selective", "total"),
                },
            )
            self.assertTrue(all(row["status"] == "passed" for row in rows))
            total = next(row for row in rows if row["component"] == "total")
            self.assertEqual(float(total["seconds"]), 7.0)

    def test_full_curl_records_cross_validated_and_speculative_profiles(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            binary = self._write_executable(
                root / "curl-injected", "#!/bin/sh\nexit 0\n"
            )
            reference = self._write_executable(
                root / "curl-reference", "#!/bin/sh\nexit 0\n"
            )
            workload = root / "curl-5k.bin"
            workload.write_bytes(b"x" * 5120)
            nm = self._write_executable(
                root / "nm",
                "#!/bin/sh\n"
                "printf '%s\\n' '0000000000402000 T main' "
                "'0000000000402100 T focaccia_trace_stop_curl'\n",
            )
            capture = self._fake_capture(root / "capture")
            rr = self._fake_rr(root / "rr")
            config = self._write_config(
                root,
                capture=capture,
                nm=nm,
                rr=rr,
                http_server=Path(sys.executable),
                applications={
                    "curl-full": {
                        "referenceBinary": str(reference),
                        "injectedBinary": str(binary),
                        "workload": str(workload),
                        "workloadKind": "curl",
                        "expectedStatus": 0,
                        "startSymbol": "main",
                        "stopSymbol": "focaccia_trace_stop_curl",
                        "traceMode": "full",
                    }
                },
            )
            output = root / "run"

            result = evaluation.main(
                (
                    "--config",
                    str(config),
                    "--output",
                    str(output),
                    "--case",
                    "curl-full",
                )
            )

            system_directory = output / "native" / self._current_system()
            diagnostic_metadata = json.loads(
                (system_directory / "metadata.json").read_text()
            )
            with (system_directory / "results.csv").open(newline="") as result_file:
                diagnostic_rows = list(csv.DictReader(result_file))
            self.assertEqual(
                result,
                0,
                {"metadata": diagnostic_metadata, "rows": diagnostic_rows},
            )
            self.assertTrue(
                (
                    system_directory / "oracles/curl-full-0-cross-validated.trace"
                ).is_file()
            )
            self.assertTrue(
                (system_directory / "oracles/curl-full-0-speculative.trace").is_file()
            )
            cross_log = (
                system_directory / "logs/curl-full-0-cross-validated-capture.log"
            ).read_text()
            speculative_log = (
                system_directory / "logs/curl-full-0-speculative-capture.log"
            ).read_text()
            self.assertIn("--cross-validate", cross_log)
            self.assertNotIn("--cross-validate", speculative_log)
            metadata = json.loads((system_directory / "metadata.json").read_text())
            iteration = metadata["cases"]["curl-full"]["iterations"][0]
            self.assertEqual(iteration["traceMode"], "full")
            self.assertEqual(
                iteration["oracle"], "oracles/curl-full-0-speculative.trace"
            )
            self.assertEqual(
                set(iteration["fullCaptures"]),
                {"native-full-cross-validated", "native-full-speculative"},
            )
            with (system_directory / "results.csv").open(newline="") as result_file:
                rows = list(csv.DictReader(result_file))
            self.assertEqual(
                {(row["mode"], row["component"]) for row in rows},
                {
                    ("native", "execution"),
                    ("native-rr", "record"),
                    ("native-full-cross-validated", "concrete"),
                    ("native-full-cross-validated", "symbolic"),
                    ("native-full-cross-validated", "validation"),
                    ("native-full-cross-validated", "total"),
                    ("native-full-speculative", "concrete"),
                    ("native-full-speculative", "symbolic"),
                    ("native-full-speculative", "validation"),
                    ("native-full-speculative", "total"),
                },
            )
            self.assertTrue(all(row["status"] == "passed" for row in rows))

    def test_curl_and_lua_workloads_have_explicit_selective_plans(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            fixture = root / "fixture"
            fixture.write_bytes(b"x" * 5120)
            common = {
                "reference_binary": root / "reference",
                "injected_binary": root / "injected",
                "expected_status": 0,
                "start_symbol": "main",
                "stop_symbol": "stop",
            }
            curl = evaluation.Application(
                identifier="curl",
                workload=fixture,
                workload_kind="curl",
                **common,
            )
            curl_plan = evaluation.prepare_application(curl, root / "curl")
            self.assertEqual(curl_plan.server_root, root / "curl")
            self.assertIn("curl-5k.bin", curl_plan.argv[-1])
            self.assertFalse(curl_plan.deliver_sigint)

            lua = evaluation.Application(
                identifier="lua",
                workload=fixture,
                workload_kind="lua",
                **common,
            )
            lua_plan = evaluation.prepare_application(lua, root / "lua")
            self.assertEqual(lua_plan.argv, ("workload.lua",))
            self.assertTrue(lua_plan.deliver_sigint)
            self.assertIsNone(lua_plan.server_root)

    def test_box64_emulated_role_consumes_native_oracle_and_structured_report(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            input_directory = root / "run"
            native_directory = input_directory / "native" / "x86_64-linux"
            (native_directory / "binaries").mkdir(parents=True)
            (native_directory / "oracles").mkdir()
            self._write_executable(
                native_directory / "binaries/reproducer-508",
                "#!/bin/sh\nexit 0\n",
            )
            oracle = native_directory / "oracles/508-0.trace"
            oracle.write_text("oracle\n")
            (native_directory / "metadata.json").write_text(
                json.dumps(
                    {
                        "schema": "focaccia-native-evaluation-v2",
                        "traceFormat": "msgpack",
                        "cases": {
                            "508": {
                                "status": "passed",
                                "iterations": [
                                    {
                                        "binary": "binaries/reproducer-508",
                                        "oracle": "oracles/508-0.trace",
                                        "expectedNativeStatus": 0,
                                        "traceFormat": "msgpack",
                                        "startAddress": 0x401000,
                                        "stopAddress": 0x401010,
                                    }
                                ],
                            }
                        },
                    }
                )
            )

            emulator_output = root / "box64-output"
            (emulator_output / "bin").mkdir(parents=True)
            self._write_executable(
                emulator_output / "bin/box64",
                "#!/bin/sh\n"
                'test "$BOX64_TRACE" = 0x401000-0x401011 || exit 8\n'
                'test "$BOX64_TRACE_FILE" = stderr || exit 8\n'
                'test "$BOX64_DYNAREC_TRACE" = 1 || exit 8\n'
                "printf '%s\\n' 'ES=0 RAX=1 RIP=401000'\n"
                "exit 0\n",
            )
            offline_validator = self._write_executable(
                root / "offline-validator",
                "#!/bin/sh\n"
                'while test "$#" -gt 0; do\n'
                '  if test "$1" = --report; then shift; report=$1; fi\n'
                '  if test "$1" = --trace-type; then shift; trace_type=$1; fi\n'
                "  shift\n"
                "done\n"
                'test "$trace_type" = msgpack || exit 9\n'
                "printf '%s\\n' "
                '\'{"schema":"focaccia-offline-validation-v1",\''
                '\'"status":"mismatch"}\' > "$report"\n',
            )
            unused = self._write_executable(root / "unused", "#!/bin/sh\nexit 0\n")
            config = self._write_config(
                root,
                capture=unused,
                nm=unused,
                rr=unused,
                role="box64",
                offline_validator=offline_validator,
                emulators={
                    "box64-0-3-8": {
                        "backend": "box64-log",
                        "output": str(emulator_output),
                        "version": "0.3.8",
                    }
                },
                emulator_cases={
                    "box64-508": {
                        "kind": "trigger",
                        "trigger": "508",
                        "guestSystem": "x86_64-linux",
                        "emulator": "box64-0-3-8",
                        "program": "bin/box64",
                        "expectedValidation": "mismatch",
                    }
                },
            )

            result = evaluation.main(
                (
                    "--config",
                    str(config),
                    "--input",
                    str(input_directory),
                    "--case",
                    "508",
                    "--emulator",
                    "box64",
                )
            )

            self.assertEqual(result, 0)
            system_directory = (
                input_directory / "emulated" / "box64" / self._current_system()
            )
            metadata = json.loads((system_directory / "metadata.json").read_text())
            self.assertEqual(metadata["status"], "passed")
            self.assertEqual(
                metadata["cases"]["box64-508"]["backend"],
                "box64-log",
            )
            report = system_directory / "box64-log/box64-0-3-8/508/0/validation.json"
            self.assertTrue(report.is_file())
            with (system_directory / "results.csv").open(newline="") as result_file:
                rows = list(csv.DictReader(result_file))
            self.assertEqual(
                [(row["component"], row["status"]) for row in rows],
                [("execution", "passed"), ("validation", "passed")],
            )

    def test_qemu_emulated_role_launches_gdb_driver_and_checks_report(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            input_directory = root / "run"
            native_directory = input_directory / "native" / "aarch64-linux"
            (native_directory / "binaries").mkdir(parents=True)
            (native_directory / "oracles").mkdir()
            self._write_executable(
                native_directory / "binaries/reproducer-364",
                "#!/bin/sh\nexit 0\n",
            )
            (native_directory / "oracles/364-0.trace").write_text("oracle\n")
            (native_directory / "metadata.json").write_text(
                json.dumps(
                    {
                        "schema": "focaccia-native-evaluation-v2",
                        "traceFormat": "msgpack",
                        "cases": {
                            "364": {
                                "status": "passed",
                                "iterations": [
                                    {
                                        "binary": "binaries/reproducer-364",
                                        "oracle": "oracles/364-0.trace",
                                        "expectedNativeStatus": 0,
                                        "traceFormat": "msgpack",
                                        "stopAddress": 0x401020,
                                    }
                                ],
                            }
                        },
                    }
                )
            )

            emulator_output = root / "qemu-output"
            (emulator_output / "bin").mkdir(parents=True)
            self._write_executable(
                emulator_output / "bin/qemu-aarch64",
                f"#!{sys.executable}\n"
                "import socket, sys, time\n"
                "port = int(sys.argv[sys.argv.index('-g') + 1])\n"
                "server = socket.socket()\n"
                "server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
                "server.bind(('127.0.0.1', port))\n"
                "server.listen()\n"
                "time.sleep(60)\n",
            )
            validate_qemu = self._write_executable(
                root / "validate-qemu",
                "#!/bin/sh\n"
                'while test "$#" -gt 0; do\n'
                '  if test "$1" = --report; then shift; report=$1; fi\n'
                '  if test "$1" = --profile-report; then shift; profile=$1; fi\n'
                '  if test "$1" = --output; then shift; output=$1; fi\n'
                '  if test "$1" = --trace-type; then shift; trace_type=$1; fi\n'
                '  if test "$1" = --cutpoint-address; then shift; cutpoint=$1; fi\n'
                "  shift\n"
                "done\n"
                'test "$trace_type" = msgpack || exit 9\n'
                'test "$cutpoint" = 0x401020 || exit 10\n'
                "printf '%s\\n' "
                '\'{"schema":"focaccia-qemu-validation-v1",\''
                '\'"status":"mismatch"}\' > "$report"\n'
                "printf '%s\\n' "
                '\'{"schema":"focaccia-qemu-validation-profile-v1",\''
                '\'"status":"passed","timings":{\''
                '\'"executionSeconds":1,"tracingSeconds":2,\''
                '\'"validationSeconds":3,"serializationSeconds":4,\''
                '\'"totalSeconds":10}}\' > "$profile"\n'
                "printf '%s\\n' states > \"$output\"\n",
            )
            unused = self._write_executable(root / "unused", "#!/bin/sh\nexit 0\n")
            config = self._write_config(
                root,
                capture=unused,
                nm=unused,
                rr=unused,
                role="qemu",
                validate_qemu=validate_qemu,
                emulators={
                    "qemu-5-2-0": {
                        "backend": "qemu-gdb",
                        "output": str(emulator_output),
                        "version": "5.2.0",
                    }
                },
                emulator_cases={
                    "qemu-364": {
                        "kind": "trigger",
                        "trigger": "364",
                        "guestSystem": "aarch64-linux",
                        "emulator": "qemu-5-2-0",
                        "program": "bin/qemu-aarch64",
                        "expectedValidation": "mismatch",
                        "validationCutpoint": "stop",
                    }
                },
            )

            result = evaluation.main(
                (
                    "--config",
                    str(config),
                    "--input",
                    str(input_directory),
                    "--case",
                    "364",
                    "--emulator",
                    "qemu",
                )
            )

            self.assertEqual(result, 0)
            system_directory = (
                input_directory / "emulated" / "qemu" / self._current_system()
            )
            metadata = json.loads((system_directory / "metadata.json").read_text())
            self.assertEqual(metadata["status"], "passed")
            case = metadata["cases"]["qemu-364"]
            self.assertEqual(case["backend"], "qemu-gdb")
            self.assertEqual(case["iterations"][0]["validationCutpoint"], "stop")
            self.assertEqual(
                case["iterations"][0]["validationCutpointAddress"], 0x401020
            )
            case_directory = system_directory / "qemu-gdb/qemu-5-2-0/364/0"
            self.assertTrue((case_directory / "validation.json").is_file())
            self.assertTrue((case_directory / "states.trace").is_file())
            profile = json.loads((case_directory / "profile.json").read_text())
            self.assertEqual(profile["timings"]["executionSeconds"], 1)
            with (system_directory / "results.csv").open(newline="") as result_file:
                rows = list(csv.DictReader(result_file))
            self.assertEqual(
                [(row["component"], row["seconds"]) for row in rows],
                [
                    ("execution", "1"),
                    ("tracing", "2"),
                    ("validation", "3"),
                    ("serialization", "4"),
                    ("total", "10"),
                ],
            )

    def test_qemu_plugin_role_requires_complete_localized_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            input_directory = root / "run"
            native_directory = input_directory / "native" / "aarch64-linux"
            (native_directory / "binaries").mkdir(parents=True)
            (native_directory / "oracles").mkdir()
            binary = self._write_executable(
                native_directory / "binaries/reproducer-2248",
                "#!/bin/sh\nexit 0\n",
            )
            oracle = native_directory / "oracles/2248-0.trace"
            oracle.write_text("oracle\n")
            (native_directory / "metadata.json").write_text(
                json.dumps(
                    {
                        "schema": "focaccia-native-evaluation-v2",
                        "traceFormat": "msgpack",
                        "cases": {
                            "2248": {
                                "status": "passed",
                                "iterations": [
                                    {
                                        "binary": "binaries/reproducer-2248",
                                        "binarySha256": evaluation._sha256(binary),
                                        "oracle": "oracles/2248-0.trace",
                                        "oracleSha256": evaluation._sha256(oracle),
                                        "expectedNativeStatus": 0,
                                        "witnessSha256": "1" * 64,
                                        "traceFormat": "msgpack",
                                        "startAddress": 0x401000,
                                        "stopAddress": 0x40101C,
                                    }
                                ],
                            }
                        },
                    }
                )
            )

            emulator_output = root / "qemu-plugin-output"
            (emulator_output / "bin").mkdir(parents=True)
            (emulator_output / "lib/plugins").mkdir(parents=True)
            (emulator_output / "lib/plugins/libfocaccia.so").write_bytes(b"plugin")
            qemu = self._write_executable(
                emulator_output / "bin/qemu-aarch64",
                f"#!{sys.executable}\n"
                "import pathlib, socket, sys, time\n"
                "plugin = sys.argv[sys.argv.index('-plugin') + 1]\n"
                "socket_value = next(item for item in plugin.split(',') "
                "if item.startswith('socket='))\n"
                "socket_path = pathlib.Path(socket_value.split('=', 1)[1])\n"
                "client = socket.socket(socket.AF_UNIX)\n"
                "client.connect(str(socket_path))\n"
                "client.close()\n"
                "while socket_path.exists(): time.sleep(0.01)\n"
                "raise SystemExit(1)\n",
            )
            validate_qemu = self._write_executable(
                root / "validate-qemu",
                f"#!{sys.executable}\n"
                "import json, pathlib, socket, sys\n"
                "args = sys.argv[1:]\n"
                "def value(name): return args[args.index(name) + 1]\n"
                "sockpath = pathlib.Path(value('--use-socket'))\n"
                "server = socket.socket(socket.AF_UNIX)\n"
                "server.bind(str(sockpath))\n"
                "server.listen(1)\n"
                "connection, _ = server.accept()\n"
                "connection.close()\n"
                "server.close()\n"
                "sockpath.unlink()\n"
                "report = {\n"
                " 'schema':'focaccia-qemu-validation-v1', 'status':'mismatch',\n"
                " 'trace':{'available':True,'complete':True,'state_count':8,\n"
                "          'transform_count':7,'terminal_reached':True},\n"
                " 'validation':{'entries':[{'transition_range':[0x401018,0x40101c],\n"
                "  'errors':[{'severity':'confirmed','code':'register-content-mismatch',\n"
                "             'subject':'X0'}]}]}}\n"
                "pathlib.Path(value('--report')).write_text(json.dumps(report))\n"
                "profile = {'schema':'focaccia-qemu-validation-profile-v1',\n"
                " 'status':'passed','timings':{'executionSeconds':1,\n"
                " 'tracingSeconds':2,'validationSeconds':3,\n"
                " 'serializationSeconds':4,'totalSeconds':10}}\n"
                "pathlib.Path(value('--profile-report')).write_text(json.dumps(profile))\n"
                "pathlib.Path(value('--output')).write_text('states\\n')\n",
            )
            nm = self._write_executable(
                root / "nm",
                "#!/bin/sh\n"
                "printf '%s\\n' "
                "'0000000000401000 T focaccia_trace_start' "
                "'0000000000401018 T focaccia_expected_mismatch' "
                "'000000000040101c T focaccia_trace_stop'\n",
            )
            unused = self._write_executable(root / "unused", "#!/bin/sh\nexit 0\n")
            config = self._write_config(
                root,
                capture=unused,
                nm=nm,
                rr=unused,
                role="qemu",
                validate_qemu=validate_qemu,
                emulators={
                    "qemu-8-2-1-plugin": {
                        "backend": "qemu-plugin",
                        "output": str(emulator_output),
                        "version": "8.2.1",
                    }
                },
                emulator_cases={
                    "qemu-2248": {
                        "kind": "trigger",
                        "trigger": "2248",
                        "guestSystem": "aarch64-linux",
                        "emulator": "qemu-8-2-1-plugin",
                        "program": "bin/qemu-aarch64",
                        "expectedValidation": "mismatch",
                        "expectedWitnessSha256": "1" * 64,
                        "expectedMismatchSourceSymbol": "focaccia_expected_mismatch",
                        "expectedMismatchSubject": "X0",
                    }
                },
            )

            result = evaluation.main(
                ("--config", str(config), "--input", str(input_directory))
            )

            self.assertEqual(result, 0)
            system_directory = (
                input_directory / "emulated" / "qemu" / self._current_system()
            )
            case = json.loads((system_directory / "metadata.json").read_text())[
                "cases"
            ]["qemu-2248"]
            self.assertEqual(case["backend"], "qemu-plugin")
            self.assertTrue(case["iterations"][0]["expectedMismatchLocalized"])
            self.assertEqual(case["iterations"][0]["guestStatus"], 1)
            self.assertTrue(qemu.is_file())

    def test_qemu_plugin_role_rejects_obsolete_native_binary(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            input_directory = root / "run"
            native_directory = input_directory / "native" / "aarch64-linux"
            (native_directory / "binaries").mkdir(parents=True)
            (native_directory / "oracles").mkdir()
            binary = self._write_executable(
                native_directory / "binaries/reproducer-2248",
                "#!/bin/sh\nexit 0\n",
            )
            oracle = native_directory / "oracles/2248-0.trace"
            oracle.write_text("oracle\n")
            (native_directory / "metadata.json").write_text(
                json.dumps(
                    {
                        "schema": "focaccia-native-evaluation-v2",
                        "traceFormat": "msgpack",
                        "cases": {
                            "2248": {
                                "status": "passed",
                                "iterations": [
                                    {
                                        "binary": "binaries/reproducer-2248",
                                        "binarySha256": evaluation._sha256(binary),
                                        "oracle": "oracles/2248-0.trace",
                                        "oracleSha256": evaluation._sha256(oracle),
                                        "expectedNativeStatus": 0,
                                        "traceFormat": "msgpack",
                                    }
                                ],
                            }
                        },
                    }
                )
            )
            unused = self._write_executable(root / "unused", "#!/bin/sh\nexit 0\n")
            emulator_output = root / "qemu-plugin-output"
            (emulator_output / "bin").mkdir(parents=True)
            qemu = self._write_executable(
                emulator_output / "bin/qemu-aarch64",
                "#!/bin/sh\nexit 99\n",
            )
            config = self._write_config(
                root,
                capture=unused,
                nm=unused,
                rr=unused,
                role="qemu",
                emulators={
                    "qemu-8-2-1-plugin": {
                        "backend": "qemu-plugin",
                        "output": str(emulator_output),
                        "version": "8.2.1",
                    }
                },
                emulator_cases={
                    "qemu-2248": {
                        "kind": "trigger",
                        "trigger": "2248",
                        "guestSystem": "aarch64-linux",
                        "emulator": "qemu-8-2-1-plugin",
                        "program": "bin/qemu-aarch64",
                        "expectedValidation": "mismatch",
                        "expectedWitnessSha256": "0" * 64,
                        "expectedMismatchSourceSymbol": "focaccia_expected_mismatch",
                        "expectedMismatchSubject": "X0",
                    }
                },
            )

            result = evaluation.main(
                ("--config", str(config), "--input", str(input_directory))
            )

            self.assertEqual(result, 1)
            system_directory = (
                input_directory / "emulated" / "qemu" / self._current_system()
            )
            metadata = json.loads((system_directory / "metadata.json").read_text())
            error = metadata["cases"]["qemu-2248"]["iterations"][0]["error"]
            self.assertIn("does not match the configured witness", error)
            self.assertTrue(qemu.is_file())

    def test_qemu_application_role_replays_bound_native_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            input_directory = root / "run"
            native_directory = input_directory / "native" / "x86_64-linux"
            (native_directory / "binaries").mkdir(parents=True)
            (native_directory / "oracles").mkdir()
            (native_directory / "rr/sqlite-0").mkdir(parents=True)
            binary = self._write_executable(
                native_directory / "binaries/application-sqlite-injected",
                "#!/bin/sh\nexit 0\n",
            )
            oracle = native_directory / "oracles/sqlite-0-selective.trace"
            oracle.write_text("oracle\n")
            (native_directory / "rr/sqlite-0/events").write_text("events\n")
            workload = root / "sqlite.sql"
            workload.write_text("select 1;\n")
            (native_directory / "metadata.json").write_text(
                json.dumps(
                    {
                        "schema": "focaccia-native-evaluation-v2",
                        "traceFormat": "msgpack",
                        "cases": {
                            "sqlite": {
                                "kind": "application",
                                "status": "passed",
                                "iterations": [
                                    {
                                        "kind": "application",
                                        "injectedBinary": "binaries/application-sqlite-injected",
                                        "injectedBinarySha256": evaluation._sha256(
                                            binary
                                        ),
                                        "oracle": "oracles/sqlite-0-selective.trace",
                                        "oracleSha256": evaluation._sha256(oracle),
                                        "rrTrace": "rr/sqlite-0",
                                        "argv": ["evaluation.db"],
                                        "workloadKind": "sqlite",
                                        "workloadSha256": evaluation._sha256(workload),
                                        "traceFormat": "msgpack",
                                        "startAddress": 0x401000,
                                        "stopAddress": 0x402000,
                                    }
                                ],
                            }
                        },
                    }
                )
            )

            emulator_output = root / "qemu-output"
            (emulator_output / "bin").mkdir(parents=True)
            self._write_executable(
                emulator_output / "bin/qemu-x86_64",
                f"#!{sys.executable}\n"
                "import pathlib, socket, sys, time\n"
                "if sys.argv[-1] != 'evaluation.db': raise SystemExit(8)\n"
                "if not pathlib.Path('input.sql').is_file(): raise SystemExit(8)\n"
                "port = int(sys.argv[sys.argv.index('-g') + 1])\n"
                "server = socket.socket()\n"
                "server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
                "server.bind(('127.0.0.1', port))\n"
                "server.listen()\n"
                "time.sleep(60)\n",
            )
            preflight_program = self._write_executable(
                root / "preflight",
                "#!/bin/sh\n"
                'while test "$#" -gt 0; do\n'
                '  if test "$1" = --output; then shift; output=$1; fi\n'
                "  shift\n"
                "done\n"
                "printf '%s\\n' "
                '\'{"schema":"focaccia-replay-preflight-v1",'
                '"status":"passed","failures":[]}\' > "$output"\n',
            )
            manifest_program = self._write_executable(
                root / "manifest",
                "#!/bin/sh\n"
                'while test "$#" -gt 0; do\n'
                '  if test "$1" = --output; then shift; output=$1; fi\n'
                '  if test "$1" = --trace-type; then shift; trace_type=$1; fi\n'
                '  if test "$1" = --argv-json; then shift; argv=$1; fi\n'
                '  if test "$1" = --input; then shift; input=$1; fi\n'
                "  shift\n"
                "done\n"
                'test "$trace_type" = msgpack || exit 9\n'
                'test "$argv" = \'["evaluation.db"]\' || exit 9\n'
                'test "${input%%=*}" = workload || exit 9\n'
                'printf \'%s\\n\' \'{"schema":"focaccia-rr-qemu-run-v1"}\' > "$output"\n',
            )
            validate_qemu = self._write_executable(
                root / "validate-qemu",
                "#!/bin/sh\n"
                'while test "$#" -gt 0; do\n'
                '  if test "$1" = --report; then shift; report=$1; fi\n'
                '  if test "$1" = --profile-report; then shift; profile=$1; fi\n'
                '  if test "$1" = --output; then shift; output=$1; fi\n'
                '  if test "$1" = --deterministic-log; then deterministic=1; fi\n'
                '  if test "$1" = --run-manifest; then manifest=1; fi\n'
                '  if test "$1" = --run-input; then input=1; fi\n'
                '  if test "$1" = --skip-unmatched; then skip=1; fi\n'
                '  if test "$1" = --quiet; then quiet=1; fi\n'
                "  shift\n"
                "done\n"
                'test "$deterministic$manifest$input$skip$quiet" = 11111 || exit 9\n'
                "printf '%s\\n' "
                '\'{"schema":"focaccia-qemu-validation-v1",'
                '"status":"mismatch","validation":{"entries":[{'
                '"transition_range":[4198400,4202496],"errors":[{'
                '"severity":"confirmed","code":"register-content-mismatch",'
                '"subject":"RAX"}]}]},"replay":{"active":true,'
                '"record_count":2,"by_outcome":{"handled":2}}}\' > "$report"\n'
                "printf '%s\\n' "
                '\'{"schema":"focaccia-qemu-validation-profile-v1",\''
                '\'"status":"passed","timings":{\''
                '\'"executionSeconds":1,"tracingSeconds":2,\''
                '\'"validationSeconds":3,"serializationSeconds":4,\''
                '\'"totalSeconds":10}}\' > "$profile"\n'
                "printf '%s\\n' states > \"$output\"\n",
            )
            nm = self._write_executable(
                root / "nm",
                "#!/bin/sh\nprintf '%s\\n' "
                "'0000000000401000 T focaccia_injection_sqlite_508'\n",
            )
            unused = self._write_executable(root / "unused", "#!/bin/sh\nexit 0\n")
            config = self._write_config(
                root,
                capture=unused,
                nm=nm,
                rr=unused,
                role="qemu",
                validate_qemu=validate_qemu,
                replay_manifest=manifest_program,
                replay_preflight=preflight_program,
                emulators={
                    "qemu-6-1-0": {
                        "backend": "qemu-gdb",
                        "output": str(emulator_output),
                        "version": "6.1.0",
                    }
                },
                emulator_cases={
                    "qemu-app-sqlite": {
                        "kind": "application",
                        "trigger": "sqlite",
                        "guestSystem": "x86_64-linux",
                        "emulator": "qemu-6-1-0",
                        "program": "bin/qemu-x86_64",
                        "expectedValidation": "mismatch",
                        "expectedMismatchSourceSymbol": "focaccia_injection_sqlite_508",
                        "expectedMismatchSubject": "RAX",
                        "workload": str(workload),
                        "workloadKind": "sqlite",
                    }
                },
            )

            with chdir(root):
                result = evaluation.main(
                    (
                        "--config",
                        str(config),
                        "--input",
                        "run",
                        "--case",
                        "sqlite",
                        "--skip-unmatched",
                    )
                )

            self.assertEqual(result, 0)
            system_directory = (
                input_directory / "emulated" / "qemu" / self._current_system()
            )
            metadata = json.loads((system_directory / "metadata.json").read_text())
            case = metadata["cases"]["qemu-app-sqlite"]
            self.assertEqual(case["kind"], "application")
            iteration = case["iterations"][0]
            self.assertEqual(iteration["validationStatus"], "mismatch")
            self.assertEqual(iteration["argv"], ["evaluation.db"])
            self.assertTrue(iteration["skipUnmatched"])
            self.assertTrue(metadata["skipUnmatched"])
            self.assertTrue(iteration["expectedMismatchLocalized"])
            self.assertEqual(len(iteration["runManifestSha256"]), 64)

    def test_qemu_application_recreates_recorded_workload_interfaces(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            common = {
                "binary": root / "binary",
                "oracle": root / "oracle",
                "rr_trace": root / "rr",
                "trace_format": "msgpack",
                "metadata": {},
            }
            variants = (
                (
                    "sqlite",
                    root / "input.sql",
                    ("evaluation.db",),
                ),
                (
                    "curl",
                    root / "curl-5k.bin",
                    (
                        "--output",
                        "download.bin",
                        "http://127.0.0.1:43123/curl-5k.bin",
                    ),
                ),
                ("lua", root / "workload.lua", ("workload.lua",)),
            )
            for kind, workload, argv in variants:
                with self.subTest(kind=kind):
                    case = evaluation.EmulatorCase(
                        identifier=f"qemu-app-{kind}",
                        kind="application",
                        trigger=kind,
                        guest_system="x86_64-linux",
                        emulator="qemu",
                        program="bin/qemu-x86_64",
                        expected_validation="mismatch",
                        workload=workload,
                        workload_kind=kind,
                    )
                    artifacts = evaluation.NativeApplicationArtifacts(
                        workload=workload,
                        argv=argv,
                        **common,
                    )

                    prepared = evaluation._prepare_qemu_application(case, artifacts)

                    self.assertEqual(prepared.argv, argv)
                    if kind == "sqlite":
                        self.assertEqual(prepared.stdin_path, workload)
                    elif kind == "curl":
                        self.assertEqual(prepared.server_root, root)
                        self.assertEqual(prepared.server_port, 43123)
                    else:
                        self.assertFalse(prepared.deliver_sigint)
                        self.assertTrue(prepared.pipe_stdin)

    def test_qemu_application_rejects_inactive_or_failed_replay_coverage(self):
        for replay in (
            {"active": False, "record_count": 0, "by_outcome": {}},
            {"active": True, "record_count": 1, "by_outcome": {"rejected": 1}},
            {"active": True, "record_count": 1, "by_outcome": {"failed": 1}},
        ):
            with (
                self.subTest(replay=replay),
                self.assertRaises(evaluation.EvaluationError),
            ):
                evaluation._require_successful_replay({"replay": replay})

    def test_failed_native_run_is_not_a_timing_sample(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            binary = self._write_executable(root / "trigger", "#!/bin/sh\nexit 1\n")
            nm = self._write_executable(
                root / "nm",
                "#!/bin/sh\n"
                "printf '%s\\n' '0000000000401000 T focaccia_trace_start' "
                "'0000000000401010 T focaccia_trace_stop'\n",
            )
            unused = self._write_executable(root / "unused", "#!/bin/sh\nexit 0\n")
            config = self._write_config(
                root,
                capture=unused,
                nm=nm,
                rr=unused,
                triggers={"test": {"binary": str(binary), "expectedStatus": 0}},
            )
            output = root / "run"

            result = evaluation.main(("--config", str(config), "--output", str(output)))

            self.assertEqual(result, 1)
            system_directory = output / "native" / self._current_system()
            with (system_directory / "results.csv").open(newline="") as result_file:
                rows = list(csv.DictReader(result_file))
            self.assertEqual(rows[0]["status"], "failed")
            self.assertEqual(rows[0]["seconds"], "")

    @classmethod
    def _write_config(
        cls,
        root: Path,
        *,
        capture: Path,
        nm: Path,
        rr: Path,
        role: str = "native",
        triggers: dict[str, object] | None = None,
        applications: dict[str, object] | None = None,
        offline_validator: Path | None = None,
        http_server: Path | None = None,
        validate_qemu: Path | None = None,
        replay_manifest: Path | None = None,
        replay_preflight: Path | None = None,
        emulators: dict[str, object] | None = None,
        emulator_cases: dict[str, object] | None = None,
    ) -> Path:
        config = root / "config.json"
        config.write_text(
            json.dumps(
                {
                    "schema": "focaccia-evaluation-config-v5",
                    "role": role,
                    "system": cls._current_system(),
                    "captureProgram": str(capture),
                    "nmProgram": str(nm),
                    "rrProgram": str(rr),
                    "httpServerProgram": str(http_server or capture),
                    "offlineValidatorProgram": str(offline_validator or capture),
                    "validateQemuProgram": str(validate_qemu or capture),
                    "replayManifestProgram": str(replay_manifest or capture),
                    "replayPreflightProgram": str(replay_preflight or capture),
                    "triggers": triggers or {},
                    "applications": applications or {},
                    "emulators": emulators or {},
                    "emulatorCases": emulator_cases or {},
                }
            )
        )
        return config

    @classmethod
    def _fake_capture(cls, path: Path) -> Path:
        return cls._write_executable(
            path,
            "#!/bin/sh\n"
            "printf '%s\\n' \"$*\"\n"
            'while test "$#" -gt 0; do\n'
            '  if test "$1" = --output && test -z "$output"; then shift; output=$1; fi\n'
            '  if test "$1" = --profile-report; then shift; profile=$1; fi\n'
            "  shift\n"
            "done\n"
            "printf '{}\\n' > \"$output\"\n"
            "cat > \"$profile\" <<'EOF'\n"
            '{"status":"passed","timings":{"concreteSeconds":1.0,'
            '"symbolicSeconds":2.0,"validationSeconds":3.0,'
            '"traceSeconds":7.0,"serializationSeconds":11.0}}\n'
            "EOF\n",
        )

    @classmethod
    def _fake_rr(cls, path: Path) -> Path:
        return cls._write_executable(
            path,
            f"#!{sys.executable}\n"
            "import pathlib, socket, sys, time\n"
            "if sys.argv[1] == 'record':\n"
            "    output = pathlib.Path(sys.argv[sys.argv.index('-o') + 1])\n"
            "    output.mkdir(parents=True)\n"
            "    (output / 'events').write_bytes(b'events')\n"
            "    raise SystemExit(0)\n"
            "port = int(sys.argv[sys.argv.index('-s') + 1])\n"
            "server = socket.socket()\n"
            "server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
            "server.bind(('127.0.0.1', port))\n"
            "server.listen()\n"
            "time.sleep(60)\n",
        )

    @staticmethod
    def _write_executable(path: Path, contents: str) -> Path:
        path.write_text(contents)
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    @staticmethod
    def _current_system() -> str:
        machine = evaluation.normalize_machine(platform.machine())
        return f"{machine}-linux"


if __name__ == "__main__":
    unittest.main()
