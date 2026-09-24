from __future__ import annotations

import csv
import json
import platform
import stat
import sys
import tempfile
import unittest
from contextlib import chdir
from copy import deepcopy
from dataclasses import replace
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

    def _gdb_trigger_configuration(self, root, **contract):
        unused = root / "unused"
        return self._write_config(
            root,
            capture=unused,
            nm=unused,
            rr=unused,
            role="qemu",
            emulators={
                "qemu-test": {
                    "backend": "qemu-gdb",
                    "output": str(root),
                    "version": "1",
                }
            },
            emulator_cases={
                "qemu-test": {
                    "kind": "trigger",
                    "trigger": "test",
                    "guestSystem": "x86_64-linux",
                    "emulator": "qemu-test",
                    "program": "bin/qemu-x86_64",
                    "expectedValidation": "mismatch",
                    "expectedMismatchSourceSymbol": "focaccia_trace_start",
                    "expectedMismatchSourceOffset": 23,
                    "expectedMismatchLength": 5,
                    "expectedMismatchCode": "register-content-mismatch",
                    "expectedMismatchSubject": "CF",
                    **contract,
                }
            },
        )

    def _native_bundle_fixture(self, root):
        directory = root / "native" / "x86_64-linux"
        directory.mkdir(parents=True)
        (directory / "binary").write_bytes(b"binary")
        (directory / "oracle").write_bytes(b"oracle")
        item = {
            "kind": "trigger",
            "binary": "binary",
            "oracle": "oracle",
            "binarySha256": evaluation._sha256(directory / "binary"),
            "oracleSha256": evaluation._sha256(directory / "oracle"),
            "expectedNativeStatus": 0,
            "traceFormat": "msgpack",
        }
        document = {
            "schema": evaluation.NATIVE_SCHEMA,
            "role": "native",
            "system": "x86_64-linux",
            "machine": "AMD64",
            "traceFormat": "msgpack",
            "status": "failed",
            "cases": {
                "test": {"kind": "trigger", "status": "passed", "iterations": [item]},
                "unrelated": {"kind": "trigger", "status": "failed", "iterations": []},
            },
        }
        case = evaluation.EmulatorCase(
            identifier="qemu-test",
            kind="trigger",
            trigger="test",
            guest_system="x86_64-linux",
            emulator="qemu-test",
            program="bin/qemu-x86_64",
            expected_validation="mismatch",
        )
        return directory, document, case

    def test_native_oracle_identity_requires_explicit_producer_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory, good, case = self._native_bundle_fixture(root)
            path = directory / "metadata.json"
            path.write_text(json.dumps(good))
            self.assertEqual(
                evaluation._native_trigger_artifacts(root, case, 0)[3], "msgpack"
            )
            mutations = []
            for field, bad in (
                ("schema", "unknown"),
                ("role", "qemu"),
                ("system", "aarch64-linux"),
                ("machine", "arm64"),
                ("traceFormat", "yaml"),
            ):
                for value in (None, bad):
                    doc = deepcopy(good)
                    if value is None:
                        del doc[field]
                    else:
                        doc[field] = value
                    mutations.append(doc)
            for level in ("case", "iteration"):
                for value in (None, "application"):
                    doc = deepcopy(good)
                    target = doc["cases"]["test"]
                    if level == "iteration":
                        target = target["iterations"][0]
                    if value is None:
                        del target["kind"]
                    else:
                        target["kind"] = value
                    mutations.append(doc)
            for field in ("binarySha256", "oracleSha256", "traceFormat"):
                for value in (None, "", 123, "0" * 64, "json"):
                    doc = deepcopy(good)
                    target = doc["cases"]["test"]["iterations"][0]
                    if value is None:
                        del target[field]
                    else:
                        target[field] = value
                    mutations.append(doc)
            for index, doc in enumerate(mutations):
                with self.subTest(index=index):
                    path.write_text(json.dumps(doc))
                    with self.assertRaises(evaluation.EvaluationError):
                        evaluation._native_trigger_artifacts(root, case, 0)

    def test_native_oracle_paths_reject_escape_and_allow_bundle_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory, document, case = self._native_bundle_fixture(root / "original")
            path = directory / "metadata.json"
            path.write_text(json.dumps(document))
            relocated = root / "relocated"
            (relocated / "native").mkdir(parents=True)
            (relocated / "native/x86_64-linux").symlink_to(
                directory, target_is_directory=True
            )
            self.assertEqual(
                evaluation._native_trigger_artifacts(relocated, case, 0)[0],
                directory / "binary",
            )
            outside = directory.parent / "outside"
            outside.write_bytes(b"binary")
            (directory / "escape").symlink_to(outside)
            for field in ("binary", "oracle"):
                for value in (str(directory / "binary"), "../outside", "escape"):
                    with self.subTest(field=field, value=value):
                        changed = deepcopy(document)
                        changed["cases"]["test"]["iterations"][0][field] = value
                        path.write_text(json.dumps(changed))
                        with self.assertRaises(evaluation.EvaluationError):
                            evaluation._native_trigger_artifacts(relocated, case, 0)

    def test_application_oracle_requires_producer_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory, document, case = self._native_bundle_fixture(root)
            workload = root / "input.sql"
            workload.write_text("select 1;")
            (directory / "rr").mkdir()
            (directory / "rr/events").write_bytes(b"events")
            selected = document["cases"]["test"]
            selected["kind"] = "application"
            item = selected["iterations"][0]
            item.update(
                kind="application",
                injectedBinary="binary",
                injectedBinarySha256=item["binarySha256"],
                workloadKind="sqlite",
                workloadSha256=evaluation._sha256(workload),
                traceMode="selective",
                rrTrace="rr",
                argv=["evaluation.db"],
                startAddress=1,
                stopAddress=2,
            )
            case = replace(
                case,
                kind="application",
                workload=workload,
                workload_kind="sqlite",
                trace_mode="selective",
            )
            path = directory / "metadata.json"
            path.write_text(json.dumps(document))
            evaluation._native_application_artifacts(root, case, 0, root / "case")
            for value in (None, "", False, "0" * 64):
                changed = deepcopy(document)
                target = changed["cases"]["test"]["iterations"][0]
                if value is None:
                    del target["oracleSha256"]
                else:
                    target["oracleSha256"] = value
                path.write_text(json.dumps(changed))
                with self.assertRaisesRegex(evaluation.EvaluationError, "oracleSha256"):
                    evaluation._native_application_artifacts(
                        root, case, 0, root / "invalid"
                    )

    def test_plugin_reference_acceptance_needs_no_mismatch_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self._gdb_trigger_configuration(root)
            document = json.loads(path.read_text())
            document["emulators"]["qemu-test"]["backend"] = "qemu-plugin"
            encoded = document["emulatorCases"]["qemu-test"]
            encoded["expectedValidation"] = "accepted"
            for name in list(encoded):
                if name.startswith("expectedMismatch"):
                    del encoded[name]
            path.write_text(json.dumps(document))
            config = evaluation.load_config(path)
            case = config.emulator_cases["qemu-test"]
            self.assertIsNone(case.expected_mismatch_source_symbol)
            binary, oracle = root / "binary", root / "oracle"
            binary.write_bytes(b"binary")
            oracle.write_bytes(b"oracle")
            (root / "lib/plugins").mkdir(parents=True)
            (root / "lib/plugins/libfocaccia.so").write_bytes(b"plugin")
            trace = {
                "available": True,
                "complete": True,
                "terminal_reached": True,
                "state_count": 3,
                "transform_count": 2,
            }
            completion = {
                "scope": "whole-program",
                "complete": True,
                "ordinary_prefix_complete": True,
                "expected_completion_available": True,
                "observed_completion_available": True,
                "final_live_boundary_bound": True,
                "execution_complete": True,
                "full_run_timing_eligible": True,
                "terminal_action": "match",
                "terminal_outcome": "match",
            }
            for field in (
                "scope",
                "expected_completion_available",
                "observed_completion_available",
                "final_live_boundary_bound",
                "execution_complete",
                "full_run_timing_eligible",
                "terminal_action",
                "terminal_outcome",
            ):
                incomplete_completion = dict(completion)
                del incomplete_completion[field]
                with self.subTest(missing_plugin_completion_field=field):
                    with self.assertRaises(evaluation.EvaluationError):
                        evaluation._require_plugin_terminal_provenance(
                            {"trace": trace, "completion": incomplete_completion}
                        )
            for index, (status, guest_status, complete) in enumerate(
                (
                    ("accepted", 0, True),
                    ("accepted", 1, True),
                    ("mismatch", 0, True),
                    ("accepted", 0, False),
                )
            ):
                directory = root / f"case-{index}"
                directory.mkdir()
                (directory / "validation.json").write_text(
                    json.dumps(
                        {
                            "schema": "focaccia-qemu-validation-v1",
                            "status": status,
                            "trace": {**trace, "complete": complete},
                            "completion": completion,
                        }
                    )
                )
                (directory / "profile.json").write_text("{}")
                validator, guest = mock.MagicMock(), mock.MagicMock()
                validator.__enter__.return_value.wait.return_value = 0
                guest_process = guest.__enter__.return_value
                guest_process.pid = 1234
                guest_process.wait.return_value = guest_status
                (directory / "plugin-terminal-ready.json").write_text(
                    json.dumps(
                        {
                            "schema": "focaccia-plugin-terminal-ready-v1",
                            "nonce": "fixture-nonce",
                            "pid": 1234,
                            "binarySha256": evaluation._sha256(binary),
                        }
                    )
                )
                with (
                    mock.patch.object(
                        evaluation,
                        "_native_trigger_artifacts",
                        return_value=(
                            binary,
                            oracle,
                            0,
                            "msgpack",
                            {"startAddress": 0x1000, "stopAddress": 0x1008},
                        ),
                    ),
                    mock.patch.object(
                        evaluation,
                        "read_symbols",
                        return_value={
                            "focaccia_trace_start": 0x1000,
                            "focaccia_trace_stop": 0x1008,
                        },
                    ),
                    mock.patch.object(
                        evaluation, "ManagedProcess", side_effect=[validator, guest]
                    ),
                    mock.patch.object(Path, "is_socket", return_value=True),
                    mock.patch.object(Path, "unlink", return_value=None),
                    mock.patch.object(
                        evaluation, "_expected_register_mismatch"
                    ) as localization,
                    mock.patch.object(
                        evaluation, "_qemu_profile_rows", return_value=([], {})
                    ) as timings,
                ):
                    if complete:
                        _, metadata, passed = evaluation._evaluate_qemu_plugin_trigger(
                            config,
                            case,
                            config.emulators[case.emulator],
                            root / "qemu",
                            root,
                            0,
                            directory,
                        )
                        self.assertEqual(passed, index == 0)
                        self.assertIsNone(metadata["expectedMismatchLocalized"])
                    else:
                        with self.assertRaises(evaluation.EvaluationError):
                            evaluation._evaluate_qemu_plugin_trigger(
                                config,
                                case,
                                config.emulators[case.emulator],
                                root / "qemu",
                                root,
                                0,
                                directory,
                            )
                    localization.assert_not_called()
                    self.assertEqual(timings.call_count, int(index == 0))

    def test_trigger_mismatch_contract_rejects_missing_and_invalid_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self._gdb_trigger_configuration(root)
            good = json.loads(path.read_text())
            evaluation.load_config(path)
            bad_values = {
                "expectedMismatchSourceSymbol": [None, "", False, 1, []],
                "expectedMismatchSourceOffset": [None, True, -1, 1 << 64, 0.5, "0", []],
                "expectedMismatchLength": [None, False, 0, -1, 1 << 64, 1.5, "5", {}],
                "expectedMismatchCode": [None, "", "unexpected-guest-signal", [], {}],
                "expectedMismatchSubject": [None, "", 1, False, []],
            }
            for key, values in bad_values.items():
                for value in [*values, "missing"]:
                    with self.subTest(key=key, value=value):
                        document = deepcopy(good)
                        case = document["emulatorCases"]["qemu-test"]
                        if value == "missing":
                            del case[key]
                        else:
                            case[key] = value
                        path.write_text(json.dumps(document))
                        with self.assertRaises(evaluation.EvaluationError):
                            evaluation.load_config(path)
            for subject in (None, "0x123abc"):
                path = self._gdb_trigger_configuration(
                    root,
                    expectedMismatchCode="memory-content-mismatch",
                    expectedMismatchSubject=subject,
                )
                evaluation.load_config(path)
            for subject in (
                "",
                "RAX",
                123,
                False,
                [],
                "0x10000000000000000",
                "0x" + "0" * 100,
            ):
                path = self._gdb_trigger_configuration(
                    root,
                    expectedMismatchCode="memory-content-mismatch",
                    expectedMismatchSubject=subject,
                )
                with self.assertRaises(evaluation.EvaluationError):
                    evaluation.load_config(path)

    def test_trigger_mismatch_rejects_address_overflow_before_qemu(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = evaluation.load_config(self._gdb_trigger_configuration(root))
            case = config.emulator_cases["qemu-test"]
            for symbol, offset, length in (
                (-1, 0, 4),
                (True, 0, 4),
                ("0x401000", 0, 4),
                (None, 0, 4),
                (1 << 64, 0, 4),
                ((1 << 64) - 1, 1, 4),
                ((1 << 64) - 4, 0, 4),
            ):
                with (
                    self.subTest(symbol=symbol, offset=offset, length=length),
                    mock.patch.object(
                        evaluation,
                        "_native_trigger_artifacts",
                        return_value=(
                            root / "binary",
                            root / "oracle",
                            0,
                            "msgpack",
                            {},
                        ),
                    ),
                    mock.patch.object(
                        evaluation,
                        "read_symbols",
                        return_value={"focaccia_trace_start": symbol},
                    ),
                    mock.patch.object(evaluation, "ManagedProcess") as qemu,
                    mock.patch.object(evaluation, "_free_loopback_port") as port,
                ):
                    with self.assertRaises(evaluation.EvaluationError):
                        evaluation._evaluate_qemu_trigger(
                            config,
                            replace(
                                case,
                                expected_mismatch_source_offset=offset,
                                expected_mismatch_length=length,
                            ),
                            config.emulators[case.emulator],
                            root / "qemu",
                            root,
                            0,
                            root / "invalid",
                        )
                    qemu.assert_not_called()
                    port.assert_not_called()

    def test_trigger_mismatch_requires_exact_localization_before_timings(self):
        report = {
            "schema": "focaccia-qemu-validation-v1",
            "status": "mismatch",
            "validation": {
                "entries": [
                    {
                        "transition_range": [0x401017, 0x40101C],
                        "errors": [
                            {
                                "severity": "confirmed",
                                "code": "register-content-mismatch",
                                "subject": "CF",
                            }
                        ],
                    }
                ]
            },
        }
        variants = [("exact", report, True)]
        for key, value in (
            ("subject", "RAX"),
            ("subject", None),
            ("severity", "unconfirmed"),
            ("severity", "incomplete"),
            ("code", None),
            ("code", "memory-content-mismatch"),
        ):
            changed = deepcopy(report)
            changed["validation"]["entries"][0]["errors"][0][key] = value
            variants.append((f"{key}-{value}", changed, False))
        for bounds in (
            [0x400000, 0x400005],
            [0x401017, 0x40101D],
            [0x401018, 0x40101C],
            [0x401017],
            None,
        ):
            changed = deepcopy(report)
            changed["validation"]["entries"][0]["transition_range"] = bounds
            variants.append((f"range-{bounds}", changed, False))
        variants.extend(
            [
                (
                    "aggregate-only",
                    {"schema": report["schema"], "status": "mismatch"},
                    False,
                ),
                ("empty", {**report, "validation": {"entries": []}}, False),
            ]
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = evaluation.load_config(self._gdb_trigger_configuration(root))
            case = config.emulator_cases["qemu-test"]
            binary, oracle = root / "binary", root / "oracle"
            binary.write_bytes(b"binary")
            oracle.write_bytes(b"oracle")
            for name, candidate, expected in variants:
                with self.subTest(name=name):
                    directory = root / name
                    directory.mkdir()
                    (directory / "validation.json").write_text(json.dumps(candidate))
                    (directory / "profile.json").write_text("{}")
                    with (
                        mock.patch.object(
                            evaluation,
                            "_native_trigger_artifacts",
                            return_value=(binary, oracle, 0, "msgpack", {}),
                        ),
                        mock.patch.object(
                            evaluation,
                            "read_symbols",
                            return_value={"focaccia_trace_start": 0x401000},
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
                            "_qemu_profile_rows",
                            return_value=(
                                [{"seconds": "10", "status": "passed"}],
                                {"totalSeconds": 10},
                            ),
                        ) as timings,
                    ):
                        rows, metadata, passed = evaluation._evaluate_qemu_trigger(
                            config,
                            case,
                            config.emulators[case.emulator],
                            root / "qemu",
                            root,
                            0,
                            directory,
                        )
                    self.assertEqual(passed, expected)
                    self.assertEqual(metadata["expectedMismatchLocalized"], expected)
                    self.assertEqual(
                        metadata["expectedMismatchRange"], [0x401017, 0x40101C]
                    )
                    self.assertEqual(timings.call_count, int(expected))
                    if not expected:
                        self.assertEqual(metadata["profileTimings"], {})
                        self.assertIsNone(metadata["profileSha256"])
                        self.assertTrue(
                            all(
                                row["status"] == "failed" and row["seconds"] == ""
                                for row in rows
                            )
                        )
            with mock.patch.object(
                evaluation, "_native_trigger_artifacts"
            ) as artifacts:
                with self.assertRaises(evaluation.EvaluationError):
                    evaluation._evaluate_qemu_trigger(
                        config,
                        replace(case, expected_mismatch_length=None),
                        config.emulators[case.emulator],
                        root / "qemu",
                        root,
                        0,
                        root / "invalid",
                    )
                artifacts.assert_not_called()

    def test_trigger_memory_mismatch_requires_structured_address(self):
        for subject in (
            "0x4000800bc0",
            "0x5500800bcf",
            None,
            "",
            123,
            "RAX",
            "memory",
            "0x",
            "0x10000000000000000",
            "0x" + "0" * 100,
            False,
        ):
            with self.subTest(subject=subject):
                report = {
                    "validation": {
                        "entries": [
                            {
                                "transition_range": [0x40106A, 0x401072],
                                "errors": [
                                    {
                                        "severity": "confirmed",
                                        "code": "memory-content-mismatch",
                                        "subject": subject,
                                    }
                                ],
                            }
                        ]
                    }
                }
                self.assertEqual(
                    evaluation._expected_trigger_mismatch(
                        report, 0x40106A, 0x401072, "memory-content-mismatch", None
                    ),
                    subject in ("0x4000800bc0", "0x5500800bcf"),
                )
                self.assertFalse(
                    evaluation._expected_trigger_mismatch(
                        report, 0x40106A, 0x40106E, "memory-content-mismatch", None
                    )
                )
                report["validation"]["entries"][0]["errors"][0]["code"] = None
                self.assertFalse(
                    evaluation._expected_trigger_mismatch(
                        report, 0x40106A, 0x401072, "memory-content-mismatch", None
                    )
                )

    def test_trigger_reference_requires_terminal_completion_before_timings(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = evaluation.load_config(self._gdb_trigger_configuration(root))
            case = replace(
                config.emulator_cases["qemu-test"], expected_validation="accepted"
            )
            binary, oracle = root / "binary", root / "oracle"
            binary.write_bytes(b"binary")
            oracle.write_bytes(b"oracle")
            trace = {
                "available": True,
                "complete": True,
                "terminal_reached": True,
                "state_count": 3,
                "transform_count": 2,
            }
            for index, candidate in enumerate(
                (
                    trace,
                    {},
                    {**trace, "terminal_reached": False},
                    {**trace, "state_count": 2},
                )
            ):
                directory = root / str(index)
                directory.mkdir()
                (directory / "validation.json").write_text(
                    json.dumps(
                        {
                            "schema": "focaccia-qemu-validation-v1",
                            "status": "accepted",
                            "trace": candidate,
                        }
                    )
                )
                (directory / "profile.json").write_text("{}")
                with (
                    mock.patch.object(
                        evaluation,
                        "_native_trigger_artifacts",
                        return_value=(binary, oracle, 0, "msgpack", {}),
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
                        evaluation, "_qemu_profile_rows", return_value=([], {})
                    ) as timings,
                ):
                    if index == 0:
                        self.assertTrue(
                            evaluation._evaluate_qemu_trigger(
                                config,
                                case,
                                config.emulators[case.emulator],
                                root / "qemu",
                                root,
                                0,
                                directory,
                            )[2]
                        )
                        timings.assert_called_once()
                    else:
                        with self.assertRaises(evaluation.EvaluationError):
                            evaluation._evaluate_qemu_trigger(
                                config,
                                case,
                                config.emulators[case.emulator],
                                root / "qemu",
                                root,
                                0,
                                directory,
                            )
                        timings.assert_not_called()

    def test_whole_program_completion_without_witness_stop_pc(self):
        # Representative projection of retained river-full-curl-001 validation.json.
        report = {
            "completion": {
                "complete": True,
                "expected_completion_available": True,
                "final_live_boundary_bound": True,
                "full_run_timing_eligible": True,
                "observed_completion_available": True,
                "ordinary_prefix_complete": True,
                "scope": "whole-program",
                "terminal_action": "match",
                "terminal_outcome": "match",
            },
            "trace": {
                "available": True,
                "complete": True,
                "expected_terminal_pc": None,
                "state_count": 374273,
                "terminal_pc": 5046004,
                "terminal_reached": False,
                "transform_count": 374272,
            },
        }
        evaluation._require_whole_program_completion(report)
        with self.assertRaises(evaluation.EvaluationError):
            evaluation._require_complete_terminal_trace(report)
        for section, fields in (
            ("completion", tuple(report["completion"])),
            ("trace", ("available", "complete", "state_count", "transform_count")),
        ):
            for field in fields:
                for value in (None, False, 1, "unknown"):
                    with self.subTest(section=section, field=field, value=value):
                        mutated = {**report, section: {**report[section], field: value}}
                        with self.assertRaises(evaluation.EvaluationError):
                            evaluation._require_whole_program_completion(mutated)
                mutated = {**report, section: dict(report[section])}
                del mutated[section][field]
                with self.assertRaises(evaluation.EvaluationError):
                    evaluation._require_whole_program_completion(mutated)

    def test_full_application_requires_completion_before_timings(self):
        complete = {
            "scope": "whole-program",
            "ordinary_prefix_complete": True,
            "complete": True,
            "full_run_timing_eligible": True,
            "expected_completion_available": True,
            "observed_completion_available": True,
            "final_live_boundary_bound": True,
            "terminal_action": "match",
            "terminal_outcome": "match",
        }
        candidates = (
            ("full", complete, True),
            ("missing", None, False),
            ("prefix-only", {"ordinary_prefix_complete": True}, False),
            ("wrong-scope", {**complete, "scope": "selective"}, False),
            ("partial", {**complete, "complete": False}, False),
            ("ineligible", {**complete, "full_run_timing_eligible": False}, False),
            ("non-boolean", {**complete, "complete": 1}, False),
            ("selective", None, True),
            ("wrong-localization", complete, False),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = evaluation.load_config(self._gdb_trigger_configuration(root))
            artifact = root / "artifact"
            artifact.write_bytes(b"fixture")
            artifacts = evaluation.NativeApplicationArtifacts(
                artifact,
                artifact,
                artifact,
                artifact,
                (),
                "msgpack",
                {"stopAddress": 0x402000},
            )
            prepared = evaluation.PreparedApplication(
                root, (), None, None, None, False, False
            )
            for expectation in ("accepted", "mismatch"):
                for name, completion, eligible in candidates:
                    with self.subTest(expectation=expectation, completion=name):
                        case = replace(
                            config.emulator_cases["qemu-test"],
                            kind="application",
                            trace_mode="selective" if name == "selective" else "full",
                            expected_validation=expectation,
                            expected_mismatch_source_symbol="injection",
                            expected_mismatch_subject="CF",
                        )
                        directory = root / f"{expectation}-{name}"
                        directory.mkdir()
                        for filename in (
                            "replay-preflight.json",
                            "run-manifest.json",
                            "profile.json",
                        ):
                            (directory / filename).write_text("{}")
                        report = {
                            "schema": "focaccia-qemu-validation-v1",
                            "status": expectation,
                            "trace": {
                                "available": True,
                                "complete": True,
                                "terminal_reached": name == "selective",
                                "expected_terminal_pc": None,
                                "state_count": 3,
                                "transform_count": 2,
                            },
                            "replay": {
                                "active": True,
                                "record_count": 6,
                                "by_outcome": {"applied": 6},
                            },
                            "validation": {
                                "diagnostics": [],
                                "diagnostic_counts": {},
                                "severity_counts": {"confirmed": 1},
                                "entries": [
                                    {
                                        "transition_range": [0x401000, 0x402000],
                                        "errors": [
                                            {
                                                "severity": "confirmed",
                                                "code": "register-content-mismatch",
                                                "subject": "RAX"
                                                if name == "wrong-localization"
                                                else "CF",
                                            }
                                        ],
                                    }
                                ],
                            },
                        }
                        if expectation == "accepted" and name == "selective":
                            report["validation"] = {
                                "entries": [],
                                "diagnostics": [],
                                "severity_counts": {},
                                "diagnostic_counts": {},
                            }
                        if completion is not None:
                            report["completion"] = completion
                        (directory / "validation.json").write_text(json.dumps(report))
                        with (
                            mock.patch.object(
                                evaluation,
                                "_native_application_artifacts",
                                return_value=artifacts,
                            ),
                            mock.patch.object(
                                evaluation,
                                "_prepare_qemu_application",
                                return_value=prepared,
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
                                return_value={"injection": 0x401000},
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

                            if name == "wrong-localization":
                                self.assertEqual(
                                    consume()[2], expectation == "accepted"
                                )
                            elif eligible:
                                self.assertTrue(consume()[2])
                            else:
                                with self.assertRaisesRegex(
                                    evaluation.EvaluationError,
                                    "whole-program completion",
                                ):
                                    consume()
                            if eligible or (
                                name == "wrong-localization"
                                and expectation == "accepted"
                            ):
                                timings.assert_called_once()
                            else:
                                timings.assert_not_called()

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

    def test_marker_free_trigger_capture_uses_whole_program(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            binary = self._write_executable(root / "unannotated", "#!/bin/sh\nexit 0\n")
            capture = self._fake_capture(root / "capture")
            path = self._write_config(
                root,
                capture=capture,
                nm=root / "must-not-run-nm",
                rr=capture,
                triggers={"test": {"binary": str(binary), "expectedStatus": 0}},
                trigger_trace_mode="whole-program",
            )
            document = json.loads(path.read_text())
            del document["triggerTraceMode"]
            path.write_text(json.dumps(document))
            config = evaluation.load_config(path)
            self.assertEqual(config.trigger_trace_mode, "whole-program")
            output = root / "native"
            with mock.patch.object(
                evaluation, "read_symbols", side_effect=AssertionError("symbol lookup")
            ):
                _, metadata, passed = evaluation.evaluate_trigger(
                    config, config.triggers["test"], 0, output, "json"
                )
            self.assertTrue(passed)
            self.assertEqual(metadata["traceMode"], "whole-program")
            self.assertNotIn("startAddress", metadata)
            self.assertNotIn("stopAddress", metadata)
            command = (output / "logs/test-0-capture.log").read_text()
            self.assertIn("--whole-program", command)
            self.assertNotIn("--start-address", command)
            self.assertNotIn("--stop-address", command)

    def test_marker_free_trigger_consumer_rejects_truncated_and_legacy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self._gdb_trigger_configuration(root)
            document = json.loads(path.read_text())
            document["triggerTraceMode"] = "whole-program"
            contract = document["emulatorCases"]["qemu-test"]
            contract.pop("expectedMismatchSourceSymbol")
            contract.pop("expectedMismatchSourceOffset")
            contract["expectedMismatchSourceAddress"] = 0x401017
            path.write_text(json.dumps(document))
            config = evaluation.load_config(path)
            case = config.emulator_cases["qemu-test"]
            binary, oracle = root / "binary", root / "oracle"
            binary.write_bytes(b"binary")
            oracle.write_bytes(b"oracle")
            report = {
                "schema": "focaccia-qemu-validation-v1",
                "status": "mismatch",
                "trace": {
                    "available": True,
                    "complete": True,
                    "state_count": 3,
                    "transform_count": 2,
                },
                "completion": {
                    "scope": "whole-program",
                    "complete": True,
                    "full_run_timing_eligible": True,
                    "expected_completion_available": True,
                    "observed_completion_available": True,
                    "ordinary_prefix_complete": True,
                    "final_live_boundary_bound": True,
                    "terminal_action": "match",
                    "terminal_outcome": "match",
                },
                "validation": {
                    "severity_counts": {"confirmed": 1},
                    "diagnostic_counts": {},
                    "entries": [
                        {
                            "transition_range": [0x401017, 0x40101C],
                            "errors": [
                                {
                                    "severity": "confirmed",
                                    "code": "register-content-mismatch",
                                    "subject": "CF",
                                }
                            ],
                        }
                    ],
                },
            }
            for mode in ("complete", "truncated", "legacy", "wrong-location"):
                directory = root / mode
                directory.mkdir()
                candidate = deepcopy(report)
                if mode == "truncated":
                    candidate["completion"]["ordinary_prefix_complete"] = False
                    candidate["completion"]["observed_completion_available"] = False
                    candidate["completion"]["final_live_boundary_bound"] = False
                if mode == "wrong-location":
                    candidate["validation"]["entries"][0]["transition_range"] = [1, 2]
                (directory / "validation.json").write_text(json.dumps(candidate))
                (directory / "profile.json").write_text("{}")
                native = {} if mode == "legacy" else {"traceMode": "whole-program"}
                with (
                    self.subTest(mode=mode),
                    mock.patch.object(
                        evaluation,
                        "_native_trigger_artifacts",
                        return_value=(binary, oracle, 0, "json", native),
                    ),
                    mock.patch.object(
                        evaluation,
                        "read_symbols",
                        side_effect=AssertionError("symbol lookup"),
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
                    ) as run,
                    mock.patch.object(
                        evaluation,
                        "_qemu_profile_rows",
                        return_value=(
                            [{"seconds": "10", "status": "passed"}],
                            {"totalSeconds": 10},
                        ),
                    ) as timings,
                ):
                    if mode in {"truncated", "legacy"}:
                        with self.assertRaises(evaluation.EvaluationError):
                            evaluation._evaluate_qemu_trigger(
                                config,
                                case,
                                config.emulators[case.emulator],
                                root / "qemu",
                                root,
                                0,
                                directory,
                            )
                        timings.assert_not_called()
                    else:
                        _, _, passed = evaluation._evaluate_qemu_trigger(
                            config,
                            case,
                            config.emulators[case.emulator],
                            root / "qemu",
                            root,
                            0,
                            directory,
                        )
                        self.assertEqual(passed, mode == "complete")
                    if run.called:
                        command = run.call_args.args[0]
                        self.assertNotIn("--cutpoint-address", command)
                        self.assertNotIn("0x401017", command)
                        self.assertNotIn("0x40101c", command)

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

    def test_native_trigger_gdbserver_transport(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            binary = self._write_executable(root / "trigger", "#!/bin/sh\nexit 0\n")
            capture = self._fake_capture(root / "capture")
            server = self._write_executable(root / "gdbserver", "#!/bin/sh\nexit 0\n")
            path = self._write_config(
                root,
                capture=capture,
                nm=capture,
                rr=capture,
                triggers={
                    "arbitrary": {
                        "binary": str(binary),
                        "expectedStatus": 0,
                        "nativeTransport": "gdbserver",
                    }
                },
            )
            document = json.loads(path.read_text())
            document["gdbserverProgram"] = str(server)
            document["triggerTraceMode"] = "whole-program"
            path.write_text(json.dumps(document))
            config = evaluation.load_config(path)
            with (
                mock.patch.object(evaluation, "ManagedProcess") as managed,
                mock.patch.object(
                    evaluation, "_wait_for_gdbserver", return_value=43210
                ),
                mock.patch.object(
                    evaluation.socket, "create_connection", side_effect=AssertionError
                ),
            ):
                rows, metadata, passed = evaluation.evaluate_trigger(
                    config, config.triggers["arbitrary"], 0, root / "run", "msgpack"
                )
            self.assertTrue(passed, rows)
            self.assertEqual(metadata["nativeTransport"], "gdbserver")
            self.assertEqual(metadata["gdbserverProgram"], str(server))
            self.assertEqual(metadata["gdbserverSha256"], evaluation._sha256(server))
            command = managed.call_args.args[0]
            self.assertEqual(command[:3], (str(server), "--once", "127.0.0.1:0"))
            self.assertEqual(managed.call_args.kwargs["env"]["SHELL"], "/bin/sh")
            self.assertEqual(managed.call_args.kwargs["env"]["ZDOTDIR"], "/nonexistent")
            managed.return_value.__exit__.assert_called_once()
            self.assertIn(
                "-r 127.0.0.1:43210",
                (root / "run/logs/arbitrary-0-capture.log").read_text(),
            )
            with (
                mock.patch.object(evaluation, "ManagedProcess") as managed,
                mock.patch.object(
                    evaluation,
                    "_wait_for_gdbserver",
                    side_effect=evaluation.EvaluationError("not ready"),
                ),
            ):
                rows, _, passed = evaluation.evaluate_trigger(
                    config, config.triggers["arbitrary"], 1, root / "run", "msgpack"
                )
            self.assertFalse(passed)
            managed.return_value.__exit__.assert_called_once()
            self.assertEqual(rows[-1]["status"], "failed")
            del document["gdbserverProgram"]
            path.write_text(json.dumps(document))
            with self.assertRaises(evaluation.EvaluationError):
                evaluation.load_config(path)

    def test_gdbserver_lifecycle_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            log = Path(temporary_directory) / "server.log"
            with (
                mock.patch.object(evaluation.subprocess, "Popen") as popen,
                mock.patch.object(evaluation.os, "killpg") as killpg,
            ):
                process = popen.return_value
                process.pid = 1234
                process.poll.return_value = None
                process.wait.side_effect = [
                    evaluation.subprocess.TimeoutExpired("server", 3),
                    0,
                ]
                with self.assertRaisesRegex(
                    evaluation.EvaluationError, "capture failed"
                ):
                    with evaluation.ManagedProcess(
                        ("server",), log, env={"SHELL": "/bin/sh"}
                    ):
                        raise evaluation.EvaluationError("capture failed")
                self.assertEqual(
                    killpg.call_args_list,
                    [
                        mock.call(1234, evaluation.signal.SIGTERM),
                        mock.call(1234, evaluation.signal.SIGKILL),
                    ],
                )
                self.assertTrue(popen.call_args.kwargs["start_new_session"])
                self.assertTrue(popen.call_args.kwargs["stdout"].closed)

    def test_gdbserver_readiness_does_not_connect(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            log = Path(temporary_directory) / "server.log"
            log.write_text("Process created; pid = 123\nListening on port 43210\n")
            process = mock.Mock()
            process.poll.return_value = None
            with mock.patch.object(
                evaluation.socket, "socket", side_effect=AssertionError
            ):
                self.assertEqual(evaluation._wait_for_gdbserver(process, log), 43210)
                process.poll.return_value = 1
                with self.assertRaisesRegex(evaluation.EvaluationError, "exited"):
                    evaluation._wait_for_gdbserver(process, log)
                process.poll.return_value = None
                log.write_text("Listening on port 99999\n")
                with self.assertRaisesRegex(evaluation.EvaluationError, "invalid port"):
                    evaluation._wait_for_gdbserver(process, log)
                log.write_text("")
                with mock.patch.object(evaluation, "SERVER_STARTUP_TIMEOUT_SECONDS", 0):
                    with self.assertRaisesRegex(
                        evaluation.EvaluationError, "timed out"
                    ):
                        evaluation._wait_for_gdbserver(process, log)

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
            self.assertEqual(
                application_metadata["oracleSha256"],
                evaluation._sha256(system_directory / application_metadata["oracle"]),
            )
            self.assertEqual(application_metadata["traceSeconds"], 7.0)
            self.assertEqual(application_metadata["serializationSeconds"], 11.0)
            capture_log = (system_directory / "logs/sqlite-0-capture.log").read_text()
            self.assertIn("--start-address 0x402000", capture_log)
            self.assertIn("--profile-report", capture_log)
            self.assertIn("--out-type msgpack", capture_log)
            self.assertNotIn("--cross-validate", capture_log)
            self.assertNotIn("--whole-program", capture_log)
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
            for capture_log in (cross_log, speculative_log):
                self.assertIn("--whole-program", capture_log)
                self.assertNotIn("--start-address", capture_log)
                self.assertNotIn("--stop-address", capture_log)
                self.assertNotIn("--skip-unmatched", capture_log)
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

    def test_box64_whole_program_binds_process_completion_and_structured_report(self):
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

            self._complete_native_fixture_identity(native_directory)
            emulator_output = root / "box64-output"
            (emulator_output / "bin").mkdir(parents=True)
            self._write_executable(
                emulator_output / "bin/box64",
                "#!/bin/sh\n"
                'test "$BOX64_TRACE" = 1 || exit 8\n'
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
                '\'"status":"mismatch","completion":{"executionComplete":true}}\' > "$report"\n',
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
                trigger_trace_mode="whole-program",
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
            case_root = system_directory / "box64-log/box64-0-3-8/508/0"
            report = case_root / "validation.json"
            self.assertTrue(report.is_file())
            evidence = json.loads((case_root / "execution-evidence.json").read_text())
            self.assertEqual(evidence["schema"], "focaccia-text-process-evidence-v1")
            self.assertEqual(evidence["processState"], "exited")
            self.assertEqual(evidence["exitStatus"], 0)
            self.assertEqual(
                metadata["cases"]["box64-508"]["iterations"][0]["executionComplete"],
                True,
            )
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

            self._complete_native_fixture_identity(native_directory)
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
                '\'"status":"mismatch","validation":{"entries":[{\''
                '\'"transition_range":[4198400,4198404],"errors":[{\''
                '\'"severity":"confirmed","code":"memory-content-mismatch",\''
                '\'"subject":"0x5500800bcf"}]}]}}\' > "$report"\n'
                "printf '%s\\n' "
                '\'{"schema":"focaccia-qemu-validation-profile-v1",\''
                '\'"status":"passed","timings":{\''
                '\'"executionSeconds":1,"tracingSeconds":2,\''
                '\'"validationSeconds":3,"serializationSeconds":4,\''
                '\'"totalSeconds":10}}\' > "$profile"\n'
                "printf '%s\\n' states > \"$output\"\n",
            )
            unused = self._write_executable(root / "unused", "#!/bin/sh\nexit 0\n")
            nm = self._write_executable(
                root / "nm",
                "#!/bin/sh\nprintf '0000000000401000 T focaccia_trace_start\\n'\n",
            )
            config = self._write_config(
                root,
                capture=unused,
                nm=nm,
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
                        "expectedMismatchSourceSymbol": "focaccia_trace_start",
                        "expectedMismatchSourceOffset": 0,
                        "expectedMismatchLength": 4,
                        "expectedMismatchCode": "memory-content-mismatch",
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

            self._complete_native_fixture_identity(native_directory)
            emulator_output = root / "qemu-plugin-output"
            (emulator_output / "bin").mkdir(parents=True)
            (emulator_output / "lib/plugins").mkdir(parents=True)
            (emulator_output / "lib/plugins/libfocaccia.so").write_bytes(b"plugin")
            qemu = self._write_executable(
                emulator_output / "bin/qemu-aarch64",
                f"#!{sys.executable}\n"
                "import os, pathlib, socket, sys, time\n"
                f"pathlib.Path({str(root / 'qemu.pid')!r}).write_text(str(os.getpid()))\n"
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
                "ready_path = pathlib.Path(value('--plugin-terminal-ready'))\n"
                "evidence_path = pathlib.Path(value('--plugin-terminal-evidence'))\n"
                "ready = {'schema':'focaccia-plugin-terminal-ready-v1',\n"
                f" 'nonce':'n','pid':int(pathlib.Path({str(root / 'qemu.pid')!r}).read_text()),\n"
                f" 'binarySha256':{evaluation._sha256(binary)!r},\n"
                " 'finalPc':0x40101c,'transformCount':7,'stateCount':8}\n"
                "ready_path.write_text(json.dumps(ready))\n"
                "while not evidence_path.exists(): pass\n"
                "report = {\n"
                " 'schema':'focaccia-qemu-validation-v1', 'status':'mismatch',\n"
                " 'trace':{'available':True,'complete':False,'state_count':8,\n"
                "          'transform_count':7,'terminal_reached':False},\n"
                " 'completion':{'scope':'whole-program',\n"
                "  'expected_completion_available':True,\n"
                "  'observed_completion_available':True,\n"
                "  'final_live_boundary_bound':True,'execution_complete':True,\n"
                "  'full_run_timing_eligible':True,\n"
                "  'terminal_outcome':'mismatch','terminal_action':'mismatch'},\n"
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
            self._complete_native_fixture_identity(native_directory)
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

            self._complete_native_fixture_identity(native_directory)
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
                '"trace":{"available":true,"complete":true,'
                '"terminal_reached":true,"state_count":2,"transform_count":1},'
                '"status":"mismatch","validation":{"diagnostics":[],"diagnostic_counts":{},'
                '"severity_counts":{"confirmed":1},"entries":[{'
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

    @staticmethod
    def _complete_native_fixture_identity(directory: Path) -> None:
        """Simulate producer metadata for newly created fake artifacts only."""
        path = directory / "metadata.json"
        document = json.loads(path.read_text())
        document.update(
            role="native",
            system=directory.name,
            machine=directory.name.removesuffix("-linux"),
        )
        for case in document["cases"].values():
            kind = case.setdefault("kind", "trigger")
            for item in case["iterations"]:
                item["kind"] = kind
                for field in (
                    ("binary",) if kind == "trigger" else ("injectedBinary",)
                ) + ("oracle",):
                    item.setdefault(
                        field + "Sha256", evaluation._sha256(directory / item[field])
                    )
        path.write_text(json.dumps(document))

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
        trigger_trace_mode: str = "legacy-witness",
    ) -> Path:
        config = root / "config.json"
        config.write_text(
            json.dumps(
                {
                    "schema": "focaccia-evaluation-config-v5",
                    "role": role,
                    "triggerTraceMode": trigger_trace_mode,
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
