"""Plot geometry must preserve measurements, not just produce a PDF."""

import csv
import hashlib
import json
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import matplotlib.pyplot as plt

import plots


class ReproducerSizePlotTests(unittest.TestCase):
    def tearDown(self):
        plt.close("all")

    def test_large_guest_and_minimized_sizes_are_not_clipped(self):
        sizes = {"sqlite": (1600.0, 120.0), "1370": (80.0, 65.0)}
        with patch.object(plots, "_save") as save:
            plots.plot_reproducer_sizes(sizes, Path("unused"))
        figure = save.call_args.args[0]
        self.assertEqual(len(figure.axes), 2)
        for axis, expected in zip(figure.axes, sizes.values()):
            self.assertEqual([bar.get_height() for bar in axis.patches], list(expected))
            self.assertGreater(axis.get_ylim()[1], max(expected))
            self.assertEqual(axis.texts[0].get_position()[1], expected[0])
        self.assertEqual(figure.axes[0].get_ylim(), figure.axes[1].get_ylim())

    def test_small_sizes_retain_paper_scale(self):
        with patch.object(plots, "_save") as save:
            plots.plot_reproducer_sizes({"1372": (32.0, 4.0)}, Path("unused"))
        axis = save.call_args.args[0].axes[0]
        self.assertEqual([bar.get_height() for bar in axis.patches], [32.0, 4.0])
        self.assertEqual(axis.get_ylim(), (0.0, 50.0))

    def test_missing_evidence_does_not_generate_a_size_figure(self):
        with patch.object(plots, "_save") as save:
            self.assertIsNone(plots.plot_reproducer_sizes({}, Path("unused")))
        save.assert_not_called()


class ApplicationTrendPlotTests(unittest.TestCase):
    def tearDown(self):
        plt.close("all")

    def test_ratios_use_shared_qemu_over_native_normalization(self):
        rows = []
        for benchmark, native, qemu in (
            ("lua", (1, 2, 0), (6, 3, 0)),
            ("curl", (2, 2, 0), (8, 4, 0)),
        ):
            for mode, names, values in (
                ("native-selective", ("concrete", "symbolic", "validation"), native),
                ("qemu-test", ("execution", "tracing", "validation"), qemu),
            ):
                for component, seconds in zip(names, values):
                    rows.append(
                        {
                            "benchmark": benchmark,
                            "mode": mode,
                            "component": component,
                            "seconds": str(seconds),
                            "status": "passed",
                            "system": "test-system",
                        }
                    )
        labels, paper, current = plots.application_trend_ratios(
            plots.Measurements(rows)
        )
        self.assertEqual(labels, ["Lua", "Curl"])
        self.assertEqual(current, [3.0, 3.0])
        self.assertAlmostEqual(
            paper[0],
            sum(plots.PAPER_APPLICATION_COMPONENTS["lua"][1])
            / sum(plots.PAPER_APPLICATION_COMPONENTS["lua"][0]),
        )


class TimingAccountingTests(unittest.TestCase):
    def measurements(self):
        rows = []
        values = {
            "native-full-cross-validated": (10, 20, 30, 65, 5, 72),
            "native-full-speculative": (2, 20, 0, 24, 4, 29),
        }
        for mode, (*components, trace, serialization, capture) in values.items():
            for component, seconds in zip(
                (
                    "concrete",
                    "symbolic",
                    "validation",
                    "total",
                    "serialization",
                    "capture",
                ),
                (*components, trace, serialization, capture),
            ):
                rows.append(
                    {
                        "benchmark": "curl-full",
                        "mode": mode,
                        "component": component,
                        "seconds": str(seconds),
                        "status": "passed",
                        "system": "x86_64-linux",
                    }
                )
        return plots.Measurements(rows)

    def test_exact_accounting_keeps_exclusive_trace_serialization_and_setup_disjoint(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp:
            destination = plots.write_timing_accounting(self.measurements(), Path(temp))
            document = json.loads(destination.read_text())
        cross = document["cases"]["native-cross-validated"]
        self.assertEqual(cross["exclusiveSumSeconds"], 60)
        self.assertEqual(cross["traceResidualSeconds"], 5)
        self.assertEqual(cross["setupResidualSeconds"], 2)
        self.assertEqual(cross["endToEndWallSeconds"], 72)
        self.assertEqual(
            cross["traceWallSeconds"]
            + cross["serializationSeconds"]
            + cross["setupResidualSeconds"],
            72,
        )
        self.assertEqual(document["speedups"]["endToEndWall"], 72 / 29)
        self.assertFalse(document["paperLegacy"]["equivalentToCurrentAccounting"])

    def test_negative_residual_is_rejected_instead_of_double_counted(self):
        data = self.measurements()
        data.values[("curl-full", "native-full-cross-validated", "capture")] = 60
        with (
            tempfile.TemporaryDirectory() as temp,
            self.assertRaisesRegex(ValueError, "negative setup residual"),
        ):
            plots.write_timing_accounting(data, Path(temp))


class ProfileRelocationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.old = Path("/nonexistent-recorded-run")
        self.system = self.root / "emulated/qemu/aarch64-linux"
        self.system.mkdir(parents=True)
        self.profile = self.system / "profile.json"
        self.document = {
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
        self.encoded = {
            "profile": str(self.old / self.profile.relative_to(self.root)),
        }
        self.write_profile()
        with (self.system / "results.csv").open("w") as stream:
            writer = csv.writer(stream)
            writer.writerow(
                ["benchmark", "mode", "component", "seconds", "iteration", "status"]
            )
            for component, seconds in zip(
                ["execution", "tracing", "validation", "serialization", "total"],
                [1, 2, 3, 4, 10],
            ):
                writer.writerow(["508", "qemu-test", component, seconds, 0, "passed"])

    def write_profile(self):
        self.profile.write_text(json.dumps(self.document))
        self.encoded["profileSha256"] = hashlib.sha256(
            self.profile.read_bytes()
        ).hexdigest()

    def load(self, relocate=True):
        metadata = {
            "schema": plots.EMULATED_METADATA_SCHEMA,
            "role": "qemu",
            "system": "aarch64-linux",
            "cases": {
                "qemu-508": {
                    "status": "passed",
                    "benchmark": "508",
                    "emulator": "qemu-test",
                    "iterations": [self.encoded],
                }
            },
        }
        (self.system / "metadata.json").write_text(json.dumps(metadata))
        data = plots.load_measurements(
            self.root, relocate_from=self.old if relocate else None
        )
        return data.get("508", "qemu-test", "execution")

    def test_explicit_relocation_preserves_measurements(self):
        self.assertIsNone(self.load(relocate=False))
        self.assertEqual(self.load(), 1)
        args = plots.make_argparser().parse_args(
            ["--input", str(self.root), "--relocate-from", str(self.old)]
        )
        self.assertEqual(args.relocate_from, self.old)

    def test_relative_and_existing_absolute_paths_are_unchanged(self):
        for path in ("profile.json", str(self.profile)):
            with self.subTest(path=path):
                self.encoded["profile"] = path
                self.assertEqual(self.load(), 1)
                self.assertEqual(self.load(relocate=False), 1)

    def test_unrelated_prefix_and_traversal_are_not_remapped(self):
        for path in (
            "/nonexistent-recorded-run-other/emulated/qemu/aarch64-linux/profile.json",
            "/unrelated/emulated/qemu/aarch64-linux/profile.json",
            str(self.old / ".." / self.root.name / "profile.json"),
        ):
            with self.subTest(path=path):
                self.encoded["profile"] = path
                self.assertIsNone(self.load())

    def test_relocation_still_requires_hash_schema_status_and_csv_agreement(self):
        self.encoded["profileSha256"] = "0" * 64
        self.assertIsNone(self.load())
        for key, value in (("schema", "unsupported"), ("status", "failed")):
            original = self.document[key]
            self.document[key] = value
            self.write_profile()
            self.assertIsNone(self.load())
            self.document[key] = original
        self.document["timings"]["executionSeconds"] = 99
        self.write_profile()
        self.assertIsNone(self.load())

    def test_invalid_relocation_root_is_rejected(self):
        for root in (Path("relative"), Path("/old/../root")):
            with self.subTest(root=root), self.assertRaises(ValueError):
                plots.load_measurements(self.root, relocate_from=root)


class CrossIsaFullCurlPlotTests(unittest.TestCase):
    def tearDown(self):
        plt.close("all")

    @staticmethod
    def _write_json(path, document):
        path.parent.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(document, sort_keys=True).encode()
        path.write_bytes(encoded)
        return hashlib.sha256(encoded).hexdigest()

    def _run_root(self, root):
        native_directory = root / "native/x86_64-linux"
        qemu_directory = root / "emulated/qemu/aarch64-linux"
        guest_binary = native_directory / "binaries/application-curl-injected"
        oracle = native_directory / "oracles/curl-full.trace"
        workload_bytes = b"fixed 5 KiB Curl workload fixture"
        guest_binary.parent.mkdir(parents=True)
        oracle.parent.mkdir(parents=True)
        guest_binary.write_bytes(b"guest ELF identity")
        oracle.write_bytes(b"native symbolic oracle")
        binary_hash = hashlib.sha256(guest_binary.read_bytes()).hexdigest()
        oracle_hash = hashlib.sha256(oracle.read_bytes()).hexdigest()
        workload_hash = hashlib.sha256(workload_bytes).hexdigest()
        argv = [
            "--fail",
            "--silent",
            "--show-error",
            "--output",
            "download.bin",
            "http://127.0.0.1:12345/curl-5k.bin",
        ]
        rr_directory = native_directory / "rr/curl-full-0"
        rr_directory.mkdir(parents=True)
        (rr_directory / "events").write_bytes(b"rr-v85 events")

        native_profiles = {}
        native_rows = []
        capture_values = {
            "native-full-cross-validated": (2, 3, 4, 10, 1, 12, True),
            "native-full-speculative": (1, 5, 0, 7, 1, 9, False),
        }
        for mode, (
            concrete,
            symbolic,
            validation,
            trace,
            serialization,
            capture,
            cross,
        ) in capture_values.items():
            profile = {
                "accounting": {"method": "exclusive-components-v1"},
                "status": "passed",
                "timings": {
                    "concreteSeconds": concrete,
                    "symbolicSeconds": symbolic,
                    "validationSeconds": validation,
                    "traceSeconds": trace,
                    "serializationSeconds": serialization,
                },
            }
            profile_name = f"profiles/{mode}.json"
            profile_path = native_directory / profile_name
            profile_hash = self._write_json(profile_path, profile)
            native_profiles[mode] = {
                "crossValidated": cross,
                "oracle": "oracles/curl-full.trace",
                "oracleSha256": oracle_hash,
                "profile": profile_name,
                "profileSha256": profile_hash,
                "traceSeconds": trace,
                "serializationSeconds": serialization,
                "captureProcessSeconds": capture,
            }
            for component, seconds in (
                ("concrete", concrete),
                ("symbolic", symbolic),
                ("validation", validation),
                ("total", trace),
                ("serialization", serialization),
                ("capture", capture),
                ("setup-residual", capture - trace - serialization),
            ):
                native_rows.append(
                    ["curl-full", mode, component, seconds, 0, "passed", ""]
                )
        self._write_json(
            native_directory / "metadata.json",
            {
                "schema": plots.NATIVE_METADATA_SCHEMA,
                "role": "native",
                "system": "x86_64-linux",
                "status": "passed",
                "cases": {
                    "curl-full": {
                        "kind": "application",
                        "status": "passed",
                        "iterations": [
                            {
                                "kind": "application",
                                "injectedBinary": "binaries/application-curl-injected",
                                "injectedBinarySha256": binary_hash,
                                "oracle": "oracles/curl-full.trace",
                                "oracleSha256": oracle_hash,
                                "workloadKind": "curl",
                                "workloadSha256": workload_hash,
                                "workloadStorePath": "/nix/store/curl-workload",
                                "traceFormat": "msgpack",
                                "traceMode": "full",
                                "argv": argv,
                                "expectedNativeStatus": 0,
                                "rrTrace": "rr/curl-full-0",
                                "startAddress": 0x401000,
                                "stopAddress": 0x43DDA1,
                                "fullCaptures": native_profiles,
                                "profile": native_profiles["native-full-speculative"][
                                    "profile"
                                ],
                                "profileSha256": native_profiles[
                                    "native-full-speculative"
                                ]["profileSha256"],
                            }
                        ],
                    }
                },
            },
        )
        with (native_directory / "results.csv").open("w", newline="") as stream:
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
            writer.writerows(native_rows)

        qemu_binary = qemu_directory / "binaries/application-curl-injected"
        qemu_oracle = qemu_directory / "oracles/curl-full.trace"
        qemu_workload = qemu_directory / "work/curl-5k.bin"
        qemu_binary.parent.mkdir(parents=True)
        qemu_oracle.parent.mkdir(parents=True)
        qemu_workload.parent.mkdir(parents=True)
        qemu_binary.write_bytes(guest_binary.read_bytes())
        qemu_oracle.write_bytes(oracle.read_bytes())
        qemu_workload.write_bytes(workload_bytes)
        finding = {
            "severity": "confirmed",
            "code": "register-content-mismatch",
            "subject": "CF",
        }
        report = {
            "schema": "focaccia-qemu-validation-v1",
            "status": "mismatch",
            "trace": {
                "available": True,
                "complete": True,
                "terminal_reached": False,
                "state_count": 101,
                "transform_count": 100,
            },
            "completion": {
                "scope": "whole-program",
                "complete": True,
                "execution_complete": True,
                "full_run_timing_eligible": True,
                "expected_completion_available": True,
                "observed_completion_available": True,
                "ordinary_prefix_complete": True,
                "final_live_boundary_bound": True,
                "terminal_action": "match",
                "terminal_outcome": "match",
            },
            "replay": {
                "active": True,
                "record_count": 3,
                "by_outcome": {"handled": 3},
            },
            "validation": {
                "diagnostics": [],
                "diagnostic_counts": {},
                "severity_counts": {"confirmed": 1},
                "entries": [
                    {
                        "transition_range": [0x43DD9C, 0x43DDA1],
                        "errors": [finding],
                    }
                ],
            },
        }
        report_path = qemu_directory / "validation/validation.json"
        report_hash = self._write_json(report_path, report)
        manifest = {
            "schema": "focaccia-rr-qemu-run-v1",
            "guest_architecture": {"isa": "x86_64", "endianness": "little"},
            "binary": {"name": "guest-binary", "sha256": binary_hash},
            "oracle": {"name": "symbolic-oracle", "sha256": oracle_hash},
            "inputs": [{"name": "workload", "sha256": workload_hash}],
            "argv": argv,
            "rr": {
                "native_architecture": {"isa": "x86_64", "endianness": "little"},
                "schema_version": "rr-trace-v85",
                "trace_version": 85,
                "trace_uuid": "00112233445566778899aabbccddeeff",
                "directory_sha256": "1" * 64,
            },
        }
        manifest_path = qemu_directory / "validation/run-manifest.json"
        manifest_hash = self._write_json(manifest_path, manifest)
        qemu_profile = {
            "schema": "focaccia-qemu-validation-profile-v1",
            "status": "passed",
            "timings": {
                "executionSeconds": 20,
                "tracingSeconds": 30,
                "validationSeconds": 40,
                "serializationSeconds": 2,
                "totalSeconds": 95,
            },
        }
        qemu_profile_path = qemu_directory / "profiles/curl-full.json"
        qemu_profile_hash = self._write_json(qemu_profile_path, qemu_profile)
        qemu_native = json.loads((native_directory / "metadata.json").read_text())[
            "cases"
        ]["curl-full"]["iterations"][0]
        qemu_iteration = {
            "kind": "application",
            "backend": "qemu-gdb",
            "emulator": "qemu-8-2-0",
            "emulatorVersion": "8.2.0",
            "traceMode": "full",
            "binary": "binaries/application-curl-injected",
            "binarySha256": binary_hash,
            "oracle": "oracles/curl-full.trace",
            "oracleSha256": oracle_hash,
            "workload": "work/curl-5k.bin",
            "workloadSha256": workload_hash,
            "argv": argv,
            "expectedValidation": "mismatch",
            "expectedMismatchLocalized": True,
            "expectedMismatchRange": [0x43DD9C, 0x43DDA1],
            "expectedMismatchSubject": "CF",
            "report": "validation/validation.json",
            "reportSha256": report_hash,
            "runManifest": "validation/run-manifest.json",
            "runManifestSha256": manifest_hash,
            "profile": "profiles/curl-full.json",
            "profileSha256": qemu_profile_hash,
            "native": qemu_native,
            "rrTrace": str(rr_directory.resolve()),
        }
        self._write_json(
            qemu_directory / "metadata.json",
            {
                "schema": plots.EMULATED_METADATA_SCHEMA,
                "role": "qemu",
                "system": "aarch64-linux",
                "status": "passed",
                "cases": {
                    "qemu-app-curl-full": {
                        "kind": "application",
                        "benchmark": "curl-full",
                        "emulator": "qemu-8-2-0",
                        "status": "passed",
                        "iterations": [qemu_iteration],
                    }
                },
            },
        )
        with (qemu_directory / "results.csv").open("w", newline="") as stream:
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
            writer.writerows(
                [
                    ["curl-full", "qemu-8-2-0", "execution", 20, 0, "passed", ""],
                    ["curl-full", "qemu-8-2-0", "tracing", 30, 0, "passed", ""],
                    ["curl-full", "qemu-8-2-0", "validation", 40, 0, "passed", ""],
                    ["curl-full", "qemu-8-2-0", "serialization", 2, 0, "passed", ""],
                    ["curl-full", "qemu-8-2-0", "total", 95, 0, "passed", ""],
                ]
            )
        return root

    def _pair_measurements(self, root):
        return plots._cross_isa_full_curl_measurements(
            root,
            plots.load_measurements(root, system="x86_64-linux"),
            plots.load_measurements(root, system="aarch64-linux"),
            None,
        )

    def _add_duplicate_host_qemu_mode(self, root, system):
        directory = root / "emulated/qemu" / system
        directory.mkdir(parents=True, exist_ok=True)
        profile = {
            "schema": "focaccia-qemu-validation-profile-v1",
            "status": "passed",
            "timings": {
                "executionSeconds": 2,
                "tracingSeconds": 3,
                "validationSeconds": 4,
                "serializationSeconds": 1,
                "totalSeconds": 10,
            },
        }
        profile_hash = self._write_json(directory / "profiles/508.json", profile)
        metadata_path = directory / "metadata.json"
        metadata = (
            json.loads(metadata_path.read_text())
            if metadata_path.exists()
            else {
                "schema": plots.EMULATED_METADATA_SCHEMA,
                "role": "qemu",
                "system": system,
                "status": "passed",
                "cases": {},
            }
        )
        metadata["cases"]["qemu-508-test"] = {
            "kind": "trigger",
            "benchmark": "508",
            "emulator": "qemu-same-mode",
            "status": "passed",
            "iterations": [
                {"profile": "profiles/508.json", "profileSha256": profile_hash}
            ],
        }
        metadata_path.write_text(json.dumps(metadata))
        result_path = directory / "results.csv"
        if result_path.exists():
            with result_path.open(newline="") as stream:
                rows = list(csv.DictReader(stream))
        else:
            rows = []
        with result_path.open("w", newline="") as stream:
            fields = [
                "benchmark",
                "mode",
                "component",
                "seconds",
                "iteration",
                "status",
                "detail",
            ]
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
            for component, seconds in (
                ("execution", 2),
                ("tracing", 3),
                ("validation", 4),
                ("serialization", 1),
                ("total", 10),
            ):
                writer.writerow(
                    {
                        "benchmark": "508",
                        "mode": "qemu-same-mode",
                        "component": component,
                        "seconds": seconds,
                        "iteration": 0,
                        "status": "passed",
                        "detail": "",
                    }
                )

    def test_cli_generates_full_curl_figure_from_bound_cross_isa_roles(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self._run_root(Path(temp))
            self._add_duplicate_host_qemu_mode(root, "x86_64-linux")
            self._add_duplicate_host_qemu_mode(root, "aarch64-linux")
            output = root / "figures"
            stderr = io.StringIO()
            with (
                patch("sys.argv", ["plots", "--input", str(root)]),
                patch("sys.stderr", stderr),
                patch.object(
                    plots,
                    "read_symbols",
                    return_value={"focaccia_injection_curl_2175": 0x43DD9C},
                ),
            ):
                self.assertEqual(plots.main(), 0)

            figure = output / "tracing-comparison.pdf"
            self.assertTrue(figure.is_file(), stderr.getvalue())
            self.assertGreater(figure.stat().st_size, 0)
            evidence = json.loads(
                (output / plots.MULTI_HOST_FULL_CURL_EVIDENCE_NAME).read_text()
            )
            self.assertEqual(evidence["producerSystem"], "x86_64-linux")
            self.assertEqual(evidence["emulatorHostSystem"], "aarch64-linux")
            self.assertEqual(evidence["guestIsa"], "x86_64")
            self.assertEqual(len(evidence["iterations"]), 1)
            summary = json.loads((output / plots.MULTI_HOST_SUMMARY_NAME).read_text())
            self.assertEqual(summary["crossRolePlots"]["curl-full"]["status"], "passed")

    def test_pair_rejects_mismatched_guest_input_oracle_and_findings(self):
        mutations = (
            ("binary", lambda item: item.__setitem__("binarySha256", "0" * 64)),
            ("workload", lambda item: item.__setitem__("workloadSha256", "0" * 64)),
            ("oracle", lambda item: item.__setitem__("oracleSha256", "0" * 64)),
            (
                "guest-isa",
                lambda data: data.__setitem__(
                    "guest_architecture", {"isa": "aarch64", "endianness": "little"}
                ),
            ),
            (
                "unrelated-finding",
                lambda data: data["validation"]["entries"][0]["errors"].append(
                    {
                        "severity": "confirmed",
                        "code": "register-content-mismatch",
                        "subject": "RAX",
                    }
                ),
            ),
        )
        for name, mutate in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                root = self._run_root(Path(temp))
                qemu_directory = root / "emulated/qemu/aarch64-linux"
                iteration = json.loads((qemu_directory / "metadata.json").read_text())[
                    "cases"
                ]["qemu-app-curl-full"]["iterations"][0]
                if name in {"binary", "workload", "oracle"}:
                    mutate(iteration)
                    metadata = json.loads(
                        (qemu_directory / "metadata.json").read_text()
                    )
                    metadata["cases"]["qemu-app-curl-full"]["iterations"][0] = iteration
                    (qemu_directory / "metadata.json").write_text(json.dumps(metadata))
                elif name == "guest-isa":
                    manifest_path = qemu_directory / iteration["runManifest"]
                    manifest = json.loads(manifest_path.read_text())
                    mutate(manifest)
                    manifest_bytes = json.dumps(manifest, sort_keys=True).encode()
                    manifest_path.write_bytes(manifest_bytes)
                    iteration["runManifestSha256"] = hashlib.sha256(
                        manifest_bytes
                    ).hexdigest()
                    metadata = json.loads(
                        (qemu_directory / "metadata.json").read_text()
                    )
                    metadata["cases"]["qemu-app-curl-full"]["iterations"][0] = iteration
                    (qemu_directory / "metadata.json").write_text(json.dumps(metadata))
                else:
                    report_path = qemu_directory / iteration["report"]
                    report = json.loads(report_path.read_text())
                    mutate(report)
                    report_bytes = json.dumps(report, sort_keys=True).encode()
                    report_path.write_bytes(report_bytes)
                    iteration["reportSha256"] = hashlib.sha256(report_bytes).hexdigest()
                    metadata = json.loads(
                        (qemu_directory / "metadata.json").read_text()
                    )
                    metadata["cases"]["qemu-app-curl-full"]["iterations"][0] = iteration
                    (qemu_directory / "metadata.json").write_text(json.dumps(metadata))
                with patch.object(
                    plots,
                    "read_symbols",
                    return_value={"focaccia_injection_curl_2175": 0x43DD9C},
                ):
                    with self.assertRaises(plots.EvaluationError):
                        self._pair_measurements(root)

    def test_other_host_timings_are_not_joined_into_role_pair(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self._run_root(Path(temp))
            native = plots.load_measurements(root, system="x86_64-linux")
            consumer = plots.load_measurements(root, system="aarch64-linux")
            # Add an unrelated full-Curl-looking mode to the producer host view.
            # The cross-role constructor must still source QEMU only from AArch64.
            native.values[("curl-full", "qemu-decoy", "execution")] = 9999
            native.modes["curl-full"].add("qemu-decoy")
            with patch.object(
                plots,
                "read_symbols",
                return_value={"focaccia_injection_curl_2175": 0x43DD9C},
            ):
                paired, _ = plots._cross_isa_full_curl_measurements(
                    root, native, consumer, None
                )
            self.assertEqual(paired.get("curl-full", "qemu-8-2-0", "execution"), 20)
            self.assertIsNone(paired.get("curl-full", "qemu-decoy", "execution"))


class HostMeasurementIdentityTests(unittest.TestCase):
    def row(self, system, seconds, component="execution", benchmark="508"):
        return {
            "benchmark": benchmark,
            "mode": "qemu-test",
            "component": component,
            "seconds": str(seconds),
            "iteration": "0",
            "status": "passed",
            "system": system,
        }

    def test_same_host_iterations_still_average(self):
        data = plots.Measurements(
            [self.row("aarch64-linux", 2), self.row("aarch64-linux", 4)]
        )
        self.assertEqual(data.get("508", "qemu-test", "execution"), 3)

    def test_mixed_hosts_cannot_average_or_assemble_components(self):
        for component in ("execution", "tracing"):
            with (
                self.subTest(component=component),
                self.assertRaisesRegex(ValueError, "ambiguous measurement systems"),
            ):
                plots.Measurements(
                    [
                        self.row("aarch64-linux", 2),
                        self.row("x86_64-linux", 40, component),
                    ]
                )

    def test_disjoint_benchmarks_on_different_systems_remain_valid(self):
        data = plots.Measurements(
            [
                self.row("aarch64-linux", 2),
                self.row("x86_64-linux", 40, benchmark="2419"),
            ]
        )
        self.assertEqual(data.get("508", "qemu-test", "execution"), 2)
        self.assertEqual(data.get("2419", "qemu-test", "execution"), 40)

    def write_evidence(self, root, system, seconds, *, profile):
        directory = root / "emulated" / "qemu" / system
        directory.mkdir(parents=True)
        case = {
            "status": "passed",
            "benchmark": "508",
            "emulator": "qemu-test",
            "iterations": [],
        }
        rows = [self.row("untrusted-csv-system", seconds)]
        if profile:
            fields = {
                "execution": "executionSeconds",
                "tracing": "tracingSeconds",
                "validation": "validationSeconds",
                "serialization": "serializationSeconds",
                "total": "totalSeconds",
            }
            document = {
                "schema": "focaccia-qemu-validation-profile-v1",
                "status": "passed",
                "timings": dict.fromkeys(fields.values(), seconds),
            }
            encoded = json.dumps(document).encode()
            (directory / "profile.json").write_bytes(encoded)
            case["iterations"] = [
                {
                    "profile": "profile.json",
                    "profileSha256": hashlib.sha256(encoded).hexdigest(),
                }
            ]
            rows = [self.row("untrusted-csv-system", seconds, c) for c in fields]
        (directory / "metadata.json").write_text(
            json.dumps(
                {
                    "schema": plots.EMULATED_METADATA_SCHEMA,
                    "role": "qemu",
                    "system": system,
                    "cases": {"qemu-508": case},
                }
            )
        )
        with (directory / "results.csv").open("w") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)

    def test_loader_retains_system_for_csv_and_verified_profiles(self):
        for profile in (False, True):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                self.write_evidence(root, "aarch64-linux", 2, profile=profile)
                self.assertEqual(
                    plots.load_measurements(root).get("508", "qemu-test", "execution"),
                    2,
                )
                self.write_evidence(root, "x86_64-linux", 40, profile=profile)
                with self.assertRaisesRegex(
                    ValueError, "ambiguous measurement systems"
                ):
                    plots.load_measurements(root)

    def test_cli_separates_multi_host_figures_and_measurements(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_evidence(root, "aarch64-linux", 2, profile=True)
            self.write_evidence(root, "x86_64-linux", 40, profile=True)
            output = root / "figures"
            with (
                patch("sys.argv", ["plots", "--input", str(root)]),
                patch("sys.stderr", new_callable=io.StringIO),
            ):
                self.assertEqual(plots.main(), 0)

            self.assertEqual(
                plots.load_measurements(root, system="aarch64-linux").get(
                    "508", "qemu-test", "execution"
                ),
                2,
            )
            self.assertEqual(
                plots.load_measurements(root, system="x86_64-linux").get(
                    "508", "qemu-test", "execution"
                ),
                40,
            )
            self.assertFalse(
                any((output / name).exists() for name in plots.FIGURE_NAMES)
            )
            summary = json.loads(
                (output / plots.MULTI_HOST_SUMMARY_NAME).read_text(encoding="utf-8")
            )
            self.assertEqual(set(summary["hosts"]), {"aarch64-linux", "x86_64-linux"})
            for system in summary["hosts"]:
                figure = output / system / "combined-bug-study.pdf"
                self.assertGreater(figure.stat().st_size, 0)
                self.assertIn(figure.name, summary["hosts"][system])


if __name__ == "__main__":
    unittest.main()
