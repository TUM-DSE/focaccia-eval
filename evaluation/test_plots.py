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

    def test_cli_rejects_ambiguity_before_modifying_figures(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_evidence(root, "aarch64-linux", 2, profile=True)
            self.write_evidence(root, "x86_64-linux", 40, profile=True)
            output = root / "figures"
            output.mkdir()
            retained = output / plots.FIGURE_NAMES[0]
            retained.write_bytes(b"retained figure")
            with (
                patch("sys.argv", ["plots", "--input", str(root)]),
                patch("sys.stderr", new_callable=io.StringIO) as stderr,
                self.assertRaises(SystemExit) as error,
            ):
                plots.main()
            self.assertEqual(error.exception.code, 2)
            self.assertIn("ambiguous measurement systems", stderr.getvalue())
            self.assertEqual(retained.read_bytes(), b"retained figure")


if __name__ == "__main__":
    unittest.main()
