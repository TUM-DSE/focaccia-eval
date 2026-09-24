from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from focaccia.arch import x86
from focaccia.completion import TraceCompletion, TraceScope
from focaccia.execution import ExecutionOutcome, ExecutionState
from focaccia.persistence import serialize_transformations
from focaccia.symbolic import SymbolicTransform
from focaccia.trace import MaterializedTrace, TraceEnvironment

import reproducer_evaluation as evaluation


class DiagnosticAdapterTests(unittest.TestCase):
    def fixture(self, root):
        expected = bytes(range(32)).hex()
        actual = (bytes(range(16)) + bytes(16)).hex()
        target = dict(code="memory-content-mismatch", widthBytes=32, expected=expected, actual=actual)
        report = {"schema": evaluation.QEMU_REPORT_SCHEMA, "status": "mismatch", "completion": {"execution_complete": True}, "trace": {"complete": False}, "validation": {"entries": [{"pc": 4096, "errors": [{"code": target["code"], "severity": "confirmed", "message": f"Content of memory at 0x10 is false. Expected {expected}, actual {actual}."}]}]}}
        document = {"schema": evaluation.DIAGNOSTIC_ADAPTER_SCHEMA, "case": "qemu-1861404", "admission": "diagnostic-target-only", "notClaims": evaluation.DIAGNOSTIC_NOT_CLAIMS.copy(), "binary": {}, "oracle": {}, "consumer": {"status": "mismatch", "executionCompleted": True, "allTransitionsValidated": False, "confirmedTarget": target}}
        for section, key, digest in (("binary", "path", "sha256"), ("oracle", "path", "sha256"), ("oracle", "profile", "profileSha256"), ("consumer", "report", "reportSha256"), ("consumer", "states", "statesSha256"), ("consumer", "profile", "profileSha256")):
            path = root / (section + '-' + key)
            path.write_text(json.dumps(report) if key == "report" else "fixture")
            document[section][key] = path.name
            document[section][digest] = evaluation.common._sha256(path)
        adapter = root / "adapter.json"
        adapter.write_text(json.dumps(document))
        case = mock.Mock(identifier="1861404", source_case="qemu-1861404")
        return adapter, case, document, report

    def test_admits_only_explicit_hash_bound_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            adapter, case, document, report = self.fixture(root)
            artifacts = evaluation.load_diagnostic_source_adapter(adapter, root, case)
            self.assertEqual(artifacts.metadata["diagnosticAdapter"]["notClaims"], evaluation.DIAGNOSTIC_NOT_CLAIMS)
            self.assertNotIn("native", artifacts.metadata)
            document["admission"] = "passed"
            adapter.write_text(json.dumps(document))
            with self.assertRaises(evaluation.ReproducerEvaluationError):
                evaluation.load_diagnostic_source_adapter(adapter, root, case)

    def test_every_hash_is_verified(self):
        for name in ("binary-path", "oracle-path", "oracle-profile", "consumer-report", "consumer-states", "consumer-profile"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                adapter, case, _, _ = self.fixture(root)
                (root / name).write_text("tampered")
                with self.assertRaisesRegex(evaluation.ReproducerEvaluationError, "hash mismatch"):
                    evaluation.load_diagnostic_source_adapter(adapter, root, case)

    def test_exact_32_byte_mismatch_required(self):
        with tempfile.TemporaryDirectory() as directory:
            _, _, document, report = self.fixture(Path(directory))
            target = document["consumer"]["confirmedTarget"]
            evaluation.require_exact_vector_mismatch(report, target)
            error = report["validation"]["entries"][0]["errors"][0]
            error["message"] = error["message"].replace(target["actual"], "00")
            with self.assertRaisesRegex(evaluation.ReproducerEvaluationError, "32-byte"):
                evaluation.require_exact_vector_mismatch(report, target)
            target["widthBytes"] = 16
            with self.assertRaisesRegex(evaluation.ReproducerEvaluationError, "32-byte"):
                evaluation.require_exact_vector_mismatch(report, target)

    def test_reference_incomplete_is_not_acceptance(self):
        with self.assertRaisesRegex(evaluation.ReproducerEvaluationError, "not acceptance"):
            evaluation.require_reference_acceptance({"status": "incomplete"})

    def test_source_scope_is_verified_against_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            adapter, case, document, report = self.fixture(root)
            report["completion"]["execution_complete"] = False
            path = root / document["consumer"]["report"]
            path.write_text(json.dumps(report))
            document["consumer"]["reportSha256"] = evaluation.common._sha256(path)
            adapter.write_text(json.dumps(document))
            with self.assertRaisesRegex(evaluation.ReproducerEvaluationError, "scope contradicts"):
                evaluation.load_diagnostic_source_adapter(adapter, root, case)

    def test_contiguous_composition_preserves_each_transform(self):
        first = mock.Mock(range=(4096, 4100))
        second = mock.Mock(range=(4100, 4110))
        contract = evaluation.MismatchContract(4096, 4110, ())
        with mock.patch.object(evaluation, "_decode_indexed_msgpack_transforms", side_effect=[[first], [second]]) as decode:
            result = evaluation._load_diagnostic_transform(Path("fixture"), contract)
        self.assertIs(result, first.composed_with.return_value)
        first.composed_with.assert_called_once_with(second)
        self.assertEqual([call.args[1] for call in decode.call_args_list], [4096, 4100])
        for candidates in ([], [first, first], [mock.Mock(range=(4096, 4096))], [mock.Mock(range=(4096, 4111))]):
            with self.subTest(candidates=candidates), mock.patch.object(evaluation, "_decode_indexed_msgpack_transforms", return_value=candidates):
                with self.assertRaises(evaluation.ReproducerEvaluationError):
                    evaluation._load_diagnostic_transform(Path("fixture"), contract)

    def test_cli_diagnostic_options_are_explicit(self):
        with mock.patch.object(evaluation, "run") as normal:
            self.assertEqual(evaluation.main(["--config", "config", "--input", ".", "--diagnostic-source-adapter", "adapter"]), 2)
            self.assertEqual(evaluation.main(["--config", "config", "--input", ".", "--artifact-root", "."]), 2)
            normal.assert_not_called()

    def test_paths_cannot_escape_artifact_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            adapter, case, document, _ = self.fixture(root)
            document["binary"]["path"] = str(Path(__file__).resolve())
            adapter.write_text(json.dumps(document))
            with self.assertRaisesRegex(evaluation.ReproducerEvaluationError, "escapes"):
                evaluation.load_diagnostic_source_adapter(adapter, root, case)


class AArch64AdmissionTests(unittest.TestCase):
    def test_retained_mismatch_is_not_entry_context(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "validation.json"
            report.write_text(json.dumps({"schema": evaluation.QEMU_REPORT_SCHEMA, "status": "mismatch"}))
            metadata = root / "emulated/qemu/aarch64-linux/metadata.json"
            metadata.parent.mkdir(parents=True)
            metadata.write_text(json.dumps({
                "schema": evaluation.SOURCE_METADATA_SCHEMA,
                "cases": {
                    "qemu-364": {"status": "passed", "iterations": [{"report": str(report)}]},
                    "qemu-2248": {"status": "failed", "iterations": [{"error": "whole-program completion unsupported"}]},
                    "qemu-2419": {"status": "passed", "iterations": [{"report": str(report)}]},
                },
            }))
            result = evaluation.aarch64_preflight(root)
            self.assertEqual(result["status"], "blocked")
            for case in result["cases"].values():
                self.assertFalse(case["generationAttempted"])
                self.assertFalse(case["controlsAttempted"])
                self.assertEqual(len(case["missingEntryContract"]), 3)
            self.assertEqual(result["cases"]["2248"]["missingSourceArtifacts"], ["binary", "oracle", "states", "report"])
            self.assertEqual(result["cases"]["364"]["artifacts"]["report"]["sha256"], evaluation.common._sha256(report))
            encoded = json.loads(metadata.read_text())
            encoded["cases"]["qemu-364"]["iterations"][0]["reportSha256"] = "0" * 64
            metadata.write_text(json.dumps(encoded))
            with self.assertRaisesRegex(evaluation.ReproducerEvaluationError, "hash mismatch"):
                evaluation.aarch64_preflight(root)
            with tempfile.TemporaryDirectory() as external:
                outside = Path(external) / "report.json"
                outside.write_text("{}")
                encoded["cases"]["qemu-364"]["iterations"][0] = {"report": str(outside)}
                metadata.write_text(json.dumps(encoded))
                with self.assertRaisesRegex(evaluation.ReproducerEvaluationError, "escapes"):
                    evaluation.aarch64_preflight(root)

    def test_missing_metadata_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(evaluation.ReproducerEvaluationError):
                evaluation.aarch64_preflight(Path(directory))


class ReproducerEvaluationTests(unittest.TestCase):
    @staticmethod
    def _report(
        *,
        status: str,
        source: int = 0x401000,
        destination: int = 0x401005,
        errors: list[dict[str, str]] | None = None,
        state_count: int = 2,
        transform_count: int = 1,
    ) -> dict:
        return {
            "schema": evaluation.QEMU_REPORT_SCHEMA,
            "status": status,
            "trace": {
                "available": True,
                "complete": True,
                "terminal_reached": True,
                "state_count": state_count,
                "transform_count": transform_count,
            },
            "terminal_reason": None,
            "validation": {
                "entries": [
                    {
                        "pc": source,
                        "transition_range": [source, destination],
                        "errors": errors or [],
                    }
                ]
            },
        }

    @staticmethod
    def _confirmed(code: str, subject: str) -> dict[str, str]:
        return {"severity": "confirmed", "code": code, "subject": subject}

    @staticmethod
    def _config() -> evaluation.Config:
        identifiers = (
            "508",
            "1370",
            "1371",
            "1372",
            "1374",
            "1375",
            "1376",
            "1377",
            "1828867",
            "1832422",
            "1861404",
            "2175",
            "2495",
            "sqlite",
        )
        cases = tuple(
            evaluation.CaseConfig(
                identifier=identifier,
                source_case=f"qemu-{identifier}",
                buggy_emulator="qemu-buggy",
                buggy_version="1",
                buggy_program=Path("/buggy"),
                reference_kind="qemu",
                reference_emulator="qemu-reference",
                reference_version="2",
                reference_program=Path("/reference"),
                primary_error=evaluation.ErrorSignature(
                    "register-content-mismatch", "RAX"
                ),
                source_symbol=None,
                entry_prefix_symbol=None,
                required_registers=(),
                condition_code_seed=None,
            )
            for identifier in identifiers
        )
        return evaluation.Config(
            system=evaluation.EXPECTED_SYSTEM,
            focaccia_source_identity={"kind": "git-revision", "value": "a" * 40},
            compiler=Path("/compiler"),
            nm=Path("/nm"),
            validate_qemu=Path("/validate-qemu"),
            cases=cases,
        )

    def test_content_addressed_source_identity_is_explicit_and_versioned(self):
        identity = evaluation._parse_source_identity(
            {
                "focacciaSourceIdentity": {
                    "kind": "nix-store-path",
                    "value": "/nix/store/0123456789abcdefghijklmnopqrstuv-source",
                }
            },
            "focaccia-reproducer-evaluation-config-v2",
        )
        self.assertEqual(
            identity,
            {
                "kind": "nix-store-path",
                "value": "/nix/store/0123456789abcdefghijklmnopqrstuv-source",
            },
        )
        with self.assertRaisesRegex(
            evaluation.ReproducerEvaluationError, "invalid Focaccia store-path"
        ):
            evaluation._parse_source_identity(
                {
                    "focacciaSourceIdentity": {
                        "kind": "nix-store-path",
                        "value": "/tmp/unbound-source",
                    }
                },
                "focaccia-reproducer-evaluation-config-v2",
            )

    def test_messagepack_extraction_decodes_only_indexed_candidate(self):
        arch = x86.ArchX86()
        transforms = tuple(
            SymbolicTransform(index, {}, [], arch, address, address + 1)
            for index, address in enumerate((0x1000, 0x2000, 0x3000))
        )
        trace = MaterializedTrace(
            transforms,
            TraceEnvironment(
                None,
                (),
                (),
                binary_hash=None,
                architecture=arch.key,
            ),
            (0x1000, 0x2000, 0x3000),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oracle.trace"
            serialize_transformations(trace, path, "msgpack")
            contract = evaluation.MismatchContract(0x3000, 0x3001, ())
            with mock.patch.object(
                evaluation,
                "stream_transformation",
                wraps=evaluation.stream_transformation,
            ) as decoder:
                selected = evaluation._load_transform(path, "msgpack", contract)

        self.assertEqual(selected.range, (0x3000, 0x3001))
        self.assertEqual(decoder.call_count, 1)

    def test_messagepack_extraction_drops_whole_trace_completion_binding(self):
        arch = x86.ArchX86()
        transforms = tuple(
            SymbolicTransform(index, {}, [], arch, address, address + 1)
            for index, address in enumerate((0x1000, 0x2000, 0x3000))
        )
        trace = MaterializedTrace(
            transforms,
            TraceEnvironment(None, (), (), binary_hash=None, architecture=arch.key),
            (0x1000, 0x2000, 0x3000),
            scope=TraceScope.WHOLE_PROGRAM,
            completion=TraceCompletion(
                final_pc=0x3001,
                transform_count=3,
                state_count=4,
                outcome=ExecutionOutcome(ExecutionState.EXITED, exit_status=0),
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oracle.trace"
            serialize_transformations(trace, path, "msgpack")
            contract = evaluation.MismatchContract(0x3000, 0x3001, ())
            selected = evaluation._load_transform(path, "msgpack", contract)

        self.assertEqual(selected.range, (0x3000, 0x3001))

    def test_mismatch_contract_retains_every_confirmed_error_on_transition(self):
        report = self._report(
            status="mismatch",
            errors=[
                self._confirmed("register-content-mismatch", "RAX"),
                self._confirmed("register-content-mismatch", "SF"),
                {"severity": "incomplete", "code": "unknown", "subject": "ZF"},
            ],
        )

        contract = evaluation.select_mismatch_contract(
            report,
            evaluation.ErrorSignature("register-content-mismatch", "RAX"),
        )

        self.assertEqual(contract.transition_range, (0x401000, 0x401005))
        self.assertEqual(
            contract.signatures,
            (
                evaluation.ErrorSignature("register-content-mismatch", "RAX"),
                evaluation.ErrorSignature("register-content-mismatch", "SF"),
            ),
        )

    def test_mismatch_contract_rejects_ambiguous_localization(self):
        error = self._confirmed("register-content-mismatch", "CF")
        report = self._report(status="mismatch", errors=[error])
        report["validation"]["entries"].append(
            {
                "pc": 0x402000,
                "transition_range": [0x402000, 0x402005],
                "errors": [error],
            }
        )

        with self.assertRaisesRegex(evaluation.ReproducerEvaluationError, "found 2"):
            evaluation.select_mismatch_contract(
                report,
                evaluation.ErrorSignature("register-content-mismatch", "CF"),
            )

        contract = evaluation.select_mismatch_contract(
            report,
            evaluation.ErrorSignature("register-content-mismatch", "CF"),
            source_address=0x402000,
        )
        self.assertEqual(contract.source, 0x402000)

    def test_buggy_and_reference_reports_require_same_one_transition_contract(self):
        errors = [
            self._confirmed("register-content-mismatch", "RAX"),
            self._confirmed("register-content-mismatch", "SF"),
        ]
        buggy = self._report(status="mismatch", errors=errors)
        contract = evaluation.MismatchContract(
            0x401000,
            0x401005,
            (
                evaluation.ErrorSignature("register-content-mismatch", "RAX"),
                evaluation.ErrorSignature("register-content-mismatch", "SF"),
            ),
        )
        evaluation.require_buggy_reproduction(buggy, contract)
        evaluation.require_reference_acceptance(self._report(status="accepted"))

        buggy["validation"]["entries"][0]["errors"].pop()
        with self.assertRaisesRegex(
            evaluation.ReproducerEvaluationError, "complete localized mismatch"
        ):
            evaluation.require_buggy_reproduction(buggy, contract)

        incomplete_reference = self._report(
            status="accepted", state_count=1, transform_count=0
        )
        with self.assertRaisesRegex(
            evaluation.ReproducerEvaluationError, "exactly one complete transition"
        ):
            evaluation.require_reference_acceptance(incomplete_reference)

    def test_native_oracle_control_requires_successful_trigger_and_exact_prefix(self):
        artifacts = evaluation.SourceArtifacts(
            binary=Path("/guest"),
            oracle=Path("/oracle"),
            states=Path("/states"),
            report=Path("/report"),
            trace_format="msgpack",
            metadata={
                "native": {
                    "kind": "trigger",
                    "expectedNativeStatus": 0,
                }
            },
        )
        prefix = evaluation.EntryPrefix(0x401000, b"\x90")

        evaluation.require_native_oracle_acceptance(artifacts, prefix, ())
        evaluation.require_native_oracle_acceptance(artifacts, None, ("RAX", "RBX"))
        with self.assertRaisesRegex(
            evaluation.ReproducerEvaluationError, "restored transition context"
        ):
            evaluation.require_native_oracle_acceptance(artifacts, None, ())

    def test_run_retains_only_successfully_verified_size_evidence(self):
        config = self._config()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def fake_evaluate_case(
                _config: evaluation.Config,
                case: evaluation.CaseConfig,
                _input: Path,
                output: Path,
            ) -> dict:
                case_root = output / "artifacts" / case.identifier
                case_root.mkdir(parents=True)
                (case_root / "guest-program").write_bytes(b"guest")
                (case_root / "reproducer").write_bytes(b"minimized")
                if case.identifier == "1376":
                    raise evaluation.ReproducerFragmentError("not reproduced")
                return {"status": "passed"}

            with (
                mock.patch.object(
                    evaluation.platform, "machine", return_value="aarch64"
                ),
                mock.patch.object(
                    evaluation, "evaluate_case", side_effect=fake_evaluate_case
                ),
            ):
                status = evaluation.run(config, root, 3)

            self.assertEqual(status, 1)
            output = root / "reproducers" / evaluation.GUEST_SYSTEM
            metadata = json.loads((output / "metadata.json").read_text())
            evidence = json.loads((output / "reproducer-sizes.json").read_text())
            self.assertEqual(metadata["status"], "failed")
            self.assertEqual(metadata["requestedIterations"], 3)
            self.assertEqual(metadata["cases"]["1376"]["status"], "failed")
            self.assertNotIn("1376", evidence["cases"])
            self.assertEqual(len(evidence["cases"]), 13)

    def test_run_rejects_overwriting_prior_evidence(self):
        config = self._config()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "reproducers" / evaluation.GUEST_SYSTEM
            output.mkdir(parents=True)
            with mock.patch.object(
                evaluation.platform, "machine", return_value="aarch64"
            ):
                with self.assertRaisesRegex(
                    evaluation.ReproducerEvaluationError, "archive it"
                ):
                    evaluation.run(config, root, 1)


if __name__ == "__main__":
    unittest.main()
