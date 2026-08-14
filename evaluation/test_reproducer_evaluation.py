from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from focaccia.arch import x86
from focaccia.persistence import serialize_transformations
from focaccia.symbolic import SymbolicTransform
from focaccia.trace import MaterializedTrace, TraceEnvironment

import reproducer_evaluation as evaluation


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
        identifiers = ("1370", "1371", "1372", "1374", "1376", "1377", "2175", "sqlite")
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
                condition_code_seed=None,
            )
            for identifier in identifiers
        )
        return evaluation.Config(
            system=evaluation.EXPECTED_SYSTEM,
            focaccia_revision="a" * 40,
            compiler=Path("/compiler"),
            nm=Path("/nm"),
            validate_qemu=Path("/validate-qemu"),
            cases=cases,
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

        evaluation.require_native_oracle_acceptance(artifacts, prefix)
        with self.assertRaisesRegex(
            evaluation.ReproducerEvaluationError, "exact entry-to-transition"
        ):
            evaluation.require_native_oracle_acceptance(artifacts, None)

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
                    raise evaluation.ReproducerEvaluationError("not reproduced")
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
            self.assertEqual(len(evidence["cases"]), 7)

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
