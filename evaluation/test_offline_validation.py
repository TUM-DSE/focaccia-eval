from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from miasm.expression.expression import ExprId, ExprInt

import offline_validation
from focaccia import parser
from focaccia.arch import x86
from focaccia.symbolic import SymbolicTransform
from focaccia.trace import MaterializedTrace, TraceEnvironment


class OfflineValidationTests(unittest.TestCase):
    def test_box64_log_is_validated_with_oracle_guest_architecture(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            oracle = root / "oracle.trace"
            log = root / "box64.log"
            architecture = x86.ArchX86()
            transform = SymbolicTransform(
                1,
                {
                    ExprId("RAX", 64): ExprInt(2, 64),
                    ExprId("RIP", 64): ExprInt(0x1001, 64),
                },
                [],
                architecture,
                0x1000,
                0x1001,
            )
            trace = MaterializedTrace(
                [transform],
                TraceEnvironment(
                    None,
                    (),
                    (),
                    binary_hash=None,
                    architecture=architecture.key,
                ),
                [0x1000],
            )
            parser.serialize_transformations(trace, oracle)

            log.write_text(
                "Box64 trace\n"
                "ES=0 RIP=1000 RAX=1 FLAGS=-------\n"
                "ES=0 RIP=1001 RAX=2 FLAGS=-------\n"
            )
            accepted = offline_validation.validate("box64", oracle, log)
            self.assertEqual(accepted["status"], "accepted")
            self.assertEqual(
                accepted["guestArchitecture"],
                {"isa": "x86_64", "endianness": "little"},
            )
            self.assertEqual(
                accepted["boundaryPolicy"],
                {
                    "kind": "observed-coarse-cutpoints-v1",
                    "rawStateCount": 2,
                    "retainedStateCount": 2,
                    "discardedFusedPushRecords": 0,
                    "instructionBoundaryComplete": False,
                },
            )

            log.write_text(
                "Box64 trace\n"
                "ES=0 RIP=1000 RAX=1 FLAGS=-------\n"
                "ES=0 RIP=1001 RAX=3 FLAGS=-------\n"
            )
            mismatch = offline_validation.validate("box64", oracle, log)
            self.assertEqual(mismatch["status"], "mismatch")

            msgpack_oracle = root / "oracle.msgpack"
            parser.serialize_transformations(trace, msgpack_oracle, "msgpack")
            log.write_text(
                "Box64 trace\n"
                "ES=0 RIP=1000 RAX=1 FLAGS=-------\n"
                "ES=0 RIP=1001 RAX=2 FLAGS=-------\n"
            )
            accepted_msgpack = offline_validation.validate(
                "box64", msgpack_oracle, log, "msgpack"
            )
            self.assertEqual(accepted_msgpack["status"], "accepted")

            binary = root / "program"
            binary.write_bytes(b"guest")
            evidence = root / "execution.json"

            def digest(path: Path) -> str:
                return hashlib.sha256(path.read_bytes()).hexdigest()

            evidence.write_text(
                json.dumps(
                    {
                        "schema": "focaccia-text-process-evidence-v1",
                        "runId": "run-1",
                        "binary": str(binary),
                        "binarySha256": digest(binary),
                        "oracleSha256": digest(msgpack_oracle),
                        "logSha256": digest(log),
                        "processState": "exited",
                        "exitStatus": 0,
                        "expectedExitStatus": 0,
                    }
                )
            )
            completed = offline_validation.validate(
                "box64", msgpack_oracle, log, "msgpack", evidence
            )
            self.assertTrue(completed["completion"]["executionComplete"])
            self.assertFalse(completed["completion"]["semanticComplete"])
            self.assertTrue(completed["completion"]["entryBoundary"]["match"])
            self.assertTrue(completed["completion"]["finalOrdinaryBoundary"]["match"])
            self.assertEqual(
                completed["unsupportedData"],
                ["memory-state", "system-actions", "unlogged-register-bits"],
            )

            document = json.loads(evidence.read_text())
            document["logSha256"] = "0" * 64
            evidence.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, "logSha256"):
                offline_validation.validate(
                    "box64", msgpack_oracle, log, "msgpack", evidence
                )


if __name__ == "__main__":
    unittest.main()
