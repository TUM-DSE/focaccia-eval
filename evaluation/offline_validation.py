#!/usr/bin/env python3

"""Validate emulator text logs with Focaccia's offline trace APIs."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from focaccia import parser
from focaccia.arch import supported_architectures
from focaccia.compare import compare_symbolic
from focaccia.match import match_transitions
from focaccia.qemu.report import validation_report_document


REPORT_SCHEMA = "focaccia-offline-validation-v1"
PARSERS = {
    "box64": parser.parse_box64,
    "arancini": parser.parse_arancini,
}


def make_argument_parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser(
        description="Validate a text emulator trace against a symbolic oracle."
    )
    argument_parser.add_argument("--backend", required=True, choices=PARSERS)
    argument_parser.add_argument("--oracle", required=True, type=Path)
    argument_parser.add_argument(
        "--trace-type",
        choices=("msgpack", "json"),
        default="json",
        help="symbolic oracle persistence format (default: json)",
    )
    argument_parser.add_argument("--log", required=True, type=Path)
    argument_parser.add_argument("--report", required=True, type=Path)
    argument_parser.add_argument(
        "--execution-evidence",
        type=Path,
        help="independent process outcome and artifact binding for whole runs",
    )
    return argument_parser


def _oracle_architecture(symbolic_trace):
    architecture_key = symbolic_trace.env.architecture
    if architecture_key is None:
        raise ValueError("Symbolic oracle has no guest architecture identity.")
    for architecture in supported_architectures.values():
        if architecture.key == architecture_key:
            return architecture
    raise ValueError(f"Unsupported oracle architecture {architecture_key}.")


def _write_report(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _execution_completion(
    evidence_path: Path,
    oracle: Path,
    log: Path,
    symbolic_trace,
    concrete_trace,
    matched,
) -> dict[str, object]:
    evidence = json.loads(evidence_path.read_text())
    required = {
        "schema",
        "runId",
        "binary",
        "binarySha256",
        "oracleSha256",
        "logSha256",
        "processState",
        "exitStatus",
        "expectedExitStatus",
    }
    if not isinstance(evidence, dict) or set(evidence) != required:
        raise ValueError("Execution evidence has invalid fields.")
    if evidence["schema"] != "focaccia-text-process-evidence-v1":
        raise ValueError("Execution evidence has unsupported schema.")
    run_id = evidence["runId"]
    binary = Path(evidence["binary"])
    if not isinstance(run_id, str) or not run_id or not binary.is_file():
        raise ValueError("Execution evidence has invalid run or binary identity.")
    for field, observed in (
        ("binarySha256", _sha256(binary)),
        ("oracleSha256", _sha256(oracle)),
        ("logSha256", _sha256(log)),
    ):
        if evidence[field] != observed:
            raise ValueError(f"Execution evidence {field} does not match its artifact.")
    status = evidence["exitStatus"]
    expected_status = evidence["expectedExitStatus"]
    process_exited = (
        evidence["processState"] == "exited"
        and type(status) is int
        and type(expected_status) is int
        and status == expected_status
    )
    matched_states = (
        getattr(matched.trace, "state_boundaries", ())
        if matched.trace is not None
        else ()
    )
    first_pc = matched_states[0].read_pc() if matched_states else None
    final_pc = matched_states[-1].read_pc() if matched_states else None
    expected_entry = symbolic_trace.addresses[0] if symbolic_trace.addresses else None
    final_transform = (
        matched.trace.transforms[-1]
        if matched.trace and matched.trace.transforms
        else None
    )
    expected_final = final_transform.range[1] if final_transform is not None else None
    entry_bound = first_pc is not None and first_pc == expected_entry
    consumed_transform_count = getattr(matched, "consumed_transform_count", None)
    ordinary_consumed = matched.trace is not None and (
        consumed_transform_count == len(symbolic_trace.addresses)
        if consumed_transform_count is not None
        else len(matched.trace.transforms) == len(symbolic_trace.addresses)
    )
    final_boundary_bound = (
        ordinary_consumed and final_pc is not None and final_pc == expected_final
    )
    return {
        "runId": run_id,
        "binary": str(binary),
        "binarySha256": evidence["binarySha256"],
        "oracleSha256": evidence["oracleSha256"],
        "logSha256": evidence["logSha256"],
        "processOutcome": {
            "state": evidence["processState"],
            "exitStatus": status,
            "expectedExitStatus": expected_status,
            "match": process_exited,
        },
        "entryBoundary": {
            "expected": expected_entry,
            "observed": first_pc,
            "match": entry_bound,
        },
        "finalOrdinaryBoundary": {
            "expected": expected_final,
            "observed": final_pc,
            "allTransformsConsumed": ordinary_consumed,
            "match": final_boundary_bound,
        },
        "executionComplete": process_exited and entry_bound and final_boundary_bound,
        "semanticComplete": False,
    }


def validate(
    backend: str,
    oracle: Path,
    log: Path,
    trace_type: str = "json",
    execution_evidence: Path | None = None,
) -> dict[str, object]:
    mode = "rb" if trace_type == "msgpack" else "r"
    with oracle.open(mode) as oracle_file:
        if trace_type == "msgpack":
            symbolic_trace = parser.stream_transformation(oracle_file)
        elif trace_type == "json":
            symbolic_trace = parser.parse_transformations(oracle_file)
        else:
            raise ValueError(f"Unsupported symbolic trace type {trace_type!r}.")
        architecture = _oracle_architecture(symbolic_trace)
        with log.open() as log_file:
            concrete_trace = PARSERS[backend](log_file, architecture)
        raw_box64_state_count = None
        if backend == "box64":
            raw_box64_state_count = len(
                [
                    line
                    for line in log.read_text().splitlines()
                    if line.startswith("ES=")
                ]
            )

        matched = match_transitions(concrete_trace, symbolic_trace)
        report = compare_symbolic(
            matched.trace,
            diagnostics=matched.diagnostics,
        )
        validation = validation_report_document(report, None)
        status = validation["status"]
        validation_document = validation["validation"]
        if (
            status == "accepted"
            and isinstance(validation_document, dict)
            and validation_document.get("entry_count") == 0
        ):
            status = "incomplete"
        completion = (
            _execution_completion(
                execution_evidence, oracle, log, symbolic_trace, concrete_trace, matched
            )
            if execution_evidence is not None
            else None
        )
        document: dict[str, object] = {
            "schema": REPORT_SCHEMA,
            "backend": backend,
            "status": status,
            "partialState": True,
            "guestArchitecture": {
                "isa": architecture.key.isa,
                "endianness": architecture.key.endianness,
            },
            "validation": validation_document,
            "unsupportedData": [
                "memory-state",
                "system-actions",
                "unlogged-register-bits",
            ],
        }
        if backend == "box64":
            assert raw_box64_state_count is not None
            document["boundaryPolicy"] = {
                "kind": "observed-coarse-cutpoints-v1",
                "rawStateCount": raw_box64_state_count,
                "retainedStateCount": len(concrete_trace),
                "discardedFusedPushRecords": (
                    raw_box64_state_count - len(concrete_trace)
                ),
                "instructionBoundaryComplete": False,
            }
        if completion is not None:
            document["completion"] = completion
        return document


def main(arguments: list[str] | None = None) -> int:
    args = make_argument_parser().parse_args(arguments)
    try:
        document = validate(
            args.backend,
            args.oracle,
            args.log,
            args.trace_type,
            args.execution_evidence,
        )
        _write_report(args.report, document)
        return 0
    except (OSError, ValueError) as error:
        print(f"offline-validation: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
