#!/usr/bin/env python3

"""Validate emulator text logs with Focaccia's offline trace APIs."""

from __future__ import annotations

import argparse
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


def validate(
    backend: str,
    oracle: Path,
    log: Path,
    trace_type: str = "json",
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
        return {
            "schema": REPORT_SCHEMA,
            "backend": backend,
            "status": status,
            "partialState": True,
            "guestArchitecture": {
                "isa": architecture.key.isa,
                "endianness": architecture.key.endianness,
            },
            "validation": validation_document,
        }


def main(arguments: list[str] | None = None) -> int:
    args = make_argument_parser().parse_args(arguments)
    try:
        document = validate(args.backend, args.oracle, args.log, args.trace_type)
        _write_report(args.report, document)
        return 0
    except (OSError, ValueError) as error:
        print(f"offline-validation: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
