#!/usr/bin/env python3

"""Create a content-bound manifest for an existing native RR oracle bundle."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from focaccia.deterministic import DeterministicLog
from focaccia.persistence import parse_transformations, stream_transformation
from focaccia.qemu.integration import (
    create_replay_run_manifest,
    write_replay_run_manifest,
)


def _parse_input(value: str) -> tuple[str, Path]:
    name, separator, path = value.partition("=")
    if not separator or not name or not path:
        raise argparse.ArgumentTypeError("inputs must use NAME=PATH")
    return name, Path(path)


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bind a binary, oracle, inputs, arguments, and RR trace."
    )
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--oracle", type=Path, required=True)
    parser.add_argument("--trace-type", choices=("msgpack", "json"), required=True)
    parser.add_argument("--deterministic-log", type=Path, required=True)
    parser.add_argument("--argv-json", required=True)
    parser.add_argument("--input", action="append", default=[], type=_parse_input)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(arguments: list[str] | None = None) -> None:
    parser = make_parser()
    args = parser.parse_args(arguments)
    try:
        argv = json.loads(args.argv_json)
    except json.JSONDecodeError as error:
        parser.error(f"--argv-json is invalid JSON: {error}")
    if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
        parser.error("--argv-json must contain a string list")
    inputs = dict(args.input)
    if len(inputs) != len(args.input):
        parser.error("--input names must be unique")

    mode = "rb" if args.trace_type == "msgpack" else "r"
    with args.oracle.open(mode) as oracle_stream:
        if args.trace_type == "msgpack":
            trace = stream_transformation(oracle_stream)
        else:
            trace = parse_transformations(oracle_stream)
        manifest = create_replay_run_manifest(
            binary_path=args.binary,
            input_paths=inputs,
            argv=argv,
            oracle_path=args.oracle,
            trace_environment=trace.env,
            deterministic_log=DeterministicLog(args.deterministic_log),
        )
    write_replay_run_manifest(args.output, manifest)


if __name__ == "__main__":
    main()
