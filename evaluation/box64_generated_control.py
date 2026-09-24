#!/usr/bin/env python3
"""Generate and validate the paper's register-form Box64 CMPXCHG witness."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

from focaccia import parser
from focaccia.arch.x86 import ArchX86
from focaccia.reproducer import (
    Reproducer,
    extract_executable_fragment,
    single_transition_reproducer_trace,
)

SOURCE = 0x401054
DESTINATION = 0x401057
EXPECTED_BYTES = bytes.fromhex("0fb1d1")
GPRS = (
    "RAX",
    "RBX",
    "RCX",
    "RDX",
    "RSI",
    "RDI",
    "RBP",
    "RSP",
    "R8",
    "R9",
    "R10",
    "R11",
    "R12",
    "R13",
    "R14",
    "R15",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(
    command: list[str], *, env: dict[str, str] | None = None, output: Path | None = None
) -> None:
    result = subprocess.run(
        command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False
    )
    if output is not None:
        output.write_bytes(result.stdout)
    if result.returncode != 0:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}")


def main() -> None:
    ap = argparse.ArgumentParser()
    for name in (
        "oracle",
        "guest",
        "source-log",
        "compiler",
        "nm",
        "buggy",
        "reference",
        "validator",
        "output",
    ):
        ap.add_argument(f"--{name}", required=True, type=Path)
    args = ap.parse_args()
    out = args.output
    out.mkdir(parents=True, exist_ok=False)

    with args.oracle.open("rb") as stream:
        oracle = parser.stream_transformation(stream)
        transform = next(t for t in oracle if t.range == (SOURCE, DESTINATION))
    with args.source_log.open() as stream:
        states = parser.parse_box64(stream, ArchX86())
    snapshot = next(state for state in states if state.read_pc() == SOURCE)
    required = tuple(register for register in GPRS if snapshot.test_register(register))
    if required != GPRS:
        raise RuntimeError(f"full observed GPR context unavailable: {required}")
    observed = {register: snapshot.read_register(register) for register in required}
    if (
        observed["RAX"] != 0x1234567812345678
        or observed["RCX"] != 0x12345678
        or observed["RDX"] != 0x77777777
    ):
        raise RuntimeError("unexpected source CMPXCHG operands")

    fragment = extract_executable_fragment(args.guest, SOURCE, DESTINATION)
    if fragment.data != EXPECTED_BYTES:
        raise RuntimeError(f"unexpected transition bytes: {fragment.data.hex()}")
    reproducer = Reproducer(
        str(args.guest),
        [],
        snapshot,
        transform,
        fragment=fragment,
        required_registers=required,
    )
    assembly = out / "reproducer.S"
    binary = out / "reproducer"
    generated_oracle = out / "oracle.json"
    assembly.write_text(reproducer.asm())
    run(
        [
            str(args.compiler),
            "-nostdlib",
            "-static",
            "-no-pie",
            "-Wl,--build-id=none",
            f"-Wl,-Ttext={reproducer.link_address:#x}",
            "-Wl,-e,_start",
            "-Wl,-z,max-page-size=0x1000",
            "-o",
            str(binary),
            str(assembly),
        ],
        output=out / "compile.log",
    )
    symbols = subprocess.check_output([str(args.nm), "-n", str(binary)], text=True)
    address = next(
        int(line.split()[0], 16)
        for line in symbols.splitlines()
        if line.endswith(" focaccia_reproducer_transition")
    )
    generated = extract_executable_fragment(binary, SOURCE, DESTINATION)
    if address != SOURCE or generated.data != EXPECTED_BYTES:
        raise RuntimeError("generated transition address or bytes differ")
    parser.serialize_transformations(
        single_transition_reproducer_trace(transform, binary), generated_oracle, "json"
    )

    reports = {}
    for label, emulator in (("buggy", args.buggy), ("reference", args.reference)):
        log = out / f"{label}.log"
        report = out / f"{label}.json"
        env = os.environ.copy()
        env.update(
            {
                "BOX64_TRACE": f"0x{SOURCE:x}-0x{DESTINATION + 1:x}",
                "BOX64_TRACE_FILE": "stderr",
                "BOX64_DYNAREC_TRACE": "1",
                "BOX64_DYNAREC_DF": "0",
            }
        )
        run([str(emulator), str(binary)], env=env, output=log)
        run(
            [
                str(args.validator),
                "--backend",
                "box64",
                "--oracle",
                str(generated_oracle),
                "--trace-type",
                "json",
                "--log",
                str(log),
                "--report",
                str(report),
            ]
        )
        reports[label] = json.loads(report.read_text())

    buggy = reports["buggy"]
    confirmed = [
        error
        for entry in buggy["validation"]["entries"]
        for error in entry["errors"]
        if error.get("severity") == "confirmed"
    ]
    if (
        buggy["status"] != "mismatch"
        or len(confirmed) != 1
        or confirmed[0].get("subject") != "RAX"
        or "Expected 0x1234567812345678, actual 0x12345678."
        not in confirmed[0]["message"]
    ):
        raise RuntimeError("buggy package did not reproduce the exact RAX mismatch")
    reference = reports["reference"]
    reference_errors = [
        error
        for entry in reference["validation"]["entries"]
        for error in entry["errors"]
        if error.get("severity") in {"confirmed", "possible"}
        or "register RAX" in error.get("message", "")
    ]
    if reference["status"] not in {"accepted", "incomplete"} or reference_errors:
        raise RuntimeError("reference package did not preserve RAX")

    manifest = {
        "schema": "focaccia-box64-generated-control-v1",
        "sourceRange": [SOURCE, DESTINATION],
        "instructionBytes": EXPECTED_BYTES.hex(),
        "sourceRegisters": {name: f"0x{value:x}" for name, value in observed.items()},
        "requiredRegisters": list(required),
        "artifacts": {
            name: {
                "path": path.name,
                "sha256": digest(path),
                "size": path.stat().st_size,
            }
            for name, path in {
                "sourceGuest": args.guest,
                "sourceOracle": args.oracle,
                "generatedAssembly": assembly,
                "generatedBinary": binary,
                "generatedOracle": generated_oracle,
                "buggyLog": out / "buggy.log",
                "buggyReport": out / "buggy.json",
                "referenceLog": out / "reference.log",
                "referenceReport": out / "reference.json",
            }.items()
        },
        "buggyStatus": buggy["status"],
        "referenceStatus": reference["status"],
        "confirmedCount": len(confirmed),
        "partialState": True,
        "semanticComplete": False,
    }
    (out / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )


if __name__ == "__main__":
    main()
