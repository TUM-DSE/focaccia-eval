"""Complete the plot package's synthetic cross-ISA role-pair fixture.

This fixture is never executed or admitted as performance evidence. It exercises
only the same hash/provenance gates the runtime full-Curl plotter applies.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, document: object) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(document, indent=2, sort_keys=True).encode() + b"\n"
    path.write_bytes(content)
    return hashlib.sha256(content).hexdigest()


def rr_tree_sha256(directory: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(
        directory.rglob("*"), key=lambda item: item.relative_to(directory).as_posix()
    ):
        relative = path.relative_to(directory).as_posix().encode("utf-8")
        if path.is_symlink():
            kind, payload = b"L", str(path.readlink()).encode("utf-8")
        elif path.is_file():
            kind, payload = b"F", path.read_bytes()
        elif path.is_dir():
            kind, payload = b"D", b""
        else:
            raise ValueError(f"unsupported RR fixture entry: {path}")
        digest.update(kind)
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def symbols(binary: Path) -> dict[str, int]:
    result = subprocess.run(
        ("nm", "-n", str(binary)),
        check=True,
        capture_output=True,
        text=True,
    )
    found: dict[str, int] = {}
    for line in result.stdout.splitlines():
        match = re.fullmatch(r"([0-9a-fA-F]+)\s+[Tt]\s+(\S+)", line.strip())
        if match:
            found[match.group(2)] = int(match.group(1), 16)
    return found


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: prepare_cross_isa_full_curl.py RUN_ROOT X86_GUEST_ELF")
    root, generated_guest = map(Path, sys.argv[1:])
    native = root / "native/x86_64-linux"
    qemu = root / "emulated/qemu/aarch64-linux"
    guest = native / "binaries/application-curl-full-injected"
    oracle = native / "oracles/curl-full-0-speculative.trace"
    workload = native / "work/curl-full-0/curl-5k.bin"
    rr = native / "rr/curl-full-0"
    for path in (guest, oracle, workload, rr / "events"):
        path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(generated_guest, guest)
    oracle.write_bytes(b"deterministic fixture oracle; not runtime evidence\n")
    workload.write_bytes(("0123456789abcdef" * 4).encode() * 80)
    (rr / "events").write_bytes(b"rr-trace-v85 fixture events\n")
    if workload.stat().st_size != 5120:
        raise ValueError("full-Curl plotting workload fixture must remain 5 KiB")

    binary_hash = sha256(guest)
    oracle_hash = sha256(oracle)
    workload_hash = sha256(workload)
    guest_symbols = symbols(guest)
    source = guest_symbols["focaccia_injection_curl_2175"]
    stop = guest_symbols["focaccia_trace_stop_curl"]
    argv = [
        "--fail",
        "--silent",
        "--show-error",
        "--output",
        "download.bin",
        "http://127.0.0.1:12345/curl-5k.bin",
    ]
    native_metadata_path = native / "metadata.json"
    native_metadata = json.loads(native_metadata_path.read_text())
    native_iteration = native_metadata["cases"]["curl-full"]["iterations"][0]
    captures = native_iteration["fullCaptures"]
    for name, cross_validated in (
        ("native-full-cross-validated", True),
        ("native-full-speculative", False),
    ):
        capture = captures[name]
        profile_path = native / capture["profile"]
        profile = json.loads(profile_path.read_text())
        timings = profile["timings"]
        capture.update(
            {
                "crossValidated": cross_validated,
                "oracle": "oracles/curl-full-0-speculative.trace",
                "oracleSha256": oracle_hash,
                "profileSha256": sha256(profile_path),
                "traceSeconds": timings["traceSeconds"],
                "serializationSeconds": timings["serializationSeconds"],
                "captureProcessSeconds": (
                    timings["traceSeconds"] + timings["serializationSeconds"] + 5
                ),
            }
        )
    native_iteration.update(
        {
            "kind": "application",
            "injectedBinary": "binaries/application-curl-full-injected",
            "injectedBinarySha256": binary_hash,
            "oracle": "oracles/curl-full-0-speculative.trace",
            "oracleSha256": oracle_hash,
            "workloadKind": "curl",
            "workloadSha256": workload_hash,
            "workloadStorePath": str(workload.resolve()),
            "traceFormat": "msgpack",
            "traceMode": "full",
            "argv": argv,
            "rrTrace": "rr/curl-full-0",
            "startAddress": 0x401000,
            "stopAddress": stop,
            "profile": captures["native-full-speculative"]["profile"],
            "profileSha256": captures["native-full-speculative"]["profileSha256"],
            "traceSeconds": captures["native-full-speculative"]["traceSeconds"],
            "serializationSeconds": captures["native-full-speculative"][
                "serializationSeconds"
            ],
            "captureProcessSeconds": captures["native-full-speculative"][
                "captureProcessSeconds"
            ],
            "fullCaptures": captures,
        }
    )
    native_metadata_path.write_text(json.dumps(native_metadata, indent=2) + "\n")

    qemu_guest = qemu / "binaries/application-curl-full-injected"
    qemu_oracle = qemu / "oracles/curl-full-0-speculative.trace"
    qemu_workload = qemu / "work/curl-full-0/curl-5k.bin"
    for path in (qemu_guest, qemu_oracle, qemu_workload):
        path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(guest, qemu_guest)
    shutil.copy2(oracle, qemu_oracle)
    shutil.copy2(workload, qemu_workload)

    report_path = qemu / "curl-full/0/validation.json"
    manifest_path = qemu / "curl-full/0/run-manifest.json"
    rr_hash = rr_tree_sha256(rr)
    report = {
        "schema": "focaccia-qemu-validation-v1",
        "status": "mismatch",
        "trace": {
            "available": True,
            "complete": True,
            "terminal_reached": False,
            "state_count": 1001,
            "transform_count": 1000,
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
        "replay": {"active": True, "record_count": 3, "by_outcome": {"handled": 3}},
        "validation": {
            "diagnostics": [],
            "diagnostic_counts": {},
            "severity_counts": {"confirmed": 1},
            "entries": [
                {
                    "pc": source,
                    "transition_range": [source, stop],
                    "errors": [
                        {
                            "severity": "confirmed",
                            "code": "register-content-mismatch",
                            "subject": "CF",
                            "message": "Content of register CF is false. Expected 0x1, actual 0x0.",
                        }
                    ],
                }
            ],
        },
    }
    report_hash = write_json(report_path, report)
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
            "schema_id": "0xcaa0b1486c12c629",
            "trace_uuid": "00112233445566778899aabbccddeeff",
            "directory_sha256": rr_hash,
        },
    }
    manifest_hash = write_json(manifest_path, manifest)
    qemu_metadata_path = qemu / "metadata.json"
    qemu_metadata = json.loads(qemu_metadata_path.read_text())
    qemu_item = qemu_metadata["cases"]["qemu-app-curl-full"]["iterations"][0]
    qemu_item.update(
        {
            "kind": "application",
            "backend": "qemu-gdb",
            "traceMode": "full",
            "binary": "binaries/application-curl-full-injected",
            "binarySha256": binary_hash,
            "oracle": "oracles/curl-full-0-speculative.trace",
            "oracleSha256": oracle_hash,
            "workload": "work/curl-full-0/curl-5k.bin",
            "workloadSha256": workload_hash,
            "argv": argv,
            "expectedValidation": "mismatch",
            "expectedMismatchLocalized": True,
            "expectedMismatchRange": [source, stop],
            "expectedMismatchSubject": "CF",
            "expectedMismatchSourceSymbol": "focaccia_injection_curl_2175",
            "report": "curl-full/0/validation.json",
            "reportSha256": report_hash,
            "runManifest": "curl-full/0/run-manifest.json",
            "runManifestSha256": manifest_hash,
            "rrTrace": str(rr.resolve()),
            "native": native_iteration,
        }
    )
    qemu_metadata_path.write_text(json.dumps(qemu_metadata, indent=2) + "\n")
    prepare_selective_applications(root, generated_guest)


def prepare_selective_applications(root: Path, generated_guest: Path) -> None:
    native = root / "native/x86_64-linux"
    qemu = root / "emulated/qemu/aarch64-linux"
    native_metadata_path = native / "metadata.json"
    qemu_metadata_path = qemu / "metadata.json"
    native_metadata = json.loads(native_metadata_path.read_text())
    qemu_metadata = json.loads(qemu_metadata_path.read_text())
    all_symbols = symbols(generated_guest)
    contracts = {
        "curl": (
            "focaccia_injection_curl_2175",
            "focaccia_trace_stop_curl",
            "CF",
            "qemu-8-2-0",
        ),
        "lua": (
            "focaccia_injection_lua_2495",
            "focaccia_trace_stop_lua",
            "R8",
            "qemu-9-0-0",
        ),
        "sqlite": (
            "focaccia_injection_sqlite_508",
            "focaccia_trace_stop_sqlite",
            "RAX",
            "qemu-6-1-0",
        ),
    }
    argv_values = {
        "curl": [
            "--fail",
            "--silent",
            "--show-error",
            "--output",
            "download.bin",
            "http://127.0.0.1:12345/curl-5k.bin",
        ],
        "lua": ["workload.lua"],
        "sqlite": ["evaluation.db"],
    }
    workloads = {
        "curl": root / "native/x86_64-linux/work/curl-full-0/curl-5k.bin",
        "lua": root / "workloads/workload.lua",
        "sqlite": root / "workloads/input.sql",
    }
    workloads["lua"].parent.mkdir(parents=True, exist_ok=True)
    workloads["lua"].write_bytes(b"print(_VERSION)\\n")
    workloads["sqlite"].write_bytes(b"select 1;\\n")

    native_rows_path = native / "results.csv"
    with native_rows_path.open(newline="") as stream:
        native_rows = list(csv.DictReader(stream))
    native_rows = [
        row
        for row in native_rows
        if not (
            row.get("benchmark") in contracts
            and row.get("mode") in {"native", "native-selective"}
        )
    ]
    qemu_rows_path = qemu / "results.csv"
    with qemu_rows_path.open(newline="") as stream:
        qemu_rows = list(csv.DictReader(stream))
    qemu_rows = [
        row
        for row in qemu_rows
        if not (
            row.get("benchmark") in contracts
            and row.get("mode") in {item[3] for item in contracts.values()}
        )
    ]

    for index, (application, contract) in enumerate(contracts.items()):
        source_symbol, stop_symbol, subject, emulator = contract
        source_address, stop_address = (
            all_symbols[source_symbol],
            all_symbols[stop_symbol],
        )
        guest = native / f"binaries/application-{application}-injected"
        guest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(generated_guest, guest)
        binary_hash = sha256(guest)
        workload = workloads[application]
        workload_hash = sha256(workload)
        oracle = native / f"oracles/{application}-0-selective.trace"
        oracle.write_bytes(f"synthetic {application} selective oracle\\n".encode())
        oracle_hash = sha256(oracle)
        rr = native / f"rr/{application}-0"
        rr.mkdir(parents=True, exist_ok=True)
        (rr / "events").write_bytes(f"rr-trace-v85 {application} fixture\\n".encode())
        argv = argv_values[application]
        trace = root / f"native/x86_64-linux/profiles/{application}-0-selective.json"
        native_timing = {
            "concreteSeconds": float(4 + index),
            "symbolicSeconds": float(8 + index),
            "validationSeconds": float(1 + index),
            "traceSeconds": float(13 + 3 * index),
            "serializationSeconds": 1.0,
        }
        native_profile_hash = write_json(
            trace, {"status": "passed", "timings": native_timing}
        )
        native_item = {
            "kind": "application",
            "injectedBinary": f"binaries/application-{application}-injected",
            "injectedBinarySha256": binary_hash,
            "oracle": f"oracles/{application}-0-selective.trace",
            "oracleSha256": oracle_hash,
            "workloadKind": application,
            "workloadSha256": workload_hash,
            "workloadStorePath": str(workload.resolve()),
            "traceFormat": "msgpack",
            "traceMode": "selective",
            "argv": argv,
            "expectedNativeStatus": 1 if application == "lua" else 0,
            "rrTrace": f"rr/{application}-0",
            "startAddress": 0x401000,
            "stopAddress": stop_address,
            "profile": f"profiles/{application}-0-selective.json",
            "profileSha256": native_profile_hash,
        }
        native_metadata["cases"][application] = {
            "kind": "application",
            "status": "passed",
            "iterations": [native_item],
        }
        for component, seconds in (
            ("execution", float(1 + index)),
            ("concrete", native_timing["concreteSeconds"]),
            ("symbolic", native_timing["symbolicSeconds"]),
            ("validation", native_timing["validationSeconds"]),
            ("total", native_timing["traceSeconds"]),
        ):
            native_rows.append(
                {
                    "benchmark": application,
                    "mode": "native"
                    if component == "execution"
                    else "native-selective",
                    "component": component,
                    "seconds": str(seconds),
                    "iteration": "0",
                    "status": "passed",
                    "detail": "",
                }
            )

        qemu_guest = qemu / f"binaries/application-{application}-injected"
        qemu_oracle = qemu / f"oracles/{application}-0-selective.trace"
        qemu_workload = (
            qemu
            / f"work/{application}-0/{Path(argv[-1] if application == 'curl' else argv[0]).name}"
        )
        for path in (qemu_guest, qemu_oracle, qemu_workload):
            path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(guest, qemu_guest)
        shutil.copy2(oracle, qemu_oracle)
        shutil.copy2(workload, qemu_workload)
        report_path = qemu / f"{application}/0/validation.json"
        manifest_path = qemu / f"{application}/0/run-manifest.json"
        report = {
            "schema": "focaccia-qemu-validation-v1",
            "status": "mismatch",
            "trace": {
                "available": True,
                "complete": True,
                "terminal_reached": True,
                "state_count": 101,
                "transform_count": 100,
            },
            "replay": {"active": True, "record_count": 3, "by_outcome": {"handled": 3}},
            "validation": {
                "diagnostics": [],
                "diagnostic_counts": {},
                "severity_counts": {"confirmed": 1},
                "entries": [
                    {
                        "pc": source_address,
                        "transition_range": [source_address, stop_address],
                        "errors": [
                            {
                                "severity": "confirmed",
                                "code": "register-content-mismatch",
                                "subject": subject,
                            }
                        ],
                    }
                ],
            },
        }
        report_hash = write_json(report_path, report)
        rr_hash = rr_tree_sha256(rr)
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
                "schema_id": "0xcaa0b1486c12c629",
                "trace_uuid": f"00112233445566778899aabbccddeeff{index:02x}"[-32:],
                "directory_sha256": rr_hash,
            },
        }
        manifest_hash = write_json(manifest_path, manifest)
        qemu_profile = {
            "schema": "focaccia-qemu-validation-profile-v1",
            "status": "passed",
            "timings": {
                "executionSeconds": float(10 + index),
                "tracingSeconds": float(20 + index),
                "validationSeconds": 2.0,
                "serializationSeconds": 1.0,
                "totalSeconds": float(33 + index),
            },
        }
        qemu_profile_path = qemu / f"profiles/{application}-selective.json"
        qemu_profile_hash = write_json(qemu_profile_path, qemu_profile)
        qemu_item = {
            "kind": "application",
            "backend": "qemu-gdb",
            "emulator": emulator,
            "emulatorVersion": emulator.removeprefix("qemu-").replace("-", "."),
            "traceMode": "selective",
            "binary": qemu_guest.relative_to(qemu).as_posix(),
            "binarySha256": binary_hash,
            "oracle": qemu_oracle.relative_to(qemu).as_posix(),
            "oracleSha256": oracle_hash,
            "workload": qemu_workload.relative_to(qemu).as_posix(),
            "workloadSha256": workload_hash,
            "argv": argv,
            "expectedValidation": "mismatch",
            "expectedMismatchLocalized": True,
            "expectedMismatchRange": [source_address, stop_address],
            "expectedMismatchSubject": subject,
            "report": report_path.relative_to(qemu).as_posix(),
            "reportSha256": report_hash,
            "runManifest": manifest_path.relative_to(qemu).as_posix(),
            "runManifestSha256": manifest_hash,
            "profile": qemu_profile_path.relative_to(qemu).as_posix(),
            "profileSha256": qemu_profile_hash,
            "rrTrace": str(rr.resolve()),
            "native": native_item,
        }
        qemu_metadata["cases"][f"qemu-app-{application}"] = {
            "kind": "application",
            "benchmark": application,
            "emulator": emulator,
            "status": "passed",
            "iterations": [qemu_item],
        }
        for component, seconds in qemu_profile["timings"].items():
            qemu_rows.append(
                {
                    "benchmark": application,
                    "mode": emulator,
                    "component": component.removesuffix("Seconds").lower()
                    if component != "tracingSeconds"
                    else "tracing",
                    "seconds": str(seconds),
                    "iteration": "0",
                    "status": "passed",
                    "detail": "",
                }
            )

    write_json(native_metadata_path, native_metadata)
    write_json(qemu_metadata_path, qemu_metadata)
    for path, rows in (
        (native / "results.csv", native_rows),
        (qemu / "results.csv", qemu_rows),
    ):
        with path.open("w", newline="") as stream:
            writer = csv.DictWriter(
                stream,
                fieldnames=[
                    "benchmark",
                    "mode",
                    "component",
                    "seconds",
                    "iteration",
                    "status",
                    "detail",
                ],
            )
            writer.writeheader()
            writer.writerows(rows)


if __name__ == "__main__":
    main()
