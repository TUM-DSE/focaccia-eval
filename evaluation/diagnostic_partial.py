#!/usr/bin/env python3
"""Audit retained diagnostic whole-run evidence and plot an explicit partial figure."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import signal
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt

from evaluation import (
    EvaluationError,
    _expected_guest_signal,
    _expected_trigger_mismatch,
    _require_trigger_mismatch_contract,
    load_config,
    read_symbols,
    require_whole_program_experiment_execution,
)

SCHEMA = "focaccia-diagnostic-whole-run-index-v1"
COMPONENTS = (
    ("executionSeconds", "QEMU execution"),
    ("tracingSeconds", "Concrete tracing"),
    ("validationSeconds", "Validation"),
    ("serializationSeconds", "Serialization"),
    ("unattributedSeconds", "Unattributed"),
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require_artifact_hash(path: Path, expected: object, label: str) -> None:
    if not isinstance(expected, str) or sha256(path) != expected:
        raise EvaluationError(f"{label} artifact hash mismatch.")


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise EvaluationError(f"{path} is not a JSON object.")
    return value


def require_known_fatal_signal(
    report: dict[str, Any], signal_name: str, fault_pc: int
) -> dict[str, Any]:
    """Require localized crash diagnostics plus independent process death."""
    if not _expected_guest_signal(report, signal_name, fault_pc):
        raise EvaluationError(
            f"Expected localized {signal_name} guest failure at {fault_pc:#x}."
        )
    reason = report.get("terminal_reason")
    delivery = reason.get("delivery") if isinstance(reason, dict) else None
    try:
        signal_number = int(getattr(signal, signal_name))
    except (AttributeError, TypeError, ValueError) as error:
        raise EvaluationError(f"Unsupported expected signal {signal_name}.") from error
    if (
        not isinstance(delivery, dict)
        or delivery.get("attempted") is not True
        or delivery.get("state") != "exited"
        or delivery.get("known_terminated") is not True
        or delivery.get("termination_signal") != signal_number
        or delivery.get("exit_status") is not None
    ):
        raise EvaluationError(
            f"Localized {signal_name} stop lacks matching fatal process outcome."
        )
    return {
        "actualEmulatedProgramEnd": True,
        "expectedCrashLocalized": True,
        "semanticCompletion": False,
        "nativeFinalActionsReached": False,
    }


def baseline_rows(path: Path) -> dict[str, float]:
    result: dict[str, float] = {}
    with path.open(newline="") as stream:
        for row in csv.DictReader(stream):
            if (
                row.get("mode") == "native"
                and row.get("component") == "execution"
                and row.get("status") == "passed"
            ):
                value = float(row["seconds"])
                if value <= 0 or row["benchmark"] in result:
                    raise EvaluationError(
                        "Native baseline rows are invalid or duplicated."
                    )
                result[row["benchmark"]] = value
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--nm", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    root = args.run.resolve()
    native_dir = root / "native/x86_64-linux"
    emulated_dir = root / "emulated/qemu/aarch64-linux"
    native_metadata_path = native_dir / "metadata.json"
    emulator_metadata_path = emulated_dir / "metadata.json"
    native_metadata = load(native_metadata_path)
    emulator_metadata = load(emulator_metadata_path)
    baselines = baseline_rows(native_dir / "results.csv")
    config = load_config(args.config)
    admitted: list[dict[str, Any]] = []
    excluded: list[dict[str, str]] = []

    for identifier, case in sorted(
        config.emulator_cases.items(), key=lambda item: item[1].trigger
    ):
        trigger = case.trigger
        if trigger not in baselines or trigger not in native_metadata.get("cases", {}):
            continue
        contract = (
            None
            if case.expected_terminal_signal is not None
            else _require_trigger_mismatch_contract(case)
        )
        native_case = native_metadata["cases"][trigger]
        native_item = native_case["iterations"][0]
        binary = native_dir / native_item["binary"]
        oracle = native_dir / native_item["oracle"]
        require_artifact_hash(
            binary, native_item.get("binarySha256"), f"{trigger} binary"
        )
        require_artifact_hash(
            oracle, native_item.get("oracleSha256"), f"{trigger} oracle"
        )
        symbols = read_symbols(args.nm, binary)
        if case.expected_terminal_signal is not None:
            if case.expected_fault_symbol is None:
                raise EvaluationError(f"Fatal case {trigger} lacks a fault symbol.")
            source = symbols[case.expected_fault_symbol]
            stop = source
            code = "unexpected-guest-signal"
        else:
            if contract is None:
                raise AssertionError("Non-signal case lacks a mismatch contract.")
            symbol, offset, length, code = contract
            source = offset if symbol is None else symbols[symbol] + offset
            stop = source + length
        variant = config.emulators[case.emulator]
        directory = emulated_dir / variant.backend / variant.identifier / trigger / "0"
        report_path = directory / "validation.json"
        profile_path = directory / "profile.json"
        report = load(report_path)
        profile = load(profile_path)
        if case.expected_terminal_signal is not None:
            evidence = require_known_fatal_signal(
                report, case.expected_terminal_signal, source
            )
        else:
            localized = _expected_trigger_mismatch(
                report, source, stop, code, case.expected_mismatch_subject
            )
            evidence = require_whole_program_experiment_execution(
                report, expected_bug_localized=localized
            )
        timings = profile.get("timings")
        if (
            profile.get("schema") != "focaccia-qemu-validation-profile-v1"
            or profile.get("status") != "passed"
            or not isinstance(timings, dict)
        ):
            raise EvaluationError(f"Invalid QEMU profile for {trigger}.")
        values = {field: float(timings[field]) for field, _ in COMPONENTS}
        total_seconds = float(timings["totalSeconds"])
        if any(value < 0 for value in (*values.values(), total_seconds)):
            raise EvaluationError(f"Negative QEMU timing for {trigger}.")
        if abs(sum(values.values()) - total_seconds) > max(1e-9, total_seconds * 1e-9):
            raise EvaluationError(
                f"QEMU timing components do not sum to total for {trigger}."
            )
        validation = report["validation"]
        admitted.append(
            {
                "case": trigger,
                "emulator": variant.identifier,
                "originalEvaluatorStatus": emulator_metadata["cases"][identifier][
                    "status"
                ],
                "diagnosticEligibility": evidence,
                "terminalObservation": (
                    report.get("terminal_reason")
                    if case.expected_terminal_signal is not None
                    else None
                ),
                "expectedMismatch": {
                    "range": [source, stop],
                    "code": code,
                    "subject": (
                        case.expected_terminal_signal
                        if case.expected_terminal_signal is not None
                        else case.expected_mismatch_subject
                    ),
                },
                "nativeBaselineSeconds": baselines[trigger],
                "timings": {**values, "totalSeconds": total_seconds},
                "normalized": {
                    **{
                        field: value / baselines[trigger]
                        for field, value in values.items()
                    },
                    "totalSeconds": total_seconds / baselines[trigger],
                },
                "coverage": {
                    "stateCount": report["trace"]["state_count"],
                    "transformCount": report["trace"]["transform_count"],
                    "confirmed": validation["severity_counts"].get("confirmed", 0),
                    "unconfirmed": sum(
                        count
                        for name, count in validation["severity_counts"].items()
                        if name != "confirmed"
                    ),
                    "diagnostics": sum(validation["diagnostic_counts"].values()),
                    "allTransitionsValidated": False,
                },
                "artifacts": {
                    "binary": str(binary.relative_to(root)),
                    "binarySha256": sha256(binary),
                    "oracle": str(oracle.relative_to(root)),
                    "oracleSha256": sha256(oracle),
                    "profile": str(profile_path.relative_to(root)),
                    "profileSha256": sha256(profile_path),
                    "report": str(report_path.relative_to(root)),
                    "reportSha256": sha256(report_path),
                },
            }
        )

    missing = ["2419", "1861404"]
    document = {
        "schema": SCHEMA,
        "classification": "partial-diagnostic-whole-run-overhead",
        "validatedCompletionClaim": False,
        "originalNativeMetadata": {
            "path": str(native_metadata_path.relative_to(root)),
            "sha256": sha256(native_metadata_path),
        },
        "originalEmulatorMetadata": {
            "path": str(emulator_metadata_path.relative_to(root)),
            "sha256": sha256(emulator_metadata_path),
            "statusPreserved": True,
        },
        "admittedCaseCount": len(admitted),
        "paperCaseCount": 11,
        "missingCases": missing,
        "excludedCases": excluded,
        "cases": admitted,
    }
    args.output.mkdir(parents=True, exist_ok=False)
    index_path = args.output / "diagnostic-evidence-index.json"
    index_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")

    labels = [item["case"] for item in admitted]
    figure, axis = plt.subplots(figsize=(7.0, 3.2))
    bottoms = [0.0] * len(admitted)
    for field, label in COMPONENTS:
        values = [item["normalized"][field] for item in admitted]
        axis.bar(labels, values, bottom=bottoms, label=label)
        bottoms = [a + b for a, b in zip(bottoms, values, strict=True)]
    axis.set_yscale("log")
    axis.set_ylabel("Time / native execution baseline (log scale)")
    axis.set_xlabel("Emulator bug case")
    axis.set_title(f"PARTIAL diagnostic whole-run overhead ({len(admitted)}/11 cases)")
    axis.legend(fontsize=7, ncols=2)
    axis.text(
        0.01,
        -0.28,
        "Missing: 2419, 1861404. Gaps/findings retained; not validated completion.",
        transform=axis.transAxes,
        fontsize=8,
    )
    figure.tight_layout()
    plot_path = args.output / "partial-diagnostic-trigger-overhead.pdf"
    figure.savefig(plot_path, metadata={"CreationDate": None})
    plt.close(figure)
    (args.output / "artifact-sha256.json").write_text(
        json.dumps(
            {
                "diagnostic-evidence-index.json": sha256(index_path),
                "partial-diagnostic-trigger-overhead.pdf": sha256(plot_path),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
