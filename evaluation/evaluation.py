#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Sequence, TextIO
from urllib.parse import urlsplit


RESULT_FIELDS = (
    "benchmark",
    "mode",
    "component",
    "seconds",
    "iteration",
    "status",
    "detail",
)
PROCESS_TIMEOUT_SECONDS = 30 * 60
CAPTURE_TIMEOUT_SECONDS = 120 * 60
SERVER_STARTUP_TIMEOUT_SECONDS = 15
SIGNAL_READINESS_TIMEOUT_SECONDS = 15
SYMBOL_PATTERN = re.compile(
    r"^\s*([0-9a-fA-F]+)\s+\S\s+(\S+)\s*$",
    re.MULTILINE,
)
CONFIG_SCHEMA = "focaccia-evaluation-config-v5"
EVALUATION_ROLES = {"native", "qemu", "box64"}
NATIVE_SCHEMA = "focaccia-native-evaluation-v2"
EMULATED_SCHEMA = "focaccia-emulated-evaluation-v1"
OFFLINE_REPORT_SCHEMA = "focaccia-offline-validation-v1"
WORKLOAD_KINDS = {"sqlite", "curl", "lua"}
APPLICATION_TRACE_MODES = {"selective", "full"}
EMULATOR_BACKENDS = {"qemu-gdb", "qemu-plugin", "box64-log", "arancini-log"}
VALIDATION_EXPECTATIONS = {"accepted", "mismatch"}
QEMU_PROFILE_SCHEMA = "focaccia-qemu-validation-profile-v1"
QEMU_PROFILE_FIELDS = {
    "execution": "executionSeconds",
    "tracing": "tracingSeconds",
    "validation": "validationSeconds",
    "serialization": "serializationSeconds",
    "total": "totalSeconds",
}


class EvaluationError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class Trigger:
    identifier: str
    binary: Path
    expected_status: int
    witness_sha256: str | None = None
    native_transport: str = "local"


@dataclass(frozen=True, slots=True)
class Application:
    identifier: str
    reference_binary: Path
    injected_binary: Path
    workload: Path
    workload_kind: str
    expected_status: int
    start_symbol: str
    stop_symbol: str
    trace_mode: str = "selective"


@dataclass(frozen=True, slots=True)
class EmulatorVariant:
    identifier: str
    backend: str
    output: Path
    version: str


@dataclass(frozen=True, slots=True)
class EmulatorCase:
    identifier: str
    kind: str
    trigger: str
    guest_system: str
    emulator: str
    program: str
    expected_validation: str
    expected_witness_sha256: str | None = None
    workload: Path | None = None
    workload_kind: str | None = None
    trace_mode: str | None = None
    expected_mismatch_source_symbol: str | None = None
    expected_mismatch_source_address: int | None = None
    expected_mismatch_subject: str | None = None
    expected_mismatch_source_offset: int | None = None
    expected_mismatch_length: int | None = None
    expected_mismatch_code: str | None = None
    validation_cutpoint: str | None = None
    expected_terminal_signal: str | None = None
    expected_fault_symbol: str | None = None
    qemu_cpu_model: str | None = None


@dataclass(frozen=True, slots=True)
class EvaluationConfig:
    role: str
    system: str
    capture_program: Path
    nm_program: Path
    rr_program: Path
    http_server_program: Path
    offline_validator_program: Path
    validate_qemu_program: Path
    replay_manifest_program: Path
    replay_preflight_program: Path
    triggers: dict[str, Trigger]
    applications: dict[str, Application]
    emulators: dict[str, EmulatorVariant]
    emulator_cases: dict[str, EmulatorCase]
    trigger_trace_mode: str = "whole-program"
    gdbserver_program: Path | None = None


@dataclass(frozen=True, slots=True)
class ProcessResult:
    returncode: int
    elapsed: float
    output: str


@dataclass(frozen=True, slots=True)
class PreparedApplication:
    directory: Path
    argv: tuple[str, ...]
    stdin_path: Path | None
    server_root: Path | None
    server_port: int | None
    deliver_sigint: bool
    pipe_stdin: bool


@dataclass(frozen=True, slots=True)
class NativeApplicationArtifacts:
    binary: Path
    oracle: Path
    rr_trace: Path
    workload: Path
    argv: tuple[str, ...]
    trace_format: str
    metadata: dict[str, Any]


class ManagedProcess:
    def __init__(
        self,
        command: Sequence[str],
        log_path: Path,
        *,
        cwd: Path | None = None,
        stdin_path: Path | None = None,
        pipe_stdin: bool = False,
        env: dict[str, str] | None = None,
    ) -> None:
        self.command = tuple(command)
        self.env = env
        self.log_path = log_path
        self.cwd = cwd
        self.stdin_path = stdin_path
        self.pipe_stdin = pipe_stdin
        if stdin_path is not None and pipe_stdin:
            raise ValueError("A managed process cannot use both a file and pipe stdin.")
        self._log: TextIO | None = None
        self._stdin: TextIO | None = None
        self.process: subprocess.Popen[str] | None = None

    def start(self) -> subprocess.Popen[str]:
        self._log = self.log_path.open("w", encoding="utf-8")
        if self.stdin_path is not None:
            self._stdin = self.stdin_path.open(encoding="utf-8")
        try:
            self.process = subprocess.Popen(
                self.command,
                cwd=self.cwd,
                env=self.env,
                stdin=(subprocess.PIPE if self.pipe_stdin else self._stdin),
                stdout=self._log,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
            if self.pipe_stdin:
                self._stdin = self.process.stdin
        except OSError as error:
            self.close()
            raise EvaluationError(
                f"Unable to launch {list(self.command)!r}: {error}"
            ) from error
        return self.process

    def stop(self) -> None:
        process = self.process
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=3)
        self.close()

    def close(self) -> None:
        if self._stdin is not None:
            self._stdin.close()
            self._stdin = None
        if self._log is not None:
            self._log.close()
            self._log = None

    def __enter__(self) -> subprocess.Popen[str]:
        return self.start()

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.stop()


def normalize_machine(machine: str) -> str:
    normalized = machine.lower().replace("-", "_")
    if normalized in {"amd64", "x64", "x86_64"}:
        return "x86_64"
    if normalized in {"aarch64", "arm64"}:
        return "aarch64"
    raise EvaluationError(f"Unsupported native evaluation machine: {machine!r}.")


def expected_machine(system: str) -> str:
    if system.startswith("x86_64-"):
        return "x86_64"
    if system.startswith("aarch64-"):
        return "aarch64"
    raise EvaluationError(f"Unsupported Nix evaluation system: {system!r}.")


def _required_string(document: dict[str, Any], name: str, context: str) -> str:
    value = document.get(name)
    if not isinstance(value, str) or not value:
        raise EvaluationError(f"{context} has invalid {name}.")
    return value


def _required_status(document: dict[str, Any], context: str) -> int:
    value = document.get("expectedStatus")
    if not isinstance(value, int) or isinstance(value, bool):
        raise EvaluationError(f"{context} has invalid expectedStatus.")
    return value


def load_config(path: Path) -> EvaluationConfig:
    try:
        document = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise EvaluationError(
            f"Unable to read evaluation configuration {path}: {error}"
        ) from error

    if not isinstance(document, dict) or document.get("schema") != CONFIG_SCHEMA:
        raise EvaluationError("Unsupported evaluation configuration schema.")
    role = _required_string(document, "role", "Evaluation configuration")
    if role not in EVALUATION_ROLES:
        raise EvaluationError(f"Unsupported evaluation role {role!r}.")
    system = _required_string(document, "system", "Evaluation configuration")
    capture_program = _required_string(
        document, "captureProgram", "Evaluation configuration"
    )
    gdbserver_program = document.get("gdbserverProgram")
    if gdbserver_program is not None and (
        not isinstance(gdbserver_program, str) or not gdbserver_program
    ):
        raise EvaluationError("Invalid gdbserverProgram.")
    nm_program = _required_string(document, "nmProgram", "Evaluation configuration")
    rr_program = _required_string(document, "rrProgram", "Evaluation configuration")
    http_server_program = _required_string(
        document, "httpServerProgram", "Evaluation configuration"
    )
    offline_validator_program = _required_string(
        document, "offlineValidatorProgram", "Evaluation configuration"
    )
    validate_qemu_program = _required_string(
        document, "validateQemuProgram", "Evaluation configuration"
    )
    replay_manifest_program = _required_string(
        document, "replayManifestProgram", "Evaluation configuration"
    )
    replay_preflight_program = _required_string(
        document, "replayPreflightProgram", "Evaluation configuration"
    )
    trigger_trace_mode = document.get("triggerTraceMode", "whole-program")
    if trigger_trace_mode not in {"whole-program", "legacy-witness"}:
        raise EvaluationError("Unsupported triggerTraceMode.")
    encoded_triggers = document.get("triggers")
    encoded_applications = document.get("applications")
    encoded_emulators = document.get("emulators")
    encoded_emulator_cases = document.get("emulatorCases")
    if not isinstance(encoded_triggers, dict):
        raise EvaluationError("Evaluation configuration has no trigger map.")
    if not isinstance(encoded_applications, dict):
        raise EvaluationError("Evaluation configuration has no application map.")
    if not isinstance(encoded_emulators, dict):
        raise EvaluationError("Evaluation configuration has no emulator map.")
    if not isinstance(encoded_emulator_cases, dict):
        raise EvaluationError("Evaluation configuration has no emulator case map.")

    triggers: dict[str, Trigger] = {}
    for identifier, encoded in encoded_triggers.items():
        if not isinstance(identifier, str) or not isinstance(encoded, dict):
            raise EvaluationError("Evaluation trigger entries must be named objects.")
        context = f"Evaluation trigger {identifier}"
        witness_sha256 = encoded.get("witnessSha256")
        if witness_sha256 is not None and (
            not isinstance(witness_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", witness_sha256) is None
        ):
            raise EvaluationError(f"{context} has an invalid witness hash.")
        native_transport = encoded.get("nativeTransport", "local")
        if native_transport not in ("local", "gdbserver"):
            raise EvaluationError(f"{context} has unsupported nativeTransport.")
        if native_transport == "gdbserver" and gdbserver_program is None:
            raise EvaluationError(f"{context} requires gdbserverProgram.")
        triggers[identifier] = Trigger(
            identifier,
            Path(_required_string(encoded, "binary", context)),
            _required_status(encoded, context),
            witness_sha256,
            native_transport,
        )

    applications: dict[str, Application] = {}
    for identifier, encoded in encoded_applications.items():
        if not isinstance(identifier, str) or not isinstance(encoded, dict):
            raise EvaluationError(
                "Evaluation application entries must be named objects."
            )
        context = f"Evaluation application {identifier}"
        workload_kind = _required_string(encoded, "workloadKind", context)
        if workload_kind not in WORKLOAD_KINDS:
            raise EvaluationError(
                f"{context} has unsupported workloadKind {workload_kind!r}."
            )
        trace_mode = encoded.get("traceMode", "selective")
        if not isinstance(trace_mode, str) or (
            trace_mode not in APPLICATION_TRACE_MODES
            or (trace_mode == "full" and workload_kind != "curl")
        ):
            raise EvaluationError(
                f"{context} has unsupported traceMode {trace_mode!r}."
            )
        applications[identifier] = Application(
            identifier=identifier,
            reference_binary=Path(
                _required_string(encoded, "referenceBinary", context)
            ),
            injected_binary=Path(_required_string(encoded, "injectedBinary", context)),
            workload=Path(_required_string(encoded, "workload", context)),
            workload_kind=workload_kind,
            expected_status=_required_status(encoded, context),
            start_symbol=_required_string(encoded, "startSymbol", context),
            stop_symbol=_required_string(encoded, "stopSymbol", context),
            trace_mode=trace_mode,
        )

    emulators: dict[str, EmulatorVariant] = {}
    for identifier, encoded in encoded_emulators.items():
        if not isinstance(identifier, str) or not isinstance(encoded, dict):
            raise EvaluationError("Evaluation emulator entries must be named objects.")
        context = f"Evaluation emulator {identifier}"
        backend = _required_string(encoded, "backend", context)
        if backend not in EMULATOR_BACKENDS:
            raise EvaluationError(f"{context} has unsupported backend {backend!r}.")
        emulators[identifier] = EmulatorVariant(
            identifier=identifier,
            backend=backend,
            output=Path(_required_string(encoded, "output", context)),
            version=_required_string(encoded, "version", context),
        )

    emulator_cases: dict[str, EmulatorCase] = {}
    for identifier, encoded in encoded_emulator_cases.items():
        if not isinstance(identifier, str) or not isinstance(encoded, dict):
            raise EvaluationError("Evaluation emulator cases must be named objects.")
        context = f"Evaluation emulator case {identifier}"
        emulator = _required_string(encoded, "emulator", context)
        if emulator not in emulators:
            raise EvaluationError(
                f"{context} references unknown emulator {emulator!r}."
            )
        expectation = _required_string(encoded, "expectedValidation", context)
        if expectation not in VALIDATION_EXPECTATIONS:
            raise EvaluationError(
                f"{context} has unsupported expectedValidation {expectation!r}."
            )
        kind = _required_string(encoded, "kind", context)
        if kind not in {"trigger", "application"}:
            raise EvaluationError(f"{context} has unsupported kind {kind!r}.")
        workload = None
        workload_kind = None
        trace_mode = None
        expected_witness_sha256 = encoded.get("expectedWitnessSha256")
        if expected_witness_sha256 is not None and (
            kind != "trigger"
            or not isinstance(expected_witness_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected_witness_sha256) is None
        ):
            raise EvaluationError(f"{context} has an invalid expected witness hash.")
        expected_mismatch_source_symbol = None
        expected_mismatch_subject = None
        validation_cutpoint = encoded.get("validationCutpoint")
        expected_terminal_signal = encoded.get("expectedTerminalSignal")
        expected_fault_symbol = encoded.get("expectedFaultSymbol")
        if (expected_terminal_signal is None) != (expected_fault_symbol is None):
            raise EvaluationError(
                f"{context} must declare expectedTerminalSignal and "
                "expectedFaultSymbol together."
            )
        if expected_terminal_signal is not None and (
            not isinstance(expected_terminal_signal, str)
            or not expected_terminal_signal.startswith("SIG")
            or not isinstance(expected_fault_symbol, str)
            or not expected_fault_symbol
        ):
            raise EvaluationError(f"{context} has an invalid terminal signal contract.")
        if expected_terminal_signal is not None and kind != "trigger":
            raise EvaluationError(
                f"{context} cannot declare a trigger terminal signal contract."
            )
        if validation_cutpoint is not None and validation_cutpoint != "stop":
            raise EvaluationError(
                f"{context} has unsupported validationCutpoint {validation_cutpoint!r}."
            )
        if validation_cutpoint is not None and kind != "trigger":
            raise EvaluationError(
                f"{context} cannot declare a trigger validation cutpoint."
            )
        if kind == "application":
            workload = Path(_required_string(encoded, "workload", context))
            workload_kind = _required_string(encoded, "workloadKind", context)
            if workload_kind not in WORKLOAD_KINDS:
                raise EvaluationError(
                    f"{context} has unsupported workloadKind {workload_kind!r}."
                )
            trace_mode = encoded.get("traceMode", "selective")
            if not isinstance(trace_mode, str) or (
                trace_mode not in APPLICATION_TRACE_MODES
                or (trace_mode == "full" and workload_kind != "curl")
            ):
                raise EvaluationError(
                    f"{context} has unsupported traceMode {trace_mode!r}."
                )
        ordinary_gdb_mismatch = (
            expectation == "mismatch"
            and kind == "trigger"
            and emulators[emulator].backend == "qemu-gdb"
            and expected_terminal_signal is None
        )
        if expectation == "mismatch" and (
            kind == "application"
            or emulators[emulator].backend == "qemu-plugin"
            or ordinary_gdb_mismatch
        ):
            if (
                not ordinary_gdb_mismatch
                or "expectedMismatchSourceAddress" not in encoded
            ):
                expected_mismatch_source_symbol = _required_string(
                    encoded, "expectedMismatchSourceSymbol", context
                )
            if not ordinary_gdb_mismatch or encoded.get("expectedMismatchCode") != (
                "memory-content-mismatch"
            ):
                expected_mismatch_subject = _required_string(
                    encoded, "expectedMismatchSubject", context
                )
            else:
                expected_mismatch_subject = encoded.get("expectedMismatchSubject")
        qemu_cpu_model = encoded.get("qemuCpuModel")
        if qemu_cpu_model is not None and (
            kind != "trigger"
            or emulators[emulator].backend != "qemu-gdb"
            or not isinstance(qemu_cpu_model, str)
            or not qemu_cpu_model
        ):
            raise EvaluationError(f"{context} has an invalid qemuCpuModel.")
        case = EmulatorCase(
            identifier=identifier,
            kind=kind,
            trigger=_required_string(encoded, "trigger", context),
            guest_system=_required_string(encoded, "guestSystem", context),
            emulator=emulator,
            program=_required_string(encoded, "program", context),
            expected_validation=expectation,
            expected_witness_sha256=expected_witness_sha256,
            workload=workload,
            workload_kind=workload_kind,
            trace_mode=trace_mode,
            expected_mismatch_source_symbol=expected_mismatch_source_symbol,
            expected_mismatch_source_address=encoded.get(
                "expectedMismatchSourceAddress"
            ),
            expected_mismatch_subject=expected_mismatch_subject,
            expected_mismatch_source_offset=encoded.get("expectedMismatchSourceOffset"),
            expected_mismatch_length=encoded.get("expectedMismatchLength"),
            expected_mismatch_code=encoded.get("expectedMismatchCode"),
            validation_cutpoint=validation_cutpoint,
            expected_terminal_signal=expected_terminal_signal,
            expected_fault_symbol=expected_fault_symbol,
            qemu_cpu_model=qemu_cpu_model,
        )
        if ordinary_gdb_mismatch:
            _require_trigger_mismatch_contract(case)
        emulator_cases[identifier] = case

    return EvaluationConfig(
        role=role,
        system=system,
        capture_program=Path(capture_program),
        gdbserver_program=Path(gdbserver_program) if gdbserver_program else None,
        nm_program=Path(nm_program),
        rr_program=Path(rr_program),
        http_server_program=Path(http_server_program),
        offline_validator_program=Path(offline_validator_program),
        validate_qemu_program=Path(validate_qemu_program),
        replay_manifest_program=Path(replay_manifest_program),
        replay_preflight_program=Path(replay_preflight_program),
        triggers=triggers,
        applications=applications,
        emulators=emulators,
        emulator_cases=emulator_cases,
        trigger_trace_mode=trigger_trace_mode,
    )


def run_process(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout_seconds: int = PROCESS_TIMEOUT_SECONDS,
) -> ProcessResult:
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        output = error.stdout or ""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        return ProcessResult(
            returncode=124,
            elapsed=time.perf_counter() - started,
            output=output + f"\nTimed out after {timeout_seconds} seconds.\n",
        )
    except OSError as error:
        return ProcessResult(
            returncode=127,
            elapsed=time.perf_counter() - started,
            output=f"Unable to execute {list(command)!r}: {error}\n",
        )
    return ProcessResult(
        returncode=completed.returncode,
        elapsed=time.perf_counter() - started,
        output=completed.stdout,
    )


def read_symbols(nm_program: Path, binary: Path) -> dict[str, int]:
    result = run_process((str(nm_program), "-n", str(binary)))
    if result.returncode != 0:
        raise EvaluationError(
            f"nm failed for {binary} with status {result.returncode}: "
            f"{result.output.strip()}"
        )
    return {
        name: int(address, 16)
        for address, name in SYMBOL_PATTERN.findall(result.output)
    }


def resolve_named_bounds(
    nm_program: Path,
    binary: Path,
    start_symbol: str,
    stop_symbol: str,
) -> tuple[int, int]:
    symbols = read_symbols(nm_program, binary)
    missing = [name for name in (start_symbol, stop_symbol) if name not in symbols]
    if missing:
        raise EvaluationError(
            f"{binary} is missing required symbols: {', '.join(missing)}."
        )
    start = symbols[start_symbol]
    stop = symbols[stop_symbol]
    if stop <= start:
        raise EvaluationError(
            f"{binary} has invalid selective bounds {start:#x}:{stop:#x}."
        )
    return start, stop


def resolve_trace_bounds(config: EvaluationConfig, trigger: Trigger) -> tuple[int, int]:
    return resolve_named_bounds(
        config.nm_program,
        trigger.binary,
        "focaccia_trace_start",
        "focaccia_trace_stop",
    )


def load_qemu_component_timings(path: Path) -> dict[str, float]:
    try:
        document = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise EvaluationError(f"Unable to read QEMU profile {path}: {error}") from error
    if (
        not isinstance(document, dict)
        or document.get("schema") != QEMU_PROFILE_SCHEMA
        or document.get("status") != "passed"
        or not isinstance(document.get("timings"), dict)
    ):
        raise EvaluationError("QEMU validation profile is incomplete or unsupported.")
    encoded = document["timings"]
    timings: dict[str, float] = {}
    for component, field in QEMU_PROFILE_FIELDS.items():
        value = encoded.get(field)
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
            raise EvaluationError(
                f"QEMU validation profile has invalid {component} timing {value!r}."
            )
        timings[component] = float(value)
    return timings


def _qemu_profile_rows(
    benchmark: str,
    mode: str,
    iteration: int,
    profile: Path,
) -> tuple[list[dict[str, str | int]], dict[str, float]]:
    timings = load_qemu_component_timings(profile)
    rows = [
        result_row(
            benchmark,
            mode,
            component,
            timings[component],
            iteration,
            "passed",
        )
        for component in QEMU_PROFILE_FIELDS
    ]
    return rows, timings


def load_component_timings(path: Path) -> dict[str, float]:
    document = _load_json_object(path, "capture profile")
    if document.get("status") != "passed":
        raise EvaluationError("Capture profile does not report successful completion.")
    encoded = document.get("timings")
    expected = {
        "concrete": "concreteSeconds",
        "symbolic": "symbolicSeconds",
        "validation": "validationSeconds",
        "trace": "traceSeconds",
        "serialization": "serializationSeconds",
    }
    if not isinstance(encoded, dict) or set(encoded) != set(expected.values()):
        raise EvaluationError("Capture profile has invalid timing fields.")

    timings: dict[str, float] = {}
    for component, field in expected.items():
        value = encoded[field]
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(value)
            or value < 0
        ):
            raise EvaluationError(
                f"Capture profile has invalid {component} timing {value!r}."
            )
        timings[component] = float(value)
    return timings


def result_row(
    benchmark: str,
    mode: str,
    component: str,
    seconds: float | None,
    iteration: int,
    status: str,
    detail: str = "",
) -> dict[str, str | int]:
    return {
        "benchmark": benchmark,
        "mode": mode,
        "component": component,
        "seconds": "" if seconds is None else format(seconds, ".17g"),
        "iteration": iteration,
        "status": status,
        "detail": detail,
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def evaluate_trigger(
    config: EvaluationConfig,
    trigger: Trigger,
    iteration: int,
    system_directory: Path,
    trace_format: str,
) -> tuple[list[dict[str, str | int]], dict[str, Any], bool]:
    binaries_directory = system_directory / "binaries"
    logs_directory = system_directory / "logs"
    oracles_directory = system_directory / "oracles"
    profiles_directory = system_directory / "profiles"
    binaries_directory.mkdir(parents=True, exist_ok=True)
    logs_directory.mkdir(parents=True, exist_ok=True)
    oracles_directory.mkdir(parents=True, exist_ok=True)
    profiles_directory.mkdir(parents=True, exist_ok=True)

    binary = binaries_directory / f"reproducer-{trigger.identifier}"
    if not binary.exists():
        shutil.copy2(trigger.binary, binary)
    captured_trigger = Trigger(
        trigger.identifier, binary, trigger.expected_status, trigger.witness_sha256
    )
    rows: list[dict[str, str | int]] = []
    metadata: dict[str, Any] = {
        "kind": "trigger",
        "binary": str(binary.relative_to(system_directory)),
        "binarySha256": _sha256(binary),
        "binaryStorePath": str(trigger.binary),
        "expectedNativeStatus": trigger.expected_status,
        "nativeTransport": trigger.native_transport,
        "traceFormat": trace_format,
    }
    if trigger.witness_sha256 is not None:
        metadata["witnessSha256"] = trigger.witness_sha256

    metadata["traceMode"] = config.trigger_trace_mode
    capture_scope = ("--whole-program",)
    if config.trigger_trace_mode == "legacy-witness":
        try:
            start, stop = resolve_trace_bounds(config, captured_trigger)
        except EvaluationError as error:
            rows.append(
                result_row(
                    trigger.identifier,
                    "native-cross-validated",
                    "setup",
                    None,
                    iteration,
                    "failed",
                    str(error),
                )
            )
            return rows, metadata, False
        metadata.update({"startAddress": start, "stopAddress": stop})
        capture_scope = ("--start-address", hex(start), "--stop-address", hex(stop))

    baseline = run_process((str(binary),))
    (logs_directory / f"{trigger.identifier}-{iteration}-execution.log").write_text(
        baseline.output
    )
    baseline_ok = baseline.returncode == trigger.expected_status
    rows.append(
        result_row(
            trigger.identifier,
            "native",
            "execution",
            baseline.elapsed if baseline_ok else None,
            iteration,
            "passed" if baseline_ok else "failed",
            ""
            if baseline_ok
            else f"native status {baseline.returncode}, expected {trigger.expected_status}",
        )
    )
    if not baseline_ok:
        return rows, metadata, False

    oracle = oracles_directory / f"{trigger.identifier}-{iteration}.trace"
    profile = profiles_directory / f"{trigger.identifier}-{iteration}.json"
    capture_command = (
        str(config.capture_program),
        "--cross-validate",
        *capture_scope,
        "--output",
        str(oracle),
        "--profile-report",
        str(profile),
        "--out-type",
        trace_format,
        str(binary),
    )
    try:
        if trigger.native_transport == "gdbserver":
            if config.gdbserver_program is None:
                raise EvaluationError("gdbserver transport requires gdbserverProgram.")
            transport_env = {
                **os.environ,
                "SHELL": "/bin/sh",
                "ZDOTDIR": "/nonexistent",
            }
            metadata["gdbserverProgram"] = str(config.gdbserver_program)
            metadata["gdbserverSha256"] = _sha256(config.gdbserver_program)
            metadata["nativeTransportEnvironment"] = {
                "SHELL": transport_env["SHELL"],
                "ZDOTDIR": transport_env["ZDOTDIR"],
            }
            server_log = (
                logs_directory / f"{trigger.identifier}-{iteration}-gdbserver.log"
            )
            with ManagedProcess(
                (str(config.gdbserver_program), "--once", "127.0.0.1:0", str(binary)),
                server_log,
                env=transport_env,
            ) as server:
                port = _wait_for_gdbserver(server, server_log)
                endpoint = f"127.0.0.1:{port}"
                remote_capture_command = (
                    *capture_command[:-1],
                    "-r",
                    endpoint,
                    str(binary),
                )
                metadata["nativeTransportEndpoint"] = endpoint
                metadata["captureCommand"] = list(remote_capture_command)
                capture = run_process(
                    remote_capture_command,
                    env=transport_env,
                    timeout_seconds=CAPTURE_TIMEOUT_SECONDS,
                )
        elif trigger.native_transport == "local":
            capture = run_process(
                capture_command, timeout_seconds=CAPTURE_TIMEOUT_SECONDS
            )
        else:
            raise EvaluationError(
                f"Unsupported native transport {trigger.native_transport!r}."
            )
    except (EvaluationError, OSError) as error:
        rows.append(
            result_row(
                trigger.identifier,
                "native-cross-validated",
                "total",
                None,
                iteration,
                "failed",
                str(error),
            )
        )
        return rows, metadata, False
    (logs_directory / f"{trigger.identifier}-{iteration}-capture.log").write_text(
        capture.output
    )
    if capture.returncode != 0:
        rows.append(
            result_row(
                trigger.identifier,
                "native-cross-validated",
                "total",
                None,
                iteration,
                "failed",
                f"capture status {capture.returncode}",
            )
        )
        return rows, metadata, False
    if not oracle.is_file() or oracle.stat().st_size == 0:
        rows.append(
            result_row(
                trigger.identifier,
                "native-cross-validated",
                "total",
                None,
                iteration,
                "failed",
                "capture produced no oracle trace",
            )
        )
        return rows, metadata, False

    try:
        timings = load_component_timings(profile)
    except EvaluationError as error:
        rows.append(
            result_row(
                trigger.identifier,
                "native-cross-validated",
                "total",
                None,
                iteration,
                "failed",
                str(error),
            )
        )
        return rows, metadata, False

    for component in ("concrete", "symbolic", "validation"):
        rows.append(
            result_row(
                trigger.identifier,
                "native-cross-validated",
                component,
                timings[component],
                iteration,
                "passed",
            )
        )
    rows.append(
        result_row(
            trigger.identifier,
            "native-cross-validated",
            "total",
            timings["trace"],
            iteration,
            "passed",
        )
    )
    metadata["oracle"] = str(oracle.relative_to(system_directory))
    metadata["oracleSha256"] = _sha256(oracle)
    metadata["profile"] = str(profile.relative_to(system_directory))
    metadata["profileSha256"] = _sha256(profile)
    metadata["traceSeconds"] = timings["trace"]
    metadata["serializationSeconds"] = timings["serialization"]
    metadata["captureProcessSeconds"] = capture.elapsed
    return rows, metadata, True


def _wait_for_gdbserver(process: subprocess.Popen[str], log_path: Path) -> int:
    """Read GNU gdbserver's allocated port without consuming its one connection."""
    deadline = time.monotonic() + SERVER_STARTUP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        status = process.poll()
        if status is not None:
            raise EvaluationError(
                f"gdbserver exited with status {status} before readiness."
            )
        output = log_path.read_text(encoding="utf-8", errors="replace")
        match = re.search(r"^Listening on port ([0-9]+)\s*$", output, re.MULTILINE)
        if match:
            port = int(match.group(1))
            if not 1 <= port <= 65535:
                raise EvaluationError("gdbserver reported an invalid port.")
            return port
        time.sleep(0.05)
    raise EvaluationError("gdbserver readiness timed out.")


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        candidate.bind(("127.0.0.1", 0))
        return int(candidate.getsockname()[1])


def _is_listening(port: int) -> bool:
    encoded_port = f"{port:04X}"
    for table in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        try:
            rows = table.read_text(encoding="ascii").splitlines()[1:]
        except OSError:
            continue
        for row in rows:
            fields = row.split()
            if (
                len(fields) >= 4
                and fields[1].rsplit(":", 1)[-1] == encoded_port
                and fields[3] == "0A"
            ):
                return True
    return False


def _wait_for_listener(process: subprocess.Popen[str], port: int, stage: str) -> None:
    deadline = time.monotonic() + SERVER_STARTUP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        returncode = process.poll()
        if returncode is not None:
            raise EvaluationError(
                f"{stage} exited with status {returncode} before listening on port {port}."
            )
        if _is_listening(port):
            return
        time.sleep(0.05)
    raise EvaluationError(
        f"{stage} did not listen on port {port} within "
        f"{SERVER_STARTUP_TIMEOUT_SECONDS} seconds."
    )


def _wait_for_output(process: subprocess.Popen[str], log_path: Path) -> None:
    deadline = time.monotonic() + SIGNAL_READINESS_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise EvaluationError(
                f"Lua exited with status {process.returncode} before becoming ready."
            )
        try:
            if log_path.stat().st_size > 0:
                return
        except OSError:
            pass
        time.sleep(0.05)
    raise EvaluationError("Lua produced no output before the SIGINT readiness timeout.")


def _wait_for_signal_target(process: subprocess.Popen[str], tracee_child: bool) -> int:
    deadline = time.monotonic() + SIGNAL_READINESS_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise EvaluationError(
                f"Lua exited with status {process.returncode} before signal delivery."
            )
        if not tracee_child:
            return process.pid
        frontier = [process.pid]
        descendants: list[int] = []
        while frontier:
            parent = frontier.pop()
            children_path = Path(f"/proc/{parent}/task/{parent}/children")
            try:
                children = [int(value) for value in children_path.read_text().split()]
            except (OSError, ValueError):
                children = []
            descendants.extend(children)
            frontier.extend(children)
        if descendants:
            return descendants[-1]
        time.sleep(0.05)
    raise EvaluationError("Unable to identify the Lua tracee for SIGINT delivery.")


def prepare_application(
    application: Application,
    directory: Path,
) -> PreparedApplication:
    directory.mkdir(parents=True)
    if application.workload_kind == "sqlite":
        workload = directory / "workload.sql"
        shutil.copy2(application.workload, workload)
        return PreparedApplication(
            directory, ("evaluation.db",), workload, None, None, False, False
        )
    if application.workload_kind == "curl":
        fixture = directory / "curl-5k.bin"
        shutil.copy2(application.workload, fixture)
        port = _free_loopback_port()
        return PreparedApplication(
            directory,
            (
                "--fail",
                "--silent",
                "--show-error",
                "--output",
                "download.bin",
                f"http://127.0.0.1:{port}/curl-5k.bin",
            ),
            None,
            directory,
            port,
            False,
            False,
        )
    if application.workload_kind == "lua":
        workload = directory / "workload.lua"
        shutil.copy2(application.workload, workload)
        return PreparedApplication(
            directory,
            ("workload.lua",),
            None,
            None,
            None,
            True,
            True,
        )
    raise EvaluationError(
        f"Unsupported application workload kind {application.workload_kind!r}."
    )


def execute_application(
    config: EvaluationConfig,
    application: Application,
    prepared: PreparedApplication,
    binary: Path,
    log_path: Path,
    *,
    rr_trace: Path | None = None,
) -> ProcessResult:
    command: tuple[str, ...]
    if rr_trace is None:
        command = (str(binary), *prepared.argv)
    else:
        command = (
            str(config.rr_program),
            "record",
            "-n",
            "-o",
            str(rr_trace),
            str(binary),
            *prepared.argv,
        )

    server: ManagedProcess | None = None
    if prepared.server_root is not None and prepared.server_port is not None:
        server = ManagedProcess(
            (
                str(config.http_server_program),
                "-m",
                "http.server",
                str(prepared.server_port),
                "--bind",
                "127.0.0.1",
                "--directory",
                str(prepared.server_root),
            ),
            log_path.with_suffix(".server.log"),
        )

    if server is not None:
        server_process = server.start()
        try:
            _wait_for_listener(server_process, prepared.server_port, "HTTP server")
        except EvaluationError:
            server.stop()
            raise

    managed = ManagedProcess(
        command,
        log_path,
        cwd=prepared.directory,
        stdin_path=prepared.stdin_path,
        pipe_stdin=prepared.pipe_stdin,
    )
    started = time.perf_counter()
    try:
        with managed as process:
            if prepared.deliver_sigint:
                _wait_for_output(process, log_path)
                target = _wait_for_signal_target(process, rr_trace is not None)
                try:
                    os.kill(target, signal.SIGINT)
                except ProcessLookupError as error:
                    raise EvaluationError(
                        "Lua tracee exited before SIGINT delivery."
                    ) from error
            try:
                returncode = process.wait(timeout=PROCESS_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                returncode = 124
    finally:
        if server is not None:
            server.stop()
    try:
        output = log_path.read_text(errors="replace")
    except OSError:
        output = ""
    return ProcessResult(returncode, time.perf_counter() - started, output)


def _failed_application_result(
    application: Application,
    iteration: int,
    mode: str,
    detail: str,
    metadata: dict[str, Any],
    rows: list[dict[str, str | int]],
) -> tuple[list[dict[str, str | int]], dict[str, Any], bool]:
    rows.append(
        result_row(
            application.identifier,
            mode,
            "total",
            None,
            iteration,
            "failed",
            detail,
        )
    )
    return rows, metadata, False


def _capture_full_application_mode(
    config: EvaluationConfig,
    application: Application,
    binary: Path,
    prepared: PreparedApplication,
    rr_trace: Path,
    iteration: int,
    trace_format: str,
    system_directory: Path,
    *,
    mode: str,
    cross_validate: bool,
) -> tuple[list[dict[str, str | int]], dict[str, Any]]:
    logs_directory = system_directory / "logs"
    oracles_directory = system_directory / "oracles"
    profiles_directory = system_directory / "profiles"
    suffix = "cross-validated" if cross_validate else "speculative"
    oracle = oracles_directory / f"{application.identifier}-{iteration}-{suffix}.trace"
    profile = profiles_directory / f"{application.identifier}-{iteration}-{suffix}.json"
    rr_port = _free_loopback_port()
    rr_server = ManagedProcess(
        (
            str(config.rr_program),
            "replay",
            "-s",
            str(rr_port),
            str(rr_trace),
        ),
        logs_directory / f"{application.identifier}-{iteration}-{suffix}-rr-replay.log",
    )
    with rr_server as rr_process:
        _wait_for_listener(rr_process, rr_port, "RR replay server")
        command = (
            str(config.capture_program),
            "--whole-program",
            "--remote",
            f"127.0.0.1:{rr_port}",
            "--deterministic-log",
            str(rr_trace),
            "--output",
            str(oracle),
            "--profile-report",
            str(profile),
            "--out-type",
            trace_format,
            *(("--cross-validate",) if cross_validate else ()),
            str(binary),
            *prepared.argv,
        )
        capture = run_process(
            command,
            cwd=prepared.directory,
            timeout_seconds=CAPTURE_TIMEOUT_SECONDS,
        )
    (
        logs_directory / f"{application.identifier}-{iteration}-{suffix}-capture.log"
    ).write_text(capture.output)
    if capture.returncode != 0:
        raise EvaluationError(
            f"Full {application.workload_kind} {suffix} capture exited "
            f"with status {capture.returncode}."
        )
    if not oracle.is_file() or oracle.stat().st_size == 0:
        raise EvaluationError(
            f"Full {application.workload_kind} {suffix} capture is empty."
        )
    timings = load_component_timings(profile)
    rows = [
        result_row(
            application.identifier,
            mode,
            component,
            timings[component],
            iteration,
            "passed",
        )
        for component in ("concrete", "symbolic", "validation")
    ]
    rows.append(
        result_row(
            application.identifier,
            mode,
            "total",
            timings["trace"],
            iteration,
            "passed",
        )
    )
    return rows, {
        "oracle": str(oracle.relative_to(system_directory)),
        "oracleSha256": _sha256(oracle),
        "profile": str(profile.relative_to(system_directory)),
        "profileSha256": _sha256(profile),
        "traceSeconds": timings["trace"],
        "serializationSeconds": timings["serialization"],
        "captureProcessSeconds": capture.elapsed,
        "crossValidated": cross_validate,
    }


def evaluate_application(
    config: EvaluationConfig,
    application: Application,
    iteration: int,
    system_directory: Path,
    trace_format: str,
) -> tuple[list[dict[str, str | int]], dict[str, Any], bool]:
    binaries_directory = system_directory / "binaries"
    logs_directory = system_directory / "logs"
    oracles_directory = system_directory / "oracles"
    profiles_directory = system_directory / "profiles"
    rr_directory = system_directory / "rr"
    work_directory = system_directory / "work" / f"{application.identifier}-{iteration}"
    for directory in (
        binaries_directory,
        logs_directory,
        oracles_directory,
        profiles_directory,
        rr_directory,
    ):
        directory.mkdir(parents=True, exist_ok=True)

    reference = binaries_directory / f"application-{application.identifier}"
    injected = binaries_directory / f"application-{application.identifier}-injected"
    if not reference.exists():
        shutil.copy2(application.reference_binary, reference)
    if not injected.exists():
        shutil.copy2(application.injected_binary, injected)

    rows: list[dict[str, str | int]] = []
    metadata: dict[str, Any] = {
        "kind": "application",
        "referenceBinary": str(reference.relative_to(system_directory)),
        "referenceBinarySha256": _sha256(reference),
        "referenceBinaryStorePath": str(application.reference_binary),
        "injectedBinary": str(injected.relative_to(system_directory)),
        "injectedBinarySha256": _sha256(injected),
        "injectedBinaryStorePath": str(application.injected_binary),
        "workloadStorePath": str(application.workload),
        "workloadSha256": _sha256(application.workload),
        "workloadKind": application.workload_kind,
        "expectedNativeStatus": application.expected_status,
        "selectiveStartSymbol": application.start_symbol,
        "selectiveStopSymbol": application.stop_symbol,
        "traceFormat": trace_format,
        "traceMode": application.trace_mode,
    }

    try:
        start, stop = resolve_named_bounds(
            config.nm_program,
            injected,
            application.start_symbol,
            application.stop_symbol,
        )
    except EvaluationError as error:
        return _failed_application_result(
            application,
            iteration,
            "native-selective",
            str(error),
            metadata,
            rows,
        )
    metadata.update({"startAddress": start, "stopAddress": stop})

    try:
        baseline_plan = prepare_application(application, work_directory / "baseline")
        baseline = execute_application(
            config,
            application,
            baseline_plan,
            injected,
            logs_directory / f"{application.identifier}-{iteration}-execution.log",
        )
    except EvaluationError as error:
        return _failed_application_result(
            application,
            iteration,
            "native",
            str(error),
            metadata,
            rows,
        )
    baseline_ok = baseline.returncode == application.expected_status
    rows.append(
        result_row(
            application.identifier,
            "native",
            "execution",
            baseline.elapsed if baseline_ok else None,
            iteration,
            "passed" if baseline_ok else "failed",
            ""
            if baseline_ok
            else (
                f"native status {baseline.returncode}, "
                f"expected {application.expected_status}"
            ),
        )
    )
    if not baseline_ok:
        return rows, metadata, False

    rr_trace = rr_directory / f"{application.identifier}-{iteration}"
    try:
        record_plan = prepare_application(application, work_directory / "record")
        recording = execute_application(
            config,
            application,
            record_plan,
            injected,
            logs_directory / f"{application.identifier}-{iteration}-rr-record.log",
            rr_trace=rr_trace,
        )
    except EvaluationError as error:
        return _failed_application_result(
            application,
            iteration,
            "native-rr",
            str(error),
            metadata,
            rows,
        )
    recording_ok = recording.returncode == application.expected_status
    if not recording_ok:
        return _failed_application_result(
            application,
            iteration,
            "native-rr",
            f"RR record status {recording.returncode}, expected {application.expected_status}",
            metadata,
            rows,
        )
    events = rr_trace / "events"
    if not events.is_file() or events.stat().st_size == 0:
        return _failed_application_result(
            application,
            iteration,
            "native-rr",
            "RR recording produced no event log",
            metadata,
            rows,
        )
    rows.append(
        result_row(
            application.identifier,
            "native-rr",
            "record",
            recording.elapsed,
            iteration,
            "passed",
        )
    )

    if application.trace_mode == "full":
        captures: dict[str, dict[str, Any]] = {}
        for mode, cross_validate in (
            ("native-full-cross-validated", True),
            ("native-full-speculative", False),
        ):
            try:
                mode_rows, mode_metadata = _capture_full_application_mode(
                    config,
                    application,
                    injected,
                    record_plan,
                    rr_trace,
                    iteration,
                    trace_format,
                    system_directory,
                    mode=mode,
                    cross_validate=cross_validate,
                )
            except EvaluationError as error:
                return _failed_application_result(
                    application,
                    iteration,
                    mode,
                    str(error),
                    metadata,
                    rows,
                )
            rows.extend(mode_rows)
            captures[mode] = mode_metadata
        speculative = captures["native-full-speculative"]
        metadata.update(
            {
                "argv": list(record_plan.argv),
                "rrTrace": str(rr_trace.relative_to(system_directory)),
                "oracle": speculative["oracle"],
                "oracleSha256": speculative["oracleSha256"],
                "profile": speculative["profile"],
                "profileSha256": speculative["profileSha256"],
                "traceSeconds": speculative["traceSeconds"],
                "serializationSeconds": speculative["serializationSeconds"],
                "captureProcessSeconds": speculative["captureProcessSeconds"],
                "fullCaptures": captures,
            }
        )
        return rows, metadata, True

    oracle = oracles_directory / f"{application.identifier}-{iteration}-selective.trace"
    profile = (
        profiles_directory / f"{application.identifier}-{iteration}-selective.json"
    )
    rr_port = _free_loopback_port()
    rr_server = ManagedProcess(
        (
            str(config.rr_program),
            "replay",
            "-s",
            str(rr_port),
            str(rr_trace),
        ),
        logs_directory / f"{application.identifier}-{iteration}-rr-replay.log",
    )
    try:
        with rr_server as rr_process:
            _wait_for_listener(rr_process, rr_port, "RR replay server")
            capture_command = (
                str(config.capture_program),
                "--remote",
                f"127.0.0.1:{rr_port}",
                "--deterministic-log",
                str(rr_trace),
                "--start-address",
                hex(start),
                "--stop-address",
                hex(stop),
                "--output",
                str(oracle),
                "--profile-report",
                str(profile),
                "--out-type",
                trace_format,
                str(injected),
                *record_plan.argv,
            )
            capture = run_process(
                capture_command,
                cwd=record_plan.directory,
                timeout_seconds=CAPTURE_TIMEOUT_SECONDS,
            )
    except EvaluationError as error:
        return _failed_application_result(
            application,
            iteration,
            "native-selective",
            str(error),
            metadata,
            rows,
        )
    (logs_directory / f"{application.identifier}-{iteration}-capture.log").write_text(
        capture.output
    )
    if capture.returncode != 0:
        return _failed_application_result(
            application,
            iteration,
            "native-selective",
            f"capture status {capture.returncode}",
            metadata,
            rows,
        )
    if not oracle.is_file() or oracle.stat().st_size == 0:
        return _failed_application_result(
            application,
            iteration,
            "native-selective",
            "capture produced no selective oracle trace",
            metadata,
            rows,
        )
    try:
        timings = load_component_timings(profile)
    except EvaluationError as error:
        return _failed_application_result(
            application,
            iteration,
            "native-selective",
            str(error),
            metadata,
            rows,
        )

    for component in ("concrete", "symbolic", "validation"):
        rows.append(
            result_row(
                application.identifier,
                "native-selective",
                component,
                timings[component],
                iteration,
                "passed",
            )
        )
    rows.append(
        result_row(
            application.identifier,
            "native-selective",
            "total",
            timings["trace"],
            iteration,
            "passed",
        )
    )
    metadata.update(
        {
            "argv": list(record_plan.argv),
            "rrTrace": str(rr_trace.relative_to(system_directory)),
            "oracle": str(oracle.relative_to(system_directory)),
            "oracleSha256": _sha256(oracle),
            "profile": str(profile.relative_to(system_directory)),
            "profileSha256": _sha256(profile),
            "traceSeconds": timings["trace"],
            "serializationSeconds": timings["serialization"],
            "captureProcessSeconds": capture.elapsed,
            "rrPort": rr_port,
        }
    )
    return rows, metadata, True


def write_results(path: Path, rows: Sequence[dict[str, str | int]]) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=RESULT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def _write_metadata(path: Path, metadata: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def _read_results(path: Path) -> list[dict[str, str | int]]:
    try:
        with path.open(newline="") as source:
            reader = csv.DictReader(source)
            if tuple(reader.fieldnames or ()) != RESULT_FIELDS:
                raise EvaluationError(
                    f"Existing evaluation results have an unsupported schema: {path}."
                )
            return [dict(row) for row in reader]
    except OSError as error:
        raise EvaluationError(
            f"Unable to read existing evaluation results {path}: {error}"
        ) from error


def run_native(
    config: EvaluationConfig,
    output: Path,
    requested_cases: Sequence[str],
    iterations: int,
    trace_format: str,
) -> int:
    actual_machine = normalize_machine(platform.machine())
    configured_machine = expected_machine(config.system)
    if actual_machine != configured_machine:
        raise EvaluationError(
            f"Nix system {config.system} requires {configured_machine}, but the runtime host is "
            f"{actual_machine}."
        )

    available = set(config.triggers) | set(config.applications)
    unknown = sorted(set(requested_cases) - available)
    if unknown:
        raise EvaluationError(
            f"Cases are unavailable for native {config.system}: {', '.join(unknown)}."
        )
    selected = list(requested_cases) if requested_cases else sorted(available)
    if not selected:
        raise EvaluationError(f"No native cases are configured for {config.system}.")

    system_directory = output.resolve() / "native" / config.system
    created_at = datetime.now(UTC).isoformat()
    rows: list[dict[str, str | int]] = []
    cases: dict[str, Any] = {}
    if system_directory.exists():
        previous = _load_json_object(
            system_directory / "metadata.json", "existing native metadata"
        )
        expected = {
            "schema": NATIVE_SCHEMA,
            "system": config.system,
            "machine": actual_machine,
            "role": "native",
            "iterations": iterations,
            "traceFormat": trace_format,
        }
        if any(previous.get(name) != value for name, value in expected.items()):
            raise EvaluationError(
                "Existing native evaluation metadata is incompatible with this run."
            )
        previous_cases = previous.get("cases")
        if not isinstance(previous_cases, dict) or not all(
            isinstance(identifier, str)
            and isinstance(case, dict)
            and case.get("kind") in {"trigger", "application"}
            and case.get("status") in {"passed", "failed"}
            for identifier, case in previous_cases.items()
        ):
            raise EvaluationError("Existing native evaluation cases are malformed.")
        duplicates = sorted(set(selected) & set(previous_cases))
        if duplicates:
            raise EvaluationError(
                "Native cases already exist; archive before rerunning: "
                + ", ".join(duplicates)
                + "."
            )
        previous_rows = _read_results(system_directory / "results.csv")
        if any(row.get("benchmark") not in previous_cases for row in previous_rows):
            raise EvaluationError(
                "Existing native results contain an unregistered benchmark."
            )
        encoded_created_at = previous.get("createdAt")
        if not isinstance(encoded_created_at, str):
            raise EvaluationError("Existing native metadata has no creation time.")
        cases.update(previous_cases)
        rows.extend(previous_rows)
        created_at = encoded_created_at
    else:
        system_directory.mkdir(parents=True)

    all_passed = all(
        isinstance(case, dict) and case.get("status") == "passed"
        for case in cases.values()
    )
    invocation_passed = True
    for identifier in selected:
        case_metadata: dict[str, Any] = {"iterations": []}
        case_passed = True
        kind = "application" if identifier in config.applications else "trigger"
        print(f"[{config.system}] native {kind} {identifier}", flush=True)
        for iteration in range(iterations):
            if kind == "application":
                iteration_rows, iteration_metadata, passed = evaluate_application(
                    config,
                    config.applications[identifier],
                    iteration,
                    system_directory,
                    trace_format,
                )
            else:
                iteration_rows, iteration_metadata, passed = evaluate_trigger(
                    config,
                    config.triggers[identifier],
                    iteration,
                    system_directory,
                    trace_format,
                )
            rows.extend(iteration_rows)
            case_metadata["iterations"].append(iteration_metadata)
            case_passed &= passed
        case_metadata.update(
            {"kind": kind, "status": "passed" if case_passed else "failed"}
        )
        cases[identifier] = case_metadata
        all_passed &= case_passed
        invocation_passed &= case_passed

    write_results(system_directory / "results.csv", rows)
    scope = (
        "triggers-and-applications"
        if any(
            isinstance(case, dict) and case.get("kind") == "application"
            for case in cases.values()
        )
        else "triggers"
    )
    metadata = {
        "schema": NATIVE_SCHEMA,
        "system": config.system,
        "machine": actual_machine,
        "role": "native",
        "scope": scope,
        "createdAt": created_at,
        "updatedAt": datetime.now(UTC).isoformat(),
        "iterations": iterations,
        "traceFormat": trace_format,
        "cases": cases,
        "status": "passed" if all_passed else "failed",
    }
    _write_metadata(system_directory / "metadata.json", metadata)
    return 0 if invocation_passed else 1


def _load_json_object(path: Path, context: str) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise EvaluationError(f"Unable to read {context} {path}: {error}") from error
    if not isinstance(document, dict):
        raise EvaluationError(f"{context} {path} is not a JSON object.")
    return document


def _select_emulator_cases(
    config: EvaluationConfig,
    requested_cases: Sequence[str],
    requested_emulators: Sequence[str],
) -> list[EmulatorCase]:
    cases = list(config.emulator_cases.values())
    if requested_cases:
        selected = set(requested_cases)
        cases = [
            case
            for case in cases
            if case.identifier in selected or case.trigger in selected
        ]
        matched = {case.identifier for case in cases} | {case.trigger for case in cases}
        missing = sorted(selected - matched)
        if missing:
            raise EvaluationError(
                f"Unknown or inapplicable emulator cases: {', '.join(missing)}."
            )
    if requested_emulators:
        selected_emulators = set(requested_emulators)
        cases = [
            case
            for case in cases
            if (
                case.emulator in selected_emulators
                or config.emulators[case.emulator].backend in selected_emulators
                or config.emulators[case.emulator].backend.split("-", 1)[0]
                in selected_emulators
            )
        ]
        if not cases:
            raise EvaluationError("No emulator cases match --emulator selection.")
    if not cases:
        raise EvaluationError(
            f"No emulator cases are applicable to host system {config.system}."
        )
    return sorted(cases, key=lambda case: case.identifier)


def _emulator_output(variant: EmulatorVariant) -> Path:
    if not variant.output.is_dir():
        raise EvaluationError(
            f"Emulator output does not exist for {variant.identifier}: {variant.output}."
        )
    return variant.output


def _native_bundle_iteration(
    input_directory: Path, case: EmulatorCase, iteration: int, kind: str
) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    if case.guest_system not in {"x86_64-linux", "aarch64-linux"}:
        raise EvaluationError("Native bundle requires a supported guest system.")
    machine = expected_machine(case.guest_system)
    directory = (input_directory / "native" / case.guest_system).resolve()
    metadata = _load_json_object(directory / "metadata.json", "native metadata")
    if (
        metadata.get("schema") != NATIVE_SCHEMA
        or metadata.get("role") != "native"
        or metadata.get("system") != case.guest_system
        or normalize_machine(_required_string(metadata, "machine", "Native metadata"))
        != machine
    ):
        raise EvaluationError(
            "Native metadata has invalid schema or producer system identity."
        )
    cases = metadata.get("cases")
    encoded = cases.get(case.trigger) if isinstance(cases, dict) else None
    if (
        not isinstance(encoded, dict)
        or encoded.get("kind") != kind
        or encoded.get("status") != "passed"
    ):
        raise EvaluationError(
            f"Native {kind} {case.trigger} is absent or did not pass capture with the expected kind."
        )
    iterations = encoded.get("iterations")
    if (
        type(iteration) is not int
        or iteration < 0
        or not isinstance(iterations, list)
        or iteration >= len(iterations)
    ):
        raise EvaluationError(
            f"Native {kind} {case.trigger} lacks iteration {iteration}."
        )
    item = iterations[iteration]
    if not isinstance(item, dict) or item.get("kind") != kind:
        raise EvaluationError(
            f"Native {kind} {case.trigger} iteration {iteration} has invalid kind."
        )
    return directory, metadata, item


def _native_artifact_path(directory: Path, item: dict[str, Any], field: str) -> Path:
    relative = Path(_required_string(item, field, "Native artifact"))
    if relative.is_absolute():
        raise EvaluationError(f"Native artifact {field} must be bundle-relative.")
    resolved = (directory / relative).resolve()
    if not resolved.is_relative_to(directory.resolve()):
        raise EvaluationError(
            f"Native artifact {field} escapes the guest-native directory."
        )
    return resolved


def _native_trace_format(metadata: dict[str, Any], item: dict[str, Any]) -> str:
    trace_format = _required_string(metadata, "traceFormat", "Native metadata")
    if (
        trace_format not in {"msgpack", "json"}
        or item.get("traceFormat") != trace_format
    ):
        raise EvaluationError(
            "Native trace format metadata is missing, invalid or inconsistent."
        )
    return trace_format


def _require_native_hash(path: Path, item: dict[str, Any], field: str) -> None:
    digest = item.get(field)
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise EvaluationError(f"Native artifact has missing or invalid {field}.")
    if not path.is_file() or _sha256(path) != digest:
        raise EvaluationError(f"Native artifact hash mismatch for {path} ({field}).")


def _native_trigger_artifacts(
    input_directory: Path,
    case: EmulatorCase,
    iteration: int,
) -> tuple[Path, Path, int, str, dict[str, Any]]:
    system_directory, metadata, item = _native_bundle_iteration(
        input_directory, case, iteration, "trigger"
    )
    binary = _native_artifact_path(system_directory, item, "binary")
    oracle = _native_artifact_path(system_directory, item, "oracle")
    expected_status = item.get("expectedNativeStatus")
    if not isinstance(expected_status, int) or isinstance(expected_status, bool):
        raise EvaluationError(
            "Native trigger metadata has invalid expectedNativeStatus."
        )
    trace_format = _native_trace_format(metadata, item)
    _require_native_hash(binary, item, "binarySha256")
    _require_native_hash(oracle, item, "oracleSha256")
    native_witness_sha256 = item.get("witnessSha256")
    if case.expected_witness_sha256 is not None and (
        native_witness_sha256 != case.expected_witness_sha256
    ):
        raise EvaluationError(
            f"Native trigger {case.trigger} does not match the configured witness."
        )
    return binary, oracle, expected_status, trace_format, item


def _native_application_artifacts(
    input_directory: Path,
    case: EmulatorCase,
    iteration: int,
    case_directory: Path,
) -> NativeApplicationArtifacts:
    if case.workload is None or case.workload_kind is None:
        raise EvaluationError(f"Application case {case.identifier} has no workload.")
    system_directory, metadata, item = _native_bundle_iteration(
        input_directory, case, iteration, "application"
    )
    if item.get("workloadKind") != case.workload_kind:
        raise EvaluationError(
            "Native application workload kind does not match the case."
        )
    if item.get("traceMode", "selective") != case.trace_mode:
        raise EvaluationError(
            "Native application trace mode does not match the emulator case."
        )

    binary = _native_artifact_path(system_directory, item, "injectedBinary")
    oracle = _native_artifact_path(system_directory, item, "oracle")
    rr_trace = _native_artifact_path(system_directory, item, "rrTrace")
    argv_value = item.get("argv")
    if not isinstance(argv_value, list) or not all(
        isinstance(argument, str) for argument in argv_value
    ):
        raise EvaluationError("Native application metadata has invalid argv.")
    argv = tuple(argv_value)

    trace_format = _native_trace_format(metadata, item)

    if not binary.is_file() or not oracle.is_file() or not rr_trace.is_dir():
        raise EvaluationError("Native application artifacts are incomplete.")
    _require_native_hash(binary, item, "injectedBinarySha256")
    _require_native_hash(oracle, item, "oracleSha256")
    workload_hash = item.get("workloadSha256")
    if not isinstance(workload_hash, str) or not case.workload.is_file():
        raise EvaluationError("Application workload identity is unavailable.")
    if workload_hash != _sha256(case.workload):
        raise EvaluationError(
            "Application workload hash does not match native metadata."
        )
    if not (rr_trace / "events").is_file():
        raise EvaluationError("Native application RR trace has no event log.")
    for name in ("startAddress", "stopAddress"):
        value = item.get(name)
        if not isinstance(value, int) or isinstance(value, bool):
            raise EvaluationError(f"Native application metadata has invalid {name}.")

    work_directory = case_directory / "work"
    work_directory.mkdir(parents=True, exist_ok=True)
    workload_names = {
        "sqlite": "input.sql",
        "curl": "curl-5k.bin",
        "lua": "workload.lua",
    }
    workload = work_directory / workload_names[case.workload_kind]
    shutil.copy2(case.workload, workload)
    return NativeApplicationArtifacts(
        binary,
        oracle,
        rr_trace,
        workload,
        argv,
        trace_format,
        item,
    )


def _prepare_qemu_application(
    case: EmulatorCase,
    artifacts: NativeApplicationArtifacts,
) -> PreparedApplication:
    directory = artifacts.workload.parent
    if case.workload_kind == "sqlite":
        return PreparedApplication(
            directory,
            artifacts.argv,
            artifacts.workload,
            None,
            None,
            False,
            False,
        )
    if case.workload_kind == "curl":
        urls = [
            argument for argument in artifacts.argv if argument.startswith("http://")
        ]
        if len(urls) != 1:
            raise EvaluationError("Native Curl arguments do not contain one HTTP URL.")
        url = urlsplit(urls[0])
        try:
            port = url.port
        except ValueError as error:
            raise EvaluationError("Native Curl URL has an invalid port.") from error
        if (
            url.hostname != "127.0.0.1"
            or port is None
            or url.path != f"/{artifacts.workload.name}"
        ):
            raise EvaluationError(
                "Native Curl URL does not identify the bound loopback workload."
            )
        return PreparedApplication(
            directory,
            artifacts.argv,
            None,
            directory,
            port,
            False,
            False,
        )
    if case.workload_kind == "lua":
        if artifacts.argv != (artifacts.workload.name,):
            raise EvaluationError("Native Lua arguments do not identify the workload.")
        return PreparedApplication(
            directory,
            artifacts.argv,
            None,
            None,
            None,
            False,
            True,
        )
    raise EvaluationError(f"Unsupported QEMU workload kind {case.workload_kind!r}.")


def _require_successful_replay(report: dict[str, Any]) -> None:
    replay = report.get("replay")
    if not isinstance(replay, dict) or replay.get("active") is not True:
        raise EvaluationError("QEMU application report has no active replay coverage.")
    record_count = replay.get("record_count")
    outcomes = replay.get("by_outcome")
    if (
        not isinstance(record_count, int)
        or isinstance(record_count, bool)
        or record_count <= 0
        or not isinstance(outcomes, dict)
    ):
        raise EvaluationError("QEMU application report has invalid replay coverage.")
    if any(outcomes.get(name, 0) for name in ("rejected", "failed")):
        raise EvaluationError(
            "QEMU application replay contains rejected or failed effects."
        )


def _require_complete_trace(report: dict[str, Any]) -> None:
    trace = report.get("trace")
    if not isinstance(trace, dict):
        raise EvaluationError("Reference validation report has no trace evidence.")
    state_count = trace.get("state_count")
    transform_count = trace.get("transform_count")
    if (
        trace.get("available") is not True
        or trace.get("complete") is not True
        or not isinstance(state_count, int)
        or isinstance(state_count, bool)
        or not isinstance(transform_count, int)
        or isinstance(transform_count, bool)
        or state_count != transform_count + 1
    ):
        raise EvaluationError(
            "Reference validation did not preserve a complete terminal transition trace."
        )


def _require_plugin_terminal_provenance(report: dict[str, Any]) -> None:
    trace = report.get("trace")
    completion = report.get("completion")
    if (
        not isinstance(trace, dict)
        or trace.get("available") is not True
        or not isinstance(completion, dict)
        or completion.get("scope") != "whole-program"
        or completion.get("expected_completion_available") is not True
        or completion.get("observed_completion_available") is not True
        or completion.get("final_live_boundary_bound") is not True
        or completion.get("execution_complete") is not True
        or completion.get("full_run_timing_eligible") is not True
        or completion.get("terminal_outcome") not in {"match", "mismatch"}
        or completion.get("terminal_action") not in {"match", "mismatch"}
    ):
        raise EvaluationError(
            "Plugin validation did not preserve process-bound terminal provenance."
        )


def _require_complete_terminal_trace(report: dict[str, Any]) -> None:
    _require_complete_trace(report)
    if report["trace"].get("terminal_reached") is not True:
        raise EvaluationError(
            "Reference validation did not preserve a complete terminal transition trace."
        )


def _require_whole_program_completion(report: dict[str, Any]) -> None:
    # This is deliberately the strict reference-correctness contract.  Do not
    # use experiment execution evidence to turn semantic gaps into completion.
    _require_complete_trace(report)
    completion = report.get("completion")
    if (
        not isinstance(completion, dict)
        or completion.get("scope") != "whole-program"
        or completion.get("complete") is not True
        or completion.get("full_run_timing_eligible") is not True
        or any(
            completion.get(field) is not True
            for field in (
                "expected_completion_available",
                "observed_completion_available",
                "ordinary_prefix_complete",
                "final_live_boundary_bound",
            )
        )
        or completion.get("terminal_action") != "match"
        or completion.get("terminal_outcome") != "match"
    ):
        raise EvaluationError(
            "Full application validation requires explicit whole-program completion "
            "and full-run timing eligibility."
        )


def require_whole_program_experiment_execution(
    report: dict[str, Any],
    *,
    expected_bug_localized: bool,
    expected_terminal_signal_localized: bool = False,
) -> dict[str, object]:
    """Admit diagnostic whole-run timing without claiming semantic completion.

    The caller must establish localization against its configured bug contract.
    This gate establishes only that the declared execution ran to independently
    observed termination, with cardinality and required-action evidence intact.
    Confirmed/possible/incomplete semantic findings remain counted and visible.
    """
    trace = report.get("trace")
    completion = report.get("completion")
    validation = report.get("validation")
    if report.get("schema") != "focaccia-qemu-validation-v1":
        raise EvaluationError("Whole-run experiment has an unsupported report schema.")
    if report.get("status") not in {"accepted", "mismatch", "incomplete"}:
        raise EvaluationError(
            "Whole-run experiment aborted before a reportable result."
        )
    if expected_bug_localized is not True:
        raise EvaluationError("Whole-run experiment did not localize the expected bug.")
    if (
        not isinstance(trace, dict)
        or trace.get("available") is not True
        or type(trace.get("state_count")) is not int
        or type(trace.get("transform_count")) is not int
        or trace["transform_count"] <= 0
        or trace["state_count"] != trace["transform_count"] + 1
    ):
        raise EvaluationError(
            "Whole-run experiment is truncated or lacks cardinality evidence."
        )
    normal_terminal = (
        isinstance(completion, dict)
        and completion.get("scope") == "whole-program"
        and completion.get("expected_completion_available") is True
        and completion.get("observed_completion_available") is True
        and completion.get("final_live_boundary_bound") is True
        and completion.get("terminal_action") in {"match", "mismatch"}
        and completion.get("terminal_outcome") in {"match", "mismatch"}
    )
    signal_terminal = (
        isinstance(completion, dict)
        and completion.get("scope") == "whole-program"
        and expected_terminal_signal_localized is True
        and isinstance(report.get("terminal_reason"), dict)
        and report["terminal_reason"].get("kind") == "signal"
    )
    if not normal_terminal and not signal_terminal:
        raise EvaluationError(
            "Whole-run experiment lacks independently observed terminal/action evidence."
        )
    if (
        not isinstance(validation, dict)
        or not isinstance(validation.get("severity_counts"), dict)
        or not isinstance(validation.get("diagnostic_counts"), dict)
        or any(
            type(value) is not int or value < 0
            for value in validation["severity_counts"].values()
        )
        or any(
            type(value) is not int or value < 0
            for value in validation["diagnostic_counts"].values()
        )
    ):
        raise EvaluationError("Whole-run experiment has malformed coverage counts.")
    return {
        "classification": "diagnostic-whole-run",
        "timingEligible": True,
        "executionCompleted": True,
        "referenceCorrectnessEstablished": False,
        "allTransitionsValidated": completion.get("complete") is True,
        "stateCount": trace["state_count"],
        "transformCount": trace["transform_count"],
        "confirmedFindingCount": validation["severity_counts"].get("confirmed", 0),
        "unconfirmedComparisonCount": sum(
            count
            for severity, count in validation["severity_counts"].items()
            if severity != "confirmed"
        ),
        "diagnosticCount": sum(validation["diagnostic_counts"].values()),
    }


def _expected_register_mismatch(
    report: dict[str, Any],
    source_address: int,
    stop_address: int,
    subject: str,
) -> bool:
    validation = report.get("validation")
    if not isinstance(validation, dict):
        return False
    entries = validation.get("entries")
    if not isinstance(entries, list):
        return False
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("transition_range") != [source_address, stop_address]:
            continue
        errors = entry.get("errors")
        if not isinstance(errors, list):
            continue
        if any(
            isinstance(error, dict)
            and error.get("severity") == "confirmed"
            and error.get("code") == "register-content-mismatch"
            and error.get("subject") == subject
            for error in errors
        ):
            return True
    return False


def _expected_application_mismatch(
    report: dict[str, Any],
    source_address: int,
    stop_address: int,
    subject: str,
) -> bool:
    """Locate the nominated classified bug without hiding other findings."""
    validation = report.get("validation")
    entries = validation.get("entries") if isinstance(validation, dict) else None
    if not isinstance(entries, list):
        return False
    found = 0
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("errors"), list):
            return False
        for error in entry["errors"]:
            if (
                entry.get("transition_range") == [source_address, stop_address]
                and isinstance(error, dict)
                and error.get("severity") == "confirmed"
                and error.get("code") == "register-content-mismatch"
                and error.get("subject") == subject
            ):
                found += 1
    return found == 1


def require_selective_application_acceptance(
    report: dict[str, Any],
    expected: str,
    mismatch_range: list[int] | None = None,
    subject: str | None = None,
) -> None:
    """Gate an executed selective experiment, not a clean-emulator claim.

    A mismatch run is timing/detection eligible when it reaches the declared
    terminal boundary with N+1 states, handles replay, and detects the nominated
    bug once.  Other confirmed findings and explicitly unconfirmed comparisons
    remain evidence in the report; they do not become reference correctness or
    an "all transitions validated" claim.  Accepted reference controls remain
    clean and complete.
    """
    if (
        report.get("schema") != "focaccia-qemu-validation-v1"
        or not isinstance(expected, str)
        or expected not in {"accepted", "mismatch"}
        or report.get("status") != expected
    ):
        raise EvaluationError(
            "Selective application validation status is not expected."
        )
    _require_successful_replay(report)
    _require_complete_trace(report) if expected == "accepted" else None
    trace = report.get("trace")
    if (
        not isinstance(trace, dict)
        or trace.get("available") is not True
        or trace.get("terminal_reached") is not True
        or type(trace.get("state_count")) is not int
        or type(trace.get("transform_count")) is not int
        or trace["transform_count"] <= 0
        or trace["state_count"] != trace["transform_count"] + 1
    ):
        raise EvaluationError(
            "Selective application did not execute the full declared scope with N+1 boundaries."
        )
    validation = report.get("validation")
    if (
        not isinstance(validation, dict)
        or not isinstance(validation.get("diagnostics"), list)
        or not isinstance(validation.get("diagnostic_counts"), dict)
        or not isinstance(validation.get("severity_counts"), dict)
        or not isinstance(validation.get("entries"), list)
        or any(
            type(value) is not int or value < 0
            for value in validation["diagnostic_counts"].values()
        )
        or any(
            type(value) is not int or value < 0
            for value in validation["severity_counts"].values()
        )
    ):
        raise EvaluationError("Selective application has malformed report evidence.")
    if expected == "mismatch":
        if (
            not isinstance(mismatch_range, list)
            or len(mismatch_range) != 2
            or any(type(value) is not int for value in mismatch_range)
            or not isinstance(subject, str)
            or not subject
            or type(validation["severity_counts"].get("confirmed")) is not int
            or validation["severity_counts"].get("confirmed", 0) < 1
            or not _expected_application_mismatch(report, *mismatch_range, subject)
        ):
            raise EvaluationError(
                "Selective application requires the nominated classified mismatch "
                "within a fully executed, cardinality-consistent scope."
            )
    else:
        validation = report.get("validation")
        if (
            not isinstance(validation, dict)
            or validation.get("diagnostics") != []
            or not isinstance(validation.get("entries"), list)
            or any(
                not isinstance(entry, dict) or entry.get("errors") != []
                for entry in validation["entries"]
            )
            or any(validation.get("severity_counts", {}).values())
            or any(validation.get("diagnostic_counts", {}).values())
        ):
            raise EvaluationError(
                "Accepted selective application contains diagnostics."
            )


def _evaluate_qemu_application(
    config: EvaluationConfig,
    case: EmulatorCase,
    variant: EmulatorVariant,
    program: Path,
    input_directory: Path,
    iteration: int,
    case_directory: Path,
    *,
    skip_unmatched: bool = False,
) -> tuple[list[dict[str, str | int]], dict[str, Any], bool]:
    case_directory.mkdir(parents=True, exist_ok=True)
    artifacts = _native_application_artifacts(
        input_directory,
        case,
        iteration,
        case_directory,
    )
    preflight_path = case_directory / "replay-preflight.json"
    preflight = run_process(
        (
            str(config.replay_preflight_program),
            "--deterministic-log",
            str(artifacts.rr_trace),
            "--output",
            str(preflight_path),
        )
    )
    if preflight.returncode != 0:
        detail = f"Replay preflight failed with status {preflight.returncode}."
        if preflight_path.is_file():
            document = _load_json_object(preflight_path, "replay preflight report")
            failures = document.get("failures")
            if isinstance(failures, list) and failures:
                first = failures[0]
                if isinstance(first, dict) and isinstance(first.get("reason"), str):
                    detail = (
                        f"Replay preflight rejected the application: {first['reason']}."
                    )
        raise EvaluationError(detail)

    manifest_path = case_directory / "run-manifest.json"
    manifest_log = case_directory / "run-manifest.log"
    manifest = run_process(
        (
            str(config.replay_manifest_program),
            "--binary",
            str(artifacts.binary),
            "--oracle",
            str(artifacts.oracle),
            "--trace-type",
            artifacts.trace_format,
            "--deterministic-log",
            str(artifacts.rr_trace),
            "--argv-json",
            json.dumps(artifacts.argv),
            "--input",
            f"workload={artifacts.workload}",
            "--output",
            str(manifest_path),
        )
    )
    manifest_log.write_text(manifest.output)
    if manifest.returncode != 0 or not manifest_path.is_file():
        raise EvaluationError(
            f"Replay manifest generation failed with status {manifest.returncode}."
        )

    prepared = _prepare_qemu_application(case, artifacts)
    qemu_log = case_directory / "qemu.log"
    validation_log = case_directory / "validation.log"
    report_path = case_directory / "validation.json"
    profile_path = case_directory / "profile.json"
    states_path = case_directory / "states.trace"
    port = _free_loopback_port()
    qemu = ManagedProcess(
        (str(program), "-g", str(port), str(artifacts.binary), *prepared.argv),
        qemu_log,
        cwd=prepared.directory,
        stdin_path=prepared.stdin_path,
        pipe_stdin=prepared.pipe_stdin,
    )
    server: ManagedProcess | None = None
    if prepared.server_root is not None and prepared.server_port is not None:
        server = ManagedProcess(
            (
                str(config.http_server_program),
                "-m",
                "http.server",
                str(prepared.server_port),
                "--bind",
                "127.0.0.1",
                "--directory",
                str(prepared.server_root),
            ),
            case_directory / "http-server.log",
        )
    started = time.perf_counter()
    try:
        if server is not None:
            server_process = server.start()
            _wait_for_listener(server_process, prepared.server_port, "HTTP server")
        with qemu as qemu_process:
            _wait_for_listener(qemu_process, port, "QEMU GDB server")
            validation = run_process(
                (
                    str(config.validate_qemu_program),
                    "--remote",
                    f"127.0.0.1:{port}",
                    "--symb-trace",
                    str(artifacts.oracle),
                    "--trace-type",
                    artifacts.trace_format,
                    "--executable",
                    str(artifacts.binary),
                    "--deterministic-log",
                    str(artifacts.rr_trace),
                    "--run-manifest",
                    str(manifest_path),
                    "--run-input",
                    f"workload={artifacts.workload}",
                    "--output",
                    str(states_path),
                    "--report",
                    str(report_path),
                    "--profile-report",
                    str(profile_path),
                    "--error-level",
                    "info",
                    "--quiet",
                    *(("--skip-unmatched",) if skip_unmatched else ()),
                ),
                cwd=prepared.directory,
                timeout_seconds=CAPTURE_TIMEOUT_SECONDS,
            )
    except EvaluationError as error:
        validation_log.write_text(str(error) + "\n")
        rows = [
            result_row(
                case.trigger,
                variant.identifier,
                "validation",
                None,
                iteration,
                "failed",
                str(error),
            )
        ]
        return rows, {"error": str(error)}, False
    finally:
        if server is not None:
            server.stop()

    validation_log.write_text(validation.output)
    total = time.perf_counter() - started
    metadata: dict[str, Any] = {
        "kind": "application",
        "backend": variant.backend,
        "emulator": variant.identifier,
        "emulatorVersion": variant.version,
        "binary": str(artifacts.binary),
        "binarySha256": _sha256(artifacts.binary),
        "oracle": str(artifacts.oracle),
        "oracleSha256": _sha256(artifacts.oracle),
        "rrTrace": str(artifacts.rr_trace),
        "workload": str(artifacts.workload),
        "workloadSha256": _sha256(artifacts.workload),
        "argv": list(artifacts.argv),
        "replayPreflight": str(preflight_path),
        "replayPreflightSha256": _sha256(preflight_path),
        "runManifest": str(manifest_path),
        "runManifestSha256": _sha256(manifest_path),
        "native": artifacts.metadata,
        "qemuLog": str(qemu_log),
        "states": str(states_path),
        "skipUnmatched": skip_unmatched,
    }
    if validation.returncode != 0:
        rows = [
            result_row(
                case.trigger,
                variant.identifier,
                "validation",
                None,
                iteration,
                "failed",
                f"QEMU validation status {validation.returncode}",
            )
        ]
        return rows, metadata, False

    report = _load_json_object(report_path, "QEMU application validation report")
    if report.get("schema") != "focaccia-qemu-validation-v1":
        raise EvaluationError("QEMU validator produced an unsupported report schema.")
    _require_successful_replay(report)
    if case.trace_mode == "full":
        _require_whole_program_completion(report)
    observed = report.get("status")
    localization_error = ""
    passed = observed == case.expected_validation
    if passed and case.expected_validation == "mismatch":
        source_symbol = case.expected_mismatch_source_symbol
        subject = case.expected_mismatch_subject
        stop_address = artifacts.metadata.get("stopAddress")
        if (
            source_symbol is None
            or subject is None
            or not isinstance(stop_address, int)
            or isinstance(stop_address, bool)
        ):
            raise EvaluationError(
                "Injected application mismatch metadata is incomplete."
            )
        symbols = read_symbols(config.nm_program, artifacts.binary)
        source_address = symbols.get(source_symbol)
        if source_address is None:
            raise EvaluationError(
                f"Injected application binary has no symbol {source_symbol!r}."
            )
        metadata.update(
            {
                "expectedMismatchRange": [source_address, stop_address],
                "expectedMismatchSubject": subject,
            }
        )
        passed = _expected_application_mismatch(
            report,
            source_address,
            stop_address,
            subject,
        )
        if not passed:
            localization_error = (
                "expected confirmed register-content-mismatch for "
                f"{subject} at {hex(source_address)} -> {hex(stop_address)} was absent "
                "or accompanied by unrelated errors or diagnostics"
            )
    if passed and case.trace_mode != "full":
        require_selective_application_acceptance(
            report,
            case.expected_validation,
            metadata.get("expectedMismatchRange"),
            metadata.get("expectedMismatchSubject"),
        )
        validation = report["validation"]
        trace = report["trace"]
        metadata["selectiveEvidence"] = {
            "classification": "intended-bug-detected",
            "timingEligible": True,
            "referenceCorrectnessEstablished": False,
            "allTransitionsValidated": trace.get("complete") is True,
            "stateCount": trace["state_count"],
            "transformCount": trace["transform_count"],
            "confirmedFindingCount": validation["severity_counts"].get("confirmed", 0),
            "unconfirmedComparisonCount": sum(
                count
                for severity, count in validation["severity_counts"].items()
                if severity != "confirmed"
            ),
            "diagnosticCount": sum(validation["diagnostic_counts"].values()),
            "reportSha256": _sha256(report_path),
        }
    if passed:
        try:
            rows, timings = _qemu_profile_rows(
                case.trigger,
                variant.identifier,
                iteration,
                profile_path,
            )
        except EvaluationError as error:
            return (
                [
                    result_row(
                        case.trigger,
                        variant.identifier,
                        "total",
                        None,
                        iteration,
                        "failed",
                        str(error),
                    )
                ],
                metadata,
                False,
            )
    else:
        timings = {}
        rows = [
            result_row(
                case.trigger,
                variant.identifier,
                "total",
                None,
                iteration,
                "failed",
                localization_error
                or f"validation status {observed!r}, expected {case.expected_validation!r}",
            )
        ]
    metadata.update(
        {
            "report": str(report_path),
            "profile": str(profile_path),
            "profileSha256": _sha256(profile_path) if passed else None,
            "profileTimings": timings,
            "reportSha256": _sha256(report_path),
            "traceMode": case.trace_mode,
            "validationProcessSeconds": total,
            "validationStatus": observed,
            "expectedValidation": case.expected_validation,
            "expectedMismatchLocalized": passed
            if case.expected_validation == "mismatch"
            else None,
        }
    )
    return rows, metadata, passed


def _expected_guest_signal(
    report: dict[str, Any],
    signal_name: str,
    fault_pc: int,
) -> bool:
    reason = report.get("terminal_reason")
    if not isinstance(reason, dict):
        return False
    if (
        reason.get("kind") != "signal"
        or reason.get("signal") != signal_name
        or reason.get("pc") != fault_pc
    ):
        return False
    validation = report.get("validation")
    entries = validation.get("entries") if isinstance(validation, dict) else None
    if not isinstance(entries, list):
        return False
    errors = [
        error
        for entry in entries
        if isinstance(entry, dict) and entry.get("pc") == fault_pc
        for error in entry.get("errors", ())
        if isinstance(error, dict)
    ]
    return any(
        error.get("severity") == "confirmed"
        and error.get("code") == "unexpected-guest-signal"
        and error.get("subject") == signal_name
        for error in errors
    )


def _is_memory_address_subject(subject: object) -> bool:
    return (
        isinstance(subject, str)
        and re.fullmatch(r"0x[0-9a-fA-F]{1,16}", subject) is not None
        and int(subject, 16) < 1 << 64
    )


def _require_trigger_mismatch_contract(
    case: EmulatorCase,
) -> tuple[str | None, int, int, str]:
    symbol = case.expected_mismatch_source_symbol
    address = case.expected_mismatch_source_address
    offset = case.expected_mismatch_source_offset if address is None else address
    length = case.expected_mismatch_length
    code = case.expected_mismatch_code
    subject = case.expected_mismatch_subject
    if (
        (address is None and (not isinstance(symbol, str) or not symbol))
        or (address is not None and symbol is not None)
        or type(offset) is not int
        or not 0 <= offset < 1 << 64
        or type(length) is not int
        or not 0 < length < 1 << 64
        or not isinstance(code, str)
        or code not in {"register-content-mismatch", "memory-content-mismatch"}
        or (
            code == "register-content-mismatch"
            and (not isinstance(subject, str) or not subject)
        )
        or (
            code == "memory-content-mismatch"
            and subject is not None
            and not _is_memory_address_subject(subject)
        )
    ):
        raise EvaluationError(
            f"QEMU trigger {case.identifier} mismatch contract is incomplete or invalid."
        )
    return symbol, offset, length, code


def _expected_trigger_mismatch(
    report: dict[str, Any], source: int, stop: int, code: str, subject: str | None
) -> bool:
    validation = report.get("validation")
    entries = validation.get("entries") if isinstance(validation, dict) else None
    if not isinstance(entries, list):
        return False
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        bounds = entry.get("transition_range")
        if (
            not isinstance(bounds, list)
            or len(bounds) != 2
            or any(type(value) is not int for value in bounds)
            or bounds != [source, stop]
        ):
            continue
        errors = entry.get("errors")
        if not isinstance(errors, list):
            continue
        for error in errors:
            if (
                not isinstance(error, dict)
                or error.get("severity") != "confirmed"
                or error.get("code") != code
            ):
                continue
            actual_subject = error.get("subject")
            if code == "register-content-mismatch" and actual_subject == subject:
                return True
            if (
                code == "memory-content-mismatch"
                and _is_memory_address_subject(actual_subject)
                and (subject is None or actual_subject == subject)
            ):
                return True
    return False


def _evaluate_qemu_trigger(
    config: EvaluationConfig,
    case: EmulatorCase,
    variant: EmulatorVariant,
    program: Path,
    input_directory: Path,
    iteration: int,
    case_directory: Path,
    *,
    skip_unmatched: bool = False,
) -> tuple[list[dict[str, str | int]], dict[str, Any], bool]:
    mismatch_contract = None
    if case.expected_validation == "mismatch" and case.expected_terminal_signal is None:
        mismatch_contract = _require_trigger_mismatch_contract(case)
    binary, oracle, _expected_status, trace_format, native_metadata = (
        _native_trigger_artifacts(
            input_directory,
            case,
            iteration,
        )
    )
    native_scope = native_metadata.get("traceMode", "legacy-witness")
    if native_scope != config.trigger_trace_mode:
        raise EvaluationError(
            "Native trigger trace scope does not match the requested evaluation mode."
        )
    mismatch_range = None
    if mismatch_contract is not None:
        symbol, offset, length, _code = mismatch_contract
        # Expectations are post-hoc assertions, never capture bounds or validator inputs.
        symbol_address = (
            0 if symbol is None else read_symbols(config.nm_program, binary).get(symbol)
        )
        if symbol_address is None:
            raise EvaluationError(
                f"QEMU trigger binary has no mismatch symbol {symbol!r}."
            )
        if type(symbol_address) is not int or not 0 <= symbol_address < 1 << 64:
            raise EvaluationError(
                "QEMU trigger mismatch symbol is not a 64-bit address."
            )
        mismatch_range = (symbol_address + offset, symbol_address + offset + length)
        if any(address >= 1 << 64 for address in mismatch_range):
            raise EvaluationError(
                "QEMU trigger mismatch range exceeds 64-bit addresses."
            )
    case_directory.mkdir(parents=True, exist_ok=True)
    qemu_log = case_directory / "qemu.log"
    validation_log = case_directory / "validation.log"
    report_path = case_directory / "validation.json"
    profile_path = case_directory / "profile.json"
    states_path = case_directory / "states.trace"
    port = _free_loopback_port()
    qemu_command = (
        str(program),
        *(("-cpu", case.qemu_cpu_model) if case.qemu_cpu_model is not None else ()),
        "-g",
        str(port),
        str(binary),
    )
    qemu = ManagedProcess(qemu_command, qemu_log)
    cutpoint_address = None
    if (
        config.trigger_trace_mode == "legacy-witness"
        and case.validation_cutpoint == "stop"
    ):
        cutpoint_address = native_metadata.get("stopAddress")
        if not isinstance(cutpoint_address, int) or isinstance(cutpoint_address, bool):
            raise EvaluationError(
                "Native trigger metadata has no valid terminal validation cutpoint."
            )
    started = time.perf_counter()
    try:
        with qemu as qemu_process:
            _wait_for_listener(qemu_process, port, "QEMU GDB server")
            validation = run_process(
                (
                    str(config.validate_qemu_program),
                    "--remote",
                    f"127.0.0.1:{port}",
                    "--symb-trace",
                    str(oracle),
                    "--trace-type",
                    trace_format,
                    "--executable",
                    str(binary),
                    "--output",
                    str(states_path),
                    "--report",
                    str(report_path),
                    "--profile-report",
                    str(profile_path),
                    "--error-level",
                    "info",
                    *(
                        ("--cutpoint-address", hex(cutpoint_address))
                        if cutpoint_address is not None
                        else ()
                    ),
                    *(("--skip-unmatched",) if skip_unmatched else ()),
                    *(
                        ("--qemu-aarch64-cpu-model", case.qemu_cpu_model)
                        if case.qemu_cpu_model is not None
                        else ()
                    ),
                )
            )
    except EvaluationError as error:
        validation_log.write_text(str(error) + "\n")
        rows = [
            result_row(
                case.trigger,
                variant.identifier,
                "validation",
                None,
                iteration,
                "failed",
                str(error),
            )
        ]
        return rows, {"error": str(error)}, False

    validation_log.write_text(validation.output)
    total = time.perf_counter() - started
    metadata: dict[str, Any] = {
        "backend": variant.backend,
        "emulator": variant.identifier,
        "emulatorVersion": variant.version,
        "binary": str(binary),
        "binarySha256": _sha256(binary),
        "oracle": str(oracle),
        "oracleSha256": _sha256(oracle),
        "native": native_metadata,
        "qemuLog": str(qemu_log),
        "states": str(states_path),
        "skipUnmatched": skip_unmatched,
        "validationCutpoint": case.validation_cutpoint,
        "validationCutpointAddress": cutpoint_address,
        "qemuCommand": list(qemu_command),
        "qemuCpuModel": case.qemu_cpu_model,
    }
    if validation.returncode != 0:
        rows = [
            result_row(
                case.trigger,
                variant.identifier,
                "validation",
                None,
                iteration,
                "failed",
                f"QEMU validation status {validation.returncode}",
            )
        ]
        return rows, metadata, False

    report = _load_json_object(report_path, "QEMU validation report")
    if report.get("schema") != "focaccia-qemu-validation-v1":
        raise EvaluationError("QEMU validator produced an unsupported report schema.")
    observed = report.get("status")
    passed = observed == case.expected_validation
    localization_error = ""
    if (
        passed
        and case.expected_validation == "accepted"
        and config.trigger_trace_mode == "whole-program"
    ):
        _require_whole_program_completion(report)
    if (
        passed
        and case.expected_validation == "accepted"
        and config.trigger_trace_mode == "legacy-witness"
    ):
        _require_complete_terminal_trace(report)
    if passed and mismatch_contract is not None and mismatch_range is not None:
        passed = _expected_trigger_mismatch(
            report,
            *mismatch_range,
            mismatch_contract[3],
            case.expected_mismatch_subject,
        )
        if not passed:
            localization_error = (
                f"expected confirmed {mismatch_contract[3]} for "
                f"{case.expected_mismatch_subject or 'a memory address'} at "
                f"{mismatch_range[0]:#x} -> {mismatch_range[1]:#x} was absent"
            )
    if passed and case.expected_terminal_signal is not None:
        fault_symbol = case.expected_fault_symbol
        if fault_symbol is None:
            raise EvaluationError("QEMU signal contract has no fault symbol.")
        fault_address = read_symbols(config.nm_program, binary).get(fault_symbol)
        if fault_address is None:
            raise EvaluationError(
                f"QEMU trigger binary has no fault symbol {fault_symbol!r}."
            )
        passed = _expected_guest_signal(
            report,
            case.expected_terminal_signal,
            fault_address,
        )
        if not passed:
            localization_error = (
                f"expected {case.expected_terminal_signal} at "
                f"{fault_symbol} ({fault_address:#x}) was absent"
            )
    if (
        passed
        and config.trigger_trace_mode == "whole-program"
        and case.expected_validation == "mismatch"
    ):
        execution_evidence = require_whole_program_experiment_execution(
            report,
            expected_bug_localized=True,
            expected_terminal_signal_localized=case.expected_terminal_signal
            is not None,
        )
        execution_evidence["reportSha256"] = _sha256(report_path)
        metadata["experimentExecutionEvidence"] = execution_evidence
    if passed:
        try:
            rows, timings = _qemu_profile_rows(
                case.trigger,
                variant.identifier,
                iteration,
                profile_path,
            )
        except EvaluationError as error:
            return (
                [
                    result_row(
                        case.trigger,
                        variant.identifier,
                        "total",
                        None,
                        iteration,
                        "failed",
                        str(error),
                    )
                ],
                metadata,
                False,
            )
    else:
        timings = {}
        rows = [
            result_row(
                case.trigger,
                variant.identifier,
                "total",
                None,
                iteration,
                "failed",
                localization_error
                or f"validation status {observed!r}, expected {case.expected_validation!r}",
            )
        ]
    metadata.update(
        {
            "report": str(report_path),
            "profile": str(profile_path),
            "profileSha256": _sha256(profile_path) if passed else None,
            "profileTimings": timings,
            "validationProcessSeconds": total,
            "validationStatus": observed,
            "expectedValidation": case.expected_validation,
            "expectedMismatchLocalized": passed
            if mismatch_contract is not None
            else None,
            "expectedMismatchRange": list(mismatch_range)
            if mismatch_range is not None
            else None,
            "expectedMismatchCode": case.expected_mismatch_code,
            "expectedMismatchSubject": case.expected_mismatch_subject,
            "expectedTerminalSignal": case.expected_terminal_signal,
            "expectedFaultSymbol": case.expected_fault_symbol,
            "expectedTerminalLocalized": (
                passed if case.expected_terminal_signal is not None else None
            ),
        }
    )
    return rows, metadata, passed


def _evaluate_qemu_plugin_trigger(
    config: EvaluationConfig,
    case: EmulatorCase,
    variant: EmulatorVariant,
    program: Path,
    input_directory: Path,
    iteration: int,
    case_directory: Path,
) -> tuple[list[dict[str, str | int]], dict[str, Any], bool]:
    binary, oracle, _expected_status, trace_format, native_metadata = (
        _native_trigger_artifacts(input_directory, case, iteration)
    )
    symbols = read_symbols(config.nm_program, binary)
    start_address = None
    stop_address = None
    if config.trigger_trace_mode == "legacy-witness":
        start_address = symbols.get("focaccia_trace_start")
        stop_address = symbols.get("focaccia_trace_stop")
        if (
            start_address is None
            or stop_address is None
            or start_address >= stop_address
        ):
            raise EvaluationError(
                "QEMU plugin trigger has invalid trace symbol bounds."
            )
        if native_metadata.get("startAddress") != start_address or (
            native_metadata.get("stopAddress") != stop_address
        ):
            raise EvaluationError(
                "Native trigger metadata does not match current symbol bounds."
            )

    mismatch_symbol = case.expected_mismatch_source_symbol
    mismatch_subject = case.expected_mismatch_subject
    mismatch_address = None
    if case.expected_validation == "mismatch":
        if mismatch_symbol is None or mismatch_subject is None:
            raise EvaluationError("QEMU plugin mismatch contract is incomplete.")
        mismatch_address = symbols.get(mismatch_symbol)
        if mismatch_address is None:
            raise EvaluationError(
                f"QEMU trigger binary has no mismatch symbol {mismatch_symbol!r}."
            )

    case_directory.mkdir(parents=True, exist_ok=True)
    qemu_log = case_directory / "qemu.log"
    validation_log = case_directory / "validation.log"
    report_path = case_directory / "validation.json"
    profile_path = case_directory / "profile.json"
    states_path = case_directory / "states.trace"
    terminal_ready_path = case_directory / "plugin-terminal-ready.json"
    terminal_evidence_path = case_directory / "plugin-terminal-evidence.json"
    socket_directory = Path(os.environ.get("TMPDIR", "/tmp"))
    socket_name = hashlib.sha256(str(case_directory).encode()).hexdigest()[:16]
    socket_path = socket_directory / f"focaccia-{socket_name}.sock"
    if len(os.fsencode(socket_path)) >= 104:
        raise EvaluationError(
            "QEMU plugin socket path exceeds the portable Unix limit."
        )
    plugin_path = variant.output / "lib/plugins/libfocaccia.so"
    if not plugin_path.is_file():
        raise EvaluationError(
            f"Emulator {variant.identifier} lacks plugin {plugin_path}."
        )

    validator = ManagedProcess(
        (
            str(config.validate_qemu_program),
            "--use-socket",
            str(socket_path),
            "--guest-arch",
            "aarch64l" if case.guest_system == "aarch64-linux" else "x86_64",
            "--symb-trace",
            str(oracle),
            "--trace-type",
            trace_format,
            "--output",
            str(states_path),
            "--report",
            str(report_path),
            "--profile-report",
            str(profile_path),
            "--error-level",
            "info",
            "--plugin-terminal-ready",
            str(terminal_ready_path),
            "--plugin-terminal-evidence",
            str(terminal_evidence_path),
            "--quiet",
        ),
        validation_log,
    )
    plugin_options = f"{plugin_path},socket={socket_path}"
    if start_address is not None and stop_address is not None:
        plugin_options += f",start={start_address:#x},stop={stop_address:#x}"
    qemu_command = (
        str(program),
        "-plugin",
        plugin_options,
        str(binary),
    )

    started = time.perf_counter()
    try:
        for stale_path in (socket_path, terminal_ready_path, terminal_evidence_path):
            try:
                stale_path.unlink()
            except FileNotFoundError:
                pass
        with validator as validator_process:
            deadline = time.monotonic() + SERVER_STARTUP_TIMEOUT_SECONDS
            while not socket_path.is_socket():
                if validator_process.poll() is not None:
                    raise EvaluationError(
                        f"QEMU plugin validator exited with status "
                        f"{validator_process.returncode} before listening."
                    )
                if time.monotonic() >= deadline:
                    raise EvaluationError(
                        "Timed out waiting for QEMU plugin validator."
                    )
                time.sleep(0.05)

            qemu = ManagedProcess(qemu_command, qemu_log)
            with qemu as qemu_process:
                terminal_deadline = time.monotonic() + PROCESS_TIMEOUT_SECONDS
                while not terminal_ready_path.is_file():
                    if validator_process.poll() is not None:
                        raise EvaluationError(
                            f"QEMU plugin validator exited with status "
                            f"{validator_process.returncode} before terminal readiness."
                        )
                    if qemu_process.poll() is not None:
                        raise EvaluationError(
                            f"QEMU guest exited with status {qemu_process.returncode} "
                            "before terminal readiness."
                        )
                    if time.monotonic() >= terminal_deadline:
                        raise EvaluationError(
                            "Timed out waiting for bound plugin terminal readiness."
                        )
                    time.sleep(0.05)
                try:
                    ready = json.loads(terminal_ready_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as error:
                    raise EvaluationError(
                        "Malformed plugin terminal readiness record."
                    ) from error
                if (
                    not isinstance(ready, dict)
                    or ready.get("schema") != "focaccia-plugin-terminal-ready-v1"
                    or ready.get("pid") != qemu_process.pid
                    or ready.get("binarySha256") != _sha256(binary)
                ):
                    raise EvaluationError(
                        "Plugin terminal readiness does not bind the launched guest process and binary."
                    )
                try:
                    guest_status = qemu_process.wait(timeout=5)
                except subprocess.TimeoutExpired as error:
                    raise EvaluationError(
                        "QEMU guest did not exit after plugin terminal release."
                    ) from error
                command_digest = hashlib.sha256(
                    json.dumps(qemu_command, separators=(",", ":")).encode("utf-8")
                ).hexdigest()
                evidence = {
                    "schema": "focaccia-plugin-terminal-evidence-v1",
                    "nonce": ready.get("nonce"),
                    "pid": qemu_process.pid,
                    "binarySha256": _sha256(binary),
                    "commandSha256": command_digest,
                    "returncode": guest_status,
                }
                evidence_temporary = terminal_evidence_path.with_name(
                    f".{terminal_evidence_path.name}.tmp"
                )
                evidence_temporary.write_text(
                    json.dumps(evidence, sort_keys=True) + "\n", encoding="utf-8"
                )
                evidence_temporary.replace(terminal_evidence_path)
                try:
                    validator_status = validator_process.wait(timeout=5)
                except subprocess.TimeoutExpired as error:
                    raise EvaluationError(
                        "QEMU plugin validator did not consume terminal evidence."
                    ) from error
    except EvaluationError as error:
        rows = [
            result_row(
                case.trigger,
                variant.identifier,
                "validation",
                None,
                iteration,
                "failed",
                str(error),
            )
        ]
        return rows, {"error": str(error)}, False
    finally:
        try:
            socket_path.unlink()
        except FileNotFoundError:
            pass

    total = time.perf_counter() - started
    metadata: dict[str, Any] = {
        "backend": variant.backend,
        "emulator": variant.identifier,
        "emulatorVersion": variant.version,
        "binary": str(binary),
        "binarySha256": _sha256(binary),
        "oracle": str(oracle),
        "oracleSha256": _sha256(oracle),
        "native": native_metadata,
        "qemuLog": str(qemu_log),
        "states": str(states_path),
        "plugin": str(plugin_path),
        "startAddress": start_address,
        "stopAddress": stop_address,
        "pluginTerminalReady": str(terminal_ready_path),
        "pluginTerminalReadySha256": _sha256(terminal_ready_path),
        "pluginTerminalEvidence": str(terminal_evidence_path),
        "pluginTerminalEvidenceSha256": _sha256(terminal_evidence_path),
    }
    if validator_status != 0 or guest_status not in {0, 1}:
        detail = (
            f"plugin validator status {validator_status}, guest status {guest_status}"
        )
        rows = [
            result_row(
                case.trigger,
                variant.identifier,
                "validation",
                None,
                iteration,
                "failed",
                detail,
            )
        ]
        return rows, metadata, False

    report = _load_json_object(report_path, "QEMU plugin validation report")
    if report.get("schema") != "focaccia-qemu-validation-v1":
        raise EvaluationError(
            "QEMU plugin validator produced an unsupported report schema."
        )
    if case.expected_validation == "mismatch":
        _require_plugin_terminal_provenance(report)
    else:
        _require_whole_program_completion(report)
    observed = report.get("status")
    localized = None
    if mismatch_address is not None and mismatch_subject is not None:
        localized = _expected_register_mismatch(
            report, mismatch_address, mismatch_address + 4, mismatch_subject
        )
    expected_guest_status = 1 if case.expected_validation == "mismatch" else 0
    passed = (
        observed == case.expected_validation
        and guest_status == expected_guest_status
        and (localized if case.expected_validation == "mismatch" else True)
    )
    if passed:
        try:
            rows, timings = _qemu_profile_rows(
                case.trigger,
                variant.identifier,
                iteration,
                profile_path,
            )
        except EvaluationError as error:
            return (
                [
                    result_row(
                        case.trigger,
                        variant.identifier,
                        "total",
                        None,
                        iteration,
                        "failed",
                        str(error),
                    )
                ],
                metadata,
                False,
            )
    else:
        timings = {}
        rows = [
            result_row(
                case.trigger,
                variant.identifier,
                "total",
                None,
                iteration,
                "failed",
                (
                    f"validation status {observed!r}, guest status "
                    f"{guest_status}, localized={localized}"
                ),
            )
        ]
    metadata.update(
        {
            "report": str(report_path),
            "profile": str(profile_path),
            "profileSha256": _sha256(profile_path) if passed else None,
            "profileTimings": timings,
            "validationProcessSeconds": total,
            "validationStatus": observed,
            "expectedValidation": case.expected_validation,
            "expectedMismatchSourceSymbol": mismatch_symbol,
            "expectedMismatchSubject": mismatch_subject,
            "expectedMismatchLocalized": localized,
            "guestStatus": guest_status,
        }
    )
    return rows, metadata, passed


def _evaluate_log_trigger(
    config: EvaluationConfig,
    case: EmulatorCase,
    variant: EmulatorVariant,
    program: Path,
    input_directory: Path,
    iteration: int,
    case_directory: Path,
) -> tuple[list[dict[str, str | int]], dict[str, Any], bool]:
    if config.trigger_trace_mode not in {"legacy-witness", "whole-program"}:
        raise EvaluationError(
            "Text-log backend received an unsupported trigger trace mode."
        )
    binary, oracle, expected_status, trace_format, native_metadata = (
        _native_trigger_artifacts(
            input_directory,
            case,
            iteration,
        )
    )
    case_directory.mkdir(parents=True, exist_ok=True)
    log_backend = variant.backend.removesuffix("-log")
    raw_log = case_directory / f"{log_backend}.log"
    report_path = case_directory / "validation.json"

    environment = os.environ.copy()
    if log_backend == "box64":
        if config.trigger_trace_mode == "whole-program":
            trace_selector = "1"
        else:
            start_address = native_metadata.get("startAddress")
            stop_address = native_metadata.get("stopAddress")
            if (
                not isinstance(start_address, int)
                or isinstance(start_address, bool)
                or not isinstance(stop_address, int)
                or isinstance(stop_address, bool)
                or stop_address < start_address
            ):
                raise EvaluationError(
                    "Native trigger metadata has invalid trace bounds."
                )
            trace_selector = f"0x{start_address:x}-0x{stop_address + 1:x}"
        environment.update(
            {
                "BOX64_TRACE": trace_selector,
                "BOX64_TRACE_FILE": "stderr",
                "BOX64_DYNAREC_TRACE": "1",
                "BOX64_DYNAREC_DF": "0",
            }
        )
    execution = run_process((str(program), str(binary)), env=environment)
    raw_log.write_text(execution.output)
    execution_evidence = case_directory / "execution-evidence.json"
    execution_evidence.write_text(
        json.dumps(
            {
                "schema": "focaccia-text-process-evidence-v1",
                "runId": str(uuid.uuid4()),
                "binary": str(binary.resolve()),
                "binarySha256": _sha256(binary),
                "oracleSha256": _sha256(oracle),
                "logSha256": _sha256(raw_log),
                "processState": "exited",
                "exitStatus": execution.returncode,
                "expectedExitStatus": expected_status,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    rows = [
        result_row(
            case.trigger,
            variant.identifier,
            "execution",
            execution.elapsed if execution.returncode == expected_status else None,
            iteration,
            "passed" if execution.returncode == expected_status else "failed",
            ""
            if execution.returncode == expected_status
            else f"emulator status {execution.returncode}, expected {expected_status}",
        )
    ]
    metadata: dict[str, Any] = {
        "backend": variant.backend,
        "emulator": variant.identifier,
        "emulatorVersion": variant.version,
        "binary": str(binary),
        "binarySha256": _sha256(binary),
        "oracle": str(oracle),
        "oracleSha256": _sha256(oracle),
        "native": native_metadata,
        "rawLog": str(raw_log),
    }
    if execution.returncode != expected_status:
        return rows, metadata, False

    validation = run_process(
        (
            str(config.offline_validator_program),
            "--backend",
            log_backend,
            "--oracle",
            str(oracle),
            "--trace-type",
            trace_format,
            "--log",
            str(raw_log),
            "--report",
            str(report_path),
            "--execution-evidence",
            str(execution_evidence),
        )
    )
    (case_directory / "validation.log").write_text(validation.output)
    if validation.returncode != 0:
        rows.append(
            result_row(
                case.trigger,
                variant.identifier,
                "validation",
                None,
                iteration,
                "failed",
                f"offline validation status {validation.returncode}",
            )
        )
        return rows, metadata, False

    report = _load_json_object(report_path, "offline validation report")
    if report.get("schema") != OFFLINE_REPORT_SCHEMA:
        raise EvaluationError(
            "Offline validator produced an unsupported report schema."
        )
    observed = report.get("status")
    completion = report.get("completion")
    execution_complete = (
        isinstance(completion, dict) and completion.get("executionComplete") is True
    )
    passed = observed == case.expected_validation and (
        config.trigger_trace_mode != "whole-program" or execution_complete
    )
    rows.append(
        result_row(
            case.trigger,
            variant.identifier,
            "validation",
            validation.elapsed if passed else None,
            iteration,
            "passed" if passed else "failed",
            ""
            if passed
            else f"validation status {observed!r}, expected {case.expected_validation!r}",
        )
    )
    metadata.update(
        {
            "report": str(report_path),
            "validationStatus": observed,
            "expectedValidation": case.expected_validation,
            "executionEvidence": str(execution_evidence),
            "executionEvidenceSha256": _sha256(execution_evidence),
            "executionComplete": execution_complete,
        }
    )
    return rows, metadata, passed


def run_emulated(
    config: EvaluationConfig,
    input_directory: Path,
    requested_cases: Sequence[str],
    requested_emulators: Sequence[str],
    iterations: int,
    *,
    skip_unmatched: bool = False,
) -> int:
    input_directory = input_directory.resolve()
    actual_machine = normalize_machine(platform.machine())
    configured_machine = expected_machine(config.system)
    if actual_machine != configured_machine:
        raise EvaluationError(
            f"Evaluation configuration is for {configured_machine}, but runtime host is "
            f"{actual_machine}."
        )
    if not input_directory.is_dir():
        raise EvaluationError(f"Evaluation input does not exist: {input_directory}.")

    selected = _select_emulator_cases(
        config,
        requested_cases,
        requested_emulators,
    )
    if skip_unmatched and any(
        case.kind != "application"
        or config.emulators[case.emulator].backend != "qemu-gdb"
        for case in selected
    ):
        raise EvaluationError(
            "--skip-unmatched is supported only for QEMU application cases."
        )
    variants = {case.emulator: config.emulators[case.emulator] for case in selected}
    emulator_outputs = {
        identifier: _emulator_output(variant)
        for identifier, variant in variants.items()
    }

    system_directory = input_directory / "emulated" / config.role / config.system
    created_at = datetime.now(UTC).isoformat()
    rows: list[dict[str, str | int]] = []
    cases: dict[str, Any] = {}
    if system_directory.exists():
        previous = _load_json_object(
            system_directory / "metadata.json", "existing emulated metadata"
        )
        expected = {
            "schema": EMULATED_SCHEMA,
            "system": config.system,
            "machine": actual_machine,
            "role": config.role,
            "iterations": iterations,
            "skipUnmatched": skip_unmatched,
        }
        if any(previous.get(name) != value for name, value in expected.items()):
            raise EvaluationError(
                "Existing emulated evaluation metadata is incompatible with this run."
            )
        previous_cases = previous.get("cases")
        if not isinstance(previous_cases, dict) or not all(
            isinstance(identifier, str)
            and isinstance(case, dict)
            and (
                case.get("benchmark") is None or isinstance(case.get("benchmark"), str)
            )
            and case.get("kind") in {"trigger", "application"}
            and case.get("status") in {"passed", "failed"}
            for identifier, case in previous_cases.items()
        ):
            raise EvaluationError("Existing emulated evaluation cases are malformed.")
        duplicates = sorted(
            {case.identifier for case in selected} & set(previous_cases)
        )
        if duplicates:
            raise EvaluationError(
                "Emulated cases already exist; archive before rerunning: "
                + ", ".join(duplicates)
                + "."
            )
        registered_benchmarks = {
            case.get("benchmark") for case in previous_cases.values()
        }
        previous_rows = _read_results(system_directory / "results.csv")
        if None not in registered_benchmarks and any(
            row.get("benchmark") not in registered_benchmarks for row in previous_rows
        ):
            raise EvaluationError(
                "Existing emulated results contain an unregistered benchmark."
            )
        encoded_created_at = previous.get("createdAt")
        if not isinstance(encoded_created_at, str):
            raise EvaluationError("Existing emulated metadata has no creation time.")
        cases.update(previous_cases)
        rows.extend(previous_rows)
        created_at = encoded_created_at
    else:
        system_directory.mkdir(parents=True)
    for case in selected:
        variant = variants[case.emulator]
        case_root = (
            system_directory / variant.backend / variant.identifier / case.trigger
        )
        if case_root.exists():
            raise EvaluationError(
                f"Unregistered emulated case artifacts already exist: {case_root}."
            )

    all_passed = all(
        isinstance(case, dict) and case.get("status") == "passed"
        for case in cases.values()
    )
    invocation_passed = True
    for case in selected:
        print(
            f"[{config.system}] emulated {case.kind} {case.trigger} "
            f"with {case.emulator}",
            flush=True,
        )
        variant = variants[case.emulator]
        case_metadata: dict[str, Any] = {"iterations": []}
        case_passed = True
        for iteration in range(iterations):
            case_directory = (
                system_directory
                / variant.backend
                / variant.identifier
                / case.trigger
                / str(iteration)
            )
            try:
                program = emulator_outputs[case.emulator] / case.program
                if not program.is_file() or not os.access(program, os.X_OK):
                    raise EvaluationError(
                        f"Emulator {variant.identifier} lacks executable {case.program}."
                    )
                if variant.backend == "qemu-gdb" and case.kind == "application":
                    iteration_rows, iteration_metadata, passed = (
                        _evaluate_qemu_application(
                            config,
                            case,
                            variant,
                            program,
                            input_directory,
                            iteration,
                            case_directory,
                            skip_unmatched=skip_unmatched,
                        )
                    )
                elif variant.backend == "qemu-gdb":
                    iteration_rows, iteration_metadata, passed = _evaluate_qemu_trigger(
                        config,
                        case,
                        variant,
                        program,
                        input_directory,
                        iteration,
                        case_directory,
                        skip_unmatched=skip_unmatched,
                    )
                elif variant.backend == "qemu-plugin" and case.kind == "trigger":
                    iteration_rows, iteration_metadata, passed = (
                        _evaluate_qemu_plugin_trigger(
                            config,
                            case,
                            variant,
                            program,
                            input_directory,
                            iteration,
                            case_directory,
                        )
                    )
                elif variant.backend.endswith("-log"):
                    iteration_rows, iteration_metadata, passed = _evaluate_log_trigger(
                        config,
                        case,
                        variant,
                        program,
                        input_directory,
                        iteration,
                        case_directory,
                    )
                else:
                    raise EvaluationError(
                        f"Emulator backend {variant.backend} is not implemented yet."
                    )
            except EvaluationError as error:
                iteration_rows = [
                    result_row(
                        case.trigger,
                        variant.identifier,
                        "setup",
                        None,
                        iteration,
                        "failed",
                        str(error),
                    )
                ]
                iteration_metadata = {"error": str(error)}
                passed = False
            rows.extend(iteration_rows)
            case_metadata["iterations"].append(iteration_metadata)
            case_passed &= passed
        case_metadata.update(
            {
                "kind": case.kind,
                "benchmark": case.trigger,
                "backend": variant.backend,
                "emulator": variant.identifier,
                "status": "passed" if case_passed else "failed",
            }
        )
        cases[case.identifier] = case_metadata
        all_passed &= case_passed
        invocation_passed &= case_passed

    write_results(system_directory / "results.csv", rows)
    metadata = {
        "schema": EMULATED_SCHEMA,
        "system": config.system,
        "machine": actual_machine,
        "role": config.role,
        "createdAt": created_at,
        "updatedAt": datetime.now(UTC).isoformat(),
        "iterations": iterations,
        "cases": cases,
        "skipUnmatched": skip_unmatched,
        "status": "passed" if all_passed else "failed",
    }
    _write_metadata(system_directory / "metadata.json", metadata)
    return 0 if invocation_passed else 1


def make_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evaluation",
        description="Collect Focaccia evaluation measurements for the configured role.",
    )
    parser.add_argument("--config", type=Path, required=True, help=argparse.SUPPRESS)
    parser.add_argument("--output", type=Path, help="shared native output directory")
    parser.add_argument("--input", type=Path, help="shared native oracle directory")
    parser.add_argument(
        "--case",
        action="append",
        default=[],
        help="run one trigger ID or application name (repeatable)",
    )
    parser.add_argument(
        "--emulator",
        action="append",
        default=[],
        help="select an emulator variant, family, or backend (repeatable)",
    )
    parser.add_argument(
        "--iterations", type=int, default=1, help="measurement iterations"
    )
    parser.add_argument(
        "--skip-unmatched",
        action="store_true",
        help=(
            "for QEMU applications, skip unmatched symbolic ranges as explicit "
            "incomplete gaps (default: off)"
        ),
    )
    parser.add_argument(
        "--trace-format",
        choices=("msgpack", "json"),
        default="msgpack",
        help="native oracle persistence format (default: msgpack)",
    )
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parser = make_argument_parser()
    args = parser.parse_args(arguments)
    try:
        config = load_config(args.config)
        if args.iterations < 1:
            raise EvaluationError("--iterations must be at least one.")
        if config.role == "native":
            if args.output is None or args.input is not None:
                raise EvaluationError(
                    "Native evaluation requires --output and does not accept --input."
                )
            if args.emulator:
                raise EvaluationError("--emulator is not valid for native evaluation.")
            if args.skip_unmatched:
                raise EvaluationError(
                    "--skip-unmatched is not valid for native evaluation."
                )
            return run_native(
                config,
                args.output,
                args.case,
                args.iterations,
                args.trace_format,
            )
        if args.input is None or args.output is not None:
            raise EvaluationError(
                "Emulator evaluation requires --input and does not accept --output."
            )
        if args.trace_format != "msgpack":
            raise EvaluationError(
                "--trace-format is only configurable for native evaluation."
            )
        return run_emulated(
            config,
            args.input,
            args.case,
            args.emulator,
            args.iterations,
            skip_unmatched=args.skip_unmatched,
        )
    except EvaluationError as error:
        print(f"evaluation: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
