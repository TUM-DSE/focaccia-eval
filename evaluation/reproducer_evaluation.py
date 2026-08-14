#!/usr/bin/env python3

"""Generate and verify the eight x86-64 reproducers measured in Figure 8."""

from __future__ import annotations

import argparse
import io
import json
import platform
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from struct import Struct
from typing import Any

import msgpack
from focaccia.persistence import (
    MSGPACK_MAGIC,
    parse_snapshots,
    parse_transformations,
    serialize_transformations,
    stream_transformation,
)
from focaccia.reproducer import (
    EntryPrefix,
    Reproducer,
    extract_executable_fragment,
    single_transition_reproducer_trace,
)
from focaccia.snapshot import ProgramState
from focaccia.symbolic import SymbolicTransform

import evaluation as common


CONFIG_SCHEMA = "focaccia-reproducer-evaluation-config-v1"
METADATA_SCHEMA = "focaccia-reproducer-evaluation-v1"
SIZE_EVIDENCE_SCHEMA = "focaccia-reproducer-size-evidence-v1"
QEMU_REPORT_SCHEMA = "focaccia-qemu-validation-v1"
SOURCE_METADATA_SCHEMA = "focaccia-emulated-evaluation-v1"
EXPECTED_SYSTEM = "aarch64-linux"
GUEST_SYSTEM = "x86_64-linux"
HEX_DIGITS = frozenset("0123456789abcdef")
_FRAME_LENGTH = Struct(">Q")


class ReproducerEvaluationError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ErrorSignature:
    code: str
    subject: str


@dataclass(frozen=True, slots=True)
class MismatchContract:
    source: int
    destination: int
    signatures: tuple[ErrorSignature, ...]

    @property
    def transition_range(self) -> tuple[int, int]:
        return (self.source, self.destination)


@dataclass(frozen=True, slots=True)
class CaseConfig:
    identifier: str
    source_case: str
    buggy_emulator: str
    buggy_version: str
    buggy_program: Path
    reference_kind: str
    reference_emulator: str
    reference_version: str
    reference_program: Path | None
    primary_error: ErrorSignature
    source_symbol: str | None
    entry_prefix_symbol: str | None
    condition_code_seed: int | None


@dataclass(frozen=True, slots=True)
class Config:
    system: str
    focaccia_revision: str
    compiler: Path
    nm: Path
    validate_qemu: Path
    cases: tuple[CaseConfig, ...]


@dataclass(frozen=True, slots=True)
class SourceArtifacts:
    binary: Path
    oracle: Path
    states: Path
    report: Path
    trace_format: str
    metadata: dict[str, Any]


def _required_string(document: dict[str, Any], name: str, context: str) -> str:
    value = document.get(name)
    if not isinstance(value, str) or not value:
        raise ReproducerEvaluationError(f"{context} has invalid {name}.")
    return value


def _required_path(document: dict[str, Any], name: str, context: str) -> Path:
    return Path(_required_string(document, name, context))


def _parse_error_signature(document: object, context: str) -> ErrorSignature:
    if not isinstance(document, dict):
        raise ReproducerEvaluationError(f"{context} must be an object.")
    return ErrorSignature(
        _required_string(document, "code", context),
        _required_string(document, "subject", context),
    )


def load_config(path: Path) -> Config:
    document = common._load_json_object(path, "reproducer evaluation config")
    if document.get("schema") != CONFIG_SCHEMA:
        raise ReproducerEvaluationError(
            "Unsupported reproducer evaluation config schema."
        )
    system = _required_string(document, "system", "Reproducer config")
    if system != EXPECTED_SYSTEM:
        raise ReproducerEvaluationError(
            f"Reproducer evaluation is supported only on {EXPECTED_SYSTEM}, not {system}."
        )
    revision = _required_string(document, "focacciaRevision", "Reproducer config")
    if len(revision) != 40 or any(
        character not in HEX_DIGITS for character in revision
    ):
        raise ReproducerEvaluationError(
            "Reproducer config has an invalid Focaccia revision."
        )

    encoded_cases = document.get("cases")
    if not isinstance(encoded_cases, dict) or not encoded_cases:
        raise ReproducerEvaluationError("Reproducer config has no cases.")
    cases: list[CaseConfig] = []
    for identifier, encoded in encoded_cases.items():
        context = f"Reproducer case {identifier!r}"
        if not isinstance(identifier, str) or not isinstance(encoded, dict):
            raise ReproducerEvaluationError(
                "Reproducer config contains a malformed case."
            )
        source_symbol = encoded.get("sourceSymbol")
        entry_prefix_symbol = encoded.get("entryPrefixSymbol")
        condition_code_seed = encoded.get("conditionCodeSeed")
        reference_kind = encoded.get("referenceKind", "qemu")
        if reference_kind not in {"qemu", "native-oracle"}:
            raise ReproducerEvaluationError(f"{context} has invalid referenceKind.")
        reference_program = encoded.get("referenceProgram")
        if reference_kind == "qemu":
            if not isinstance(reference_program, str) or not reference_program:
                raise ReproducerEvaluationError(
                    f"{context} has invalid referenceProgram."
                )
            parsed_reference_program: Path | None = Path(reference_program)
        else:
            if reference_program is not None:
                raise ReproducerEvaluationError(
                    f"{context} native-oracle control cannot name referenceProgram."
                )
            parsed_reference_program = None
        if source_symbol is not None and not isinstance(source_symbol, str):
            raise ReproducerEvaluationError(f"{context} has invalid sourceSymbol.")
        if entry_prefix_symbol is not None and not isinstance(entry_prefix_symbol, str):
            raise ReproducerEvaluationError(f"{context} has invalid entryPrefixSymbol.")
        if condition_code_seed is not None and (
            not isinstance(condition_code_seed, int)
            or isinstance(condition_code_seed, bool)
            or not 0 <= condition_code_seed <= 0x7FFFFFFF
        ):
            raise ReproducerEvaluationError(f"{context} has invalid conditionCodeSeed.")
        cases.append(
            CaseConfig(
                identifier=identifier,
                source_case=_required_string(encoded, "sourceCase", context),
                buggy_emulator=_required_string(encoded, "buggyEmulator", context),
                buggy_version=_required_string(encoded, "buggyVersion", context),
                buggy_program=_required_path(encoded, "buggyProgram", context),
                reference_kind=reference_kind,
                reference_emulator=_required_string(
                    encoded, "referenceEmulator", context
                ),
                reference_version=_required_string(
                    encoded, "referenceVersion", context
                ),
                reference_program=parsed_reference_program,
                primary_error=_parse_error_signature(
                    encoded.get("primaryError"), f"{context} primaryError"
                ),
                source_symbol=source_symbol,
                entry_prefix_symbol=entry_prefix_symbol,
                condition_code_seed=condition_code_seed,
            )
        )

    expected_cases = {"1370", "1371", "1372", "1374", "1376", "1377", "2175", "sqlite"}
    actual_cases = {case.identifier for case in cases}
    if actual_cases != expected_cases:
        raise ReproducerEvaluationError(
            "Reproducer config must contain exactly the Figure 8 cases: "
            f"expected {sorted(expected_cases)}, got {sorted(actual_cases)}."
        )

    return Config(
        system=system,
        focaccia_revision=revision,
        compiler=_required_path(document, "compilerProgram", "Reproducer config"),
        nm=_required_path(document, "nmProgram", "Reproducer config"),
        validate_qemu=_required_path(
            document, "validateQemuProgram", "Reproducer config"
        ),
        cases=tuple(sorted(cases, key=lambda case: case.identifier)),
    )


def _require_contained_file(path: Path, root: Path, context: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ReproducerEvaluationError(
            f"Unable to resolve {context} {path}: {error}"
        ) from error
    if not resolved.is_file():
        raise ReproducerEvaluationError(f"{context} is not a file: {resolved}.")
    if not resolved.is_relative_to(root):
        raise ReproducerEvaluationError(
            f"{context} escapes the selected evaluation root: {resolved}."
        )
    return resolved


def load_source_artifacts(input_root: Path, case: CaseConfig) -> SourceArtifacts:
    emulated_root = input_root / "emulated" / "qemu" / EXPECTED_SYSTEM
    metadata = common._load_json_object(
        emulated_root / "metadata.json", "QEMU evaluator metadata"
    )
    if metadata.get("schema") != SOURCE_METADATA_SCHEMA:
        raise ReproducerEvaluationError(
            "QEMU evaluator metadata has an unsupported schema."
        )
    encoded_cases = metadata.get("cases")
    encoded_case = (
        encoded_cases.get(case.source_case) if isinstance(encoded_cases, dict) else None
    )
    if not isinstance(encoded_case, dict) or encoded_case.get("status") != "passed":
        raise ReproducerEvaluationError(
            f"Source QEMU case {case.source_case} is absent or did not pass."
        )
    iterations = encoded_case.get("iterations")
    if (
        not isinstance(iterations, list)
        or not iterations
        or not isinstance(iterations[0], dict)
    ):
        raise ReproducerEvaluationError(
            f"Source QEMU case {case.source_case} has no successful first iteration."
        )
    item = iterations[0]
    root = input_root.resolve(strict=True)
    paths = {
        name: _require_contained_file(
            Path(_required_string(item, name, f"Source case {case.source_case}")),
            root,
            f"source {name}",
        )
        for name in ("binary", "oracle", "states", "report")
    }
    for name, metadata_name in (("binary", "binarySha256"), ("oracle", "oracleSha256")):
        expected_hash = _required_string(
            item, metadata_name, f"Source case {case.source_case}"
        )
        if common._sha256(paths[name]) != expected_hash:
            raise ReproducerEvaluationError(
                f"Source {name} hash does not match QEMU metadata for {case.source_case}."
            )

    native = item.get("native")
    if not isinstance(native, dict):
        raise ReproducerEvaluationError(
            f"Source case {case.source_case} has no native artifact metadata."
        )
    trace_format = native.get("traceFormat", "json")
    if trace_format not in {"json", "msgpack"}:
        raise ReproducerEvaluationError(
            f"Source case {case.source_case} has invalid trace format {trace_format!r}."
        )
    report = common._load_json_object(paths["report"], "source validation report")
    if report.get("schema") != QEMU_REPORT_SCHEMA or report.get("status") != "mismatch":
        raise ReproducerEvaluationError(
            f"Source validation report for {case.source_case} is not a mismatch report."
        )
    return SourceArtifacts(
        binary=paths["binary"],
        oracle=paths["oracle"],
        states=paths["states"],
        report=paths["report"],
        trace_format=trace_format,
        metadata=item,
    )


def _confirmed_signatures(entry: dict[str, Any]) -> tuple[ErrorSignature, ...]:
    errors = entry.get("errors")
    if not isinstance(errors, list):
        return ()
    signatures = {
        ErrorSignature(error["code"], error["subject"])
        for error in errors
        if isinstance(error, dict)
        and error.get("severity") == "confirmed"
        and isinstance(error.get("code"), str)
        and isinstance(error.get("subject"), str)
    }
    return tuple(
        sorted(signatures, key=lambda signature: (signature.code, signature.subject))
    )


def select_mismatch_contract(
    report: dict[str, Any],
    primary: ErrorSignature,
    *,
    source_address: int | None = None,
) -> MismatchContract:
    validation = report.get("validation")
    entries = validation.get("entries") if isinstance(validation, dict) else None
    if not isinstance(entries, list):
        raise ReproducerEvaluationError("Validation report has no mismatch entries.")

    contracts: set[MismatchContract] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        transition_range = entry.get("transition_range")
        if (
            not isinstance(transition_range, list)
            or len(transition_range) != 2
            or any(
                not isinstance(address, int) or isinstance(address, bool)
                for address in transition_range
            )
        ):
            continue
        source, destination = transition_range
        signatures = _confirmed_signatures(entry)
        if primary not in signatures:
            continue
        if source_address is not None and source != source_address:
            continue
        contracts.add(MismatchContract(source, destination, signatures))

    if len(contracts) != 1:
        raise ReproducerEvaluationError(
            "Expected one localized source mismatch contract for "
            f"{primary.code}/{primary.subject}, found {len(contracts)}."
        )
    return next(iter(contracts))


def _read_frame_payload(stream: Any, context: str, file_size: int) -> bytes:
    encoded_length = stream.read(_FRAME_LENGTH.size)
    if len(encoded_length) != _FRAME_LENGTH.size:
        raise ReproducerEvaluationError(f"{context} has a truncated frame length.")
    (length,) = _FRAME_LENGTH.unpack(encoded_length)
    if stream.tell() + length > file_size:
        raise ReproducerEvaluationError(f"{context} has a truncated frame payload.")
    payload = stream.read(length)
    if len(payload) != length:
        raise ReproducerEvaluationError(f"{context} has a truncated frame payload.")
    return payload


def _decode_indexed_msgpack_transforms(
    path: Path,
    source: int,
) -> list[SymbolicTransform]:
    """Decode only frames whose indexed source PC can match the mismatch."""
    file_size = path.stat().st_size
    with path.open("rb") as stream:
        if stream.read(len(MSGPACK_MAGIC)) != MSGPACK_MAGIC:
            raise ReproducerEvaluationError(
                "Reproducer extraction requires versioned MessagePack framing."
            )
        header_payload = _read_frame_payload(
            stream, "MessagePack oracle header", file_size
        )
        try:
            header = msgpack.unpackb(header_payload, raw=False, strict_map_key=False)
        except (ValueError, msgpack.ExtraData) as error:
            raise ReproducerEvaluationError(
                f"Unable to decode MessagePack oracle header: {error}"
            ) from error
        if not isinstance(header, dict):
            raise ReproducerEvaluationError(
                "MessagePack oracle header is not an object."
            )
        addresses = header.get("addresses")
        item_count = header.get("item_count")
        if (
            not isinstance(addresses, list)
            or not isinstance(item_count, int)
            or isinstance(item_count, bool)
            or len(addresses) != item_count
        ):
            raise ReproducerEvaluationError(
                "MessagePack oracle has an invalid address index."
            )
        candidate_indices = {
            index for index, address in enumerate(addresses) if address == source
        }
        if not candidate_indices:
            return []

        selected_payloads: list[bytes] = []
        for index in range(item_count):
            encoded_length = stream.read(_FRAME_LENGTH.size)
            if len(encoded_length) != _FRAME_LENGTH.size:
                raise ReproducerEvaluationError(
                    "MessagePack oracle has a truncated item-frame length."
                )
            (length,) = _FRAME_LENGTH.unpack(encoded_length)
            if stream.tell() + length > file_size:
                raise ReproducerEvaluationError(
                    "MessagePack oracle has a truncated item-frame payload."
                )
            if index in candidate_indices:
                payload = stream.read(length)
                if len(payload) != length:
                    raise ReproducerEvaluationError(
                        "MessagePack oracle has a truncated candidate frame."
                    )
                selected_payloads.append(payload)
            else:
                stream.seek(length, io.SEEK_CUR)

    sliced_header = dict(header)
    sliced_header["addresses"] = [source]
    sliced_header["item_count"] = 1
    encoded_header = msgpack.packb(sliced_header, use_bin_type=True)
    matches: list[SymbolicTransform] = []
    for payload in selected_payloads:
        encoded = io.BytesIO(
            MSGPACK_MAGIC
            + _FRAME_LENGTH.pack(len(encoded_header))
            + encoded_header
            + _FRAME_LENGTH.pack(len(payload))
            + payload
        )
        decoded = list(stream_transformation(encoded))
        if len(decoded) == 1 and isinstance(decoded[0], SymbolicTransform):
            matches.append(decoded[0])
    return matches


def _load_transform(
    path: Path,
    trace_format: str,
    contract: MismatchContract,
) -> SymbolicTransform:
    if trace_format == "msgpack":
        candidates = _decode_indexed_msgpack_transforms(path, contract.source)
    else:
        with path.open(encoding="utf-8") as stream:
            trace = parse_transformations(stream)
        candidates = [
            item
            for item in trace
            if isinstance(item, SymbolicTransform) and item.addr == contract.source
        ]
    matches = [item for item in candidates if item.range == contract.transition_range]
    if len(matches) != 1:
        raise ReproducerEvaluationError(
            f"Oracle contains {len(matches)} symbolic transforms for "
            f"{contract.source:#x}->{contract.destination:#x}."
        )
    return matches[0]


def _load_snapshot(path: Path, source: int) -> ProgramState:
    with path.open(encoding="utf-8") as stream:
        states = parse_snapshots(stream)
    matches = [state for state in states if state.read_pc() == source]
    if len(matches) != 1:
        raise ReproducerEvaluationError(
            f"Concrete trace contains {len(matches)} source states at {source:#x}."
        )
    return matches[0]


def _resolve_source_symbol(
    config: Config, case: CaseConfig, binary: Path
) -> int | None:
    if case.source_symbol is None:
        return None
    address = common.read_symbols(config.nm, binary).get(case.source_symbol)
    if address is None:
        raise ReproducerEvaluationError(
            f"Guest binary has no source symbol {case.source_symbol!r}."
        )
    return address


def _compile_reproducer(
    config: Config,
    source: Path,
    output: Path,
    link_address: int,
    log: Path,
) -> None:
    result = common.run_process(
        (
            str(config.compiler),
            "-nostdlib",
            "-static",
            "-no-pie",
            "-Wl,--build-id=none",
            f"-Wl,-Ttext={link_address:#x}",
            "-Wl,-e,_start",
            "-Wl,-z,max-page-size=0x1000",
            "-o",
            str(output),
            str(source),
        ),
        cwd=source.parent,
    )
    log.write_text(result.output)
    if result.returncode != 0 or not output.is_file():
        raise ReproducerEvaluationError(
            f"Reproducer compilation failed with status {result.returncode}."
        )


def _run_validation(
    config: Config,
    program: Path,
    binary: Path,
    oracle: Path,
    output: Path,
) -> dict[str, Any]:
    output.mkdir(parents=True)
    qemu_log = output / "qemu.log"
    validation_log = output / "validation.log"
    report_path = output / "validation.json"
    states_path = output / "states.trace"
    port = common._free_loopback_port()
    qemu = common.ManagedProcess(
        (str(program), "-g", str(port), str(binary)),
        qemu_log,
        cwd=output,
    )
    try:
        with qemu as process:
            common._wait_for_listener(process, port, "reproducer QEMU GDB server")
            validation = common.run_process(
                (
                    str(config.validate_qemu),
                    "--remote",
                    f"127.0.0.1:{port}",
                    "--symb-trace",
                    str(oracle),
                    "--trace-type",
                    "json",
                    "--executable",
                    str(binary),
                    "--output",
                    str(states_path),
                    "--report",
                    str(report_path),
                    "--error-level",
                    "info",
                    "--quiet",
                ),
                cwd=output,
            )
    except common.EvaluationError as error:
        validation_log.write_text(str(error) + "\n")
        raise ReproducerEvaluationError(str(error)) from error
    validation_log.write_text(validation.output)
    if validation.returncode != 0 or not report_path.is_file():
        raise ReproducerEvaluationError(
            f"Reproducer validation failed with status {validation.returncode}."
        )
    report = common._load_json_object(report_path, "reproducer validation report")
    if report.get("schema") != QEMU_REPORT_SCHEMA:
        raise ReproducerEvaluationError(
            "Reproducer validator emitted an unsupported report."
        )
    return report


def require_buggy_reproduction(
    report: dict[str, Any], contract: MismatchContract
) -> None:
    if report.get("status") != "mismatch":
        raise ReproducerEvaluationError(
            f"Buggy emulator reported {report.get('status')!r}, not a mismatch."
        )
    reproduced = select_mismatch_contract(
        report,
        contract.signatures[0],
        source_address=contract.source,
    )
    if reproduced != contract:
        raise ReproducerEvaluationError(
            "Generated program did not reproduce the complete localized mismatch contract."
        )

    if any(
        signature.code == "unexpected-guest-signal" for signature in contract.signatures
    ):
        reason = report.get("terminal_reason")
        signal_subjects = {
            signature.subject
            for signature in contract.signatures
            if signature.code == "unexpected-guest-signal"
        }
        if (
            not isinstance(reason, dict)
            or reason.get("kind") != "signal"
            or reason.get("pc") != contract.source
            or reason.get("signal") not in signal_subjects
        ):
            raise ReproducerEvaluationError(
                "Generated crash reproducer lacks the expected signal and fault PC."
            )
    else:
        common._require_complete_terminal_trace(report)
        trace = report.get("trace")
        if not isinstance(trace, dict) or (
            trace.get("state_count"),
            trace.get("transform_count"),
        ) != (2, 1):
            raise ReproducerEvaluationError(
                "Generated mismatch trace is not exactly one complete transition."
            )


def require_reference_acceptance(report: dict[str, Any]) -> None:
    if report.get("status") != "accepted":
        raise ReproducerEvaluationError(
            f"Reference emulator reported {report.get('status')!r}, not acceptance."
        )
    common._require_complete_terminal_trace(report)
    trace = report.get("trace")
    if not isinstance(trace, dict) or (
        trace.get("state_count"),
        trace.get("transform_count"),
    ) != (2, 1):
        raise ReproducerEvaluationError(
            "Reference reproducer trace is not exactly one complete transition."
        )
    validation = report.get("validation")
    entries = validation.get("entries") if isinstance(validation, dict) else None
    if not isinstance(entries, list) or any(
        _confirmed_signatures(entry) for entry in entries if isinstance(entry, dict)
    ):
        raise ReproducerEvaluationError(
            "Reference emulator retained a confirmed reproducer mismatch."
        )


def require_native_oracle_acceptance(
    artifacts: SourceArtifacts,
    entry_prefix: EntryPrefix | None,
) -> None:
    native = artifacts.metadata.get("native")
    if (
        not isinstance(native, dict)
        or native.get("kind") != "trigger"
        or native.get("expectedNativeStatus") != 0
    ):
        raise ReproducerEvaluationError(
            "Native acceptance control lacks a successful zero-status trigger capture."
        )
    if entry_prefix is None:
        raise ReproducerEvaluationError(
            "Native acceptance control requires the exact entry-to-transition prefix."
        )


def _relative(path: Path, root: Path) -> str:
    return str(path.relative_to(root))


def _contract_document(contract: MismatchContract) -> dict[str, Any]:
    return {
        "transitionRange": [contract.source, contract.destination],
        "errors": [
            {"code": signature.code, "subject": signature.subject}
            for signature in contract.signatures
        ],
    }


def evaluate_case(
    config: Config,
    case: CaseConfig,
    input_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    artifacts = load_source_artifacts(input_root, case)
    source_report = common._load_json_object(
        artifacts.report, "source validation report"
    )
    expected_source = _resolve_source_symbol(config, case, artifacts.binary)
    contract = select_mismatch_contract(
        source_report,
        case.primary_error,
        source_address=expected_source,
    )
    transform = _load_transform(artifacts.oracle, artifacts.trace_format, contract)
    snapshot = _load_snapshot(artifacts.states, contract.source)
    fragment = extract_executable_fragment(
        artifacts.binary, contract.source, contract.destination
    )

    case_root = output_root / "artifacts" / case.identifier
    case_root.mkdir(parents=True)
    guest = case_root / "guest-program"
    source = case_root / "reproducer.S"
    binary = case_root / "reproducer"
    oracle = case_root / "oracle.trace"
    shutil.copy2(artifacts.binary, guest)

    entry_prefix = None
    if case.entry_prefix_symbol is not None:
        prefix_address = common.read_symbols(config.nm, artifacts.binary).get(
            case.entry_prefix_symbol
        )
        if prefix_address is None or prefix_address >= contract.source:
            raise ReproducerEvaluationError(
                f"Invalid entry prefix symbol {case.entry_prefix_symbol!r}."
            )
        prefix_fragment = extract_executable_fragment(
            artifacts.binary,
            prefix_address,
            contract.source,
            require_fallthrough=True,
        )
        entry_prefix = EntryPrefix(prefix_fragment.start, prefix_fragment.data)

    reproducer = Reproducer(
        str(artifacts.binary),
        [],
        snapshot,
        transform,
        fragment=fragment,
        entry_prefix=entry_prefix,
        condition_code_seed=case.condition_code_seed,
    )
    source.write_text(reproducer.asm())
    _compile_reproducer(
        config,
        source,
        binary,
        reproducer.link_address,
        case_root / "compile.log",
    )

    generated_transition = common.read_symbols(config.nm, binary).get(
        "focaccia_reproducer_transition"
    )
    if generated_transition != contract.source:
        raise ReproducerEvaluationError(
            f"Generated transition is at {generated_transition!r}, expected {contract.source:#x}."
        )
    generated_fragment = extract_executable_fragment(
        binary, contract.source, contract.destination
    )
    if generated_fragment.data != fragment.data:
        raise ReproducerEvaluationError(
            "Generated executable does not preserve the original transition bytes."
        )
    if entry_prefix is not None:
        generated_prefix = extract_executable_fragment(
            binary, entry_prefix.start, entry_prefix.end
        )
        if generated_prefix.data != entry_prefix.data:
            raise ReproducerEvaluationError(
                "Generated executable does not preserve the entry-to-transition prefix."
            )

    minimized_trace = single_transition_reproducer_trace(transform, binary)
    serialize_transformations(minimized_trace, oracle, "json")

    validation_root = output_root / "validation" / case.identifier
    buggy_report = _run_validation(
        config,
        case.buggy_program,
        binary,
        oracle,
        validation_root / "buggy",
    )
    require_buggy_reproduction(buggy_report, contract)
    if case.reference_kind == "qemu":
        if case.reference_program is None:
            raise ReproducerEvaluationError("QEMU reference program is unavailable.")
        reference_report = _run_validation(
            config,
            case.reference_program,
            binary,
            oracle,
            validation_root / "reference",
        )
        require_reference_acceptance(reference_report)
        reference_document = {
            "kind": "qemu",
            "emulator": case.reference_emulator,
            "version": case.reference_version,
            "program": str(case.reference_program),
            "programSha256": common._sha256(case.reference_program),
            "report": _relative(
                validation_root / "reference" / "validation.json", output_root
            ),
            "reportSha256": common._sha256(
                validation_root / "reference" / "validation.json"
            ),
            "status": "accepted",
        }
    else:
        require_native_oracle_acceptance(artifacts, entry_prefix)
        reference_document = {
            "kind": "native-oracle",
            "emulator": case.reference_emulator,
            "version": case.reference_version,
            "binary": str(artifacts.binary),
            "binarySha256": common._sha256(artifacts.binary),
            "oracle": str(artifacts.oracle),
            "oracleSha256": common._sha256(artifacts.oracle),
            "status": "accepted",
        }

    source_document = {
        "sourceCase": case.source_case,
        "binary": str(artifacts.binary),
        "binarySha256": common._sha256(artifacts.binary),
        "oracle": str(artifacts.oracle),
        "oracleSha256": common._sha256(artifacts.oracle),
        "states": str(artifacts.states),
        "statesSha256": common._sha256(artifacts.states),
        "report": str(artifacts.report),
        "reportSha256": common._sha256(artifacts.report),
    }
    generated_document = {
        "source": _relative(source, output_root),
        "sourceSha256": common._sha256(source),
        "binary": _relative(binary, output_root),
        "binarySha256": common._sha256(binary),
        "oracle": _relative(oracle, output_root),
        "oracleSha256": common._sha256(oracle),
        "linkAddress": reproducer.link_address,
        "transitionBytes": fragment.data.hex(),
        "entryPrefixBytes": (
            entry_prefix.data.hex() if entry_prefix is not None else None
        ),
    }
    return {
        "status": "passed",
        "contract": _contract_document(contract),
        "source": source_document,
        "generated": generated_document,
        "buggy": {
            "emulator": case.buggy_emulator,
            "version": case.buggy_version,
            "program": str(case.buggy_program),
            "programSha256": common._sha256(case.buggy_program),
            "report": _relative(
                validation_root / "buggy" / "validation.json", output_root
            ),
            "reportSha256": common._sha256(
                validation_root / "buggy" / "validation.json"
            ),
            "status": "mismatch",
        },
        "reference": reference_document,
    }


def _write_json(path: Path, document: dict[str, Any]) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def _size_case(case: str, output_root: Path) -> dict[str, str]:
    guest = output_root / "artifacts" / case / "guest-program"
    minimized = output_root / "artifacts" / case / "reproducer"
    return {
        "guestProgram": _relative(guest, output_root),
        "guestProgramSha256": common._sha256(guest),
        "minimizedProgram": _relative(minimized, output_root),
        "minimizedProgramSha256": common._sha256(minimized),
    }


def run(
    config: Config,
    input_root: Path,
    iterations: int,
    requested_cases: tuple[str, ...] = (),
) -> int:
    if iterations <= 0:
        raise ReproducerEvaluationError("--iterations must be a positive integer.")
    if common.normalize_machine(platform.machine()) != "aarch64":
        raise ReproducerEvaluationError(
            "Reproducer evaluation must execute on AArch64."
        )
    configured = {case.identifier: case for case in config.cases}
    if requested_cases:
        if len(set(requested_cases)) != len(requested_cases):
            raise ReproducerEvaluationError(
                "A reproducer case may be selected only once."
            )
        unknown = sorted(set(requested_cases) - set(configured))
        if unknown:
            raise ReproducerEvaluationError(
                f"Unknown reproducer cases: {', '.join(unknown)}."
            )
        selected_cases = tuple(configured[identifier] for identifier in requested_cases)
    else:
        selected_cases = config.cases
    input_root = input_root.resolve(strict=True)
    output_root = input_root / "reproducers" / GUEST_SYSTEM
    if output_root.exists():
        raise ReproducerEvaluationError(
            f"Reproducer output already exists; archive it before rerunning: {output_root}."
        )
    output_root.mkdir(parents=True)

    cases: dict[str, Any] = {}
    metadata: dict[str, Any] = {
        "schema": METADATA_SCHEMA,
        "system": config.system,
        "guestSystem": GUEST_SYSTEM,
        "focacciaRevision": config.focaccia_revision,
        "requestedIterations": iterations,
        "sourceIteration": 0,
        "selectedCases": [case.identifier for case in selected_cases],
        "cases": cases,
        "status": "failed",
    }
    _write_json(output_root / "metadata.json", metadata)

    passed_cases: list[str] = []
    for case in selected_cases:
        print(f"[{config.system}] reproducer {case.identifier}", flush=True)
        try:
            cases[case.identifier] = evaluate_case(
                config, case, input_root, output_root
            )
        except (
            ReproducerEvaluationError,
            common.EvaluationError,
            OSError,
            ValueError,
        ) as error:
            cases[case.identifier] = {"status": "failed", "error": str(error)}
            print(
                f"[{config.system}] reproducer {case.identifier} failed: {error}",
                file=sys.stderr,
                flush=True,
            )
        else:
            passed_cases.append(case.identifier)
            print(f"[{config.system}] reproducer {case.identifier} passed", flush=True)
        _write_json(output_root / "metadata.json", metadata)

    evidence = {
        "schema": SIZE_EVIDENCE_SCHEMA,
        "focacciaRevision": config.focaccia_revision,
        "cases": {case: _size_case(case, output_root) for case in passed_cases},
    }
    _write_json(output_root / "reproducer-sizes.json", evidence)
    all_passed = len(passed_cases) == len(selected_cases)
    metadata["status"] = "passed" if all_passed else "failed"
    metadata["sizeEvidence"] = "reproducer-sizes.json"
    metadata["sizeEvidenceSha256"] = common._sha256(
        output_root / "reproducer-sizes.json"
    )
    _write_json(output_root / "metadata.json", metadata)
    return 0 if all_passed else 1


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Generate the Figure 8 reproducers and verify each on its buggy and "
            "reference QEMU variants."
        )
    )
    parser.add_argument("--config", type=Path, required=True, help=argparse.SUPPRESS)
    parser.add_argument(
        "--input", type=Path, required=True, help="Shared evaluation run root."
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=1,
        help="Accepted for the aggregate evaluator interface; effectiveness is checked once.",
    )
    parser.add_argument(
        "--case",
        action="append",
        default=[],
        help="Restrict the lower-level app to one Figure 8 case (repeatable).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    try:
        return run(
            load_config(args.config),
            args.input,
            args.iterations,
            tuple(args.case),
        )
    except KeyboardInterrupt:
        return 130
    except (
        ReproducerEvaluationError,
        common.EvaluationError,
        OSError,
        ValueError,
    ) as error:
        print(f"reproducer evaluation: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
