"""Local AArch64 controls from hash-bound retained native symbolic oracles.

Concrete consumer observations are explicitly not native snapshots. For 2248,
only constant register inputs established by the native prelude are admitted.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import shutil
import struct
import subprocess
import time
from pathlib import Path

from focaccia.completion import TraceCompletion, TraceScope
from focaccia.execution import ExecutionOutcome, ExecutionState
from focaccia.no_replay import ExitAction, ExitScope, NoReplayActionDescriptor, NoReplayActionKind
from focaccia.persistence import serialize_transformations
from focaccia.trace import MaterializedTrace, TraceEnvironment
from focaccia.reproducer_aarch64 import AArch64Block, generate_aarch64_reproducer
from focaccia.snapshot import ProgramState
from focaccia.symbolic import SymbolicTransformComposer, eval_symbol, iter_expression_dag
from miasm.expression.expression import ExprMem

import evaluation as common
import reproducer_evaluation as re


def elf_bytes(path: Path, start: int, end: int) -> bytes:
    data = path.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != 183:
        raise ValueError("Expected little-endian AArch64 ELF64")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    for index in range(count):
        kind, flags, offset, address, _, filesz, _, _ = struct.unpack_from("<IIQQQQQQ", data, phoff + index * size)
        if kind == 1 and flags & 1 and address <= start < end <= address + filesz:
            result = data[offset + start - address:offset + end - address]
            if len(result) == end - start:
                return result
    raise ValueError("No complete executable ELF range")


def native_artifacts(root: Path, case: str):
    base = root / "native/aarch64-linux"
    metadata = common._load_json_object(base / "metadata.json", "native metadata")
    if metadata.get("schema") != "focaccia-native-evaluation-v2" or metadata.get("role") != "native":
        raise ValueError("Invalid native provenance")
    item = metadata["cases"][case]["iterations"][0]
    paths = {}
    for name in ("binary", "oracle"):
        path = re._require_contained_file(base / item[name], root, name)
        if common._sha256(path) != item[name + "Sha256"]:
            raise ValueError(f"Native {name} hash mismatch")
        paths[name] = path
    return paths


def unique_transform(oracle: Path, pc: int):
    items = re._decode_indexed_msgpack_transforms(oracle, pc)
    if len(items) != 1:
        raise ValueError(f"Expected one native transform at {pc:#x}")
    return items[0]


def concrete_memory_dependencies(transform, state):
    """Resolve every decoded read and write target; unknown addresses fail closed."""
    ranges = set()
    expressions = list(transform.changed_regs.values())
    for write in transform.memory_writes:
        ranges.add((eval_symbol(write.address, state), write.size_bytes))
        expressions.extend((write.address, write.value))
    for expression in expressions:
        for node in iter_expression_dag(expression):
            if isinstance(node, ExprMem):
                if node.size % 8:
                    raise ValueError("Non-byte memory dependency")
                ranges.add((eval_symbol(node.ptr, state), node.size // 8))
    for address, size in ranges:
        state.read_memory(address, size)
    return tuple(sorted(ranges))


def control_backend(case: str) -> str:
    """The optimizer block needs the plugin; the two single instructions stay on GDB."""
    return "plugin" if case == "2248" else "gdb"


def add_clean_exit(source, block_size: int):
    """Make the first post-block instruction the typed AArch64 exit action."""
    landing = "    .byte 0x1f, 0x20, 0x03, 0xd5\n"
    branch = "    b reproduced_entry\n"
    if source.assembly.count(landing) != 1 or source.assembly.count(branch) != 1:
        raise ValueError("Generated control lacks unique entry/stop instructions")
    size_assert = f'ASSERT(SIZEOF(.fragment) == {block_size + 4}, "Unexpected fragment size")'
    bootstrap_assert = 'ASSERT(SIZEOF(.bootstrap) == 52, "Unexpected bootstrap size")'
    if source.linker_script.count(size_assert) != 1 or source.linker_script.count(bootstrap_assert) != 1:
        raise ValueError("Generated control has an unexpected section size contract")
    return type(source)(
        source.assembly.replace(branch, "    mov x8, #93\n" + branch).replace(landing, "    svc #0\n"),
        source.linker_script.replace(bootstrap_assert, 'ASSERT(SIZEOF(.bootstrap) == 56, "Unexpected bootstrap size")'),
        source.entry_pc,
        source.transition_pc,
        source.memory,
    )


def whole_block_trace(transform, binary: Path):
    """Bind one composed ordinary transition and its explicit exit action."""
    start, end = transform.range
    argument = (1 << 64) - 1
    descriptor = NoReplayActionDescriptor(transform.arch.key, end, NoReplayActionKind.EXIT)
    completion = TraceCompletion(
        end,
        1,
        2,
        ExecutionOutcome(ExecutionState.EXITED, exit_status=255),
        descriptor,
        ExitAction(argument, ExitScope.THREAD),
    )
    environment = TraceEnvironment(
        str(binary), (), (), start_address=start, stop_address=end,
        architecture=transform.arch.key,
    )
    return MaterializedTrace(
        (transform,), environment, (start,),
        scope=TraceScope.WHOLE_PROGRAM, completion=completion,
    )


def plugin_paths(package: Path) -> tuple[Path, Path]:
    qemu = package / "bin/qemu-aarch64"
    plugin = package / "lib/plugins/libfocaccia.so"
    if not qemu.is_file() or not plugin.is_file():
        raise ValueError(f"Plugin package lacks qemu-aarch64 or libfocaccia.so: {package}")
    return qemu, plugin


def plugin_command(qemu: Path, plugin: Path, socket: Path, binary: Path) -> tuple[str, ...]:
    # Do not bound plugin translation: 2248 depends on the optimizer seeing the
    # ordinary whole translation block.  The one-block oracle still selects
    # exactly 0x4002f4..0x400310 for validation.
    return (str(qemu), "-plugin", f"{plugin},socket={socket}", str(binary))


def terminal_evidence(ready, *, pid: int, binary_sha256: str, command: tuple[str, ...], returncode: int):
    """Validate typed readiness and construct the matching typed completion record."""
    if (not isinstance(ready, dict)
            or ready.get("schema") != "focaccia-plugin-terminal-ready-v1"
            or ready.get("pid") != pid
            or ready.get("binarySha256") != binary_sha256
            or not isinstance(ready.get("nonce"), str)):
        raise ValueError("Plugin terminal readiness does not bind the guest process and binary")
    return {
        "schema": "focaccia-plugin-terminal-evidence-v1",
        "nonce": ready["nonce"],
        "pid": pid,
        "binarySha256": binary_sha256,
        "commandSha256": hashlib.sha256(json.dumps(command, separators=(",", ":")).encode()).hexdigest(),
        "returncode": returncode,
    }


def run_plugin_validation(config, package: Path, binary: Path, oracle: Path, directory: Path):
    """Run one generated bounded control using the typed plugin completion protocol."""
    qemu, plugin = plugin_paths(package)
    directory.mkdir(parents=True, exist_ok=True)
    socket = Path(os.environ.get("TMPDIR", "/tmp")) / ("focaccia-" + hashlib.sha256(str(directory).encode()).hexdigest()[:16] + ".sock")
    ready_path, evidence_path = directory / "plugin-terminal-ready.json", directory / "plugin-terminal-evidence.json"
    report, states = directory / "validation.json", directory / "states.trace"
    validator_command = (str(config.validate_qemu), "--use-socket", str(socket), "--guest-arch", "aarch64l",
                         "--symb-trace", str(oracle), "--trace-type", "json", "--output", str(states),
                         "--report", str(report), "--error-level", "info", "--plugin-terminal-ready", str(ready_path),
                         "--plugin-terminal-evidence", str(evidence_path), "--quiet")
    qemu_command = plugin_command(qemu, plugin, socket, binary)
    for path in (socket, ready_path, evidence_path):
        path.unlink(missing_ok=True)
    validator = common.ManagedProcess(validator_command, directory / "validation.log")
    try:
        with validator as validator_process:
            deadline = time.monotonic() + common.SERVER_STARTUP_TIMEOUT_SECONDS
            while not socket.is_socket():
                if validator_process.poll() is not None or time.monotonic() >= deadline:
                    raise ValueError("Plugin validator did not become ready")
                time.sleep(0.05)
            with common.ManagedProcess(qemu_command, directory / "qemu.log") as guest:
                deadline = time.monotonic() + common.PROCESS_TIMEOUT_SECONDS
                while not ready_path.is_file():
                    if guest.poll() is not None or validator_process.poll() is not None or time.monotonic() >= deadline:
                        raise ValueError("Plugin terminal readiness was not produced before process completion")
                    time.sleep(0.05)
                ready = json.loads(ready_path.read_text())
                try:
                    status = guest.wait(timeout=5)
                except subprocess.TimeoutExpired as error:
                    raise ValueError("Generated control did not exit after the bounded block") from error
                evidence = terminal_evidence(ready, pid=guest.pid, binary_sha256=common._sha256(binary),
                                             command=qemu_command, returncode=status)
                temporary = evidence_path.with_name("." + evidence_path.name + ".tmp")
                temporary.write_text(json.dumps(evidence, sort_keys=True) + "\n")
                temporary.replace(evidence_path)
                validator_status = validator_process.wait(timeout=5)
        if status != 255 or validator_status not in {0, 1}:
            raise ValueError(f"Plugin control failed: guest {status}, validator {validator_status}")
        return common._load_json_object(report, "generated plugin validation report")
    finally:
        socket.unlink(missing_ok=True)


def prepare(root: Path, case: str, output: Path):
    paths = native_artifacts(root, case)
    oracle, binary = paths["oracle"], paths["binary"]
    provenance = {k: {"path": str(v), "sha256": common._sha256(v)} for k, v in paths.items()}
    if case == "2248":
        start, pc, end = 0x4002f4, 0x40030c, 0x400310
        transforms = [unique_transform(oracle, address) for address in range(start, end, 4)]
        names = [str(t.instructions[0]).split()[0].upper() for t in transforms]
        if names != ["CMP", "CSET", "AND", "CMP", "CSETM", "LSR", "SBFM"]:
            raise ValueError(f"Unexpected optimizer-sensitive block: {names}")
        state = ProgramState(transforms[0].arch)
        state.write_register("PC", start)
        for address, register, expected in ((0x400184, "X4", 2), (0x400188, "X3", 1), (0x400190, "X2", 0)):
            value = eval_symbol(unique_transform(oracle, address).changed_regs[register], state)
            if value != expected:
                raise ValueError("Native constant prelude disagrees")
            state.write_register(register, value)
        composer = SymbolicTransformComposer(transforms[0])
        for transform in transforms[1:]:
            composer.append(transform)
        transform = composer.finish()
        registers, memory = ("X2", "X3", "X4"), ()
        contract = None
        provenance.update(
            entryKind="native-symbolic-constant-prelude",
            composedSourceTransforms=7,
            generatedOracleTransforms=1,
            generatedOracleStates=2,
        )
    else:
        pc = start = {"364": 0x400194, "2419": 0x40019c}[case]
        end = pc + 4
        transform = unique_transform(oracle, pc)
        emulator = {"364": "qemu-5-2-0", "2419": "qemu-8-1-3"}[case]
        consumer = root / f"emulated/qemu/aarch64-linux/qemu-gdb/{emulator}/{case}/0"
        consumer_metadata = common._load_json_object(root / "emulated/qemu/aarch64-linux/metadata.json", "consumer metadata")
        observed = consumer_metadata["cases"]["qemu-" + case]["iterations"][0]
        for name, path in paths.items():
            if observed[name + "Sha256"] != common._sha256(path):
                raise ValueError("Consumer/native artifact identity mismatch")
        state = re._load_snapshot(consumer / "states.trace", pc)
        report = common._load_json_object(consumer / "validation.json", "consumer report")
        signatures = [signature for entry in report["validation"]["entries"]
                      if entry.get("transition_range", [None])[0] == pc
                      for signature in re._confirmed_signatures(entry)]
        if not signatures:
            raise ValueError("No classified source mismatch")
        contract = re.select_mismatch_contract(report, signatures[0], source_address=pc)
        for name in ("states.trace", "validation.json"):
            path = consumer / name
            provenance[name] = {"path": str(path), "sha256": common._sha256(path)}
        provenance["entryKind"] = "qemu-consumer-observation-not-native-layout"
        registers = tuple(sorted(set(transform.get_validation_input_registers()) |
                                 ({"X0", "X1", "X2", "NZCV"} if case == "364" else {"X1"})))
        memory = concrete_memory_dependencies(transform, state)
        if case == "2419" and memory != ((state.read_register("X1") - 8, 8),):
            raise ValueError("Unexpected LDAPUR decoded dependencies")
    if state.arch != transform.arch:
        raise ValueError("Consumer/native architecture identity mismatch")
    data = elf_bytes(binary, start, end)
    expected = {"364": bytes.fromhex("22402038"), "2419": bytes.fromhex("20805fd9")}.get(case)
    if expected is not None and data != expected:
        raise ValueError("Source bytes differ from admitted instruction")
    relocation = None
    if case in {"364", "2419"}:
        # Consumer observations use QEMU's high initial-stack mapping, which
        # cannot be represented by an ELF PT_LOAD. Relocate only the concrete
        # witness bytes and its pointer coherently; values and equations stay
        # unchanged because the transform addresses memory through X1.
        old_address, size = memory[0]
        new_address = 0x600000
        observed = state.read_memory(old_address, size)
        state.write_memory(new_address, observed)
        state.write_register("X1", new_address if case == "364" else new_address + 8)
        memory = ((new_address, size),)
        relocation = {"oldAddress": old_address, "newAddress": new_address, "size": size}
        if case == "364" and contract is not None:
            contract = re.MismatchContract(
                contract.source,
                contract.destination,
                tuple(
                    re.ErrorSignature(signature.code, hex(new_address))
                    if signature.code == "memory-content-mismatch"
                    else signature
                    for signature in contract.signatures
                ),
            )
    source = generate_aarch64_reproducer(
        state,
        AArch64Block(start, data, pc),
        required_registers=registers,
        memory_ranges=memory,
        bootstrap_address=0x500000,
    )
    if case == "2248":
        source = add_clean_exit(source, len(data))
    (output / "reproducer.S").write_text(source.assembly)
    (output / "reproducer.ld").write_text(source.linker_script)
    provenance.update(blockStart=start, blockEnd=end, transitionPc=pc, blockBytes=data.hex(), requiredRegisters=registers,
                      registers={name: state.read_register(name) if name != "NZCV" else
                                 {flag: state.read_register(flag) for flag in "NZCV"} for name in registers},
                      nativeEquations={name: str(expr) for name, expr in transform.changed_regs.items()},
                      nativeMemoryEquations=[{"address": str(w.address), "value": str(w.value)} for w in transform.memory_writes],
                      memory=[{"address": a, "bytes": b.hex()} for a, b in source.memory],
                      layoutRelocation=relocation)
    (output / "source.json").write_text(json.dumps(provenance, indent=2) + "\n")
    return transform, contract, data


def run(args):
    root, output = args.input.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    results = {"schema": "focaccia-aarch64-generated-controls-v1", "cases": {}}
    config = re.Config("aarch64-linux", {}, args.compiler, Path(shutil.which("nm")), Path(shutil.which("validate-qemu")), ())
    with Path("/tmp/focaccia-local-benchmark.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        for case in args.cases:
            target = output / case
            target.mkdir()
            result = results["cases"][case] = {"generationAttempted": True, "controlsAttempted": False, "status": "failed"}
            try:
                transform, contract, data = prepare(root, case, target)
                binary = target / "reproducer"
                process = common.run_process((str(args.compiler), "-nostdlib", "-static", "-no-pie", "-Wl,--build-id=none", "-Wl,-z,max-page-size=0x10000", "-Wl,-T," + str(target / "reproducer.ld"), str(target / "reproducer.S"), "-o", str(binary)), cwd=target)
                (target / "compile.log").write_text(process.output)
                if process.returncode:
                    raise ValueError(f"Compilation failed: {process.returncode}")
                if elf_bytes(binary, transform.range[0], transform.range[1]) != data:
                    raise ValueError("Generated ELF did not retain complete block bytes")
                guest = native_artifacts(root, case)["binary"]
                assembly = target / "reproducer.S"
                result["sizes"] = {
                    "guestProgram": str(guest), "guestProgramSha256": common._sha256(guest),
                    "guestProgramElfBytes": guest.stat().st_size,
                    "generatedAssembly": str(assembly), "generatedAssemblySha256": common._sha256(assembly),
                    "generatedAssemblyTextBytes": assembly.stat().st_size,
                    "generatedProgram": str(binary), "generatedProgramSha256": common._sha256(binary),
                    "generatedProgramElfBytes": binary.stat().st_size,
                    "retainedInstructionBytes": len(data),
                    "accepted": False,
                }
                oracle = target / "oracle.trace"
                trace = whole_block_trace(transform, binary) if case == "2248" else MaterializedTrace(
                    (transform,),
                    TraceEnvironment(str(binary), (), (), start_address=transform.range[0],
                                     stop_address=transform.range[1], architecture=transform.arch.key),
                    (transform.range[0],),
                )
                serialize_transformations(trace, oracle, "json")
                result["controlsAttempted"] = True
                reports = {}
                if control_backend(case) == "plugin":
                    controls = (("buggy", args.plugin_buggy_2248), ("reference", args.plugin_reference))
                else:
                    controls = (("buggy", getattr(args, "buggy_" + case)), ("reference", args.reference))
                for label, program in controls:
                    try:
                        if control_backend(case) == "plugin":
                            qemu, plugin = plugin_paths(program)
                            result[label + "Emulator"] = {
                                "package": str(program), "path": str(qemu), "sha256": common._sha256(qemu),
                                "plugin": str(plugin), "pluginSha256": common._sha256(plugin),
                            }
                            reports[label] = run_plugin_validation(config, program, binary, oracle, target / label)
                        else:
                            result[label + "Emulator"] = {"path": str(program), "sha256": common._sha256(program)}
                            reports[label] = re._run_validation(config, program, binary, oracle, target / label)
                        result[label] = reports[label].get("status")
                    except (ValueError, OSError, common.EvaluationError, re.ReproducerEvaluationError) as error:
                        result[label] = {"error": str(error)}
                if "buggy" not in reports or "reference" not in reports:
                    raise ValueError("Control execution failed")
                if contract is None:
                    signature = re.ErrorSignature("register-content-mismatch", "X0")
                    contract = re.MismatchContract(transform.range[0], transform.range[1], (signature,))
                re.require_buggy_reproduction(reports["buggy"], contract)
                re.require_reference_acceptance(reports["reference"])
                result["status"] = "passed"
                result["sizes"]["accepted"] = True
            except (ValueError, OSError, common.EvaluationError, re.ReproducerEvaluationError) as error:
                result["error"] = str(error)
            (output / "metadata.json").write_text(json.dumps(results, indent=2) + "\n")
            print(case, json.dumps(result), flush=True)
    return 0 if all(c["status"] == "passed" for c in results["cases"].values()) else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("input", "output", "compiler", "reference", "buggy-364", "buggy-2419",
                 "plugin-reference", "plugin-buggy-2248"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument(
        "--case",
        dest="cases",
        action="append",
        choices=("364", "2248", "2419"),
        help="Generate only this control (repeatable; defaults to all three).",
    )
    arguments = parser.parse_args()
    arguments.cases = tuple(arguments.cases or ("364", "2248", "2419"))
    required = {"input", "output", "compiler"}
    if "2248" in arguments.cases:
        required.update(("plugin_reference", "plugin_buggy_2248"))
    if set(arguments.cases) & {"364", "2419"}:
        required.add("reference")
    if "364" in arguments.cases:
        required.add("buggy_364")
    if "2419" in arguments.cases:
        required.add("buggy_2419")
    missing = sorted(name for name in required if getattr(arguments, name) is None)
    if missing:
        parser.error("missing required arguments for selected cases: " + ", ".join(missing))
    raise SystemExit(run(arguments))
