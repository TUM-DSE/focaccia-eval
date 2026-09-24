"""Decoded AArch64 consumer inputs never invent addresses or missing bytes."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from miasm.expression.expression import ExprId, ExprInt, ExprMem
from focaccia.arch.aarch64 import ArchAArch64
from focaccia.snapshot import ProgramState, MemoryAccessError, RegisterAccessError
from focaccia.symbolic import MemoryWrite
from aarch64_reproducer_evaluation import (
    add_clean_exit,
    concrete_memory_dependencies,
    control_backend,
    plugin_command,
    terminal_evidence,
    whole_block_trace,
)


class PluginControlTests(unittest.TestCase):
    def test_only_2248_routes_to_plugin(self):
        self.assertEqual(control_backend("2248"), "plugin")
        self.assertEqual(control_backend("364"), "gdb")
        self.assertEqual(control_backend("2419"), "gdb")

    def test_2248_plugin_command_preserves_whole_translation_block(self):
        self.assertEqual(
            plugin_command(Path("/qemu"), Path("/libfocaccia.so"), Path("/control.sock"), Path("/guest")),
            ("/qemu", "-plugin", "/libfocaccia.so,socket=/control.sock", "/guest"),
        )

    def test_typed_terminal_handshake_binds_process_binary_and_command(self):
        command = ("qemu-aarch64", "-plugin", "libfocaccia.so", "reproducer")
        ready = {
            "schema": "focaccia-plugin-terminal-ready-v1",
            "nonce": "nonce-1",
            "pid": 42,
            "binarySha256": "binary-hash",
        }
        evidence = terminal_evidence(
            ready, pid=42, binary_sha256="binary-hash", command=command, returncode=0
        )
        self.assertEqual(evidence["schema"], "focaccia-plugin-terminal-evidence-v1")
        self.assertEqual(evidence["nonce"], "nonce-1")
        self.assertEqual(evidence["returncode"], 0)
        self.assertEqual(
            evidence["commandSha256"],
            hashlib.sha256(json.dumps(command, separators=(",", ":")).encode()).hexdigest(),
        )

    def test_terminal_handshake_rejects_unbound_or_untyped_readiness(self):
        good = {
            "schema": "focaccia-plugin-terminal-ready-v1",
            "nonce": "nonce-1",
            "pid": 42,
            "binarySha256": "binary-hash",
        }
        for replacement in (
            {**good, "schema": "old"},
            {**good, "pid": 43},
            {**good, "binarySha256": "other"},
            {**good, "nonce": None},
        ):
            with self.subTest(record=replacement):
                with self.assertRaises(ValueError):
                    terminal_evidence(
                        replacement, pid=42, binary_sha256="binary-hash", command=("qemu",), returncode=0
                    )

    def test_one_composed_block_has_n_plus_one_and_explicit_exit(self):
        transform = SimpleNamespace(range=(0x4002F4, 0x400310), arch=ArchAArch64("little"))
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "guest"
            binary.write_bytes(b"guest")
            trace = whole_block_trace(transform, binary)
        self.assertEqual((len(trace), trace.completion.transform_count, trace.completion.state_count), (1, 1, 2))
        self.assertEqual(trace.completion.final_pc, 0x400310)
        self.assertEqual(trace.completion.no_replay_exit.argument, (1 << 64) - 1)

    def test_clean_exit_replaces_stop_landing_without_changing_block(self):
        source = SimpleNamespace(
            assembly="prefix\n    b reproduced_entry\n    .byte 0x1f, 0x20, 0x03, 0xd5\n",
            linker_script=('ASSERT(SIZEOF(.fragment) == 32, "Unexpected fragment size")\n'
                           'ASSERT(SIZEOF(.bootstrap) == 52, "Unexpected bootstrap size")\n'),
            entry_pc=1,
            transition_pc=2,
            memory=(),
        )
        # The production source is a dataclass; use a matching constructor here.
        source_type = type("Source", (), {"__init__": lambda self, a, l, e, t, m: self.__dict__.update(
            assembly=a, linker_script=l, entry_pc=e, transition_pc=t, memory=m
        )})
        converted = add_clean_exit(source_type(source.assembly, source.linker_script, 1, 2, ()), 28)
        self.assertIn("mov x8, #93", converted.assembly)
        self.assertIn("svc #0", converted.assembly)
        self.assertNotIn("0x1f, 0x20, 0x03, 0xd5", converted.assembly)
        self.assertIn("SIZEOF(.fragment) == 32", converted.linker_script)
        self.assertIn("SIZEOF(.bootstrap) == 56", converted.linker_script)


class ConcreteDependenciesTests(unittest.TestCase):
    def setUp(self):
        self.state = ProgramState(ArchAArch64("little"))
        self.state.write_register("X1", 0x10008)
        self.ptr = ExprId("X1", 64) - ExprInt(8, 64)

    def transform(self, reads=(), writes=()):
        return SimpleNamespace(changed_regs=dict(enumerate(reads)), memory_writes=writes)

    def test_load_retains_exact_eight_bytes_at_decoded_offset(self):
        self.state.write_memory(0x10000, bytes(range(8)))
        transform = self.transform([ExprMem(self.ptr, 64)])
        self.assertEqual(concrete_memory_dependencies(transform, self.state), ((0x10000, 8),))

    def test_write_destination_and_input_have_distinct_widths(self):
        self.state.write_memory(0x10000, bytes(range(8)))
        transform = self.transform(writes=[MemoryWrite(self.ptr, ExprMem(self.ptr, 8))])
        self.assertEqual(concrete_memory_dependencies(transform, self.state), ((0x10000, 1),))

    def test_missing_byte_rejects(self):
        self.state.write_memory(0x10000, bytes(range(7)))
        with self.assertRaises(MemoryAccessError):
            concrete_memory_dependencies(self.transform([ExprMem(self.ptr, 64)]), self.state)

    def test_missing_address_register_rejects(self):
        self.state = ProgramState(ArchAArch64("little"))
        with self.assertRaises(RegisterAccessError):
            concrete_memory_dependencies(self.transform([ExprMem(self.ptr, 64)]), self.state)


if __name__ == "__main__":
    unittest.main()
