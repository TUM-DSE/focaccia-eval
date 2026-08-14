from __future__ import annotations

import unittest

from focaccia.arch import x86
from focaccia.deterministic import (
    ExtraRegisterState,
    SignalDescriptor,
    SignalEvent,
    SyscallEvent,
)

import replay_preflight


ARCH = x86.ArchX86()


def syscall(count: int, number: int, state: str, *, command: int = 0) -> SyscallEvent:
    return SyscallEvent(
        0x400000 + count * 2,
        1,
        ARCH,
        {
            "rip": 0x400000 + count * 2,
            "rax": number if state != "exiting" else 0,
            "rsi": command,
        },
        (),
        ARCH,
        number,
        state,  # type: ignore[arg-type]
        False,
        event_count=count,
    )


def xsave(
    *, x87_byte: int = 0, xmm0: int = 0, xstate_bv: int = 0x201
) -> ExtraRegisterState:
    raw = bytearray(576)
    raw[24:28] = (0x1F80).to_bytes(4, "little")
    raw[32] = x87_byte
    raw[160:176] = xmm0.to_bytes(16, "little")
    raw[512:520] = xstate_bv.to_bytes(8, "little")
    return ExtraRegisterState(ARCH, "x86-xsave-v1", bytes(raw))


class ReplayPreflightTests(unittest.TestCase):
    def test_skips_recorder_exec_and_accepts_supported_fcntl(self):
        events = (
            syscall(1, 157, "entering"),
            syscall(2, 157, "exiting"),
            syscall(3, 59, "entering"),
            syscall(4, 59, "exiting"),
            syscall(5, 72, "entering", command=6),
            syscall(6, 72, "exiting", command=6),
        )

        report = replay_preflight.audit_events(events)

        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["eventCount"], 2)
        self.assertEqual(report["effects"], {"syscall:fcntl": 1})

    def test_rejects_unknown_fcntl_variant_before_qemu_launch(self):
        events = (
            syscall(1, 59, "exiting"),
            syscall(2, 72, "entering", command=99),
            syscall(3, 72, "exiting", command=99),
        )

        report = replay_preflight.audit_events(events)

        self.assertEqual(report["status"], "unsupported")
        self.assertIn("unsupported rsi value 99", report["failures"][0]["reason"])

    def test_accepts_x86_signal_when_only_gdb_writable_state_changes(self):
        descriptor = SignalDescriptor(
            ARCH,
            (2).to_bytes(4, "little", signed=True),
            True,
            "userHandler",
        )
        events = (
            syscall(1, 59, "exiting"),
            SignalEvent(
                0x401000,
                1,
                ARCH,
                {"rip": 0x401000},
                (),
                signal_number=descriptor,
                event_count=2,
                extra_registers=xsave(xmm0=1, xstate_bv=0x203),
            ),
            SignalEvent(
                0x402000,
                1,
                ARCH,
                {"rip": 0x402000},
                (),
                signal_handler=descriptor,
                event_count=3,
                extra_registers=xsave(),
            ),
        )

        report = replay_preflight.audit_events(events)

        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["effects"], {"signal:2": 1})

    def test_rejects_x86_signal_when_x87_state_changes(self):
        descriptor = SignalDescriptor(
            ARCH,
            (2).to_bytes(4, "little", signed=True),
            True,
            "userHandler",
        )
        events = (
            syscall(1, 59, "exiting"),
            SignalEvent(
                0x401000,
                1,
                ARCH,
                {"rip": 0x401000},
                (),
                signal_number=descriptor,
                event_count=2,
                extra_registers=xsave(x87_byte=1),
            ),
            SignalEvent(
                0x402000,
                1,
                ARCH,
                {"rip": 0x402000},
                (),
                signal_handler=descriptor,
                event_count=3,
                extra_registers=xsave(),
            ),
        )

        report = replay_preflight.audit_events(events)

        self.assertEqual(report["status"], "unsupported")
        self.assertIn("x87 or extended XSAVE", report["failures"][0]["reason"])


if __name__ == "__main__":
    unittest.main()
