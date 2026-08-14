#!/usr/bin/env python3

"""Statically reject unsupported RR effects before a long QEMU application run."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Sequence

from focaccia.deterministic import Event, SignalEvent, SyscallEvent
from focaccia.deterministic import DeterministicLog
from focaccia.qemu.deterministic import syscall_policies
from focaccia.qemu.replay import validate_x86_partial_signal_extra_transition
from focaccia.qemu.syscall import ReplayError, ReplayStrategy

REPORT_SCHEMA = "focaccia-replay-preflight-v1"


def _post_exec_events(events: Sequence[Event]) -> tuple[Event, ...]:
    for index, event in enumerate(events):
        if (
            isinstance(event, SyscallEvent)
            and event.syscall_number == 59
            and event.syscall_state == "exiting"
        ):
            return tuple(events[index + 1 :])
    return tuple(events)


def audit_events(events: Sequence[Event]) -> dict[str, Any]:
    relevant = _post_exec_events(events)
    failures: list[dict[str, object]] = []
    strategies: Counter[str] = Counter()
    effects: Counter[str] = Counter()
    index = 0
    while index < len(relevant):
        event = relevant[index]
        if isinstance(event, SyscallEvent):
            if event.syscall_state == "exiting":
                failures.append(
                    {
                        "eventCount": event.event_count,
                        "effect": f"syscall:{event.syscall_number}",
                        "reason": "unpaired system-call exit event",
                    }
                )
                index += 1
                continue
            policies = syscall_policies.get(event.syscall_arch.archname, {})
            policy = policies.get(event.syscall_number)
            if policy is None:
                failures.append(
                    {
                        "eventCount": event.event_count,
                        "effect": f"syscall:{event.syscall_number}",
                        "reason": "unclassified system call",
                    }
                )
                index += 1
                continue
            effect = f"syscall:{policy.name}"
            effects[effect] += 1
            strategies[policy.strategy.value] += 1
            if policy.strategy is ReplayStrategy.REJECT:
                failures.append(
                    {
                        "eventCount": event.event_count,
                        "effect": effect,
                        "reason": policy.reject_reason,
                    }
                )
            for register, allowed in policy.allowed_argument_values:
                try:
                    recorded = event.registers[register]
                except KeyError:
                    recorded = None
                if recorded not in allowed:
                    failures.append(
                        {
                            "eventCount": event.event_count,
                            "effect": effect,
                            "reason": f"unsupported {register} value {recorded!r}",
                        }
                    )
            if policy.requires_post_event:
                if index + 1 >= len(relevant):
                    failures.append(
                        {
                            "eventCount": event.event_count,
                            "effect": effect,
                            "reason": "missing post-event",
                        }
                    )
                else:
                    post = relevant[index + 1]
                    if (
                        not isinstance(post, SyscallEvent)
                        or post.syscall_state != "exiting"
                        or post.syscall_number != event.syscall_number
                        or post.tid != event.tid
                    ):
                        failures.append(
                            {
                                "eventCount": event.event_count,
                                "effect": effect,
                                "reason": "malformed post-event",
                            }
                        )
                    else:
                        if post.syscall_extras.kind not in policy.allowed_extras:
                            failures.append(
                                {
                                    "eventCount": post.event_count,
                                    "effect": effect,
                                    "reason": (
                                        "unsupported RR extra effect "
                                        f"{post.syscall_extras.kind!r}"
                                    ),
                                }
                            )
                        for write in post.mem_writes:
                            if not write.is_fully_known:
                                failures.append(
                                    {
                                        "eventCount": post.event_count,
                                        "effect": effect,
                                        "reason": "recorded memory output has unknown bytes",
                                    }
                                )
                        index += 1
        elif isinstance(event, SignalEvent):
            effect = f"signal:{event.descriptor.signal_number}"
            effects[effect] += 1
            if event.signal_variant == "signal":
                strategies[ReplayStrategy.RECORDED.value] += 1
                if index + 1 >= len(relevant):
                    failures.append(
                        {
                            "eventCount": event.event_count,
                            "effect": effect,
                            "reason": "missing signal-handler event",
                        }
                    )
                else:
                    post = relevant[index + 1]
                    if (
                        not isinstance(post, SignalEvent)
                        or post.signal_variant != "signalHandler"
                        or post.tid != event.tid
                        or post.descriptor != event.descriptor
                    ):
                        failures.append(
                            {
                                "eventCount": event.event_count,
                                "effect": effect,
                                "reason": "malformed signal-handler event",
                            }
                        )
                    elif event.arch.archname != "x86_64":
                        failures.append(
                            {
                                "eventCount": event.event_count,
                                "effect": effect,
                                "reason": (
                                    "QEMU GDB cannot restore recorded AArch64 "
                                    "signal-handler FP/vector state"
                                ),
                            }
                        )
                    else:
                        try:
                            validate_x86_partial_signal_extra_transition(
                                event.extra_registers,
                                post.extra_registers,
                            )
                        except ReplayError as error:
                            failures.append(
                                {
                                    "eventCount": event.event_count,
                                    "effect": effect,
                                    "reason": str(error),
                                }
                            )
                        for write in post.mem_writes:
                            if not write.is_fully_known:
                                failures.append(
                                    {
                                        "eventCount": post.event_count,
                                        "effect": effect,
                                        "reason": "signal frame has unknown bytes",
                                    }
                                )
                        index += 1
        elif event.event_type not in {"exit", "sched"}:
            failures.append(
                {
                    "eventCount": event.event_count,
                    "effect": f"rr-event:{event.event_type}",
                    "reason": "unsupported RR bookkeeping event",
                }
            )
        index += 1

    return {
        "schema": REPORT_SCHEMA,
        "status": "passed" if not failures else "unsupported",
        "eventCount": len(relevant),
        "effects": dict(sorted(effects.items())),
        "strategies": dict(sorted(strategies.items())),
        "failures": failures,
    }


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit deterministic effects without launching QEMU."
    )
    parser.add_argument("--deterministic-log", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(arguments: list[str] | None = None) -> int:
    args = make_parser().parse_args(arguments)
    report = audit_events(DeterministicLog(args.deterministic_log).events())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
