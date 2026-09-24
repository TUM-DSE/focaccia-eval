"""Check catalog localization against compiled witnesses without executing guests."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path


def main() -> None:
    cases = json.loads(Path(sys.argv[1]).read_text())
    # Witness contracts reviewed against fixed inline assembly and retained reports.
    # These are deliberately independent of the catalog fields being checked.
    expected = {
        "364": (0, 4, "memory-content-mismatch", None, ["ldsmaxb"]),
        "508": (0, 5, "register-content-mismatch", "RAX", ["cmpxchg"]),
        "1370": (0, 5, "register-content-mismatch", "CF", ["blsi"]),
        "1371": (23, 5, "register-content-mismatch", "CF", ["blsmsk"]),
        "1372": (30, 5, "register-content-mismatch", "RAX", ["bextr"]),
        "1374": (0, 5, "register-content-mismatch", "RAX", ["bzhi"]),
        "1375": (0, 4, "register-content-mismatch", "XMM1", ["addsubps"]),
        "1828867": (0, 2, "register-content-mismatch", "RAX", ["lahf"]),
        "2175": (0, 5, "register-content-mismatch", "CF", ["blsi"]),
        "2495": (0, 4, "register-content-mismatch", "R8", ["movq"]),
        "1861404": (0, 8, "memory-content-mismatch", None, ["vmovdqu", "vmovdqu"]),
        "2419": (0, 4, "register-content-mismatch", "X0", ["ldapur"]),
    }
    if set(cases) != {f"qemu-{name}" for name in expected}:
        raise ValueError("Ordinary QEMU mismatch catalog has missing or extra cases")
    for name, case in cases.items():
        identifier = case["trigger"]
        offset, length, code, subject, mnemonics = expected[identifier]
        actual = (
            case["expectedMismatchSourceOffset"],
            case["expectedMismatchLength"],
            case["expectedMismatchCode"],
            case.get("expectedMismatchSubject"),
        )
        if actual != (offset, length, code, subject):
            raise ValueError(f"{name}: catalog contract drift: {actual!r}")
        if case["expectedMismatchSourceSymbol"] != "focaccia_trace_start":
            raise ValueError(f"{name}: mismatch source is not the witness start")
        output = subprocess.check_output(
            [case["objdump"], "-d", "--no-show-raw-insn", case["binary"]], text=True
        )
        symbols = {}
        instructions = {}
        for line in output.splitlines():
            label = re.fullmatch(r"([0-9a-f]+) <([^>]+)>:", line)
            if label:
                symbols[label[2]] = int(label[1], 16)
            instruction = re.match(r"\s*([0-9a-f]+):\s+(.+)", line)
            if instruction:
                instructions[int(instruction[1], 16)] = instruction[2].strip()
        start = symbols["focaccia_trace_start"]
        stop = symbols["focaccia_trace_stop"]
        source, destination = start + offset, start + offset + length
        if not (start <= source < destination <= stop):
            raise ValueError(f"{name}: mismatch escapes compiled witness bounds")
        if source not in instructions or destination not in instructions:
            raise ValueError(
                f"{name}: mismatch endpoints are not instruction boundaries"
            )
        selected = [
            text
            for address, text in sorted(instructions.items())
            if source <= address < destination
        ]
        if len(selected) != len(mnemonics) or any(
            re.search(rf"\b{mnemonic}\b", instruction) is None
            for instruction, mnemonic in zip(selected, mnemonics, strict=True)
        ):
            raise ValueError(
                f"{name}: unexpected compiled instruction sequence {selected}"
            )
        if identifier == "1375" and not selected[0].endswith("%xmm1"):
            raise ValueError(f"{name}: ADDSUBPS destination is not XMM1")
        print(f"{name}: {source:#x}->{destination:#x}: {selected}")


if __name__ == "__main__":
    main()
