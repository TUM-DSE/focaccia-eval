# Evaluation workflow

## Status

The host-generic native trigger phase, source-pinned SQLite/Curl/Lua packages, RR-backed application tracing, QEMU GDB/plugin consumers, and Box64 log consumer are implemented. QEMU runs retain structured validation reports and opt-in component profiles. Full-Curl cross-validated, speculative, and QEMU modes are separate singleton stages so normal evaluation does not repeat the long workload. On AArch64, the host-adaptive `evaluate-emulator` app also generates and verifies the eight Figure 8 reproducers after their source QEMU cases, retaining source, binaries, buggy/reference evidence, and hash-bound size evidence. Seven cases use QEMU negative controls; #1376 uses its successful native oracle plus the byte-identical entry-to-LSL prefix because upstream QEMU still exhibits that Linux-user crash. `plots.py` consumes retained evaluator artifacts and contains no runtime measurements. It also reproduces the emulator bug-study figure from the paper's fixed, manually reviewed QEMU and Box64 classification percentages.

## Goal

The complete public workflow uses `evaluate-native`, `evaluate-native-curl-full`, and `evaluate-emulator`. The same `evaluate-emulator` command is invoked on both hosts; Nix selects its host-specific closure automatically. Lower-level `evaluate-qemu`, `evaluate-box64`, per-case QEMU apps, and `evaluate-qemu-curl-full` remain available for focused iteration. The selected app determines the role, so there are no public role or system flags.

Each application derives the current architecture from the Nix system and runtime host. It must not accept an architecture override that could disagree with the machine executing the measurement. Emulator drivers derive the guest architecture from native oracle metadata rather than from a user override. `--emulator NAME` may restrict a QEMU variant within `evaluate-qemu` without changing either architecture.

| Host system | `evaluate-native` | Emulator consumers |
|---|---|---|
| x86-64 | Measure native x86-64 triggers and the SQLite, Curl, and Lua workloads; produce their oracles | `evaluate-emulator` runs every QEMU consumer for AArch64 oracles |
| AArch64 | Measure native AArch64 triggers 364, 2248, and 2419; produce their oracles | `evaluate-emulator` runs the x86-64 QEMU consumers, Box64, and full-Curl QEMU validation |

The emulator applications directly depend on every applicable pinned emulator output. Nix realizes those closures, with normal build progress and no evaluator timeout, before launching any measured execution.

Small deterministic triggers omit deterministic replay, matching the paper's runtime evaluation. Effectful application workloads use RR recording and deterministic replay. The preflight accepts the retained Lua signal because only GDB-writable MXCSR/XMM state changes; it still rejects changed x87/extended-XSAVE state before launching QEMU.

The x86-64 application package pairs are `application-{sqlite,curl,lua}` and `application-{sqlite,curl,lua}-injected`. Both members of each pair use the same locked upstream revision and build configuration; only the injected member receives the corresponding Table 3 bug patch. The shared inputs are exported by `application-workloads`, and source/injection provenance is exported by `application-catalog`.

For a selective application run, the native role first measures the injected binary, records the same workload under RR, and then captures a speculative symbolic oracle by connecting LLDB to an RR replay server. It executes and replays `_start` through `main` without symbolic validation, traces from `main`, and stops immediately after the injected instruction. The RR recording is retained for the emulator consumer. SQLite receives the SQL workload on standard input; Curl fetches the fixed 5 KiB fixture from a temporary loopback-only HTTP server. Lua writes and flushes one readiness result, then blocks on a runner-owned empty stdin pipe; the runner delivers SIGINT as soon as that flushed output is visible. This prevents workload churn between readiness and signal delivery.

## Complete invocation sequence

A complete run uses one shared output directory:

```bash
# Run once on River and once on Eliza, each on its native ISA.
nix run .#evaluate-native -- --output runs/evaluation-001

# Run on River after its ordinary native evaluation.
nix run -L .#evaluate-native-curl-full -- --output runs/evaluation-001

# Run the exact same command once on River and once on Eliza.
nix run -L .#evaluate-emulator -- --input runs/evaluation-001
```

Run these commands sequentially against the shared filesystem. On River, `evaluate-emulator` dispatches the applicable AArch64-guest QEMU cases. On Eliza, it dispatches the x86-64-guest QEMU cases and applications, Box64, and full-Curl QEMU validation. Independent emulator stages continue after an ordinary failure, and the wrapper exits nonzero if any stage fails. An interrupt stops the wrapper immediately instead of starting another evaluation. It accepts only `--input` and `--iterations` because it always means “all applicable emulator evaluations”; use a lower-level app for filtering.

Evaluators append only disjoint cases to a compatible role/system result and reject duplicate case IDs, incompatible iteration/profile settings, and unregistered artifacts. Archive an existing case before rerunning it; no command overwrites a prior sample.

The role-specific evaluation apps expose only injected/buggy paper cases; reference variants are dedicated negative-control checks. By default, `evaluate-native` runs all trigger cases matching the host ISA and, on x86-64, the three selective applications. `--case ID` and `--iterations N` restrict a run. Full Curl is never part of that default. Native oracles use streaming MessagePack persistence by default; `--trace-format json` retains the legacy JSON option. Trigger cases capture a cross-validated oracle between explicit witness bounds. Selective applications replay `_start` onward but symbolically trace only `main` through the injected transition. The full-Curl native singleton records once, then retains both a cross-validated full trace and a speculative full trace; the speculative trace is the QEMU consumer oracle. Exact binaries, workloads, RR traces, symbolic traces, logs, hashes, profiles, component measurements, and bounds are retained. Failed stages have an empty timing field and cannot become samples. Native symbolic capture is bounded at 120 minutes; other subprocess stages retain the 30-minute limit.

## Run layout

```text
runs/evaluation-001/
  native/
    x86_64-linux/
    aarch64-linux/
  emulated/
    qemu/
      x86_64-linux/
      aarch64-linux/
    box64/
      aarch64-linux/
  figures/
```

Native directories contain measurements, symbolic traces, and any RR data needed by consumers. Emulated directories contain measurements, concrete traces, raw emulator logs, replay preflight and content-bound manifest reports, and validation reports under `<backend>/<variant>/<case>/<iteration>/`. QEMU uses the live GDB driver; Box64 and a future Arancini driver consume their debug logs through Focaccia's existing offline parsers. Box64 validation remains explicitly partial because its logs expose register state only at basic-block boundaries. Generated PDFs belong under `figures/` and must remain untracked.

## Measurement and plotting requirements

- Nix builds complete before timing begins.
- Native runs request Focaccia's opt-in profile for concrete, symbolic, validation, trace, and serialization time. QEMU runs retain exclusive execution, tracing, validation, serialization, total, and unattributed time. CSV component rows must agree with the hash-bound profile before plotting accepts them. Paper stacks use only measured concrete/trace-collection and validation components; serialization, total, and unattributed time remain explicit diagnostics and are not silently reassigned.
- Failed capture, replay, validation, target crash, timeout, and infrastructure failure are recorded as failures rather than timing samples.
- Independent cases continue after a failure, but the invocation exits nonzero if any requested case fails.
- Plot generation uses only successful cases. It warns about omitted cases and skips a figure when no complete sample remains; it never substitutes zero or a paper value.
- The resulting data must regenerate the paper's runtime figures:
  - trigger overhead breakdown;
  - full Curl tracing comparison;
  - selective Lua, Curl, and SQLite runtime breakdown.

Generate available figures from one retained run with:

```bash
nix run .#plot-evaluation -- --input runs/evaluation-001
```

Outputs default to `runs/evaluation-001/figures/`. Existing known figure names are removed before generation so an omitted figure cannot survive as stale evidence. The Eliza `evaluate-emulator` stage writes this input to `reproducers/x86_64-linux/reproducer-sizes.json`. Pass that path as optional `--reproducer-sizes PATH`; it uses schema `focaccia-reproducer-size-evidence-v1`, names guest and minimized binaries, binds both with SHA-256, and records the exact Focaccia revision. Artifact paths are relative to the evidence file:

```json
{
  "schema": "focaccia-reproducer-size-evidence-v1",
  "focacciaRevision": "<40-character Git revision>",
  "cases": {
    "1372": {
      "guestProgram": "artifacts/guest-1372",
      "guestProgramSha256": "<SHA-256>",
      "minimizedProgram": "artifacts/minimized-1372",
      "minimizedProgramSha256": "<SHA-256>"
    }
  }
}
```

Runtime CSVs never supply code sizes. Without verified evidence, the size figure is skipped. `combined-bug-study.pdf` is deliberately independent of the evaluator run: it uses the fixed percentages reported by the paper's manually reviewed QEMU and Box64 bug study. The paper source checkout remains unchanged.
