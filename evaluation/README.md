# Evaluation workflow

## Status

The host-generic native trigger phase, source-pinned SQLite/Curl/Lua packages, RR-backed application tracing, QEMU GDB/plugin consumers, and Box64 log consumer are implemented. QEMU runs retain structured validation reports and opt-in component profiles. Full-Curl cross-validated, speculative, and QEMU modes are separate singleton stages so normal evaluation does not repeat the long workload. On AArch64, the host-adaptive `evaluate-emulator` app also runs `evaluate-reproducers` for its complete configured set: 13 trigger cases and the SQLite application case. Eight of those trigger reproducers supply the Figure 8 size evidence. Configured QEMU controls normally require both buggy reproduction and strict reference acceptance. Two paper outcomes are kept distinct rather than mislabeled as clean references: 1375 requires the reference to reproduce the exact same localized XMM1 NaN mismatch (`detected-reference-shared`), while 1861404 requires an incomplete one-transition reference report with exactly the configured ZMM0-unavailable diagnostic and no confirmed mismatch (`detected-reference-partial`). Both retain `referenceCorrectnessEstablished: false`, and unrelated mismatches fail. Case 1376 instead uses its successful native oracle and explicitly restored transition context because upstream QEMU still exhibits the Linux-user crash. `plots.py` consumes retained evaluator artifacts and contains no runtime measurements. It also reproduces the emulator bug-study figure from the paper's fixed, manually reviewed QEMU and Box64 classification percentages.

## Goal

The complete public workflow uses `evaluate-native`, `evaluate-native-curl-full`, and `evaluate-emulator`. The same `evaluate-emulator` command is invoked on both hosts; Nix selects its host-specific closure automatically. Lower-level `evaluate-qemu`, `evaluate-box64`, per-case QEMU apps, and `evaluate-qemu-curl-full` remain available for focused iteration. The selected app determines the role, so there are no public role or system flags.

Each application derives the current architecture from the Nix system and runtime host. It must not accept an architecture override that could disagree with the machine executing the measurement. Emulator drivers derive the guest architecture from native oracle metadata rather than from a user override. `--emulator NAME` may restrict a QEMU variant within `evaluate-qemu` without changing either architecture.

| Host system | `evaluate-native` | Emulator consumers |
|---|---|---|
| x86-64 | Measure native x86-64 triggers and the SQLite, Curl, and Lua workloads; produce their oracles | `evaluate-emulator` runs the 14 catalogued QEMU trigger consumers and three selective application consumers against the shared native inputs |
| AArch64 | Measure native AArch64 triggers 364, 2248, and 2419; produce their oracles | `evaluate-emulator` runs the same QEMU evaluator, then the eight-reproducer Figure 8 workflow, Box64, and full-Curl QEMU validation |

The eight Figure 8 outputs are a plotted subset, not the size of the default
reproducer run. `evaluate-reproducers` processes all 14 configured cases and
retains each case's applicable buggy/reference or native-oracle controls.
Box64 remains partial basic-block-boundary validation and is not promoted to
full transition acceptance by this workflow.

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

Run these commands sequentially against the shared filesystem. On both hosts, `evaluate-emulator` invokes the QEMU evaluator containing all 14 catalogued trigger consumers and the three selective application consumers; missing or incompatible native inputs fail closed. On AArch64 it additionally dispatches the Figure 8 reproducer workflow, Box64, and full-Curl QEMU validation. Independent emulator stages continue after an ordinary failure, and the wrapper exits nonzero if any stage fails. An interrupt stops the wrapper immediately instead of starting another evaluation. It accepts only `--input` and `--iterations` because it always means “all applicable emulator evaluations”; use a lower-level app for filtering.

## Docker invocation

Build and load the architecture-specific image on each matching-ISA host:

```bash
nix build -L .#docker-artifact
nix run -L .#load-docker-artifact
```

The build result is a nix2container descriptor, not input for `docker load`.
The loader copies the descriptor and its Nix closure to the local Docker daemon.
Use one preserved host directory as the `/artifacts` bind mount and pass paths
inside that mount to every stage. For example:

```bash
mkdir -p "$PWD/artifacts/evaluation-001"

docker run --rm --privileged --security-opt seccomp=unconfined \
  -v "$PWD/artifacts:/artifacts" \
  focaccia-artifact:<revision> \
  evaluate-native --output /artifacts/evaluation-001

# Run on the native x86-64 host after its ordinary native evaluation.
docker run --rm --privileged --security-opt seccomp=unconfined \
  -v "$PWD/artifacts:/artifacts" \
  focaccia-artifact:<revision> \
  evaluate-native-curl-full --output /artifacts/evaluation-001

docker run --rm \
  -v "$PWD/artifacts:/artifacts" \
  focaccia-artifact:<revision> \
  evaluate-emulator --input /artifacts/evaluation-001

docker run --rm \
  -v "$PWD/artifacts:/artifacts" \
  focaccia-artifact:<revision> \
  plot-evaluation --input /artifacts/evaluation-001
```

Run native collection on each native ISA before its consumers. The native
container needs debugger attachment, perf events, and personality control;
the emulator and plotting invocations do not inherit those privileges here.
The retained metadata and manifests bind the system, programs, workloads,
oracles, and revisions. Moving the shared directory is supported when its
contents and relative layout are preserved; combining unrelated or modified
runs is rejected rather than silently relocated.

Evaluators append only disjoint cases to a compatible role/system result and reject duplicate case IDs, incompatible iteration/profile settings, and unregistered artifacts. Archive an existing case before rerunning it; no command overwrites a prior sample.

Native trigger transport is case-configured: `nativeTransport` defaults to `local`; case 1861404 uses `gdbserver` with the packaged GNU `gdbserverProgram`. The server allocates a dynamic port and readiness is read from its log without opening a probe connection. Its child environment sets `SHELL=/bin/sh` and `ZDOTDIR=/nonexistent`; the process group is cleaned up after capture, including failures. Native metadata retains the configured transport, server program path and SHA-256, alongside binary provenance. This transport still requires a native runner with debugger/ptrace permission; the named `native-trigger-gdbserver-transport` check uses fixtures, not native tracing.

The role-specific evaluation apps expose only injected/buggy paper cases; reference variants are dedicated negative-control checks. By default, `evaluate-native` runs all trigger cases matching the host ISA and, on x86-64, the three selective applications. `--case ID` and `--iterations N` restrict a run. Full Curl is never part of that default. Native oracles use streaming MessagePack persistence by default; `--trace-format json` retains the legacy JSON option. Trigger cases capture a cross-validated whole-program oracle; legacy witness-bounded runners remain separate compatibility tools. Selective applications replay `_start` onward but symbolically trace only `main` through the injected transition. The full-Curl native singleton records once, then retains both a cross-validated full trace and a speculative full trace; the speculative trace is the QEMU consumer oracle. Exact binaries, workloads, RR traces, symbolic traces, logs, hashes, profiles, component measurements, and bounds are retained. Failed stages have an empty timing field and cannot become samples. Native symbolic capture is bounded at 120 minutes; other subprocess stages retain the 30-minute limit.

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
