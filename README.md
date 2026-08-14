# Focaccia Reproducers

This repository provides the reproducible evaluation corpus for the 17 mistranslation cases in Table 2 of *Veritas: Semantic Validation for CPU Emulators*. It also packages the historical emulators, application workloads, evaluation programs, plotting tools, and provenance records used by the study.

Focaccia is consumed from the pinned `main` revision and remains responsible for tracing and semantic validation. This repository owns the evaluation inputs and emulator provenance.

## Scope

The repository includes the following components.

- All 17 Table 2 cases, including separate register and memory CMPXCHG witnesses for Box64 and QEMU.
- Static non-PIE x86-64 and AArch64 guest binaries.
- Reproducible GCC 14.2.1 and Musl 1.2.5 cross-compilation through Nix.
- Explicit `focaccia_trace_start` and `focaccia_trace_stop` symbols.
- Historical QEMU packages imported from matching pinned Nixpkgs revisions.
- A trace-enabled Box64 0.3.8 package with the cited CMPXCHG regression and an unmodified reference package on AArch64.
- Focaccia's pinned RR v85 tool on x86-64 and AArch64.
- A generated and versioned trigger catalog.
- A host-adaptive `evaluate-emulator` application that runs every applicable emulator stage. Lower-level QEMU and Box64 applications remain available for focused runs.
- Source-pinned static x86-64 reference and injected builds of SQLite, Curl, and Lua.
- Deterministic QEMU consumers for the three injected applications. These consumers verify RR effects, content-bound manifests, and recreated workload interfaces.
- The Table 3 injection patches, deterministic workloads, and syscall-backed time shim.
- Dedicated full-Curl native and QEMU measurement applications.
- Evidence-driven plotting from evaluator results, metadata, hash-bound profiles, and separately recorded reproducer sizes.

The following work remains outside the checked artifact.

- Reviewed native oracle bundles for the remaining emulator cases.
- Final component profiles for SQLite, Curl, and Lua under QEMU.
- Final full-Curl cross-validated, speculative, and QEMU measurements.
- Remaining QEMU emulated cases.
- Final aggregate capture across both native systems.
- Behavior-specific checks for the remaining emulator and application cases.

The presence of a package establishes that its source, patches, build recipe, and historical Nixpkgs revision are pinned. It does not establish end-to-end detection by Focaccia. A behavior check is exposed only when the buggy emulator produces the expected diagnostic and a reviewed reference accepts the same oracle.

## Development environment

The included `.envrc` loads the default flake development shell through nix-direnv. Enable it once in each checkout.

```bash
direnv allow
```

The shell provides Focaccia, RR, Binutils, `jq`, and the plotting dependencies from the pinned flake inputs. The equivalent command without direnv is `nix develop`.

## Build outputs

Inspect the complete output set.

```bash
nix flake show
```

Build the guest corpus for the current host.

```bash
nix build -L .#corpus
```

Build one trigger.

```bash
nix build -L .#trigger-508
```

On x86-64, build the reference and injected application binaries.

```bash
nix build -L .#application-sqlite .#application-sqlite-injected
nix build -L .#application-curl .#application-curl-injected
nix build -L .#application-lua .#application-lua-injected
nix build -L .#application-workloads
```

The `application-injections` check verifies that all six binaries are static. It confirms each injected instruction in its intended function, confirms its absence from the reference build, and runs native smoke tests. These application packages are available only on x86-64 because the Table 3 injections contain x86-64 instructions.

Run the non-privileged checks supported by the current host.

```bash
nix flake check -L
```

## Docker artifact

Build and load the artifact image for the current Linux architecture.

```bash
nix build -L .#docker-artifact
docker load < result
```

The image tag is `focaccia-artifact:<revision>`, or `focaccia-artifact:dirty` for an uncommitted tree. The x86-64 and AArch64 images use the same logical name but contain architecture-specific evaluation closures.

Starting the image without a command opens Bash in `/artifacts`.

```bash
docker run --rm -it \
  -v "$PWD/artifacts:/artifacts" \
  focaccia-artifact:<revision>
```

Evaluation programs are available directly through `PATH`. Native collection can be started as follows.

```bash
docker run --rm \
  --privileged \
  --security-opt seccomp=unconfined \
  -v "$PWD/artifacts:/artifacts" \
  focaccia-artifact:<revision> \
  evaluate-native --output /artifacts/evaluation
```

The image also provides `evaluate-emulator`, `plot-evaluation`, the focused QEMU evaluators, and host-specific programs such as `evaluate-native-curl-full` and `evaluate-reproducers`. Nix is not required at runtime.

Run an image only on a Docker host with the same physical ISA. Native collection requires debugger attachment, perf events, and personality control. x86-64 RR application capture also requires a compatible host PMU.

## Historical emulators

Invoke the RR version pinned by Focaccia on x86-64 or AArch64.

```bash
nix run .#rr -- --version
```

Native AArch64 recording requires an RR-supported microarchitecture such as Arm Neoverse. Building the package or running the version check does not demonstrate that native recording succeeded.

Build a historical QEMU package with its user-mode binaries.

```bash
nix build -L .#qemu-6-1-0-user
```

Build the injected and reference Box64 0.3.8 packages on AArch64.

```bash
nix build -L .#box64-0-3-8 .#box64-0-3-8-reference
```

Both packages enable the register trace required by the paper backend. The injected package applies only the cited pre-fix CMPXCHG behavior. The reference package retains the release behavior. The following check requires the injected emulator to produce the confirmed mismatch and the reference emulator to accept the same oracle.

```bash
nix build -L .#checks.aarch64-linux.box64-cmpxchg-validation
```

Validate the injected Box64 case against a shared native-oracle directory.

```bash
nix run -L .#evaluate-box64 -- --input runs/evaluation-001 --case box64-508
```

The reference package is used only by the dedicated negative-control check.

## Evaluation workflow

The plotting implementation is maintained in `evaluation/plots.py`. The complete two-system workflow is documented in [`evaluation/README.md`](evaluation/README.md).

Collect native evidence on each supported native system.

```bash
nix run .#evaluate-native -- --output runs/evaluation-001
```

After both hosts have produced the required native oracles, run the host-adaptive emulator workflow once on each host.

```bash
nix run -L .#evaluate-emulator -- --input runs/evaluation-001
```

The command selects stages for the physical host. It attempts every independent stage before reporting an ordinary failure. On AArch64 it also generates and validates all eight Figure 8 reproducers.

Generate every figure supported by successful evidence in the run.

```bash
nix run .#plot-evaluation -- \
  --input runs/evaluation-001 \
  --reproducer-sizes runs/evaluation-001/reproducers/x86_64-linux/reproducer-sizes.json
```

PDF files are written to `runs/evaluation-001/figures` by default. Missing, failed, or provenance-invalid measurements produce warnings and are omitted. They are never replaced with zeros or paper values.

`combined-bug-study.pdf` is the sole exception. It presents the fixed and manually reviewed QEMU and Box64 classification percentages from the paper and does not depend on runtime measurements.

The `evaluation-plots` package and `data-driven-evaluation-plots` check use deterministic fixtures to verify the plotting interface. They are not paper measurements.

## Catalog and architecture model

Build and inspect the generated trigger catalog.

```bash
nix build .#trigger-catalog
cat result/share/focaccia-reproducers/catalog.json
```

Guest binaries are cross-compiled reproducibly with `pkgsCross.musl64` for x86-64 and `pkgsCross.aarch64-multiplatform-musl` for AArch64.

Cross-compilation creates only the guest binary. It does not replace native oracle collection. x86-64 oracles must be recorded on native x86-64 hardware, and AArch64 oracles must be recorded on native AArch64 hardware.

The Nix `system` identifies the machine that builds or runs a derivation. Guest ISA, native-oracle ISA, and emulator-host ISA remain separate fields in the catalog.

## License

Focaccia Eval is distributed under the BSD 3-Clause license. See [`LICENSE`](LICENSE). Bundled fixtures and upstream components retain their own licenses.

## Provenance

Authoritative trigger, emulator, and paper-case declarations live in `nix/catalog.nix`. The remaining modules under `nix/` construct packages, checks, runners, plots, and Docker images from that catalog.

Guest witnesses are curated from the paper and the original upstream reports. Historical QEMU packages are imported unchanged from exact Nixpkgs revisions. Box64 uses the pinned Nixpkgs recipe and 0.3.8 source revision. It enables upstream trace support with a shared Zydis decoder and exposes separate reference and regression-injected outputs. The injected patch restores only the cited pre-fix ARM64 CMPXCHG behavior. `emulator-bug-study/` is not a source or dependency of this repository.

`flake.lock` pins the Focaccia revision, current toolchain, application sources, and each historical emulator package set. The trigger catalog records Nixpkgs and upstream emulator revisions. The application catalog records source revisions and injection points. Focaccia's `qemu-submodule` lock entry is used to build the validator plugin and is not a historical emulator input for this corpus.
