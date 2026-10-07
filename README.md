# Focaccia evaluation artifact

This repository provides the evaluation artifact for *Veritas: Semantic Validation for CPU Emulators*: the 17 historical mistranslation cases, SQLite/Curl/Lua workloads, pinned emulators, reproducer generation, and paper plotting tools. [Focaccia](https://github.com/TUM-DSE/focaccia) provides tracing and semantic validation.

## Requirements

- Docker on **two physical Linux hosts: x86-64 and AArch64**. Each host records its own native oracles; the emulator under test never generates its own correctness oracle.
- Native collection requires privileged debugger/perf access and supported recording hardware. x86-64 RR application capture requires a compatible PMU; native AArch64 recording requires an RR-supported processor, such as Arm Neoverse.
- Approximately **5 GB of image downloads per host**, plus space for unpacked images and generated results.
- Allow several hours for a complete campaign.

Use one shared results directory, or copy its complete contents between hosts after each phase. Preserve the relative layout and do not mix unrelated runs. A single host without the other architecture's native oracles cannot complete the campaign.

## Get the Docker image

On both hosts:

```bash
export IMAGE=taugoust/focaccia-artifact
docker pull "$IMAGE"
mkdir -p runs
```

Docker selects the matching architecture. The image contains the runtime dependencies; Nix is not required. Commands can be inspected with, for example:

```bash
docker run --rm "$IMAGE" evaluate-native --help
```

## Run the evaluation

Run phases sequentially, making each phase's results available on both hosts before proceeding.

### 1. Collect native evidence on both hosts

Run once on each physical architecture:

```bash
docker run --rm --privileged --security-opt seccomp=unconfined \
  -v "$PWD/runs:/artifacts" "$IMAGE" \
  evaluate-native --output /artifacts/evaluation-001
```

Then run the additional full-Curl collection **on x86-64 only**:

```bash
docker run --rm --privileged --security-opt seccomp=unconfined \
  -v "$PWD/runs:/artifacts" "$IMAGE" \
  evaluate-native-curl-full --output /artifacts/evaluation-001
```

### 2. Validate under emulation on both hosts

After all native collection finishes, run once on each host:

```bash
docker run --rm -v "$PWD/runs:/artifacts" "$IMAGE" \
  evaluate-emulator --input /artifacts/evaluation-001
```

This selects the host's emulator stages. On AArch64 it also runs Box64, reproducers, and full-Curl QEMU validation. Missing or incompatible inputs fail explicitly. Independent stages continue after ordinary failures, but the aggregate command returns nonzero if any stage fails.

### 3. Generate the figures

With results from both hosts available, run on either host:

```bash
docker run --rm -v "$PWD/runs:/artifacts" "$IMAGE" \
  plot-evaluation --input /artifacts/evaluation-001 \
  --reproducer-sizes /artifacts/evaluation-001/reproducers/x86_64-linux/reproducer-sizes.json
```

## Expected outputs

`runs/evaluation-001/` contains native oracles, validation reports, logs, profiles, metadata, and reproducers. Artifact hashes bind the evidence to its inputs. A successful historical-bug evaluation means the expected error was detected and localized—not that the mistranslated execution was accepted.

The five paper figures are written under `figures/`:

| Figure | File |
| --- | --- |
| Bug study | `combined-bug-study.pdf` |
| Trigger overhead | `split-overhead-breakdown.pdf` |
| Full-Curl tracing | `tracing-comparison.pdf` |
| Reproducer size | `reproducer-code-size.pdf` |
| Application overhead | `realworld-split-overhead-breakdown.pdf` |

Host-local views are under `figures/<system>/`; `multi-host-summary.json` indexes the outputs. Missing or invalid measurements are omitted with warnings, never replaced with zeros or paper runtime values. The bug-study figure uses the paper's fixed classification percentages, not fresh runtime measurements. `application-trend-ratios.pdf` is supplemental.

Reference outcomes remain explicit: case 1375 has a shared reference finding, and case 1861404 has partial reference visibility. Neither establishes reference correctness. See the [detailed evaluation guide](evaluation/README.md) for classifications and evidence contracts.

## Further documentation

- [Evaluation guide](evaluation/README.md): individual stages, selective runs, evidence formats, and limitations.
- [Development and technical reference](DEVELOPMENT.md): Nix builds/checks, historical emulators, architecture model, and provenance.
- [Emulator bug study](https://github.com/TUM-DSE/emulator-bug-study): underlying classification data and analysis.

## License

BSD 3-Clause; see [LICENSE](LICENSE). Bundled components retain their upstream licenses.
