# Evaluation guide

The [main README](../README.md) contains the Docker setup, smoke test, and complete evaluation commands. This guide covers running from source and selecting individual cases.

## Run from source

Run these commands from the repository root. Native collection requires the same hardware and permissions as the Docker workflow. Use a shared results directory, or copy the complete directory between hosts after each phase.

```bash
# Collect native evidence on both x86-64 and AArch64.
nix run .#evaluate-native -- --output runs/evaluation-001

# Additional native collection on x86-64 only.
nix run -L .#evaluate-native-curl-full -- --output runs/evaluation-001

# After collection finishes, run on both hosts.
nix run -L .#evaluate-emulator -- --input runs/evaluation-001

# Generate figures after both emulator runs finish.
nix run .#plot-evaluation -- \
  --input runs/evaluation-001 \
  --reproducer-sizes runs/evaluation-001/reproducers/x86_64-linux/reproducer-sizes.json
```

On AArch64, `evaluate-emulator` also runs Box64, reproducer generation, and full-Curl QEMU validation.

## Individual cases

For example, collect case 1372 on x86-64, then validate it on AArch64 using the same results directory:

```bash
# x86-64
nix run .#evaluate-native -- --output runs/single-case --case 1372

# AArch64
nix run .#evaluate-qemu-1372 -- --input runs/single-case
```

Use `--iterations N` for repeated measurements. Use a new output directory when rerunning an existing case. Existing samples are not overwritten.

Each command provides `--help`. The aggregate `evaluate-emulator` command accepts `--input` and `--iterations`. Use per-case commands to select a smaller run.

## Results

Results are organized by stage and host:

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
  reproducers/
    x86_64-linux/
  figures/
```

Native directories contain oracles, timings, logs, and replay recordings. Emulator directories contain validation reports, traces, and timings. Generated figures are under `figures/`.

If a stage fails, inspect its logs and validation report. Independent stages continue, and the command exits nonzero when any requested stage fails.

## Development

- [Build and emulator reference](../DEVELOPMENT.md)
- [Implementation details and evidence formats](REFERENCE.md)
