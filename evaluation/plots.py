#!/usr/bin/env python3

"""Generate evaluation figures from one retained evaluator run.

Mixed systems for the same benchmark/mode are rejected before plotting.
Incomplete measured figures are skipped with a warning. Runtime measurements
and reproducer sizes are never replaced with paper values or zeros. The
emulator bug-study figure separately presents the paper's fixed, manually
reviewed classification percentages.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import statistics
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from matplotlib.gridspec import GridSpec
from matplotlib.patches import ConnectionPatch, Patch
from matplotlib.ticker import MultipleLocator

from evaluation import (
    EvaluationError,
    read_symbols,
    require_selective_application_acceptance,
)


FIXED_METADATA = {"CreationDate": None}
PAPER_ONE_COLUMN = (3.335, 2.3)
PAPER_TWO_COLUMN = (7.0, 2.8)
COLORS = sns.color_palette("pastel")
HATCHES = ("//", "xx", "OO")

TRIGGER_GROUPS = (
    ("Computation", ("508", "1372", "1374")),
    ("Flags", ("1370", "1371", "2175")),
    ("Vectors", ("1375", "2495", "1861404")),
    ("Crash", ("1832422",)),
    ("Memory", ("2419",)),
)
APPLICATIONS = ("lua", "curl", "sqlite")
REPRODUCER_GROUPS = (
    ("Computation", ("1372", "1374", "sqlite")),
    ("Flags", ("1370", "1371", "2175")),
    ("Crash", ("1376", "1377")),
)
REPRODUCER_SIZE_SCHEMA = "focaccia-reproducer-size-evidence-v1"
NATIVE_METADATA_SCHEMA = "focaccia-native-evaluation-v2"
EMULATED_METADATA_SCHEMA = "focaccia-emulated-evaluation-v1"
ACCOUNTING_NAME = "timing-accounting.json"
FIGURE_NAMES = (
    "split-overhead-breakdown.pdf",
    "tracing-comparison.pdf",
    "realworld-split-overhead-breakdown.pdf",
    "application-trend-ratios.pdf",
    "reproducer-code-size.pdf",
    "combined-bug-study.pdf",
)

# Seconds copied from the paper's numerical source (resources/plots.py:768-770).
# These are used only as a labelled comparison series, never as replacement data.
PAPER_APPLICATION_COMPONENTS = {
    "lua": ((28.52, 270.51, 0.0), (1401.04, 0.0, 31.367)),
    "curl": ((214.44, 476.70, 0.0), (1347.68, 0.0, 119.367)),
    "sqlite": ((35.38, 86.64, 0.0), (202.17, 0.0, 10.38)),
}

# Rounded percentages from the paper's manually reviewed emulator bug study.
# Unlike runtime and reproducer measurements, these are fixed study results,
# not values produced by an evaluator run.
BUG_STUDY_ERROR_LABELS = ("Runtime", "Mistranslations", "System calls")
BUG_STUDY_QEMU = (63, 22, 15)
BUG_STUDY_BOX64 = (84, 10, 6)
BUG_STUDY_MISTRANSLATION_LABELS = (
    "Computation",
    "Crash",
    "Flags",
    "Memory",
    "Vectors",
    "Optimizations",
)
BUG_STUDY_QEMU_MISTRANSLATIONS = (19, 32, 12, 9, 27, 1)
BUG_STUDY_MISTRANSLATION_COLORS = (
    "#a7a7a7",
    "#FFDFBA",
    "#BEFF99",
    "#AF99FF",
    "#ECFF99",
    "#FF9999",
)
BUG_STUDY_MISTRANSLATION_HATCHES = ("//", "\\\\", "oo", "OO", "xx", "**")


class Measurements:
    def __init__(self, rows: list[dict[str, str]]) -> None:
        samples: dict[tuple[str, str, str], list[float]] = defaultdict(list)
        self.modes: dict[str, set[str]] = defaultdict(set)
        systems: dict[tuple[str, str], set[str]] = defaultdict(set)
        for row in rows:
            if row.get("status") != "passed" or not row.get("seconds"):
                continue
            try:
                seconds = float(row["seconds"])
            except (TypeError, ValueError):
                _warn(f"ignoring malformed timing row: {row!r}")
                continue
            if seconds < 0:
                _warn(f"ignoring negative timing row: {row!r}")
                continue
            benchmark = row.get("benchmark", "")
            mode = row.get("mode", "")
            component = row.get("component", "")
            if not benchmark or not mode or not component:
                _warn(f"ignoring incomplete timing row: {row!r}")
                continue
            # A mode's components must all describe the same execution system.
            # Reject ambiguity before averaging or assembling partial profiles.
            identity = (benchmark, mode)
            systems[identity].add(row.get("system", ""))
            if len(systems[identity]) > 1:
                raise ValueError(
                    f"ambiguous measurement systems for {benchmark}/{mode}: "
                    f"{sorted(systems[identity])!r}; provide host-separated evidence"
                )
            samples[(benchmark, mode, component)].append(seconds)
            self.modes[benchmark].add(mode)
        self.values = {key: statistics.fmean(values) for key, values in samples.items()}

    def get(self, benchmark: str, mode: str, component: str) -> float | None:
        return self.values.get((benchmark, mode, component))

    def components(
        self,
        benchmark: str,
        mode: str,
        names: tuple[str, ...],
    ) -> tuple[float, ...] | None:
        values = tuple(self.get(benchmark, mode, name) for name in names)
        if any(value is None for value in values):
            return None
        return tuple(float(value) for value in values if value is not None)

    def qemu_mode(
        self,
        benchmark: str,
        components: tuple[str, ...],
    ) -> str | None:
        candidates = sorted(
            mode
            for mode in self.modes.get(benchmark, ())
            if mode.startswith("qemu-")
            and self.components(benchmark, mode, components) is not None
        )
        if len(candidates) == 1:
            return candidates[0]
        if len(candidates) > 1:
            _warn(
                f"omitting {benchmark}: multiple complete QEMU modes "
                f"{candidates!r} are present"
            )
        return None


def _warn(message: str) -> None:
    print(f"warning: {message}", file=sys.stderr)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_reproducer_sizes(path: Path | None) -> dict[str, tuple[float, float]]:
    if path is None:
        _warn(
            "reproducer-code-size.pdf requires --reproducer-sizes with "
            "provenance-bound artifacts"
        )
        return {}
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        _warn(f"not using reproducer size evidence {path}: {error}")
        return {}
    if (
        not isinstance(document, dict)
        or document.get("schema") != REPRODUCER_SIZE_SCHEMA
    ):
        _warn(f"not using reproducer size evidence {path}: unsupported schema")
        return {}
    revision = document.get("focacciaRevision")
    identity = document.get("focacciaSourceIdentity")
    valid_revision = (
        isinstance(revision, str)
        and len(revision) == 40
        and all(character in "0123456789abcdef" for character in revision)
    )
    valid_identity = (
        isinstance(identity, dict)
        and identity.get("kind") in {"git-revision", "nix-store-path"}
        and isinstance(identity.get("value"), str)
        and (
            (
                identity["kind"] == "git-revision"
                and len(identity["value"]) == 40
                and all(
                    character in "0123456789abcdef" for character in identity["value"]
                )
            )
            or (
                identity["kind"] == "nix-store-path"
                and identity["value"].startswith("/nix/store/")
            )
        )
    )
    if not (valid_revision or valid_identity):
        _warn(
            f"not using reproducer size evidence {path}: invalid Focaccia source identity"
        )
        return {}
    encoded_cases = document.get("cases")
    if not isinstance(encoded_cases, dict):
        _warn(f"not using reproducer size evidence {path}: cases are missing")
        return {}

    sizes: dict[str, tuple[float, float]] = {}
    for _, benchmarks in REPRODUCER_GROUPS:
        for benchmark in benchmarks:
            encoded = encoded_cases.get(benchmark)
            if not isinstance(encoded, dict):
                continue
            artifacts: list[float] = []
            valid = True
            for artifact_name in ("guestProgram", "minimizedProgram"):
                encoded_path = encoded.get(artifact_name)
                encoded_hash = encoded.get(f"{artifact_name}Sha256")
                if not isinstance(encoded_path, str) or not isinstance(
                    encoded_hash, str
                ):
                    valid = False
                    break
                artifact = path.parent / encoded_path
                if (
                    not artifact.is_file()
                    or len(encoded_hash) != 64
                    or _sha256(artifact) != encoded_hash
                ):
                    valid = False
                    break
                artifacts.append(artifact.stat().st_size / 1024)
            if valid:
                sizes[benchmark] = (artifacts[0], artifacts[1])
            else:
                _warn(
                    f"ignoring {benchmark} reproducer sizes: artifact provenance failed"
                )
    return sizes


def _configure_matplotlib() -> None:
    plt.rcParams.update(
        {
            "font.family": "Linux Libertine O",
            "font.size": 9,
            "axes.titlesize": 9,
            "axes.labelsize": 9,
            "xtick.labelsize": 8,
            "ytick.labelsize": 8,
            "legend.fontsize": 8,
            "pdf.fonttype": 42,
        }
    )


def _load_json_object(path: Path) -> dict[str, object] | None:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        _warn(f"ignoring evaluator artifacts beside {path}: {error}")
        return None
    if not isinstance(document, dict):
        _warn(f"ignoring evaluator artifacts beside {path}: metadata is not an object")
        return None
    return document


def _profile_document(
    system_directory: Path,
    encoded: dict[str, object],
    *,
    qemu: bool,
    relocation: tuple[Path, Path] | None = None,
) -> dict[str, object] | None:
    encoded_path = encoded.get("profile")
    encoded_hash = encoded.get("profileSha256")
    if not isinstance(encoded_path, str) or not isinstance(encoded_hash, str):
        return None
    profile = Path(encoded_path)
    if not profile.is_absolute():
        profile = system_directory / profile
    elif relocation is not None:
        old_root, new_root = relocation
        if profile.is_relative_to(old_root):
            relative = profile.relative_to(old_root)
            if ".." in relative.parts:
                _warn(f"ignoring profile with unsafe relocation path: {profile}")
                return None
            profile = new_root / relative
    if not profile.is_file() or _sha256(profile) != encoded_hash:
        _warn(f"ignoring profile with failed provenance: {profile}")
        return None
    document = _load_json_object(profile)
    if document is None or document.get("status") != "passed":
        return None
    if qemu and document.get("schema") != "focaccia-qemu-validation-profile-v1":
        _warn(f"ignoring QEMU profile with unsupported schema: {profile}")
        return None
    return document


def _evidence_path(
    encoded: object,
    system_directory: Path,
    relocation: tuple[Path, Path] | None,
) -> Path | None:
    if not isinstance(encoded, str):
        return None
    path = Path(encoded)
    if ".." in path.parts:
        return None
    if not path.is_absolute():
        return system_directory / path
    if relocation is not None and path.is_relative_to(relocation[0]):
        return relocation[1] / path.relative_to(relocation[0])
    return path


def _selective_application_evidence(
    system_directory: Path,
    encoded: dict[str, object],
    benchmark: str,
    relocation: tuple[Path, Path] | None,
) -> bool:
    report_path = _evidence_path(encoded.get("report"), system_directory, relocation)
    if report_path is None:
        return False
    report = _load_json_object(report_path)
    if report is None:
        return False
    report_hash = encoded.get("reportSha256")
    if report_hash is not None and _sha256(report_path) != report_hash:
        return False
    bounds = encoded.get("expectedMismatchRange")
    subject = encoded.get("expectedMismatchSubject")
    if bounds is None and encoded.get("expectedValidation") == "mismatch":
        # Legacy evaluator metadata did not retain its expected range. Recover it
        # from the hash-bound guest ELF, never from the observed mismatches.
        contracts = {
            "curl": ("focaccia_injection_curl_2175", "CF"),
            "lua": ("focaccia_injection_lua_2495", "R8"),
            "sqlite": ("focaccia_injection_sqlite_508", "RAX"),
        }
        contract = contracts.get(benchmark)
        binary = _evidence_path(encoded.get("binary"), system_directory, relocation)
        native = encoded.get("native")
        if (
            contract is None
            or binary is None
            or not binary.is_file()
            or _sha256(binary) != encoded.get("binarySha256")
            or not isinstance(native, dict)
        ):
            return False
        try:
            symbols = read_symbols(Path("nm"), binary)
        except (EvaluationError, OSError):
            return False
        bounds = [symbols.get(contract[0]), native.get("stopAddress")]
        subject = contract[1]
    try:
        require_selective_application_acceptance(
            report, encoded.get("expectedValidation"), bounds, subject
        )
    except EvaluationError as error:
        _warn(f"omitting {benchmark}: {error}")
        return False
    return True


def _csv_timing(
    rows: list[dict[str, str]],
    key: tuple[str, str, str, int],
) -> float | None:
    benchmark, mode, component, iteration = key
    matches = [
        row
        for row in rows
        if row.get("benchmark") == benchmark
        and row.get("mode") == mode
        and row.get("component") == component
        and row.get("iteration") == str(iteration)
        and row.get("status") == "passed"
    ]
    if len(matches) != 1:
        return None
    try:
        return float(matches[0]["seconds"])
    except (KeyError, TypeError, ValueError):
        return None


def _add_verified_profile(
    output: list[dict[str, str]],
    profile_keys: set[tuple[str, str, str, int]],
    csv_rows: list[dict[str, str]],
    system_directory: Path,
    encoded: dict[str, object],
    benchmark: str,
    mode: str,
    iteration: int,
    fields: dict[str, str],
    *,
    qemu: bool,
    relocation: tuple[Path, Path] | None = None,
) -> None:
    keys = {component: (benchmark, mode, component, iteration) for component in fields}
    profile_keys.update(keys.values())
    document = _profile_document(
        system_directory, encoded, qemu=qemu, relocation=relocation
    )
    if document is None:
        _warn(f"omitting {benchmark}/{mode} iteration {iteration}: profile unavailable")
        return
    timings = document.get("timings")
    if not isinstance(timings, dict):
        _warn(f"omitting {benchmark}/{mode} iteration {iteration}: timings missing")
        return
    verified: dict[str, float] = {}
    for component, field in fields.items():
        value = timings.get(field)
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
            break
        csv_value = _csv_timing(csv_rows, keys[component])
        if csv_value is None or not math.isclose(
            float(value), csv_value, rel_tol=1e-9, abs_tol=1e-12
        ):
            break
        verified[component] = float(value)
    if len(verified) != len(fields):
        _warn(
            f"omitting {benchmark}/{mode} iteration {iteration}: "
            "CSV and profile timings disagree"
        )
        return
    output.extend(
        {
            "benchmark": benchmark,
            "mode": mode,
            "component": component,
            "seconds": str(value),
            "iteration": str(iteration),
            "status": "passed",
            "detail": "",
        }
        for component, value in verified.items()
    )


def _verified_profile_rows(
    system_directory: Path,
    metadata: dict[str, object],
    csv_rows: list[dict[str, str]],
    relocation: tuple[Path, Path] | None = None,
) -> tuple[
    set[str],
    set[tuple[str, str, str, int]],
    list[dict[str, str]],
]:
    cases = metadata.get("cases")
    if not isinstance(cases, dict):
        return set(), set(), []
    role = metadata.get("role")
    allowed: set[str] = set()
    profile_keys: set[tuple[str, str, str, int]] = set()
    profile_rows: list[dict[str, str]] = []
    native_fields = {
        "concrete": "concreteSeconds",
        "symbolic": "symbolicSeconds",
        "validation": "validationSeconds",
        "total": "traceSeconds",
    }
    qemu_fields = {
        "execution": "executionSeconds",
        "tracing": "tracingSeconds",
        "validation": "validationSeconds",
        "serialization": "serializationSeconds",
        "total": "totalSeconds",
    }

    for identifier, case_value in cases.items():
        if not isinstance(identifier, str) or not isinstance(case_value, dict):
            continue
        if case_value.get("status") != "passed":
            continue
        benchmark = identifier if role == "native" else case_value.get("benchmark")
        if not isinstance(benchmark, str):
            _warn(f"ignoring {identifier}: evaluator metadata has no benchmark")
            continue
        allowed.add(benchmark)
        iterations = case_value.get("iterations")
        if not isinstance(iterations, list):
            continue
        for iteration, item_value in enumerate(iterations):
            if not isinstance(item_value, dict):
                continue
            if role == "native":
                captures = item_value.get("fullCaptures")
                if isinstance(captures, dict):
                    for mode, capture_value in captures.items():
                        if isinstance(mode, str) and isinstance(capture_value, dict):
                            before = len(profile_rows)
                            _add_verified_profile(
                                profile_rows,
                                profile_keys,
                                csv_rows,
                                system_directory,
                                capture_value,
                                benchmark,
                                mode,
                                iteration,
                                native_fields,
                                qemu=False,
                                relocation=relocation,
                            )
                            if len(profile_rows) != before:
                                profile = _profile_document(
                                    system_directory,
                                    capture_value,
                                    qemu=False,
                                    relocation=relocation,
                                )
                                timings = profile.get("timings") if profile else None
                                serialization = capture_value.get(
                                    "serializationSeconds"
                                )
                                capture = capture_value.get("captureProcessSeconds")
                                trace = (
                                    timings.get("traceSeconds")
                                    if isinstance(timings, dict)
                                    else None
                                )
                                profile_serialization = (
                                    timings.get("serializationSeconds")
                                    if isinstance(timings, dict)
                                    else None
                                )
                                if (
                                    isinstance(serialization, (int, float))
                                    and isinstance(capture, (int, float))
                                    and isinstance(trace, (int, float))
                                    and serialization == profile_serialization
                                    and capture >= trace + serialization
                                ):
                                    for component, value in (
                                        ("serialization", serialization),
                                        ("capture", capture),
                                        (
                                            "setup-residual",
                                            capture - trace - serialization,
                                        ),
                                    ):
                                        profile_rows.append(
                                            {
                                                "benchmark": benchmark,
                                                "mode": mode,
                                                "component": component,
                                                "seconds": str(value),
                                                "iteration": str(iteration),
                                                "status": "passed",
                                                "detail": "",
                                            }
                                        )
                                else:
                                    _warn(
                                        f"omitting end-to-end accounting for {benchmark}/{mode}: invalid or negative residual"
                                    )
                    continue
                mode = (
                    "native-selective"
                    if case_value.get("kind") == "application"
                    else "native-cross-validated"
                )
                _add_verified_profile(
                    profile_rows,
                    profile_keys,
                    csv_rows,
                    system_directory,
                    item_value,
                    benchmark,
                    mode,
                    iteration,
                    native_fields,
                    qemu=False,
                    relocation=relocation,
                )
            elif role == "qemu":
                mode = case_value.get("emulator")
                if isinstance(mode, str):
                    if benchmark in APPLICATIONS:
                        if not _selective_application_evidence(
                            system_directory, item_value, benchmark, relocation
                        ):
                            _warn(
                                f"omitting {benchmark}/{mode}: validation evidence failed"
                            )
                            continue
                    _add_verified_profile(
                        profile_rows,
                        profile_keys,
                        csv_rows,
                        system_directory,
                        item_value,
                        benchmark,
                        mode,
                        iteration,
                        qemu_fields,
                        qemu=True,
                        relocation=relocation,
                    )
    return allowed, profile_keys, profile_rows


def load_measurements(root: Path, *, relocate_from: Path | None = None) -> Measurements:
    if relocate_from is not None and (
        not relocate_from.is_absolute() or ".." in relocate_from.parts
    ):
        raise ValueError("relocate_from must be an absolute run root without '..'")
    relocation = (relocate_from, root) if relocate_from is not None else None
    paths = [
        *sorted((root / "native").glob("*/results.csv")),
        *sorted((root / "emulated" / "qemu").glob("*/results.csv")),
        *sorted((root / "emulated" / "box64").glob("*/results.csv")),
    ]
    if not paths:
        _warn(f"no evaluator results found under {root}")
        return Measurements([])
    rows: list[dict[str, str]] = []
    for path in paths:
        metadata = _load_json_object(path.with_name("metadata.json"))
        if metadata is None:
            continue
        relative_parts = path.relative_to(root).parts
        if relative_parts[0] == "native":
            expected_schema = NATIVE_METADATA_SCHEMA
            expected_role = "native"
            expected_system = relative_parts[1]
        else:
            expected_schema = EMULATED_METADATA_SCHEMA
            expected_role = relative_parts[1]
            expected_system = relative_parts[2]
        if (
            metadata.get("schema") != expected_schema
            or metadata.get("role") != expected_role
            or metadata.get("system") != expected_system
        ):
            _warn(f"ignoring evaluator artifacts with inconsistent metadata: {path}")
            continue
        with path.open(newline="", encoding="utf-8") as source:
            csv_rows = list(csv.DictReader(source))
        allowed, profile_keys, profile_rows = _verified_profile_rows(
            path.parent, metadata, csv_rows, relocation
        )
        for row in csv_rows:
            # Selective QEMU samples enter only via the report/profile gate;
            # never rescue stale, unknown-mode or extra-iteration CSV rows.
            try:
                key = (
                    row["benchmark"],
                    row["mode"],
                    row["component"],
                    int(row["iteration"]),
                )
            except (KeyError, TypeError, ValueError):
                continue
            if (
                row.get("benchmark") in allowed
                and key not in profile_keys
                and not (
                    expected_role == "qemu" and row.get("benchmark") in APPLICATIONS
                )
            ):
                rows.append({**row, "system": expected_system})
        rows.extend({**row, "system": expected_system} for row in profile_rows)
    return Measurements(rows)


def _save(fig: plt.Figure, output: Path, name: str) -> Path:
    destination = output / name
    fig.savefig(destination, bbox_inches="tight", metadata=FIXED_METADATA)
    plt.close(fig)
    return destination


def plot_trigger_overhead(data: Measurements, output: Path) -> Path | None:
    component_names = ("concrete", "symbolic", "validation")
    qemu_names = ("execution", "tracing", "validation")
    grouped: list[
        tuple[str, list[str], list[tuple[float, ...]], list[tuple[float, ...]]]
    ] = []
    omitted: list[str] = []

    for category, benchmarks in TRIGGER_GROUPS:
        labels: list[str] = []
        native_rows: list[tuple[float, ...]] = []
        qemu_rows: list[tuple[float, ...]] = []
        for benchmark in benchmarks:
            baseline = data.get(benchmark, "native", "execution")
            native = data.components(
                benchmark, "native-cross-validated", component_names
            )
            qemu_mode = data.qemu_mode(benchmark, qemu_names)
            qemu_profile = (
                data.components(benchmark, qemu_mode, qemu_names)
                if qemu_mode is not None
                else None
            )
            qemu = (
                (qemu_profile[0] + qemu_profile[1], 0.0, qemu_profile[2])
                if qemu_profile is not None
                else None
            )
            if baseline is None or baseline <= 0 or native is None or qemu is None:
                omitted.append(benchmark)
                continue
            labels.append(f"#{benchmark}")
            native_rows.append(tuple(value / baseline for value in native))
            qemu_rows.append(tuple(value / baseline for value in qemu))
        if labels:
            grouped.append((category, labels, native_rows, qemu_rows))

    if omitted:
        _warn(f"trigger overhead omits incomplete cases: {', '.join(omitted)}")
    if not grouped:
        _warn(
            "not generating split-overhead-breakdown.pdf: no complete trigger samples"
        )
        return None

    widths = [max(len(labels), 0.35) for _, labels, _, _ in grouped]
    figure = plt.figure(figsize=(PAPER_TWO_COLUMN[0], 1.5))
    grid = GridSpec(2, len(grouped), width_ratios=widths, figure=figure)
    native_axes: list[plt.Axes] = []
    qemu_axes: list[plt.Axes] = []
    legend_labels = ("Concrete", "Symbolic", "Validation")
    paper_hatches = ("\\", "x", "O")
    all_native = [sum(row) for _, _, rows, _ in grouped for row in rows]
    all_qemu = [sum(row) for _, _, _, rows in grouped for row in rows]
    native_limit = max(all_native) * 1.08
    qemu_limit = max(all_qemu) * 1.08
    handles: list[object] = []

    for column, (category, labels, native_rows, qemu_rows) in enumerate(grouped):
        native_axis = figure.add_subplot(grid[0, column])
        qemu_axis = figure.add_subplot(grid[1, column])
        native_axes.append(native_axis)
        qemu_axes.append(qemu_axis)
        for axis in (native_axis, qemu_axis):
            axis.spines[["top", "right"]].set_visible(False)
        if column:
            for axis in (native_axis, qemu_axis):
                axis.spines["left"].set_visible(False)
                axis.set_yticks([])

        for axis, rows in ((native_axis, native_rows), (qemu_axis, qemu_rows)):
            values = np.asarray(rows)
            positions = np.arange(len(labels))
            bottom = np.zeros(len(labels))
            for index, legend_label in enumerate(legend_labels):
                bars = axis.bar(
                    positions,
                    values[:, index],
                    bottom=bottom,
                    width=0.4,
                    color=COLORS[index],
                    edgecolor="black",
                    linewidth=0.6,
                    hatch=paper_hatches[index],
                    label=legend_label,
                )
                if column == 0 and axis is native_axis:
                    handles.append(bars)
                bottom += values[:, index]

        native_axis.set_ylim(0, native_limit)
        native_axis.set_xticks([])
        qemu_axis.set_ylim(0, qemu_limit)
        qemu_axis.set_xticks(np.arange(len(labels)), labels, fontsize=7)
        qemu_axis.set_xlabel(category)

    figure.supylabel("Overhead", x=0.01, y=0.58)
    figure.text(0.045, 0.78, "Native", rotation=90, va="center", ha="center")
    figure.text(0.045, 0.37, "QEMU", rotation=90, va="center", ha="center")
    figure.legend(
        handles,
        legend_labels,
        loc="upper center",
        bbox_to_anchor=(0.5, 1.09),
        ncol=3,
        frameon=False,
    )
    figure.tight_layout()
    return _save(figure, output, "split-overhead-breakdown.pdf")


def plot_selective_applications(data: Measurements, output: Path) -> Path | None:
    native_names = ("concrete", "symbolic", "validation")
    qemu_names = ("execution", "tracing", "validation")
    applications: list[str] = []
    native_rows: list[tuple[float, ...]] = []
    qemu_rows: list[tuple[float, ...]] = []
    omitted: list[str] = []

    for application in APPLICATIONS:
        native = data.components(application, "native-selective", native_names)
        qemu_mode = data.qemu_mode(application, qemu_names)
        qemu_profile = (
            data.components(application, qemu_mode, qemu_names)
            if qemu_mode is not None
            else None
        )
        qemu = (
            (qemu_profile[0] + qemu_profile[1], 0.0, qemu_profile[2])
            if qemu_profile is not None
            else None
        )
        if native is None or qemu is None:
            omitted.append(application)
            continue
        applications.append(application.capitalize())
        native_rows.append(tuple(value / 60 for value in native))
        qemu_rows.append(tuple(value / 60 for value in qemu))

    if omitted:
        _warn(
            f"selective application figure omits incomplete cases: {', '.join(omitted)}"
        )
    if not applications:
        _warn(
            "not generating realworld-split-overhead-breakdown.pdf: "
            "no complete application samples"
        )
        return None

    figure, axes = plt.subplots(
        len(applications) * 2,
        figsize=(PAPER_ONE_COLUMN[0], 2.3),
        sharex=True,
    )
    hatches = ("\\", "x", "O")
    labels = ("Concrete", "Symbolic", "Validation")
    handles: list[object] = []
    all_rows = native_rows + qemu_rows
    maximum = max(sum(row) for row in all_rows) * 1.1

    for mode_index, rows in enumerate((native_rows, qemu_rows)):
        for application_index, (application, values) in enumerate(
            zip(applications, rows)
        ):
            axis_index = mode_index * len(applications) + application_index
            axis = axes[axis_index]
            left = 0.0
            for component_index, value in enumerate(values):
                bars = axis.barh(
                    0,
                    value,
                    left=left,
                    height=0.25,
                    color=COLORS[component_index],
                    edgecolor="black",
                    linewidth=0.6,
                    hatch=hatches[component_index],
                )
                if axis_index == 0:
                    handles.append(bars[0])
                left += value
            axis.text(left, 0, f" {int(left)}", va="center", ha="left", fontsize=8)
            axis.set_ylabel(
                application, fontsize=8, rotation=0, va="center", ha="right"
            )
            axis.set_yticks([])
            axis.set_xticks([])
            axis.spines[:].set_visible(False)
            axis.set_xlim(0, maximum)

    axes[-1].spines["bottom"].set_visible(True)
    axes[-1].spines["bottom"].set_position(("outward", 6))
    axes[-1].set_xlabel("minutes")
    axes[-1].xaxis.set_major_locator(MultipleLocator(5))
    axes[-1].tick_params(axis="x", labelsize=7)
    for axis in axes[:-1]:
        axis.tick_params(axis="x", length=0, labelbottom=False)

    figure.text(0.02, 0.74, "Native", rotation=90, va="center", ha="center")
    figure.text(0.02, 0.36, "QEMU", rotation=90, va="center", ha="center")
    axes[0].legend(
        handles,
        labels,
        loc="lower right",
        bbox_to_anchor=(1, 1),
        ncol=3,
        columnspacing=0.9,
        handletextpad=0.4,
        frameon=False,
        fontsize=8,
    )
    native_bottom = axes[len(applications) - 1].get_position().y0
    qemu_top = axes[len(applications)].get_position().y1
    separator = (native_bottom + qemu_top) / 2 + 0.05
    figure.add_artist(
        plt.Line2D(
            [0.1, 0.97],
            [separator, separator],
            transform=figure.transFigure,
            linestyle="--",
            linewidth=0.8,
            color="black",
        )
    )
    figure.tight_layout()
    return _save(figure, output, "realworld-split-overhead-breakdown.pdf")


def application_trend_ratios(
    data: Measurements,
) -> tuple[list[str], list[float], list[float]]:
    """Return paper/current QEMU-to-native ratios on one shared definition."""
    labels: list[str] = []
    paper: list[float] = []
    current: list[float] = []
    for application in APPLICATIONS:
        native = data.components(
            application, "native-selective", ("concrete", "symbolic", "validation")
        )
        qemu_mode = data.qemu_mode(application, ("execution", "tracing", "validation"))
        qemu = (
            data.components(
                application, qemu_mode, ("execution", "tracing", "validation")
            )
            if qemu_mode is not None
            else None
        )
        if native is None or qemu is None:
            continue
        paper_native, paper_qemu = PAPER_APPLICATION_COMPONENTS[application]
        labels.append(application.capitalize())
        paper.append(sum(paper_qemu) / sum(paper_native))
        current.append(sum(qemu) / sum(native))
    return labels, paper, current


def plot_application_trends(data: Measurements, output: Path) -> Path | None:
    labels, paper, current = application_trend_ratios(data)
    if not labels:
        _warn("not generating application-trend-ratios.pdf: no complete samples")
        return None

    positions = np.arange(len(labels))
    width = 0.36
    figure, axis = plt.subplots(figsize=PAPER_ONE_COLUMN)
    axis.bar(positions - width / 2, paper, width, label="Paper", color=COLORS[0])
    axis.bar(positions + width / 2, current, width, label="Current", color=COLORS[1])
    axis.set_xticks(positions, labels)
    axis.set_ylabel("QEMU / native runtime")
    axis.axhline(1, color="black", linewidth=0.7)
    axis.legend(frameon=False)
    axis.set_ylim(0, max(paper + current) * 1.12)
    figure.tight_layout()
    return _save(figure, output, "application-trend-ratios.pdf")


def plot_full_curl(data: Measurements, output: Path) -> Path | None:
    native_names = ("concrete", "symbolic", "validation")
    qemu_names = ("execution", "tracing", "validation")
    cross_validated = data.components(
        "curl-full", "native-full-cross-validated", native_names
    )
    speculative = data.components("curl-full", "native-full-speculative", native_names)
    qemu_mode = data.qemu_mode("curl-full", qemu_names)
    qemu_profile = (
        data.components("curl-full", qemu_mode, qemu_names)
        if qemu_mode is not None
        else None
    )
    qemu = (
        (qemu_profile[0] + qemu_profile[1], 0.0, qemu_profile[2])
        if qemu_profile is not None
        else None
    )
    if cross_validated is None or speculative is None or qemu is None:
        _warn(
            "not generating tracing-comparison.pdf: full Curl measurements are incomplete"
        )
        return None

    rows = np.asarray((cross_validated, speculative, qemu)) / 60
    labels = ("Cross\nValidated", "Speculative", "QEMU")
    components = (
        "Concrete (exclusive)",
        "Symbolic (exclusive)",
        "Validation (exclusive)",
    )
    hatches = ("\\", "x", "O")
    figure, axes = plt.subplots(3, figsize=(PAPER_ONE_COLUMN[0], 1.55), sharex=True)
    handles: list[object] = []
    maximum = max(sum(row) for row in rows) * 1.1

    for row_index, (axis, label, values) in enumerate(zip(axes, labels, rows)):
        left = 0.0
        for component_index, value in enumerate(values):
            bars = axis.barh(
                0,
                value,
                left=left,
                height=0.22,
                color=COLORS[component_index],
                edgecolor="black",
                linewidth=0.6,
                hatch=hatches[component_index],
            )
            if row_index == 0:
                handles.append(bars[0])
            left += value
        mode = (
            "native-full-cross-validated",
            "native-full-speculative",
            qemu_mode,
        )[row_index]
        wall = data.get("curl-full", mode, "capture" if row_index < 2 else "total")
        suffix = f"; end-to-end {wall / 60:.2f}" if wall is not None else ""
        axis.text(
            left,
            0,
            f" {left:.2f} exclusive{suffix}",
            va="center",
            ha="left",
            fontsize=7,
        )
        axis.set_ylabel(label, fontsize=8, rotation=0, va="center", ha="right")
        axis.set_yticks([])
        axis.set_xticks([])
        axis.spines[:].set_visible(False)
        axis.set_xlim(0, maximum)

    axes[0].legend(
        handles,
        components,
        loc="lower right",
        bbox_to_anchor=(1, 1),
        ncol=3,
        columnspacing=0.9,
        handletextpad=0.4,
        frameon=False,
    )
    axes[-1].spines["bottom"].set_visible(True)
    axes[-1].spines["bottom"].set_position(("outward", 6))
    axes[-1].set_xlabel("minutes")
    axes[-1].xaxis.set_major_locator(MultipleLocator(10))
    axes[-1].tick_params(axis="x", labelsize=7)
    for axis in axes[:-1]:
        axis.tick_params(axis="x", length=0, labelbottom=False)

    separator = (axes[1].get_position().y0 + axes[2].get_position().y1) / 2 + 0.125
    figure.add_artist(
        plt.Line2D(
            [0.17, 0.97],
            [separator, separator],
            transform=figure.transFigure,
            linestyle="--",
            linewidth=0.8,
            color="black",
        )
    )
    figure.tight_layout()
    return _save(figure, output, "tracing-comparison.pdf")


def plot_reproducer_sizes(
    sizes: dict[str, tuple[float, float]], output: Path
) -> Path | None:
    available = [
        (category, benchmark, sizes[benchmark])
        for category, benchmarks in REPRODUCER_GROUPS
        for benchmark in benchmarks
        if benchmark in sizes
    ]
    missing = [
        benchmark
        for _, benchmarks in REPRODUCER_GROUPS
        for benchmark in benchmarks
        if benchmark not in sizes
    ]
    if missing:
        _warn(f"reproducer size figure omits incomplete cases: {', '.join(missing)}")
    if not available:
        _warn("not generating reproducer-code-size.pdf: no verified size evidence")
        return None

    category_counts = [
        sum(1 for item in available if item[0] == category)
        for category, _ in REPRODUCER_GROUPS
    ]
    populated = [
        (category, count)
        for (category, _), count in zip(REPRODUCER_GROUPS, category_counts)
        if count
    ]
    fig, axes_value = plt.subplots(
        1,
        len(populated),
        figsize=(PAPER_TWO_COLUMN[0], 1.5),
        squeeze=False,
        gridspec_kw={"width_ratios": [count for _, count in populated]},
    )
    axes = axes_value[0]
    maximum = max(50.0, max(max(values) for _, _, values in available) * 1.15)
    for axis_index, (category, _) in enumerate(populated):
        axis = axes[axis_index]
        category_rows = [item for item in available if item[0] == category]
        x = np.arange(len(category_rows))
        guest = np.asarray([values[0] for _, _, values in category_rows])
        minimized = np.asarray([values[1] for _, _, values in category_rows])
        width = 0.35
        axis.bar(
            x - width / 2,
            guest,
            width,
            color=COLORS[0],
            edgecolor="black",
            linewidth=0.6,
            hatch="/",
        )
        axis.bar(
            x + width / 2,
            minimized,
            width,
            color=COLORS[1],
            edgecolor="black",
            linewidth=0.6,
            hatch="o",
        )
        for position, value in zip(x - width / 2, guest):
            axis.text(
                position,
                value,
                f"{value:.1f}",
                ha="center",
                va="bottom",
                fontsize=7,
            )
        axis.set_xticks(
            x,
            [
                "SQLite" if benchmark == "sqlite" else f"#{benchmark}"
                for _, benchmark, _ in category_rows
            ],
        )
        axis.set_xlabel(category)
        axis.set_ylim(0, maximum)
        axis.spines[["top", "right"]].set_visible(False)
        if axis_index:
            axis.spines["left"].set_visible(False)
            axis.set_yticks([])
        else:
            axis.set_ylabel("Size (KiB)")
    fig.legend(
        handles=[
            Patch(
                facecolor=COLORS[0],
                edgecolor="black",
                hatch="/",
                label="Guest program",
            ),
            Patch(
                facecolor=COLORS[1],
                edgecolor="black",
                hatch="o",
                label="Minimized program",
            ),
        ],
        loc="upper center",
        bbox_to_anchor=(0.5, 1.09),
        ncol=2,
        frameon=False,
    )
    fig.tight_layout()
    return _save(fig, output, "reproducer-code-size.pdf")


def _plot_bug_study_bar(
    axis: plt.Axes,
    sizes: tuple[int, ...],
    emulator: str,
    colors: list[tuple[float, float, float]] | tuple[str, ...],
    hatches: tuple[str, ...],
    *,
    labels_above: bool,
) -> list[object]:
    cumulative = np.cumsum((0, *sizes[:-1]))
    bars: list[object] = []
    for index, (size, color, hatch) in enumerate(zip(sizes, colors, hatches)):
        bar = axis.barh(
            0,
            size,
            left=cumulative[index],
            color=color,
            edgecolor="black",
            linewidth=0.6,
            height=0.22,
            hatch=hatch,
        )[0]
        bars.append(bar)
        axis.text(
            cumulative[index] + size / 2,
            bar.get_height() - 0.1 if labels_above else -0.16,
            f"{size}%",
            va="bottom" if labels_above else "top",
            ha="center",
            color="black",
            fontweight="bold",
            fontsize=9,
        )
    axis.set_xlim(0, sum(sizes))
    axis.set_ylabel(
        emulator, rotation=0, va="center", ha="right", multialignment="left"
    )
    axis.set_yticks([])
    axis.set_xticks([])
    axis.spines[:].set_visible(False)
    return bars


def plot_combined_bug_study(output: Path) -> Path:
    """Plot the paper's fixed, manually reviewed bug-study percentages."""
    fig = plt.figure(figsize=(PAPER_TWO_COLUMN[0], 3.3))
    grid = fig.add_gridspec(4, 2, width_ratios=(1, 30))
    box64_axis = fig.add_subplot(grid[0, :])
    qemu_axis = fig.add_subplot(grid[1, :])
    breakdown_axis = fig.add_subplot(grid[2, 1:])

    error_hatches = ("\\\\", "OO", "xx")
    box64_bars = _plot_bug_study_bar(
        box64_axis,
        BUG_STUDY_BOX64,
        "Box64",
        COLORS[:3],
        error_hatches,
        labels_above=True,
    )
    qemu_bars = _plot_bug_study_bar(
        qemu_axis,
        BUG_STUDY_QEMU,
        "QEMU",
        COLORS[:3],
        error_hatches,
        labels_above=True,
    )
    breakdown_bars = _plot_bug_study_bar(
        breakdown_axis,
        BUG_STUDY_QEMU_MISTRANSLATIONS,
        "QEMU\nmistranslation\nbreakdown",
        BUG_STUDY_MISTRANSLATION_COLORS,
        BUG_STUDY_MISTRANSLATION_HATCHES,
        labels_above=False,
    )

    box64_axis.legend(
        box64_bars + qemu_bars,
        BUG_STUDY_ERROR_LABELS,
        loc="lower center",
        bbox_to_anchor=(0.5, 0.9),
        bbox_transform=fig.transFigure,
        ncol=3,
        frameon=False,
    )
    breakdown_axis.legend(
        breakdown_bars,
        BUG_STUDY_MISTRANSLATION_LABELS,
        loc="upper center",
        bbox_to_anchor=(0.5, 0.2),
        bbox_transform=fig.transFigure,
        ncol=3,
        frameon=False,
    )

    mistranslation_index = 1
    qemu_mistranslations = qemu_bars[mistranslation_index]
    first_breakdown = breakdown_bars[0]
    final_breakdown = breakdown_bars[-1]
    left_connection = ConnectionPatch(
        xyA=(qemu_mistranslations.get_x(), qemu_mistranslations.get_y()),
        coordsA=qemu_axis.transData,
        xyB=(
            first_breakdown.get_x(),
            first_breakdown.get_y() + first_breakdown.get_height(),
        ),
        coordsB=breakdown_axis.transData,
        color="black",
        linewidth=1,
        linestyle="--",
    )
    right_connection = ConnectionPatch(
        xyA=(
            qemu_mistranslations.get_x() + qemu_mistranslations.get_width(),
            qemu_mistranslations.get_y(),
        ),
        coordsA=qemu_axis.transData,
        xyB=(
            final_breakdown.get_x() + final_breakdown.get_width(),
            final_breakdown.get_y() + final_breakdown.get_height(),
        ),
        coordsB=breakdown_axis.transData,
        color="black",
        linewidth=1,
        linestyle="--",
    )
    fig.add_artist(left_connection)
    fig.add_artist(right_connection)
    fig.subplots_adjust(left=0.12, right=0.98, top=0.86, bottom=0.24, hspace=0.38)
    return _save(fig, output, "combined-bug-study.pdf")


def write_timing_accounting(data: Measurements, output: Path) -> Path:
    """Write denominators without converting exclusive components into wall time."""
    cases: dict[str, object] = {}
    modes = (
        (
            "native-cross-validated",
            "curl-full",
            "native-full-cross-validated",
            ("concrete", "symbolic", "validation"),
            "capture",
        ),
        (
            "native-speculative",
            "curl-full",
            "native-full-speculative",
            ("concrete", "symbolic", "validation"),
            "capture",
        ),
    )
    for label, benchmark, mode, names, wall_name in modes:
        components = data.components(benchmark, mode, names)
        trace = data.get(benchmark, mode, "total")
        serialization = data.get(benchmark, mode, "serialization")
        wall = data.get(benchmark, mode, wall_name)
        if components is None or trace is None:
            continue
        trace_residual = trace - sum(components)
        if trace_residual < 0:
            raise ValueError(f"negative trace residual for {benchmark}/{mode}")
        entry: dict[str, object] = {
            "exclusiveComponentsSeconds": dict(zip(names, components)),
            "exclusiveSumSeconds": sum(components),
            "traceWallSeconds": trace,
            "traceResidualSeconds": trace_residual,
        }
        if serialization is not None and wall is not None:
            if wall - trace - serialization < 0:
                raise ValueError(f"negative setup residual for {benchmark}/{mode}")
            entry.update(
                {
                    "serializationSeconds": serialization,
                    "setupResidualSeconds": wall - trace - serialization,
                    "endToEndWallSeconds": wall,
                }
            )
        cases[label] = entry
    cross = cases.get("native-cross-validated")
    speculative = cases.get("native-speculative")
    speedups: dict[str, float] = {}
    if isinstance(cross, dict) and isinstance(speculative, dict):
        for key, label in (
            ("exclusiveSumSeconds", "exclusiveComponents"),
            ("traceWallSeconds", "traceWall"),
            ("endToEndWallSeconds", "endToEndWall"),
        ):
            if key in cross and key in speculative:
                speedups[label] = float(cross[key]) / float(speculative[key])
    document = {
        "schema": "focaccia-timing-accounting-v1",
        "componentContract": "exclusive-components-v1",
        "paperLegacy": {
            "equivalentToCurrentAccounting": False,
            "note": "Hard-coded rounded legacy counters; raw end-to-end wall and serialization boundary are unavailable.",
            "nativeCrossValidatedMinutes": [28, 9, 1],
            "nativeSpeculativeMinutes": [4, 9, 0],
        },
        "cases": cases,
        "speedups": speedups,
    }
    destination = output / ACCOUNTING_NAME
    destination.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    return destination


def make_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input", type=Path, required=True, help="Completed evaluator run root"
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Figure directory (default: <input>/figures)",
    )
    parser.add_argument(
        "--relocate-from",
        type=Path,
        metavar="OLD_RUN_ROOT",
        help="Explicitly map absolute profile paths under this old root to --input",
    )
    parser.add_argument(
        "--reproducer-sizes",
        type=Path,
        help=(
            "Specialized, hash-bound reproducer size evidence; "
            "runtime results never supply code sizes"
        ),
    )
    return parser


def main() -> int:
    parser = make_argparser()
    args = parser.parse_args()
    if args.relocate_from is not None and (
        not args.relocate_from.is_absolute() or ".." in args.relocate_from.parts
    ):
        parser.error("--relocate-from must be an absolute run root without '..'")
    try:
        measurements = load_measurements(args.input, relocate_from=args.relocate_from)
    except ValueError as error:
        parser.error(str(error))
    output = args.output or args.input / "figures"
    output.mkdir(parents=True, exist_ok=True)
    for name in (*FIGURE_NAMES, ACCOUNTING_NAME):
        (output / name).unlink(missing_ok=True)
    _configure_matplotlib()
    generated = [
        figure
        for figure in (
            plot_trigger_overhead(measurements, output),
            plot_full_curl(measurements, output),
            plot_selective_applications(measurements, output),
            plot_application_trends(measurements, output),
            plot_reproducer_sizes(load_reproducer_sizes(args.reproducer_sizes), output),
            plot_combined_bug_study(output),
        )
        if figure is not None
    ]
    generated.append(write_timing_accounting(measurements, output))
    for figure in generated:
        print(figure)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
