#!/usr/bin/env python3

"""Generate evaluation figures from one retained evaluator run.

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
from matplotlib.patches import ConnectionPatch, Patch


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
FIGURE_NAMES = (
    "split-overhead-breakdown.pdf",
    "tracing-comparison.pdf",
    "realworld-split-overhead-breakdown.pdf",
    "reproducer-code-size.pdf",
    "combined-bug-study.pdf",
)

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
    if (
        not isinstance(revision, str)
        or len(revision) != 40
        or any(character not in "0123456789abcdef" for character in revision)
    ):
        _warn(f"not using reproducer size evidence {path}: invalid Focaccia revision")
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
) -> dict[str, object] | None:
    encoded_path = encoded.get("profile")
    encoded_hash = encoded.get("profileSha256")
    if not isinstance(encoded_path, str) or not isinstance(encoded_hash, str):
        return None
    profile = Path(encoded_path)
    if not profile.is_absolute():
        profile = system_directory / profile
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
) -> None:
    keys = {component: (benchmark, mode, component, iteration) for component in fields}
    profile_keys.update(keys.values())
    document = _profile_document(system_directory, encoded, qemu=qemu)
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
                )
            elif role == "qemu":
                mode = case_value.get("emulator")
                if isinstance(mode, str):
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
                    )
    return allowed, profile_keys, profile_rows


def load_measurements(root: Path) -> Measurements:
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
            path.parent, metadata, csv_rows
        )
        for row in csv_rows:
            try:
                key = (
                    row["benchmark"],
                    row["mode"],
                    row["component"],
                    int(row["iteration"]),
                )
            except (KeyError, TypeError, ValueError):
                continue
            if row.get("benchmark") in allowed and key not in profile_keys:
                rows.append(row)
        rows.extend(profile_rows)
    return Measurements(rows)


def _save(fig: plt.Figure, output: Path, name: str) -> Path:
    destination = output / name
    fig.savefig(destination, bbox_inches="tight", metadata=FIXED_METADATA)
    plt.close(fig)
    return destination


def plot_trigger_overhead(data: Measurements, output: Path) -> Path | None:
    component_names = ("concrete", "symbolic", "validation")
    qemu_names = ("execution", "tracing", "validation")
    labels: list[str] = []
    categories: list[str] = []
    native_rows: list[tuple[float, ...]] = []
    qemu_rows: list[tuple[float, ...]] = []
    omitted: list[str] = []

    for category, benchmarks in TRIGGER_GROUPS:
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
            categories.append(category)
            native_rows.append(tuple(value / baseline for value in native))
            qemu_rows.append(tuple(value / baseline for value in qemu))

    if omitted:
        _warn(f"trigger overhead omits incomplete cases: {', '.join(omitted)}")
    if not labels:
        _warn(
            "not generating split-overhead-breakdown.pdf: no complete trigger samples"
        )
        return None

    fig, axes = plt.subplots(2, 1, figsize=PAPER_TWO_COLUMN, sharex=True)
    x = np.arange(len(labels))
    legend_labels = ("Concrete execution", "Symbolic/trace collection", "Validation")
    for axis, rows, title in zip(axes, (native_rows, qemu_rows), ("Native", "QEMU")):
        values = np.asarray(rows)
        bottom = np.zeros(len(labels))
        for index, legend_label in enumerate(legend_labels):
            axis.bar(
                x,
                values[:, index],
                bottom=bottom,
                color=COLORS[index],
                edgecolor="black",
                linewidth=0.6,
                hatch=HATCHES[index],
                label=legend_label,
            )
            bottom += values[:, index]
        axis.set_ylabel(title, rotation=0, ha="right", va="center")
        axis.spines[["top", "right"]].set_visible(False)
        axis.grid(axis="y", linewidth=0.3, alpha=0.4)

    axes[-1].set_xticks(x, labels)
    axes[-1].set_ylabel("QEMU", rotation=0, ha="right", va="center")
    fig.supylabel("Overhead (× native execution)", x=0.01)
    axes[0].legend(
        loc="upper center", bbox_to_anchor=(0.5, 1.42), ncol=3, frameon=False
    )

    previous = None
    start = 0
    for index, category in enumerate(categories + [""]):
        if previous is None:
            previous = category
        if category != previous:
            center = (start + index - 1) / 2
            axes[-1].text(
                center,
                -0.34,
                previous,
                ha="center",
                va="top",
                transform=axes[-1].get_xaxis_transform(),
            )
            if index < len(categories):
                for axis in axes:
                    axis.axvline(index - 0.5, color="black", linewidth=0.4, alpha=0.5)
            start = index
            previous = category
    fig.subplots_adjust(bottom=0.24, top=0.84, hspace=0.18)
    return _save(fig, output, "split-overhead-breakdown.pdf")


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

    fig, axis = plt.subplots(figsize=PAPER_ONE_COLUMN)
    x = np.arange(len(applications))
    width = 0.36
    for offset, rows, mode_label in (
        (-width / 2, native_rows, "Native"),
        (width / 2, qemu_rows, "QEMU"),
    ):
        values = np.asarray(rows)
        bottom = np.zeros(len(applications))
        for index in range(3):
            axis.bar(
                x + offset,
                values[:, index],
                width,
                bottom=bottom,
                color=COLORS[index],
                edgecolor="black",
                linewidth=0.6,
                hatch=HATCHES[index] if mode_label == "Native" else None,
            )
            bottom += values[:, index]
        for position, total in zip(x + offset, bottom):
            axis.text(
                position, total, f"{total:.1f}", ha="center", va="bottom", fontsize=7
            )

    axis.set_xticks(x, applications)
    axis.set_ylabel("minutes")
    axis.spines[["top", "right"]].set_visible(False)
    component_legend = [
        Patch(
            facecolor=COLORS[index],
            edgecolor="black",
            hatch=HATCHES[index],
            label=label,
        )
        for index, label in enumerate(("Concrete", "Symbolic/trace", "Validation"))
    ]
    mode_legend = [
        Patch(facecolor="white", edgecolor="black", hatch="//", label="Native"),
        Patch(facecolor="white", edgecolor="black", label="QEMU"),
    ]
    axis.legend(
        handles=component_legend + mode_legend,
        loc="upper center",
        bbox_to_anchor=(0.5, 1.3),
        ncol=3,
        frameon=False,
    )
    fig.tight_layout()
    return _save(fig, output, "realworld-split-overhead-breakdown.pdf")


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

    values = np.asarray((cross_validated, speculative, qemu)) / 60
    labels = ("Cross-validated", "Speculative", "QEMU")
    fig, axis = plt.subplots(figsize=(PAPER_ONE_COLUMN[0], 1.7))
    y = np.arange(3)
    left = np.zeros(3)
    for index, component in enumerate(("Concrete", "Symbolic/trace", "Validation")):
        axis.barh(
            y,
            values[:, index],
            left=left,
            color=COLORS[index],
            edgecolor="black",
            linewidth=0.6,
            hatch=HATCHES[index],
            label=component,
        )
        left += values[:, index]
    for position, total in zip(y, left):
        axis.text(total, position, f" {total:.1f}", va="center", fontsize=7)
    axis.set_yticks(y, labels)
    axis.invert_yaxis()
    axis.set_xlabel("minutes")
    axis.spines[["top", "right", "left"]].set_visible(False)
    axis.legend(loc="lower center", bbox_to_anchor=(0.5, 1.02), ncol=3, frameon=False)
    fig.tight_layout()
    return _save(fig, output, "tracing-comparison.pdf")


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
        figsize=PAPER_TWO_COLUMN,
        squeeze=False,
        gridspec_kw={"width_ratios": [count for _, count in populated]},
    )
    axes = axes_value[0]
    maximum = 50.0
    clipped_maximum = maximum - 1.0
    for axis_index, (category, _) in enumerate(populated):
        axis = axes[axis_index]
        category_rows = [item for item in available if item[0] == category]
        x = np.arange(len(category_rows))
        guest = np.asarray([values[0] for _, _, values in category_rows])
        minimized = np.asarray([values[1] for _, _, values in category_rows])
        width = 0.35
        axis.bar(
            x - width / 2,
            np.minimum(guest, clipped_maximum),
            width,
            color=COLORS[0],
            edgecolor="black",
            linewidth=0.6,
            hatch="//",
        )
        axis.bar(
            x + width / 2,
            np.minimum(minimized, clipped_maximum),
            width,
            color=COLORS[1],
            edgecolor="black",
            linewidth=0.6,
            hatch="OO",
        )
        for position, value in zip(x - width / 2, guest):
            axis.text(
                position,
                min(value, clipped_maximum),
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
                hatch="//",
                label="Guest program",
            ),
            Patch(
                facecolor=COLORS[1],
                edgecolor="black",
                hatch="OO",
                label="Minimized program",
            ),
        ],
        loc="upper center",
        bbox_to_anchor=(0.5, 1.02),
        ncol=2,
        frameon=False,
    )
    fig.tight_layout(rect=(0, 0, 1, 0.91))
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
        "--reproducer-sizes",
        type=Path,
        help=(
            "Specialized, hash-bound reproducer size evidence; "
            "runtime results never supply code sizes"
        ),
    )
    return parser


def main() -> int:
    args = make_argparser().parse_args()
    output = args.output or args.input / "figures"
    output.mkdir(parents=True, exist_ok=True)
    for name in FIGURE_NAMES:
        (output / name).unlink(missing_ok=True)
    _configure_matplotlib()
    measurements = load_measurements(args.input)
    generated = [
        figure
        for figure in (
            plot_trigger_overhead(measurements, output),
            plot_full_curl(measurements, output),
            plot_selective_applications(measurements, output),
            plot_reproducer_sizes(load_reproducer_sizes(args.reproducer_sizes), output),
            plot_combined_bug_study(output),
        )
        if figure is not None
    ]
    for figure in generated:
        print(figure)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
