"""Diagnostics for the three-organization (US/UK/YT) leave-one-out cold-start
experiment implemented in ``moniotr_cross_lab.py`` (Sec. V-D of the paper).

These do not change the primary result in ``leave_one_out_three_lab.csv``;
they investigate the large F1 asymmetry between YT-as-receiver and
US/UK-as-receiver observed there:

1. Reference-set size diagnostic -- tests whether YT's single-day,
   40-PCAP-capped capture produces much smaller per-device ground-truth
   reference sets than US/UK's multi-day captures, which would make
   precision/recall/F1 more volatile per device for YT.
2. Bootstrap CI on macro-F1 -- resamples the 6 shared device types with
   replacement to quantify how much the reported macro-F1 could move by
   chance given only 6 devices contribute to the macro average.
3. Leave-one-device-out (LODO) sensitivity -- shows how much any single
   device type drives the reported 6-device macro-F1.
4. Window-normalized variant -- truncates Mon(IoT)r US/UK to the same
   single UTC calendar day YourThings covers, and reruns the three-lab
   leave-one-out on that truncated aggregate, to check whether the
   asymmetry is a capture-window artifact rather than a property of the
   admission rule.

Each analysis reuses ``load``, ``load_label_mapping``, ``collapse_site_three``,
``per_device_metrics``, ``leave_one_out_generalized``, and ``mean`` from
``moniotr_cross_lab.py`` rather than reimplementing scoring logic.
"""
from __future__ import annotations

import argparse
import csv
import random
from datetime import date
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from moniotr_cross_lab import (  # noqa: E402
    collapse_site_three,
    leave_one_out_generalized,
    load,
    load_label_mapping,
    per_device_metrics,
    write_csv,
)

SITES = ("US", "UK", "YT")
SEED = 42
N_RESAMPLES = 1000


def reference_set_sizes(data, sites: tuple[str, ...] = SITES) -> list[dict[str, object]]:
    """For each receiver and each of its target device types (shared with
    both other sites after label alignment), the size of the receiver's own
    ground-truth reference set and the raw observation row count backing it."""
    rows: list[dict[str, object]] = []
    for receiver in sites:
        target_devices, _candidates, _metrics = per_device_metrics(data, sites, receiver)
        for device in target_devices:
            rows.append({
                "receiver": receiver,
                "device_type": device,
                "reference_endpoint_count": len(data.profiles[receiver][device]),
                "observation_row_count": data.site_device_counts[(receiver, device)],
            })
    return rows


def _percentile(sorted_values: list[float], pct: float) -> float:
    """Nearest-rank-free linear-interpolation percentile (numpy-style),
    used instead of statistics.quantiles for robustness at small n."""
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return sorted_values[0]
    k = (len(sorted_values) - 1) * (pct / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_values) - 1)
    if f == c:
        return sorted_values[f]
    return sorted_values[f] + (sorted_values[c] - sorted_values[f]) * (k - f)


def bootstrap_ci(data, sites: tuple[str, ...] = SITES, *, seed: int = SEED, n_resamples: int = N_RESAMPLES) -> list[dict[str, object]]:
    """Bootstrap-resample the shared device types (with replacement) per
    receiver (fixed seed for reproducibility) and recompute macro-F1 each
    time, reporting mean + 95% percentile CI."""
    rows: list[dict[str, object]] = []
    for receiver in sites:
        _target_devices, _candidates, metrics = per_device_metrics(data, sites, receiver)
        f1_values = [m["f1"] for m in metrics]
        n = len(f1_values)
        rng = random.Random(seed)
        resample_means = []
        for _ in range(n_resamples):
            sample = [f1_values[rng.randrange(n)] for _ in range(n)]
            resample_means.append(sum(sample) / n)
        resample_means.sort()
        rows.append({
            "receiver": receiver,
            "mean_f1": sum(resample_means) / len(resample_means),
            "ci_low_2.5": _percentile(resample_means, 2.5),
            "ci_high_97.5": _percentile(resample_means, 97.5),
            "n_resamples": n_resamples,
        })
    return rows


def leave_one_device_out(data, sites: tuple[str, ...] = SITES) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for receiver in sites:
        target_devices, _candidates, metrics = per_device_metrics(data, sites, receiver)
        full_f1 = sum(m["f1"] for m in metrics) / len(metrics) if metrics else 0.0
        for i, removed_device in enumerate(target_devices):
            remaining = [m["f1"] for j, m in enumerate(metrics) if j != i]
            f1_without = sum(remaining) / len(remaining) if remaining else 0.0
            rows.append({
                "receiver": receiver,
                "removed_device_type": removed_device,
                "f1_macro_without_device": f1_without,
                "delta_from_full_f1": f1_without - full_f1,
            })
    return rows


def find_yourthings_day(yourthings_path: Path) -> date:
    """Confirm YourThings' single capture day directly from its own rows'
    timestamps (rather than assuming the date recorded in data_provenance.md)."""
    from datetime import datetime

    days: set[date] = set()
    with yourthings_path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            days.add(datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00")).date())
    if len(days) != 1:
        raise SystemExit(f"expected YourThings to cover exactly one UTC day, found {sorted(days)}")
    return next(iter(days))


def busiest_day_per_site(data, sites: tuple[str, ...]) -> dict[str, date]:
    """The single UTC calendar day with the most kept observation rows for
    each site, used only for the window-length-matched supplementary
    variant (see module docstring / find_yourthings_day)."""
    totals: dict[tuple[str, date], int] = {}
    for (site, _device, day), count in data.site_device_date_counts.items():
        if site in sites:
            totals[(site, day)] = totals.get((site, day), 0) + count
    best: dict[str, date] = {}
    best_count: dict[str, int] = {}
    for (site, day), count in totals.items():
        if count > best_count.get(site, -1):
            best[site] = day
            best_count[site] = count
    return best


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--observations", default="data/processed/moniotr_full_observations.csv")
    parser.add_argument("--yourthings-observations", required=True)
    parser.add_argument("--label-mapping", required=True)
    parser.add_argument("--output-dir", default="experiments/30_three_lab_loo")
    args = parser.parse_args(argv)

    source = Path(args.observations)
    yt_path = Path(args.yourthings_observations)
    label_map = load_label_mapping(Path(args.label_mapping))
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)

    data = load(
        source,
        extra_paths=[yt_path],
        collapse_fn=collapse_site_three,
        label_map=label_map,
    )

    write_csv(output / "reference_set_sizes.csv", reference_set_sizes(data))
    write_csv(output / "bootstrap_ci.csv", bootstrap_ci(data))
    write_csv(output / "leave_one_device_out.csv", leave_one_device_out(data))

    yt_day = find_yourthings_day(yt_path)
    single_day_data = load(
        source,
        extra_paths=[yt_path],
        collapse_fn=collapse_site_three,
        label_map=label_map,
        only_day=yt_day,
    )
    single_day_rows = leave_one_out_generalized(single_day_data, SITES)
    write_csv(output / "leave_one_out_three_lab_single_day.csv", single_day_rows)
    print(f"YourThings capture day (confirmed from data): {yt_day.isoformat()}")
    if all(int(row["target_device_types"]) == 0 for row in single_day_rows):
        print(
            "NOTE: literal same-calendar-day truncation is degenerate -- Mon(IoT)r US/UK "
            "rows fall entirely in 2019-03-29..2019-05-08 and share zero calendar dates "
            "with YourThings' 2018-03-21 capture, so no rows survive the US/UK truncation "
            "at all. See leave_one_out_three_lab_single_day_window_matched.csv for a "
            "window-LENGTH-matched (not identical-date) supplementary variant."
        )

    # Supplementary window-length-matched variant: since Mon(IoT)r and
    # YourThings were captured in different years, forcing an identical
    # calendar date is vacuous (see NOTE above). This instead gives each
    # Mon(IoT)r site its own single busiest UTC day -- matching YT's window
    # LENGTH (one day) without the impossible identical-date constraint --
    # so the three-lab comparison is at least apples-to-apples on capture
    # duration.
    full_three_lab = load(
        source, extra_paths=[yt_path], collapse_fn=collapse_site_three, label_map=label_map,
    )
    per_site_day = busiest_day_per_site(full_three_lab, ("US", "UK"))
    per_site_day["YT"] = yt_day
    window_matched_data = load(
        source,
        extra_paths=[yt_path],
        collapse_fn=collapse_site_three,
        label_map=label_map,
        only_day=per_site_day,
    )
    window_matched_rows = leave_one_out_generalized(window_matched_data, SITES)
    write_csv(
        output / "leave_one_out_three_lab_single_day_window_matched.csv",
        window_matched_rows,
    )
    print(f"Window-length-matched per-site days used: {per_site_day}")

    print(f"Wrote diagnostics to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
