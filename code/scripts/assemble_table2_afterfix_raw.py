"""Assemble the post-item1-fix 20-seed Table II raw per-seed CSV from the three
source artifacts under reports/item1_private_ip_filter/, so paired_config_statistics.py
can be re-run against corrected (exclude_non_global_ips=True) data instead of the
buggy pre-filter batch in outputs/tnsm_submission_2026/ablation_multiseed/.

Sources:
  - variance_group_a_AFTER.log            graph_augmented seeds 0-7  (text log)
  - variance_group_a_AFTER_resume_ga/raw_per_seed.csv  graph_augmented seeds 8-19
  - variance_group_a_AFTER_gf/raw_per_seed.csv         graph_free seeds 0-19
"""
from __future__ import annotations

import csv
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "reports" / "item1_private_ip_filter"
OUT = ROOT / "outputs" / "tnsm_submission_2026" / "table2_multiseed_afterfix" / "raw_per_seed_afterfix.csv"

LOG_LINE = re.compile(
    r"\[graph_augmented\] seed=(\d+) mean_f1=([\d.]+) std_across_devices=([\d.]+) day0_f1=([\d.]+)"
)

FIELDS = ["config", "seed", "variant", "mean_f1_vs_ground_truth", "std_across_devices", "device_count", "day0_cold_start_f1"]


def rows_from_log(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text().splitlines():
        m = LOG_LINE.match(line.strip())
        if not m:
            continue
        seed, mean_f1, std, day0 = m.groups()
        rows.append({
            "config": "graph_augmented",
            "seed": int(seed),
            "variant": "full",
            "mean_f1_vs_ground_truth": mean_f1,
            "std_across_devices": std,
            "device_count": "",
            "day0_cold_start_f1": day0,
        })
    return rows


def rows_from_csv(path: Path) -> list[dict]:
    rows = []
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            rows.append({
                "config": row["config_label"],
                "seed": int(row["seed"]),
                "variant": "full",
                "mean_f1_vs_ground_truth": row["mean_per_device_f1_unsw"],
                "std_across_devices": row["std_across_devices_unsw"],
                "device_count": row["device_count"],
                "day0_cold_start_f1": row["day0_cold_start_f1"],
            })
    return rows


def main() -> int:
    rows = []
    rows += rows_from_log(SRC / "variance_group_a_AFTER.log")
    rows += rows_from_csv(SRC / "variance_group_a_AFTER_resume_ga" / "raw_per_seed.csv")
    rows += rows_from_csv(SRC / "variance_group_a_AFTER_gf" / "raw_per_seed.csv")

    ga_seeds = sorted(r["seed"] for r in rows if r["config"] == "graph_augmented")
    gf_seeds = sorted(r["seed"] for r in rows if r["config"] == "graph_free")
    assert ga_seeds == list(range(20)), f"graph_augmented seeds incomplete: {ga_seeds}"
    assert gf_seeds == list(range(20)), f"graph_free seeds incomplete: {gf_seeds}"

    rows.sort(key=lambda r: (r["config"], r["seed"]))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {len(rows)} rows ({len(ga_seeds)} graph_augmented + {len(gf_seeds)} graph_free) -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
