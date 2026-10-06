"""Pareto frontier over (queue size, recall) for the three-lab cold-start
leave-one-receiver-out setting (Table tab:threelab / tab:reviewcost).

The paper reports four discrete operating points (union, quorum, quorum+score,
DIB) plus a separately-computed ranked-union curve
(experiments/38_union_ranked_budget), but never places them on one figure, and
never sweeps the admission threshold theta or the quorum m in this specific
leave-one-out setting -- theta=0.65 and m=2 are hardcoded throughout
moniotr_cross_lab.py (score_keys) and v28_matched_ablation.py. This script
adds that sweep, reusing the loading/evaluation machinery unchanged and only
parametrizing score_keys' theta and quorum threshold (score_keys itself is not
modified -- see score_keys_param below, a drop-in copy with theta/m as
arguments instead of the literals 0.65 and 2).

Output: experiments/46_pareto_frontier/{sweep.csv, frontier_points.csv,
manifest.json}. sweep.csv gives (receiver, theta, m, queue_size=candidates,
precision, recall, f1) for every swept cell; frontier_points.csv adds the
four existing discrete stages (union/quorum/quorum_score/DIB, from
experiments/33_v28_matched_ablation/matched_ablation.csv) and the
ranked-union curve (from experiments/38_union_ranked_budget/
ranked_union_curve.csv) on the same (queue_size, recall) axes, so a single
figure can plot all of them together.

Run from the repository root:  python3 code/scripts/pareto_frontier.py
"""
from __future__ import annotations

import csv
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from moniotr_cross_lab import (  # noqa: E402
    Aggregate, Key, ELIGIBLE, classify_core,
    collapse_site_three, load, load_label_mapping,
    per_device_metrics, set_metrics, mean, write_csv, sha256,
)

THETA_VALUES = [round(0.50 + 0.025 * i, 3) for i in range(13)]  # 0.50..0.80 step .025
M_VALUES = (2, 3)
RECEIVERS = ("US", "UK", "YT")


def score_keys_param(
    data: Aggregate, sites: set[str], theta: float, m: int, *, gate: bool = True,
) -> set[Key]:
    """Drop-in copy of moniotr_cross_lab.score_keys with theta and the
    quorum threshold m as parameters instead of the hardcoded 0.65 / 2. The
    scoring arithmetic (site_conf, temporal, value = 0.6*site_conf +
    0.4*temporal) is identical -- alpha/beta are not swept here, matching
    the paper's own operating point; only theta and m vary.
    """
    predicted: set[Key] = set()
    for key, supporters_all in data.endpoints.items():
        supporters = {site for site in supporters_all & sites}
        device, endpoint, protocol, port = key
        eligible = {site for site in data.device_sites[device] & sites}
        if not supporters or not eligible:
            continue
        site_conf = len(supporters) / len(eligible)
        endpoint_days = {day for site in sites for day in data.site_endpoint_days[(site, key)]}
        device_days = {day for site in sites for day in data.site_device_days[(site, device)]}
        endpoint_count = sum(
            data.site_endpoint_date_counts[(site, key, day)]
            for site in sites for day in data.site_endpoint_days[(site, key)]
        )
        device_count = sum(
            data.site_device_date_counts[(site, device, day)]
            for site in sites for day in data.site_device_days[(site, device)]
        )
        active_day_ratio = len(endpoint_days) / max(len(device_days), 1)
        frequency_ratio = endpoint_count / max(device_count, 1)
        temporal = min(1.0, 0.7 * active_day_ratio + 0.3 * frequency_ratio)
        value = 0.6 * site_conf + 0.4 * temporal
        portable = classify_core(endpoint, protocol, port) in ELIGIBLE
        if value >= theta and (not gate or portable) and len(supporters) >= m:
            predicted.add(key)
    return predicted


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    inputs = [
        root / "code/data/processed/moniotr_full_observations.csv",
        root / "code/data/processed/yourthings_observations.csv",
    ]
    mapping = root / "experiments/30_three_lab_loo/label_mapping_v16.csv"
    out = root / "experiments/46_pareto_frontier"
    out.mkdir(parents=True, exist_ok=True)

    data = load(inputs[0], extra_paths=inputs[1:], collapse_fn=collapse_site_three,
                label_map=load_label_mapping(mapping))
    sites = RECEIVERS

    sweep_rows = []
    for receiver in sites:
        sources = set(sites) - {receiver}
        devices, locked, _locked_metrics = per_device_metrics(data, sites, receiver)
        for m in M_VALUES:
            for theta in THETA_VALUES:
                candidates = {k for k in score_keys_param(data, sources, theta, m) if k[0] in devices}
                metrics = [
                    set_metrics({k for k in candidates if k[0] == device}, data.profiles[receiver][device])
                    for device in devices
                ]
                sweep_rows.append({
                    "receiver": receiver, "theta": theta, "m": m,
                    "queue_size": len(candidates),
                    "precision": round(mean(metrics, "precision"), 6),
                    "recall": round(mean(metrics, "recall"), 6),
                    "f1": round(mean(metrics, "f1"), 6),
                    "is_operating_point": theta == 0.65 and m == 2,
                })
        print(f"receiver={receiver}: swept {len(THETA_VALUES) * len(M_VALUES)} (theta,m) cells "
              f"over {len(devices)} devices", flush=True)

    write_csv(out / "sweep.csv", sweep_rows)

    # Frontier reference points: the four existing discrete stages plus the
    # ranked-union curve, both already computed elsewhere and reused as-is.
    frontier_rows = []
    matched_path = root / "experiments/33_v28_matched_ablation/matched_ablation.csv"
    if matched_path.exists():
        with matched_path.open(newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                frontier_rows.append({
                    "receiver": row["receiver"], "series": row["stage"],
                    "queue_size": row["candidates"], "recall": row["recall"],
                    "precision": row["precision"], "f1": row["f1"],
                })
    ranked_path = root / "experiments/38_union_ranked_budget/ranked_union_curve.csv"
    if ranked_path.exists():
        with ranked_path.open(newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                frontier_rows.append({
                    "receiver": row["receiver"], "series": "union_ranked",
                    "queue_size": row["reviewed"], "recall": "", "precision": "",
                    "f1": "",
                })
    write_csv(out / "frontier_points.csv", frontier_rows)

    manifest = {
        "experiment": "pareto_frontier",
        "config": {
            "theta_values": THETA_VALUES, "m_values": list(M_VALUES),
            "alpha": 0.6, "beta": 0.4, "operating_point": {"theta": 0.65, "m": 2},
            "receivers": list(RECEIVERS),
        },
        "inputs": {str(p.relative_to(root)): sha256_of(p) for p in inputs + [mapping]},
        "reused_unmodified": {
            "experiments/33_v28_matched_ablation/matched_ablation.csv": matched_path.exists(),
            "experiments/38_union_ranked_budget/ranked_union_curve.csv": ranked_path.exists(),
        },
        "commands": [["python3", "code/scripts/pareto_frontier.py"]],
        "metrics": {"sweep_cells": len(sweep_rows), "frontier_reference_rows": len(frontier_rows)},
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"done: {len(sweep_rows)} sweep cells, {len(frontier_rows)} frontier reference rows", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
