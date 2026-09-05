"""Per-site cold-start detail at the representative seed.

`cold_start_multiseed.py` keeps only day-0 F1 and discards the candidate count,
precision, and recall that `cold_start_rows` already computes, so the paper
could report cold start only as an F1 against a local-only value that is zero
by construction. This script keeps the full row set for one seed, so the
day-0 candidate volume and its precision/recall composition are reportable.

The twenty-seed F1 aggregate stays with `cold_start_multiseed.py`; this is the
composition of a single representative partition, not a replacement for it.
"""
from __future__ import annotations

import argparse
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import yaml

from dib.core.io import filter_observations, read_observations_csv, write_csv
from dib.evaluation.dib import ScoringConfig
from dib.evaluation.profiles import load_profile_dir
from dib.evaluation.trust import calibrate_reference_breadth
from dib.experiments.cold_start import cold_start_rows
from dib.simulator.sites import partition_observations

FIELDS = ["site_id", "window_days", "method", "device_count", "predicted_endpoint_count",
          "mean_semantic_precision", "mean_semantic_recall", "mean_semantic_f1"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observations", default="data/processed/observations_enriched.csv")
    parser.add_argument("--ground-truth-dir", default="data/unsw/profiles/normalized")
    parser.add_argument("--config", default=str(ROOT.parent / "configs" / "graph_free_selected.yaml"))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output-dir", default=str(ROOT.parent / "experiments" / "24_cold_start_detail"))
    parser.add_argument(
        "--windows", default="0",
        help="Comma-separated local-observation windows in days. Default 0 (original "
        "day-0-only behavior). Pass e.g. 0,7,14,30 to compare local-only-N-days "
        "against DIB's day-0 cross-site seed.",
    )
    args = parser.parse_args(argv)
    windows = [int(w) for w in args.windows.split(",") if w.strip()]

    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    observations = list(filter_observations(read_observations_csv(ROOT / args.observations), exclude_non_global_ips=True))
    truth = load_profile_dir(ROOT / args.ground_truth_dir)
    sites = partition_observations(observations, 10, strategy="random", seed=args.seed)
    partitioned = [obs for site in sites for obs in site.observations]
    del observations, sites

    scoring = yaml.safe_load(Path(args.config).read_text(encoding="utf-8"))["scoring"]
    trust = bool(scoring.get("trust_weighted", False))
    config = ScoringConfig(
        alpha=float(scoring["alpha"]), beta=float(scoring["beta"]), gamma=float(scoring["gamma"]),
        theta=float(scoring["theta"]), min_reporting_sites=int(scoring["min_reporting_sites"]),
        graph_enabled=bool(scoring.get("graph_enabled", True)), trust_weighted=trust,
        trust_reference_breadth=calibrate_reference_breadth(partitioned) if trust else 0.0,
    )

    rows = cold_start_rows(partitioned, truth, config, windows=windows)
    write_csv(output / "cold_start_detail.csv", rows, FIELDS)

    for window_days in windows:
        for method in sorted({str(r["method"]) for r in rows}):
            cells = [r for r in rows if r["method"] == method and r["window_days"] == window_days]
            if not cells:
                continue
            counts = [float(r["predicted_endpoint_count"]) for r in cells]
            print(f"window={window_days:>3} {method}: sites={len(cells)} candidates mean={statistics.mean(counts):.1f} "
                  f"min={min(counts):.0f} max={max(counts):.0f} "
                  f"P={statistics.mean(float(r['mean_semantic_precision']) for r in cells):.4f} "
                  f"R={statistics.mean(float(r['mean_semantic_recall']) for r in cells):.4f} "
                  f"F1={statistics.mean(float(r['mean_semantic_f1']) for r in cells):.4f}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
