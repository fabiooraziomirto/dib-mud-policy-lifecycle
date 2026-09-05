"""Twenty-seed confidence interval for the day-0-DIB-vs-30-day-local-only
comparison (Sec. V-B's "4.5x" claim, previously reported at a single seed=42
from cold_start_detail.py). Mirrors cold_start_multiseed.py's seed convention
exactly (seeds 0..19, exclude_non_global_ips, site_count=10,
partition_strategy=random) and reuses cold_start_rows() unmodified.

For each seed: local_only F1 at window_days=30 (a month of the joining
site's own traffic, no cross-site evidence) and registry_seeded F1 at
window_days=0 (DIB's cross-site candidates, zero local history). Reports
mean+-std for both and for their per-seed ratio.
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
from tnsm_submission_common import write_manifest

CONFIG_PATH = ROOT.parent / "configs" / "graph_free_selected.yaml"
SEEDS = list(range(20))
WINDOWS = [0, 30]


def base_config(path: Path, observations) -> ScoringConfig:
    scoring = yaml.safe_load(path.read_text(encoding="utf-8"))["scoring"]
    trust = bool(scoring.get("trust_weighted", False))
    return ScoringConfig(
        alpha=float(scoring["alpha"]), beta=float(scoring["beta"]), gamma=float(scoring["gamma"]),
        theta=float(scoring["theta"]), min_reporting_sites=int(scoring["min_reporting_sites"]),
        graph_enabled=bool(scoring.get("graph_enabled", True)),
        trust_weighted=trust,
        trust_reference_breadth=calibrate_reference_breadth(observations) if trust else 0.0,
    )


def mean_f1(rows: list[dict[str, object]], method: str, window_days: int) -> float:
    cells = [r for r in rows if r["method"] == method and r["window_days"] == window_days]
    return sum(float(r["mean_semantic_f1"]) for r in cells) / len(cells) if cells else 0.0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observations", default="data/processed/observations_enriched.csv")
    parser.add_argument("--ground-truth-dir", default="data/unsw/profiles/normalized")
    parser.add_argument("--output-dir", default="outputs/cold_start_local_vs_registry_multiseed")
    args = parser.parse_args(argv)

    output = ROOT / args.output_dir
    output.mkdir(parents=True, exist_ok=True)
    observation_path = ROOT / args.observations

    original = read_observations_csv(observation_path)
    filtered = list(filter_observations(original, exclude_non_global_ips=True))
    truth = load_profile_dir(ROOT / args.ground_truth_dir)

    detail_rows = []
    dib_day0 = []
    local_30 = []
    dib_plus_local_30 = []
    ratios = []
    for seed in SEEDS:
        sites = partition_observations(filtered, 10, strategy="random", seed=seed)
        observations = [obs for site in sites for obs in site.observations]
        config = base_config(CONFIG_PATH, observations)
        rows = cold_start_rows(observations, truth, config, windows=WINDOWS)
        dib0 = mean_f1(rows, "registry_seeded", 0)
        local30 = mean_f1(rows, "local_only", 30)
        dib30 = mean_f1(rows, "registry_seeded", 30)
        ratio = dib0 / local30 if local30 > 0 else float("inf")
        dib_day0.append(dib0)
        local_30.append(local30)
        dib_plus_local_30.append(dib30)
        ratios.append(ratio)
        detail_rows.append({
            "seed": seed,
            "dib_day0_f1": round(dib0, 6),
            "local_only_30day_f1": round(local30, 6),
            "dib_plus_30day_local_f1": round(dib30, 6),
            "ratio_dib_day0_over_local_30day": round(ratio, 6),
        })
        print(f"seed={seed}: dib_day0={dib0:.6f} local_30d={local30:.6f} "
              f"dib_plus_local_30d={dib30:.6f} ratio={ratio:.3f}", flush=True)

    def summarize(name: str, values: list[float]) -> tuple[float, float]:
        m = statistics.mean(values)
        s = statistics.stdev(values) if len(values) > 1 else 0.0
        print(f"{name}: mean={m:.6f} std={s:.6f} over {len(values)} seeds", flush=True)
        return m, s

    dib0_mean, dib0_std = summarize("dib_day0_f1", dib_day0)
    local30_mean, local30_std = summarize("local_only_30day_f1", local_30)
    dib30_mean, dib30_std = summarize("dib_plus_30day_local_f1", dib_plus_local_30)
    ratio_mean, ratio_std = summarize("ratio_dib_day0_over_local_30day", ratios)

    write_csv(output / "cold_start_local_vs_registry_detail.csv", detail_rows,
              ["seed", "dib_day0_f1", "local_only_30day_f1", "dib_plus_30day_local_f1",
               "ratio_dib_day0_over_local_30day"])
    write_manifest(
        output,
        experiment="cold_start_local_vs_registry_multiseed",
        config={"config": str(CONFIG_PATH), "seeds": SEEDS, "site_count": 10,
                "partition_strategy": "random", "windows": WINDOWS, "exclude_non_global_ips": True},
        inputs={"observations": args.observations, "ground_truth": args.ground_truth_dir},
        commands=[],
        metrics={
            "dib_day0_f1_mean": round(dib0_mean, 6), "dib_day0_f1_std": round(dib0_std, 6),
            "local_only_30day_f1_mean": round(local30_mean, 6), "local_only_30day_f1_std": round(local30_std, 6),
            "dib_plus_30day_local_f1_mean": round(dib30_mean, 6), "dib_plus_30day_local_f1_std": round(dib30_std, 6),
            "ratio_mean": round(ratio_mean, 6), "ratio_std": round(ratio_std, 6),
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
