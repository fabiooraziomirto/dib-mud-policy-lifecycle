"""Twenty-seed component ablation for both declared TNSM operating points.

It writes each completed cell immediately, so an interrupted long run resumes
without recomputing prior seeds.  Parallel orchestration is intentionally left
to the caller after a measured-RSS preflight; this process itself is one worker.
"""
from __future__ import annotations

import argparse
import csv
import math
import sys
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import yaml

from dib.core.io import filter_observations, read_observations_csv, write_csv
from dib.evaluation.dib import DIBScorer, ScoringConfig, accepted_endpoint_keys
from dib.evaluation.profiles import PREDICTED_DIRECTION, canonical_device_name, load_profile_dir, normalize_profile_protocol, semantic_match_metrics
from dib.evaluation.trust import calibrate_reference_breadth
from dib.simulator.sites import partition_observations
from tnsm_submission_common import write_manifest


CONFIGS = {
    # Absolute paths into reproducibility/configs/ (this package's single
    # canonical copy, see configs/LOCKED_CONFIGS.md) rather than
    # ROOT-relative ("configs/default_hyperparams.yaml" etc., the DIB/-root
    # paths these are verbatim copies of but that do not exist inside this
    # self-contained code/ checkout).
    "graph_augmented": ROOT.parent / "configs" / "graph_augmented.yaml",
    "graph_free": ROOT.parent / "configs" / "graph_free_selected.yaml",
}
VARIANTS = ("full", "no_site", "no_temporal", "no_graph")
FIELDS = ["config", "seed", "variant", "accepted_count", "jaccard_vs_full", "mean_f1_vs_ground_truth", "graph_identity_control", "exclude_non_global_ips", "reference_seed"]


def base_config(path: Path, observations) -> ScoringConfig:
    config = yaml.safe_load(path.read_text(encoding="utf-8"))["scoring"]
    trust = bool(config.get("trust_weighted", False))
    # min_reporting_sites is mandatory, same convention as alpha/beta/gamma/
    # theta -- see runner.py:_scoring_config() and configs/LOCKED_CONFIGS.md.
    return ScoringConfig(alpha=float(config["alpha"]), beta=float(config["beta"]), gamma=float(config["gamma"]), theta=float(config["theta"]), min_reporting_sites=int(config["min_reporting_sites"]), graph_enabled=bool(config.get("graph_enabled", True)), graph_max_endpoints_per_device=config.get("graph_max_endpoints_per_device"), trust_weighted=trust, trust_reference_breadth=calibrate_reference_breadth(observations) if trust else 0.0)


def mean_f1(scores, truth) -> float:
    predicted: dict[str, set] = {}
    for score in scores:
        if score.accepted:
            device = canonical_device_name(score.device_type)
            predicted.setdefault(device, set()).add((device, PREDICTED_DIRECTION, score.endpoint.lower(), normalize_profile_protocol(score.protocol, score.port), score.port))
    values = [semantic_match_metrics(predicted.get(device, set()), rules)["semantic_f1"] for device, rules in truth.items()]
    return sum(values) / len(values) if values else 0.0


def summarize(rows: list[dict[str, str]]) -> list[dict[str, object]]:
    out = []
    for config in CONFIGS:
        for variant in VARIANTS:
            # The reference seed is emitted for a direct Table-II audit, but
            # remains outside the pre-registered 0..19 aggregate.
            cells = [r for r in rows if r["config"] == config and r["variant"] == variant and r.get("reference_seed", "False") != "True"]
            for metric in ("accepted_count", "jaccard_vs_full", "mean_f1_vs_ground_truth"):
                values = [float(r[metric]) for r in cells]
                avg = sum(values) / len(values) if values else 0.0
                sd = math.sqrt(sum((x - avg) ** 2 for x in values) / (len(values) - 1)) if len(values) > 1 else 0.0
                out.append({"config": config, "variant": variant, "metric": metric, "n_seeds": len(values), "mean": round(avg, 6), "sample_sd": round(sd, 6), "minimum": round(min(values), 6) if values else "", "maximum": round(max(values), 6) if values else ""})
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observations", default="data/processed/observations_enriched.csv")
    parser.add_argument("--ground-truth-dir", default="data/unsw/profiles/normalized")
    parser.add_argument("--output-dir", default="outputs/tnsm_submission_2026/ablation_multiseed")
    parser.add_argument("--seeds", type=int, default=20)
    parser.add_argument("--seed-start", type=int, default=0)
    parser.add_argument("--reference-seed", type=int, default=42, help="Extra Table-II verification seed; excluded from the 0..N-1 aggregate.")
    parser.add_argument("--exclude-non-global-ips", action=argparse.BooleanOptionalAction, default=True,
                        help="Apply the same post-load, pre-partition filter as runner.py --exclude-non-global-ips.")
    args = parser.parse_args(argv)
    output = ROOT / args.output_dir
    raw_path = output / "raw_per_seed.csv"
    existing = []
    if raw_path.exists():
        with raw_path.open(newline="", encoding="utf-8") as handle:
            existing = list(csv.DictReader(handle))
    done = {(r["config"], int(r["seed"]), r["variant"]) for r in existing}
    observations = read_observations_csv(ROOT / args.observations)
    # Matches src/dib/experiments/runner.py:main(): load -> filter ->
    # partition_observations.  This is the post-private-IP population used by
    # Table II's 422/0.154 and 431/0.165 reference rows.
    if args.exclude_non_global_ips:
        observations = list(filter_observations(observations, exclude_non_global_ips=True))
    truth = load_profile_dir(ROOT / args.ground_truth_dir)
    rows = list(existing)
    for label, config_path in CONFIGS.items():
        run_seeds = list(range(args.seed_start, args.seeds))
        if args.reference_seed not in run_seeds:
            run_seeds.append(args.reference_seed)
        for seed in run_seeds:
            if all((label, seed, v) in done for v in VARIANTS):
                continue
            sites = partition_observations(observations, 10, strategy="random", seed=seed)
            partitioned = [obs for site in sites for obs in site.observations]
            base = base_config(ROOT / config_path, partitioned)
            configs = {"full": base, "no_site": replace(base, alpha=0.0), "no_temporal": replace(base, beta=0.0), "no_graph": replace(base, gamma=0.0)}
            full = DIBScorer(base).score(partitioned)
            full_accepted = accepted_endpoint_keys(full)
            for variant, scoring in configs.items():
                if (label, seed, variant) in done:
                    continue
                scores = full if variant == "full" else DIBScorer(scoring).score(partitioned)
                accepted = accepted_endpoint_keys(scores)
                union = accepted | full_accepted
                rows.append({"config": label, "seed": seed, "variant": variant, "accepted_count": len(accepted), "jaccard_vs_full": round(len(accepted & full_accepted) / len(union) if union else 1.0, 6), "mean_f1_vs_ground_truth": round(mean_f1(scores, truth), 6), "graph_identity_control": label == "graph_free" and variant == "no_graph", "exclude_non_global_ips": args.exclude_non_global_ips, "reference_seed": seed == args.reference_seed})
            write_csv(raw_path, rows, FIELDS)
            print(f"completed {label} seed={seed}", flush=True)
    write_csv(output / "summary.csv", summarize(rows), ["config", "variant", "metric", "n_seeds", "mean", "sample_sd", "minimum", "maximum"])
    write_manifest(output, experiment="ablation_multiseed", config={"configs": {k: str(v) for k, v in CONFIGS.items()}, "variants": VARIANTS, "aggregate_seeds": list(range(args.seed_start, args.seeds)), "reference_seed": args.reference_seed, "exclude_non_global_ips": args.exclude_non_global_ips, "pipeline_order": "read_observations_csv -> filter_observations(exclude_non_global_ips=True) -> partition_observations"}, inputs={"observations": args.observations, "ground_truth": args.ground_truth_dir}, commands=[], metrics={"completed_cells": len(rows)})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
