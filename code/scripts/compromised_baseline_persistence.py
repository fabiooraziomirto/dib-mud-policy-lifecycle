"""A1 persistence sweep -- cheap, additive, isolated.

Tests whether a compromise sustained over a longer local-learning window
(the same real captured attack endpoints, repeated across 30/60/120 days
instead of injected once) raises the malicious endpoint's temporal
confidence Ct enough to shift DIB's breakpoint k* toward the value
Proposition 1's worst-case bound predicts.

Only the DIB variants are recomputed here: local_only, pooled_union,
majority_registry, and frequency_filtered_registry admit or reject based
purely on which/how many sites report an endpoint, not on how many days it
spans -- their k* is identical for every spread_days value at the same k
(see dib.experiments.compromised_baseline.evaluate_compromised_baseline's
docstring), so re-sweeping them here would just re-derive numbers already
in outputs/compromised_baseline/compromised_baseline_sweep.csv (spread_days
implicitly 1) at real compute cost for zero new information.

Does not touch dib.experiments.management_attack, the one-shot A1 sweep, or
any other experiment's output tree.

Usage:
    python3 scripts/compromised_baseline_persistence.py
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dib.adapters.unsw_attack_2018 import MAC_TO_DEVICE, load_malicious_endpoints
from dib.core.io import filter_observations, read_observations_csv, write_csv
from dib.evaluation.dib import ScoringConfig
from dib.evaluation.profiles import load_profile_dir
from dib.experiments.compromised_baseline import evaluate_compromised_baseline
from dib.simulator.sites import partition_observations

DEVICE_TYPES = sorted({device_type for device_type, _ip in MAC_TO_DEVICE.values()})
DIB_STRATEGIES = ("dib_vanilla", "dib_trust_weighted", "dib_independence_aware")


def _load_config(path: str) -> dict:
    text = Path(path).read_text(encoding="utf-8")
    try:
        import yaml

        return yaml.safe_load(text)
    except ImportError:
        return json.loads(text)


def _scoring_config(config_path: str) -> ScoringConfig:
    scoring = _load_config(config_path)["scoring"]
    # Forced vanilla regardless of scoring.trust_weighted in the YAML -- same
    # reasoning as scripts/compromised_baseline.py's _scoring_config().
    return ScoringConfig(
        alpha=float(scoring["alpha"]),
        beta=float(scoring["beta"]),
        gamma=float(scoring["gamma"]),
        theta=float(scoring["theta"]),
        min_reporting_sites=int(scoring["min_reporting_sites"]),
        graph_enabled=bool(scoring.get("graph_enabled", True)),
        graph_max_endpoints_per_device=scoring.get("graph_max_endpoints_per_device"),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="configs/default_hyperparams.yaml")
    parser.add_argument("--observations", default="data/processed/observations_enriched.csv")
    parser.add_argument("--attack-annotations-dir", default="data/unsw_attack_2018/annotations")
    parser.add_argument("--ground-truth-dir", default="data/unsw/profiles/normalized")
    parser.add_argument("--output-dir", default="outputs/compromised_baseline")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--site-count", type=int, default=10)
    parser.add_argument("--partition-strategy", default="random")
    parser.add_argument("--spread-days", default="1,30,60,120")
    parser.add_argument("--exclude-non-global-ips", action=argparse.BooleanOptionalAction, default=True,
                        help="Apply the same post-load, pre-partition filter as runner.py --exclude-non-global-ips.")
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    spread_days_values = [int(v) for v in args.spread_days.split(",") if v.strip()]

    print(f"loading observations from {args.observations} ...", flush=True)
    observations = read_observations_csv(Path(args.observations))
    if args.exclude_non_global_ips:
        observations = list(filter_observations(observations, exclude_non_global_ips=True))
        print(f"exclude_non_global_ips=True: filtered to {len(observations)} observations", flush=True)
    sites = partition_observations(
        observations, args.site_count, strategy=args.partition_strategy, seed=args.seed
    )
    clean_observations = [o for site in sites for o in site.observations]

    malicious_endpoints = load_malicious_endpoints(Path(args.attack_annotations_dir))
    ground_truth = load_profile_dir(Path(args.ground_truth_dir))
    scoring_config = _scoring_config(args.config)
    print(f"scoring_config: {scoring_config}", flush=True)

    rows: list[dict[str, object]] = []
    for device_type in DEVICE_TYPES:
        hosting_sites = {o.site_id for o in clean_observations if o.device_type == device_type}
        max_k = min(args.site_count, len(hosting_sites))
        for spread_days in spread_days_values:
            for k in range(0, max_k + 1):
                rows.extend(
                    evaluate_compromised_baseline(
                        clean_observations,
                        malicious_endpoints,
                        device_type,
                        k,
                        scoring_config,
                        ground_truth,
                        seed=args.seed,
                        spread_days=spread_days,
                        strategies=DIB_STRATEGIES,
                    )
                )
            print(f"  {device_type}: spread_days={spread_days}, swept k=0..{max_k}", flush=True)

    fields = [
        "device_type", "strategy", "policy_scope", "k", "spread_days", "site_count", "malicious_endpoint_count",
        "malicious_admission_rate", "benign_exceptions_per_site", "benign_f1",
    ]
    write_csv(output_dir / "compromised_baseline_persistence_sweep.csv", rows, fields)
    print(f"\nwrote {output_dir / 'compromised_baseline_persistence_sweep.csv'} ({len(rows)} rows)")

    # k* per (device_type, spread_days): smallest k where dib_vanilla first admits.
    print(f"\n{'device_type':<26} " + " ".join(f"spread={d:>4}" for d in spread_days_values))
    kstars: dict[tuple[str, int], int | None] = {}
    for device_type in DEVICE_TYPES:
        line = f"{device_type:<26} "
        for spread_days in spread_days_values:
            admitted = [
                r for r in rows
                if r["device_type"] == device_type and r["strategy"] == "dib_vanilla"
                and r["spread_days"] == spread_days and r["malicious_admission_rate"] > 0
            ]
            kstar = min((r["k"] for r in admitted), default=None)
            kstars[(device_type, spread_days)] = kstar
            line += f"k*={kstar!s:>6} "
        print(line)

    theta, alpha = scoring_config.theta, scoring_config.alpha
    beta_plus_gamma = scoring_config.beta + scoring_config.gamma
    bound_k = (theta - beta_plus_gamma) / alpha * args.site_count  # f_max*site_count where bound crosses theta
    print(f"\nProposition 1 bound crossing (worst case, Ct=Cg=1): f_max={(theta - beta_plus_gamma) / alpha:.4f} "
          f"-> k={bound_k:.2f} of {args.site_count} sites")
    print("If empirical k* at high spread_days converges down toward this value, the analytical bound is "
          "confirmed as achievable, not just an upper bound, using real captured attack traffic.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
