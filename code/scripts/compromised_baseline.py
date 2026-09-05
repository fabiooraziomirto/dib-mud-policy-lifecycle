"""A1 ("poisoned local baseline") experiment driver -- isolated, additive.

Measures what dib_TNSM.tex's threat model names but no prior experiment
covered: a device already compromised during a site's *local* learning
window, using REAL captured attack traffic
(https://iotanalytics.unsw.edu.au/attack-data.html, via
dib.adapters.unsw_attack_2018) rather than a synthetic fake endpoint.

Does not touch dib.experiments.management_attack, Table IV, or any other
experiment's output tree. Writes only to --output-dir (default
outputs/compromised_baseline/), a new location.

Usage:
    python3 scripts/compromised_baseline.py

Outputs:
    compromised_baseline_sweep.csv   -- every (device_type, strategy, k) cell,
                                         k=0..site_count, for verifying the
                                         Proposition-1-style k/site_count bound.
    compromised_baseline_table.csv   -- headline table at --headline-k
                                         (default 3, i.e. f=0.30, matching the
                                         malicious budget already used
                                         elsewhere in the paper), mean across
                                         the 5 covered device types: exactly
                                         [malicious admission rate | benign
                                         exceptions per site | benign F1] per
                                         strategy.
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
from dib.experiments.compromised_baseline import STRATEGIES, evaluate_compromised_baseline
from dib.simulator.sites import partition_observations

DEVICE_TYPES = sorted({device_type for device_type, _ip in MAC_TO_DEVICE.values()})


def _load_config(path: str) -> dict:
    text = Path(path).read_text(encoding="utf-8")
    try:
        import yaml

        return yaml.safe_load(text)
    except ImportError:
        return json.loads(text)


def _scoring_config(config_path: str) -> ScoringConfig:
    scoring = _load_config(config_path)["scoring"]
    # Forced vanilla regardless of scoring.trust_weighted in the YAML: this is
    # the "dib_vanilla" comparison point that evaluate_compromised_baseline
    # (src/dib/experiments/compromised_baseline.py:277-286) derives its own
    # dib_trust_weighted/dib_independence_aware variants from via
    # dataclass_replace. Letting a trust_weighted YAML flag leak in here would
    # silently corrupt the vanilla baseline with an uncalibrated (zero)
    # trust_reference_breadth -- same failure mode fixed in runner.py.
    return ScoringConfig(
        alpha=float(scoring["alpha"]),
        beta=float(scoring["beta"]),
        gamma=float(scoring["gamma"]),
        theta=float(scoring["theta"]),
        # Mandatory, same convention as alpha/beta/gamma/theta -- see
        # runner.py:_scoring_config() and configs/LOCKED_CONFIGS.md.
        min_reporting_sites=int(scoring["min_reporting_sites"]),
        graph_enabled=bool(scoring.get("graph_enabled", True)),
        graph_max_endpoints_per_device=scoring.get("graph_max_endpoints_per_device"),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="configs/default_hyperparams.yaml")
    parser.add_argument("--observations", default="data/processed/observations_enriched.csv")
    parser.add_argument("--calibration-observations", required=True,
                        help="Separate pre-registered governance-bootstrap CSV; disjoint from --observations.")
    parser.add_argument("--attack-annotations-dir", default="data/unsw_attack_2018/annotations")
    parser.add_argument("--ground-truth-dir", default="data/unsw/profiles/normalized")
    parser.add_argument("--output-dir", default="outputs/compromised_baseline")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--site-count", type=int, default=10)
    parser.add_argument("--partition-strategy", default="random")
    parser.add_argument("--headline-k", type=int, default=3, help="k for the headline table (default 3 -> f=0.30)")
    parser.add_argument("--frequency-min-count", type=int, default=2)
    parser.add_argument("--strategies", default=None,
                        help="Comma-separated strategy subset; default runs all existing strategies.")
    parser.add_argument(
        "--rwv-threshold",
        type=float,
        default=0.65,
        help="Frozen-reputation voting threshold (strict >; default 0.65).",
    )
    parser.add_argument("--exclude-non-global-ips", action=argparse.BooleanOptionalAction, default=True,
                        help="Apply the same post-load, pre-partition filter as runner.py --exclude-non-global-ips.")
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"loading observations from {args.observations} ...", flush=True)
    observations = read_observations_csv(Path(args.observations))
    calibration_observations = read_observations_csv(Path(args.calibration_observations))
    if args.exclude_non_global_ips:
        observations = list(filter_observations(observations, exclude_non_global_ips=True))
        calibration_observations = list(filter_observations(calibration_observations, exclude_non_global_ips=True))
        print(f"exclude_non_global_ips=True: filtered to {len(observations)} observations", flush=True)
    sites = partition_observations(
        observations, args.site_count, strategy=args.partition_strategy, seed=args.seed
    )
    clean_observations = [o for site in sites for o in site.observations]

    malicious_endpoints = load_malicious_endpoints(Path(args.attack_annotations_dir))
    if not malicious_endpoints:
        print(f"ERROR: no malicious endpoints found under {args.attack_annotations_dir}", file=sys.stderr)
        return 1
    print(f"{len(malicious_endpoints)} real malicious endpoint observations across {len(DEVICE_TYPES)} device types",
          flush=True)

    ground_truth = load_profile_dir(Path(args.ground_truth_dir))

    scoring_config = _scoring_config(args.config)
    print(f"scoring_config: {scoring_config}", flush=True)

    sweep_rows: list[dict[str, object]] = []
    strategies = [s.strip() for s in args.strategies.split(",") if s.strip()] if args.strategies else None
    for device_type in DEVICE_TYPES:
        hosting_sites = {o.site_id for o in clean_observations if o.device_type == device_type}
        max_k = min(args.site_count, len(hosting_sites))
        if max_k == 0:
            print(f"WARNING: no sites host device_type={device_type!r}, skipping", file=sys.stderr)
            continue
        for k in range(0, max_k + 1):
            rows = evaluate_compromised_baseline(
                clean_observations,
                malicious_endpoints,
                device_type,
                k,
                scoring_config,
                ground_truth,
                frequency_min_count=args.frequency_min_count,
                seed=args.seed,
                rwv_threshold=args.rwv_threshold,
                calibration_observations=calibration_observations,
                strategies=strategies,
            )
            sweep_rows.extend(rows)
        print(f"  {device_type}: swept k=0..{max_k}", flush=True)

    fields = [
        "device_type", "strategy", "policy_scope", "k", "spread_days", "site_count", "malicious_endpoint_count",
        "malicious_admission_rate", "benign_exceptions_per_site", "benign_f1",
    ]
    write_csv(output_dir / "compromised_baseline_sweep.csv", sweep_rows, fields)
    print(f"\nwrote {output_dir / 'compromised_baseline_sweep.csv'} ({len(sweep_rows)} rows)")

    # Headline table: mean across the 5 device types at a fixed k, one row per strategy.
    headline_rows = [r for r in sweep_rows if r["k"] == args.headline_k]
    table_rows = []
    for strategy in STRATEGIES:
        cells = [r for r in headline_rows if r["strategy"] == strategy]
        if not cells:
            continue
        table_rows.append(
            {
                "strategy": strategy,
                "k": args.headline_k,
                "device_types_covered": len(cells),
                "mean_malicious_admission_rate": round(sum(c["malicious_admission_rate"] for c in cells) / len(cells), 6),
                "mean_benign_exceptions_per_site": round(sum(c["benign_exceptions_per_site"] for c in cells) / len(cells), 6),
                "mean_benign_f1": round(sum(c["benign_f1"] for c in cells) / len(cells), 6),
            }
        )
    write_csv(
        output_dir / "compromised_baseline_table.csv",
        table_rows,
        ["strategy", "k", "device_types_covered", "mean_malicious_admission_rate",
         "mean_benign_exceptions_per_site", "mean_benign_f1"],
    )
    print(f"wrote {output_dir / 'compromised_baseline_table.csv'}")

    print(f"\n{'strategy':<28} {'admission_rate':>15} {'exceptions/site':>16} {'benign_F1':>10}")
    for row in table_rows:
        print(f"{row['strategy']:<28} {row['mean_malicious_admission_rate']:>15.3f} "
              f"{row['mean_benign_exceptions_per_site']:>16.3f} {row['mean_benign_f1']:>10.3f}")

    # Hypothesis checks (task 3): flag rather than silently pass.
    #
    # local_only's reported admission_rate is a MEAN over all site_count
    # sites (k compromised + (site_count-k) clean), not the rate at the
    # compromised sites alone -- a compromised site admits its own
    # compromised traffic 100% of the time by construction, but clean sites
    # correctly admit 0%, so the aggregate is exactly k/site_count, not 1.0.
    # Check the real per-construction invariant directly against the sweep
    # rows: every device's local_only admission rate at k must equal
    # round(k/site_count, 6) exactly.
    local_only_rows = [r for r in sweep_rows if r["k"] == args.headline_k and r["strategy"] == "local_only"]
    pooled = next((r for r in table_rows if r["strategy"] == "pooled_union"), None)
    problems = []
    if args.headline_k >= 1:
        for row in local_only_rows:
            expected = round(args.headline_k / row["site_count"], 6)
            if abs(row["malicious_admission_rate"] - expected) > 1e-6:
                problems.append(
                    f"local_only admission rate for {row['device_type']} is "
                    f"{row['malicious_admission_rate']} at k={args.headline_k}, expected exactly "
                    f"k/site_count={expected} (100% of compromised sites, 0% of clean sites averaged "
                    "together) -- investigate the injector."
                )
        if pooled and pooled["mean_malicious_admission_rate"] < 1.0 - 1e-9:
            problems.append(
                f"pooled_union admission rate is {pooled['mean_malicious_admission_rate']} at k={args.headline_k}, "
                "expected 1.0 (a global union of all sites' observations must contain every observation ever "
                "made, including injected ones) -- investigate the injector."
            )
    if problems:
        print("\nHYPOTHESIS CHECK FAILED:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print(f"\nHypothesis check passed at k={args.headline_k}: every compromised site's own local_only "
          f"profile admits its real malicious endpoint 100% of the time (aggregate rate = k/site_count "
          "exactly), and pooled_union admits it 100% globally -- both by construction, as expected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
