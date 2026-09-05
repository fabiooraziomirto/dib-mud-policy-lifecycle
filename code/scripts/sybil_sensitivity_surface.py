from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from dataclasses import replace as dataclass_replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dib.core.io import filter_observations, read_observations_csv, write_csv
from dib.core.models import endpoint_to_string
from dib.evaluation.dib import DIBScorer, ScoringConfig, accepted_endpoint_keys
from dib.evaluation.baselines import ReputationWeightedVotingBaseline
from dib.evaluation.graph import graph_confidence
from dib.evaluation.trust import build_reputation_snapshot, calibrate_reference_breadth
from dib.experiments.poisoning import inject_adaptive_sybil_endpoint
from dib.simulator.sites import partition_observations

OUTPUT_DIR = Path("outputs/tnsm_review_2026-06-20/experiments/sybil_sensitivity")
FAKE_ENDPOINT = "evil-c2.net"


def _load_config(path: str) -> dict:
    text = Path(path).read_text(encoding="utf-8")
    try:
        import yaml

        return yaml.safe_load(text)
    except ImportError:
        return json.loads(text)


def _scoring_config(config_path: str | None) -> ScoringConfig:
    if config_path is None:
        return ScoringConfig()
    scoring = _load_config(config_path)["scoring"]
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
    parser = argparse.ArgumentParser(
        description="2D sensitivity surface of the adaptive-Sybil breakpoint: sweep "
        "Sybil identity count x persistence window for vanilla / trust-weighted / "
        "independence-aware scoring, reporting the fake-endpoint score, its acceptance, "
        "and the accepted-endpoint count for the attacked device (the 'empty' metric)."
    )
    parser.add_argument("--observations", default="data/processed/observations_enriched.csv")
    parser.add_argument("--calibration-observations", required=True,
                        help="Separate governance-bootstrap CSV, disjoint from --observations.")
    parser.add_argument(
        "--config",
        default=None,
        help="Optional YAML with a scoring: block (alpha/beta/gamma/theta/graph_enabled). "
        "Defaults to the shipped MEAS ScoringConfig() when omitted.",
    )
    parser.add_argument("--output-dir", default=str(OUTPUT_DIR))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--rwv-threshold",
        type=float,
        default=0.65,
        help="Frozen-reputation voting threshold (strict >; default 0.65).",
    )
    parser.add_argument(
        "--site-count",
        type=int,
        default=10,
        help="Partition the single physical UNSW site into this many simulated genuine "
        "sites before injecting Sybils (matches the Table IV management-attack setup).",
    )
    parser.add_argument("--partition-strategy", default="random", choices=["random", "device_balanced", "time_window", "existing"])
    parser.add_argument("--exclude-non-global-ips", action=argparse.BooleanOptionalAction, default=True,
                        help="Apply the same post-load, pre-partition filter as runner.py --exclude-non-global-ips.")
    parser.add_argument(
        "--counts",
        default="200,400,800,1600,2400,3200",
        help="Comma-separated Sybil identity counts.",
    )
    parser.add_argument(
        "--target-device-type",
        default=None,
        help="Device type to attack. Defaults to the most-observed type in the "
        "partitioned corpus (the original single-type behavior); pass explicitly "
        "to test generalization across device types with different endpoint-pool "
        "sizes and eligible-site counts.",
    )
    parser.add_argument(
        "--days",
        default="20,40,80,120,140,180,250,400",
        help="Comma-separated persistence windows (distinct active days per Sybil).",
    )
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    counts = [int(c) for c in args.counts.split(",") if c.strip()]
    days = [int(d) for d in args.days.split(",") if d.strip()]

    load_started = time.perf_counter()
    observations = read_observations_csv(Path(args.observations))
    calibration_observations = read_observations_csv(Path(args.calibration_observations))
    if args.exclude_non_global_ips:
        observations = list(filter_observations(observations, exclude_non_global_ips=True))
        calibration_observations = list(
            filter_observations(calibration_observations, exclude_non_global_ips=True)
        )
    if args.site_count:
        sites = partition_observations(
            observations, args.site_count, strategy=args.partition_strategy, seed=args.seed
        )
        observations = [observation for site in sites for observation in site.observations]
    if args.target_device_type:
        available = {o.device_type for o in observations}
        if args.target_device_type not in available:
            raise SystemExit(f"--target-device-type {args.target_device_type!r} not present after filtering/partitioning")
        target_device_type = args.target_device_type
    else:
        target_device_type = Counter(o.device_type for o in observations).most_common(1)[0][0]
    trust_reference = calibrate_reference_breadth(calibration_observations)
    reputation_snapshot = build_reputation_snapshot(calibration_observations, unknown_site_weight=0.1)
    print(
        f"loaded {len(observations)} observations ({args.site_count} genuine sites) in "
        f"{time.perf_counter() - load_started:.1f}s; target={target_device_type}; "
        f"trust_reference={trust_reference}; exclude_non_global_ips={args.exclude_non_global_ips}",
        flush=True,
    )

    # Mirror the corrected management-attack scoring path exactly so the surface is
    # consistent with Table IV: vanilla is scored target-scoped, its full-registry
    # graph confidence is reused as an override for the mitigations, and trust
    # reference breadth is calibrated on the clean pre-attack population.
    vanilla_config = _scoring_config(args.config)
    trust_config = dataclass_replace(
        vanilla_config, trust_weighted=True, trust_reference_breadth=trust_reference
    )
    independence_config = dataclass_replace(vanilla_config, independence_aware=True)

    def score_cell(poisoned):
        target_poisoned_keys = {o.endpoint_key for o in poisoned if o.device_type == target_device_type}
        vanilla_scorer = DIBScorer(vanilla_config)
        vanilla_scores = vanilla_scorer.score(poisoned, target_device_type=target_device_type)
        graph_override = None
        if vanilla_config.graph_enabled and vanilla_scorer.last_graph is not None:
            node_confidence = graph_confidence(vanilla_scorer.last_graph)
            graph_override = {
                key: node_confidence.get(endpoint_to_string(key), 0.0) for key in target_poisoned_keys
            }
        rwv = ReputationWeightedVotingBaseline(reputation_snapshot, threshold=args.rwv_threshold)
        rwv.fit([o for o in poisoned if o.device_type == target_device_type])
        return {
            "vanilla": vanilla_scores,
            "trust": DIBScorer(trust_config).score(
                poisoned, target_device_type=target_device_type, graph_confidence_override=graph_override
            ),
            "independence": DIBScorer(independence_config).score(
                poisoned, target_device_type=target_device_type, graph_confidence_override=graph_override
            ),
            "rwv": rwv,
        }

    rows = []
    for count in counts:
        for spread_days in days:
            cell_started = time.perf_counter()
            poisoned = inject_adaptive_sybil_endpoint(
                observations, count, target_device_type, spread_days, seed=args.seed
            )
            row = {"sybil_site_count": count, "spread_days": spread_days, "target_device_type": target_device_type}
            for name, scores in score_cell(poisoned).items():
                if name == "rwv":
                    fake_score = scores.scores.get((target_device_type, FAKE_ENDPOINT, "https", 443), 0.0)
                    fake_breakdown = scores.score_breakdown.get((target_device_type, FAKE_ENDPOINT, "https", 443), {})
                    fake_accepted = fake_score > args.rwv_threshold
                    accepted_for_device = sum(
                        1 for key in scores.predict(target_device_type) if key[1] != FAKE_ENDPOINT
                    )
                else:
                    fake = [s for s in scores if s.endpoint == FAKE_ENDPOINT]
                    fake_score = max((s.score for s in fake), default=0.0)
                    fake_accepted = any(s.accepted for s in fake)
                    accepted_for_device = sum(
                        1 for key in accepted_endpoint_keys(scores)
                        if key[0] == target_device_type and key[1] != FAKE_ENDPOINT
                    )
                row[f"fake_score_{name}"] = round(fake_score, 6)
                row[f"fake_accepted_{name}"] = fake_accepted
                row[f"legit_accepted_{name}"] = accepted_for_device
                if name == "rwv":
                    row["rwv_frozen_only_score"] = round(fake_breakdown.get("frozen_only_score", 0.0), 6)
                    row["rwv_probation_mass"] = round(fake_breakdown.get("probation_mass", 0.0), 6)
                    row["rwv_probation_numerator"] = round(fake_breakdown.get("probation_numerator", 0.0), 6)
            rows.append(row)
            print(
                f"  count={count} days={spread_days}: "
                f"vanilla={row['fake_score_vanilla']:.3f}({'A' if row['fake_accepted_vanilla'] else '-'}) "
                f"trust={row['fake_score_trust']:.3f}({'A' if row['fake_accepted_trust'] else '-'}) "
                f"indep={row['fake_score_independence']:.3f}({'A' if row['fake_accepted_independence'] else '-'}) "
                f"rwv={row['fake_score_rwv']:.3f}({'A' if row['fake_accepted_rwv'] else '-'}) "
                f"legit_v/t/i={row['legit_accepted_vanilla']}/{row['legit_accepted_trust']}/{row['legit_accepted_independence']} "
                f"[{time.perf_counter() - cell_started:.1f}s]",
                flush=True,
            )

    fieldnames = [
        "sybil_site_count", "spread_days", "target_device_type",
        "fake_score_vanilla", "fake_accepted_vanilla", "legit_accepted_vanilla",
        "fake_score_trust", "fake_accepted_trust", "legit_accepted_trust",
        "fake_score_independence", "fake_accepted_independence", "legit_accepted_independence",
        "fake_score_rwv", "fake_accepted_rwv", "legit_accepted_rwv",
        "rwv_frozen_only_score", "rwv_probation_mass", "rwv_probation_numerator",
    ]
    write_csv(output_dir / "sybil_sensitivity_surface.csv", rows, fieldnames)
    print(f"wrote {len(rows)} cells to {output_dir / 'sybil_sensitivity_surface.csv'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
