"""Adaptive-Sybil padding sweep at a fixed identity count and persistence window.

scripts/sybil_sensitivity_surface.py evaluates *templated* Sybils: every
identity contributes exactly the same single fake endpoint, so their per-device
endpoint sets are identical (pairwise Jaccard 1.0) and similarity clustering
collapses them into one component regardless of how many there are. That is the
easiest possible adversary for the clustering mitigation.

This script keeps the identity count and persistence window fixed at the largest
surface cell and instead sweeps how much each Sybil *pads* its endpoint set with
distinct, genuinely observed endpoints of the target device type
(dib.experiments.poisoning.inject_diversified_sybil_endpoint). Padding lowers
pairwise similarity between identities without fabricating traffic, which is the
anti-clustering lever an adaptive adversary actually has, and it also raises each
Sybil's contributed breadth and therefore its trust weight.

Padding is expressed as a fraction of the real endpoint pool available for the
target device type, so the sweep reports both the fraction and the realized
per-identity padding count. For each point it records the fabricated endpoint's
score under vanilla, trust-weighted, and similarity-clustering scoring, whether
it is admitted, and the realized cluster structure over the Sybil identities:
the point at which the number of Sybil clusters exceeds one is the point at
which clustering stops collapsing the identities.
"""
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
from dib.evaluation.dib import DIBScorer, ScoringConfig, accepted_endpoint_keys
from dib.evaluation.independence import (
    build_site_similarity_graph,
    compute_site_clusters,
    compute_site_endpoint_sets,
    jaccard_similarity,
)
from dib.evaluation.trust import calibrate_reference_breadth, compute_site_trust_weights
from dib.experiments.poisoning import inject_diversified_sybil_endpoint
from dib.simulator.sites import partition_observations

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
        min_reporting_sites=int(scoring["min_reporting_sites"]),
        graph_enabled=bool(scoring.get("graph_enabled", True)),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observations", default="data/processed/observations_enriched.csv")
    parser.add_argument("--calibration-observations", required=True)
    parser.add_argument("--config", default=None)
    parser.add_argument("--output-dir", default="outputs/sybil_padding_sweep")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--site-count", type=int, default=10)
    parser.add_argument("--partition-strategy", default="random",
                        choices=["random", "device_balanced", "time_window", "existing"])
    parser.add_argument("--exclude-non-global-ips", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--sybil-count", type=int, default=3200,
                        help="Fixed identity count (default: largest surface cell).")
    parser.add_argument("--spread-days", type=int, default=400,
                        help="Fixed persistence window (default: largest surface cell).")
    parser.add_argument("--padding-fractions", default="0,0.1,0.25,0.5",
                        help="Padding per identity as a fraction of the real endpoint pool.")
    parser.add_argument("--thresholds", default="0.8",
                        help="Comma-separated Jaccard similarity thresholds for the independence-aware "
                        "clustering scorer (default 0.8, the paper's locked operating point). Crossed "
                        "with --padding-fractions.")
    parser.add_argument(
        "--target-device-type",
        default=None,
        help="Device type to attack. Defaults to the most-observed type in the "
        "partitioned corpus; pass explicitly to test generalization across "
        "device types with different endpoint-pool sizes.",
    )
    parser.add_argument(
        "--jaccard-sample-size",
        type=int,
        default=0,
        help="Cap the number of Sybil identities used to estimate mean pairwise "
        "Jaccard similarity (0 = use the full Sybil population, exact but O(n^2); "
        "at 3200 identities this is ~5.1M pairs, still seconds in pure Python).",
    )
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    fractions = [float(f) for f in args.padding_fractions.split(",") if f.strip()]

    started = time.perf_counter()
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
        target = args.target_device_type
    else:
        target = Counter(o.device_type for o in observations).most_common(1)[0][0]
    trust_reference = calibrate_reference_breadth(calibration_observations)
    pool = {
        (o.fqdn, o.protocol, o.port)
        for o in observations
        if o.device_type == target and o.fqdn and o.fqdn != FAKE_ENDPOINT
    }
    print(
        f"loaded {len(observations)} observations in {time.perf_counter() - started:.1f}s; "
        f"target={target}; real endpoint pool={len(pool)}; trust_reference={trust_reference}",
        flush=True,
    )

    vanilla_config = _scoring_config(args.config)
    trust_config = dataclass_replace(
        vanilla_config, trust_weighted=True, trust_reference_breadth=trust_reference
    )
    thresholds = [float(t) for t in args.thresholds.split(",") if t.strip()]

    rows = []
    for fraction in fractions:
        padding = int(round(fraction * len(pool)))
        poisoned = inject_diversified_sybil_endpoint(
            observations, args.sybil_count, target, args.spread_days,
            padding_per_sybil=padding, seed=args.seed,
        )
        vanilla_scores = DIBScorer(vanilla_config).score(poisoned, target_device_type=target)
        trust_scores = DIBScorer(trust_config).score(poisoned, target_device_type=target)
        vanilla_fake = [s for s in vanilla_scores if s.endpoint == FAKE_ENDPOINT]
        trust_fake = [s for s in trust_scores if s.endpoint == FAKE_ENDPOINT]

        for threshold in thresholds:
            cell_started = time.perf_counter()
            independence_config = dataclass_replace(
                vanilla_config, independence_aware=True, independence_similarity_threshold=threshold
            )
            row: dict[str, object] = {
                "padding_fraction": fraction,
                "padding_per_sybil": min(padding, len(pool)),
                "real_endpoint_pool": len(pool),
                "sybil_site_count": args.sybil_count,
                "spread_days": args.spread_days,
                "target_device_type": target,
                "fake_score_vanilla": round(max((s.score for s in vanilla_fake), default=0.0), 6),
                "fake_accepted_vanilla": any(s.accepted for s in vanilla_fake),
                "legit_accepted_vanilla": sum(
                    1 for key in accepted_endpoint_keys(vanilla_scores)
                    if key[0] == target and key[1] != FAKE_ENDPOINT
                ),
                "fake_score_trust": round(max((s.score for s in trust_fake), default=0.0), 6),
                "fake_accepted_trust": any(s.accepted for s in trust_fake),
                "legit_accepted_trust": sum(
                    1 for key in accepted_endpoint_keys(trust_scores)
                    if key[0] == target and key[1] != FAKE_ENDPOINT
                ),
            }
            independence_scores = DIBScorer(independence_config).score(poisoned, target_device_type=target)
            independence_fake = [s for s in independence_scores if s.endpoint == FAKE_ENDPOINT]
            row["fake_score_independence"] = round(max((s.score for s in independence_fake), default=0.0), 6)
            row["fake_accepted_independence"] = any(s.accepted for s in independence_fake)
            row["legit_accepted_independence"] = sum(
                1 for key in accepted_endpoint_keys(independence_scores)
                if key[0] == target and key[1] != FAKE_ENDPOINT
            )

            # Realized independence structure over the Sybil identities only.
            endpoint_sets = compute_site_endpoint_sets(poisoned, target)
            sybil_sites = sorted(s for s in endpoint_sets if s.startswith("sybil-"))
            clusters = compute_site_clusters(
                build_site_similarity_graph(endpoint_sets, similarity_threshold=threshold)
            )
            row["sybil_clusters"] = len({clusters[s] for s in sybil_sites})
            row["largest_sybil_cluster"] = max(
                Counter(clusters[s] for s in sybil_sites).values(), default=0
            )
            cap = args.jaccard_sample_size or len(sybil_sites)
            sample = sybil_sites[: min(cap, len(sybil_sites))]
            pairwise = [
                jaccard_similarity(endpoint_sets[a], endpoint_sets[b])
                for i, a in enumerate(sample) for b in sample[i + 1:]
            ]
            row["mean_pairwise_jaccard"] = round(sum(pairwise) / len(pairwise), 6) if pairwise else 0.0
            row["jaccard_pairs_sampled"] = len(pairwise)
            row["jaccard_sybil_population"] = len(sybil_sites)
            row["similarity_threshold"] = threshold
            weights = compute_site_trust_weights(poisoned, reference_breadth=trust_reference)
            sybil_weights = [weights.get(s, 0.0) for s in sybil_sites]
            row["mean_sybil_trust_weight"] = round(sum(sybil_weights) / len(sybil_weights), 6) if sybil_weights else 0.0
            rows.append(row)
            print(
                f"  padding={fraction} threshold={threshold} ({row['padding_per_sybil']} endpoints/identity): "
                f"vanilla={row['fake_score_vanilla']:.3f}({'A' if row['fake_accepted_vanilla'] else '-'}) "
                f"trust={row['fake_score_trust']:.3f}({'A' if row['fake_accepted_trust'] else '-'}) "
                f"cluster={row['fake_score_independence']:.3f}({'A' if row['fake_accepted_independence'] else '-'}) "
                f"sybil_clusters={row['sybil_clusters']} "
                f"mean_pairwise_jaccard={row['mean_pairwise_jaccard']:.3f} (n={row['jaccard_pairs_sampled']} pairs) "
                f"[{time.perf_counter() - cell_started:.1f}s]",
                flush=True,
            )

    write_csv(output_dir / "sybil_padding_sweep.csv", rows, list(rows[0]))
    (output_dir / "manifest.json").write_text(
        json.dumps(
            {
                "experiment": "sybil_padding_sweep",
                "observations": args.observations,
                "calibration_observations": args.calibration_observations,
                "config_file": args.config,
                "seed": args.seed,
                "site_count": args.site_count,
                "target_device_type": target,
                "real_endpoint_pool": len(pool),
                "sybil_site_count": args.sybil_count,
                "spread_days": args.spread_days,
                "padding_fractions": fractions,
                "similarity_thresholds": thresholds,
                "jaccard_sample_size_arg": args.jaccard_sample_size,
                "wall_seconds": round(time.perf_counter() - started, 1),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(rows)} rows to {output_dir / 'sybil_padding_sweep.csv'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
