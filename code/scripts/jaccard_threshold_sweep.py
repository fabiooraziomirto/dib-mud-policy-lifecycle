from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dib.core.io import read_observations_csv, write_csv, write_json
from dib.evaluation.dib import DIBScorer, ScoringConfig
from dib.evaluation.independence import (
    build_site_similarity_graph,
    compute_site_clusters,
    compute_site_endpoint_sets,
)
from dib.experiments.poisoning import inject_sybil_endpoint
from dib.simulator.sites import partition_observations

FAKE_ENDPOINT = "evil-c2.net"
OUTPUT_DIR = Path("outputs/jaccard_threshold_sweep")


def _float_list(values: str) -> list[float]:
    return [float(v) for v in values.split(",") if v.strip()]


def _int_list(values: str) -> list[int]:
    return [int(v) for v in values.split(",") if v.strip()]


def _effective_cluster_count(observations, target_device_type: str, threshold: float) -> int:
    site_endpoints = compute_site_endpoint_sets(observations, target_device_type)
    graph = build_site_similarity_graph(site_endpoints, similarity_threshold=threshold)
    clusters = compute_site_clusters(graph)
    return len(set(clusters.values()))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Sweep the Jaccard threshold used by independence-aware scoring. "
        "For each threshold and static-Sybil frontier point, report effective site "
        "clusters, accepted endpoints, fake score, fake acceptance, and whether the "
        "attacked device profile is empty."
    )
    parser.add_argument("--observations", default="data/processed/observations_enriched.csv")
    parser.add_argument("--output-dir", default=str(OUTPUT_DIR))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--site-count", type=int, default=10)
    parser.add_argument("--partition-strategy", default="random", choices=["random", "device_balanced", "time_window"])
    parser.add_argument("--thresholds", default="0.5,0.6,0.7,0.8,0.9,0.95")
    parser.add_argument(
        "--sybil-site-counts",
        default="1,2,5,10,20,50,100,200,400,800,1600",
        help="Static Sybil frontier points to evaluate at each threshold.",
    )
    parser.add_argument("--fake-fqdn", default=FAKE_ENDPOINT)
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    observations = read_observations_csv(Path(args.observations))
    sites = partition_observations(observations, args.site_count, strategy=args.partition_strategy, seed=args.seed)
    observations = [observation for site in sites for observation in site.observations]
    target_device_type = Counter(o.device_type for o in observations).most_common(1)[0][0]

    thresholds = _float_list(args.thresholds)
    sybil_counts = _int_list(args.sybil_site_counts)
    rows = []
    summary_rows = []

    for threshold in thresholds:
        clean_config = ScoringConfig(independence_aware=True, independence_similarity_threshold=threshold, min_reporting_sites=2)
        clean_scores = DIBScorer(clean_config).score(observations, target_device_type=target_device_type)
        clean_effective_clusters = _effective_cluster_count(observations, target_device_type, threshold)
        clean_accepted = sum(1 for score in clean_scores if score.accepted)
        first_fake_accepted = ""
        first_empty_profile = ""

        for sybil_count in sybil_counts:
            poisoned = inject_sybil_endpoint(
                observations,
                sybil_count,
                target_device_type=target_device_type,
                fake_fqdn=args.fake_fqdn,
                seed=args.seed,
            )
            config = ScoringConfig(independence_aware=True, independence_similarity_threshold=threshold, min_reporting_sites=2)
            scores = DIBScorer(config).score(poisoned, target_device_type=target_device_type)
            effective_clusters = _effective_cluster_count(poisoned, target_device_type, threshold)
            accepted_non_fake = sum(1 for s in scores if s.accepted and s.endpoint != args.fake_fqdn)
            fake_scores = [s for s in scores if s.endpoint == args.fake_fqdn]
            fake_score = max((s.score for s in fake_scores), default=0.0)
            fake_accepted = any(s.accepted for s in fake_scores)
            profile_empty = accepted_non_fake == 0
            if fake_accepted and first_fake_accepted == "":
                first_fake_accepted = sybil_count
            if profile_empty and first_empty_profile == "":
                first_empty_profile = sybil_count
            row = {
                "jaccard_threshold": threshold,
                "sybil_site_count": sybil_count,
                "alpha": config.alpha,
                "beta": config.beta,
                "gamma": config.gamma,
                "theta": config.theta,
                "target_device_type": target_device_type,
                "clean_effective_cluster_count": clean_effective_clusters,
                "effective_cluster_count": effective_clusters,
                "clean_accepted_endpoint_count": clean_accepted,
                "accepted_endpoint_count": accepted_non_fake,
                "fake_endpoint_score": round(fake_score, 6),
                "fake_accepted": fake_accepted,
                "attacked_profile_empty": profile_empty,
            }
            rows.append(row)
            print(
                f"threshold={threshold:.2f} sybils={sybil_count}: "
                f"clusters={effective_clusters}, accepted={accepted_non_fake}, "
                f"fake_score={fake_score:.6f}, fake_accepted={fake_accepted}, "
                f"empty={profile_empty}",
                flush=True,
            )

        summary_rows.append(
            {
                "jaccard_threshold": threshold,
                "target_device_type": target_device_type,
                "clean_effective_cluster_count": clean_effective_clusters,
                "clean_accepted_endpoint_count": clean_accepted,
                "first_sybil_count_fake_accepted": first_fake_accepted,
                "first_sybil_count_profile_empty": first_empty_profile,
            }
        )

    fields = [
        "jaccard_threshold",
        "sybil_site_count",
        "alpha",
        "beta",
        "gamma",
        "theta",
        "target_device_type",
        "clean_effective_cluster_count",
        "effective_cluster_count",
        "clean_accepted_endpoint_count",
        "accepted_endpoint_count",
        "fake_endpoint_score",
        "fake_accepted",
        "attacked_profile_empty",
    ]
    write_csv(output_dir / "jaccard_threshold_sweep.csv", rows, fields)
    write_csv(
        output_dir / "jaccard_threshold_sweep_summary.csv",
        summary_rows,
        [
            "jaccard_threshold",
            "target_device_type",
            "clean_effective_cluster_count",
            "clean_accepted_endpoint_count",
            "first_sybil_count_fake_accepted",
            "first_sybil_count_profile_empty",
        ],
    )
    write_json(
        output_dir / "jaccard_threshold_sweep_manifest.json",
        {
            "experiment": "jaccard_threshold_sweep",
            "observations": args.observations,
            "site_count": args.site_count,
            "partition_strategy": args.partition_strategy,
            "seed": args.seed,
            "target_device_type": target_device_type,
            "thresholds": thresholds,
            "sybil_site_counts": sybil_counts,
            "fake_fqdn": args.fake_fqdn,
            "scoring_mode": "independence_aware",
            "scoring_weights": {"alpha": 0.5, "beta": 0.3, "gamma": 0.2, "theta": 0.65},
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
