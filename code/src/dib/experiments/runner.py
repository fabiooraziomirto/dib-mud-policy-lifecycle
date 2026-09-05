from __future__ import annotations

import argparse
import json
import time
import tracemalloc
from collections import Counter
from dataclasses import replace as dataclass_replace
from pathlib import Path

from dib.core.io import filter_observations, read_observations_csv, stream_observations_csv, write_csv, write_json
from dib.evaluation.baselines import (
    FrequencyFilteredBaseline,
    LocalProfilingBaseline,
    MajorityVotingBaseline,
    ReputationWeightedVotingBaseline,
    WeightedVotingBaseline,
)
from dib.evaluation.dib import DIBScorer, ScoringConfig, accepted_endpoint_keys
from dib.evaluation.global_profiles import build_global_profiles, export_global_profiles
from dib.evaluation.graph import export_graph, export_graph_confidence, export_graph_explanations, graph_confidence
from dib.evaluation.local_profiling import build_all_local_profiles, export_all_local_profiles
from dib.evaluation.profiles import (
    PREDICTED_DIRECTION,
    canonical_device_name,
    load_profile_dir,
    normalize_profile_protocol,
    semantic_match_metrics,
)
from dib.evaluation.independence import build_site_similarity_graph, compute_site_clusters, compute_site_endpoint_sets
from dib.evaluation.trust import build_reputation_snapshot, calibrate_reference_breadth, compute_site_trust_weights
from dib.experiments.cold_start import cold_start_rows, summarize_cold_start
from dib.experiments.drift import drift_classification_rows, summarize_drift
from dib.experiments.firmware import inject_legitimate_endpoint
from dib.experiments.lifecycle import lifecycle_churn_rows, summarize_lifecycle
from dib.experiments.management_attack import (
    evaluate_management_strategies,
    management_auditability_rows,
    management_rows_from_evaluations,
)
from dib.experiments.attestation_cost import attestation_cost_rows, summarize_attestation_cost
from dib.experiments.registry_cost import registry_cost_rows, summarize_registry_cost
from dib.experiments.poisoning import (
    inject_adaptive_sybil_endpoint,
    inject_diversified_sybil_endpoint,
    inject_fake_endpoint,
    inject_sybil_endpoint,
)
from dib.simulator.sites import partition_observations


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = _load_config(args.config)
    if args.no_graph:
        config.setdefault("scoring", {})["graph_enabled"] = False
    if args.graph_max_endpoints_per_device is not None:
        config.setdefault("scoring", {})["graph_max_endpoints_per_device"] = args.graph_max_endpoints_per_device
    input_path = Path(args.observations or config["experiments"]["observations_csv"])
    output_dir = Path(args.output_dir or config["outputs"]["root"])

    if args.stream:
        if args.experiment != "reconstruction":
            parser.error("--stream currently supports --experiment reconstruction")
        if args.site_count:
            parser.error("--stream cannot be combined with --site-count")
        observations = stream_observations_csv(input_path)
    else:
        observations = read_observations_csv(input_path)
    if args.exclude_non_global_ips:
        observations = filter_observations(observations, exclude_non_global_ips=True)
    if args.site_count:
        sites = partition_observations(
            observations,
            args.site_count,
            strategy=args.partition_strategy,
            seed=config["experiments"]["seed"],
        )
        observations = [observation for site in sites for observation in site.observations]
    if args.experiment in {"all", "reconstruction"}:
        run_reconstruction(observations, output_dir, config)
    if args.experiment in {"all", "poisoning"}:
        run_poisoning(observations, output_dir, config)
    if args.experiment in {"all", "management_attack"}:
        run_management_attack(observations, output_dir, config, ground_truth_dir=args.ground_truth_dir)
    if args.experiment in {"all", "registry_cost"}:
        run_registry_cost(observations, output_dir, config)
    if args.experiment in {"all", "attestation_cost"}:
        run_attestation_cost(observations, output_dir, config)
    if args.experiment in {"all", "cold_start"}:
        run_cold_start(observations, output_dir, config, ground_truth_dir=args.ground_truth_dir)
    if args.experiment in {"all", "firmware"}:
        run_firmware(observations, output_dir, config)
    if args.experiment in {"all", "drift"}:
        run_drift(observations, output_dir, config)
    if args.experiment in {"all", "lifecycle"}:
        run_lifecycle(observations, output_dir, config)
    if args.experiment in {"all", "scalability"}:
        run_scalability(observations, output_dir, config, partition_strategy=args.partition_strategy)
    if args.experiment in {"all", "ablation"}:
        run_ablation(observations, output_dir, config, ground_truth_dir=args.ground_truth_dir)
    if args.experiment in {"all", "sensitivity"}:
        run_sensitivity(observations, output_dir, config)
    write_json(
        output_dir / "experiment_manifest.json",
        {
            "input": str(input_path),
            "experiment": args.experiment,
            "stream": args.stream,
            "exclude_non_global_ips": args.exclude_non_global_ips,
            "graph_enabled": not args.no_graph,
            "graph_max_endpoints_per_device": args.graph_max_endpoints_per_device,
        },
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run DIB experimental setup over normalized real observations.")
    parser.add_argument("--config", default="configs/default_hyperparams.yaml")
    parser.add_argument("--observations", help="CSV containing normalized Observation rows")
    parser.add_argument("--output-dir", help="Directory for experiment outputs")
    parser.add_argument("--site-count", type=int, help="Redistribute observations across this many simulated sites")
    parser.add_argument(
        "--stream",
        action="store_true",
        help="Keep RAM bounded by scanning the observation CSV incrementally (reconstruction only).",
    )
    parser.add_argument(
        "--no-graph",
        action="store_true",
        help="Skip the dense endpoint co-occurrence graph and renormalize site/temporal scoring.",
    )
    parser.add_argument(
        "--graph-max-endpoints-per-device",
        type=int,
        metavar="N",
        help="Build the exact graph only over the N strongest endpoint candidates per device.",
    )
    parser.add_argument(
        "--exclude-non-global-ips",
        action="store_true",
        help="Exclude IP-only endpoints that are private, reserved, link-local, or otherwise non-global.",
    )
    parser.add_argument(
        "--partition-strategy",
        choices=["random", "device_balanced", "time_window"],
        default="device_balanced",
    )
    parser.add_argument(
        "--experiment",
        choices=[
            "all",
            "reconstruction",
            "poisoning",
            "management_attack",
            "registry_cost",
            "attestation_cost",
            "cold_start",
            "firmware",
            "drift",
            "lifecycle",
            "scalability",
            "ablation",
            "sensitivity",
        ],
        default="all",
    )
    parser.add_argument(
        "--ground-truth-dir",
        default="data/unsw/profiles/normalized",
        help="Reference profile directory used by the ablation experiment to report mean F1 per variant.",
    )
    return parser


def run_reconstruction(observations, output_dir: Path, config: dict) -> None:
    experiment_dir = output_dir / "experiments" / "reconstruction"
    scoring_config = _scoring_config(config, observations)
    scorer = DIBScorer(scoring_config)
    dib_scores = scorer.score(observations)
    _write_scores(experiment_dir / "dib_scores.csv", dib_scores)
    _write_scores(output_dir / "final_scores.csv", dib_scores)

    write_csv(
        output_dir / "site_confidence.csv",
        [
            {
                "device_type": s.device_type,
                "endpoint": s.endpoint,
                "protocol": s.protocol,
                "port": s.port,
                "site_confidence": round(s.site_confidence, 6),
                "supporting_sites": s.supporting_sites,
                "eligible_sites": s.eligible_sites,
            }
            for s in dib_scores
        ],
        ["device_type", "endpoint", "protocol", "port", "site_confidence", "supporting_sites", "eligible_sites"],
    )
    write_csv(
        output_dir / "temporal_confidence.csv",
        [
            {
                "device_type": s.device_type,
                "endpoint": s.endpoint,
                "protocol": s.protocol,
                "port": s.port,
                "temporal_confidence": round(s.temporal_confidence, 6),
            }
            for s in dib_scores
        ],
        ["device_type", "endpoint", "protocol", "port", "temporal_confidence"],
    )

    if scorer.last_graph is not None:
        export_graph(scorer.last_graph, output_dir)
        node_scores = graph_confidence(scorer.last_graph)
        export_graph_confidence(node_scores, output_dir)
        export_graph_explanations(scorer.last_graph, node_scores, output_dir)

    global_profiles = build_global_profiles(dib_scores, scoring_config)
    export_global_profiles(global_profiles, output_dir / "global_profiles")

    local_profiles = build_all_local_profiles(observations)
    export_all_local_profiles(local_profiles, output_dir / "local_profiles")

    baselines = [
        LocalProfilingBaseline(),
        MajorityVotingBaseline(),
        WeightedVotingBaseline(threshold=config["baselines"]["weighted_threshold"]),
        ReputationWeightedVotingBaseline(
            build_reputation_snapshot(observations), threshold=config["scoring"]["theta"]
        ),
        FrequencyFilteredBaseline(min_count=config["baselines"]["frequency_min_count"]),
    ]
    rows = []
    accepted = accepted_endpoint_keys(dib_scores)
    for baseline in baselines:
        baseline.fit(observations)
        baseline.export(experiment_dir / "baselines")
        for device_type in sorted(baseline.device_types):
            prediction = baseline.predict(device_type)
            rows.append(
                {
                    "method": baseline.name,
                    "device_type": device_type,
                    "endpoint_count": len(prediction),
                }
            )
    rows.append({"method": "dib", "device_type": "all", "endpoint_count": len(accepted)})
    write_csv(experiment_dir / "profile_reconstruction_summary.csv", rows, ["method", "device_type", "endpoint_count"])


def run_poisoning(observations, output_dir: Path, config: dict) -> None:
    rows = []
    for fraction in config["experiments"]["malicious_site_fractions"]:
        poisoned = inject_fake_endpoint(observations, fraction, seed=config["experiments"]["seed"])
        scores = DIBScorer(_scoring_config(config, observations)).score(poisoned)
        fake_scores = [score for score in scores if score.endpoint == "evil-c2.net"]
        accepted = any(score.accepted for score in fake_scores)
        max_score = max((score.score for score in fake_scores), default=0.0)
        rows.append(
            {
                "malicious_fraction": fraction,
                "fake_endpoint_accepted": accepted,
                "fake_endpoint_score": max_score,
            }
        )
    write_csv(output_dir / "experiments" / "poisoning" / "poisoning_resistance.csv", rows, ["malicious_fraction", "fake_endpoint_accepted", "fake_endpoint_score"])
    run_sybil_poisoning(observations, output_dir, config)
    run_combined_attack(observations, output_dir, config)
    run_diversified_sybil(observations, output_dir, config)


def run_management_attack(
    observations,
    output_dir: Path,
    config: dict,
    ground_truth_dir: str | None = None,
) -> None:
    """TNSM management-strategy comparison under bounded and Sybil attacks.

    Writes to its own additive experiment directory. In particular, it does not
    change any of the established poisoning CSV schemas consumed by the paper.
    """
    target_device_type = Counter(obs.device_type for obs in observations).most_common(1)[0][0]
    # Forced vanilla regardless of config["scoring"]["trust_weighted"]: this base config
    # is the "dib_vanilla" comparison point inside evaluate_management_strategies, which
    # derives its own trust-weighted/independence-aware variants from it. Letting a
    # trust_weighted YAML flag leak in here would silently corrupt the vanilla baseline
    # with an uncalibrated (zero) trust_reference_breadth.
    scoring_config = dataclass_replace(
        _scoring_config(config), trust_weighted=False, independence_aware=False, combined_mitigation=False
    )
    truth_path = Path(ground_truth_dir or "data/unsw/profiles/normalized")
    truth_profiles = load_profile_dir(truth_path) if truth_path.exists() else {}
    truth = truth_profiles.get(canonical_device_name(target_device_type), set())
    rows = []
    auditability_rows = []

    def append_results(poisoned, attack_type: str, attack_budget: float | int) -> None:
        evaluations = evaluate_management_strategies(
            poisoned,
            observations,
            target_device_type,
            scoring_config,
            frequency_min_count=config["baselines"]["frequency_min_count"],
        )
        rows.extend(
            management_rows_from_evaluations(
                evaluations, attack_type, attack_budget, target_device_type
            )
        )
        auditability_rows.extend(
            management_auditability_rows(
                evaluations, truth, attack_type, attack_budget, target_device_type
            )
        )

    for fraction in config["experiments"]["malicious_site_fractions"]:
        poisoned = inject_fake_endpoint(observations, fraction, seed=config["experiments"]["seed"])
        append_results(poisoned, "bounded_poisoning", fraction)
    for sybil_count in config["experiments"]["sybil_site_counts"]:
        poisoned = inject_sybil_endpoint(
            observations,
            sybil_count,
            target_device_type,
            seed=config["experiments"]["seed"],
        )
        append_results(poisoned, "sybil", sybil_count)
    adaptive_sybil_count = max(config["experiments"]["sybil_site_counts"])
    for spread_days in config["experiments"].get(
        "management_attack_adaptive_days",
        config["experiments"]["adaptive_sybil_spread_days"],
    ):
        poisoned = inject_adaptive_sybil_endpoint(
            observations,
            adaptive_sybil_count,
            target_device_type,
            spread_days,
            seed=config["experiments"]["seed"],
        )
        append_results(poisoned, f"adaptive_sybil_{adaptive_sybil_count}_sites", spread_days)
    write_csv(
        output_dir / "experiments" / "management_attack" / "management_strategies_under_attack.csv",
        rows,
        [
            "attack_type",
            "attack_budget",
            "target_device_type",
            "strategy",
            "policy_scope",
            "evaluated_unit_count",
            "policy_endpoint_count",
            "fake_endpoint_accepted",
            "false_grant_rate",
            "fake_endpoint_score",
        ],
    )
    write_csv(
        output_dir / "experiments" / "management_attack" / "policy_auditability_under_attack.csv",
        auditability_rows,
        [
            "attack_type",
            "attack_budget",
            "target_device_type",
            "strategy",
            "policy_scope",
            "evaluated_policy_count",
            "mean_policy_endpoint_count",
            "mean_estimated_acl_entries",
            "mean_normalized_profile_bytes",
            "mean_semantic_precision",
            "mean_semantic_recall",
            "mean_semantic_f1",
            "mean_monitor_only_exception_candidates",
            "mean_denied_endpoint_rate",
            "fake_endpoint_accepted",
            "false_grant_rate",
        ],
    )


def run_registry_cost(observations, output_dir: Path, config: dict) -> None:
    experiment_dir = output_dir / "experiments" / "registry_cost"
    target_device_type = Counter(obs.device_type for obs in observations).most_common(1)[0][0]
    rows = registry_cost_rows(
        observations,
        target_device_type,
        experiment_dir / "benchmark_registry.db",
        query_repeats=config["experiments"].get("registry_query_repeats", 30),
    )
    detail_fields = [
        "operation", "sample_index", "site_id", "payload_endpoint_count",
        "latency_ms", "version_snapshot_bytes", "registry_db_bytes",
    ]
    write_csv(experiment_dir / "registry_incremental_cost.csv", rows, detail_fields)
    write_csv(
        experiment_dir / "registry_incremental_cost_summary.csv",
        summarize_registry_cost(rows),
        [
            "operation", "sample_count", "mean_latency_ms", "p50_latency_ms",
            "p95_latency_ms", "mean_payload_endpoint_count",
            "mean_version_snapshot_bytes", "final_registry_db_bytes",
        ],
    )


def run_attestation_cost(observations, output_dir: Path, config: dict) -> None:
    experiment_dir = output_dir / "experiments" / "attestation_cost"
    target_device_type = Counter(obs.device_type for obs in observations).most_common(1)[0][0]
    rows = attestation_cost_rows(
        observations,
        target_device_type,
        _scoring_config(config, observations),
        experiment_dir / "benchmark_attestation.db",
        max_endpoints=config["experiments"].get("attestation_cost_max_endpoints", 30),
    )
    write_csv(
        experiment_dir / "attestation_lifecycle_cost.csv",
        rows,
        ["operation", "sample_index", "latency_ms", "sibling_endpoints_changed", "registry_db_bytes"],
    )
    write_csv(
        experiment_dir / "attestation_lifecycle_cost_summary.csv",
        summarize_attestation_cost(rows),
        [
            "operation", "sample_count", "mean_latency_ms", "p50_latency_ms",
            "p95_latency_ms", "total_sibling_endpoints_changed", "final_registry_db_bytes",
        ],
    )


def run_cold_start(observations, output_dir: Path, config: dict, ground_truth_dir: str | None = None) -> None:
    truth_path = Path(ground_truth_dir or "data/unsw/profiles/normalized")
    truth = load_profile_dir(truth_path) if truth_path.exists() else {}
    rows = cold_start_rows(
        observations,
        truth,
        _scoring_config(config, observations),
        windows=config["experiments"].get("cold_start_window_days"),
    )
    fieldnames = [
        "site_id",
        "window_days",
        "method",
        "device_count",
        "predicted_endpoint_count",
        "mean_semantic_precision",
        "mean_semantic_recall",
        "mean_semantic_f1",
    ]
    write_csv(output_dir / "experiments" / "cold_start" / "cold_start_convergence.csv", rows, fieldnames)
    write_csv(
        output_dir / "experiments" / "cold_start" / "cold_start_summary.csv",
        summarize_cold_start(rows),
        [
            "window_days",
            "method",
            "site_count",
            "mean_semantic_precision",
            "mean_semantic_recall",
            "mean_semantic_f1",
            "mean_predicted_endpoint_count",
        ],
    )


def run_sybil_poisoning(observations, output_dir: Path, config: dict) -> None:
    """Coordinated adversary: Sybil site identities rather than a fraction of
    compromised real sites (see dib/experiments/poisoning.py:inject_sybil_endpoint).
    Targets the device_type with the most observations, since it is guaranteed to
    have a template and gives the adversary the largest real `eligible_sites`
    denominator to overcome. Reports both vanilla and trust-weighted scoring
    (the reference breadth is calibrated on `observations`, the clean pre-attack
    baseline, never on the poisoned population -- see dib/evaluation/trust.py)."""
    target_device_type = Counter(obs.device_type for obs in observations).most_common(1)[0][0]
    trust_reference = calibrate_reference_breadth(observations)
    # Forced vanilla regardless of config["scoring"]["trust_weighted"]: this is the
    # comparison baseline that trusted_config/independence_config/combined_config are
    # derived from below via dataclass_replace. See run_management_attack for why the
    # YAML flag must not leak into this base.
    vanilla_config = dataclass_replace(
        _scoring_config(config), trust_weighted=False, independence_aware=False, combined_mitigation=False
    )
    trusted_config = dataclass_replace(vanilla_config, trust_weighted=True, trust_reference_breadth=trust_reference)
    independence_config = dataclass_replace(vanilla_config, independence_aware=True)
    combined_config = dataclass_replace(
        vanilla_config, combined_mitigation=True, trust_reference_breadth=trust_reference
    )
    rows = []
    for sybil_count in config["experiments"]["sybil_site_counts"]:
        poisoned = inject_sybil_endpoint(
            observations, sybil_count, target_device_type, seed=config["experiments"]["seed"]
        )
        vanilla_scores = DIBScorer(vanilla_config).score(poisoned)
        trusted_scores = DIBScorer(trusted_config).score(poisoned)
        independence_scores = DIBScorer(independence_config).score(poisoned)
        combined_scores = DIBScorer(combined_config).score(poisoned)
        vanilla_fake = [score for score in vanilla_scores if score.endpoint == "evil-c2.net"]
        trusted_fake = [score for score in trusted_scores if score.endpoint == "evil-c2.net"]
        independence_fake = [score for score in independence_scores if score.endpoint == "evil-c2.net"]
        combined_fake = [score for score in combined_scores if score.endpoint == "evil-c2.net"]
        rows.append(
            {
                "sybil_site_count": sybil_count,
                "target_device_type": target_device_type,
                "fake_endpoint_accepted": any(score.accepted for score in vanilla_fake),
                "fake_endpoint_score": max((score.score for score in vanilla_fake), default=0.0),
                "fake_endpoint_accepted_trusted": any(score.accepted for score in trusted_fake),
                "fake_endpoint_score_trusted": max((score.score for score in trusted_fake), default=0.0),
                "fake_endpoint_accepted_independence": any(score.accepted for score in independence_fake),
                "fake_endpoint_score_independence": max(
                    (score.score for score in independence_fake), default=0.0
                ),
                "fake_endpoint_accepted_combined": any(score.accepted for score in combined_fake),
                "fake_endpoint_score_combined": max((score.score for score in combined_fake), default=0.0),
            }
        )
    write_csv(
        output_dir / "experiments" / "poisoning" / "sybil_resistance.csv",
        rows,
        [
            "sybil_site_count",
            "target_device_type",
            "fake_endpoint_accepted",
            "fake_endpoint_score",
            "fake_endpoint_accepted_trusted",
            "fake_endpoint_score_trusted",
            "fake_endpoint_accepted_independence",
            "fake_endpoint_score_independence",
            "fake_endpoint_accepted_combined",
            "fake_endpoint_score_combined",
        ],
    )
    run_adaptive_sybil_poisoning(observations, output_dir, config, target_device_type, trust_reference)


def run_adaptive_sybil_poisoning(
    observations, output_dir: Path, config: dict, target_device_type: str, trust_reference: float
) -> None:
    """Adaptive escalation of the Sybil attack: holds the Sybil count fixed at the
    largest value tested in run_sybil_poisoning and sweeps how many distinct days
    each Sybil sustains its presence, to see whether a longer-running campaign
    closes the temporal_confidence gap that a single-shot Sybil cannot. Reports
    vanilla, trust-weighted, and independence-aware scoring, same calibration as
    run_sybil_poisoning."""
    sybil_count = max(config["experiments"]["sybil_site_counts"])
    # Forced vanilla regardless of config["scoring"]["trust_weighted"]: this is the
    # comparison baseline that trusted_config/independence_config/combined_config are
    # derived from below via dataclass_replace. See run_management_attack for why the
    # YAML flag must not leak into this base.
    vanilla_config = dataclass_replace(
        _scoring_config(config), trust_weighted=False, independence_aware=False, combined_mitigation=False
    )
    trusted_config = dataclass_replace(vanilla_config, trust_weighted=True, trust_reference_breadth=trust_reference)
    independence_config = dataclass_replace(vanilla_config, independence_aware=True)
    combined_config = dataclass_replace(
        vanilla_config, combined_mitigation=True, trust_reference_breadth=trust_reference
    )
    rows = []
    for spread_days in config["experiments"]["adaptive_sybil_spread_days"]:
        poisoned = inject_adaptive_sybil_endpoint(
            observations,
            sybil_count,
            target_device_type,
            spread_days,
            seed=config["experiments"]["seed"],
        )
        vanilla_scores = DIBScorer(vanilla_config).score(poisoned)
        trusted_scores = DIBScorer(trusted_config).score(poisoned)
        independence_scores = DIBScorer(independence_config).score(poisoned)
        combined_scores = DIBScorer(combined_config).score(poisoned)
        vanilla_fake = [score for score in vanilla_scores if score.endpoint == "evil-c2.net"]
        trusted_fake = [score for score in trusted_scores if score.endpoint == "evil-c2.net"]
        independence_fake = [score for score in independence_scores if score.endpoint == "evil-c2.net"]
        combined_fake = [score for score in combined_scores if score.endpoint == "evil-c2.net"]
        rows.append(
            {
                "sybil_site_count": sybil_count,
                "spread_days": spread_days,
                "target_device_type": target_device_type,
                "fake_endpoint_accepted": any(score.accepted for score in vanilla_fake),
                "fake_endpoint_score": max((score.score for score in vanilla_fake), default=0.0),
                "fake_endpoint_accepted_trusted": any(score.accepted for score in trusted_fake),
                "fake_endpoint_score_trusted": max((score.score for score in trusted_fake), default=0.0),
                "fake_endpoint_accepted_independence": any(score.accepted for score in independence_fake),
                "fake_endpoint_score_independence": max(
                    (score.score for score in independence_fake), default=0.0
                ),
                "fake_endpoint_accepted_combined": any(score.accepted for score in combined_fake),
                "fake_endpoint_score_combined": max((score.score for score in combined_fake), default=0.0),
            }
        )
    write_csv(
        output_dir / "experiments" / "poisoning" / "adaptive_sybil_resistance.csv",
        rows,
        [
            "sybil_site_count",
            "spread_days",
            "target_device_type",
            "fake_endpoint_accepted",
            "fake_endpoint_score",
            "fake_endpoint_accepted_trusted",
            "fake_endpoint_score_trusted",
            "fake_endpoint_accepted_independence",
            "fake_endpoint_score_independence",
            "fake_endpoint_accepted_combined",
            "fake_endpoint_score_combined",
        ],
    )


def run_combined_attack(observations, output_dir: Path, config: dict) -> None:
    """TDSC roadmap P1 #6: bounded poisoner (a fraction of real, compromised
    sites) overlaid with an adaptive Sybil campaign, both corroborating the
    SAME fake endpoint -- the worst case for the defender, since neither
    attack alone has to carry the full burden of reaching theta. Evaluated
    under all three scoring modes plus the new combined mitigation."""
    target_device_type = Counter(obs.device_type for obs in observations).most_common(1)[0][0]
    trust_reference = calibrate_reference_breadth(observations)
    # Forced vanilla regardless of config["scoring"]["trust_weighted"]: this is the
    # comparison baseline that trusted_config/independence_config/combined_config are
    # derived from below via dataclass_replace. See run_management_attack for why the
    # YAML flag must not leak into this base.
    vanilla_config = dataclass_replace(
        _scoring_config(config), trust_weighted=False, independence_aware=False, combined_mitigation=False
    )
    trusted_config = dataclass_replace(vanilla_config, trust_weighted=True, trust_reference_breadth=trust_reference)
    independence_config = dataclass_replace(vanilla_config, independence_aware=True)
    combined_config = dataclass_replace(
        vanilla_config, combined_mitigation=True, trust_reference_breadth=trust_reference
    )
    sybil_count = max(config["experiments"]["sybil_site_counts"])
    rows = []
    for malicious_fraction in config["experiments"]["combined_attack_malicious_fractions"]:
        bounded = inject_fake_endpoint(observations, malicious_fraction, seed=config["experiments"]["seed"])
        for spread_days in config["experiments"]["combined_attack_spread_days"]:
            overlaid = inject_adaptive_sybil_endpoint(
                bounded,
                sybil_count,
                target_device_type,
                spread_days,
                seed=config["experiments"]["seed"],
            )
            scored = {
                "vanilla": DIBScorer(vanilla_config).score(overlaid),
                "trusted": DIBScorer(trusted_config).score(overlaid),
                "independence": DIBScorer(independence_config).score(overlaid),
                "combined": DIBScorer(combined_config).score(overlaid),
            }
            row = {
                "malicious_fraction": malicious_fraction,
                "sybil_site_count": sybil_count,
                "spread_days": spread_days,
                "target_device_type": target_device_type,
            }
            for mode, scores in scored.items():
                fake = [score for score in scores if score.endpoint == "evil-c2.net"]
                row[f"fake_endpoint_accepted_{mode}"] = any(score.accepted for score in fake)
                row[f"fake_endpoint_score_{mode}"] = max((score.score for score in fake), default=0.0)
            rows.append(row)
    write_csv(
        output_dir / "experiments" / "poisoning" / "combined_attack_resistance.csv",
        rows,
        [
            "malicious_fraction",
            "sybil_site_count",
            "spread_days",
            "target_device_type",
            "fake_endpoint_accepted_vanilla",
            "fake_endpoint_score_vanilla",
            "fake_endpoint_accepted_trusted",
            "fake_endpoint_score_trusted",
            "fake_endpoint_accepted_independence",
            "fake_endpoint_score_independence",
            "fake_endpoint_accepted_combined",
            "fake_endpoint_score_combined",
        ],
    )


def run_diversified_sybil(observations, output_dir: Path, config: dict) -> None:
    """TDSC roadmap P1 #6: anti-clustering / breadth-fabrication adversary.
    Each Sybil pads its profile with real, distinct, benign-looking endpoints
    (see dib/experiments/poisoning.py:inject_diversified_sybil_endpoint) to
    probe whether padding (a) breaks independence-aware clustering and (b)
    inflates trust-weighted scoring, at the known 140-day adaptive breakdown
    point and fixed Sybil count."""
    target_device_type = Counter(obs.device_type for obs in observations).most_common(1)[0][0]
    trust_reference = calibrate_reference_breadth(observations)
    # Forced vanilla regardless of config["scoring"]["trust_weighted"]: this is the
    # comparison baseline that trusted_config/independence_config/combined_config are
    # derived from below via dataclass_replace. See run_management_attack for why the
    # YAML flag must not leak into this base.
    vanilla_config = dataclass_replace(
        _scoring_config(config), trust_weighted=False, independence_aware=False, combined_mitigation=False
    )
    trusted_config = dataclass_replace(vanilla_config, trust_weighted=True, trust_reference_breadth=trust_reference)
    independence_config = dataclass_replace(vanilla_config, independence_aware=True)
    combined_config = dataclass_replace(
        vanilla_config, combined_mitigation=True, trust_reference_breadth=trust_reference
    )
    sybil_count = max(config["experiments"]["sybil_site_counts"])
    spread_days = 140
    rows = []
    for padding in config["experiments"]["diversified_sybil_padding"]:
        poisoned = inject_diversified_sybil_endpoint(
            observations,
            sybil_count,
            target_device_type,
            spread_days,
            padding_per_sybil=padding,
            seed=config["experiments"]["seed"],
        )
        site_endpoints = compute_site_endpoint_sets(poisoned, target_device_type)
        similarity_graph = build_site_similarity_graph(site_endpoints)
        clusters = compute_site_clusters(similarity_graph)
        sybil_sites = [site for site in site_endpoints if site.startswith("sybil-")]
        sybil_cluster_count = len({clusters[site] for site in sybil_sites}) if sybil_sites else 0

        trust_weights = compute_site_trust_weights(poisoned, reference_breadth=trust_reference)
        mean_sybil_trust_weight = (
            sum(trust_weights.get(site, 0.0) for site in sybil_sites) / len(sybil_sites) if sybil_sites else 0.0
        )

        scored = {
            "vanilla": DIBScorer(vanilla_config).score(poisoned),
            "trusted": DIBScorer(trusted_config).score(poisoned),
            "independence": DIBScorer(independence_config).score(poisoned),
            "combined": DIBScorer(combined_config).score(poisoned),
        }
        row = {
            "padding_per_sybil": padding,
            "sybil_site_count": sybil_count,
            "spread_days": spread_days,
            "target_device_type": target_device_type,
            "sybil_cluster_count": sybil_cluster_count,
            "mean_sybil_trust_weight": round(mean_sybil_trust_weight, 6),
        }
        for mode, scores in scored.items():
            fake = [score for score in scores if score.endpoint == "evil-c2.net"]
            row[f"fake_endpoint_accepted_{mode}"] = any(score.accepted for score in fake)
            row[f"fake_endpoint_score_{mode}"] = max((score.score for score in fake), default=0.0)
        rows.append(row)
    write_csv(
        output_dir / "experiments" / "poisoning" / "diversified_sybil_resistance.csv",
        rows,
        [
            "padding_per_sybil",
            "sybil_site_count",
            "spread_days",
            "target_device_type",
            "sybil_cluster_count",
            "mean_sybil_trust_weight",
            "fake_endpoint_accepted_vanilla",
            "fake_endpoint_score_vanilla",
            "fake_endpoint_accepted_trusted",
            "fake_endpoint_score_trusted",
            "fake_endpoint_accepted_independence",
            "fake_endpoint_score_independence",
            "fake_endpoint_accepted_combined",
            "fake_endpoint_score_combined",
        ],
    )


def run_firmware(observations, output_dir: Path, config: dict) -> None:
    rows = []
    for fraction in config["experiments"]["firmware_adoption_fractions"]:
        updated = inject_legitimate_endpoint(observations, fraction, seed=config["experiments"]["seed"])
        scores = DIBScorer(_scoring_config(config, observations)).score(updated)
        endpoint_scores = [score for score in scores if score.endpoint == "new-firmware.vendor.example"]
        accepted = any(score.accepted for score in endpoint_scores)
        max_score = max((score.score for score in endpoint_scores), default=0.0)
        rows.append(
            {
                "adoption_fraction": fraction,
                "new_endpoint_accepted": accepted,
                "new_endpoint_score": max_score,
            }
        )
    write_csv(output_dir / "experiments" / "firmware" / "firmware_adaptation.csv", rows, ["adoption_fraction", "new_endpoint_accepted", "new_endpoint_score"])


def run_drift(observations, output_dir: Path, config: dict) -> None:
    rows = drift_classification_rows(
        observations,
        _scoring_config(config, observations),
        adoption_fractions=config["experiments"]["firmware_adoption_fractions"],
        promote_fraction=config["experiments"].get("drift_promote_fraction", 0.6),
        attack_spread_days=config["experiments"].get("drift_attack_spread_days"),
        seed=config["experiments"]["seed"],
    )
    write_csv(
        output_dir / "experiments" / "drift" / "drift_classification.csv",
        rows,
        [
            "scenario",
            "adoption_fraction",
            "spread_days",
            "target_device_type",
            "endpoint_score",
            "site_confidence",
            "temporal_confidence",
            "accepted",
            "expected_decision",
            "predicted_decision",
            "correct",
        ],
    )
    write_csv(
        output_dir / "experiments" / "drift" / "drift_summary.csv",
        summarize_drift(rows),
        ["scenario", "case_count", "accuracy", "promoted_count", "mean_endpoint_score"],
    )


def run_lifecycle(observations, output_dir: Path, config: dict) -> None:
    rows = lifecycle_churn_rows(
        observations,
        _scoring_config(config, observations),
        checkpoint_days=config["experiments"].get("lifecycle_checkpoint_days"),
        checkpoint_fractions=config["experiments"].get("lifecycle_checkpoint_fractions"),
    )
    write_csv(
        output_dir / "experiments" / "lifecycle" / "policy_churn.csv",
        rows,
        [
            "checkpoint_day",
            "trace_fraction",
            "observation_count",
            "accepted_endpoint_count",
            "added_endpoint_count",
            "removed_endpoint_count",
            "policy_update_count",
            "updates_per_day",
            "added_endpoint_sample",
            "removed_endpoint_sample",
        ],
    )
    write_csv(
        output_dir / "experiments" / "lifecycle" / "policy_churn_summary.csv",
        summarize_lifecycle(rows),
        [
            "checkpoint_count",
            "total_policy_updates",
            "mean_updates_per_checkpoint",
            "mean_updates_per_day",
            "max_updates_per_checkpoint",
            "final_accepted_endpoint_count",
        ],
    )


def run_scalability(observations, output_dir: Path, config: dict, partition_strategy: str = "random") -> None:
    """Measure how runtime, peak memory, and registry storage size grow with the number
    of simulated sites. Registry storage is approximated as the number of (site, device,
    endpoint) rows the registry would store -- this grows with site_count even though the
    underlying observation volume is fixed, because each site keeps its own profile rows
    (see dib/registry/db.py Profile/Endpoint uniqueness on site_id). A flat global score
    count across site_count values would indicate the experiment isn't exercising anything
    that actually depends on the number of sites.
    """
    rows = []
    for site_count in config["experiments"]["site_counts"]:
        tracemalloc.start()
        started = time.perf_counter()
        sites = partition_observations(observations, site_count, strategy=partition_strategy, seed=config["experiments"]["seed"])
        redistributed = [obs for site in sites for obs in site.observations]
        scores = DIBScorer(_scoring_config(config, observations)).score(redistributed)
        local_profiles = build_all_local_profiles(redistributed)
        registry_rows = sum(len(profile.endpoints) for profile in local_profiles)
        runtime_seconds = time.perf_counter() - started
        _, peak_memory_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        rows.append(
            {
                "site_count": site_count,
                "observation_count": len(redistributed),
                "score_count": len(scores),
                "registry_profile_count": len(local_profiles),
                "registry_endpoint_rows": registry_rows,
                "runtime_seconds": round(runtime_seconds, 6),
                "peak_memory_mb": round(peak_memory_bytes / (1024 * 1024), 3),
            }
        )
    write_csv(
        output_dir / "experiments" / "scalability" / "scalability.csv",
        rows,
        [
            "site_count",
            "observation_count",
            "score_count",
            "registry_profile_count",
            "registry_endpoint_rows",
            "runtime_seconds",
            "peak_memory_mb",
        ],
    )


def run_ablation(observations, output_dir: Path, config: dict, ground_truth_dir: str | None = None) -> None:
    """E5: zero out one confidence component at a time (no redistribution of its weight)
    and measure both self-consistency (jaccard vs the full model) and, when ground truth
    is available, mean per-device F1 against it -- so the experiment answers "which
    component contributes most to *accuracy*", not just "which makes the model stricter".
    """
    base = _scoring_config(config, observations)
    full_scores = DIBScorer(base).score(observations)
    full_accepted = accepted_endpoint_keys(full_scores)

    truth = load_profile_dir(Path(ground_truth_dir)) if ground_truth_dir and Path(ground_truth_dir).exists() else {}

    variants = {
        "full": base,
        "no_site": dataclass_replace(base, alpha=0.0),
        "no_temporal": dataclass_replace(base, beta=0.0),
        "no_graph": dataclass_replace(base, gamma=0.0),
    }
    rows = []
    for variant_name, variant_config in variants.items():
        scores = DIBScorer(variant_config).score(observations)
        accepted = accepted_endpoint_keys(scores)
        union = accepted | full_accepted
        overlap = len(accepted & full_accepted) / len(union) if union else 1.0
        mean_f1 = _mean_f1_against_truth(scores, truth) if truth else None
        rows.append(
            {
                "variant": variant_name,
                "alpha": variant_config.alpha,
                "beta": variant_config.beta,
                "gamma": variant_config.gamma,
                "accepted_count": len(accepted),
                "jaccard_vs_full": round(overlap, 6),
                "mean_f1_vs_ground_truth": round(mean_f1, 6) if mean_f1 is not None else "",
            }
        )
    write_csv(
        output_dir / "experiments" / "ablation" / "ablation.csv",
        rows,
        ["variant", "alpha", "beta", "gamma", "accepted_count", "jaccard_vs_full", "mean_f1_vs_ground_truth"],
    )


def _mean_f1_against_truth(scores, truth: dict[str, set]) -> float:
    predicted: dict[str, set] = {}
    for score in scores:
        if not score.accepted:
            continue
        device_type = canonical_device_name(score.device_type)
        protocol = normalize_profile_protocol(score.protocol, score.port)
        # PREDICTED_DIRECTION: every observation is device-initiated (from-device).
        predicted.setdefault(device_type, set()).add(
            (device_type, PREDICTED_DIRECTION, score.endpoint.lower(), protocol, score.port)
        )
    f1_values = [
        semantic_match_metrics(predicted.get(device_type, set()), truth_set)["semantic_f1"]
        for device_type, truth_set in truth.items()
    ]
    return sum(f1_values) / len(f1_values) if f1_values else 0.0


def run_sensitivity(observations, output_dir: Path, config: dict) -> None:
    """E6: vary alpha/beta/gamma/theta independently around the base configuration."""
    base = _scoring_config(config, observations)
    base_scores = DIBScorer(base).score(observations)
    base_accepted = accepted_endpoint_keys(base_scores)
    grid = config.get("sensitivity", {})
    rows = []
    for param in ("alpha", "beta", "gamma", "theta"):
        for value in grid.get(param, []):
            variant_config = dataclass_replace(base, **{param: value})
            scores = DIBScorer(variant_config).score(observations)
            accepted = accepted_endpoint_keys(scores)
            union = accepted | base_accepted
            overlap = len(accepted & base_accepted) / len(union) if union else 1.0
            rows.append(
                {
                    "parameter": param,
                    "value": value,
                    "accepted_count": len(accepted),
                    "jaccard_vs_base": round(overlap, 6),
                }
            )
    write_csv(
        output_dir / "experiments" / "sensitivity" / "sensitivity.csv",
        rows,
        ["parameter", "value", "accepted_count", "jaccard_vs_base"],
    )


def _write_scores(path: Path, scores) -> None:
    fieldnames = [
        "device_type",
        "endpoint",
        "protocol",
        "port",
        "site_confidence",
        "temporal_confidence",
        "graph_confidence",
        "score",
        "accepted",
        "supporting_sites",
        "eligible_sites",
        "endpoint_class",
        "direction",
    ]
    write_csv(path, [score.to_dict() for score in scores], fieldnames)


def _scoring_config(config: dict, observations=None) -> ScoringConfig:
    scoring = config["scoring"]
    graph_enabled = scoring.get("graph_enabled", True)
    alpha = scoring["alpha"]
    beta = scoring["beta"]
    gamma = scoring["gamma"]
    if not graph_enabled:
        remaining = alpha + beta
        alpha = alpha / remaining if remaining else 0.0
        beta = beta / remaining if remaining else 0.0
        gamma = 0.0
    trust_weighted = bool(scoring.get("trust_weighted", False))
    independence_aware = bool(scoring.get("independence_aware", False))
    trust_reference_breadth = 0.0
    if trust_weighted and observations is not None:
        trust_reference_breadth = calibrate_reference_breadth(observations)
    return ScoringConfig(
        alpha=alpha,
        beta=beta,
        gamma=gamma,
        theta=scoring["theta"],
        # Mandatory key, same convention as alpha/beta/gamma/theta above: a
        # config YAML missing this must fail loudly (KeyError) rather than
        # silently falling back to ScoringConfig's own default and changing
        # admission behavior unnoticed (review fix 2026-07-24, Sec. IV-B
        # corroboration quorum). See configs/LOCKED_CONFIGS.md.
        min_reporting_sites=scoring["min_reporting_sites"],
        graph_enabled=graph_enabled,
        graph_max_endpoints_per_device=scoring.get("graph_max_endpoints_per_device"),
        trust_weighted=trust_weighted,
        trust_reference_breadth=trust_reference_breadth,
        independence_aware=independence_aware,
    )


def _load_config(path: str) -> dict:
    text = Path(path).read_text(encoding="utf-8")
    try:
        import yaml

        return yaml.safe_load(text)
    except ImportError:
        return json.loads(text)


if __name__ == "__main__":
    raise SystemExit(main())
