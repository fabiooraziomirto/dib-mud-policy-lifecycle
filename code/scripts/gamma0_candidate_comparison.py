from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dib.core.io import (
    filter_observations,
    read_observations_csv,
    stream_observations_csv,
    write_csv,
    write_json,
)
from dib.core.models import Observation
from dib.evaluation.dib import DIBScorer, ScoringConfig
from dib.evaluation.profiles import (
    PREDICTED_DIRECTION,
    EndpointKey,
    canonical_device_name,
    load_profile_dir,
    normalize_profile_protocol,
    semantic_match_metrics,
)
from dib.experiments.cold_start import cold_start_rows, summarize_cold_start
from dib.experiments.lifecycle import lifecycle_churn_rows, summarize_lifecycle
from dib.experiments.poisoning import inject_adaptive_sybil_endpoint, inject_fake_endpoint, inject_sybil_endpoint
from dib.simulator.sites import partition_observations

FAKE_ENDPOINT = "evil-c2.net"
OUTPUT_DIR = Path("outputs/gamma0_candidate_comparison")


class ExcludingSiteStream:
    def __init__(self, observations: Iterable[Observation], excluded_site: str) -> None:
        self.observations = observations
        self.excluded_site = excluded_site

    def __iter__(self) -> Iterator[Observation]:
        return (item for item in self.observations if item.site_id != self.excluded_site)


def _configs() -> dict[str, ScoringConfig]:
    return {
        "default": ScoringConfig(),
        "gamma0_candidate": ScoringConfig(alpha=0.6, beta=0.4, gamma=0.0, theta=0.65, graph_enabled=False),
    }


def _profile_from_scores(scores) -> dict[str, set[EndpointKey]]:
    predicted: dict[str, set[EndpointKey]] = defaultdict(set)
    for score in scores:
        if not score.accepted:
            continue
        device = canonical_device_name(score.device_type)
        protocol = normalize_profile_protocol(score.protocol, score.port)
        predicted[device].add((device, PREDICTED_DIRECTION, score.endpoint.lower(), protocol, score.port))
    return predicted


def _profile_from_observations(observations: Iterable[Observation]) -> dict[str, set[EndpointKey]]:
    observed: dict[str, set[EndpointKey]] = defaultdict(set)
    for obs in observations:
        endpoint = obs.fqdn or obs.remote_ip
        if endpoint is None:
            continue
        device = canonical_device_name(obs.device_type)
        protocol = normalize_profile_protocol(obs.protocol, obs.port)
        observed[device].add((device, PREDICTED_DIRECTION, endpoint.lower(), protocol, obs.port))
    return observed


def _semantic_summary(predicted: dict[str, set[EndpointKey]], truth: dict[str, set[EndpointKey]]) -> dict[str, float | int]:
    metrics = [semantic_match_metrics(predicted.get(device, set()), rules) for device, rules in truth.items()]
    return {
        "accepted_endpoint_count": sum(len(items) for items in predicted.values()),
        "mean_semantic_precision": _mean(item["semantic_precision"] for item in metrics),
        "mean_semantic_recall": _mean(item["semantic_recall"] for item in metrics),
        "mean_semantic_f1": _mean(item["semantic_f1"] for item in metrics),
    }


def _set_metrics(predicted: set[EndpointKey], observed: set[EndpointKey]) -> dict[str, float]:
    intersection = len(predicted & observed)
    precision = intersection / len(predicted) if predicted else 0.0
    recall = intersection / len(observed) if observed else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


def _transfer_summary(predicted: dict[str, set[EndpointKey]], observed: dict[str, set[EndpointKey]]) -> dict[str, float | int]:
    shared = sorted(set(predicted) & set(observed))
    metrics = [_set_metrics(predicted.get(device, set()), observed[device]) for device in shared]
    return {
        "shared_device_count": len(shared),
        "predicted_endpoint_count": sum(len(predicted.get(device, set())) for device in shared),
        "mean_transfer_precision": _mean(item["precision"] for item in metrics),
        "mean_transfer_recall": _mean(item["recall"] for item in metrics),
        "mean_transfer_f1": _mean(item["f1"] for item in metrics),
    }


def _fake_score(scores) -> tuple[float, bool]:
    fake = [score for score in scores if score.endpoint == FAKE_ENDPOINT]
    return max((score.score for score in fake), default=0.0), any(score.accepted for score in fake)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Side-by-side comparison of the shipped default and a normalized gamma=0 "
        "candidate, without changing the code default."
    )
    parser.add_argument("--observations", default="data/processed/observations_enriched.csv")
    parser.add_argument("--moniotr-observations", default="data/processed/moniotr_full_observations.csv")
    parser.add_argument("--yourthings-observations", default="data/processed/yourthings_observations.csv")
    parser.add_argument("--ground-truth-dir", default="data/unsw/profiles/normalized")
    parser.add_argument("--output-dir", default=str(OUTPUT_DIR))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--site-count", type=int, default=10)
    parser.add_argument("--partition-strategy", default="random", choices=["random", "device_balanced", "time_window"])
    parser.add_argument("--bounded-fractions", default="0.01,0.05,0.10,0.20,0.30")
    parser.add_argument("--sybil-site-counts", default="1,2,5,10,20,50,100,200,400,800,1600")
    parser.add_argument("--adaptive-sybil-days", default="1,120,140,1000")
    parser.add_argument(
        "--variants",
        default="default,gamma0_candidate",
        help="Comma-separated variants to compute: default,gamma0_candidate.",
    )
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    requested_variants = [value.strip() for value in args.variants.split(",") if value.strip()]
    all_configs = _configs()
    unknown = sorted(set(requested_variants) - set(all_configs))
    if unknown:
        raise ValueError(f"unknown variants: {', '.join(unknown)}")
    configs = {name: all_configs[name] for name in requested_variants}
    truth = load_profile_dir(Path(args.ground_truth_dir))
    observations = read_observations_csv(Path(args.observations))
    sites = partition_observations(observations, args.site_count, strategy=args.partition_strategy, seed=args.seed)
    observations = [observation for site in sites for observation in site.observations]
    target_device_type = Counter(o.device_type for o in observations).most_common(1)[0][0]
    bounded_fractions = [float(value) for value in args.bounded_fractions.split(",") if value.strip()]
    sybil_counts = [int(value) for value in args.sybil_site_counts.split(",") if value.strip()]
    adaptive_days = [int(value) for value in args.adaptive_sybil_days.split(",") if value.strip()]

    detail_rows: list[dict[str, object]] = []

    learned_profiles: dict[str, dict[str, set[EndpointKey]]] = {}
    for variant, config in configs.items():
        print(f"{variant}: scoring UNSW fidelity", flush=True)
        scores = DIBScorer(config).score(observations)
        profile = _profile_from_scores(scores)
        learned_profiles[variant] = profile
        metrics = _semantic_summary(profile, truth)
        detail_rows.append({"experiment": "unsw_fidelity", "scenario": "all_devices", "variant": variant, **metrics})
        print(f"{variant} UNSW F1={metrics['mean_semantic_f1']:.6f} accepted={metrics['accepted_endpoint_count']}", flush=True)

        print(f"{variant}: cold start", flush=True)
        cold_rows = cold_start_rows(observations, truth, config)
        for row in summarize_cold_start(cold_rows):
            detail_rows.append({"experiment": "cold_start", "scenario": f"{row['method']}_day_{row['window_days']}", "variant": variant, **row})

        print(f"{variant}: lifecycle churn", flush=True)
        lifecycle_rows = lifecycle_churn_rows(
            observations,
            config,
            checkpoint_fractions=[0.01, 0.05, 0.10, 0.20, 0.40, 0.60, 0.80, 1.00],
        )
        for row in summarize_lifecycle(lifecycle_rows):
            detail_rows.append({"experiment": "lifecycle_churn", "scenario": "trace_fraction_checkpoints", "variant": variant, **row})

        print(f"{variant}: bounded poisoning", flush=True)
        for fraction in bounded_fractions:
            scores = DIBScorer(config).score(inject_fake_endpoint(observations, fraction, seed=args.seed))
            fake_score, fake_accepted = _fake_score(scores)
            detail_rows.append(
                {
                    "experiment": "bounded_poisoning",
                    "scenario": f"malicious_fraction_{fraction}",
                    "variant": variant,
                    "fake_endpoint_score": round(fake_score, 6),
                    "fake_accepted": fake_accepted,
                }
            )

        print(f"{variant}: static Sybil frontier", flush=True)
        for count in sybil_counts:
            poisoned = inject_sybil_endpoint(observations, count, target_device_type, seed=args.seed)
            scores = DIBScorer(config).score(poisoned, target_device_type=target_device_type)
            fake_score, fake_accepted = _fake_score(scores)
            accepted_non_fake = sum(1 for score in scores if score.accepted and score.endpoint != FAKE_ENDPOINT)
            detail_rows.append(
                {
                    "experiment": "sybil_frontier_static",
                    "scenario": f"sybil_site_count_{count}",
                    "variant": variant,
                    "target_device_type": target_device_type,
                    "fake_endpoint_score": round(fake_score, 6),
                    "fake_accepted": fake_accepted,
                    "accepted_endpoint_count": accepted_non_fake,
                }
            )

        print(f"{variant}: adaptive Sybil frontier", flush=True)
        for days in adaptive_days:
            poisoned = inject_adaptive_sybil_endpoint(observations, max(sybil_counts), target_device_type, days, seed=args.seed)
            scores = DIBScorer(config).score(poisoned, target_device_type=target_device_type)
            fake_score, fake_accepted = _fake_score(scores)
            accepted_non_fake = sum(1 for score in scores if score.accepted and score.endpoint != FAKE_ENDPOINT)
            detail_rows.append(
                {
                    "experiment": "sybil_frontier_adaptive",
                    "scenario": f"sybil_{max(sybil_counts)}_days_{days}",
                    "variant": variant,
                    "target_device_type": target_device_type,
                    "fake_endpoint_score": round(fake_score, 6),
                    "fake_accepted": fake_accepted,
                    "accepted_endpoint_count": accepted_non_fake,
                }
            )

    moniotr_path = Path(args.moniotr_observations)
    if moniotr_path.exists():
        print("Mon(IoT)r transfer", flush=True)
        moniotr_rows = _moniotr_transfer_rows(moniotr_path, configs)
        detail_rows.extend(moniotr_rows)
    else:
        print(f"skipping Mon(IoT)r transfer; missing {moniotr_path}", flush=True)

    yourthings_path = Path(args.yourthings_observations)
    if yourthings_path.exists():
        print("YourThings transfer", flush=True)
        observed = _profile_from_observations(read_observations_csv(yourthings_path))
        for variant, profile in learned_profiles.items():
            detail_rows.append(
                {
                    "experiment": "yourthings_transfer",
                    "scenario": "unsw_profile_to_yourthings_observed",
                    "variant": variant,
                    **_transfer_summary(profile, observed),
                }
            )
    else:
        print(f"skipping YourThings transfer; missing {yourthings_path}", flush=True)

    fieldnames = sorted({key for row in detail_rows for key in row})
    write_csv(output_dir / "gamma0_candidate_detail.csv", detail_rows, fieldnames)
    write_csv(output_dir / "gamma0_candidate_summary.csv", _summary_rows(detail_rows), ["experiment", "scenario", "metric", "default", "gamma0_candidate", "delta"])
    write_json(
        output_dir / "gamma0_candidate_manifest.json",
        {
            "experiment": "gamma0_candidate_comparison",
            "observations": args.observations,
            "moniotr_observations": args.moniotr_observations,
            "yourthings_observations": args.yourthings_observations,
            "ground_truth_dir": args.ground_truth_dir,
            "site_count": args.site_count,
            "partition_strategy": args.partition_strategy,
            "seed": args.seed,
            "target_device_type": target_device_type,
            "bounded_fractions": bounded_fractions,
            "sybil_site_counts": sybil_counts,
            "adaptive_sybil_days": adaptive_days,
            "configs": {
                name: {
                    "alpha": config.alpha,
                    "beta": config.beta,
                    "gamma": config.gamma,
                    "theta": config.theta,
                    "graph_enabled": config.graph_enabled,
                }
                for name, config in configs.items()
            },
            "gamma0_rationale": (
                "gamma0_candidate uses alpha=0.6, beta=0.4, gamma=0.0, theta=0.65, "
                "with graph disabled. The non-graph weights sum to one, matching the "
                "runner's renormalization principle for no-graph scoring without "
                "changing the shipped default."
            ),
            "yourthings_note": (
                "YourThings has one normalized site in this artifact, so the comparison "
                "measures transfer from UNSW-learned accepted profiles to observed "
                "YourThings endpoints for overlapping canonical devices."
            ),
        },
    )
    return 0


def _moniotr_transfer_rows(path: Path, configs: dict[str, ScoringConfig]) -> list[dict[str, object]]:
    source = filter_observations(stream_observations_csv(path), exclude_non_global_ips=True)
    observed_by_site: dict[str, dict[str, set[EndpointKey]]] = defaultdict(lambda: defaultdict(set))
    for observation in source:
        endpoint = observation.fqdn or observation.remote_ip
        if endpoint is None:
            continue
        device = canonical_device_name(observation.device_type)
        protocol = normalize_profile_protocol(observation.protocol, observation.port)
        observed_by_site[observation.site_id][device].add((device, endpoint.lower(), protocol, observation.port))

    rows: list[dict[str, object]] = []
    for held_out_site in sorted(observed_by_site):
        held_out = observed_by_site[held_out_site]
        for variant, config in configs.items():
            scores = DIBScorer(config).score(ExcludingSiteStream(source, held_out_site))
            profile = _profile_from_scores(scores)
            rows.append(
                {
                    "experiment": "moniotr_transfer",
                    "scenario": f"held_out_{held_out_site}",
                    "variant": variant,
                    **_transfer_summary(profile, held_out),
                }
            )
    return rows


def _summary_rows(detail_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[tuple[str, str, str], dict[str, object]] = defaultdict(dict)
    skip = {"experiment", "scenario", "variant", "target_device_type", "method", "site_count"}
    for row in detail_rows:
        variant = str(row["variant"])
        for key, value in row.items():
            if key in skip or isinstance(value, bool) or value == "":
                continue
            if isinstance(value, (int, float)):
                grouped[(str(row["experiment"]), str(row["scenario"]), key)][variant] = value
    summary = []
    for (experiment, scenario, metric), values in sorted(grouped.items()):
        default = values.get("default", "")
        candidate = values.get("gamma0_candidate", "")
        delta = ""
        if isinstance(default, (int, float)) and isinstance(candidate, (int, float)):
            delta = round(float(candidate) - float(default), 6)
        summary.append(
            {
                "experiment": experiment,
                "scenario": scenario,
                "metric": metric,
                "default": default,
                "gamma0_candidate": candidate,
                "delta": delta,
            }
        )
    return summary


def _mean(values) -> float:
    values = list(values)
    return round(sum(values) / len(values), 6) if values else 0.0


if __name__ == "__main__":
    raise SystemExit(main())
