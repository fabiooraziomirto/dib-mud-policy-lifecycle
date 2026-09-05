from __future__ import annotations

import argparse
import json
import resource
import sys
import time
from collections import defaultdict
from collections.abc import Iterable, Iterator
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dib.core.io import filter_observations, stream_observations_csv, write_csv
from dib.core.models import Observation
from dib.evaluation.dib import DIBScorer, ScoringConfig
from dib.evaluation.profiles import PREDICTED_DIRECTION, canonical_device_name, load_profile_dir, normalize_profile_protocol, semantic_match_metrics


Endpoint = tuple[str, str, str, int]


def _scoring_config(path: str | None, graph_max_endpoints_per_device: int) -> ScoringConfig:
    if path is None:
        return ScoringConfig(graph_max_endpoints_per_device=graph_max_endpoints_per_device)
    text = Path(path).read_text(encoding="utf-8")
    try:
        import yaml
        scoring = yaml.safe_load(text)["scoring"]
    except ImportError:
        scoring = json.loads(text)["scoring"]
    return ScoringConfig(
        alpha=float(scoring["alpha"]), beta=float(scoring["beta"]), gamma=float(scoring["gamma"]),
        theta=float(scoring["theta"]), min_reporting_sites=int(scoring["min_reporting_sites"]),
        graph_enabled=bool(scoring.get("graph_enabled", True)),
        graph_max_endpoints_per_device=graph_max_endpoints_per_device,
    )


class ExcludingSiteStream:
    def __init__(self, observations: Iterable[Observation], excluded_site: str) -> None:
        self.observations = observations
        self.excluded_site = excluded_site

    def __iter__(self) -> Iterator[Observation]:
        return (item for item in self.observations if item.site_id != self.excluded_site)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Leave-one-capture-tree-out Mon(IoT)r evaluation.")
    parser.add_argument("--observations", default="data/processed/moniotr_full_observations.csv")
    parser.add_argument("--ground-truth-dir", default="data/unsw/profiles/normalized")
    parser.add_argument("--output-dir", default="outputs/moniotr_cross_site")
    parser.add_argument("--graph-max-endpoints-per-device", type=int, default=100)
    parser.add_argument("--config", default=None, help="Optional fixed scoring YAML for transfer comparisons.")
    args = parser.parse_args(argv)

    source = filter_observations(
        stream_observations_csv(Path(args.observations)),
        exclude_non_global_ips=True,
    )
    observed: dict[str, dict[str, set[Endpoint]]] = defaultdict(lambda: defaultdict(set))
    for observation in source:
        endpoint = observation.fqdn or observation.remote_ip
        if endpoint is None:
            continue
        device = canonical_device_name(observation.device_type)
        protocol = normalize_profile_protocol(observation.protocol, observation.port)
        observed[observation.site_id][device].add((device, PREDICTED_DIRECTION, endpoint.lower(), protocol, observation.port))

    truth = load_profile_dir(Path(args.ground_truth_dir))
    config = _scoring_config(args.config, args.graph_max_endpoints_per_device)
    rows = []
    for held_out_site in sorted(observed):
        training_union: dict[str, set[Endpoint]] = defaultdict(set)
        for site, profiles in observed.items():
            if site == held_out_site:
                continue
            for device, endpoints in profiles.items():
                training_union[device].update(endpoints)

        started = time.perf_counter()
        scores = DIBScorer(config).score(ExcludingSiteStream(source, held_out_site))
        runtime = time.perf_counter() - started
        dib_profiles: dict[str, set[Endpoint]] = defaultdict(set)
        for score in scores:
            if not score.accepted:
                continue
            device = canonical_device_name(score.device_type)
            protocol = normalize_profile_protocol(score.protocol, score.port)
            dib_profiles[device].add((device, PREDICTED_DIRECTION, score.endpoint.lower(), protocol, score.port))

        held_out = observed[held_out_site]
        shared_devices = sorted(set(training_union) & set(held_out))
        for method, profiles in (("dib", dib_profiles), ("pooled_union", training_union)):
            transfer = [_set_metrics(profiles.get(device, set()), held_out[device]) for device in shared_devices]
            ground_truth_devices = sorted(set(shared_devices) & set(truth))
            semantic = [
                semantic_match_metrics(profiles.get(device, set()), truth[device])
                for device in ground_truth_devices
            ]
            rows.append(
                {
                    "held_out_site": held_out_site,
                    "method": method,
                    "shared_device_count": len(shared_devices),
                    "ground_truth_overlap_device_count": len(ground_truth_devices),
                    "predicted_endpoint_count": sum(len(profiles.get(device, set())) for device in shared_devices),
                    "mean_transfer_precision": _mean(transfer, "precision"),
                    "mean_transfer_recall": _mean(transfer, "recall"),
                    "mean_transfer_f1": _mean(transfer, "f1"),
                    "mean_ground_truth_semantic_f1": _mean(semantic, "semantic_f1"),
                    "runtime_seconds": round(runtime, 3) if method == "dib" else 0.0,
                    "process_peak_memory_mib": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 3),
                }
            )

    write_csv(
        Path(args.output_dir) / "cross_site_heterogeneity.csv",
        rows,
        [
            "held_out_site",
            "method",
            "shared_device_count",
            "ground_truth_overlap_device_count",
            "predicted_endpoint_count",
            "mean_transfer_precision",
            "mean_transfer_recall",
            "mean_transfer_f1",
            "mean_ground_truth_semantic_f1",
            "runtime_seconds",
            "process_peak_memory_mib",
        ],
    )
    return 0


def _set_metrics(predicted: set[Endpoint], observed: set[Endpoint]) -> dict[str, float]:
    intersection = len(predicted & observed)
    precision = intersection / len(predicted) if predicted else 0.0
    recall = intersection / len(observed) if observed else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


def _mean(rows: list[dict[str, float]], key: str) -> float:
    return round(sum(row[key] for row in rows) / len(rows), 6) if rows else 0.0


if __name__ == "__main__":
    raise SystemExit(main())
