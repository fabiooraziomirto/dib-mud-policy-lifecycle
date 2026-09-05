from __future__ import annotations

import argparse
import resource
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dib.core.io import filter_observations, stream_observations_csv, write_csv
from dib.evaluation.dib import DIBScorer, ScoringConfig, accepted_endpoint_keys
from dib.evaluation.profiles import PREDICTED_DIRECTION, canonical_device_name, load_profile_dir, normalize_profile_protocol, semantic_match_metrics
from dib.experiments.fingerprinting import FingerprintPerturbationStream


DEFAULT_RATES = (0.01, 0.05, 0.10, 0.20, 0.30)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Controlled fingerprint-key robustness on Mon(IoT)r.")
    parser.add_argument("--observations", default="data/processed/moniotr_full_observations.csv")
    parser.add_argument("--ground-truth-dir", default="data/unsw/profiles/normalized")
    parser.add_argument("--output-dir", default="outputs/moniotr_fingerprint")
    parser.add_argument("--rates", default=",".join(str(value) for value in DEFAULT_RATES))
    parser.add_argument("--graph-max-endpoints-per-device", type=int, default=100)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)

    source = filter_observations(
        stream_observations_csv(Path(args.observations)),
        exclude_non_global_ips=True,
    )
    device_types = sorted({observation.device_type for observation in source})
    truth = load_profile_dir(Path(args.ground_truth_dir))
    overlap_devices = sorted({canonical_device_name(item) for item in device_types} & set(truth))
    config = ScoringConfig(min_reporting_sites=2, graph_max_endpoints_per_device=args.graph_max_endpoints_per_device)

    baseline_scores, baseline_runtime, baseline_peak = _score(source, config)
    baseline_accepted = accepted_endpoint_keys(baseline_scores)
    rows = [_result_row("baseline", 0.0, baseline_scores, baseline_accepted, truth, overlap_devices, baseline_runtime, baseline_peak)]
    rates = [float(value.strip()) for value in args.rates.split(",") if value.strip()]
    for scenario in ("fragmentation", "collision"):
        for rate in rates:
            perturbed = FingerprintPerturbationStream(
                source,
                scenario=scenario,
                error_rate=rate,
                device_types=device_types,
                seed=args.seed,
            )
            scores, runtime, peak = _score(perturbed, config)
            rows.append(
                _result_row(
                    scenario,
                    rate,
                    scores,
                    baseline_accepted,
                    truth,
                    overlap_devices,
                    runtime,
                    peak,
                )
            )

    output_dir = Path(args.output_dir)
    write_csv(
        output_dir / "fingerprint_robustness.csv",
        rows,
        [
            "scenario",
            "error_rate",
            "accepted_endpoint_count",
            "overlap_accepted_endpoint_count",
            "overlap_device_count",
            "mean_semantic_precision",
            "mean_semantic_recall",
            "mean_semantic_f1",
            "jaccard_vs_baseline",
            "runtime_seconds",
            "peak_memory_mib",
        ],
    )
    return 0


def _score(observations, config: ScoringConfig):
    started = time.perf_counter()
    scores = DIBScorer(config).score(observations)
    runtime = time.perf_counter() - started
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    return scores, runtime, peak


def _result_row(scenario, rate, scores, baseline_accepted, truth, overlap_devices, runtime, peak):
    accepted = accepted_endpoint_keys(scores)
    by_device: dict[str, set[tuple[str, str, str, int]]] = {}
    for score in scores:
        if not score.accepted:
            continue
        device = canonical_device_name(score.device_type)
        if device not in overlap_devices:
            continue
        protocol = normalize_profile_protocol(score.protocol, score.port)
        by_device.setdefault(device, set()).add((device, PREDICTED_DIRECTION, score.endpoint, protocol, score.port))
    metrics = [semantic_match_metrics(by_device.get(device, set()), truth[device]) for device in overlap_devices]
    union = accepted | baseline_accepted
    return {
        "scenario": scenario,
        "error_rate": rate,
        "accepted_endpoint_count": len(accepted),
        "overlap_accepted_endpoint_count": sum(len(items) for items in by_device.values()),
        "overlap_device_count": len(overlap_devices),
        "mean_semantic_precision": _mean(metrics, "semantic_precision"),
        "mean_semantic_recall": _mean(metrics, "semantic_recall"),
        "mean_semantic_f1": _mean(metrics, "semantic_f1"),
        "jaccard_vs_baseline": round(len(accepted & baseline_accepted) / len(union), 6) if union else 1.0,
        "runtime_seconds": round(runtime, 3),
        "peak_memory_mib": round(peak, 3),
    }


def _mean(rows: list[dict[str, float]], key: str) -> float:
    return round(sum(row[key] for row in rows) / len(rows), 6) if rows else 0.0


if __name__ == "__main__":
    raise SystemExit(main())
