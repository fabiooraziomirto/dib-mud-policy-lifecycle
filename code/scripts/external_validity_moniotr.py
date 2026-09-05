from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dib.core.io import filter_observations, stream_observations_csv, write_csv
from dib.evaluation.dib import DIBScorer, ScoringConfig
from dib.evaluation.profiles import PREDICTED_DIRECTION, canonical_device_name, load_profile_dir, semantic_match_metrics


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="External-validity check over normalized Mon(IoT)r observations.")
    parser.add_argument("--observations", default="data/processed/moniotr_observations.csv")
    parser.add_argument("--ground-truth-dir", default="data/unsw/profiles/normalized")
    parser.add_argument("--output-dir", default="outputs/moniotr_external")
    parser.add_argument("--no-graph", action="store_true", help="Skip the dense co-occurrence graph.")
    parser.add_argument("--graph-max-endpoints-per-device", type=int, metavar="N")
    parser.add_argument("--exclude-non-global-ips", action=argparse.BooleanOptionalAction, default=True,
                        help="Apply the same post-load filter as runner.py --exclude-non-global-ips.")
    args = parser.parse_args(argv)

    observations = stream_observations_csv(Path(args.observations))
    if args.exclude_non_global_ips:
        observations = filter_observations(observations, exclude_non_global_ips=True)
    observed_devices = {canonical_device_name(obs.device_type) for obs in observations}
    scoring_config = (
        # main.tex: "Removing the graph term raises F1 to 0.508" -- this is
        # literally that operation on the graph-augmented default
        # (alpha=0.5, beta=0.3, gamma=0.2): gamma zeroed, alpha/beta
        # proportionally renormalized to sum to 1 (0.5/0.8, 0.3/0.8),
        # preserving their 5:3 ratio. Deliberately NOT
        # configs/graph_free_selected.yaml's (0.6, 0.4) -- that is a
        # separately tuned operating point (Sec. VI-B), not what this
        # ablation is described as producing. Re-flagged as a "third ad hoc
        # config" during Fase 0/1 diagnostics; re-checked against main.tex's
        # own wording in Fase 3.2 and confirmed correct as implemented.
        # min_reporting_sites=2 mirrors the locked configs' Sec. IV-B
        # corroboration quorum (review fix 2026-07-24); kept explicit here
        # since this script has no --config YAML to load it from.
        ScoringConfig(alpha=0.625, beta=0.375, gamma=0.0, min_reporting_sites=2, graph_enabled=False)
        if args.no_graph
        else ScoringConfig(min_reporting_sites=2, graph_max_endpoints_per_device=args.graph_max_endpoints_per_device)
    )
    scores = DIBScorer(scoring_config).score(observations)
    truth = load_profile_dir(Path(args.ground_truth_dir))
    predicted: dict[str, set[tuple[str, str, str, str, int]]] = {}
    for score in scores:
        if not score.accepted:
            continue
        device = canonical_device_name(score.device_type)
        predicted.setdefault(device, set()).add((device, PREDICTED_DIRECTION, score.endpoint, score.protocol, score.port))

    output_dir = Path(args.output_dir)
    rows = []
    for device in sorted(set(predicted) | set(truth)):
        pred_set = predicted.get(device, set())
        truth_set = truth.get(device, set())
        semantic = semantic_match_metrics(pred_set, truth_set) if truth_set else {
            "semantic_precision": 0.0,
            "semantic_recall": 0.0,
            "semantic_f1": 0.0,
        }
        rows.append(
            {
                "device_type": device,
                "observed_in_moniotr": device in observed_devices,
                "accepted_in_moniotr": bool(pred_set),
                "in_unsw_ground_truth": bool(truth_set),
                "predicted_endpoint_count": len(pred_set),
                "truth_endpoint_count": len(truth_set),
                "semantic_precision": round(semantic["semantic_precision"], 6),
                "semantic_recall": round(semantic["semantic_recall"], 6),
                "semantic_f1": round(semantic["semantic_f1"], 6),
            }
        )
    observed_overlapping = [row for row in rows if row["observed_in_moniotr"] and row["in_unsw_ground_truth"]]
    accepted_overlapping = [row for row in rows if row["accepted_in_moniotr"] and row["in_unsw_ground_truth"]]
    summary = [
        {
            "moniotr_observation_count": sum(1 for _ in observations),
            "moniotr_site_count": len({obs.site_id for obs in observations}),
            "moniotr_device_count": len(observed_devices),
            "accepted_endpoint_count": sum(len(items) for items in predicted.values()),
            "observed_overlap_device_count": len(observed_overlapping),
            "accepted_overlap_device_count": len(accepted_overlapping),
            "mean_semantic_f1_on_observed_overlap": round(
                sum(float(row["semantic_f1"]) for row in observed_overlapping) / len(observed_overlapping), 6
            )
            if observed_overlapping
            else 0.0,
            "mean_semantic_f1_on_accepted_overlap": round(
                sum(float(row["semantic_f1"]) for row in accepted_overlapping) / len(accepted_overlapping), 6
            )
            if accepted_overlapping
            else 0.0,
        }
    ]
    write_csv(
        output_dir / "moniotr_external_validity.csv",
        rows,
        [
            "device_type",
            "observed_in_moniotr",
            "accepted_in_moniotr",
            "in_unsw_ground_truth",
            "predicted_endpoint_count",
            "truth_endpoint_count",
            "semantic_precision",
            "semantic_recall",
            "semantic_f1",
        ],
    )
    write_csv(
        output_dir / "moniotr_external_summary.csv",
        summary,
        [
            "moniotr_observation_count",
            "moniotr_site_count",
            "moniotr_device_count",
            "accepted_endpoint_count",
            "observed_overlap_device_count",
            "accepted_overlap_device_count",
            "mean_semantic_f1_on_observed_overlap",
            "mean_semantic_f1_on_accepted_overlap",
        ],
    )
    _write_scores(output_dir / "moniotr_scores.csv", scores)
    return 0


def _write_scores(path: Path, scores) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
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
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for score in scores:
            writer.writerow(score.to_dict())


if __name__ == "__main__":
    raise SystemExit(main())
