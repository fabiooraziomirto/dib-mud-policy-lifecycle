from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dib.adapters.unsw_iotraffic import iter_flow_observations
from dib.core.io import write_csv
from dib.evaluation.dib import DIBScorer, ScoringConfig, accepted_endpoint_keys
from dib.evaluation.profiles import PREDICTED_DIRECTION, canonical_device_name, load_profile_dir, normalize_profile_protocol, semantic_match_metrics
from dib.experiments.fingerprint_classifier import (
    GaussianNaiveBayesClassifier,
    SklearnFlowClassifier,
    chronological_split,
    classification_report,
    confusion_matrix,
    leave_one_class_out_predictions,
    load_flow_dataset,
    temporal_stability,
)
from dib.experiments.fingerprinting import FingerprintPerturbationStream

OUTPUT_DIR = Path("outputs/full_unsw/experiments/fingerprint_classifier")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Train and evaluate a real device-type classifier over UNSW IoTraffic flow features, "
        "then feed its predicted labels into DIB and compare against clean and controlled-error labels."
    )
    parser.add_argument("--flows-dir", default="data/unsw_iotraffic_2025/flows_extracted/flows")
    parser.add_argument("--protocols-dir", default="data/unsw_iotraffic_2025/protocols_extracted/protocols")
    parser.add_argument("--ground-truth-dir", default="data/unsw/profiles/normalized")
    parser.add_argument("--output-dir", default=str(OUTPUT_DIR))
    parser.add_argument("--train-fraction", type=float, default=0.7)
    parser.add_argument("--max-rows-per-file", type=int, help="Optional cap for smoke tests or sampling.")
    parser.add_argument(
        "--classifier",
        choices=["gnb", "random_forest", "gradient_boosting"],
        default="gnb",
        help="Device-type classifier whose predicted labels are fed into DIB. "
        "Default 'gnb' reproduces the original Gaussian Naive Bayes run.",
    )
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    samples = load_flow_dataset(Path(args.flows_dir), max_rows_per_file=args.max_rows_per_file)
    train_samples, test_samples = chronological_split(samples, train_fraction=args.train_fraction)
    labels = sorted({s.device_type for s in samples})

    if args.classifier == "gnb":
        classifier = GaussianNaiveBayesClassifier().fit(train_samples)
    else:
        classifier = SklearnFlowClassifier(kind=args.classifier).fit(train_samples)
    test_predictions = classifier.predict_batch(test_samples)

    write_csv(
        output_dir / "classification_report.csv",
        classification_report(test_samples, test_predictions, labels),
        ["device_type", "support", "precision", "recall", "f1"],
    )

    matrix = confusion_matrix(test_samples, test_predictions, labels)
    write_csv(
        output_dir / "confusion_matrix.csv",
        [
            {"true_device_type": true, "predicted_device_type": pred, "count": count}
            for (true, pred), count in matrix.items()
            if count > 0
        ],
        ["true_device_type", "predicted_device_type", "count"],
    )

    accuracy = sum(1 for s, p in zip(test_samples, test_predictions) if s.device_type == p) / len(test_samples)
    error_rate = 1.0 - accuracy
    write_csv(
        output_dir / "accuracy_summary.csv",
        [{"train_flows": len(train_samples), "test_flows": len(test_samples), "accuracy": round(accuracy, 6), "error_rate": round(error_rate, 6)}],
        ["train_flows", "test_flows", "accuracy", "error_rate"],
    )

    write_csv(
        output_dir / "temporal_stability.csv",
        temporal_stability(test_samples, test_predictions),
        ["device_id", "flow_count", "flip_rate"],
    )

    write_csv(
        output_dir / "unknown_device_handling.csv",
        leave_one_class_out_predictions(samples, labels),
        [
            "held_out_device_type",
            "flow_count",
            "most_common_misclassification",
            "most_common_misclassification_share",
            "mean_confidence",
        ],
    )

    # (device_id, timestamp) -> predicted label, restricted to the held-out test split only.
    predicted_lookup = {
        (sample.device_id, sample.timestamp): predicted
        for sample, predicted in zip(test_samples, test_predictions)
    }
    test_keys = set(predicted_lookup)
    train_keys = {(sample.device_id, sample.timestamp) for sample in train_samples}

    # The registry's existing history (train period) keeps its trusted ground-truth
    # label in every variant -- only the most recent (test-period) slice differs by
    # label source. This mirrors a deployed registry that already corroborated older
    # traffic and is now ingesting live classifier output for new traffic; restricting
    # the whole comparison to the test slice alone leaves too little history for any
    # site/temporal corroboration regardless of label correctness (verified: an
    # earlier version of this experiment did that and tied at zero accepted endpoints
    # for all three variants).
    train_observations: list = []
    test_clean_observations: list = []
    for observation in iter_flow_observations(
        flows_dir=Path(args.flows_dir),
        protocols_dir=Path(args.protocols_dir),
        site_id="unsw-iotraffic-2025",
        max_rows_per_file=args.max_rows_per_file,
    ):
        key = (observation.device_id, observation.timestamp)
        if key in train_keys:
            train_observations.append(observation)
        elif key in test_keys:
            test_clean_observations.append(observation)

    test_predicted_observations = [
        replace(observation, device_type=predicted_lookup[(observation.device_id, observation.timestamp)])
        for observation in test_clean_observations
    ]
    test_controlled_error_observations = list(
        FingerprintPerturbationStream(
            test_clean_observations,
            scenario="collision",
            error_rate=error_rate,
            device_types=labels,
        )
    )

    ground_truth = load_profile_dir(Path(args.ground_truth_dir)) if Path(args.ground_truth_dir).exists() else {}
    comparison_rows = []
    for variant_name, test_variant_observations in (
        ("clean_label", test_clean_observations),
        ("classifier_predicted_label", test_predicted_observations),
        ("controlled_error_label", test_controlled_error_observations),
    ):
        comparison_rows.append(
            _evaluate_variant(
                variant_name,
                train_observations + test_variant_observations,
                ground_truth,
            )
        )
    write_csv(
        output_dir / "dib_label_source_comparison.csv",
        comparison_rows,
        ["variant", "accepted_endpoint_count", "mean_semantic_precision", "mean_semantic_recall", "mean_semantic_f1"],
    )
    return 0


def _evaluate_variant(name: str, observations: list, ground_truth: dict) -> dict[str, object]:
    # Matches the production reconstruction setup (reproduce_all.sh, run_experiments.py
    # with no --site-count): the real UNSW IoTraffic dataset has exactly one real site,
    # so site_confidence is trivially 1.0 for any observed endpoint and all selectivity
    # comes from temporal/graph confidence. An earlier version of this experiment
    # partitioned into synthetic sites here, which only fragmented one physical
    # device's already-thin traffic and deflated site_confidence without adding any
    # genuine cross-site corroboration -- that produced zero accepted endpoints for
    # every variant and was not a real comparison.
    scores = DIBScorer(ScoringConfig()).score(observations)
    accepted = accepted_endpoint_keys(scores)
    by_device: dict[str, set] = {}
    for device_type, endpoint, protocol, port in accepted:
        canonical = canonical_device_name(device_type)
        normalized_protocol = normalize_profile_protocol(protocol, port)
        by_device.setdefault(canonical, set()).add((canonical, PREDICTED_DIRECTION, endpoint.lower(), normalized_protocol, port))

    device_types = sorted(set(by_device) | set(ground_truth))
    precisions, recalls, f1s = [], [], []
    for device_type in device_types:
        metrics = semantic_match_metrics(by_device.get(device_type, set()), ground_truth.get(device_type, set()))
        precisions.append(metrics["semantic_precision"])
        recalls.append(metrics["semantic_recall"])
        f1s.append(metrics["semantic_f1"])
    return {
        "variant": name,
        "accepted_endpoint_count": len(accepted),
        "mean_semantic_precision": round(sum(precisions) / len(precisions), 6) if precisions else 0.0,
        "mean_semantic_recall": round(sum(recalls) / len(recalls), 6) if recalls else 0.0,
        "mean_semantic_f1": round(sum(f1s) / len(f1s), 6) if f1s else 0.0,
    }


if __name__ == "__main__":
    raise SystemExit(main())
