from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dib.core.io import write_csv
from dib.experiments.fingerprint_classifier import (
    GaussianNaiveBayesClassifier,
    SklearnFlowClassifier,
    chronological_split,
    classification_report,
    confusion_matrix,
    load_flow_dataset,
)

OUTPUT_DIR = Path("outputs/tnsm_review_2026-06-20/experiments/fingerprint_classifier_strong")


def _macro_f1(report_rows: list[dict[str, object]]) -> float:
    f1s = [float(r["f1"]) for r in report_rows if int(r["support"]) > 0]
    return sum(f1s) / len(f1s) if f1s else 0.0


def _weighted_f1(report_rows: list[dict[str, object]]) -> float:
    total = sum(int(r["support"]) for r in report_rows)
    if not total:
        return 0.0
    return sum(float(r["f1"]) * int(r["support"]) for r in report_rows) / total


def _top_confusions(matrix: dict[tuple[str, str], int], top_n: int = 15) -> list[dict[str, object]]:
    off_diagonal = [
        {"true_device_type": t, "predicted_device_type": p, "count": c}
        for (t, p), c in matrix.items()
        if t != p and c > 0
    ]
    off_diagonal.sort(key=lambda r: r["count"], reverse=True)
    return off_diagonal[:top_n]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare Gaussian Naive Bayes against scikit-learn tree ensembles "
        "on the same UNSW IoTraffic flow features and chronological split (classifier "
        "quality only; no DIB re-scoring)."
    )
    parser.add_argument("--flows-dir", default="data/unsw_iotraffic_2025/flows_extracted/flows")
    parser.add_argument("--ground-truth-dir", default="data/unsw/profiles/normalized")
    parser.add_argument("--output-dir", default=str(OUTPUT_DIR))
    parser.add_argument("--train-fraction", type=float, default=0.7)
    parser.add_argument("--max-rows-per-file", type=int, help="Optional cap for smoke tests.")
    parser.add_argument(
        "--classifiers",
        default="gnb,random_forest,gradient_boosting",
        help="Comma-separated subset of {gnb,random_forest,gradient_boosting}.",
    )
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    load_started = time.perf_counter()
    samples = load_flow_dataset(Path(args.flows_dir), max_rows_per_file=args.max_rows_per_file)
    train_samples, test_samples = chronological_split(samples, train_fraction=args.train_fraction)
    labels = sorted({s.device_type for s in samples})
    print(
        f"loaded {len(samples)} flows ({len(train_samples)} train / {len(test_samples)} test), "
        f"{len(labels)} device types, in {time.perf_counter() - load_started:.1f}s",
        flush=True,
    )

    def make(kind: str):
        if kind == "gnb":
            return GaussianNaiveBayesClassifier()
        return SklearnFlowClassifier(kind=kind)

    summary_rows = []
    for kind in [c.strip() for c in args.classifiers.split(",") if c.strip()]:
        started = time.perf_counter()
        classifier = make(kind).fit(train_samples)
        fit_seconds = time.perf_counter() - started
        predicted = classifier.predict_batch(test_samples)
        predict_seconds = time.perf_counter() - started - fit_seconds

        accuracy = sum(1 for s, p in zip(test_samples, predicted) if s.device_type == p) / len(test_samples)
        report = classification_report(test_samples, predicted, labels)
        matrix = confusion_matrix(test_samples, predicted, labels)

        write_csv(
            output_dir / f"classification_report_{kind}.csv",
            report,
            ["device_type", "support", "precision", "recall", "f1"],
        )
        write_csv(
            output_dir / f"top_confusions_{kind}.csv",
            _top_confusions(matrix),
            ["true_device_type", "predicted_device_type", "count"],
        )
        summary_rows.append(
            {
                "classifier": kind,
                "train_flows": len(train_samples),
                "test_flows": len(test_samples),
                "accuracy": round(accuracy, 6),
                "macro_f1": round(_macro_f1(report), 6),
                "weighted_f1": round(_weighted_f1(report), 6),
                "fit_seconds": round(fit_seconds, 2),
                "predict_seconds": round(predict_seconds, 2),
            }
        )
        print(
            f"  {kind}: accuracy={accuracy:.4f} macro_f1={_macro_f1(report):.4f} "
            f"fit={fit_seconds:.1f}s",
            flush=True,
        )

    write_csv(
        output_dir / "classifier_accuracy_comparison.csv",
        summary_rows,
        ["classifier", "train_flows", "test_flows", "accuracy", "macro_f1", "weighted_f1", "fit_seconds", "predict_seconds"],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
