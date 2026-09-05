from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dib.core.io import write_csv
from dib.evaluation.metrics import f1_score, jaccard, precision, recall
from dib.evaluation.profiles import load_dib_scores, load_profile_dir, semantic_match_metrics


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare inferred DIB profiles against reference profiles.")
    parser.add_argument(
        "--scores",
        default="outputs/experiments/reconstruction/dib_scores.csv",
        help="DIB score CSV emitted by run_experiments.py.",
    )
    parser.add_argument(
        "--ground-truth-dir",
        default="data/unsw/profiles/normalized",
        help="Directory containing reference profile JSON/CSV files.",
    )
    parser.add_argument("--output", default="outputs/profile_accuracy.csv")
    parser.add_argument("--overlap-output", default="outputs/profile_overlap.csv")
    args = parser.parse_args(argv)

    predicted = load_dib_scores(Path(args.scores), accepted_only=True)
    truth = load_profile_dir(Path(args.ground_truth_dir))
    rows = []
    overlap_rows = []
    for device_type in sorted(set(predicted) | set(truth)):
        pred_set = predicted.get(device_type, set())
        truth_set = truth.get(device_type, set())
        semantic = semantic_match_metrics(pred_set, truth_set)
        rows.append(
            {
                "device_type": device_type,
                "predicted_count": len(pred_set),
                "truth_count": len(truth_set),
                "precision": round(precision(pred_set, truth_set), 6),
                "recall": round(recall(pred_set, truth_set), 6),
                "f1": round(f1_score(pred_set, truth_set), 6),
                "jaccard": round(jaccard(pred_set, truth_set), 6),
                "semantic_precision": round(semantic["semantic_precision"], 6),
                "semantic_recall": round(semantic["semantic_recall"], 6),
                "semantic_f1": round(semantic["semantic_f1"], 6),
            }
        )
        overlap_rows.append(
            {
                "device_type": device_type,
                "shared_endpoint_count": len(pred_set & truth_set),
                "predicted_only_count": len(pred_set - truth_set),
                "truth_only_count": len(truth_set - pred_set),
                "union_count": len(pred_set | truth_set),
                "overlap_ratio": round(jaccard(pred_set, truth_set), 6),
            }
        )
    write_csv(
        Path(args.output),
        rows,
        [
            "device_type",
            "predicted_count",
            "truth_count",
            "precision",
            "recall",
            "f1",
            "jaccard",
            "semantic_precision",
            "semantic_recall",
            "semantic_f1",
        ],
    )
    write_csv(
        Path(args.overlap_output),
        overlap_rows,
        [
            "device_type",
            "shared_endpoint_count",
            "predicted_only_count",
            "truth_only_count",
            "union_count",
            "overlap_ratio",
        ],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
