from __future__ import annotations

import argparse
import csv
import itertools
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dib.core.io import write_csv
from dib.evaluation.dib import admit_auto
from dib.evaluation.profiles import (
    PREDICTED_DIRECTION,
    canonical_device_name,
    load_profile_dir,
    normalize_profile_protocol,
    semantic_match_metrics,
)
from dib.evaluation.statistics import compare_paired


def load_scored_rows(path: Path) -> list[dict]:
    """Load final_scores.csv and reuse its already-computed C_site/C_time/C_graph per
    endpoint, so re-scoring a weight combination is just float math, not a full re-run
    of DIBScorer (which would re-build the co-occurrence graph and re-run PageRank).

    Also loads endpoint_class (added to final_scores.csv by Fase 2.3a) so that
    predicted_sets_for_params() can apply admit_auto()'s typed gate, not just
    score>=theta -- prior to this fix, this loader silently dropped the column
    entirely, so the grid search / cross-validated F1 this script reports never
    exercised the typed gate at all, regardless of how the input file was
    generated (Fase 3, Gruppo (b): same bug class as
    dib.experiments.compromised_baseline.admission_exception_curve, Fase 3
    Gruppo (a)).
    """
    rows = []
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            device_type = canonical_device_name(row["device_type"])
            protocol = normalize_profile_protocol(row["protocol"], int(row["port"]))
            rows.append(
                {
                    "device_type": device_type,
                    "key": (device_type, PREDICTED_DIRECTION, row["endpoint"].lower(), protocol, int(row["port"])),
                    "site_confidence": float(row["site_confidence"]),
                    "temporal_confidence": float(row["temporal_confidence"]),
                    "graph_confidence": float(row["graph_confidence"]),
                    "endpoint_class": row.get("endpoint_class", "other"),
                }
            )
    return rows


def predicted_sets_for_params(
    rows: list[dict], alpha: float, beta: float, gamma: float, theta: float
) -> dict[str, set]:
    predicted: dict[str, set] = {}
    for row in rows:
        score = alpha * row["site_confidence"] + beta * row["temporal_confidence"] + gamma * row["graph_confidence"]
        if admit_auto(score, theta, row["endpoint_class"]):
            predicted.setdefault(row["device_type"], set()).add(row["key"])
    return predicted


def mean_f1(predicted: dict[str, set], truth: dict[str, set], devices: list[str]) -> float:
    values = [
        semantic_match_metrics(predicted.get(device, set()), truth[device])["semantic_f1"] for device in devices
    ]
    return sum(values) / len(values) if values else 0.0


def grid_search_best(
    rows: list[dict], truth: dict[str, set], devices: list[str], grid: dict[str, list[float]]
) -> tuple[tuple[float, float, float, float], float]:
    best_params = (0.5, 0.3, 0.2, 0.65)
    best_score = -1.0
    for alpha, beta, gamma, theta in itertools.product(
        grid["alpha"], grid["beta"], grid["gamma"], grid["theta"]
    ):
        predicted = predicted_sets_for_params(rows, alpha, beta, gamma, theta)
        score = mean_f1(predicted, truth, devices)
        if score > best_score:
            best_score = score
            best_params = (alpha, beta, gamma, theta)
    return best_params, best_score


def cross_validate(
    rows: list[dict], truth: dict[str, set], grid: dict[str, list[float]], folds: int, seed: int
) -> tuple[dict[str, float], list[dict]]:
    """Tune (alpha, beta, gamma, theta) on K-1 folds of device types and evaluate on the
    held-out fold, so the reported DIB F1 is not selected against the same devices it is
    scored on (unlike a plain grid search against the full ground truth, which would let
    DIB's hyperparameters overfit the test set while baselines have none to tune).
    """
    devices = sorted(truth)
    rng = random.Random(seed)
    shuffled = devices[:]
    rng.shuffle(shuffled)
    fold_assignment = {device: i % folds for i, device in enumerate(shuffled)}

    held_out_f1: dict[str, float] = {}
    fold_rows: list[dict] = []
    for fold in range(folds):
        train_devices = [d for d in devices if fold_assignment[d] != fold]
        test_devices = [d for d in devices if fold_assignment[d] == fold]
        if not test_devices:
            continue
        best_params, train_score = grid_search_best(rows, truth, train_devices, grid)
        predicted = predicted_sets_for_params(rows, *best_params)
        for device in test_devices:
            held_out_f1[device] = semantic_match_metrics(predicted.get(device, set()), truth[device])["semantic_f1"]
        fold_rows.append(
            {
                "fold": fold,
                "alpha": best_params[0],
                "beta": best_params[1],
                "gamma": best_params[2],
                "theta": best_params[3],
                "train_mean_f1": round(train_score, 6),
                "test_devices": ";".join(test_devices),
            }
        )
    return held_out_f1, fold_rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Grid-search DIB's alpha/beta/gamma/theta against ground truth using K-fold "
            "cross-validation across device types, so the reported accuracy is not "
            "tuned and evaluated on the same data (which would be an unfair comparison "
            "against baselines that have no hyperparameters to tune)."
        )
    )
    parser.add_argument("--final-scores", default="outputs/final_scores.csv")
    parser.add_argument("--ground-truth-dir", default="data/unsw/profiles/normalized")
    parser.add_argument("--output-dir", default="outputs/tuning")
    parser.add_argument("--folds", type=int, default=4)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--alpha", type=float, nargs="+", default=[0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9])
    parser.add_argument("--beta", type=float, nargs="+", default=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7])
    parser.add_argument("--gamma", type=float, nargs="+", default=[0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7])
    parser.add_argument(
        "--theta",
        type=float,
        nargs="+",
        default=[0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.55, 0.6, 0.65, 0.7],
    )
    args = parser.parse_args(argv)

    rows = load_scored_rows(Path(args.final_scores))
    truth = load_profile_dir(Path(args.ground_truth_dir))
    grid = {"alpha": args.alpha, "beta": args.beta, "gamma": args.gamma, "theta": args.theta}

    devices = sorted(truth)
    overall_best_params, overall_best_score = grid_search_best(rows, truth, devices, grid)
    print(f"unconstrained (overfit) best params: {overall_best_params} mean_f1={overall_best_score:.6f}")

    held_out_f1, fold_rows = cross_validate(rows, truth, grid, args.folds, args.seed)
    output_dir = Path(args.output_dir)
    write_csv(
        output_dir / "cross_validation_folds.csv",
        fold_rows,
        ["fold", "alpha", "beta", "gamma", "theta", "train_mean_f1", "test_devices"],
    )
    write_csv(
        output_dir / "cross_validated_f1.csv",
        [{"device_type": device, "semantic_f1": round(f1, 6)} for device, f1 in sorted(held_out_f1.items())],
        ["device_type", "semantic_f1"],
    )

    cv_mean = sum(held_out_f1.values()) / len(held_out_f1) if held_out_f1 else 0.0
    print(f"cross-validated (honest) mean_f1 across {args.folds} folds: {cv_mean:.6f}")
    print(f"wrote {output_dir / 'cross_validation_folds.csv'}")
    print(f"wrote {output_dir / 'cross_validated_f1.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
