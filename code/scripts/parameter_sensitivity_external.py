"""Experiment B1+B2 -- theta and (alpha,beta) sensitivity OUTSIDE UNSW
(Mon(IoT)r all capture trees + hold-out, and YourThings), graph-free.

Scores each corpus exactly ONCE per run (graph_enabled=False, so the
component confidences are independent of alpha/beta/theta -- the same
"weight-independent" property scripts/poisoning_weight_grid.py already
relies on, verified by reading dib.py in Step 0 of this session: alpha and
beta only ever appear in the final linear combination, never inside the
site_confidence/temporal_confidence computation itself). Every
(theta) or (alpha,beta) cell is then produced by recombining those SAME
raw per-fact components and re-gating with the real admit_auto() imported
from dib.evaluation.dib -- never a local reimplementation of the
admission rule, which is exactly the bug class found and fixed elsewhere
in this session (compromised_baseline.py, tune_dib_weights.py, etc).

B1: theta in [0.50, 0.80] step 0.025, alpha/beta fixed at the paper's
    selected graph-free operating point (0.6/0.4).
B2: alpha in [0.4, 0.9] step 0.05, beta=1-alpha, gamma=0, theta fixed at
    0.65 (baseline). Margin theta-bound(alpha,f) at f=0.30/0.50 computed
    analytically via dib.analysis.poison_bound (already-proven closed
    form, not re-derived here) alongside the measured F1.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dib.analysis.poison_bound import evaluate_bound
from dib.core.io import filter_observations, read_observations_csv, write_csv
from dib.evaluation.dib import DIBScorer, ScoringConfig, admit_auto
from dib.evaluation.profiles import PREDICTED_DIRECTION, canonical_device_name, load_profile_dir, semantic_match_metrics

THETAS = [round(0.50 + 0.025 * i, 3) for i in range(13)]  # 0.50..0.80
ALPHAS = [round(0.4 + 0.05 * i, 3) for i in range(11)]  # 0.4..0.9
MARGIN_FRACTIONS = [0.30, 0.50]
BASELINE_ALPHA, BASELINE_BETA, BASELINE_THETA = 0.6, 0.4, 0.65


def _score_once(observations: list) -> list:
    config = ScoringConfig(alpha=BASELINE_ALPHA, beta=BASELINE_BETA, gamma=0.0, theta=BASELINE_THETA, graph_enabled=False)
    return DIBScorer(config).score(observations)


def _metrics_for_predicted(predicted: dict, truth: dict) -> tuple[float, float, float, int]:
    devices = sorted(set(predicted) | set(truth))
    precisions, recalls, f1s = [], [], []
    n_admitted = sum(len(v) for v in predicted.values())
    for device in devices:
        pred_set = predicted.get(device, set())
        truth_set = truth.get(device, set())
        if not truth_set:
            continue
        m = semantic_match_metrics(pred_set, truth_set)
        precisions.append(m["semantic_precision"])
        recalls.append(m["semantic_recall"])
        f1s.append(m["semantic_f1"])
    n = len(f1s)
    return (
        round(sum(precisions) / n, 6) if n else 0.0,
        round(sum(recalls) / n, 6) if n else 0.0,
        round(sum(f1s) / n, 6) if n else 0.0,
        n_admitted,
    )


def _predicted_at(scores: list, truth: dict) -> dict:
    predicted: dict[str, set] = {}
    for score in scores:
        device = canonical_device_name(score.device_type)
        if device not in truth:
            continue
        predicted.setdefault(device, set()).add((device, PREDICTED_DIRECTION, score.endpoint, score.protocol, score.port))
    return predicted


def theta_sweep(scores: list, truth: dict) -> list[dict]:
    rows = []
    for theta in THETAS:
        admitted = [
            s for s in scores
            if admit_auto(s.site_confidence * BASELINE_ALPHA + s.temporal_confidence * BASELINE_BETA, theta, s.endpoint_class)
        ]
        predicted = _predicted_at(admitted, truth)
        precision, recall, f1, n = _metrics_for_predicted(predicted, truth)
        rows.append({"theta": theta, "alpha": BASELINE_ALPHA, "beta": BASELINE_BETA,
                      "admitted_endpoint_count": n, "precision": precision, "recall": recall, "f1": f1})
    return rows


def alpha_sweep(scores: list, truth: dict) -> tuple[list[dict], list[dict]]:
    rows = []
    for alpha in ALPHAS:
        beta = round(1.0 - alpha, 6)
        admitted = [
            s for s in scores
            if admit_auto(s.site_confidence * alpha + s.temporal_confidence * beta, BASELINE_THETA, s.endpoint_class)
        ]
        predicted = _predicted_at(admitted, truth)
        precision, recall, f1, n = _metrics_for_predicted(predicted, truth)
        rows.append({"alpha": alpha, "beta": beta, "theta": BASELINE_THETA,
                      "admitted_endpoint_count": n, "precision": precision, "recall": recall, "f1": f1})
    margin_rows = []
    for alpha in ALPHAS:
        beta = round(1.0 - alpha, 6)
        for f in MARGIN_FRACTIONS:
            ev = evaluate_bound(alpha, beta, 0.0, BASELINE_THETA, f)
            margin_rows.append({
                "alpha": alpha, "beta": beta, "theta": BASELINE_THETA, "malicious_fraction": f,
                "theoretical_bound": round(ev.theoretical_bound, 6), "margin": round(ev.margin, 6),
                "provably_safe": ev.provably_safe,
            })
    return rows, margin_rows


def run_corpus(name: str, observations_path: Path, ground_truth_dir: Path, output_dir: Path) -> None:
    print(f"--- {name} ---", flush=True)
    observations = list(filter_observations(read_observations_csv(observations_path), exclude_non_global_ips=True))
    print(f"{len(observations)} obs after filter", flush=True)
    scores = _score_once(observations)
    truth = load_profile_dir(ground_truth_dir)

    theta_rows = theta_sweep(scores, truth)
    alpha_rows, margin_rows = alpha_sweep(scores, truth)

    write_csv(output_dir / f"{name}_theta_sweep.csv", theta_rows,
              ["theta", "alpha", "beta", "admitted_endpoint_count", "precision", "recall", "f1"])
    write_csv(output_dir / f"{name}_alpha_sweep.csv", alpha_rows,
              ["alpha", "beta", "theta", "admitted_endpoint_count", "precision", "recall", "f1"])
    write_csv(output_dir / f"{name}_alpha_margin.csv", margin_rows,
              ["alpha", "beta", "theta", "malicious_fraction", "theoretical_bound", "margin", "provably_safe"])
    print(f"{name}: wrote theta_sweep ({len(theta_rows)} rows), alpha_sweep ({len(alpha_rows)} rows)", flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--moniotr-observations", default="data/processed/moniotr_full_observations.csv")
    parser.add_argument("--yourthings-observations", default="")
    parser.add_argument("--ground-truth-dir", default="data/unsw/profiles/normalized")
    parser.add_argument("--output-dir", default="outputs/parameter_sensitivity_external")
    parser.add_argument("--corpora", default="moniotr,yourthings")
    args = parser.parse_args(argv)

    output = ROOT / args.output_dir
    output.mkdir(parents=True, exist_ok=True)
    truth_dir = ROOT / args.ground_truth_dir

    requested = set(args.corpora.split(","))
    if "moniotr" in requested:
        run_corpus("moniotr", ROOT / args.moniotr_observations, truth_dir, output)
    if "yourthings" in requested:
        yt_path = Path(args.yourthings_observations) if args.yourthings_observations else ROOT / "data/processed/yourthings_observations.csv"
        if not yt_path.exists():
            print(f"YourThings observations not found at {yt_path}, skipping (declare as data gap).", flush=True)
        else:
            run_corpus("yourthings", yt_path, truth_dir, output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
