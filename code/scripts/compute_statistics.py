from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dib.core.io import write_csv
from dib.evaluation.metrics import f1_score
from dib.evaluation.profiles import load_baseline_profile, load_dib_scores, load_profile_dir, semantic_match_metrics
from dib.evaluation.statistics import bootstrap_ci_diff, compare_paired, holm_bonferroni


METHOD_FILES = {
    "local_profiling": "baselines/local_profiling_profile.csv",
    "majority_voting": "baselines/majority_voting_profile.csv",
    "weighted_voting": "baselines/weighted_voting_profile.csv",
    "frequency_filtered": "baselines/frequency_filtered_profile.csv",
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Paired significance tests (DIB vs baselines) over per-device F1 against ground truth."
    )
    parser.add_argument("--experiment-dir", default="outputs/experiments/reconstruction")
    parser.add_argument("--ground-truth-dir", default="data/unsw/profiles/normalized")
    parser.add_argument("--output-dir", default="outputs/statistics")
    parser.add_argument(
        "--match",
        choices=["literal", "semantic"],
        default="semantic",
        help="literal: exact endpoint string match. semantic: also resolves MUD controller "
        "placeholders (DNS/DHCP/mDNS/gateway) and CIDR ranges (see dib/evaluation/profiles.py).",
    )
    parser.add_argument(
        "--dib-f1-csv",
        help="Optional override: per-device F1 CSV (columns device_type,semantic_f1) such as "
        "scripts/tune_dib_weights.py's cross_validated_f1.csv, to compare baselines against a "
        "held-out-tuned DIB score instead of the fixed default-weight run.",
    )
    args = parser.parse_args(argv)

    experiment_dir = Path(args.experiment_dir)
    truth = load_profile_dir(Path(args.ground_truth_dir))

    if args.dib_f1_csv:
        with Path(args.dib_f1_csv).open(newline="", encoding="utf-8") as handle:
            dib_f1 = {row["device_type"]: float(row["semantic_f1"]) for row in csv.DictReader(handle)}
        method_f1: dict[str, dict[str, float]] = {"dib": dib_f1}
    else:
        dib_profiles = load_dib_scores(experiment_dir / "dib_scores.csv", accepted_only=True)
        method_f1 = {"dib": _f1_per_device(dib_profiles, truth, args.match)}
    for method, relative_path in METHOD_FILES.items():
        path = experiment_dir / relative_path
        if not path.exists():
            continue
        profiles = load_baseline_profile(path)
        method_f1[method] = _f1_per_device(profiles, truth, args.match)

    shared_devices = sorted(set.intersection(*(set(values) for values in method_f1.values())))
    comparison_rows = []
    for method in method_f1:
        if method == "dib":
            continue
        dib_values = [method_f1["dib"][device] for device in shared_devices]
        other_values = [method_f1[method][device] for device in shared_devices]
        comparison = compare_paired("dib", dib_values, method, other_values)
        row = comparison.to_dict()
        boot_lo, boot_hi = bootstrap_ci_diff(dib_values, other_values)
        row["bootstrap_ci_95_low"] = round(boot_lo, 6)
        row["bootstrap_ci_95_high"] = round(boot_hi, 6)
        comparison_rows.append(row)

    # Holm-Bonferroni correction across the family of comparisons tested here
    # (one DIB-vs-baseline test per baseline). Without this, a per-comparison
    # alpha=0.05 inflates the family-wise false-positive rate as the number
    # of baselines grows. Applied to both the paired t-test and the paired
    # Wilcoxon signed-rank test independently -- each is its own family of
    # tests, not one family of two tests -- since Wilcoxon p-values were
    # previously reported uncorrected while t-test p-values were corrected,
    # an inconsistency in the pre-existing pipeline (predates REF-trust).
    holm_pvalues_t = holm_bonferroni([row["t_pvalue"] for row in comparison_rows])
    holm_pvalues_wilcoxon = holm_bonferroni([row["wilcoxon_pvalue"] for row in comparison_rows])
    for row, holm_p_t, holm_p_w in zip(comparison_rows, holm_pvalues_t, holm_pvalues_wilcoxon):
        row["t_pvalue_holm"] = round(holm_p_t, 6)
        row["wilcoxon_pvalue_holm"] = round(holm_p_w, 6)

    write_csv(
        Path(args.output_dir) / "method_comparison.csv",
        comparison_rows,
        [
            "method_a",
            "method_b",
            "n",
            "mean_diff",
            "t_statistic",
            "t_pvalue",
            "t_pvalue_holm",
            "wilcoxon_statistic",
            "wilcoxon_pvalue",
            "wilcoxon_pvalue_holm",
            "cohens_d",
            "ci_95_low",
            "ci_95_high",
            "bootstrap_ci_95_low",
            "bootstrap_ci_95_high",
        ],
    )
    _write_markdown_summary(Path(args.output_dir) / "method_comparison.md", comparison_rows)
    return 0


def _f1_per_device(predicted: dict[str, set], truth: dict[str, set], match: str) -> dict[str, float]:
    if match == "semantic":
        return {
            device_type: semantic_match_metrics(predicted.get(device_type, set()), truth_set)["semantic_f1"]
            for device_type, truth_set in truth.items()
        }
    return {
        device_type: f1_score(predicted.get(device_type, set()), truth_set)
        for device_type, truth_set in truth.items()
    }


def _write_markdown_summary(path: Path, rows: list[dict[str, object]]) -> None:
    lines = [
        "# Statistical Comparison: DIB vs Baselines (paired F1 against ground truth)",
        "",
        "| Baseline | n | Mean Diff (DIB - baseline) | Paired t p-value | Holm-adjusted t p-value | "
        "Wilcoxon p-value | Holm-adjusted Wilcoxon p-value | Cohen's d | 95% CI of diff | Bootstrap 95% CI |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            f"| {row['method_b']} | {row['n']} | {row['mean_diff']} | {row['t_pvalue']} | "
            f"{row['t_pvalue_holm']} | {row['wilcoxon_pvalue']} | {row['wilcoxon_pvalue_holm']} | "
            f"{row['cohens_d']} | [{row['ci_95_low']}, {row['ci_95_high']}] | "
            f"[{row['bootstrap_ci_95_low']}, {row['bootstrap_ci_95_high']}] |"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
