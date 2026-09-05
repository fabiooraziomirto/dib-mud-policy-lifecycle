"""Paired seed-level statistics for TNSM configuration comparisons."""
from __future__ import annotations

import argparse
import csv
import math
import random
from pathlib import Path

from scipy.stats import ttest_rel, wilcoxon


def percentile(values: list[float], p: float) -> float:
    values = sorted(values)
    index = (len(values) - 1) * p
    low, high = int(index), min(int(index) + 1, len(values) - 1)
    return values[low] + (values[high] - values[low]) * (index - low)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--left", default="graph_free")
    parser.add_argument("--right", default="graph_augmented")
    parser.add_argument("--metrics", default="accepted_count,jaccard_vs_full,mean_f1_vs_ground_truth")
    parser.add_argument("--bootstrap", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=20260723)
    args = parser.parse_args(argv)
    with Path(args.raw).open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    rng = random.Random(args.seed)
    output = []
    for variant in sorted({r["variant"] for r in rows}):
        left = {int(r["seed"]): r for r in rows if r["config"] == args.left and r["variant"] == variant}
        right = {int(r["seed"]): r for r in rows if r["config"] == args.right and r["variant"] == variant}
        seeds = sorted(left.keys() & right.keys())
        for metric in [m for m in args.metrics.split(",") if m]:
            delta = [float(left[s][metric]) - float(right[s][metric]) for s in seeds]
            if len(delta) < 2:
                continue
            means = [sum(rng.choices(delta, k=len(delta))) / len(delta) for _ in range(args.bootstrap)]
            try:
                w = wilcoxon(delta, alternative="two-sided", method="auto")
                wp = float(w.pvalue)
            except ValueError:
                wp = 1.0
            t = ttest_rel([float(left[s][metric]) for s in seeds], [float(right[s][metric]) for s in seeds])
            output.append({"left": args.left, "right": args.right, "variant": variant, "metric": metric, "n_pairs": len(delta), "mean_delta": round(sum(delta) / len(delta), 6), "bootstrap_ci95_low": round(percentile(means, .025), 6), "bootstrap_ci95_high": round(percentile(means, .975), 6), "wilcoxon_p_two_sided": round(wp, 8), "paired_t_p_two_sided": round(float(t.pvalue), 8)})
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(output[0]) if output else ["left", "right", "variant", "metric", "n_pairs", "mean_delta", "bootstrap_ci95_low", "bootstrap_ci95_high", "wilcoxon_p_two_sided", "paired_t_p_two_sided"])
        writer.writeheader(); writer.writerows(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
