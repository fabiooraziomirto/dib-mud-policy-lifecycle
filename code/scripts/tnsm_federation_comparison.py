"""Run graph-augmented and analytically auditable graph-free federation scoring."""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dib.core.io import write_csv
from tnsm_submission_common import run_timed, write_manifest


VARIANTS = {
    # Absolute paths into reproducibility/configs/ (this package's single
    # canonical copy, see configs/LOCKED_CONFIGS.md) rather than
    # ROOT-relative ("configs/default_hyperparams.yaml" etc., the DIB/-root
    # paths these are verbatim copies of but that do not exist inside this
    # self-contained code/ checkout -- same fix as scripts/ablation_multiseed.py).
    "graph_augmented": str(ROOT.parent / "configs" / "graph_augmented.yaml"),
    "graph_free": str(ROOT.parent / "configs" / "graph_free_unweighted_federation.yaml"),
}


def mean(rows: list[dict[str, str]], field: str) -> float:
    return sum(float(row[field]) for row in rows) / len(rows) if rows else 0.0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default="outputs/tnsm_submission_2026/federation")
    parser.add_argument("--observations", default="data/processed/real_federation_observations.csv")
    parser.add_argument("--ground-truth-dir", default="data/unsw/profiles/normalized")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)
    output = ROOT / args.output_dir
    comparison: list[dict[str, object]] = []
    commands: list[list[str]] = []
    timings: dict[str, dict] = {}
    for label, config in VARIANTS.items():
        variant_dir = output / label
        command = [sys.executable, "scripts/real_federation_scoring.py", "--config", config, "--federation-observations", args.observations, "--ground-truth-dir", args.ground_truth_dir, "--seed", str(args.seed), "--output-dir", str(variant_dir)]
        commands.append(command)
        timings[label] = run_timed(command, cwd=ROOT, log_path=variant_dir / "run.log")
        result = variant_dir / "real_federation_scoring.csv"
        with result.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        for row in rows:
            row["variant"] = label
            # Explicit margin prevents a presentation from mistaking the augmented boundary case for a proof.
            row["bound_margin"] = round(0.65 - float(row["proposition1_bound_at_f"]), 6)
            comparison.append(row)
    fields = ["variant", "device_type", "org_count", "accepted_endpoint_count", "semantic_f1_vs_unsw_ground_truth", "exception_burden_per_org", "single_org_fraction_f", "proposition1_bound_at_f", "bound_margin", "proposition1_provably_safe", "fake_endpoint_score", "fake_endpoint_accepted"]
    comparison = [{field: row.get(field, "") for field in fields} for row in comparison]
    write_csv(output / "federation_config_comparison.csv", comparison, fields)
    summary = []
    for label in VARIANTS:
        rows = [r for r in comparison if r["variant"] == label]
        summary.append({"variant": label, "device_count": len(rows), "mean_f1": round(mean(rows, "semantic_f1_vs_unsw_ground_truth"), 6), "mean_accepted": round(mean(rows, "accepted_endpoint_count"), 6), "mean_exception_burden": round(mean(rows, "exception_burden_per_org"), 6), "fake_admissions": sum(r["fake_endpoint_accepted"].lower() == "true" for r in rows), "provably_safe_devices": sum(r["proposition1_provably_safe"].lower() == "true" for r in rows)})
    write_csv(output / "federation_config_summary.csv", summary, list(summary[0]))
    write_manifest(output, experiment="federation_config_comparison", config={"variants": VARIANTS, "primary": "graph_free_nonweighted"}, inputs={"observations": args.observations, "ground_truth": args.ground_truth_dir}, commands=commands, metrics={"timings": timings})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
