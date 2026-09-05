"""Multi-seed rerun for the TNSM statistical-rigor pass (group A metrics).

Reruns mean per-device F1 (UNSW reconstruction) and day-0 cold-start F1
across N seeds, for both shipped operating points, WITHOUT changing any
weight/hyperparameter -- only `experiments.seed` varies, which is the sole
source of run-to-run variance in this pipeline (it drives
`partition_observations`, the site-partitioning step; DIBScorer itself is
deterministic given a fixed set of observations, see dib/evaluation/dib.py).

Writes one row per (config, seed) with the raw measured values, so the
per-seed data is reproducible and inspectable, plus a seed-set record.
Does NOT compute or print any summary that isn't derived from these
measured rows -- no invented std/CI.
"""
from __future__ import annotations

import argparse
import csv
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def build_seeded_config(base_config_path: Path, seed: int, tmp_dir: Path) -> Path:
    config = yaml.safe_load(base_config_path.read_text(encoding="utf-8"))
    config["experiments"]["seed"] = seed
    out_path = tmp_dir / f"{base_config_path.stem}_seed{seed}.yaml"
    out_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return out_path


def run_experiment(
    config_path: Path, experiment: str, output_dir: Path, observations: Path, exclude_non_global_ips: bool = False
) -> None:
    cmd = [
        sys.executable, str(ROOT / "run_experiments.py"),
        "--config", str(config_path),
        "--observations", str(observations),
        "--site-count", "10",
        "--partition-strategy", "random",
        "--experiment", experiment,
        "--output-dir", str(output_dir),
    ]
    if exclude_non_global_ips:
        cmd.append("--exclude-non-global-ips")
    subprocess.run(cmd, check=True, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def evaluate_reconstruction(output_dir: Path) -> tuple[float, float, int]:
    """Returns (mean_f1_across_devices, std_f1_across_devices, device_count)."""
    accuracy_csv = output_dir / "profile_accuracy.csv"
    cmd = [
        sys.executable, str(ROOT / "scripts" / "evaluate_profiles.py"),
        "--scores", str(output_dir / "final_scores.csv"),
        "--ground-truth-dir", "data/unsw/profiles/normalized",
        "--output", str(accuracy_csv),
        "--overlap-output", str(output_dir / "profile_overlap.csv"),
    ]
    subprocess.run(cmd, check=True, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    values = []
    with accuracy_csv.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            values.append(float(row["semantic_f1"]))
    n = len(values)
    mean = sum(values) / n if n else 0.0
    variance = sum((v - mean) ** 2 for v in values) / (n - 1) if n > 1 else 0.0
    return mean, variance ** 0.5, n


def read_day0_f1(output_dir: Path) -> float:
    summary_csv = output_dir / "experiments" / "cold_start" / "cold_start_summary.csv"
    with summary_csv.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if row["window_days"] == "0" and row["method"] == "registry_seeded":
                return float(row["mean_semantic_f1"])
    raise RuntimeError(f"day-0 registry_seeded row not found in {summary_csv}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observations", default="data/processed/observations_enriched.csv")
    parser.add_argument("--seeds", type=int, default=20, help="Number of trial seeds, 0..N-1")
    parser.add_argument("--seed-start", type=int, default=0, help="First seed to run (resume support)")
    parser.add_argument(
        "--configs",
        nargs="+",
        default=["configs/default_hyperparams.yaml:graph_augmented", "configs/ref_trust_hyperparams.yaml:graph_free"],
        help="path:label pairs",
    )
    parser.add_argument("--output-root", default="outputs/variance_group_a")
    parser.add_argument("--keep-run-dirs", action="store_true", help="Keep full per-seed experiment output trees (large).")
    parser.add_argument("--exclude-non-global-ips", action=argparse.BooleanOptionalAction, default=True,
                        help="Apply the same post-load, pre-partition filter as runner.py --exclude-non-global-ips.")
    args = parser.parse_args(argv)

    observations = Path(args.observations)
    output_root = Path(args.output_root)
    output_root.mkdir(parents=True, exist_ok=True)
    raw_rows = []

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        for config_entry in args.configs:
            config_path_str, label = config_entry.split(":")
            base_config_path = ROOT / config_path_str
            for seed in range(args.seed_start, args.seeds):
                seeded_config = build_seeded_config(base_config_path, seed, tmp_dir)
                run_dir = output_root / label / f"seed_{seed:02d}"
                run_experiment(seeded_config, "reconstruction", run_dir, observations, args.exclude_non_global_ips)
                run_experiment(seeded_config, "cold_start", run_dir, observations, args.exclude_non_global_ips)
                mean_f1, std_f1_devices, device_count = evaluate_reconstruction(run_dir)
                day0_f1 = read_day0_f1(run_dir)
                raw_rows.append(
                    {
                        "config_label": label,
                        "seed": seed,
                        "mean_per_device_f1_unsw": round(mean_f1, 6),
                        "std_across_devices_unsw": round(std_f1_devices, 6),
                        "device_count": device_count,
                        "day0_cold_start_f1": round(day0_f1, 6),
                        "exclude_non_global_ips": args.exclude_non_global_ips,
                    }
                )
                print(
                    f"[{label}] seed={seed:02d} mean_f1={mean_f1:.6f} "
                    f"std_across_devices={std_f1_devices:.6f} day0_f1={day0_f1:.6f}",
                    flush=True,
                )
                if not args.keep_run_dirs:
                    shutil.rmtree(run_dir, ignore_errors=True)

    raw_csv = output_root / "raw_per_seed.csv"
    fieldnames = ["config_label", "seed", "mean_per_device_f1_unsw", "std_across_devices_unsw", "device_count", "day0_cold_start_f1", "exclude_non_global_ips"]
    with raw_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(raw_rows)
    print(f"wrote {raw_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
