"""Twenty-seed day-0 (window_days=0) cold-start F1 for both operating
points (Fase 1 audit item P1: main.tex Sec. VI-C's "0.166+-0.004 /
0.177+-0.002" was previously provisional, never re-verified against the
live typed-gate admission path). Mirrors ablation_multiseed.py's seed
convention exactly (seeds 0..19, exclude_non_global_ips, site_count=10,
partition_strategy=random) and reuses cold_start_rows()/DIBScorer.score()
unmodified -- no local re-threshold, gate-aware by construction.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import yaml

from dib.core.io import filter_observations, read_observations_csv, write_csv
from dib.evaluation.dib import ScoringConfig
from dib.evaluation.profiles import load_profile_dir
from dib.evaluation.trust import calibrate_reference_breadth
from dib.experiments.cold_start import cold_start_rows
from dib.simulator.sites import partition_observations
from tnsm_submission_common import write_manifest

CONFIGS = {
    # Absolute paths into reproducibility/configs/ -- see
    # scripts/ablation_multiseed.py's identical fix and
    # configs/LOCKED_CONFIGS.md.
    "graph_augmented": ROOT.parent / "configs" / "graph_augmented.yaml",
    "graph_free_selected": ROOT.parent / "configs" / "graph_free_selected.yaml",
}
SEEDS = list(range(20))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def base_config(path: Path, observations) -> ScoringConfig:
    scoring = yaml.safe_load(path.read_text(encoding="utf-8"))["scoring"]
    trust = bool(scoring.get("trust_weighted", False))
    return ScoringConfig(
        alpha=float(scoring["alpha"]), beta=float(scoring["beta"]), gamma=float(scoring["gamma"]),
        theta=float(scoring["theta"]), min_reporting_sites=int(scoring["min_reporting_sites"]),
        graph_enabled=bool(scoring.get("graph_enabled", True)),
        trust_weighted=trust,
        trust_reference_breadth=calibrate_reference_breadth(observations) if trust else 0.0,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observations", default="data/processed/observations_enriched.csv")
    parser.add_argument("--ground-truth-dir", default="data/unsw/profiles/normalized")
    parser.add_argument("--output-dir", default="outputs/cold_start_multiseed")
    parser.add_argument("--manifest-only", action="store_true", help="Write provenance for an already generated detail CSV without recomputing it.")
    args = parser.parse_args(argv)

    output = ROOT / args.output_dir
    output.mkdir(parents=True, exist_ok=True)
    observation_path = ROOT / args.observations
    result_path = output / "cold_start_multiseed_detail.csv"
    if args.manifest_only:
        if not result_path.exists():
            raise FileNotFoundError(f"Cannot write manifest: missing {result_path}")
        with result_path.open(encoding="utf-8", newline="") as handle:
            detail_rows = list(csv.DictReader(handle))
        write_manifest(
            output,
            experiment="cold_start_multiseed",
            config={"configs": {name: str(path) for name, path in CONFIGS.items()}, "seeds": SEEDS, "site_count": 10, "partition_strategy": "random", "window_days": 0, "exclude_non_global_ips": True},
            inputs={"observations": args.observations, "observations_sha256": sha256(observation_path), "ground_truth": args.ground_truth_dir},
            commands=[], metrics={"rows": len(detail_rows), "output_sha256": sha256(result_path)},
        )
        return 0

    original = read_observations_csv(observation_path)
    filtered = list(filter_observations(original, exclude_non_global_ips=True))
    truth = load_profile_dir(ROOT / args.ground_truth_dir)

    detail_rows = []
    for config_name, config_path in CONFIGS.items():
        f1_by_seed = []
        for seed in SEEDS:
            sites = partition_observations(filtered, 10, strategy="random", seed=seed)
            observations = [obs for site in sites for obs in site.observations]
            config = base_config(ROOT / config_path, observations)
            rows = cold_start_rows(observations, truth, config, windows=[0])
            seeded = [r for r in rows if r["method"] == "registry_seeded" and r["window_days"] == 0]
            f1 = sum(float(r["mean_semantic_f1"]) for r in seeded) / len(seeded) if seeded else 0.0
            f1_by_seed.append(f1)
            detail_rows.append({"config": config_name, "seed": seed, "day0_f1": round(f1, 6)})
            print(f"{config_name} seed={seed}: day0_f1={f1:.6f}", flush=True)
        mean_f1 = statistics.mean(f1_by_seed)
        std_f1 = statistics.stdev(f1_by_seed) if len(f1_by_seed) > 1 else 0.0
        print(f"{config_name}: mean={mean_f1:.6f} std={std_f1:.6f} over {len(f1_by_seed)} seeds", flush=True)

    write_csv(output / "cold_start_multiseed_detail.csv", detail_rows, ["config", "seed", "day0_f1"])
    write_manifest(
        output,
        experiment="cold_start_multiseed",
        config={
            "configs": {name: str(path) for name, path in CONFIGS.items()},
            "seeds": SEEDS,
            "site_count": 10,
            "partition_strategy": "random",
            "window_days": 0,
            "exclude_non_global_ips": True,
        },
        inputs={
            "observations": args.observations,
            "observations_sha256": sha256(observation_path),
            "ground_truth": args.ground_truth_dir,
        },
        commands=[],
        metrics={"rows": len(detail_rows), "output_sha256": sha256(result_path)},
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
