"""Run the fixed strict graph-free suite without changing any paper artefact."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from tnsm_submission_common import run_timed, write_manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default="outputs/tnsm_submission_2026/strict_graphfree")
    parser.add_argument("--observations", default="data/processed/observations_enriched.csv")
    parser.add_argument("--federation-observations", default="data/processed/real_federation_observations.csv")
    parser.add_argument("--moniotr-observations", default="data/processed/moniotr_full_observations.csv")
    parser.add_argument("--calibration-observations", required=True)
    args = parser.parse_args(argv)
    out = ROOT / args.output_dir
    config = "configs/ref_strict_hyperparams.yaml"
    commands = {
        "sybil": [sys.executable, "scripts/sybil_sensitivity_surface.py", "--config", config, "--observations", args.observations, "--calibration-observations", args.calibration_observations, "--output-dir", str(out / "sybil")],
        "federation": [sys.executable, "scripts/real_federation_scoring.py", "--config", config, "--federation-observations", args.federation_observations, "--output-dir", str(out / "federation")],
        "transfer": [sys.executable, "scripts/cross_site_heterogeneity_moniotr.py", "--config", config, "--observations", args.moniotr_observations, "--output-dir", str(out / "transfer")],
    }
    timings = {name: run_timed(command, cwd=ROOT, log_path=out / name / "run.log") for name, command in commands.items()}
    write_manifest(out, experiment="strict_graphfree_suite", config={"alpha": .7, "beta": .3, "gamma": 0, "theta": .65, "bound_margin_at_f03": .14}, inputs={"observations": args.observations, "federation": args.federation_observations, "moniotr": args.moniotr_observations}, commands=list(commands.values()), metrics={"timings": timings})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
