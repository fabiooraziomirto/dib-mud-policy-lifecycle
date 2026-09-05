#!/usr/bin/env python3
"""Create a fixed, disjoint temporal governance-bootstrap split for RWV.

This is explicitly a simulated governance proxy: the same deterministic sites
have an initial trusted window and a later evaluation window. Site identities
therefore remain known while observations are disjoint. It must not be
described as real founding-member data.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from dataclasses import replace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dib.core.io import read_observations_csv, write_csv
from dib.simulator.sites import partition_observations


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True,
                   help="Enriched observations CSV derived from the licensed corpus.")
    p.add_argument("--output-dir", default="outputs/rwv_baseline/governance_bootstrap")
    p.add_argument("--seed", type=int, default=4201)
    p.add_argument("--total-sites", type=int, default=10)
    p.add_argument("--calibration-fraction", type=float, default=0.20,
                   help="Initial per-site fraction reserved for calibration.")
    args = p.parse_args()
    if not 0.0 < args.calibration_fraction < 1.0:
        p.error("calibration-fraction must be in (0,1)")
    observations = read_observations_csv(Path(args.input))
    sites = partition_observations(observations, args.total_sites, strategy="random", seed=args.seed)
    calibration = []
    evaluation = []
    for site in sites:
        ordered = sorted(site.observations, key=lambda o: o.timestamp)
        cut = max(1, int(len(ordered) * args.calibration_fraction))
        calibration.extend(ordered[:cut])
        evaluation.extend(ordered[cut:])
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    fields = list(observations[0].to_dict().keys())
    write_csv(out / "calibration_observations.csv", (o.to_dict() for o in calibration), fields)
    write_csv(out / "evaluation_observations.csv", (o.to_dict() for o in evaluation), fields)
    manifest = {
        "kind": "simulated_temporal_governance_bootstrap",
        "source": str(Path(args.input).resolve()),
        "partition_strategy": "random",
        "partition_seed": args.seed,
        "total_sites": args.total_sites,
        "calibration_sites": [s.site_id for s in sites],
        "evaluation_sites": [s.site_id for s in sites],
        "calibration_fraction": args.calibration_fraction,
        "calibration_observations": len(calibration),
        "evaluation_observations": len(evaluation),
        "unknown_site_weight": 0.1,
        "warning": "Proxy only; not legal founding-member or manufacturer-ratified governance data.",
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
