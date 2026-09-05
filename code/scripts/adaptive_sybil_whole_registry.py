"""Whole-registry impact of a sustained adaptive-Sybil campaign against one
device (Sec. VI-E "temporal dilution" paragraph, P3 in audit_numeri.md).

Adapted from DIB/reports/item1_private_ip_filter/adaptive_sybil_whole_registry_AFTER.py
(copied on demand; declared here). That version read a legacy pre-filtered
CSV (observations_enriched_item1fixed.csv, 1,268,020 rows after header);
this version reads the canonical observations_enriched.csv and applies
filter_observations(exclude_non_global_ips=True) explicitly, matching the
convention used everywhere else in this artifact -- confirmed row-count
identical (1,268,020) before running, so the two are the same population.
No other change: still scores via DIBScorer(...).score(...) and counts
.accepted directly (gate-aware already, no local re-threshold).
"""
from __future__ import annotations

import argparse
import csv
import sys
from dataclasses import replace as dataclass_replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dib.core.io import filter_observations, read_observations_csv
from dib.evaluation.dib import DIBScorer, ScoringConfig
from dib.evaluation.trust import calibrate_reference_breadth
from dib.experiments.poisoning import inject_adaptive_sybil_endpoint
from dib.simulator.sites import partition_observations

SEED = 42
SITE_COUNT = 10
PARTITION_STRATEGY = "random"
SYBIL_SITE_COUNT = 1600
SPREAD_DAYS = 140
TARGET_DEVICE = "AugustDoorBell"

CONFIGS = {
    "graph_augmented": ScoringConfig(alpha=0.5, beta=0.3, gamma=0.2, theta=0.65, min_reporting_sites=2, graph_enabled=True),
    "graph_free_trust": ScoringConfig(
        alpha=0.6, beta=0.4, gamma=0.0, theta=0.65, min_reporting_sites=2, graph_enabled=False, trust_weighted=True
    ),
}


def score_registry(observations, config: ScoringConfig):
    trial_config = config
    if config.trust_weighted:
        trial_config = dataclass_replace(config, trust_reference_breadth=calibrate_reference_breadth(observations))
    scores = DIBScorer(trial_config).score(observations)
    accepted = [s for s in scores if s.accepted]
    target_accepted = [s for s in accepted if s.device_type == TARGET_DEVICE]
    return len(accepted), len(target_accepted)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observations", default="data/processed/observations_enriched.csv")
    parser.add_argument("--output", default="outputs/adaptive_sybil_whole_registry/adaptive_sybil_whole_registry.csv")
    args = parser.parse_args(argv)

    original = read_observations_csv(ROOT / args.observations)
    filtered = list(filter_observations(original, exclude_non_global_ips=True))
    print(f"{len(filtered)} obs after filter", flush=True)
    sites = partition_observations(filtered, SITE_COUNT, strategy=PARTITION_STRATEGY, seed=SEED)
    redistributed = [obs for site in sites for obs in site.observations]
    attacked = inject_adaptive_sybil_endpoint(
        redistributed, SYBIL_SITE_COUNT, TARGET_DEVICE, SPREAD_DAYS, seed=SEED
    )

    rows = []
    for label, config in CONFIGS.items():
        clean_total, clean_target = score_registry(redistributed, config)
        attacked_total, attacked_target = score_registry(attacked, config)
        rows.append(
            {
                "config": label,
                "clean_accepted_total": clean_total,
                "attacked_accepted_total": attacked_total,
                "clean_accepted_target_device": clean_target,
                "attacked_accepted_target_device": attacked_target,
            }
        )
        print(
            f"{label}: clean_total={clean_total} attacked_total={attacked_total} "
            f"clean_{TARGET_DEVICE}={clean_target} attacked_{TARGET_DEVICE}={attacked_target}",
            flush=True,
        )

    out_path = ROOT / args.output
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {out_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
