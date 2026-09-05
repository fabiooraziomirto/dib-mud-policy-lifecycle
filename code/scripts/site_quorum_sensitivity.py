#!/usr/bin/env python3
"""Evaluate DIB admission sensitivity over pseudo-site count N and quorum m.

The expensive traffic parsing, partitioning, trust calibration, and scoring are
performed once per N.  Quorum is then varied over the frozen endpoint scores;
this is exact because m affects only the final admission predicate, not Cs, Ct,
or the trust weights.  UNSW partitions are pseudo-sites, so this experiment is
a sensitivity analysis rather than evidence about independent administrations.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dib.core.io import filter_observations, read_observations_csv, write_csv
from dib.evaluation.dib import DIBScorer
from dib.evaluation.profiles import load_profile_dir
from dib.simulator.sites import partition_observations

from recall_funnel import observed_stage, scoring_config, staged_stage, summarize


FIELDS = [
    "site_count",
    "quorum",
    "accepted_facts",
    "matched_reference_aces",
    "macro_full_profile_recall",
    "observable_macro_ceiling",
    "observable_retention_pct",
    "seed",
]


def parse_ints(value: str) -> list[int]:
    values = sorted({int(item) for item in value.split(",")})
    if not values or any(item < 1 for item in values):
        raise argparse.ArgumentTypeError("expected comma-separated positive integers")
    return values


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observations", required=True)
    parser.add_argument("--ground-truth-dir", required=True)
    parser.add_argument("--config", default=str(ROOT.parent / "configs" / "graph_free_selected.yaml"))
    parser.add_argument("--site-counts", type=parse_ints, default=parse_ints("2,3,5,10"))
    parser.add_argument("--quorums", type=parse_ints, default=parse_ints("1,2,3,5"))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", default=str(ROOT.parent / "results" / "site_quorum" / "site_quorum_sensitivity.csv"))
    args = parser.parse_args(argv)

    truth = load_profile_dir(Path(args.ground_truth_dir))
    observations = list(filter_observations(
        read_observations_csv(Path(args.observations)), exclude_non_global_ips=True
    ))
    observed = summarize("observed", "capture", observed_stage(observations, truth), truth)
    ceiling = float(observed["macro_share"])

    output_rows: list[dict[str, object]] = []
    for site_count in args.site_counts:
        sites = partition_observations(observations, site_count, strategy="random", seed=args.seed)
        partitioned = [obs for site in sites for obs in site.observations]
        config = replace(scoring_config(Path(args.config), partitioned), min_reporting_sites=1)
        base_scores = DIBScorer(config).score(partitioned)

        for quorum in args.quorums:
            if quorum > site_count:
                continue
            scores = [
                replace(score, accepted=score.accepted and score.supporting_sites >= quorum)
                for score in base_scores
            ]
            staged = summarize("staged", "pipeline", staged_stage(scores, truth), truth)
            recall = float(staged["macro_share"])
            output_rows.append({
                "site_count": site_count,
                "quorum": quorum,
                "accepted_facts": sum(score.accepted for score in scores),
                "matched_reference_aces": staged["matched_aces"],
                "macro_full_profile_recall": recall,
                "observable_macro_ceiling": ceiling,
                "observable_retention_pct": round(100 * recall / ceiling, 2) if ceiling else 0.0,
                "seed": args.seed,
            })
        print(f"completed N={site_count}", flush=True)

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    write_csv(output, output_rows, FIELDS)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
