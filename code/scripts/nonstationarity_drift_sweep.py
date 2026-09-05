"""Experiment A -- legitimate non-stationarity vs. drift-gate correctness,
generalized to every UNSW device type (drift.py's original A3 check covered
only the single most-common device type).

For each device type present in the corpus: simulate a firmware-update
endpoint (class-eligible "update") rolled out to an increasing fraction of
sites over a variable number of days, and ask whether admit_auto() promotes
it within a reasonable horizon -- plus the mandatory counterfactual: the
same kind of change confined to a single site, compared directly against a
single-site compromise using the same spread-days grid.

Uses the same pipeline convention as the rest of this artifact (Fase 2/3):
--exclude-non-global-ips, site_count=10, partition_strategy=random, seed=42,
config alpha=0.6/beta=0.4/gamma=0/theta=0.65 (graph_enabled=False,
trust_weighted=True, "ref_trust_hyperparams.yaml" a.k.a. the paper's
"graph-free selected" operating point) -- and calls DIBScorer.score()
(which applies admit_auto() internally, verified in Step 0 of this
session) rather than any local re-threshold, so there is no
endpoint_class-bypass risk of the kind found and fixed elsewhere in Fase 3.

Performance note: site_confidence and temporal_confidence denominators are
computed by DIBScorer per device_type in isolation (sites_by_device[...],
days_by_device[...], counts_by_device[...] only ever aggregate
observations of that same device_type -- verified by reading dib.py before
writing this script). With graph_enabled=False (this config), the graph
term never enters the score, so restricting the *observations* argument to
one device type's own rows (while still passing the full population via
trust_observations= for correct trust-weight calibration) is mathematically
identical to scoring that device type inside the full corpus. This
optimization is spot-checked against an un-sliced run for one device type
before being trusted for the full sweep (see verify_slicing_equivalence.py
companion invocation in the README).
"""
from __future__ import annotations

import argparse
import statistics
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dib.core.io import filter_observations, read_observations_csv, write_csv
from dib.evaluation.dib import DIBScorer, ScoringConfig
from dib.evaluation.trust import calibrate_reference_breadth
from dib.experiments.drift import inject_drift_endpoint
from dib.simulator.sites import partition_observations

ADOPTION_FRACTIONS = [0.2, 0.4, 0.5, 0.6, 0.8, 1.0]
ROLLOUT_DAYS = [1, 7, 30, 120]
TIME_TO_ADMISSION_CHECKPOINTS = [1, 3, 7, 14, 30, 60, 90, 120]
ISOLATED_SPREAD_DAYS = [1, 7, 30, 120]
CHURN_FRACTION = 0.6
CHURN_DAYS = 120
LEGIT_FQDN = "new-firmware.vendor.example"
COMPROMISE_FQDN = "evil-drift.example"
SEED = 42


def _base_config(clean) -> ScoringConfig:
    # min_reporting_sites=2 mirrors configs/graph_free_selected.yaml (Sec.
    # IV-B corroboration quorum, review fix 2026-07-24); kept explicit here
    # since this script inlines the selected config rather than loading it
    # from YAML.
    return ScoringConfig(
        alpha=0.6, beta=0.4, gamma=0.0, theta=0.65, min_reporting_sites=2, graph_enabled=False,
        trust_weighted=True, trust_reference_breadth=calibrate_reference_breadth(clean),
    )


def _score_of(scores, device_type: str, endpoint: str) -> dict:
    matches = [s for s in scores if s.device_type == device_type and s.endpoint == endpoint]
    if not matches:
        return {"accepted": False, "score": 0.0, "site_confidence": 0.0, "temporal_confidence": 0.0}
    best = max(matches, key=lambda s: s.score)
    return {
        "accepted": best.accepted, "score": best.score,
        "site_confidence": best.site_confidence, "temporal_confidence": best.temporal_confidence,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observations", default="data/processed/observations_enriched.csv")
    parser.add_argument("--output-dir", default="outputs/nonstationarity_drift_sweep")
    parser.add_argument("--site-count", type=int, default=10)
    parser.add_argument("--partition-strategy", default="random")
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--devices", default="", help="comma-separated subset for smoke testing")
    args = parser.parse_args(argv)

    output = ROOT / args.output_dir
    output.mkdir(parents=True, exist_ok=True)

    original = read_observations_csv(ROOT / args.observations)
    filtered = list(filter_observations(original, exclude_non_global_ips=True))
    sites = partition_observations(filtered, args.site_count, strategy=args.partition_strategy, seed=args.seed)
    clean = [obs for site in sites for obs in site.observations]
    config = _base_config(clean)

    device_types = sorted({obs.device_type for obs in clean})
    if args.devices:
        wanted = set(args.devices.split(","))
        device_types = [d for d in device_types if d in wanted]
    print(f"{len(clean)} obs after filter+partition, {len(device_types)} device types", flush=True)

    rollout_rows, ttfa_rows, churn_rows, isolated_rows = [], [], [], []

    for device_type in device_types:
        started = time.perf_counter()
        device_obs = [o for o in clean if o.device_type == device_type]
        eligible_sites = sorted({o.site_id for o in device_obs})
        n_sites = len(eligible_sites)
        import random
        rng = random.Random(args.seed)

        if n_sites < 2:
            rollout_rows.append({
                "device_type": device_type, "n_eligible_sites": n_sites, "adoption_fraction": "",
                "rollout_days": "", "adopting_sites": "", "accepted": "", "score": "",
                "site_confidence": "", "temporal_confidence": "",
                "status": "insufficient_eligible_sites_for_fraction_sweep",
            })
        else:
            # --- Rollout arm (main sweep) ---
            for fraction in ADOPTION_FRACTIONS:
                adopting_count = max(1, int(round(n_sites * fraction)))
                adopting_sites = set(rng.sample(eligible_sites, min(adopting_count, n_sites)))
                for days in ROLLOUT_DAYS:
                    drifted = inject_drift_endpoint(
                        device_obs, adopting_sites, device_type, LEGIT_FQDN,
                        "firmware_update_endpoint", spread_days=days,
                    )
                    scores = DIBScorer(config).score(drifted, trust_observations=clean, target_device_type=device_type)
                    r = _score_of(scores, device_type, LEGIT_FQDN)
                    rollout_rows.append({
                        "device_type": device_type, "n_eligible_sites": n_sites,
                        "adoption_fraction": fraction, "rollout_days": days,
                        "adopting_sites": len(adopting_sites), "accepted": r["accepted"],
                        "score": round(r["score"], 6), "site_confidence": round(r["site_confidence"], 6),
                        "temporal_confidence": round(r["temporal_confidence"], 6), "status": "ok",
                    })

            # --- Time-to-admission arm ---
            rng2 = random.Random(args.seed)
            for fraction in ADOPTION_FRACTIONS:
                adopting_count = max(1, int(round(n_sites * fraction)))
                adopting_sites = set(rng2.sample(eligible_sites, min(adopting_count, n_sites)))
                first_day = ""
                for day in TIME_TO_ADMISSION_CHECKPOINTS:
                    drifted = inject_drift_endpoint(
                        device_obs, adopting_sites, device_type, LEGIT_FQDN,
                        "firmware_update_endpoint", spread_days=day,
                    )
                    scores = DIBScorer(config).score(drifted, trust_observations=clean, target_device_type=device_type)
                    r = _score_of(scores, device_type, LEGIT_FQDN)
                    if r["accepted"]:
                        first_day = day
                        break
                ttfa_rows.append({
                    "device_type": device_type, "adoption_fraction": fraction,
                    "first_admitted_day": first_day,
                    "admitted_within_horizon": bool(first_day),
                    "horizon_days": max(TIME_TO_ADMISSION_CHECKPOINTS),
                })

            # --- Churn arm (fixed representative condition) ---
            adopting_count = max(1, int(round(n_sites * CHURN_FRACTION)))
            adopting_sites = set(random.Random(args.seed).sample(eligible_sites, min(adopting_count, n_sites)))
            before = DIBScorer(config).score(device_obs, trust_observations=clean, target_device_type=device_type)
            before_accepted = {(s.endpoint, s.protocol, s.port) for s in before if s.accepted}
            drifted = inject_drift_endpoint(
                device_obs, adopting_sites, device_type, LEGIT_FQDN,
                "firmware_update_endpoint", spread_days=CHURN_DAYS,
            )
            after = DIBScorer(config).score(drifted, trust_observations=clean, target_device_type=device_type)
            after_accepted = {(s.endpoint, s.protocol, s.port) for s in after if s.accepted and s.endpoint != LEGIT_FQDN}
            added = after_accepted - before_accepted
            removed = before_accepted - after_accepted
            churn_rows.append({
                "device_type": device_type, "adoption_fraction": CHURN_FRACTION, "rollout_days": CHURN_DAYS,
                "pre_existing_accepted_before": len(before_accepted),
                "pre_existing_accepted_after": len(after_accepted),
                "spurious_added": len(added), "spurious_removed": len(removed),
                "spurious_churn_total": len(added) + len(removed),
            })

        # --- Isolated single-site counterfactual (A3 puro), both arms ---
        if n_sites >= 1:
            fixed_site = {eligible_sites[0]}
            for days in ISOLATED_SPREAD_DAYS:
                for arm, fqdn, evidence in (
                    ("legitimate_isolated", LEGIT_FQDN, "firmware_update_endpoint"),
                    ("compromise_isolated", COMPROMISE_FQDN, "compromise_drift_endpoint"),
                ):
                    drifted = inject_drift_endpoint(device_obs, fixed_site, device_type, fqdn, evidence, spread_days=days)
                    scores = DIBScorer(config).score(drifted, trust_observations=clean, target_device_type=device_type)
                    r = _score_of(scores, device_type, fqdn)
                    isolated_rows.append({
                        "device_type": device_type, "arm": arm, "spread_days": days,
                        "n_eligible_sites": n_sites, "accepted": r["accepted"],
                        "score": round(r["score"], 6), "site_confidence": round(r["site_confidence"], 6),
                        "temporal_confidence": round(r["temporal_confidence"], 6),
                    })

        elapsed = time.perf_counter() - started
        print(f"  {device_type}: {len(device_obs)} obs, {n_sites} sites, {elapsed:.1f}s", flush=True)

    write_csv(output / "nonstationarity_rollout.csv", rollout_rows, [
        "device_type", "n_eligible_sites", "adoption_fraction", "rollout_days", "adopting_sites",
        "accepted", "score", "site_confidence", "temporal_confidence", "status",
    ])
    write_csv(output / "nonstationarity_time_to_admission.csv", ttfa_rows, [
        "device_type", "adoption_fraction", "first_admitted_day", "admitted_within_horizon", "horizon_days",
    ])
    write_csv(output / "nonstationarity_churn.csv", churn_rows, [
        "device_type", "adoption_fraction", "rollout_days", "pre_existing_accepted_before",
        "pre_existing_accepted_after", "spurious_added", "spurious_removed", "spurious_churn_total",
    ])
    write_csv(output / "nonstationarity_isolated_counterfactual.csv", isolated_rows, [
        "device_type", "arm", "spread_days", "n_eligible_sites", "accepted", "score",
        "site_confidence", "temporal_confidence",
    ])

    # --- Summaries ---
    pstar_rows = []
    by_device: dict[str, list[dict]] = {}
    for row in rollout_rows:
        by_device.setdefault(row["device_type"], []).append(row)
    for device_type, rows in sorted(by_device.items()):
        at_120 = [r for r in rows if r.get("rollout_days") == 120 and r["accepted"] is True]
        p_star = min((r["adoption_fraction"] for r in at_120), default="")
        never_admits = p_star == ""
        pstar_rows.append({"device_type": device_type, "p_star_at_120d": p_star, "never_admits_within_tested_range": never_admits})
    write_csv(output / "nonstationarity_pstar.csv", pstar_rows, ["device_type", "p_star_at_120d", "never_admits_within_tested_range"])

    admitted_days = [r["first_admitted_day"] for r in ttfa_rows if r["first_admitted_day"] != ""]
    ttfa_summary = []
    if admitted_days:
        admitted_days_sorted = sorted(admitted_days)
        p90_idx = min(len(admitted_days_sorted) - 1, int(round(0.9 * (len(admitted_days_sorted) - 1))))
        ttfa_summary.append({
            "n_cases_admitted_within_horizon": len(admitted_days),
            "n_cases_total": len(ttfa_rows),
            "median_days_to_admission": statistics.median(admitted_days_sorted),
            "p90_days_to_admission": admitted_days_sorted[p90_idx],
        })
    write_csv(output / "nonstationarity_time_to_admission_summary.csv", ttfa_summary, [
        "n_cases_admitted_within_horizon", "n_cases_total", "median_days_to_admission", "p90_days_to_admission",
    ])

    separation_rows = []
    by_key: dict[tuple[str, int], dict[str, dict]] = {}
    for row in isolated_rows:
        by_key.setdefault((row["device_type"], row["spread_days"]), {})[row["arm"]] = row
    for (device_type, days), arms in sorted(by_key.items()):
        legit = arms.get("legitimate_isolated")
        comp = arms.get("compromise_isolated")
        if not legit or not comp:
            continue
        separation_rows.append({
            "device_type": device_type, "spread_days": days,
            "legitimate_accepted": legit["accepted"], "compromise_accepted": comp["accepted"],
            "legitimate_score": legit["score"], "compromise_score": comp["score"],
            "score_gap": round(legit["score"] - comp["score"], 6),
            "separated": legit["accepted"] != comp["accepted"] or abs(legit["score"] - comp["score"]) > 0.05,
        })
    write_csv(output / "nonstationarity_isolated_separation_summary.csv", separation_rows, [
        "device_type", "spread_days", "legitimate_accepted", "compromise_accepted",
        "legitimate_score", "compromise_score", "score_gap", "separated",
    ])

    n_never = sum(1 for r in pstar_rows if r["never_admits_within_tested_range"])
    n_unseparated = sum(1 for r in separation_rows if not r["separated"])
    print(f"\n{n_never}/{len(pstar_rows)} device types never admit the legitimate rollout within tested range.")
    print(f"{n_unseparated}/{len(separation_rows)} (device,spread_days) pairs do NOT separate legitimate from compromise isolated drift.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
