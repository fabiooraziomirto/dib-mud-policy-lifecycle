"""Separate simulated-A1 disclosure for the two f_eff=1 private-IP exclusions."""
from __future__ import annotations

import argparse
import sys
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dib.adapters.unsw_attack_2018 import MaliciousEndpoint
from dib.core.io import filter_observations, read_observations_csv, write_csv
from dib.evaluation.dib import DIBScorer, ScoringConfig
from dib.evaluation.trust import calibrate_reference_breadth
from dib.experiments.compromised_baseline import inject_compromised_baseline
from tnsm_submission_common import write_manifest

DEVICE_TYPES = ("NetatmoWeatherStation", "BlipCareBPMeter")


def fake_endpoint(device_type: str, observations) -> MaliciousEndpoint:
    template = next(obs for obs in observations if obs.device_type == device_type)
    # RFC 5737 TEST-NET avoids collision with a genuine public endpoint.
    suffix = 11 if device_type == "NetatmoWeatherStation" else 12
    return MaliciousEndpoint(device_type, f"203.0.113.{suffix}", "tcp", 4444, template.timestamp + timedelta(days=1), "synthetic_a1_private_ip_exclusion")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observations", default="data/processed/observations_enriched.csv")
    parser.add_argument("--ground-truth-dir", default="data/unsw/profiles/normalized")
    parser.add_argument("--output-dir", default="outputs/tnsm_submission_2026/a1_excluded_devices")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)
    output = ROOT / args.output_dir
    original = read_observations_csv(ROOT / args.observations)
    observations = list(filter_observations(original, exclude_non_global_ips=True))
    # Keep the observed site identities intact.  Repartitioning the remaining
    # traffic into artificial sites would hide the very f_eff=1 limitation this
    # disclosure is meant to make explicit.
    clean = observations
    # Fase 3.1 fix: the README claimed this was "identica a
    # configs/graph_free_selected.yaml", but trust_weighted was never set
    # (defaults to False) -- a real config bug (CHANGES_FROM_DIAGNOSTIC.md,
    # V2), not the config actually used everywhere else for the selected
    # operating point. Fixed to match graph_free_selected.yaml exactly.
    config = ScoringConfig(
        alpha=.6, beta=.4, gamma=0.0, theta=.65, min_reporting_sites=2, graph_enabled=False,
        trust_weighted=True, trust_reference_breadth=calibrate_reference_breadth(clean),
    )
    rows = []
    for device in DEVICE_TYPES:
        device_obs = [obs for obs in clean if obs.device_type == device]
        if not device_obs:
            rows.append({"device_type": device, "status": "excluded_no_observations_after_filter"}); continue
        attack = fake_endpoint(device, device_obs)
        # This disclosure is deliberately separate: f_eff becomes 1 when only one eligible site remains.
        eligible = len({obs.site_id for obs in device_obs})
        benign_by_site: dict[str, set] = {}
        for observation in device_obs:
            benign_by_site.setdefault(observation.site_id, set()).add(observation.endpoint_key)
        for k in range(0, eligible + 1):
            poisoned, _ = inject_compromised_baseline(clean, [attack], device, k, seed=args.seed)
            scores = DIBScorer(config).score(poisoned, target_device_type=device)
            score = next((s for s in scores if s.endpoint == attack.remote_ip and s.protocol == attack.protocol and s.port == attack.port), None)
            imported = {s.endpoint_key for s in scores if s.accepted}
            review = sum(len(profile - imported) for profile in benign_by_site.values()) / len(benign_by_site)
            rows.append({"device_type": device, "status": "simulated_a1_not_aggregate", "k": k, "eligible_sites_after_filter": eligible, "effective_f": round(k / eligible, 6) if eligible else "", "malicious_admission_rate": int(bool(score and score.accepted)), "review_burden": round(review, 6), "score": round(score.score, 6) if score else "", "site_confidence": round(score.site_confidence, 6) if score else "", "temporal_confidence": round(score.temporal_confidence, 6) if score else "", "graph_confidence": round(score.graph_confidence, 6) if score else ""})
    fields = ["device_type", "status", "k", "eligible_sites_after_filter", "effective_f", "malicious_admission_rate", "review_burden", "score", "site_confidence", "temporal_confidence", "graph_confidence"]
    write_csv(output / "a1_excluded_devices.csv", rows, fields)
    write_manifest(output, experiment="a1_private_ip_exclusion_breakdown", config={"alpha": .6, "beta": .4, "gamma": 0, "theta": .65, "graph_enabled": False, "trust_weighted": True}, inputs={"observations": args.observations}, commands=[], metrics={"device_types": list(DEVICE_TYPES), "note": "synthetic A1 disclosure; never aggregate with captured-A1 results"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
