"""Adversarial service masquerading against the typed eligibility filter.

`intent_overlap.classify_core` assigns the DNS and NTP classes by
**protocol OR port**, with no payload validation:

    if protocol == "dns" or port == 53:  return "dns"
    if protocol == "ntp" or port == 123: return "ntp"

The address-scope veto that precedes them only rejects *non-global* IP
literals. An unresolved but globally-routable IP literal therefore becomes
class-eligible purely by choosing destination port 53 or 123 -- no DNS or NTP
message ever has to be sent. This is the cheapest way across the syntactic
gate, and it is not covered by the resolved-domain Sybil stress test, which
attacks the score rather than the filter.

This probe holds everything else fixed (same injector, same template
observations, same operating point, same seed) and varies only the
destination port, so any difference in admission is attributable to the
classifier alone. Port 443 is the control: identical traffic, ineligible
class.

The endpoint is 192.88.99.11, inside the deprecated 6to4 relay anycast prefix
(RFC 7526). It is globally routable as far as `ipaddress.is_global` is
concerned -- which is what the filter tests -- while not being assigned to any
real host. No packet is sent anywhere: the entire experiment is an offline
transformation of the observation CSV.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import resource
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import yaml

from dib.core.io import filter_observations, read_observations_csv, write_csv
from dib.evaluation.dib import DIBScorer, ScoringConfig
from dib.evaluation.intent_overlap import classify_core
from dib.evaluation.trust import calibrate_reference_breadth
from dib.experiments.poisoning import inject_persistent_fake_endpoint
from dib.simulator.sites import partition_observations

# Deprecated 6to4 anycast prefix (RFC 7526): globally scoped, unassigned.
MASQUERADE_ENDPOINT = "192.88.99.11"

# (label, protocol, port). "dns"/"ntp" are the two port-keyed classes; https is
# the control that only differs in destination port.
PORT_CASES = [
    ("dns-port", "udp", 53),
    ("ntp-port", "udp", 123),
    ("https-control", "https", 443),
]

FIELDS = [
    "case", "protocol", "port", "malicious_fraction", "spread_days",
    "endpoint_class", "class_eligible", "device_type", "supporting_sites", "eligible_sites",
    "site_confidence", "temporal_confidence", "score", "theta", "accepted",
    "blocked_by", "quorum_clearing_instances", "total_instances",
]


def rss_gib() -> float:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1024 * 1024)


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scoring_config(path: Path, observations) -> ScoringConfig:
    config = yaml.safe_load(path.read_text(encoding="utf-8"))["scoring"]
    trust = bool(config.get("trust_weighted", False))
    return ScoringConfig(
        alpha=float(config["alpha"]), beta=float(config["beta"]), gamma=float(config["gamma"]),
        theta=float(config["theta"]), min_reporting_sites=int(config["min_reporting_sites"]),
        graph_enabled=bool(config.get("graph_enabled", True)),
        graph_max_endpoints_per_device=config.get("graph_max_endpoints_per_device"),
        trust_weighted=trust,
        trust_reference_breadth=calibrate_reference_breadth(observations) if trust else 0.0,
    )


def blocked_reason(eligible: bool, supporting: int, quorum: int, score: float, theta: float) -> str:
    """Which admission conjunct fails first, in predicate order (dib.admit_auto)."""
    reasons = []
    if not eligible:
        reasons.append("eligibility-filter")
    if supporting < quorum:
        reasons.append("quorum")
    if score < theta:
        reasons.append("score")
    return "+".join(reasons) if reasons else "none (admitted)"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observations", default="data/processed/observations_enriched.csv")
    parser.add_argument("--config", default=str(ROOT.parent / "configs" / "graph_free_selected.yaml"))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--site-count", type=int, default=10)
    parser.add_argument("--fractions", default="0.3,0.5")
    parser.add_argument("--spread-days", default="1,30,120")
    parser.add_argument("--output-dir", default=str(ROOT.parent / "experiments" / "22_service_masquerade"))
    args = parser.parse_args(argv)

    started = time.monotonic()
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    fractions = [float(x) for x in args.fractions.split(",")]
    spreads = [int(x) for x in args.spread_days.split(",")]

    observations_path = ROOT / args.observations
    observations = list(filter_observations(read_observations_csv(observations_path), exclude_non_global_ips=True))
    sites = partition_observations(observations, args.site_count, strategy="random", seed=args.seed)
    partitioned = [obs for site in sites for obs in site.observations]
    del observations, sites
    config = scoring_config(Path(args.config), partitioned)

    rows: list[dict[str, object]] = []
    for label, protocol, port in PORT_CASES:
        endpoint_class = classify_core(MASQUERADE_ENDPOINT, protocol, port)
        eligible = endpoint_class in {"dns", "ntp", "update", "vendor-cloud"}
        for fraction in fractions:
            for spread in spreads:
                poisoned = inject_persistent_fake_endpoint(
                    partitioned, fraction, spread,
                    fake_fqdn=MASQUERADE_ENDPOINT, protocol=protocol, port=port, seed=args.seed,
                )
                scores = DIBScorer(config).score(poisoned)
                del poisoned
                # Highest-scoring instance of the masqueraded endpoint across
                # device types: the attacker only needs one to be staged.
                hits = [s for s in scores if s.endpoint.lower() == MASQUERADE_ENDPOINT and s.port == port]
                del scores
                if not hits:
                    continue
                # The attacker's best shot is the highest-scoring instance that
                # also clears the corroboration quorum: a higher-scoring
                # instance sitting at a device type only one malicious site
                # hosts can never be staged, so reporting it would understate
                # the attack. Fall back to the global maximum only when no
                # instance clears quorum at all.
                quorum_clearing = [s for s in hits if s.supporting_sites >= config.min_reporting_sites]
                best = max(quorum_clearing or hits, key=lambda s: s.score)
                admitted = bool(eligible and best.supporting_sites >= config.min_reporting_sites and best.score >= config.theta)
                rows.append({
                    "case": label, "protocol": protocol, "port": port,
                    "malicious_fraction": fraction, "spread_days": spread,
                    "endpoint_class": endpoint_class, "class_eligible": eligible,
                    "device_type": best.device_type,
                    "supporting_sites": best.supporting_sites, "eligible_sites": best.eligible_sites,
                    "site_confidence": round(best.site_confidence, 6),
                    "temporal_confidence": round(best.temporal_confidence, 6),
                    "score": round(best.score, 6), "theta": config.theta,
                    "accepted": admitted,
                    "blocked_by": blocked_reason(eligible, best.supporting_sites, config.min_reporting_sites, best.score, config.theta),
                    "quorum_clearing_instances": len(quorum_clearing),
                    "total_instances": len(hits),
                })
                write_csv(output / "service_masquerade.csv", rows, FIELDS)
                print(f"{label} f={fraction} D={spread}: class={endpoint_class} score={best.score:.4f} "
                      f"admitted={admitted} blocked_by={rows[-1]['blocked_by']} rss={rss_gib():.2f}GiB", flush=True)

    manifest = {
        "experiment": "service_masquerade",
        "config": {
            "masquerade_endpoint": MASQUERADE_ENDPOINT,
            "endpoint_rationale": "RFC 7526 deprecated 6to4 anycast prefix: globally scoped for ipaddress.is_global, assigned to no host",
            "port_cases": [list(c) for c in PORT_CASES],
            "malicious_fractions": fractions, "spread_days": spreads,
            "alpha": config.alpha, "beta": config.beta, "gamma": config.gamma,
            "theta": config.theta, "min_reporting_sites": config.min_reporting_sites,
            "trust_weighted": config.trust_weighted,
            "seed": args.seed, "site_count": args.site_count,
            "injector": "dib.experiments.poisoning.inject_persistent_fake_endpoint",
        },
        "inputs": {"observations": args.observations, "input_sha256": sha256_of(observations_path)},
        "commands": [["python3", "scripts/service_masquerade_probe.py"]],
        "metrics": {
            "cells": len(rows),
            "admitted_cells": sum(1 for r in rows if r["accepted"]),
            "class_eligible_cells": sum(1 for r in rows if r["class_eligible"]),
            "wall_seconds": round(time.monotonic() - started, 1),
            "peak_rss_gib": round(rss_gib(), 3),
        },
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"done: {len(rows)} cells, {manifest['metrics']['admitted_cells']} admitted, "
          f"peak RSS {rss_gib():.2f} GiB, {time.monotonic() - started:.1f}s", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
