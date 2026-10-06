"""A1 resolved-peer counterfactual.

The paper's captured-A1 result (Sec. VI-E) stages none of the 59 real
malicious facts replayed from ``dib.adapters.unsw_attack_2018``, and reads
this as evidence that DIB rejects real attack traffic. It does not: every
one of the 165 captured packets across the 5 covered devices records a raw
destination IP (verified here directly against
``data/unsw_attack_2018/annotations/*.log`` -- column 6 is always
dotted-decimal, never a name), so the class-eligibility gate rejects them for
*format*, not for maliciousness (``vendor-cloud`` requires "any remaining
FQDN"; an IP literal never qualifies). The paper concedes this in one
subordinate clause ("a resolved attacker domain clears it") without ever
measuring it.

This script holds the captured attack pattern fixed -- same device types,
same k-site spread, same protocol/port, same real attack timestamps -- and
varies only whether the peer is expressed as the real IP literal (as
replayed today) or as a resolvable FQDN (the counterfactual arm). This is the
same one-dimension-at-a-time design as
``scripts/service_masquerade_probe.py``: no new packet, no fabricated
malicious behavior, only a relabeling of the peer identity field that
``classify_core`` consumes. It answers the concrete question the paper's own
text raises but never tests: how many of the 59 captured facts would be
staged for review if the same attacker infrastructure had used a resolvable
domain instead of a bare IP -- something a real C2 commonly does.

Uses ``inject_compromised_baseline_persistent`` (the real driver behind
Table I's A1 baseline row and ``experiments/08_table1_baselines``), with a
thin FQDN-substitution wrapper so the injected Observation carries
``fqdn=<resolved>, remote_ip=None`` instead of the real captured IP.

Run from the repository root:  python3 code/scripts/a1_resolvable_counterfactual.py
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dib.adapters.unsw_attack_2018 import MAC_TO_DEVICE, load_malicious_endpoints
from dib.core.io import filter_observations, read_observations_csv, write_csv
from dib.core.models import Observation
from dib.evaluation.dib import DIBScorer, ScoringConfig, admit_auto
from dib.evaluation.trust import calibrate_reference_breadth
from dib.simulator.sites import partition_observations

DEVICE_TYPES = sorted({device_type for device_type, _ip in MAC_TO_DEVICE.values()})
SPREAD_DAYS = (1, 30, 120)
K_VALUES = tuple(range(1, 11))

FIELDS = [
    "device_type", "peer_form", "k", "spread_days", "sites_with_device",
    "endpoint_class", "class_eligible", "score", "theta",
    "site_confidence", "temporal_confidence", "supporting_sites",
    "min_reporting_sites", "accepted", "blocked_by",
]


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def blocked_reason(eligible: bool, supporting: int, quorum: int, score: float, theta: float) -> str:
    reasons = []
    if not eligible:
        reasons.append("eligibility-filter")
    if supporting < quorum:
        reasons.append("quorum")
    if score < theta:
        reasons.append("score")
    return "+".join(reasons) if reasons else "none (admitted)"


def resolved_fqdn_for(device_type: str, remote_ip: str) -> str:
    """Deterministic, distinct-per-endpoint resolvable name. Format only
    (vendor-cloud eligibility requires "any remaining FQDN", no further
    validation) -- chosen to be obviously not a real vendor, matching
    the paper's own naming convention for injected adversarial peers
    (cf. MASQUERADE_ENDPOINT / fake_fqdn in service_masquerade_probe.py,
    poisoning.py's "evil-c2.net").
    """
    slug = remote_ip.replace(".", "-")
    return f"c2-{slug}.evil-vendor.example"


def inject_persistent(
    observations: list[Observation],
    malicious_endpoints,
    device_type: str,
    k: int,
    spread_days: int,
    peer_form: str,
    seed: int,
) -> tuple[list[Observation], list[str]]:
    """Same semantics as
    dib.experiments.compromised_baseline.inject_compromised_baseline_persistent,
    with an added ``peer_form`` in {"ip_literal", "resolved_fqdn"} controlling
    whether the injected peer is the real captured IP (today's paper arm) or
    a resolvable name (the counterfactual arm). Everything else -- device
    selection, site sampling, protocol/port, real attack timestamps,
    replication over spread_days -- is identical to the existing injector.
    """
    import random

    device_endpoints = [e for e in malicious_endpoints if e.device_type == device_type]
    if not device_endpoints:
        raise ValueError(f"no malicious endpoints for device_type={device_type!r}")
    sites_with_device = sorted({o.site_id for o in observations if o.device_type == device_type})
    if k > len(sites_with_device):
        raise ValueError(f"k={k} exceeds the {len(sites_with_device)} sites hosting {device_type!r}")
    device_id_by_site: dict[str, str] = {}
    for obs in observations:
        if obs.device_type == device_type:
            device_id_by_site.setdefault(obs.site_id, obs.device_id or f"{obs.site_id}-{device_type}")

    rng = random.Random(seed)
    compromised_sites = sorted(rng.sample(sites_with_device, k))
    evidence_type = f"a1_resolvable_counterfactual_{peer_form}"

    poisoned = list(observations)
    for site_id in compromised_sites:
        device_id = device_id_by_site[site_id]
        for endpoint in device_endpoints:
            fqdn = None if peer_form == "ip_literal" else resolved_fqdn_for(device_type, endpoint.remote_ip)
            remote_ip = endpoint.remote_ip if peer_form == "ip_literal" else None
            for day in range(spread_days):
                poisoned.append(Observation(
                    site_id=site_id, device_id=device_id, device_type=device_type,
                    fqdn=fqdn, remote_ip=remote_ip, protocol=endpoint.protocol, port=endpoint.port,
                    timestamp=endpoint.timestamp + timedelta(days=day),
                    source_dataset="unsw_attack_2018", evidence_type=evidence_type,
                ))
    return poisoned, compromised_sites


def verify_raw_ip_literal(annotations_dir: Path) -> dict:
    """Sanity check backing the docstring claim: every captured malicious
    endpoint really is a raw IP, in the annotation files as shipped, not an
    artifact of how the adapter parses them."""
    import csv
    total = 0
    ip_literal = 0
    for mac in MAC_TO_DEVICE:
        log_path = annotations_dir / f"{mac}-packet-anomaly.log"
        if not log_path.exists():
            continue
        with log_path.open(newline="", encoding="utf-8") as handle:
            for row in csv.reader(handle):
                if len(row) < 9:
                    continue
                total += 1
                dst_ip = row[5]
                if all(part.isdigit() for part in dst_ip.split(".")) and dst_ip.count(".") == 3:
                    ip_literal += 1
    return {"total_captured_packets": total, "ip_literal_destinations": ip_literal}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observations", default="data/processed/observations_enriched.csv")
    parser.add_argument("--attack-annotations-dir", default="data/unsw_attack_2018/annotations")
    parser.add_argument("--config", default=str(ROOT.parent / "configs" / "graph_free_selected.yaml"))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--site-count", type=int, default=10)
    parser.add_argument("--output-dir", default=str(ROOT.parent / "experiments" / "45_a1_resolvable"))
    args = parser.parse_args(argv)

    started = time.monotonic()
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)

    annotations_dir = ROOT / args.attack_annotations_dir
    format_check = verify_raw_ip_literal(annotations_dir)

    observations_path = ROOT / args.observations
    observations = list(filter_observations(read_observations_csv(observations_path), exclude_non_global_ips=True))
    sites = partition_observations(observations, args.site_count, strategy="random", seed=args.seed)
    partitioned = [obs for site in sites for obs in site.observations]
    del observations, sites

    import yaml
    scoring_yaml = yaml.safe_load((ROOT.parent / "configs" / "graph_free_selected.yaml").read_text())["scoring"] \
        if Path(args.config).name == "graph_free_selected.yaml" else yaml.safe_load(Path(args.config).read_text())["scoring"]
    config = ScoringConfig(
        alpha=float(scoring_yaml["alpha"]), beta=float(scoring_yaml["beta"]), gamma=float(scoring_yaml.get("gamma", 0.0)),
        theta=float(scoring_yaml["theta"]), min_reporting_sites=int(scoring_yaml["min_reporting_sites"]),
        graph_enabled=bool(scoring_yaml.get("graph_enabled", False)),
        trust_weighted=bool(scoring_yaml.get("trust_weighted", False)),
        trust_reference_breadth=calibrate_reference_breadth(partitioned) if scoring_yaml.get("trust_weighted", False) else 0.0,
    )

    malicious_endpoints = load_malicious_endpoints(annotations_dir)

    rows: list[dict[str, object]] = []
    for device_type in DEVICE_TYPES:
        sites_with_device = len({o.site_id for o in partitioned if o.device_type == device_type})
        for peer_form in ("ip_literal", "resolved_fqdn"):
            for k in K_VALUES:
                if k > sites_with_device:
                    continue
                for spread in SPREAD_DAYS:
                    poisoned, _ = inject_persistent(
                        partitioned, malicious_endpoints, device_type, k, spread, peer_form, seed=args.seed,
                    )
                    scores = DIBScorer(config).score(poisoned, target_device_type=device_type)
                    device_endpoints = [e for e in malicious_endpoints if e.device_type == device_type]
                    hits = []
                    for endpoint in device_endpoints:
                        key = resolved_fqdn_for(device_type, endpoint.remote_ip) if peer_form == "resolved_fqdn" else endpoint.remote_ip
                        hits.extend(s for s in scores if s.endpoint.lower() == key.lower() and s.port == endpoint.port)
                    del poisoned, scores
                    if not hits:
                        continue
                    quorum_clearing = [s for s in hits if s.supporting_sites >= config.min_reporting_sites]
                    best = max(quorum_clearing or hits, key=lambda s: s.score)
                    eligible = best.endpoint_class in {"dns", "ntp", "update", "vendor-cloud"}
                    admitted = admit_auto(best.score, config.theta, best.endpoint_class,
                                          supporting_sites=best.supporting_sites,
                                          min_reporting_sites=config.min_reporting_sites)
                    rows.append({
                        "device_type": device_type, "peer_form": peer_form, "k": k, "spread_days": spread,
                        "sites_with_device": sites_with_device,
                        "endpoint_class": best.endpoint_class, "class_eligible": eligible,
                        "score": round(best.score, 6), "theta": config.theta,
                        "site_confidence": round(best.site_confidence, 6),
                        "temporal_confidence": round(best.temporal_confidence, 6),
                        "supporting_sites": best.supporting_sites, "min_reporting_sites": config.min_reporting_sites,
                        "accepted": admitted,
                        "blocked_by": blocked_reason(eligible, best.supporting_sites, config.min_reporting_sites, best.score, config.theta),
                    })
                    write_csv(output / "a1_resolvable_counterfactual.csv", rows, FIELDS)
                    print(f"{device_type} {peer_form} k={k} D={spread}: class={best.endpoint_class} "
                          f"score={best.score:.4f} admitted={admitted}", flush=True)

    ip_rows = [r for r in rows if r["peer_form"] == "ip_literal"]
    fqdn_rows = [r for r in rows if r["peer_form"] == "resolved_fqdn"]
    manifest = {
        "experiment": "a1_resolvable_counterfactual",
        "config": {
            "alpha": config.alpha, "beta": config.beta, "gamma": config.gamma, "theta": config.theta,
            "min_reporting_sites": config.min_reporting_sites, "graph_enabled": config.graph_enabled,
            "trust_weighted": config.trust_weighted,
            "seed": args.seed, "site_count": args.site_count,
            "k_values": list(K_VALUES), "spread_days": list(SPREAD_DAYS),
            "device_types": DEVICE_TYPES,
        },
        "format_check": format_check,
        "inputs": {
            "observations": args.observations, "input_sha256": sha256_of(observations_path),
            "attack_annotations_dir": args.attack_annotations_dir,
        },
        "commands": [["python3", "scripts/a1_resolvable_counterfactual.py"]],
        "metrics": {
            "cells": len(rows),
            "ip_literal_cells": len(ip_rows),
            "ip_literal_admitted": sum(1 for r in ip_rows if r["accepted"]),
            "resolved_fqdn_cells": len(fqdn_rows),
            "resolved_fqdn_admitted": sum(1 for r in fqdn_rows if r["accepted"]),
            "wall_seconds": round(time.monotonic() - started, 1),
        },
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"done: {len(rows)} cells; ip_literal admitted {manifest['metrics']['ip_literal_admitted']}/{len(ip_rows)}; "
        f"resolved_fqdn admitted {manifest['metrics']['resolved_fqdn_admitted']}/{len(fqdn_rows)}; "
        f"{time.monotonic() - started:.1f}s",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
