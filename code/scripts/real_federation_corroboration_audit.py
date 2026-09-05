"""Diagnostic audit: is DIB's acceptance on the REAL federation (UNSW + 4
Mon(IoT)r capture trees + YourThings, via dib.adapters.real_federation) driven
by genuine cross-org corroboration (Cs, |Se|>=2) or by single-org temporal
persistence (Ct) alone?

Uses the SHIPPED scorer configuration exactly as calibrated on UNSW -- no
retuning, no cherry-picking. Whatever the numbers show is reported as-is,
including if it contradicts the paper's "minority-local behaviour cannot
become consortium policy" claim.

Reuses the same federation observations, device-type list, and fake-endpoint
injection pattern as scripts/real_federation_scoring.py; that script only
emits aggregate per-device rows, this one dumps per-endpoint Cs/Ct/Cg and adds
the |Se|>=2 hard-gate counterfactual.

Usage:
    python3 scripts/real_federation_corroboration_audit.py
"""
from __future__ import annotations

import argparse
import statistics
import sys
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dib.core.io import read_observations_csv, write_csv
from dib.evaluation.dib import DIBScorer, ScoringConfig, accepted_endpoint_keys
from dib.evaluation.profiles import (
    canonical_device_name,
    load_profile_dir,
    normalize_profile_protocol,
    semantic_match_metrics,
)

DEVICE_TYPES = (
    "amazon-echo", "belkin-camera", "lifx-bulb", "netatmo-weather", "philips-hue",
    "ring-doorbell", "smartthings", "tp-link-plug", "wemo-motion", "wemo-switch",
)
FAKE_ENDPOINT = "evil-c2.federation-test"


def _canonicalize(policy: set[tuple[str, str, str, int]], device_type: str) -> set[tuple[str, str, str, int]]:
    device = canonical_device_name(device_type)
    return {
        (device, endpoint.lower(), normalize_profile_protocol(protocol, port), port)
        for _, endpoint, protocol, port in policy
    }


def _stats(values: list[float]) -> dict[str, float]:
    if not values:
        return {"mean": 0.0, "median": 0.0, "min": 0.0, "max": 0.0}
    return {
        "mean": round(statistics.mean(values), 4),
        "median": round(statistics.median(values), 4),
        "min": round(min(values), 4),
        "max": round(max(values), 4),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--federation-observations", default="data/processed/real_federation_observations.csv")
    parser.add_argument("--ground-truth-dir", default="data/unsw/profiles/normalized")
    parser.add_argument("--output-dir", default="outputs/real_federation")
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("loading real federation observations ...", flush=True)
    observations = read_observations_csv(Path(args.federation_observations))
    print(f"{len(observations)} observations loaded\n", flush=True)

    ground_truth = load_profile_dir(Path(args.ground_truth_dir))

    # Shipped config, unmodified. graph_max_endpoints_per_device=100 is the
    # same computational safety cap used in real_federation_scoring.py (OOM
    # guard on philips-hue's ~47k distinct endpoint keys), not a scoring
    # retune -- see that script's docstring.
    scoring_config = ScoringConfig(graph_max_endpoints_per_device=100)
    print(f"shipped config (NOT retuned): alpha={scoring_config.alpha} beta={scoring_config.beta} "
          f"gamma={scoring_config.gamma} theta={scoring_config.theta}\n", flush=True)

    per_endpoint_rows: list[dict[str, object]] = []
    accepted_se_values: list[int] = []
    se1_component_rows: list[tuple[float, float, float]] = []  # (alpha*Cs, beta*Ct, gamma*Cg)

    hard_gate_rows: list[dict[str, object]] = []
    fake_rows: list[dict[str, object]] = []

    for device_type in DEVICE_TYPES:
        device_obs = [o for o in observations if o.device_type == device_type]
        orgs = sorted({o.site_id for o in device_obs})
        truth = ground_truth.get(canonical_device_name(device_type), set())

        scores = DIBScorer(scoring_config).score(device_obs, target_device_type=device_type)

        for s in scores:
            row = {
                "device_type": device_type,
                "endpoint": s.endpoint,
                "protocol": s.protocol,
                "port": s.port,
                "Se": s.supporting_sites,
                "Ed": s.eligible_sites,
                "Cs": round(s.site_confidence, 6),
                "Ct": round(s.temporal_confidence, 6),
                "Cg": round(s.graph_confidence, 6),
                "score": round(s.score, 6),
                "accepted": s.accepted,
            }
            if s.accepted:
                per_endpoint_rows.append(row)
                accepted_se_values.append(s.supporting_sites)
                if s.supporting_sites == 1:
                    se1_component_rows.append(
                        (scoring_config.alpha * s.site_confidence,
                         scoring_config.beta * s.temporal_confidence,
                         scoring_config.gamma * s.graph_confidence)
                    )

        # --- Counterfactual: hard |Se|>=2 gate on top of the shipped theta ---
        hard_accepted = {s.endpoint_key for s in scores if s.accepted and s.supporting_sites >= 2}
        f1_hard = semantic_match_metrics(_canonicalize(hard_accepted, device_type), truth)["semantic_f1"]
        soft_accepted = accepted_endpoint_keys(scores)
        f1_soft = semantic_match_metrics(_canonicalize(soft_accepted, device_type), truth)["semantic_f1"]
        hard_gate_rows.append({
            "device_type": device_type,
            "org_count": len(orgs),
            "accepted_shipped": len(soft_accepted),
            "accepted_Se_ge_2_gate": len(hard_accepted),
            "semantic_f1_shipped": round(f1_soft, 6),
            "semantic_f1_Se_ge_2_gate": round(f1_hard, 6),
        })

        # --- Fake endpoint injection at exactly one real org, component breakdown ---
        template = device_obs[0]
        injected_org = orgs[0]
        fake_obs = replace(
            template,
            site_id=injected_org,
            fqdn=FAKE_ENDPOINT,
            remote_ip=None,
            protocol="https",
            port=443,
            timestamp=template.timestamp + timedelta(seconds=1),
            evidence_type="real_federation_fake_injection_test",
        )
        poisoned_scores = DIBScorer(scoring_config).score(device_obs + [fake_obs], target_device_type=device_type)
        fake_key = (device_type, FAKE_ENDPOINT, "https", 443)
        fake = next((s for s in poisoned_scores if s.endpoint_key == fake_key), None)
        if fake is not None:
            fake_rows.append({
                "device_type": device_type,
                "org_count": len(orgs),
                "Se": fake.supporting_sites,
                "Ed": fake.eligible_sites,
                "Cs": round(fake.site_confidence, 6),
                "Ct": round(fake.temporal_confidence, 6),
                "Cg": round(fake.graph_confidence, 6),
                "alpha_Cs": round(scoring_config.alpha * fake.site_confidence, 6),
                "beta_Ct": round(scoring_config.beta * fake.temporal_confidence, 6),
                "gamma_Cg": round(scoring_config.gamma * fake.graph_confidence, 6),
                "score": round(fake.score, 6),
                "accepted": fake.accepted,
            })

    # --- Write per-endpoint accepted CSV ---
    fields = ["device_type", "endpoint", "protocol", "port", "Se", "Ed", "Cs", "Ct", "Cg", "score", "accepted"]
    write_csv(output_dir / "corroboration_audit_accepted_endpoints.csv", per_endpoint_rows, fields)
    print(f"wrote {output_dir / 'corroboration_audit_accepted_endpoints.csv'} ({len(per_endpoint_rows)} accepted endpoints)\n")

    # --- Histogram of Se among accepted ---
    n = len(accepted_se_values)
    se1 = sum(1 for v in accepted_se_values if v == 1)
    se_ge2 = sum(1 for v in accepted_se_values if v >= 2)
    print("=== 2. Histogram of |Se| among ACCEPTED endpoints (all 10 devices pooled) ===")
    from collections import Counter
    hist = Counter(accepted_se_values)
    for se_val in sorted(hist):
        print(f"  |Se|={se_val}: {hist[se_val]:>5}  ({hist[se_val]/n*100:.1f}%)")
    print(f"  TOTAL accepted: {n}")
    print(f"  frazione |Se|=1 (NESSUNA corroborazione cross-org): {se1}/{n} = {se1/n*100:.1f}%")
    print(f"  frazione |Se|>=2 (corroborazione genuina):          {se_ge2}/{n} = {se_ge2/n*100:.1f}%\n")

    # --- Decomposition for |Se|=1 accepted endpoints ---
    print("=== 3. Score decomposition for |Se|=1 accepted endpoints (alpha*Cs vs beta*Ct vs gamma*Cg) ===")
    if se1_component_rows:
        alpha_cs = [r[0] for r in se1_component_rows]
        beta_ct = [r[1] for r in se1_component_rows]
        gamma_cg = [r[2] for r in se1_component_rows]
        totals = [sum(r) for r in se1_component_rows]
        print(f"  n = {len(se1_component_rows)}")
        print(f"  alpha*Cs : {_stats(alpha_cs)}")
        print(f"  beta*Ct  : {_stats(beta_ct)}")
        print(f"  gamma*Cg : {_stats(gamma_cg)}")
        mean_total = statistics.mean(totals)
        print(f"  mean total score = {mean_total:.4f}")
        print(f"  mean share of score from alpha*Cs : {statistics.mean(alpha_cs)/mean_total*100:.1f}%")
        print(f"  mean share of score from beta*Ct  : {statistics.mean(beta_ct)/mean_total*100:.1f}%")
        print(f"  mean share of score from gamma*Cg : {statistics.mean(gamma_cg)/mean_total*100:.1f}%\n")
    else:
        print("  (no |Se|=1 accepted endpoints found)\n")

    # --- Counterfactual: hard Se>=2 gate ---
    print("=== 4. Counterfactual: hard |Se|>=2 gate on top of shipped theta ===")
    fields_hg = ["device_type", "org_count", "accepted_shipped", "accepted_Se_ge_2_gate",
                 "semantic_f1_shipped", "semantic_f1_Se_ge_2_gate"]
    write_csv(output_dir / "corroboration_audit_hard_gate.csv", hard_gate_rows, fields_hg)
    for r in hard_gate_rows:
        print(f"  {r['device_type']:<18} orgs={r['org_count']} accepted_shipped={r['accepted_shipped']:<6} "
              f"accepted_Se>=2={r['accepted_Se_ge_2_gate']:<6} F1_shipped={r['semantic_f1_shipped']:.3f} "
              f"F1_Se>=2={r['semantic_f1_Se_ge_2_gate']:.3f}")
    total_shipped = sum(r["accepted_shipped"] for r in hard_gate_rows)
    total_hard = sum(r["accepted_Se_ge_2_gate"] for r in hard_gate_rows)
    mean_f1_shipped = statistics.mean(r["semantic_f1_shipped"] for r in hard_gate_rows)
    mean_f1_hard = statistics.mean(r["semantic_f1_Se_ge_2_gate"] for r in hard_gate_rows)
    print(f"\n  TOTAL accepted shipped: {total_shipped}, TOTAL accepted under Se>=2 gate: {total_hard} "
          f"({total_hard/total_shipped*100 if total_shipped else 0:.1f}% survive)")
    print(f"  mean F1 shipped: {mean_f1_shipped:.4f}  mean F1 under Se>=2 gate: {mean_f1_hard:.4f}\n")

    # --- Fake endpoint decomposition ---
    print("=== 5. Fake endpoint (single-org injection) component breakdown ===")
    fields_fake = ["device_type", "org_count", "Se", "Ed", "Cs", "Ct", "Cg",
                   "alpha_Cs", "beta_Ct", "gamma_Cg", "score", "accepted"]
    write_csv(output_dir / "corroboration_audit_fake_endpoint.csv", fake_rows, fields_fake)
    for r in fake_rows:
        dominant = max(("alpha_Cs", "beta_Ct", "gamma_Cg"), key=lambda k: r[k])
        print(f"  {r['device_type']:<18} orgs={r['org_count']} Se={r['Se']} Ed={r['Ed']} "
              f"Cs={r['Cs']:.3f} Ct={r['Ct']:.3f} Cg={r['Cg']:.3f} "
              f"alpha*Cs={r['alpha_Cs']:.3f} beta*Ct={r['beta_Ct']:.3f} gamma*Cg={r['gamma_Cg']:.3f} "
              f"score={r['score']:.3f} accepted={r['accepted']} dominant_term={dominant}")

    print(f"\nwrote {output_dir / 'corroboration_audit_hard_gate.csv'}")
    print(f"wrote {output_dir / 'corroboration_audit_fake_endpoint.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
