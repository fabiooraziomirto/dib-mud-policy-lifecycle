"""Task 3: corroboration scoring on the REAL federation, using the SHIPPED
scorer configuration exactly as calibrated on UNSW -- no retuning. If it
transfers badly to real, non-IID organisations, that is the honest result
to report, not something to fix by refitting weights to this data (which
would just move the "calibrated on X, evaluated on X" problem here).

For each of the 10 UNSW-anchored overlap device types (dib.adapters.
real_federation), reports:
  - accepted endpoint count and semantic F1 against UNSW ground truth
    (data/unsw/profiles/normalized/), i.e. does the federation-wide
    corroborated profile still resemble the known-good UNSW profile.
  - exception burden: mean, over the real orgs hosting that device, of that
    org's own local endpoints NOT covered by the federation-accepted policy.
  - fake-endpoint admission: a single fabricated endpoint injected at
    exactly ONE real org (the same "real evidence placement, synthetic
    injection" pattern used throughout this paper), checked against the
    shipped theta. With as few as 2-6 real orgs per device, one compromised
    org is a much larger fraction f of the corroborating population than in
    the 10-way synthetic split -- Proposition 1's bound (alpha*f+beta+gamma)
    predicts a correspondingly higher risk ceiling, which this experiment
    measures directly rather than assumes.

Usage:
    python3 scripts/real_federation_scoring.py
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dib.core.io import filter_observations, read_observations_csv, write_csv
from dib.evaluation.dib import DIBScorer, ScoringConfig, accepted_endpoint_keys
from dib.evaluation.baselines import ReputationWeightedVotingBaseline
from dib.evaluation.profiles import PREDICTED_DIRECTION, canonical_device_name, load_profile_dir, normalize_profile_protocol, semantic_match_metrics
from dib.analysis.poison_bound import evaluate_bound
from dib.evaluation.trust import build_reputation_snapshot


def _load_config(path: str) -> dict:
    text = Path(path).read_text(encoding="utf-8")
    try:
        import yaml

        return yaml.safe_load(text)
    except ImportError:
        return json.loads(text)


def _scoring_config(config_path: str, independence_aware: bool) -> ScoringConfig:
    scoring = _load_config(config_path)["scoring"]
    # trust_weighted deliberately NOT wired here (see plan, D2/#6): it
    # requires a defensible "trusted" reference population, and this
    # federation has no clean/attacked split -- the us/us-vpn and uk/uk-vpn
    # capture-tree pairs would also need collapsing first before any
    # breadth-based trust calibration, or the trust weight silently
    # reproduces the non-independence critique this module exists to
    # answer (see src/dib/adapters/real_federation.py). independence_aware
    # has no such requirement (it clusters by endpoint-set similarity, not
    # breadth), so it's safe to wire directly.
    return ScoringConfig(
        alpha=float(scoring["alpha"]),
        beta=float(scoring["beta"]),
        gamma=float(scoring["gamma"]),
        theta=float(scoring["theta"]),
        # Mandatory, same convention as alpha/beta/gamma/theta above -- this
        # is the exact small-population (2-organization) case the review
        # flagged for the missing corroboration quorum (Sec. IV-B).
        min_reporting_sites=int(scoring["min_reporting_sites"]),
        graph_enabled=bool(scoring.get("graph_enabled", True)),
        graph_max_endpoints_per_device=100,
        independence_aware=independence_aware,
    )

DEVICE_TYPES = (
    "amazon-echo", "belkin-camera", "lifx-bulb", "netatmo-weather", "philips-hue",
    "ring-doorbell", "smartthings", "tp-link-plug", "wemo-motion", "wemo-switch",
)
FAKE_ENDPOINT = "evil-c2.federation-test"

# See src/dib/adapters/real_federation.py's NON_INDEPENDENT_PAIRS / module
# docstring: org_D_moniotr_usvpn is the SAME physical device population as
# org_B_moniotr_us routed a different way, likewise org_E/org_C. Collapsing
# them for TRUST BREADTH CALIBRATION ONLY (not for the actual Cs
# corroboration counting below, which keeps the paper's existing convention
# of treating capture trees as distinct sites) avoids two failure modes: (a)
# a genuinely single deployment's traffic being split into two "sites" each
# looking artificially low-breadth relative to a single-capture org like
# UNSW or YourThings, and (b) the reference-breadth percentile being dragged
# by a duplicated population. This requires no clean/attacked labels -- it's
# a fixed, public fact about the corpus topology, not something the
# adversary controls or that needs an oracle.
_ORG_COLLAPSE_PAIRS = (("org_B_moniotr_us", "org_D_moniotr_usvpn"), ("org_C_moniotr_uk", "org_E_moniotr_ukvpn"))


def _collapse_non_independent_orgs(observations):
    """For TRUST BREADTH CALIBRATION ONLY: each site in a non-independent
    pair sees the UNION of both sites' endpoints when its own breadth is
    computed, so org_B and org_D (same physical population, two capture
    paths) get the same, undiluted breadth instead of each looking like a
    separate half-scale org. Site IDs are left unchanged (unlike a simple
    relabel-to-one-id), so DIBScorer.score()'s sites_by_device/
    sites_by_endpoint -- which still see both org_B and org_D as distinct
    site_ids from device_obs -- both find a trust_weight entry.
    """
    from dataclasses import replace as _replace

    by_site: dict[str, list] = defaultdict(list)
    for obs in observations:
        by_site[obs.site_id].append(obs)
    augmented = list(observations)
    for site_a, site_b in _ORG_COLLAPSE_PAIRS:
        for obs in by_site.get(site_a, []):
            augmented.append(_replace(obs, site_id=site_b))
        for obs in by_site.get(site_b, []):
            augmented.append(_replace(obs, site_id=site_a))
    return augmented


def _canonicalize(policy: set[tuple[str, str, str, int]], device_type: str) -> set[tuple[str, str, str, str, int]]:
    device = canonical_device_name(device_type)
    return {
        (device, PREDICTED_DIRECTION, endpoint.lower(), normalize_profile_protocol(protocol, port), port)
        for _, endpoint, protocol, port in policy
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--federation-observations", default="data/processed/real_federation_observations.csv")
    parser.add_argument("--calibration-observations", default=None,
                        help="Separate pre-attack calibration observations for RWV snapshot.")
    parser.add_argument("--ground-truth-dir", default="data/unsw/profiles/normalized")
    parser.add_argument("--output-dir", default="outputs/real_federation")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--config", default=None, help="Optional YAML with a scoring: block; defaults to the shipped MEAS ScoringConfig() when omitted.")
    parser.add_argument("--independence-aware", action="store_true", default=False)
    parser.add_argument("--trust-weighted", action="store_true", default=False)
    parser.add_argument("--rwv", action="store_true", default=False,
                        help="Run pure frozen-reputation weighted voting instead of DIB scoring.")
    parser.add_argument("--rwv-threshold", type=float, default=0.50,
                        help="Strict RWV threshold (used only with --rwv).")
    parser.add_argument("--exclude-non-global-ips", action=argparse.BooleanOptionalAction, default=True,
                        help="Apply the same post-load filter as runner.py --exclude-non-global-ips.")
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("loading real federation observations ...", flush=True)
    observations = read_observations_csv(Path(args.federation_observations))
    print(f"{len(observations)} observations loaded", flush=True)
    if args.exclude_non_global_ips:
        observations = list(filter_observations(observations, exclude_non_global_ips=True))
        print(f"{len(observations)} observations after exclude_non_global_ips filter", flush=True)

    ground_truth = load_profile_dir(Path(args.ground_truth_dir))
    reputation_snapshot = None
    if args.rwv:
        # Reuse the same non-independent-org correction used for trust
        # calibration, but freeze all reputations before per-device scoring.
        calibration_observations = observations if args.calibration_observations is None else read_observations_csv(Path(args.calibration_observations))
        if args.calibration_observations is not None and args.exclude_non_global_ips:
            calibration_observations = list(filter_observations(calibration_observations, exclude_non_global_ips=True))
        reputation_snapshot = build_reputation_snapshot(
            _collapse_non_independent_orgs(calibration_observations), unknown_site_weight=0.1
        )
    # Shipped alpha/beta/gamma/theta are unmodified -- this is not a retune.
    # graph_max_endpoints_per_device bounds the *computational* cost of the
    # graph term only, same safety cap already used for Mon(IoT)r-scale data
    # elsewhere in this project (CLAUDE.md, scripts/*moniotr*.py): philips-hue
    # alone has 46,952 distinct endpoint keys in this federation (vs. a few
    # hundred to a few thousand for every other device here), because most
    # Mon(IoT)r capture trees resolve philips-hue to a bare IP literal ~1-3%
    # of the time -- build_graph's O(n^2) all-pairs co-occurrence check on
    # that many nodes is what OOM-killed the uncapped first run.
    if args.config is None:
        scoring_config = ScoringConfig(graph_max_endpoints_per_device=100, independence_aware=args.independence_aware)
    else:
        scoring_config = _scoring_config(args.config, args.independence_aware)
    print(f"scoring config (NOT retuned to this data): alpha={scoring_config.alpha} beta={scoring_config.beta} "
          f"gamma={scoring_config.gamma} theta={scoring_config.theta} graph_enabled={scoring_config.graph_enabled} "
          f"independence_aware={scoring_config.independence_aware} trust_weighted={args.trust_weighted}\n", flush=True)

    rows = []
    for device_type in DEVICE_TYPES:
        device_obs = [o for o in observations if o.device_type == device_type]
        orgs = sorted({o.site_id for o in device_obs})
        truth = ground_truth.get(canonical_device_name(device_type), set())

        device_scoring_config = scoring_config
        trust_observations = None
        if args.trust_weighted:
            from dib.evaluation.trust import calibrate_reference_breadth
            from dataclasses import replace as dataclass_replace

            trust_observations = _collapse_non_independent_orgs(device_obs)
            reference_breadth = calibrate_reference_breadth(trust_observations)
            device_scoring_config = dataclass_replace(
                scoring_config, trust_weighted=True, trust_reference_breadth=reference_breadth
            )
            print(f"{device_type}: collapsed-org reference_breadth={reference_breadth}", flush=True)

        # --- Clean federation scoring ---
        # Scored on the FULL federation population (all 10 device types),
        # not device_obs: with graph_enabled, building the co-occurrence
        # graph from one device's own ~hundred-to-thousand nodes instead of
        # the full federation inflates graph_confidence for any endpoint
        # present at every org -- confirmed in A1 (same bug: a real attack
        # endpoint went from Cg=1.0 device-scoped to Cg=0.41, near the
        # whole-corpus median, in the correct scope). graph_max_endpoints_
        # per_device=100 already caps nodes PER DEVICE before the graph is
        # built (see dib.py's score()), so scoring all 10 devices together
        # tops out at <=1000 graph nodes total, not the OOM-prone unbounded
        # union -- the cap was always sufficient for this, device-scoping
        # was unnecessary.
        if args.rwv:
            rwv = ReputationWeightedVotingBaseline(reputation_snapshot, threshold=args.rwv_threshold).fit(device_obs)
            accepted = rwv.predict(device_type)
        else:
            scores = DIBScorer(device_scoring_config).score(
                observations, trust_observations=trust_observations, target_device_type=device_type
            )
            accepted = accepted_endpoint_keys(scores)
        f1 = semantic_match_metrics(_canonicalize(accepted, device_type), truth)["semantic_f1"]

        local_by_org: dict[str, set] = defaultdict(set)
        for obs in device_obs:
            local_by_org[obs.site_id].add(obs.endpoint_key)
        exceptions = [len(local_by_org[org] - accepted) for org in orgs]
        exception_burden = sum(exceptions) / len(exceptions) if exceptions else 0.0

        # --- Fake-endpoint injection at exactly one real org ---
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
        fake_key = (device_type, FAKE_ENDPOINT, "https", 443)
        if args.rwv:
            poisoned_rwv = ReputationWeightedVotingBaseline(reputation_snapshot, threshold=args.rwv_threshold).fit(
                device_obs + [fake_obs]
            )
            fake_score = poisoned_rwv.scores.get(fake_key, 0.0)
            fake_accepted = fake_score > scoring_config.theta
        else:
            poisoned_scores = DIBScorer(device_scoring_config).score(
                observations + [fake_obs], trust_observations=trust_observations, target_device_type=device_type
            )
            fake_score_obj = next((s for s in poisoned_scores if s.endpoint_key == fake_key), None)
            fake_score = fake_score_obj.score if fake_score_obj else 0.0
            fake_accepted = fake_score_obj.accepted if fake_score_obj else False
        f_single_org = 1.0 / len(orgs)
        bound = evaluate_bound(scoring_config.alpha, scoring_config.beta, scoring_config.gamma, scoring_config.theta, f_single_org)
        rwv_weighted_fraction = ""
        rwv_margin = ""
        if args.rwv:
            eligible_weight = sum(reputation_snapshot.weight_for(org) for org in orgs)
            rwv_weighted_fraction = reputation_snapshot.weight_for(injected_org) / eligible_weight if eligible_weight else 0.0
            rwv_margin = scoring_config.theta - rwv_weighted_fraction

        rows.append(
            {
                "device_type": device_type,
                "org_count": len(orgs),
                "orgs": ";".join(orgs),
                "accepted_endpoint_count": len(accepted),
                "semantic_f1_vs_unsw_ground_truth": round(f1, 6),
                "exception_burden_per_org": round(exception_burden, 6),
                "single_org_fraction_f": round(f_single_org, 6),
                "proposition1_bound_at_f": round(bound.theoretical_bound, 6),
                "proposition1_provably_safe": bound.provably_safe,
                "fake_endpoint_score": round(fake_score, 6),
                "fake_endpoint_accepted": fake_accepted,
                "rwv_weighted_fraction": "" if rwv_weighted_fraction == "" else round(rwv_weighted_fraction, 6),
                "rwv_margin": "" if rwv_margin == "" else round(rwv_margin, 6),
            }
        )
        print(f"{device_type:<18} orgs={len(orgs)} accepted={len(accepted):<5} F1={f1:.3f} "
              f"exc/org={exception_burden:.2f} f_single_org={f_single_org:.3f} "
              f"bound={bound.theoretical_bound:.3f} fake_score={fake_score:.3f} "
              f"fake_accepted={fake_accepted}", flush=True)

    fields = [
        "device_type", "org_count", "orgs", "accepted_endpoint_count",
        "semantic_f1_vs_unsw_ground_truth", "exception_burden_per_org",
        "single_org_fraction_f", "proposition1_bound_at_f", "proposition1_provably_safe",
        "fake_endpoint_score", "fake_endpoint_accepted",
        "rwv_weighted_fraction", "rwv_margin",
    ]
    output_name = "real_federation_rwv_scoring.csv" if args.rwv else "real_federation_scoring.csv"
    write_csv(output_dir / output_name, rows, fields)
    print(f"\nwrote {output_dir / output_name}")

    mean_f1 = sum(r["semantic_f1_vs_unsw_ground_truth"] for r in rows) / len(rows)
    mean_exc = sum(r["exception_burden_per_org"] for r in rows) / len(rows)
    any_fake_accepted = any(r["fake_endpoint_accepted"] for r in rows)
    print(f"\nmean semantic F1 across {len(rows)} devices (shipped config, no retune): {mean_f1:.4f}")
    print(f"mean exception burden per org: {mean_exc:.2f}")
    print(f"any single-org fake injection accepted: {any_fake_accepted}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
