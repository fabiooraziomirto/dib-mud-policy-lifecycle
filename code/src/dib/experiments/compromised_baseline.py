"""A1 ("poisoned local baseline") measurement, closing the one adversary in
the paper's threat model (Sec. Threat Model, dib_TNSM.tex) with no dedicated
experiment: a device already compromised during a site's local learning
window, causing a single-site learner to accept malicious traffic as normal.

Uses REAL captured attack traffic from the UNSW IoT Attack Dataset
(dib.adapters.unsw_attack_2018), injected into k of the 10 simulated sites'
own local observations -- not a synthetic fake endpoint. Only site
assignment (which k of the otherwise-identical sites had their device
compromised) is simulated; the endpoint, protocol, port, and timestamp of
the injected traffic are real.

Deliberately isolated from dib.experiments.management_attack (A2: registry
poisoning / Sybil, synthetic evil-c2.net endpoint). That module and its
Table IV output are untouched by this one. This module reuses the same
baseline/DIB scoring building blocks and a compatible row schema so results
are easy to place next to Table IV, but is its own script/output tree.
"""
from __future__ import annotations

import random
from collections import defaultdict
from dataclasses import dataclass
from dataclasses import replace as dataclass_replace
from datetime import timedelta
from typing import Sequence

from dib.core.models import EndpointScore, Observation
from dib.evaluation.baselines import (
    FrequencyFilteredBaseline,
    MajorityVotingBaseline,
    ReputationWeightedVotingBaseline,
)
from dib.evaluation.dib import DIBScorer, ScoringConfig, accepted_endpoint_keys, admit_auto
from dib.evaluation.profiles import (
    PREDICTED_DIRECTION,
    canonical_device_name,
    normalize_profile_protocol,
    semantic_match_metrics,
)
from dib.evaluation.trust import build_reputation_snapshot, calibrate_reference_breadth
from dib.adapters.unsw_attack_2018 import MaliciousEndpoint

EndpointKey = tuple[str, str, str, int]

STRATEGIES = (
    "local_only",
    "pooled_union",
    "majority_registry",
    "frequency_filtered_registry",
    "reputation_weighted_voting",
    "dib_vanilla",
    "dib_trust_weighted",
    "dib_independence_aware",
)


def inject_compromised_baseline(
    observations: list[Observation],
    malicious_endpoints: list[MaliciousEndpoint],
    device_type: str,
    k: int,
    seed: int = 42,
) -> tuple[list[Observation], list[str]]:
    """A1 injector: real attack endpoints for ``device_type``, added once
    (their own real timestamp, no replication) to the own local observations
    of k of the sites that already host that device type -- simulating that
    device having been compromised during those sites' local learning
    window. Thin wrapper around ``inject_compromised_baseline_persistent``
    with ``spread_days=1``.
    """
    return inject_compromised_baseline_persistent(observations, malicious_endpoints, device_type, k, 1, seed=seed)


def inject_compromised_baseline_persistent(
    observations: list[Observation],
    malicious_endpoints: list[MaliciousEndpoint],
    device_type: str,
    k: int,
    spread_days: int,
    seed: int = 42,
) -> tuple[list[Observation], list[str]]:
    """A1 injector with sustained persistence: the same real attack
    endpoints (identical remote_ip/protocol/port -- not fabricated) are
    repeated across ``spread_days`` distinct days at each of the k
    compromised sites, instead of appearing at their single original
    real timestamp.

    Tests whether a compromise sustained over a longer local-learning
    window (rather than a one-shot injection) raises the malicious
    endpoint's temporal confidence Ct enough to shift DIB's breakpoint k*
    toward the value Proposition 1's worst-case bound predicts --
    mirroring dib.experiments.poisoning.inject_persistent_fake_endpoint's
    "real evidence, simulated persistence" pattern: only the day-to-day
    repetition is a labelled synthetic perturbation
    (evidence_type="compromised_baseline_real_attack_persistent" when
    spread_days>1), the endpoint identity is real captured attack traffic.

    Raises if fewer than k sites host the device type, since silently
    injecting into fewer sites than requested would misreport the malicious
    fraction f=k/site_count the caller intends to test.
    """
    if k < 0:
        raise ValueError("k must be >= 0")
    if spread_days < 1:
        raise ValueError("spread_days must be >= 1")
    device_endpoints = [e for e in malicious_endpoints if e.device_type == device_type]
    if not device_endpoints:
        raise ValueError(f"no malicious endpoints for device_type={device_type!r}")

    sites_with_device = sorted({o.site_id for o in observations if o.device_type == device_type})
    if k > len(sites_with_device):
        raise ValueError(
            f"k={k} exceeds the {len(sites_with_device)} sites that host device_type={device_type!r}"
        )
    device_id_by_site: dict[str, str] = {}
    for obs in observations:
        if obs.device_type == device_type:
            device_id_by_site.setdefault(obs.site_id, obs.device_id or f"{obs.site_id}-{device_type}")

    rng = random.Random(seed)
    compromised_sites = sorted(rng.sample(sites_with_device, k))
    evidence_type = "compromised_baseline_real_attack" if spread_days == 1 else "compromised_baseline_real_attack_persistent"

    poisoned = list(observations)
    for site_id in compromised_sites:
        device_id = device_id_by_site[site_id]
        for endpoint in device_endpoints:
            for day in range(spread_days):
                poisoned.append(
                    Observation(
                        site_id=site_id,
                        device_id=device_id,
                        device_type=device_type,
                        fqdn=None,
                        remote_ip=endpoint.remote_ip,
                        protocol=endpoint.protocol,
                        port=endpoint.port,
                        timestamp=endpoint.timestamp + timedelta(days=day),
                        source_dataset="unsw_attack_2018",
                        evidence_type=evidence_type,
                    )
                )
    return poisoned, compromised_sites


@dataclass(frozen=True, slots=True)
class CompromisedBaselineResult:
    strategy: str
    policy_scope: str
    malicious_admission_rate: float
    benign_exceptions_per_site: float
    benign_f1: float


def _canonicalize(policy: set[EndpointKey], device_type: str) -> set[tuple[str, str, str, str, int]]:
    # 5-field (device, direction, endpoint, protocol, port) tuple for
    # semantic_match_metrics()/endpoint_satisfies_rule() -- PREDICTED_DIRECTION
    # since every observation feeding this policy is device-initiated. See
    # dib.evaluation.profiles.PREDICTED_DIRECTION's docstring.
    device = canonical_device_name(device_type)
    return {
        (device, PREDICTED_DIRECTION, endpoint.lower(), normalize_profile_protocol(protocol, port), port)
        for _, endpoint, protocol, port in policy
    }


def evaluate_compromised_baseline(
    clean_observations: list[Observation],
    malicious_endpoints: list[MaliciousEndpoint],
    device_type: str,
    k: int,
    scoring_config: ScoringConfig,
    ground_truth: dict[str, set[EndpointKey]],
    frequency_min_count: int = 2,
    rwv_threshold: float = 0.65,
    calibration_observations: list[Observation] | None = None,
    seed: int = 42,
    spread_days: int = 1,
    strategies: Sequence[str] | None = None,
) -> list[dict[str, object]]:
    """Evaluate STRATEGIES (or the subset in ``strategies``) for one
    device_type's A1 scenario at a given k (number of the 10 simulated
    sites with a compromised device).

    ``spread_days`` > 1 replicates the real malicious endpoints across that
    many days at each compromised site instead of injecting them once (see
    ``inject_compromised_baseline_persistent``) -- this only changes
    Ct-dependent strategies (the DIB variants); local_only, pooled_union,
    majority_registry, and frequency_filtered_registry admit or reject
    based purely on which sites report an endpoint, not on how many days it
    spans, so their numbers are identical across spread_days for the same
    k. ``strategies`` lets a persistence sweep skip recomputing those
    spread_days-invariant strategies (majority/frequency voting are
    non-trivial fits over a few hundred thousand rows) when only the DIB
    variants are of interest.

    malicious_admission_rate: fraction of the device's real malicious
    endpoint keys present in the policy the strategy ships (per-site mean
    for local_only, since it has no import/aggregation step; a single
    fraction of the one global policy for every other strategy).

    benign_exceptions_per_site: mean, over all sites hosting the device,
    of benign (non-malicious) local endpoints NOT covered by the imported
    global policy -- 0 for local_only, which has nothing to deny since it
    never imports anything from elsewhere.

    benign_f1: semantic F1 of the strategy's shipped policy (as actually
    shipped, including whatever malicious endpoints it admitted) against
    the checked-in UNSW ground-truth profile -- so an admitted malicious
    endpoint costs precision here, not just a separate admission count.
    """
    wanted = set(strategies) if strategies is not None else set(STRATEGIES)
    calibration = calibration_observations if calibration_observations is not None else clean_observations
    poisoned, _compromised_sites = inject_compromised_baseline_persistent(
        clean_observations, malicious_endpoints, device_type, k, spread_days, seed=seed
    )
    device_poisoned = [o for o in poisoned if o.device_type == device_type]
    device_clean = [o for o in clean_observations if o.device_type == device_type]
    all_sites = sorted({o.site_id for o in device_clean})
    if not all_sites:
        raise ValueError(f"no clean observations for device_type={device_type!r}")

    malicious_keys: set[EndpointKey] = {
        (device_type, e.remote_ip, e.protocol, e.port) for e in malicious_endpoints if e.device_type == device_type
    }
    truth = ground_truth.get(canonical_device_name(device_type), set())

    # Benign-only local profile per site (excludes injected malicious
    # observations) -- the reference for benign-exception counting.
    benign_local_profile: dict[str, set[EndpointKey]] = defaultdict(set)
    for obs in device_clean:
        benign_local_profile[obs.site_id].add(obs.endpoint_key)

    # Full (possibly compromised) local profile per site -- what local_only
    # actually ships, since a local-only learner has no way to distinguish
    # injected attack traffic from its own genuine observations.
    full_local_profile: dict[str, set[EndpointKey]] = defaultdict(set)
    for obs in device_poisoned:
        full_local_profile[obs.site_id].add(obs.endpoint_key)

    def _malicious_rate(policy: set[EndpointKey]) -> float:
        return (len(malicious_keys & policy) / len(malicious_keys)) if malicious_keys else 0.0

    results: list[CompromisedBaselineResult] = []

    if "local_only" in wanted:
        # local_only: per-site policy, no import step.
        local_rates = [_malicious_rate(full_local_profile[site]) for site in all_sites]
        local_f1s = [
            semantic_match_metrics(_canonicalize(full_local_profile[site], device_type), truth)["semantic_f1"]
            for site in all_sites
        ]
        results.append(
            CompromisedBaselineResult(
                "local_only",
                "per_real_site_mean",
                sum(local_rates) / len(local_rates),
                0.0,
                sum(local_f1s) / len(local_f1s),
            )
        )

    def _global_result(strategy: str, imported: set[EndpointKey]) -> CompromisedBaselineResult:
        exceptions = [len(benign_local_profile[site] - imported) for site in all_sites]
        f1 = semantic_match_metrics(_canonicalize(imported, device_type), truth)["semantic_f1"]
        return CompromisedBaselineResult(
            strategy,
            "global_registry",
            _malicious_rate(imported),
            sum(exceptions) / len(exceptions),
            f1,
        )

    if "pooled_union" in wanted:
        pooled = {key for site in all_sites for key in full_local_profile[site]}
        results.append(_global_result("pooled_union", pooled))

    if "majority_registry" in wanted:
        majority = MajorityVotingBaseline().fit(device_poisoned).predict(device_type)
        results.append(_global_result("majority_registry", majority))

    if "frequency_filtered_registry" in wanted:
        frequency = FrequencyFilteredBaseline(min_count=frequency_min_count).fit(device_poisoned).predict(device_type)
        results.append(_global_result("frequency_filtered_registry", frequency))

    # RWV shares DIB's governance-derived calibration but freezes it before
    # the injection.  Therefore a newly minted Sybil receives the fixed
    # probation weight rather than a population-derived live estimate.
    if "reputation_weighted_voting" in wanted:
        rwv = ReputationWeightedVotingBaseline(
            build_reputation_snapshot(calibration), threshold=rwv_threshold
        ).fit(device_poisoned)
        results.append(_global_result("reputation_weighted_voting", rwv.predict(device_type)))

    # Trust reference breadth is calibrated on the full clean population (not
    # just this device type), matching dib.experiments.management_attack's
    # convention: breadth is "distinct endpoints a site has ever contributed,
    # across all device types" (trust.py), so restricting it to one device
    # type would understate real sites' trust.
    reference_breadth = calibrate_reference_breadth(calibration)
    dib_configs = {
        "dib_vanilla": scoring_config,
        "dib_trust_weighted": dataclass_replace(
            scoring_config,
            trust_weighted=True,
            independence_aware=False,
            combined_mitigation=False,
            trust_reference_breadth=reference_breadth,
        ),
        "dib_independence_aware": dataclass_replace(
            scoring_config, trust_weighted=False, independence_aware=True, combined_mitigation=False
        ),
    }
    # Scored on the FULL multi-device population (``poisoned``, already the
    # whole corpus the caller passed in as clean_observations plus the
    # injected attack traffic), not device_poisoned, matching
    # dib.experiments.management_attack's convention (Table IV). This was
    # previously device-scoped for cost reasons (~16s/call full-population
    # vs ~1s/call device-scoped) -- but that shrinks the co-occurrence graph
    # to a few hundred nodes instead of several thousand, which measurably
    # inflates graph_confidence for any endpoint present at every site
    # (confirmed: the same real attack endpoint that reaches Cg=1.0 and gets
    # admitted at k=10 in the device-scoped graph gets Cg=0.41 -- near the
    # whole-corpus median -- and score 0.58 < theta in the correct scope).
    # Fixed at the cost of a slower sweep; see scripts/compromised_baseline.py
    # for the runtime this now takes.
    for name, config in dib_configs.items():
        if name not in wanted:
            continue
        scores = DIBScorer(config).score(poisoned, target_device_type=device_type)
        accepted = accepted_endpoint_keys(scores)
        results.append(_global_result(name, accepted))

    return [
        {
            "device_type": device_type,
            "strategy": r.strategy,
            "policy_scope": r.policy_scope,
            "k": k,
            "spread_days": spread_days,
            "site_count": len(all_sites),
            "malicious_endpoint_count": len(malicious_keys),
            "malicious_admission_rate": round(r.malicious_admission_rate, 6),
            "benign_exceptions_per_site": round(r.benign_exceptions_per_site, 6),
            "benign_f1": round(r.benign_f1, 6),
        }
        for r in results
    ]


def dib_scores_at_k(
    clean_observations: list[Observation],
    malicious_endpoints: list[MaliciousEndpoint],
    device_type: str,
    k: int,
    scoring_config: ScoringConfig,
    seed: int = 42,
) -> tuple[list[EndpointScore], set[EndpointKey], dict[str, set[EndpointKey]]]:
    """Score a device's endpoints once at k compromised sites (A1), for
    cheap re-sweeping across many theta values downstream.

    ``EndpointScore.score`` and ``EndpointScore.endpoint_class`` do not
    depend on ``scoring_config.theta`` -- only the ``accepted`` boolean does
    (``dib.evaluation.dib.DIBScorer.score`` computes
    ``accepted = admit_auto(final, self.config.theta, endpoint_class)``,
    i.e. score>=theta AND the typed gate) -- so a caller building an
    admission-rate-vs-exceptions curve across a theta sweep should call this
    once per (device, DIB variant) and re-threshold the returned scores
    locally via ``admit_auto(s.score, theta, s.endpoint_class)`` (see
    ``admission_exception_curve`` below), rather than re-running DIBScorer
    once per theta.

    Prior to Fase 2.3(a)/Fase 3, ``accepted`` WAS exactly ``score>=theta``,
    so re-thresholding via ``s.score >= theta`` alone was equivalent; after
    the typed gate was wired into ``admit_auto()``, doing that silently
    bypasses the gate. Caught in Fase 3 when this curve's theta=0.65 point
    did not match the 30.32->35.52 delta already measured by the Fase 1
    gate-impact diagnostic on the same k=3 scenario -- see
    CHANGES_FROM_DIAGNOSTIC.md.

    Returns (scores, malicious_keys, benign_local_profile_by_site) so a
    caller can compute, for any theta: the imported policy
    (``{s.endpoint_key for s in scores if admit_auto(s.score, theta, s.endpoint_class)}``),
    the malicious admission rate, and benign exceptions per site.
    """
    poisoned, _compromised_sites = inject_compromised_baseline(
        clean_observations, malicious_endpoints, device_type, k, seed=seed
    )
    device_poisoned = [o for o in poisoned if o.device_type == device_type]
    device_clean = [o for o in clean_observations if o.device_type == device_type]
    malicious_keys: set[EndpointKey] = {
        (device_type, e.remote_ip, e.protocol, e.port) for e in malicious_endpoints if e.device_type == device_type
    }
    benign_local_profile: dict[str, set[EndpointKey]] = defaultdict(set)
    for obs in device_clean:
        benign_local_profile[obs.site_id].add(obs.endpoint_key)

    # Scored on the full multi-device population, not device_poisoned -- see
    # the identical fix and rationale in evaluate_compromised_baseline above.
    scores = DIBScorer(scoring_config).score(poisoned, target_device_type=device_type)
    return scores, malicious_keys, dict(benign_local_profile)


def rwv_scores_at_k(
    clean_observations: list[Observation],
    malicious_endpoints: list[MaliciousEndpoint],
    device_type: str,
    k: int,
    seed: int = 42,
    calibration_observations: list[Observation] | None = None,
) -> tuple[dict[EndpointKey, float], set[EndpointKey], dict[str, set[EndpointKey]]]:
    """RWV counterpart to ``dib_scores_at_k`` for threshold sweeps.

    The fixed snapshot is constructed from the clean population before the
    A1 injection; callers can re-threshold the returned exact vote scores.
    """
    poisoned, _ = inject_compromised_baseline(clean_observations, malicious_endpoints, device_type, k, seed=seed)
    device_clean = [o for o in clean_observations if o.device_type == device_type]
    malicious_keys: set[EndpointKey] = {
        (device_type, e.remote_ip, e.protocol, e.port)
        for e in malicious_endpoints
        if e.device_type == device_type
    }
    benign_local_profile: dict[str, set[EndpointKey]] = defaultdict(set)
    for observation in device_clean:
        benign_local_profile[observation.site_id].add(observation.endpoint_key)
    calibration = clean_observations if calibration_observations is None else calibration_observations
    rwv = ReputationWeightedVotingBaseline(build_reputation_snapshot(calibration), threshold=0.0)
    return rwv.score([o for o in poisoned if o.device_type == device_type]), malicious_keys, dict(benign_local_profile)


def rwv_admission_exception_curve(
    scores: dict[EndpointKey, float],
    malicious_keys: set[EndpointKey],
    benign_local_profile: dict[str, set[EndpointKey]],
    thetas: Sequence[float],
) -> list[dict[str, float]]:
    """Re-threshold strict RWV scores without rebuilding site evidence."""
    all_sites = sorted(benign_local_profile)
    rows = []
    for theta in thetas:
        imported = {key for key, score in scores.items() if score > theta}
        admission_rate = len(malicious_keys & imported) / len(malicious_keys) if malicious_keys else 0.0
        exceptions = [len(benign_local_profile[site] - imported) for site in all_sites]
        rows.append({
            "theta": theta,
            "malicious_admission_rate": admission_rate,
            "benign_exceptions_per_site": sum(exceptions) / len(exceptions) if exceptions else 0.0,
        })
    return rows


def admission_exception_curve(
    scores: list[EndpointScore],
    malicious_keys: set[EndpointKey],
    benign_local_profile: dict[str, set[EndpointKey]],
    thetas: Sequence[float],
    min_reporting_sites: int = 1,
) -> list[dict[str, float]]:
    """Re-threshold a ``dib_scores_at_k`` result at each theta in ``thetas``,
    returning malicious_admission_rate and benign_exceptions_per_site per
    theta -- the per-device building block for a DIB admission-vs-exception
    curve at zero additional scorer calls.

    min_reporting_sites must be passed explicitly (matching the
    scoring_config used to produce ``scores`` via dib_scores_at_k) for the
    same reason the typed-class gate had to be wired in here rather than
    re-thresholding via ``s.score >= theta`` alone (see the class docstring
    above and CHANGES_FROM_DIAGNOSTIC.md): admit_auto()'s quorum guard
    (review fix 2026-07-24, |S_e| >= min_reporting_sites) is part of the
    same admission decision and would otherwise be silently bypassed by
    this re-threshold, exactly like the typed gate was before Fase 3.
    """
    all_sites = sorted(benign_local_profile)
    rows = []
    for theta in thetas:
        imported = {
            s.endpoint_key
            for s in scores
            if admit_auto(
                s.score, theta, s.endpoint_class,
                supporting_sites=s.supporting_sites,
                min_reporting_sites=min_reporting_sites,
            )
        }
        admission_rate = (len(malicious_keys & imported) / len(malicious_keys)) if malicious_keys else 0.0
        exceptions = [len(benign_local_profile[site] - imported) for site in all_sites]
        rows.append(
            {
                "theta": theta,
                "malicious_admission_rate": admission_rate,
                "benign_exceptions_per_site": sum(exceptions) / len(exceptions) if exceptions else 0.0,
            }
        )
    return rows
