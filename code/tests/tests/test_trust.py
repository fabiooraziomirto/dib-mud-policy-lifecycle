from __future__ import annotations

from datetime import datetime, timezone

from dib.core.models import Observation
from dib.evaluation.dib import DIBScorer, ScoringConfig
from dib.evaluation.trust import (
    build_reputation_snapshot,
    calibrate_reference_breadth,
    compute_site_breadth,
    compute_site_trust_weights,
)
from dib.evaluation.baselines import ReputationWeightedVotingBaseline
from dib.analysis.rwv_bound import max_weighted_fraction, select_declared_theta
from dib.experiments.poisoning import inject_adaptive_sybil_endpoint, inject_sybil_endpoint


def obs(site: str, device: str, fqdn: str, day: int = 1) -> Observation:
    return Observation(
        site_id=site,
        device_id=f"{site}-{device}",
        device_type=device,
        fqdn=fqdn,
        remote_ip=None,
        protocol="https",
        port=443,
        timestamp=datetime(2026, 1, day, tzinfo=timezone.utc),
        source_dataset="unit_fixture",
        evidence_type="flow",
    )


def established_site_observations(site: str, device: str, n_endpoints: int) -> list[Observation]:
    return [obs(site, device, f"endpoint-{i}.example") for i in range(n_endpoints)]


def test_compute_site_breadth_counts_distinct_endpoint_keys() -> None:
    observations = [
        obs("site-a", "camera", "a.example"),
        obs("site-a", "camera", "b.example"),
        obs("site-a", "camera", "a.example"),  # duplicate, should not double-count
        obs("site-b", "camera", "c.example"),
    ]
    breadth = compute_site_breadth(observations)
    assert breadth["site-a"] == 2
    assert breadth["site-b"] == 1


def test_trust_weight_is_one_at_or_above_median_breadth() -> None:
    observations = (
        established_site_observations("site-a", "camera", 10)
        + established_site_observations("site-b", "camera", 10)
        + established_site_observations("site-c", "camera", 10)
    )
    reference = calibrate_reference_breadth(observations)
    weights = compute_site_trust_weights(observations, reference_breadth=reference)
    assert weights["site-a"] == 1.0
    assert weights["site-b"] == 1.0
    assert weights["site-c"] == 1.0


def test_trust_weight_is_low_for_single_endpoint_sybil_among_established_sites() -> None:
    trusted_baseline = (
        established_site_observations("site-a", "camera", 20)
        + established_site_observations("site-b", "camera", 20)
        + established_site_observations("site-c", "camera", 20)
    )
    reference = calibrate_reference_breadth(trusted_baseline)
    poisoned = trusted_baseline + [obs("sybil-1", "camera", "evil.example")]
    weights = compute_site_trust_weights(poisoned, reference_breadth=reference)
    assert weights["sybil-1"] < 0.2
    assert weights["site-a"] == 1.0


def test_trust_weight_empty_input() -> None:
    assert compute_site_trust_weights([], reference_breadth=10.0) == {}


def test_rwv_snapshot_is_frozen_and_unknown_sites_get_probation_weight() -> None:
    clean = established_site_observations("site-a", "camera", 10) + established_site_observations("site-b", "camera", 10)
    snapshot = build_reputation_snapshot(clean, unknown_site_weight=0.1)
    before = dict(snapshot.weights)
    poisoned = clean + [obs("sybil-1", "camera", "evil.example")]
    rwv = ReputationWeightedVotingBaseline(snapshot, threshold=0.1).fit(poisoned)
    assert snapshot.weights == before
    # Exact pure-vote score: 0.1 / (1 + 1 + 0.1).
    assert rwv.scores[("camera", "evil.example", "https", 443)] == 0.1 / 2.1


def test_rwv_uses_strict_boundary_and_matches_majority_at_unit_weights() -> None:
    rows = [obs("site-a", "camera", "shared.example"), obs("site-b", "camera", "shared.example"), obs("site-c", "camera", "other.example")]
    rwv = ReputationWeightedVotingBaseline({"site-a": 1.0, "site-b": 1.0, "site-c": 1.0}, threshold=2 / 3).fit(rows)
    assert rwv.scores[("camera", "shared.example", "https", 443)] == 2 / 3
    assert rwv.predict("camera") == set()  # score == threshold is rejected.
    assert rwv.predict_at(0.5) == {("camera", "shared.example", "https", 443)}


def test_rwv_declared_threshold_uses_maximum_frozen_weight_share() -> None:
    rows = [obs("heavy", "camera", "a.example"), obs("light-a", "camera", "a.example"), obs("light-b", "camera", "a.example")]
    snapshot = build_reputation_snapshot(rows)
    snapshot = type(snapshot)({"heavy": 1.0, "light-a": 0.1, "light-b": 0.1}, 1.0, 0.1)
    fractions = max_weighted_fraction(rows, snapshot, compromised_sites=1)
    theta, worst = select_declared_theta(fractions, [0.4, 0.5, 0.75])
    assert abs(worst - (1.0 / 1.2)) < 1e-12
    assert theta is None


def test_reference_breadth_is_not_diluted_by_a_sybil_majority() -> None:
    """The defining property this module exists for: calibrating on trusted
    data must not let an attacker who floods many low-breadth Sybils drag the
    bar down to their own level."""
    trusted_baseline = (
        established_site_observations("site-a", "camera", 20)
        + established_site_observations("site-b", "camera", 20)
        + established_site_observations("site-c", "camera", 20)
    )
    reference = calibrate_reference_breadth(trusted_baseline)
    sybil_flood = [obs(f"sybil-{i}", "camera", "evil.example") for i in range(1000)]
    weights = compute_site_trust_weights(trusted_baseline + sybil_flood, reference_breadth=reference)
    assert all(weights[f"sybil-{i}"] < 0.2 for i in range(1000))
    assert weights["site-a"] == 1.0


def test_trust_weighted_scoring_suppresses_single_shot_sybil_more_than_vanilla() -> None:
    base = (
        established_site_observations("site-a", "AugustDoorBell", 20)
        + established_site_observations("site-b", "AugustDoorBell", 20)
        + established_site_observations("site-c", "AugustDoorBell", 20)
    )
    reference = calibrate_reference_breadth(base)
    poisoned = inject_sybil_endpoint(base, sybil_site_count=20, target_device_type="AugustDoorBell", seed=1)

    vanilla = DIBScorer(ScoringConfig()).score(poisoned)
    trusted = DIBScorer(ScoringConfig(trust_weighted=True, trust_reference_breadth=reference)).score(poisoned)

    vanilla_fake = next(s for s in vanilla if s.endpoint == "evil-c2.net")
    trusted_fake = next(s for s in trusted if s.endpoint == "evil-c2.net")
    assert trusted_fake.site_confidence < vanilla_fake.site_confidence
    assert trusted_fake.score < vanilla_fake.score


def test_trust_weighted_scoring_does_not_penalize_legitimate_endpoint() -> None:
    base = (
        established_site_observations("site-a", "AugustDoorBell", 20)
        + established_site_observations("site-b", "AugustDoorBell", 20)
        + established_site_observations("site-c", "AugustDoorBell", 20)
    )
    reference = calibrate_reference_breadth(base)
    vanilla = DIBScorer(ScoringConfig()).score(base)
    trusted = DIBScorer(ScoringConfig(trust_weighted=True, trust_reference_breadth=reference)).score(base)
    vanilla_legit = next(s for s in vanilla if s.endpoint == "endpoint-0.example")
    trusted_legit = next(s for s in trusted if s.endpoint == "endpoint-0.example")
    assert trusted_legit.site_confidence == vanilla_legit.site_confidence == 1.0


def test_device_scoped_scoring_can_use_registry_wide_live_breadth() -> None:
    target = [
        obs("site-a", "camera", "api.example"),
        obs("site-b", "camera", "api.example"),
        obs("sybil-1", "camera", "evil.example"),
    ]
    # Genuine sites have broad histories elsewhere in the live registry; the
    # Sybil contributes only its target-device endpoint.
    registry = target + established_site_observations("site-a", "speaker", 9) + established_site_observations(
        "site-b", "speaker", 9
    )
    config = ScoringConfig(
        graph_enabled=False,
        trust_weighted=True,
        trust_reference_breadth=10,
    )
    target_only = DIBScorer(config).score(target)
    registry_aware = DIBScorer(config).score(target, trust_observations=registry)
    target_only_fake = next(s for s in target_only if s.endpoint == "evil.example")
    registry_aware_fake = next(s for s in registry_aware if s.endpoint == "evil.example")
    assert registry_aware_fake.site_confidence < target_only_fake.site_confidence


def test_trust_weighted_scoring_raises_adaptive_sybil_breakdown_cost() -> None:
    """The adaptive Sybil mimics temporal persistence on ONE endpoint but still has
    breadth 1 (it never touches any other endpoint a real site naturally would),
    so trust weighting should still suppress it relative to vanilla scoring even
    when it has high temporal_confidence."""
    base = (
        established_site_observations("site-a", "AugustDoorBell", 30)
        + established_site_observations("site-b", "AugustDoorBell", 30)
        + established_site_observations("site-c", "AugustDoorBell", 30)
    )
    reference = calibrate_reference_breadth(base)
    poisoned = inject_adaptive_sybil_endpoint(
        base, sybil_site_count=20, target_device_type="AugustDoorBell", spread_days=120, seed=1
    )
    vanilla = DIBScorer(ScoringConfig()).score(poisoned)
    trusted = DIBScorer(ScoringConfig(trust_weighted=True, trust_reference_breadth=reference)).score(poisoned)
    vanilla_fake = next(s for s in vanilla if s.endpoint == "evil-c2.net")
    trusted_fake = next(s for s in trusted if s.endpoint == "evil-c2.net")
    assert trusted_fake.site_confidence < vanilla_fake.site_confidence
