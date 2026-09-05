from __future__ import annotations

from datetime import datetime, timezone

from dib.core.models import Observation
from dib.evaluation.dib import DIBScorer, ScoringConfig
from dib.evaluation.independence import (
    build_site_similarity_graph,
    compute_site_clusters,
    compute_site_endpoint_sets,
    effective_independent_count,
    jaccard_similarity,
)
from dib.experiments.poisoning import inject_sybil_endpoint


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


def diverse_site_observations(site: str, device: str, n_endpoints: int, offset: int = 0) -> list[Observation]:
    """Each site observes a DIFFERENT, idiosyncratic subset of endpoints -- like
    independently-operated real organizations would (different regional clouds etc.)."""
    return [obs(site, device, f"endpoint-{i + offset}.example") for i in range(n_endpoints)]


def test_jaccard_similarity_identical_sets_is_one() -> None:
    a = frozenset({1, 2, 3})
    assert jaccard_similarity(a, a) == 1.0


def test_jaccard_similarity_disjoint_sets_is_zero() -> None:
    assert jaccard_similarity(frozenset({1, 2}), frozenset({3, 4})) == 0.0


def test_jaccard_similarity_empty_sets_is_zero() -> None:
    assert jaccard_similarity(frozenset(), frozenset()) == 0.0


def test_templated_sybils_cluster_together() -> None:
    """Sybils that all corroborate the exact same fabricated endpoint look
    identical to each other and should land in one cluster."""
    observations = [obs(f"sybil-{i}", "camera", "evil.example") for i in range(10)]
    site_endpoints = compute_site_endpoint_sets(observations, "camera")
    graph = build_site_similarity_graph(site_endpoints, similarity_threshold=0.8)
    clusters = compute_site_clusters(graph)
    assert len({clusters[f"sybil-{i}"] for i in range(10)}) == 1


def test_independent_sites_stay_in_separate_clusters() -> None:
    observations = (
        diverse_site_observations("site-a", "camera", 5, offset=0)
        + diverse_site_observations("site-b", "camera", 5, offset=100)
        + diverse_site_observations("site-c", "camera", 5, offset=200)
    )
    site_endpoints = compute_site_endpoint_sets(observations, "camera")
    graph = build_site_similarity_graph(site_endpoints, similarity_threshold=0.8)
    clusters = compute_site_clusters(graph)
    assert len({clusters["site-a"], clusters["site-b"], clusters["site-c"]}) == 3


def test_effective_independent_count_collapses_a_cluster() -> None:
    cluster_by_site = {"sybil-1": 0, "sybil-2": 0, "sybil-3": 0, "site-a": 1}
    assert effective_independent_count({"sybil-1", "sybil-2", "sybil-3"}, cluster_by_site) == 1
    assert effective_independent_count({"sybil-1", "site-a"}, cluster_by_site) == 2


def test_effective_independent_count_handles_unclustered_singleton() -> None:
    assert effective_independent_count({"site-a", "site-b"}, {}) == 2


def test_independence_aware_scoring_suppresses_templated_sybil_flood() -> None:
    base = (
        diverse_site_observations("site-a", "AugustDoorBell", 10, offset=0)
        + diverse_site_observations("site-b", "AugustDoorBell", 10, offset=100)
        + diverse_site_observations("site-c", "AugustDoorBell", 10, offset=200)
    )
    poisoned = inject_sybil_endpoint(base, sybil_site_count=50, target_device_type="AugustDoorBell", seed=1)

    vanilla = DIBScorer(ScoringConfig()).score(poisoned)
    independence_aware = DIBScorer(ScoringConfig(independence_aware=True)).score(poisoned)

    vanilla_fake = next(s for s in vanilla if s.endpoint == "evil-c2.net")
    aware_fake = next(s for s in independence_aware if s.endpoint == "evil-c2.net")
    assert aware_fake.site_confidence < vanilla_fake.site_confidence


def test_independence_aware_scoring_does_not_penalize_genuinely_independent_sites() -> None:
    base = (
        diverse_site_observations("site-a", "AugustDoorBell", 10, offset=0)
        + diverse_site_observations("site-b", "AugustDoorBell", 10, offset=100)
        + diverse_site_observations("site-c", "AugustDoorBell", 10, offset=200)
    )
    vanilla = DIBScorer(ScoringConfig()).score(base)
    aware = DIBScorer(ScoringConfig(independence_aware=True)).score(base)
    vanilla_legit = next(s for s in vanilla if s.endpoint == "endpoint-0.example")
    aware_legit = next(s for s in aware if s.endpoint == "endpoint-0.example")
    assert vanilla_legit.site_confidence == aware_legit.site_confidence


def test_scoring_config_rejects_combining_both_mitigations() -> None:
    try:
        ScoringConfig(trust_weighted=True, independence_aware=True)
    except ValueError:
        return
    raise AssertionError("expected ValueError when combining trust_weighted and independence_aware")


def test_scoring_config_rejects_combined_mitigation_with_others() -> None:
    for kwargs in (
        {"trust_weighted": True, "combined_mitigation": True},
        {"independence_aware": True, "combined_mitigation": True},
    ):
        try:
            ScoringConfig(**kwargs)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {kwargs}")


def test_combined_mitigation_suppresses_templated_sybil_flood_at_least_as_well_as_independence() -> None:
    from dib.evaluation.trust import calibrate_reference_breadth

    base = (
        diverse_site_observations("site-a", "AugustDoorBell", 10, offset=0)
        + diverse_site_observations("site-b", "AugustDoorBell", 10, offset=100)
        + diverse_site_observations("site-c", "AugustDoorBell", 10, offset=200)
    )
    poisoned = inject_sybil_endpoint(base, sybil_site_count=50, target_device_type="AugustDoorBell", seed=1)
    reference = calibrate_reference_breadth(base)

    vanilla = DIBScorer(ScoringConfig()).score(poisoned)
    independence_aware = DIBScorer(ScoringConfig(independence_aware=True)).score(poisoned)
    combined = DIBScorer(
        ScoringConfig(combined_mitigation=True, trust_reference_breadth=reference)
    ).score(poisoned)

    vanilla_fake = next(s for s in vanilla if s.endpoint == "evil-c2.net")
    aware_fake = next(s for s in independence_aware if s.endpoint == "evil-c2.net")
    combined_fake = next(s for s in combined if s.endpoint == "evil-c2.net")
    assert combined_fake.site_confidence < vanilla_fake.site_confidence
    # Templated Sybils have breadth 1 (only the fake endpoint), well below the
    # genuine sites' breadth (10 endpoints each), so their cluster's max trust
    # weight is low -- combined should not score the fake endpoint any higher
    # than independence-aware alone does on this templated-Sybil case.
    assert combined_fake.site_confidence <= aware_fake.site_confidence + 1e-9


def test_combined_mitigation_does_not_penalize_genuinely_independent_sites() -> None:
    from dib.evaluation.trust import calibrate_reference_breadth

    base = (
        diverse_site_observations("site-a", "AugustDoorBell", 10, offset=0)
        + diverse_site_observations("site-b", "AugustDoorBell", 10, offset=100)
        + diverse_site_observations("site-c", "AugustDoorBell", 10, offset=200)
    )
    reference = calibrate_reference_breadth(base)
    vanilla = DIBScorer(ScoringConfig()).score(base)
    combined = DIBScorer(
        ScoringConfig(combined_mitigation=True, trust_reference_breadth=reference)
    ).score(base)
    vanilla_legit = next(s for s in vanilla if s.endpoint == "endpoint-0.example")
    combined_legit = next(s for s in combined if s.endpoint == "endpoint-0.example")
    assert vanilla_legit.site_confidence == combined_legit.site_confidence
