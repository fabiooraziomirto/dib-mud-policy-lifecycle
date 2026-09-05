from __future__ import annotations

from datetime import datetime, timezone

from dib.core.models import Observation
from dib.evaluation.independence import (
    build_site_similarity_graph,
    compute_site_clusters,
    compute_site_endpoint_sets,
    jaccard_similarity,
)
from dib.evaluation.trust import calibrate_reference_breadth, compute_site_trust_weights
from dib.experiments.poisoning import inject_overlap_controlled_sybil_endpoint


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


def established_site_observations(site: str, device: str, n_endpoints: int, offset: int = 0) -> list[Observation]:
    return [obs(site, device, f"endpoint-{i + offset}.example") for i in range(n_endpoints)]


def _base(n_per_site: int = 30) -> list[Observation]:
    return (
        established_site_observations("site-a", "AugustDoorBell", n_per_site, offset=0)
        + established_site_observations("site-b", "AugustDoorBell", n_per_site, offset=100)
        + established_site_observations("site-c", "AugustDoorBell", n_per_site, offset=200)
    )


def test_full_sharing_collapses_sybils_into_one_cluster_like_vanilla() -> None:
    base = _base()
    poisoned, achieved = inject_overlap_controlled_sybil_endpoint(
        base,
        sybil_site_count=10,
        target_device_type="AugustDoorBell",
        spread_days=1,
        padding_per_sybil=10,
        shared_fraction=1.0,
        seed=1,
    )
    assert achieved == 10
    site_endpoints = compute_site_endpoint_sets(poisoned, "AugustDoorBell")
    graph = build_site_similarity_graph(site_endpoints, similarity_threshold=0.8)
    clusters = compute_site_clusters(graph)
    sybil_clusters = {clusters[s] for s in site_endpoints if s.startswith("sybil-")}
    assert len(sybil_clusters) == 1


def test_low_shared_fraction_lowers_pairwise_similarity_below_full_sharing() -> None:
    base = _base()

    def mean_pairwise_jaccard(poisoned: list[Observation]) -> float:
        site_endpoints = compute_site_endpoint_sets(poisoned, "AugustDoorBell")
        sybil_sites = sorted(s for s in site_endpoints if s.startswith("sybil-"))
        pairs = [
            jaccard_similarity(site_endpoints[a], site_endpoints[b])
            for i, a in enumerate(sybil_sites)
            for b in sybil_sites[i + 1 :]
        ]
        return sum(pairs) / len(pairs) if pairs else 0.0

    fully_shared, _ = inject_overlap_controlled_sybil_endpoint(
        base, 15, "AugustDoorBell", spread_days=1, padding_per_sybil=20, shared_fraction=1.0, seed=4
    )
    mostly_unique, _ = inject_overlap_controlled_sybil_endpoint(
        base, 15, "AugustDoorBell", spread_days=1, padding_per_sybil=20, shared_fraction=0.1, seed=4
    )
    assert mean_pairwise_jaccard(mostly_unique) < mean_pairwise_jaccard(fully_shared)


def test_padding_pool_is_capped_at_available_real_endpoints() -> None:
    base = _base(n_per_site=5)  # only 15 distinct real endpoints across 3 sites
    _, achieved = inject_overlap_controlled_sybil_endpoint(
        base, 5, "AugustDoorBell", spread_days=1, padding_per_sybil=100, shared_fraction=0.5, seed=2
    )
    assert achieved == 15


def test_padding_raises_sybil_trust_weight_relative_to_unpadded() -> None:
    base = _base()
    reference = calibrate_reference_breadth(base)
    unpadded, _ = inject_overlap_controlled_sybil_endpoint(
        base, 10, "AugustDoorBell", spread_days=1, padding_per_sybil=0, shared_fraction=0.5, seed=5
    )
    padded, _ = inject_overlap_controlled_sybil_endpoint(
        base, 10, "AugustDoorBell", spread_days=1, padding_per_sybil=15, shared_fraction=0.5, seed=5
    )
    unpadded_weights = compute_site_trust_weights(unpadded, reference_breadth=reference)
    padded_weights = compute_site_trust_weights(padded, reference_breadth=reference)
    unpadded_mean = sum(w for s, w in unpadded_weights.items() if s.startswith("sybil-")) / 10
    padded_mean = sum(w for s, w in padded_weights.items() if s.startswith("sybil-")) / 10
    assert padded_mean > unpadded_mean


def test_does_not_fabricate_endpoints_outside_real_observation_set() -> None:
    base = _base()
    real_fqdns = {o.fqdn for o in base}
    poisoned, _ = inject_overlap_controlled_sybil_endpoint(
        base, 5, "AugustDoorBell", spread_days=1, padding_per_sybil=10, shared_fraction=0.3, seed=7
    )
    padding_fqdns = {o.fqdn for o in poisoned if o.evidence_type == "sybil_padding_real_endpoint"}
    assert padding_fqdns <= real_fqdns


def test_rejects_invalid_shared_fraction() -> None:
    base = _base()
    try:
        inject_overlap_controlled_sybil_endpoint(
            base, 1, "AugustDoorBell", spread_days=1, padding_per_sybil=1, shared_fraction=1.5, seed=1
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError for shared_fraction outside [0, 1]")
