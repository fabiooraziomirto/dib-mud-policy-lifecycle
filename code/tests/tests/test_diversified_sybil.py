from __future__ import annotations

from datetime import datetime, timezone

from dib.core.models import Observation
from dib.evaluation.dib import DIBScorer, ScoringConfig
from dib.evaluation.independence import (
    build_site_similarity_graph,
    compute_site_clusters,
    compute_site_endpoint_sets,
)
from dib.evaluation.trust import calibrate_reference_breadth, compute_site_trust_weights
from dib.experiments.poisoning import inject_diversified_sybil_endpoint, inject_sybil_endpoint


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


def _base(n_per_site: int = 20) -> list[Observation]:
    return (
        established_site_observations("site-a", "AugustDoorBell", n_per_site, offset=0)
        + established_site_observations("site-b", "AugustDoorBell", n_per_site, offset=100)
        + established_site_observations("site-c", "AugustDoorBell", n_per_site, offset=200)
    )


def test_no_padding_matches_templated_sybil_behaviour() -> None:
    base = _base()
    diversified = inject_diversified_sybil_endpoint(
        base, sybil_site_count=10, target_device_type="AugustDoorBell", spread_days=1, padding_per_sybil=0, seed=1
    )
    templated = inject_sybil_endpoint(base, sybil_site_count=10, target_device_type="AugustDoorBell", seed=1)
    diversified_fake_sites = {
        o.site_id for o in diversified if o.fqdn == "evil-c2.net" and o.site_id.startswith("sybil-")
    }
    templated_fake_sites = {
        o.site_id for o in templated if o.fqdn == "evil-c2.net" and o.site_id.startswith("sybil-")
    }
    assert len(diversified_fake_sites) == len(templated_fake_sites) == 10


def test_padding_breaks_the_single_cluster_independence_scoring_relies_on() -> None:
    base = _base(n_per_site=20)
    no_padding = inject_diversified_sybil_endpoint(
        base, sybil_site_count=20, target_device_type="AugustDoorBell", spread_days=1, padding_per_sybil=0, seed=3
    )
    padded = inject_diversified_sybil_endpoint(
        base, sybil_site_count=20, target_device_type="AugustDoorBell", spread_days=1, padding_per_sybil=8, seed=3
    )

    def sybil_cluster_count(observations: list[Observation]) -> int:
        site_endpoints = compute_site_endpoint_sets(observations, "AugustDoorBell")
        graph = build_site_similarity_graph(site_endpoints, similarity_threshold=0.8)
        clusters = compute_site_clusters(graph)
        sybil_clusters = {clusters[s] for s in site_endpoints if s.startswith("sybil-")}
        return len(sybil_clusters)

    # Templated (no padding) Sybils collapse into one cluster regardless of count.
    assert sybil_cluster_count(no_padding) == 1
    # Diversified padding (sampled from the 60 real endpoints across 3 sites)
    # pushes pairwise Jaccard below the 0.8 threshold for at least some pairs,
    # so the Sybils no longer all collapse into a single cluster.
    assert sybil_cluster_count(padded) > 1


def test_padding_raises_sybil_trust_weight() -> None:
    base = _base(n_per_site=20)
    reference = calibrate_reference_breadth(base)
    no_padding = inject_diversified_sybil_endpoint(
        base, sybil_site_count=10, target_device_type="AugustDoorBell", spread_days=1, padding_per_sybil=0, seed=5
    )
    padded = inject_diversified_sybil_endpoint(
        base, sybil_site_count=10, target_device_type="AugustDoorBell", spread_days=1, padding_per_sybil=10, seed=5
    )
    no_padding_weights = compute_site_trust_weights(no_padding, reference_breadth=reference)
    padded_weights = compute_site_trust_weights(padded, reference_breadth=reference)
    no_padding_sybil_mean = sum(
        w for site, w in no_padding_weights.items() if site.startswith("sybil-")
    ) / 10
    padded_sybil_mean = sum(w for site, w in padded_weights.items() if site.startswith("sybil-")) / 10
    # Padding with 10 real endpoints raises each Sybil's breadth from 1 to 11,
    # so its trust weight should rise relative to the unpadded case.
    assert padded_sybil_mean > no_padding_sybil_mean


def test_padding_does_not_fabricate_endpoints_outside_the_real_observation_set() -> None:
    base = _base(n_per_site=20)
    real_fqdns = {o.fqdn for o in base}
    padded = inject_diversified_sybil_endpoint(
        base, sybil_site_count=5, target_device_type="AugustDoorBell", spread_days=1, padding_per_sybil=10, seed=7
    )
    padding_fqdns = {o.fqdn for o in padded if o.evidence_type == "sybil_padding_real_endpoint"}
    assert padding_fqdns <= real_fqdns


def test_zero_padding_is_a_no_op_relative_to_padding_per_sybil_validation() -> None:
    base = _base()
    try:
        inject_diversified_sybil_endpoint(
            base,
            sybil_site_count=1,
            target_device_type="AugustDoorBell",
            spread_days=1,
            padding_per_sybil=-1,
            seed=1,
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError for negative padding_per_sybil")
