from __future__ import annotations

from datetime import datetime, timezone

from dib.core.models import Observation
from dib.simulator.sites import apply_synthetic_site_overlap, partition_observations


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


def sample_observations() -> list[Observation]:
    return [
        obs("site-a", "camera", f"a{i}.example", day=1 + (i % 5))
        for i in range(20)
    ] + [
        obs("site-b", "camera", f"b{i}.example", day=1 + (i % 5))
        for i in range(20)
    ]


def test_overlap_zero_is_a_noop() -> None:
    sites = partition_observations(sample_observations(), 4, strategy="random", seed=42)
    unchanged = apply_synthetic_site_overlap(sites, overlap=0.0, seed=42)
    assert [len(site.observations) for site in unchanged] == [len(site.observations) for site in sites]
    assert not any(
        o.evidence_type == "synthetic_overlap_duplicate" for site in unchanged for o in site.observations
    )


def test_full_overlap_with_fanout_one_doubles_observations() -> None:
    sites = partition_observations(sample_observations(), 4, strategy="random", seed=42)
    total_before = sum(len(site.observations) for site in sites)
    overlapped = apply_synthetic_site_overlap(sites, overlap=1.0, fanout=1, seed=42)
    total_after = sum(len(site.observations) for site in overlapped)
    assert total_after == 2 * total_before
    duplicated = sum(
        1 for site in overlapped for o in site.observations if o.evidence_type == "synthetic_overlap_duplicate"
    )
    assert duplicated == total_before


def test_original_observations_remain_at_source_site() -> None:
    sites = partition_observations(sample_observations(), 4, strategy="random", seed=42)
    overlapped = apply_synthetic_site_overlap(sites, overlap=0.5, seed=1)
    by_site = {site.site_id: site for site in sites}
    for result_site in overlapped:
        original_keys = {o.endpoint_key for o in by_site[result_site.site_id].observations}
        result_keys = {o.endpoint_key for o in result_site.observations if o.evidence_type != "synthetic_overlap_duplicate"}
        assert original_keys == result_keys


def test_deterministic_given_seed() -> None:
    sites = partition_observations(sample_observations(), 4, strategy="random", seed=42)
    first = apply_synthetic_site_overlap(sites, overlap=0.4, fanout=1, seed=7)
    second = apply_synthetic_site_overlap(sites, overlap=0.4, fanout=1, seed=7)
    first_counts = sorted((site.site_id, len(site.observations)) for site in first)
    second_counts = sorted((site.site_id, len(site.observations)) for site in second)
    assert first_counts == second_counts


def test_rejects_invalid_overlap() -> None:
    sites = partition_observations(sample_observations(), 4, strategy="random", seed=42)
    try:
        apply_synthetic_site_overlap(sites, overlap=1.5)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for overlap outside [0, 1]")


def test_rejects_invalid_fanout() -> None:
    sites = partition_observations(sample_observations(), 4, strategy="random", seed=42)
    try:
        apply_synthetic_site_overlap(sites, overlap=0.2, fanout=0)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for fanout < 1")
