from __future__ import annotations

from datetime import datetime, timezone

from dib.core.models import Observation
from dib.evaluation.baselines import MajorityVotingBaseline
from dib.evaluation.dib import DIBScorer, ScoringConfig
from dib.experiments.firmware import inject_legitimate_endpoint
from dib.experiments.poisoning import (
    inject_adaptive_sybil_endpoint,
    inject_fake_endpoint,
    inject_persistent_fake_endpoint,
    inject_sybil_endpoint,
)
from dib.simulator.sites import partition_observations


def obs(site: str, device: str, fqdn: str, day: int = 1) -> Observation:
    return Observation(
        site_id=site,
        device_id=f"{site}-{device}",
        device_type="camera",
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
        obs("site-a", "cam", "api.vendor.example"),
        obs("site-b", "cam", "api.vendor.example"),
        obs("site-c", "cam", "api.vendor.example"),
        obs("site-a", "cam", "rare.example"),
    ]


def test_dib_scores_cross_site_endpoint_higher_than_local_noise() -> None:
    scores = DIBScorer(ScoringConfig(theta=0.6)).score(sample_observations())
    by_endpoint = {score.endpoint: score for score in scores}
    assert by_endpoint["api.vendor.example"].score > by_endpoint["rare.example"].score
    assert by_endpoint["api.vendor.example"].accepted
    assert not by_endpoint["rare.example"].accepted


def test_majority_baseline_uses_site_agreement() -> None:
    baseline = MajorityVotingBaseline().fit(sample_observations())
    predicted = baseline.predict("camera")
    endpoints = {key[1] for key in predicted}
    assert "api.vendor.example" in endpoints
    assert "rare.example" not in endpoints


def test_partitioning_preserves_observations() -> None:
    observations = sample_observations()
    sites = partition_observations(observations, 2, seed=7)
    redistributed = [item for site in sites for item in site.observations]
    assert sorted(item.endpoint_key for item in redistributed) == sorted(item.endpoint_key for item in observations)


def test_poisoning_and_firmware_injections_are_parameterized() -> None:
    observations = sample_observations()
    poisoned = inject_fake_endpoint(observations, 0.5, seed=1)
    updated = inject_legitimate_endpoint(observations, 0.5, seed=1)
    assert len(poisoned) > len(observations)
    assert len(updated) > len(observations)
    assert any(item.evidence_type == "poisoned_endpoint" for item in poisoned)
    assert any(item.evidence_type == "firmware_update_endpoint" for item in updated)


def test_sybil_injection_adds_one_observation_per_sybil_site() -> None:
    observations = sample_observations()
    poisoned = inject_sybil_endpoint(observations, sybil_site_count=5, target_device_type="camera", seed=3)
    sybil_rows = [item for item in poisoned if item.evidence_type == "poisoned_endpoint_sybil"]
    assert len(sybil_rows) == 5
    assert len({item.site_id for item in sybil_rows}) == 5
    assert all(item.fqdn == "evil-c2.net" for item in sybil_rows)
    assert len(poisoned) == len(observations) + 5


def test_sybil_injection_rejects_unknown_device_type() -> None:
    try:
        inject_sybil_endpoint(sample_observations(), sybil_site_count=1, target_device_type="nonexistent")
    except ValueError:
        return
    raise AssertionError("expected ValueError for unknown device_type")


def test_sybil_site_confidence_grows_with_sybil_count_unlike_real_compromise() -> None:
    """Sybils are not bounded by the real site population, unlike compromising a
    fraction of existing sites: site_confidence for the fake endpoint can be pushed
    arbitrarily close to 1 simply by adding more fake identities."""
    observations = sample_observations()
    low = inject_sybil_endpoint(observations, sybil_site_count=2, target_device_type="camera", seed=1)
    high = inject_sybil_endpoint(observations, sybil_site_count=50, target_device_type="camera", seed=1)
    low_score = next(s for s in DIBScorer().score(low) if s.endpoint == "evil-c2.net")
    high_score = next(s for s in DIBScorer().score(high) if s.endpoint == "evil-c2.net")
    assert high_score.site_confidence > low_score.site_confidence
    assert high_score.site_confidence > 0.9


def test_adaptive_sybil_spreads_observations_across_days() -> None:
    observations = sample_observations()
    poisoned = inject_adaptive_sybil_endpoint(
        observations, sybil_site_count=2, target_device_type="camera", spread_days=4, seed=1
    )
    sybil_rows = [item for item in poisoned if item.evidence_type == "poisoned_endpoint_sybil_adaptive"]
    assert len(sybil_rows) == 2 * 4
    assert len({item.timestamp.date() for item in sybil_rows}) == 4
    assert len({item.site_id for item in sybil_rows}) == 2


def test_adaptive_sybil_raises_temporal_confidence_over_single_shot_sybil() -> None:
    observations = sample_observations()
    single_shot = inject_sybil_endpoint(observations, sybil_site_count=2, target_device_type="camera", seed=1)
    spread = inject_adaptive_sybil_endpoint(
        observations, sybil_site_count=2, target_device_type="camera", spread_days=4, seed=1
    )
    single_score = next(s for s in DIBScorer().score(single_shot) if s.endpoint == "evil-c2.net")
    spread_score = next(s for s in DIBScorer().score(spread) if s.endpoint == "evil-c2.net")
    assert spread_score.temporal_confidence > single_score.temporal_confidence
    assert spread_score.score > single_score.score


def test_adaptive_sybil_rejects_invalid_spread_days() -> None:
    try:
        inject_adaptive_sybil_endpoint(sample_observations(), 1, "camera", spread_days=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError for spread_days < 1")


def test_persistent_fake_endpoint_spreads_each_malicious_sites_observation() -> None:
    observations = sample_observations()
    poisoned = inject_persistent_fake_endpoint(observations, malicious_fraction=1.0, spread_days=3, seed=1)
    fake_rows = [item for item in poisoned if item.evidence_type == "poisoned_endpoint_persistent"]
    # sample_observations() has 3 distinct (site, device_type) pairs, all device_type="camera".
    assert len(fake_rows) == 3 * 3
    assert len({item.timestamp.date() for item in fake_rows}) == 3


def test_persistent_fake_endpoint_raises_temporal_confidence_over_single_shot() -> None:
    observations = sample_observations()
    single_shot = inject_fake_endpoint(observations, malicious_fraction=0.34, seed=1)
    persistent = inject_persistent_fake_endpoint(observations, malicious_fraction=0.34, spread_days=5, seed=1)
    single_score = next(s for s in DIBScorer().score(single_shot) if s.endpoint == "evil-c2.net")
    persistent_score = next(s for s in DIBScorer().score(persistent) if s.endpoint == "evil-c2.net")
    assert persistent_score.temporal_confidence > single_score.temporal_confidence
    assert persistent_score.score > single_score.score


def test_persistent_fake_endpoint_rejects_invalid_spread_days() -> None:
    try:
        inject_persistent_fake_endpoint(sample_observations(), malicious_fraction=0.5, spread_days=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError for spread_days < 1")
