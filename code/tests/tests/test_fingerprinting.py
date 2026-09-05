from __future__ import annotations

from datetime import datetime, timezone

import pytest

from dib.core.models import Observation
from dib.experiments.fingerprinting import FingerprintPerturbationStream


def _observation(site: str, device: str, day: int = 1) -> Observation:
    return Observation(
        site_id=site,
        device_id=f"{site}-{device}",
        device_type=device,
        fqdn="api.example",
        remote_ip=None,
        protocol="tcp",
        port=443,
        timestamp=datetime(2026, 1, day, tzinfo=timezone.utc),
        source_dataset="fixture",
        evidence_type="flow",
    )


def test_fragmentation_is_deterministic_and_site_specific() -> None:
    observations = [_observation("site-a", "camera"), _observation("site-b", "camera")]
    stream = FingerprintPerturbationStream(observations, "fragmentation", 1.0, ["camera", "plug"])

    first = [item.device_type for item in stream]
    second = [item.device_type for item in stream]

    assert first == second
    assert first[0].startswith("camera--fragment-")
    assert first[0] != first[1]


def test_collision_maps_to_another_real_device_type() -> None:
    observations = [_observation("site-a", "camera"), _observation("site-a", "plug")]
    stream = FingerprintPerturbationStream(observations, "collision", 1.0, ["camera", "plug"])

    assert [item.device_type for item in stream] == ["plug", "camera"]


def test_fingerprint_perturbation_validates_arguments() -> None:
    with pytest.raises(ValueError):
        FingerprintPerturbationStream([], "unknown", 0.1, ["camera"])
    with pytest.raises(ValueError):
        FingerprintPerturbationStream([], "collision", 1.1, ["camera"])
