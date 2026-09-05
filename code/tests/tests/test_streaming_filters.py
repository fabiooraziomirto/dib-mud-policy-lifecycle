from __future__ import annotations

from datetime import datetime, timezone

from dib.core.io import filter_observations
from dib.core.models import Observation


def _observation(fqdn: str | None, remote_ip: str) -> Observation:
    return Observation(
        site_id="site-a",
        device_id="device-a",
        device_type="camera",
        fqdn=fqdn,
        remote_ip=remote_ip,
        protocol="tcp",
        port=443,
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        source_dataset="fixture",
        evidence_type="flow",
    )


def test_non_global_ip_filter_keeps_fqdn_and_global_ip_endpoints() -> None:
    observations = [
        _observation(None, "192.168.1.1"),
        _observation(None, "8.8.8.8"),
        _observation("api.vendor.example", "192.168.1.2"),
    ]
    filtered = filter_observations(observations, exclude_non_global_ips=True)

    assert [item.endpoint_key[1] for item in filtered] == ["8.8.8.8", "api.vendor.example"]
    assert len(list(filtered)) == 2
