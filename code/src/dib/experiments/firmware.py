from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import random

from dib.core.models import Observation


def inject_legitimate_endpoint(
    observations: list[Observation],
    adoption_fraction: float,
    fqdn: str = "new-firmware.vendor.example",
    protocol: str = "https",
    port: int = 443,
    seed: int = 42,
) -> list[Observation]:
    """Model firmware rollout by adding a real-observation-derived endpoint event per adopting site."""

    if not 0.0 <= adoption_fraction <= 1.0:
        raise ValueError("adoption_fraction must be in [0, 1]")
    rng = random.Random(seed)
    sites = sorted({obs.site_id for obs in observations})
    adopting_count = int(round(len(sites) * adoption_fraction))
    adopting_sites = set(rng.sample(sites, adopting_count)) if adopting_count else set()
    updated = list(observations)
    by_site_device: dict[tuple[str, str], Observation] = {}
    for obs in observations:
        by_site_device.setdefault((obs.site_id, obs.device_type), obs)
    for site_id in adopting_sites:
        for (candidate_site, _), template in sorted(by_site_device.items()):
            if candidate_site != site_id:
                continue
            updated.append(
                replace(
                    template,
                    fqdn=fqdn,
                    remote_ip=None,
                    protocol=protocol,
                    port=port,
                    timestamp=template.timestamp + timedelta(days=1),
                    evidence_type="firmware_update_endpoint",
                )
            )
    return updated
