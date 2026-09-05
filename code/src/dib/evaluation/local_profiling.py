from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable

from dib.core.io import write_csv, write_json
from dib.core.models import Observation


@dataclass(frozen=True, slots=True)
class EndpointAggregate:
    fqdn: str
    protocol: str
    port: int
    first_seen: datetime
    last_seen: datetime
    count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "fqdn": self.fqdn,
            "protocol": self.protocol,
            "port": self.port,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "count": self.count,
        }


@dataclass(frozen=True, slots=True)
class LocalProfile:
    device_type: str
    site_id: str
    endpoints: list[EndpointAggregate]

    def to_dict(self) -> dict[str, object]:
        return {
            "device_type": self.device_type,
            "site_id": self.site_id,
            "endpoints": [endpoint.to_dict() for endpoint in self.endpoints],
        }


def build_profile(site_id: str, device_type: str, observations: Iterable[Observation]) -> LocalProfile:
    """Aggregate one site's observations for one device type into endpoint counts/seen windows."""
    buckets: dict[tuple[str, str, int], tuple[datetime, datetime, int]] = {}
    for obs in observations:
        endpoint = obs.fqdn or obs.remote_ip
        if endpoint is None:
            continue
        key = (endpoint, obs.protocol, obs.port)
        current = buckets.get(key)
        if current is None:
            buckets[key] = (obs.timestamp, obs.timestamp, 1)
        else:
            buckets[key] = (min(current[0], obs.timestamp), max(current[1], obs.timestamp), current[2] + 1)

    endpoints = [
        EndpointAggregate(
            fqdn=key[0],
            protocol=key[1],
            port=key[2],
            first_seen=aggregate[0],
            last_seen=aggregate[1],
            count=aggregate[2],
        )
        for key, aggregate in sorted(buckets.items())
    ]
    return LocalProfile(device_type=device_type, site_id=site_id, endpoints=endpoints)


def build_all_local_profiles(observations: Iterable[Observation]) -> list[LocalProfile]:
    grouped: dict[tuple[str, str], dict[tuple[str, str, int], tuple[datetime, datetime, int]]] = defaultdict(dict)
    for obs in observations:
        endpoint = obs.fqdn or obs.remote_ip
        if endpoint is None:
            continue
        profile = grouped[(obs.site_id, obs.device_type)]
        endpoint_key = (endpoint, obs.protocol, obs.port)
        current = profile.get(endpoint_key)
        if current is None:
            profile[endpoint_key] = (obs.timestamp, obs.timestamp, 1)
        else:
            profile[endpoint_key] = (
                min(current[0], obs.timestamp),
                max(current[1], obs.timestamp),
                current[2] + 1,
            )
    return [
        LocalProfile(
            device_type=device_type,
            site_id=site_id,
            endpoints=[
                EndpointAggregate(key[0], key[1], key[2], value[0], value[1], value[2])
                for key, value in sorted(items.items())
            ],
        )
        for (site_id, device_type), items in sorted(grouped.items())
    ]


def export_profile(profile: LocalProfile, output_dir: Path) -> Path:
    safe_site = profile.site_id.replace("/", "_")
    safe_device = profile.device_type.replace("/", "_")
    path = output_dir / f"{safe_site}__{safe_device}.json"
    write_json(path, profile.to_dict())
    return path


def export_all_local_profiles(profiles: list[LocalProfile], output_dir: Path) -> None:
    summary_rows = []
    for profile in profiles:
        export_profile(profile, output_dir)
        summary_rows.append(
            {
                "site_id": profile.site_id,
                "device_type": profile.device_type,
                "endpoint_count": len(profile.endpoints),
                "total_observation_count": sum(endpoint.count for endpoint in profile.endpoints),
            }
        )
    write_csv(
        output_dir / "local_profile_summary.csv",
        summary_rows,
        ["site_id", "device_type", "endpoint_count", "total_observation_count"],
    )
