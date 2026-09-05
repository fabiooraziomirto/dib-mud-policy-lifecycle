from __future__ import annotations

import random
from dataclasses import dataclass
from dataclasses import replace
from datetime import datetime
from typing import Iterable

from dib.core.models import Observation


@dataclass(slots=True)
class Site:
    site_id: str
    observations: list[Observation]
    trust_score: float = 1.0


def partition_observations(
    observations: Iterable[Observation],
    site_count: int,
    strategy: str = "device_balanced",
    seed: int = 42,
) -> list[Site]:
    observations = list(observations)
    if site_count <= 0:
        raise ValueError("site_count must be positive")
    if strategy == "existing":
        return _existing_sites(observations)
    if strategy == "random":
        return _random_split(observations, site_count, seed)
    if strategy == "device_balanced":
        return _device_balanced_split(observations, site_count, seed)
    if strategy == "time_window":
        return _time_window_split(observations, site_count)
    raise ValueError(f"unknown partitioning strategy: {strategy}")


def _empty_sites(site_count: int) -> list[Site]:
    return [Site(site_id=f"site-{idx + 1:04d}", observations=[]) for idx in range(site_count)]


def _existing_sites(observations: list[Observation]) -> list[Site]:
    grouped: dict[str, list[Observation]] = {}
    for observation in observations:
        grouped.setdefault(observation.site_id, []).append(observation)
    return [Site(site_id=site_id, observations=items) for site_id, items in sorted(grouped.items())]


def _random_split(observations: list[Observation], site_count: int, seed: int) -> list[Site]:
    rng = random.Random(seed)
    sites = _empty_sites(site_count)
    shuffled = observations[:]
    rng.shuffle(shuffled)
    for index, observation in enumerate(shuffled):
        site = sites[index % site_count]
        site.observations.append(replace(observation, site_id=site.site_id))
    return sites


def _device_balanced_split(observations: list[Observation], site_count: int, seed: int) -> list[Site]:
    rng = random.Random(seed)
    sites = _empty_sites(site_count)
    grouped: dict[str, list[Observation]] = {}
    for observation in observations:
        device_key = observation.device_id or f"{observation.device_type}:{observation.site_id}"
        grouped.setdefault(device_key, []).append(observation)
    groups = list(grouped.values())
    rng.shuffle(groups)
    for index, group in enumerate(groups):
        site = sites[index % site_count]
        site.observations.extend(replace(observation, site_id=site.site_id) for observation in group)
    return sites


def _time_window_split(observations: list[Observation], site_count: int) -> list[Site]:
    sites = _empty_sites(site_count)
    ordered = sorted(observations, key=lambda item: item.timestamp)
    if not ordered:
        return sites
    start = ordered[0].timestamp
    end = ordered[-1].timestamp
    total_seconds = max((end - start).total_seconds(), 1.0)
    for observation in ordered:
        offset = (observation.timestamp - start).total_seconds()
        index = min(int((offset / total_seconds) * site_count), site_count - 1)
        site = sites[index]
        site.observations.append(replace(observation, site_id=site.site_id))
    return sites


def eligible_site_count(sites: Iterable[Site], device_type: str) -> int:
    return sum(1 for site in sites if any(obs.device_type == device_type for obs in site.observations))


def observation_span_days(observations: Iterable[Observation]) -> int:
    timestamps: list[datetime] = [obs.timestamp for obs in observations]
    if not timestamps:
        return 0
    return max((max(timestamps).date() - min(timestamps).date()).days + 1, 1)


def apply_synthetic_site_overlap(
    sites: list[Site],
    overlap: float,
    fanout: int = 1,
    seed: int = 42,
) -> list[Site]:
    """Explicitly-labeled synthetic perturbation applied on top of an already-disjoint
    partition (e.g. the output of partition_observations): duplicates a fraction
    `overlap` of each site's observations, verbatim except for site_id, into `fanout`
    other sites. Models a graded violation of the inter-site independent-noise
    assumption that partition_observations satisfies by construction; used by
    scripts/site_correlation_sensitivity.py to measure how corroboration degrades
    when that assumption is violated. Duplicated rows carry
    evidence_type="synthetic_overlap_duplicate" so they are never mistaken for real,
    independently observed traffic. Does not modify partition_observations or any
    existing strategy; overlap=0.0 is a no-op (equivalent to the input partition).
    """
    if not 0.0 <= overlap <= 1.0:
        raise ValueError("overlap must be in [0, 1]")
    if fanout < 1:
        raise ValueError("fanout must be >= 1")
    ordered = sorted(sites, key=lambda site: site.site_id)
    result = {
        site.site_id: Site(site_id=site.site_id, observations=list(site.observations), trust_score=site.trust_score)
        for site in ordered
    }
    if overlap == 0.0 or len(ordered) < 2:
        return [result[site.site_id] for site in ordered]
    rng = random.Random(seed)
    for site in ordered:
        others = [s.site_id for s in ordered if s.site_id != site.site_id]
        stable_observations = sorted(
            site.observations,
            key=lambda o: (
                o.device_type,
                o.fqdn or "",
                o.remote_ip or "",
                o.protocol,
                o.port,
                o.timestamp.isoformat(),
                o.device_id or "",
            ),
        )
        duplicate_count = round(len(stable_observations) * overlap)
        chosen = rng.sample(stable_observations, duplicate_count) if duplicate_count else []
        for observation in chosen:
            targets = rng.sample(others, min(fanout, len(others)))
            for target_site_id in targets:
                result[target_site_id].observations.append(
                    replace(observation, site_id=target_site_id, evidence_type="synthetic_overlap_duplicate")
                )
    return [result[site.site_id] for site in ordered]
