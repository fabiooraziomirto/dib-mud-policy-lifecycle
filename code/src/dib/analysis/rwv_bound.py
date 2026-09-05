"""Exact bounded-poisoning analysis for pure reputation-weighted voting."""
from __future__ import annotations

from dataclasses import dataclass
from collections import defaultdict

from dib.core.models import Observation
from dib.evaluation.trust import ReputationSnapshot


@dataclass(frozen=True, slots=True)
class RWVBound:
    device_type: str
    compromised_sites: int
    weighted_fraction: float
    theta: float | None

    @property
    def margin(self) -> float | None:
        return None if self.theta is None else self.theta - self.weighted_fraction

    @property
    def protected(self) -> bool | None:
        # RWV admits only score > theta, so equality is rejected but is not a
        # positive-margin operating point.
        return None if self.theta is None else self.margin is not None and self.margin > 0.0


def max_weighted_fraction(
    observations: list[Observation], snapshot: ReputationSnapshot, compromised_sites: int
) -> dict[str, float]:
    """Worst-case f_w if the attacker compromises the heaviest sites per device."""
    if compromised_sites < 0:
        raise ValueError("compromised_sites must be non-negative")
    sites_by_device: dict[str, set[str]] = defaultdict(set)
    for observation in observations:
        sites_by_device[observation.device_type].add(observation.site_id)
    fractions: dict[str, float] = {}
    for device_type, sites in sites_by_device.items():
        weights = sorted((snapshot.weight_for(site) for site in sites), reverse=True)
        denominator = sum(weights)
        numerator = sum(weights[:compromised_sites])
        fractions[device_type] = numerator / denominator if denominator else 0.0
    return fractions


def select_declared_theta(
    weighted_fractions: dict[str, float], candidates: list[float]
) -> tuple[float | None, float]:
    """Smallest permitted theta strictly above the worst frozen f_w."""
    worst = max(weighted_fractions.values(), default=0.0)
    return next((theta for theta in sorted(candidates) if theta > worst), None), worst

