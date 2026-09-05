from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from dib.core.models import Observation


@dataclass(frozen=True, slots=True)
class ReputationSnapshot:
    """Immutable governance-derived reputation view for one experiment seed.

    The snapshot is deliberately built from a clean/reference observation set
    before attack injection.  Unknown identities receive the consortium's
    fixed probation weight rather than being inferred from the live scoring
    population.
    """

    weights: Mapping[str, float]
    reference_breadth: float
    unknown_site_weight: float = 0.1

    def __post_init__(self) -> None:
        object.__setattr__(self, "weights", MappingProxyType(dict(self.weights)))

    def weight_for(self, site_id: str) -> float:
        return self.weights.get(site_id, self.unknown_site_weight)


def build_reputation_snapshot(
    trusted_observations: list[Observation],
    *,
    unknown_site_weight: float = 0.1,
) -> ReputationSnapshot:
    """Freeze DIB's existing trust calibration for reuse by RWV.

    This intentionally calls the same breadth/reference functions used by
    DIB trust-weighted Cs, but performs the calculation once on the trusted,
    pre-attack population.  Callers must retain the resulting object across
    all poisoned variants of the same seed.
    """
    if not 0.0 < unknown_site_weight <= 1.0:
        raise ValueError("unknown_site_weight must be in (0, 1]")
    reference_breadth = calibrate_reference_breadth(trusted_observations)
    weights = compute_site_trust_weights(
        trusted_observations, reference_breadth=reference_breadth
    )
    return ReputationSnapshot(
        weights=MappingProxyType(dict(weights)),
        reference_breadth=reference_breadth,
        unknown_site_weight=unknown_site_weight,
    )


def compute_site_breadth(observations: list[Observation]) -> dict[str, int]:
    """Number of distinct endpoint keys each site has ever contributed,
    across all device types. A site that exists only to assert one fact
    (e.g. a Sybil identity created solely to corroborate a single poisoned
    endpoint) has breadth 1; an established, independently-operated site
    naturally accumulates breadth from observing a real device fleet.
    """
    endpoints_by_site: dict[str, set[tuple[str, str, str, int]]] = defaultdict(set)
    for obs in observations:
        endpoints_by_site[obs.site_id].add(obs.endpoint_key)
    return {site_id: len(keys) for site_id, keys in endpoints_by_site.items()}


def calibrate_reference_breadth(trusted_observations: list[Observation], percentile: float = 50.0) -> float:
    """Calibrate the trust reference from a presumed-trustworthy observation set
    (e.g. real data captured before any adversarial injection, or a known-clean
    historical baseline).

    This must NOT be computed from the live, possibly-adversarial population being
    scored: a Sybil attacker who outnumbers genuine sites would otherwise drag a
    population-derived percentile down to their own low breadth, defeating the
    defense exactly when it matters most (large-scale Sybil floods).
    """
    breadth = compute_site_breadth(trusted_observations)
    if not breadth:
        return 0.0
    return _percentile(sorted(breadth.values()), percentile)


def compute_site_trust_weights(
    observations: list[Observation],
    reference_breadth: float,
) -> dict[str, float]:
    """Per-site trust weight in (0, 1], derived from observed activity
    breadth rather than any simulation-specific identity flag.

    A site at or above ``reference_breadth`` (calibrated separately via
    ``calibrate_reference_breadth`` on trusted data) gets full trust (1.0).
    Sites below it are scaled down proportionally, so a flood of low-breadth
    identities contributes proportionally little aggregate weight instead of
    one full vote each.
    """
    breadth = compute_site_breadth(observations)
    if not breadth:
        return {}
    if reference_breadth <= 0:
        return {site_id: 1.0 for site_id in breadth}
    return {site_id: min(1.0, count / reference_breadth) for site_id, count in breadth.items()}


def _percentile(sorted_values: list[int], percentile: float) -> float:
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    rank = (percentile / 100.0) * (len(sorted_values) - 1)
    low = int(rank)
    high = min(low + 1, len(sorted_values) - 1)
    fraction = rank - low
    return sorted_values[low] + (sorted_values[high] - sorted_values[low]) * fraction
