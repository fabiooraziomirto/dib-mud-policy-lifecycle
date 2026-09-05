from __future__ import annotations

from abc import ABC, abstractmethod
from collections import Counter, defaultdict
from pathlib import Path

from dib.core.io import write_csv, write_json
from dib.core.models import Observation, endpoint_to_string
from dib.evaluation.trust import ReputationSnapshot


class Baseline(ABC):
    name: str

    @abstractmethod
    def fit(self, observations: list[Observation]) -> "Baseline":
        raise NotImplementedError

    @abstractmethod
    def predict(self, device_type: str) -> set[tuple[str, str, str, int]]:
        raise NotImplementedError

    def export(self, output_dir: Path) -> None:
        rows = []
        for device_type in sorted(self.device_types):
            for key in sorted(self.predict(device_type)):
                rows.append(
                    {
                        "baseline": self.name,
                        "device_type": key[0],
                        "endpoint": key[1],
                        "protocol": key[2],
                        "port": key[3],
                    }
                )
        write_csv(output_dir / f"{self.name}_profile.csv", rows, ["baseline", "device_type", "endpoint", "protocol", "port"])
        write_json(output_dir / f"{self.name}_profile.json", {"baseline": self.name, "endpoints": [endpoint_to_string(row_key(row)) for row in rows]})

    @property
    def device_types(self) -> set[str]:
        return set(getattr(self, "_device_types", set()))


class LocalProfilingBaseline(Baseline):
    name = "local_profiling"

    def fit(self, observations: list[Observation]) -> "LocalProfilingBaseline":
        self._device_types = {obs.device_type for obs in observations}
        grouped: dict[str, Counter[tuple[str, str, str, int]]] = defaultdict(Counter)
        for obs in observations:
            grouped[obs.device_type][obs.endpoint_key] += 1
        self._profiles = {device_type: set(counter) for device_type, counter in grouped.items()}
        return self

    def predict(self, device_type: str) -> set[tuple[str, str, str, int]]:
        return set(self._profiles.get(device_type, set()))


class MajorityVotingBaseline(Baseline):
    name = "majority_voting"

    def fit(self, observations: list[Observation]) -> "MajorityVotingBaseline":
        self._device_types = {obs.device_type for obs in observations}
        sites_by_device: dict[str, set[str]] = defaultdict(set)
        sites_by_endpoint: dict[tuple[str, str, str, int], set[str]] = defaultdict(set)
        for obs in observations:
            sites_by_device[obs.device_type].add(obs.site_id)
            sites_by_endpoint[obs.endpoint_key].add(obs.site_id)
        self._profiles: dict[str, set[tuple[str, str, str, int]]] = defaultdict(set)
        for key, supporting_sites in sites_by_endpoint.items():
            device_type = key[0]
            if len(supporting_sites) / len(sites_by_device[device_type]) >= 0.5:
                self._profiles[device_type].add(key)
        return self

    def predict(self, device_type: str) -> set[tuple[str, str, str, int]]:
        return set(self._profiles.get(device_type, set()))


class WeightedVotingBaseline(Baseline):
    name = "weighted_voting"

    def __init__(self, threshold: float = 0.6) -> None:
        self.threshold = threshold

    def fit(self, observations: list[Observation]) -> "WeightedVotingBaseline":
        self._device_types = {obs.device_type for obs in observations}
        site_weights = _site_weights(observations)
        weights_by_device: dict[str, float] = defaultdict(float)
        weights_by_endpoint: dict[tuple[str, str, str, int], float] = defaultdict(float)
        seen_pairs: set[tuple[str, tuple[str, str, str, int]]] = set()
        sites_by_device: dict[str, set[str]] = defaultdict(set)
        for obs in observations:
            sites_by_device[obs.device_type].add(obs.site_id)
            pair = (obs.site_id, obs.endpoint_key)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            weights_by_endpoint[obs.endpoint_key] += site_weights[obs.site_id]
        for device_type, site_ids in sites_by_device.items():
            weights_by_device[device_type] = sum(site_weights[site_id] for site_id in site_ids)
        self._profiles: dict[str, set[tuple[str, str, str, int]]] = defaultdict(set)
        for key, weight in weights_by_endpoint.items():
            total = weights_by_device[key[0]]
            if total and weight / total >= self.threshold:
                self._profiles[key[0]].add(key)
        return self

    def predict(self, device_type: str) -> set[tuple[str, str, str, int]]:
        return set(self._profiles.get(device_type, set()))


class ReputationWeightedVotingBaseline(Baseline):
    """Pure governance-weighted endpoint voting (RWV).

    Unlike ``WeightedVotingBaseline``, weights are never estimated from the
    population passed to ``fit``.  They are a frozen pre-attack governance
    snapshot, and an identity absent from it receives its fixed probation
    weight.  Scores are retained so theta sweeps do not repeat aggregation.
    """

    name = "reputation_weighted_voting"

    def __init__(
        self,
        reputation: ReputationSnapshot | dict[str, float],
        threshold: float = 0.65,
        unknown_site_weight: float | None = None,
    ) -> None:
        if isinstance(reputation, ReputationSnapshot):
            self._reputation = dict(reputation.weights)
            self.unknown_site_weight = reputation.unknown_site_weight
        else:
            self._reputation = dict(reputation)
            self.unknown_site_weight = 0.1 if unknown_site_weight is None else unknown_site_weight
        if not 0.0 < self.unknown_site_weight <= 1.0:
            raise ValueError("unknown_site_weight must be in (0, 1]")
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("threshold must be in [0, 1]")
        if any(not 0.0 < weight <= 1.0 for weight in self._reputation.values()):
            raise ValueError("all reputation weights must be in (0, 1]")
        self.threshold = threshold

    def score(self, observations: list[Observation]) -> dict[tuple[str, str, str, int], float]:
        self._device_types = {obs.device_type for obs in observations}
        sites_by_device: dict[str, set[str]] = defaultdict(set)
        sites_by_endpoint: dict[tuple[str, str, str, int], set[str]] = defaultdict(set)
        for observation in observations:
            sites_by_device[observation.device_type].add(observation.site_id)
            sites_by_endpoint[observation.endpoint_key].add(observation.site_id)
        scores: dict[tuple[str, str, str, int], float] = {}
        breakdown: dict[tuple[str, str, str, int], dict[str, float]] = {}
        for key, supporting_sites in sites_by_endpoint.items():
            eligible_sites = sites_by_device[key[0]]
            frozen_eligible = sum(self._reputation.get(site_id, 0.0) for site_id in eligible_sites)
            probation_eligible = sum(self.unknown_site_weight for site_id in eligible_sites if site_id not in self._reputation)
            frozen_supporting = sum(self._reputation.get(site_id, 0.0) for site_id in supporting_sites)
            probation_supporting = sum(self.unknown_site_weight for site_id in supporting_sites if site_id not in self._reputation)
            denominator = frozen_eligible + probation_eligible
            numerator = frozen_supporting + probation_supporting
            scores[key] = numerator / denominator if denominator else 0.0
            breakdown[key] = {
                "frozen_numerator": frozen_supporting,
                "probation_numerator": probation_supporting,
                "frozen_denominator": frozen_eligible,
                "probation_denominator": probation_eligible,
                "frozen_only_score": frozen_supporting / frozen_eligible if frozen_eligible else 0.0,
                "probation_mass": probation_eligible / denominator if denominator else 0.0,
            }
        self._scores = scores
        self._breakdown = breakdown
        return dict(scores)

    def fit(self, observations: list[Observation]) -> "ReputationWeightedVotingBaseline":
        self.score(observations)
        self._profiles: dict[str, set[tuple[str, str, str, int]]] = defaultdict(set)
        for key, value in self._scores.items():
            # RWV deliberately uses the paper's strict admission comparator.
            if value > self.threshold:
                self._profiles[key[0]].add(key)
        return self

    def predict(self, device_type: str) -> set[tuple[str, str, str, int]]:
        return set(self._profiles.get(device_type, set()))

    @property
    def scores(self) -> dict[tuple[str, str, str, int], float]:
        if not hasattr(self, "_scores"):
            raise RuntimeError("fit() or score() must be called before accessing RWV scores")
        return dict(self._scores)

    def predict_at(self, threshold: float) -> set[tuple[str, str, str, int]]:
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("threshold must be in [0, 1]")
        return {key for key, score in self.scores.items() if score > threshold}

    @property
    def score_breakdown(self) -> dict[tuple[str, str, str, int], dict[str, float]]:
        if not hasattr(self, "_breakdown"):
            raise RuntimeError("fit() or score() must be called before accessing RWV breakdown")
        return {key: dict(value) for key, value in self._breakdown.items()}

    def _weight(self, site_id: str) -> float:
        return self._reputation.get(site_id, self.unknown_site_weight)


class FrequencyFilteredBaseline(Baseline):
    name = "frequency_filtered"

    def __init__(self, min_count: int = 2) -> None:
        self.min_count = min_count

    def fit(self, observations: list[Observation]) -> "FrequencyFilteredBaseline":
        self._device_types = {obs.device_type for obs in observations}
        counts: Counter[tuple[str, str, str, int]] = Counter(obs.endpoint_key for obs in observations)
        self._profiles: dict[str, set[tuple[str, str, str, int]]] = defaultdict(set)
        for key, count in counts.items():
            if count >= self.min_count:
                self._profiles[key[0]].add(key)
        return self

    def predict(self, device_type: str) -> set[tuple[str, str, str, int]]:
        return set(self._profiles.get(device_type, set()))


def row_key(row: dict[str, object]) -> tuple[str, str, str, int]:
    return (str(row["device_type"]), str(row["endpoint"]), str(row["protocol"]), int(row["port"]))


def _site_weights(observations: list[Observation]) -> dict[str, float]:
    counts: Counter[str] = Counter(obs.site_id for obs in observations)
    max_count = max(counts.values(), default=1)
    return {site_id: count / max_count for site_id, count in counts.items()}
