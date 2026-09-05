from __future__ import annotations

import hashlib
from collections.abc import Iterable, Iterator
from dataclasses import replace

from dib.core.models import Observation


class FingerprintPerturbationStream:
    """Deterministic, re-iterable view that injects registry-key errors."""

    def __init__(
        self,
        observations: Iterable[Observation],
        scenario: str,
        error_rate: float,
        device_types: Iterable[str],
        seed: int = 42,
    ) -> None:
        if scenario not in {"fragmentation", "collision"}:
            raise ValueError(f"unsupported fingerprint scenario: {scenario}")
        if not 0.0 <= error_rate <= 1.0:
            raise ValueError("error_rate must be in [0, 1]")
        self.observations = observations
        self.scenario = scenario
        self.error_rate = error_rate
        self.seed = seed
        ordered = sorted(set(device_types))
        self.collision_target = {
            device: ordered[(index + 1) % len(ordered)]
            for index, device in enumerate(ordered)
        } if len(ordered) > 1 else {}

    def __iter__(self) -> Iterator[Observation]:
        for observation in self.observations:
            if self.scenario == "fragmentation":
                unit = (
                    self.scenario,
                    observation.site_id,
                    observation.device_type,
                    observation.timestamp.date().isoformat(),
                )
                if _selected(unit, self.error_rate, self.seed):
                    site_suffix = _short_hash(observation.site_id)
                    yield replace(
                        observation,
                        device_type=f"{observation.device_type}--fragment-{site_suffix}",
                    )
                    continue
            else:
                unit = (self.scenario, observation.site_id, observation.device_type)
                if _selected(unit, self.error_rate, self.seed):
                    target = self.collision_target.get(observation.device_type)
                    if target is not None:
                        yield replace(observation, device_type=target)
                        continue
            yield observation


def _selected(parts: tuple[str, ...], rate: float, seed: int) -> bool:
    if rate <= 0.0:
        return False
    if rate >= 1.0:
        return True
    payload = f"{seed}|{'|'.join(parts)}".encode("utf-8")
    value = int.from_bytes(hashlib.blake2b(payload, digest_size=8).digest(), "big")
    return value / 2**64 < rate


def _short_hash(value: str) -> str:
    return hashlib.blake2b(value.encode("utf-8"), digest_size=3).hexdigest()
