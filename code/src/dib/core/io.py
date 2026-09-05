from __future__ import annotations

import csv
import ipaddress
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Iterable

from dib.core.models import Observation, REQUIRED_OBSERVATION_COLUMNS


def read_observations_csv(path: Path) -> list[Observation]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = REQUIRED_OBSERVATION_COLUMNS - set(reader.fieldnames or [])
        if missing:
            columns = ", ".join(sorted(missing))
            raise ValueError(f"{path} is missing required observation columns: {columns}")
        observations = [Observation.from_dict(row) for row in reader]
    if not observations:
        raise ValueError(f"{path} did not contain any observations")
    return observations


class ObservationCSVStream:
    """Re-iterable, constant-memory view over a normalized observation CSV."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._validate()

    def _validate(self) -> None:
        with self.path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            missing = REQUIRED_OBSERVATION_COLUMNS - set(reader.fieldnames or [])
            if missing:
                columns = ", ".join(sorted(missing))
                raise ValueError(f"{self.path} is missing required observation columns: {columns}")
            if next(reader, None) is None:
                raise ValueError(f"{self.path} did not contain any observations")

    def __iter__(self) -> Iterator[Observation]:
        with self.path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                yield Observation.from_dict(row)


def stream_observations_csv(path: Path) -> ObservationCSVStream:
    return ObservationCSVStream(path)


def _is_ip_literal_name(value: str | None) -> bool:
    """True if `value` is missing, or is itself an IP literal (optionally with a
    trailing ``:<port>``) rather than a real resolved name.

    Backfill enrichment (`scripts/backfill_fqdn.py`) can legitimately attach a
    Host-header value observed for a remote_ip elsewhere in the corpus into
    `fqdn`; when that Host-header value is itself just a stringified IP:port
    (not a real hostname), `fqdn` ends up non-None but still name-less. Mirrors
    `dib.evaluation.mud_export._is_ip_literal`'s port-stripping so an
    observation is not treated as "has a real name" on that basis alone.
    """
    if value is None:
        return True
    head, sep, tail = value.rpartition(":")
    candidate = head if sep and tail.isdigit() else value
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


class FilteredObservationStream:
    """Re-iterable observation filter that does not materialize its input."""

    def __init__(self, observations: Iterable[Observation], exclude_non_global_ips: bool = False) -> None:
        self.observations = observations
        self.exclude_non_global_ips = exclude_non_global_ips

    def __iter__(self) -> Iterator[Observation]:
        for observation in self.observations:
            if (
                self.exclude_non_global_ips
                and _is_ip_literal_name(observation.fqdn)
                and observation.remote_ip
            ):
                try:
                    if not ipaddress.ip_address(observation.remote_ip).is_global:
                        continue
                except ValueError:
                    continue
            yield observation


def filter_observations(
    observations: Iterable[Observation], *, exclude_non_global_ips: bool = False
) -> FilteredObservationStream:
    return FilteredObservationStream(observations, exclude_non_global_ips=exclude_non_global_ips)


def write_csv(path: Path, rows: Iterable[dict[str, object]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
