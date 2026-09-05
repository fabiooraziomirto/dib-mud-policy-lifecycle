from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from dib.core.models import Observation
from dib.evaluation.dib import DIBScorer, ScoringConfig
from dib.evaluation.profiles import (
    PREDICTED_DIRECTION,
    EndpointKey,
    canonical_device_name,
    normalize_profile_protocol,
    semantic_match_metrics,
)


DEFAULT_WINDOWS = [0, 1, 3, 7, 14, 30, 60, 120]


def observation_endpoint_keys(observations: list[Observation]) -> dict[str, set[EndpointKey]]:
    profiles: dict[str, set[EndpointKey]] = defaultdict(set)
    for obs in observations:
        endpoint = obs.fqdn or obs.remote_ip
        if not endpoint:
            continue
        device_type = canonical_device_name(obs.device_type)
        protocol = normalize_profile_protocol(obs.protocol, obs.port)
        # PREDICTED_DIRECTION: every observation is device-initiated (from-device).
        profiles[device_type].add((device_type, PREDICTED_DIRECTION, endpoint.lower(), protocol, obs.port))
    return dict(profiles)


def accepted_score_endpoint_keys(scores) -> dict[str, set[EndpointKey]]:
    profiles: dict[str, set[EndpointKey]] = defaultdict(set)
    for score in scores:
        if not score.accepted:
            continue
        device_type = canonical_device_name(score.device_type)
        protocol = normalize_profile_protocol(score.protocol, score.port)
        profiles[device_type].add((device_type, PREDICTED_DIRECTION, score.endpoint.lower(), protocol, score.port))
    return dict(profiles)


def _site_jaccard(site_a: dict[str, set[EndpointKey]], site_b: dict[str, set[EndpointKey]]) -> float:
    """Jaccard similarity of two sites' combined endpoint sets, used to pick a
    ``nearest_site`` cold-start prior (TDSC roadmap P1 #7)."""
    union_a: set[EndpointKey] = set().union(*site_a.values()) if site_a else set()
    union_b: set[EndpointKey] = set().union(*site_b.values()) if site_b else set()
    if not union_a or not union_b:
        return 0.0
    intersection = len(union_a & union_b)
    return intersection / len(union_a | union_b)


def _mismatched_device_type(device_type: str, all_device_types: list[str]) -> str:
    """Deterministically map a device type to a *different* one, modelling a
    fingerprinting error that retrieves the wrong device's registry profile
    (TDSC roadmap P1 #7 negative control). Mirrors the collision strategy in
    ``dib.experiments.fingerprinting``: map to the next type in sorted order."""
    if len(all_device_types) < 2:
        return device_type
    ordered = sorted(all_device_types)
    idx = ordered.index(device_type)
    return ordered[(idx + 1) % len(ordered)]


def cold_start_rows(
    observations: list[Observation],
    truth: dict[str, set[EndpointKey]],
    scoring_config: ScoringConfig,
    windows: list[int] | None = None,
) -> list[dict[str, object]]:
    windows = windows or DEFAULT_WINDOWS
    by_site: dict[str, list[Observation]] = defaultdict(list)
    for obs in observations:
        by_site[obs.site_id].append(obs)

    all_device_types = sorted(truth)
    site_raw_profiles: dict[str, dict[str, set[EndpointKey]]] = {
        site_id: observation_endpoint_keys(site_observations) for site_id, site_observations in by_site.items()
    }

    rows: list[dict[str, object]] = []
    for site_id, target_observations in sorted(by_site.items()):
        if not target_observations:
            continue
        target_device_types = {
            canonical_device_name(obs.device_type)
            for obs in target_observations
            if canonical_device_name(obs.device_type) in truth
        }
        if not target_device_types:
            continue
        start = min(obs.timestamp for obs in target_observations)
        registry_observations = [obs for obs in observations if obs.site_id != site_id]
        registry_profiles = accepted_score_endpoint_keys(
            DIBScorer(scoring_config).score(registry_observations)
        )
        pooled_union_profiles = observation_endpoint_keys(registry_observations)

        nearest_site_id = max(
            (other for other in site_raw_profiles if other != site_id),
            key=lambda other: _site_jaccard(site_raw_profiles[site_id], site_raw_profiles[other]),
            default=None,
        )
        nearest_site_profiles = site_raw_profiles.get(nearest_site_id, {}) if nearest_site_id else {}

        for window_days in windows:
            if window_days <= 0:
                local_observations: list[Observation] = []
            else:
                cutoff = start + timedelta(days=window_days)
                local_observations = [
                    obs for obs in target_observations if start <= obs.timestamp < cutoff
                ]
            local_profiles = observation_endpoint_keys(local_observations)

            def _seeded(prior: dict[str, set[EndpointKey]]) -> dict[str, set[EndpointKey]]:
                return {
                    device_type: set(prior.get(device_type, set())) | set(local_profiles.get(device_type, set()))
                    for device_type in target_device_types
                }

            mismatched_profiles = {
                device_type: set(local_profiles.get(device_type, set()))
                | set(registry_profiles.get(_mismatched_device_type(device_type, all_device_types), set()))
                for device_type in target_device_types
            }

            rows.append(
                _metric_row(site_id, window_days, "local_only", target_device_types, local_profiles, truth)
            )
            rows.append(
                _metric_row(site_id, window_days, "registry_seeded", target_device_types, _seeded(registry_profiles), truth)
            )
            rows.append(
                _metric_row(
                    site_id, window_days, "pooled_union_seeded", target_device_types, _seeded(pooled_union_profiles), truth
                )
            )
            rows.append(
                _metric_row(
                    site_id, window_days, "nearest_site_seeded", target_device_types, _seeded(nearest_site_profiles), truth
                )
            )
            rows.append(
                _metric_row(
                    site_id, window_days, "mismatched_fingerprint_seeded", target_device_types, mismatched_profiles, truth
                )
            )
    return rows


def _metric_row(
    site_id: str,
    window_days: int,
    method: str,
    device_types: set[str],
    predicted_by_device: dict[str, set[EndpointKey]],
    truth: dict[str, set[EndpointKey]],
) -> dict[str, object]:
    metrics = [
        semantic_match_metrics(predicted_by_device.get(device_type, set()), truth[device_type])
        for device_type in sorted(device_types)
    ]
    predicted_count = sum(len(predicted_by_device.get(device_type, set())) for device_type in device_types)
    n = len(metrics)
    return {
        "site_id": site_id,
        "window_days": window_days,
        "method": method,
        "device_count": n,
        "predicted_endpoint_count": predicted_count,
        "mean_semantic_precision": _mean(item["semantic_precision"] for item in metrics),
        "mean_semantic_recall": _mean(item["semantic_recall"] for item in metrics),
        "mean_semantic_f1": _mean(item["semantic_f1"] for item in metrics),
    }


def summarize_cold_start(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[tuple[int, str], list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        grouped[(int(row["window_days"]), str(row["method"]))].append(row)
    summary = []
    for (window_days, method), items in sorted(grouped.items()):
        summary.append(
            {
                "window_days": window_days,
                "method": method,
                "site_count": len(items),
                "mean_semantic_precision": _mean(float(item["mean_semantic_precision"]) for item in items),
                "mean_semantic_recall": _mean(float(item["mean_semantic_recall"]) for item in items),
                "mean_semantic_f1": _mean(float(item["mean_semantic_f1"]) for item in items),
                "mean_predicted_endpoint_count": _mean(
                    float(item["predicted_endpoint_count"]) for item in items
                ),
            }
        )
    return summary


def _mean(values) -> float:
    values = list(values)
    return sum(values) / len(values) if values else 0.0
