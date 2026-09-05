from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from dib.core.io import write_json
from dib.core.models import EndpointScore
from dib.evaluation.dib import ScoringConfig


def build_global_profiles(scores: list[EndpointScore], config: ScoringConfig) -> dict[str, dict[str, object]]:
    """Group accepted/rejected endpoint scores per device type with a traceable score breakdown."""
    by_device: dict[str, list[EndpointScore]] = defaultdict(list)
    for score in scores:
        by_device[score.device_type].append(score)

    profiles: dict[str, dict[str, object]] = {}
    for device_type, device_scores in by_device.items():
        endpoints = []
        for score in sorted(device_scores, key=lambda item: (-item.score, item.endpoint)):
            endpoints.append(
                {
                    "endpoint": score.endpoint,
                    "protocol": score.protocol,
                    "port": score.port,
                    "accepted": score.accepted,
                    "score": round(score.score, 6),
                    "explanation": {
                        "site_confidence": round(score.site_confidence, 6),
                        "temporal_confidence": round(score.temporal_confidence, 6),
                        "graph_confidence": round(score.graph_confidence, 6),
                        "alpha": config.alpha,
                        "beta": config.beta,
                        "gamma": config.gamma,
                        "theta": config.theta,
                        "supporting_sites": score.supporting_sites,
                        "eligible_sites": score.eligible_sites,
                        "formula": "score = alpha*site_confidence + beta*temporal_confidence + gamma*graph_confidence",
                    },
                }
            )
        profiles[device_type] = {
            "device_type": device_type,
            "endpoint_count": len(endpoints),
            "accepted_count": sum(1 for item in endpoints if item["accepted"]),
            "endpoints": endpoints,
        }
    return profiles


def export_global_profiles(profiles: dict[str, dict[str, object]], output_dir: Path) -> None:
    for device_type, payload in profiles.items():
        safe_name = device_type.replace("/", "_")
        write_json(output_dir / f"{safe_name}.json", payload)
