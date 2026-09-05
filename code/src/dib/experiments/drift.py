from __future__ import annotations

from collections import Counter
from dataclasses import replace
from datetime import timedelta
import random

from dib.core.models import Observation
from dib.evaluation.dib import DIBScorer, ScoringConfig


def inject_drift_endpoint(
    observations: list[Observation],
    site_ids: set[str],
    target_device_type: str,
    fqdn: str,
    evidence_type: str,
    spread_days: int = 1,
    protocol: str = "https",
    port: int = 443,
) -> list[Observation]:
    """Add a candidate drift endpoint for a target device type at selected sites."""

    if spread_days < 1:
        raise ValueError("spread_days must be >= 1")
    updated = list(observations)
    templates: dict[str, Observation] = {}
    for obs in observations:
        if obs.device_type == target_device_type and obs.site_id in site_ids:
            templates.setdefault(obs.site_id, obs)
    for site_id, template in sorted(templates.items()):
        for offset in range(spread_days):
            updated.append(
                replace(
                    template,
                    fqdn=fqdn,
                    remote_ip=None,
                    protocol=protocol,
                    port=port,
                    timestamp=template.timestamp + timedelta(days=offset + 1),
                    evidence_type=evidence_type,
                )
            )
    return updated


def drift_classification_rows(
    observations: list[Observation],
    scoring_config: ScoringConfig,
    adoption_fractions: list[float],
    promote_fraction: float = 0.6,
    attack_spread_days: list[int] | None = None,
    legitimate_spread_days: int = 120,
    seed: int = 42,
) -> list[dict[str, object]]:
    """Evaluate whether corroboration promotes fleet-wide drift and rejects local drift.

    The experiment uses repeatable endpoint injections over real observations:
    legitimate firmware drift is injected across an increasing fraction of sites,
    while compromise drift remains confined to one site and is repeated across
    days to model low-and-slow persistence. `legitimate_spread_days` gives the
    rollout endpoint the same persistence as a mature, already-established
    change (matching the longest persistence window used for the isolated-
    compromise arm and the cold-start evaluation's final observation window)
    rather than a single day, so adoption fraction is the only varied
    dimension and temporal confidence is not artificially suppressed.
    Promotion/quarantine decisions use the scorer's own acceptance gate
    (`score >= theta`), the same rule the rest of the paper reports, rather
    than a separate ad hoc site-confidence threshold.
    """

    if not observations:
        return []
    target_device_type = Counter(obs.device_type for obs in observations).most_common(1)[0][0]
    eligible_sites = sorted({obs.site_id for obs in observations if obs.device_type == target_device_type})
    if not eligible_sites:
        return []

    rng = random.Random(seed)
    rows: list[dict[str, object]] = []
    for fraction in adoption_fractions:
        adopting_count = int(round(len(eligible_sites) * fraction))
        adopting_sites = set(rng.sample(eligible_sites, adopting_count)) if adopting_count else set()
        drifted = inject_drift_endpoint(
            observations,
            adopting_sites,
            target_device_type,
            "new-firmware.vendor.example",
            "firmware_update_endpoint",
            spread_days=legitimate_spread_days,
        )
        score = _endpoint_score(drifted, scoring_config, target_device_type, "new-firmware.vendor.example")
        expected = "promote" if fraction >= promote_fraction else "observe"
        predicted = "promote" if bool(score["accepted"]) else "observe"
        rows.append(
            _row("legitimate_firmware", fraction, legitimate_spread_days, target_device_type, score, expected, predicted)
        )

    attack_days = attack_spread_days or [1, 30, 120]
    compromised_site = {eligible_sites[0]}
    for spread_days in attack_days:
        drifted = inject_drift_endpoint(
            observations,
            compromised_site,
            target_device_type,
            "evil-drift.example",
            "compromise_drift_endpoint",
            spread_days=spread_days,
        )
        score = _endpoint_score(drifted, scoring_config, target_device_type, "evil-drift.example")
        predicted = "promote" if bool(score["accepted"]) else "quarantine"
        rows.append(
            _row(
                "isolated_compromise",
                1 / len(eligible_sites),
                spread_days,
                target_device_type,
                score,
                "quarantine",
                predicted,
            )
        )
    return rows


def summarize_drift(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    by_scenario: dict[str, list[dict[str, object]]] = {}
    for row in rows:
        by_scenario.setdefault(str(row["scenario"]), []).append(row)
    summary = []
    for scenario, items in sorted(by_scenario.items()):
        correct = sum(1 for item in items if item["correct"])
        promoted = sum(1 for item in items if item["predicted_decision"] == "promote")
        summary.append(
            {
                "scenario": scenario,
                "case_count": len(items),
                "accuracy": round(correct / len(items), 6) if items else 0.0,
                "promoted_count": promoted,
                "mean_endpoint_score": round(sum(float(item["endpoint_score"]) for item in items) / len(items), 6)
                if items
                else 0.0,
            }
        )
    return summary


def _endpoint_score(
    observations: list[Observation], config: ScoringConfig, device_type: str, endpoint: str
) -> dict[str, object]:
    scores = [
        score
        for score in DIBScorer(config).score(observations)
        if score.device_type == device_type and score.endpoint == endpoint
    ]
    if not scores:
        return {"score": 0.0, "accepted": False, "site_confidence": 0.0, "temporal_confidence": 0.0}
    score = max(scores, key=lambda item: item.score)
    return {
        "score": score.score,
        "accepted": score.accepted,
        "site_confidence": score.site_confidence,
        "temporal_confidence": score.temporal_confidence,
    }


def _row(
    scenario: str,
    adoption_fraction: float,
    spread_days: int,
    target_device_type: str,
    score: dict[str, object],
    expected: str,
    predicted: str,
) -> dict[str, object]:
    return {
        "scenario": scenario,
        "adoption_fraction": round(adoption_fraction, 6),
        "spread_days": spread_days,
        "target_device_type": target_device_type,
        "endpoint_score": round(float(score["score"]), 6),
        "site_confidence": round(float(score["site_confidence"]), 6),
        "temporal_confidence": round(float(score["temporal_confidence"]), 6),
        "accepted": bool(score["accepted"]),
        "expected_decision": expected,
        "predicted_decision": predicted,
        "correct": expected == predicted,
    }
