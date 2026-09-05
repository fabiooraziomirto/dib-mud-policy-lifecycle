from __future__ import annotations

from datetime import timedelta

from dib.core.models import Observation, endpoint_to_string
from dib.evaluation.dib import DIBScorer, ScoringConfig, accepted_endpoint_keys


def lifecycle_churn_rows(
    observations: list[Observation],
    scoring_config: ScoringConfig,
    checkpoint_days: list[int] | None = None,
    checkpoint_fractions: list[float] | None = None,
) -> list[dict[str, object]]:
    """Measure policy reconfiguration churn across cumulative time checkpoints."""

    if not observations:
        return []
    ordered = sorted(observations, key=lambda obs: obs.timestamp)
    started = ordered[0].timestamp
    checkpoints = _checkpoint_indices(ordered, checkpoint_fractions) if checkpoint_fractions else []
    if not checkpoints:
        checkpoints = [
            (day, len([obs for obs in ordered if obs.timestamp <= started + timedelta(days=day)]), "")
            for day in sorted(set(checkpoint_days or []))
        ]
    previous: set[tuple[str, str, str, int]] = set()
    previous_checkpoint_day = 0
    rows: list[dict[str, object]] = []
    for checkpoint_day, observation_count, trace_fraction in checkpoints:
        window = ordered[:observation_count]
        accepted = accepted_endpoint_keys(DIBScorer(scoring_config).score(window)) if window else set()
        added = accepted - previous
        removed = previous - accepted
        update_count = len(added) + len(removed)
        elapsed = max(checkpoint_day - previous_checkpoint_day, 1)
        rows.append(
            {
                "checkpoint_day": checkpoint_day,
                "trace_fraction": trace_fraction,
                "observation_count": len(window),
                "accepted_endpoint_count": len(accepted),
                "added_endpoint_count": len(added),
                "removed_endpoint_count": len(removed),
                "policy_update_count": update_count,
                "updates_per_day": round(update_count / elapsed, 6),
                "added_endpoint_sample": _sample_endpoint(added),
                "removed_endpoint_sample": _sample_endpoint(removed),
            }
        )
        previous = accepted
        previous_checkpoint_day = checkpoint_day
    return rows


def summarize_lifecycle(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    if not rows:
        return []
    total_updates = sum(int(row["policy_update_count"]) for row in rows)
    total_days = max(int(row["checkpoint_day"]) for row in rows) or len(rows)
    return [
        {
            "checkpoint_count": len(rows),
            "total_policy_updates": total_updates,
            "mean_updates_per_checkpoint": round(total_updates / len(rows), 6),
            "mean_updates_per_day": round(total_updates / total_days, 6),
            "max_updates_per_checkpoint": max(int(row["policy_update_count"]) for row in rows),
            "final_accepted_endpoint_count": rows[-1]["accepted_endpoint_count"],
        }
    ]


def _sample_endpoint(endpoints: set[tuple[str, str, str, int]]) -> str:
    if not endpoints:
        return ""
    return endpoint_to_string(sorted(endpoints)[0])


def _checkpoint_indices(
    observations: list[Observation], checkpoint_fractions: list[float] | None
) -> list[tuple[int, int, str]]:
    if not checkpoint_fractions:
        return []
    count = len(observations)
    checkpoints = []
    started = None
    for fraction in sorted(set(checkpoint_fractions)):
        if not 0.0 < fraction <= 1.0:
            raise ValueError("checkpoint fractions must be in (0, 1]")
        observation_count = max(1, int(round(count * fraction)))
        checkpoint_time = observations[observation_count - 1].timestamp
        if started is None:
            started = checkpoint_time
        checkpoint_day = max((checkpoint_time - started).days, 0)
        checkpoints.append((checkpoint_day, observation_count, f"{fraction:.3f}"))
    return checkpoints
