from __future__ import annotations

from dataclasses import dataclass

from dib.core.models import EndpointScore
from dib.evaluation.dib import admit_auto
from dib.evaluation.profiles import (
    PREDICTED_DIRECTION,
    canonical_device_name,
    normalize_profile_protocol,
    semantic_match_metrics,
)


@dataclass(frozen=True)
class TradeoffVariant:
    parameter: str
    value: float
    alpha: float
    beta: float
    gamma: float
    theta: float


def one_at_a_time_variants(base: dict[str, float], grid: dict[str, list[float]]) -> list[TradeoffVariant]:
    variants = []
    for parameter in ("alpha", "beta", "gamma", "theta"):
        for value in grid[parameter]:
            params = dict(base)
            params[parameter] = value
            variants.append(TradeoffVariant(parameter, value, **params))
    return variants


def accepted_keys(
    scores: list[EndpointScore], variant: TradeoffVariant, min_reporting_sites: int = 1
) -> set[tuple[str, str, str, int]]:
    # Fase 3, Gruppo (c) pre-check: this used to compare component_score(...)
    # to theta directly, never reading endpoint_class -- same bug class as
    # dib.experiments.compromised_baseline.admission_exception_curve (Fase 3
    # Gruppo a) and scripts/tune_dib_weights.py (Gruppo b). Not currently
    # wired into any active script in this artifact (only
    # DIB/scripts/tnsm_tradeoff.py, not yet copied here), but fixed
    # proactively since it is shared library code.
    #
    # min_reporting_sites (review fix 2026-07-24): same reasoning -- the
    # corroboration quorum is part of admit_auto()'s admission decision and
    # would otherwise be silently bypassed here exactly like the typed gate
    # was before this function's original fix. TradeoffVariant does not
    # sweep this parameter, so it is passed through unchanged from the base
    # scoring config a caller is varying alpha/beta/gamma/theta around.
    return {
        score.endpoint_key
        for score in scores
        if admit_auto(
            component_score(score, variant), variant.theta, score.endpoint_class,
            supporting_sites=score.supporting_sites,
            min_reporting_sites=min_reporting_sites,
        )
    }


def component_score(score: EndpointScore, variant: TradeoffVariant) -> float:
    return (
        variant.alpha * score.site_confidence
        + variant.beta * score.temporal_confidence
        + variant.gamma * score.graph_confidence
    )


def static_tradeoff_metrics(
    scores: list[EndpointScore],
    truth: dict[str, set[tuple[str, str, str, str, int]]],
    variant: TradeoffVariant,
    min_reporting_sites: int = 1,
) -> dict[str, float | int]:
    predicted: dict[str, set[tuple[str, str, str, str, int]]] = {}
    for key in accepted_keys(scores, variant, min_reporting_sites=min_reporting_sites):
        device_type, endpoint, protocol, port = key
        canonical = canonical_device_name(device_type)
        # PREDICTED_DIRECTION: every observation in this codebase is
        # device-initiated (from-device) -- see its docstring.
        predicted.setdefault(canonical, set()).add(
            (canonical, PREDICTED_DIRECTION, endpoint.lower(), normalize_profile_protocol(protocol, port), port)
        )
    metrics = [semantic_match_metrics(predicted.get(device, set()), rules) for device, rules in truth.items()]
    return {
        "accepted_normalized_endpoint_count": sum(len(policy) for policy in predicted.values()),
        "mean_semantic_precision": _mean(metrics, "semantic_precision"),
        "mean_semantic_recall": _mean(metrics, "semantic_recall"),
        "mean_semantic_f1": _mean(metrics, "semantic_f1"),
    }


def churn_metrics(
    score_snapshots: list[list[EndpointScore]], variant: TradeoffVariant, min_reporting_sites: int = 1
) -> dict[str, float | int]:
    previous: set[tuple[str, str, str, int]] = set()
    updates = []
    for scores in score_snapshots:
        current = accepted_keys(scores, variant, min_reporting_sites=min_reporting_sites)
        updates.append(len(current - previous) + len(previous - current))
        previous = current
    return {
        "total_policy_updates": sum(updates),
        "mean_updates_per_checkpoint": sum(updates) / len(updates) if updates else 0.0,
        "max_updates_per_checkpoint": max(updates, default=0),
    }


def first_accepted_budget(
    fake_scores_by_budget: list[tuple[float, EndpointScore | None]],
    variant: TradeoffVariant,
    min_reporting_sites: int = 1,
) -> str:
    for budget, score in sorted(fake_scores_by_budget, key=lambda item: item[0]):
        if score is not None and admit_auto(
            component_score(score, variant), variant.theta, score.endpoint_class,
            supporting_sites=score.supporting_sites,
            min_reporting_sites=min_reporting_sites,
        ):
            return str(budget)
    return f">{max((budget for budget, _ in fake_scores_by_budget), default=0.0)}"


def _mean(metrics: list[dict[str, float]], key: str) -> float:
    return sum(metric[key] for metric in metrics) / len(metrics) if metrics else 0.0
