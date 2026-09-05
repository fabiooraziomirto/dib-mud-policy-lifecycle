from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, replace as dataclass_replace
import json

from dib.core.models import Observation, endpoint_to_string
from dib.evaluation.baselines import (
    FrequencyFilteredBaseline,
    MajorityVotingBaseline,
    ReputationWeightedVotingBaseline,
)
from dib.evaluation.dib import DIBScorer, ScoringConfig, accepted_endpoint_keys
from dib.evaluation.graph import graph_confidence
from dib.evaluation.profiles import (
    PREDICTED_DIRECTION,
    canonical_device_name,
    normalize_profile_protocol,
    semantic_match_metrics,
)
from dib.evaluation.trust import build_reputation_snapshot, calibrate_reference_breadth


FAKE_ENDPOINT = "evil-c2.net"
EndpointKey = tuple[str, str, str, int]


@dataclass(frozen=True)
class StrategyEvaluation:
    strategy: str
    policy_scope: str
    policies: tuple[frozenset[EndpointKey], ...]
    real_site_ids: tuple[str, ...]
    local_profiles: tuple[frozenset[EndpointKey], ...]
    fake_key: EndpointKey
    fake_endpoint_score: float | str = ""


def management_strategy_rows(
    poisoned: list[Observation],
    clean: list[Observation],
    target_device_type: str,
    attack_type: str,
    attack_budget: float | int,
    scoring_config: ScoringConfig,
    frequency_min_count: int = 2,
) -> list[dict[str, object]]:
    evaluations = evaluate_management_strategies(
        poisoned,
        clean,
        target_device_type,
        scoring_config,
        frequency_min_count=frequency_min_count,
    )
    return management_rows_from_evaluations(evaluations, attack_type, attack_budget, target_device_type)


def management_rows_from_evaluations(
    evaluations: list[StrategyEvaluation],
    attack_type: str,
    attack_budget: float | int,
    target_device_type: str,
) -> list[dict[str, object]]:
    return [_attack_row(e, attack_type, attack_budget, target_device_type) for e in evaluations]


def evaluate_management_strategies(
    poisoned: list[Observation],
    clean: list[Observation],
    target_device_type: str,
    scoring_config: ScoringConfig,
    frequency_min_count: int = 2,
    calibration_observations: list[Observation] | None = None,
) -> list[StrategyEvaluation]:
    """Compare policy-management strategies for one attacked device type.

    Baselines are device-type isolated. DIB receives the full registry population
    because its graph term can connect endpoint nodes from different device types;
    only score emission and independence clustering are target-scoped. ``clean``
    supplies both the genuine deployment-site set (Sybils must not become local-
    policy evaluation sites) and the pre-attack trust calibration.

    Local-only is intentionally distinct from pooled union: it reports the mean
    size of a genuine site's local policy and the fraction of genuine sites whose
    local policy contains the fake endpoint. Global strategies report a binary
    acceptance rate (0 or 1).
    """
    calibration = calibration_observations if calibration_observations is not None else clean
    target_poisoned = [o for o in poisoned if o.device_type == target_device_type]
    target_clean = [o for o in clean if o.device_type == target_device_type]
    if not target_clean:
        raise ValueError(f"no clean observations for device_type={target_device_type!r}")

    fake_key = (target_device_type, FAKE_ENDPOINT, "https", 443)
    clean_sites = sorted({o.site_id for o in target_clean})
    local_profiles: dict[str, set[tuple[str, str, str, int]]] = defaultdict(set)
    for observation in target_poisoned:
        if observation.site_id in clean_sites:
            local_profiles[observation.site_id].add(observation.endpoint_key)
    local_profile_tuple = tuple(frozenset(local_profiles[site]) for site in clean_sites)
    evaluations = [
        StrategyEvaluation(
            "local_only",
            "per_real_site_mean",
            local_profile_tuple,
            tuple(clean_sites),
            local_profile_tuple,
            fake_key,
        )
    ]

    pooled = {o.endpoint_key for o in target_poisoned}
    evaluations.append(
        _global_evaluation("pooled_union", pooled, clean_sites, local_profile_tuple, fake_key)
    )

    majority = MajorityVotingBaseline().fit(target_poisoned).predict(target_device_type)
    evaluations.append(
        _global_evaluation("majority_registry", majority, clean_sites, local_profile_tuple, fake_key)
    )

    frequency = FrequencyFilteredBaseline(min_count=frequency_min_count).fit(target_poisoned).predict(
        target_device_type
    )

    rwv = ReputationWeightedVotingBaseline(
        build_reputation_snapshot(calibration), threshold=scoring_config.theta
    ).fit(target_poisoned)
    rwv_fake_score = rwv.scores.get(fake_key, 0.0)
    evaluations.append(
        _global_evaluation(
            "reputation_weighted_voting",
            rwv.predict(target_device_type),
            clean_sites,
            local_profile_tuple,
            fake_key,
            round(rwv_fake_score, 6),
        )
    )
    evaluations.append(
        _global_evaluation(
            "frequency_filtered_registry",
            frequency,
            clean_sites,
            local_profile_tuple,
            fake_key,
        )
    )

    reference_breadth = calibrate_reference_breadth(calibration)
    vanilla_scorer = DIBScorer(scoring_config)
    vanilla_scores = vanilla_scorer.score(poisoned, target_device_type=target_device_type)
    graph_override = None
    if scoring_config.graph_enabled and vanilla_scorer.last_graph is not None:
        node_confidence = graph_confidence(vanilla_scorer.last_graph)
        graph_override = {
            key: node_confidence.get(endpoint_to_string(key), 0.0)
            for key in {o.endpoint_key for o in target_poisoned}
        }
    dib_configs = {
        "dib_vanilla": (scoring_config, vanilla_scores),
        "dib_trust_weighted": (dataclass_replace(
            scoring_config,
            trust_weighted=True,
            independence_aware=False,
            combined_mitigation=False,
            trust_reference_breadth=reference_breadth,
        ), None),
        "dib_independence_aware": (dataclass_replace(
            scoring_config,
            trust_weighted=False,
            independence_aware=True,
            combined_mitigation=False,
        ), None),
    }
    for name, (config, precomputed_scores) in dib_configs.items():
        scores = precomputed_scores or DIBScorer(config).score(
            poisoned,
            target_device_type=target_device_type,
            graph_confidence_override=graph_override,
        )
        accepted = accepted_endpoint_keys(scores)
        fake_score = max((score.score for score in scores if score.endpoint_key == fake_key), default=0.0)
        evaluations.append(
            _global_evaluation(
                name,
                accepted,
                clean_sites,
                local_profile_tuple,
                fake_key,
                round(fake_score, 6),
            )
        )
    return evaluations


def _global_evaluation(
    strategy: str,
    policy: set[EndpointKey],
    clean_sites: list[str],
    local_profiles: tuple[frozenset[EndpointKey], ...],
    fake_key: EndpointKey,
    fake_score: float | str = "",
) -> StrategyEvaluation:
    return StrategyEvaluation(
        strategy,
        "global_registry",
        (frozenset(policy),),
        tuple(clean_sites),
        local_profiles,
        fake_key,
        fake_score,
    )


def _attack_row(
    evaluation: StrategyEvaluation,
    attack_type: str,
    attack_budget: float | int,
    target_device_type: str,
) -> dict[str, object]:
    fake_count = sum(evaluation.fake_key in policy for policy in evaluation.policies)
    sizes = [len(policy) for policy in evaluation.policies]
    return {
        "attack_type": attack_type,
        "attack_budget": attack_budget,
        "target_device_type": target_device_type,
        "strategy": evaluation.strategy,
        "policy_scope": evaluation.policy_scope,
        "evaluated_unit_count": len(evaluation.policies),
        "policy_endpoint_count": round(sum(sizes) / len(sizes), 6),
        "fake_endpoint_accepted": fake_count > 0,
        "false_grant_rate": round(fake_count / len(evaluation.policies), 6),
        "fake_endpoint_score": evaluation.fake_endpoint_score,
    }


def management_auditability_rows(
    evaluations: list[StrategyEvaluation],
    truth: set[EndpointKey],
    attack_type: str,
    attack_budget: float | int,
    target_device_type: str,
) -> list[dict[str, object]]:
    """Measure strategy-neutral policy compactness, fidelity and review load.

    One normalized endpoint tuple is counted as one estimated egress ACL entry.
    This is deliberately not called an exact RFC 8520 ACE count because the
    normalized observation schema does not retain traffic direction.
    """
    rows = []
    for evaluation in evaluations:
        canonical_policies = [_canonical_policy(policy, target_device_type) for policy in evaluation.policies]
        metrics = [semantic_match_metrics(policy, truth) for policy in canonical_policies]
        sizes = [len(policy) for policy in evaluation.policies]
        profile_bytes = [_normalized_profile_bytes(policy, target_device_type) for policy in evaluation.policies]
        if evaluation.policy_scope == "global_registry":
            imported = evaluation.policies[0]
            exceptions = [len(local - imported) for local in evaluation.local_profiles]
            denied_rates = [
                len(local - imported) / len(local) if local else 0.0
                for local in evaluation.local_profiles
            ]
        else:
            exceptions = [0 for _ in evaluation.local_profiles]
            denied_rates = [0.0 for _ in evaluation.local_profiles]
        attack_row = _attack_row(evaluation, attack_type, attack_budget, target_device_type)
        rows.append(
            {
                "attack_type": attack_type,
                "attack_budget": attack_budget,
                "target_device_type": target_device_type,
                "strategy": evaluation.strategy,
                "policy_scope": evaluation.policy_scope,
                "evaluated_policy_count": len(evaluation.policies),
                "mean_policy_endpoint_count": round(sum(sizes) / len(sizes), 6),
                "mean_estimated_acl_entries": round(sum(sizes) / len(sizes), 6),
                "mean_normalized_profile_bytes": round(sum(profile_bytes) / len(profile_bytes), 6),
                "mean_semantic_precision": round(_mean(metrics, "semantic_precision"), 6),
                "mean_semantic_recall": round(_mean(metrics, "semantic_recall"), 6),
                "mean_semantic_f1": round(_mean(metrics, "semantic_f1"), 6),
                "mean_monitor_only_exception_candidates": round(sum(exceptions) / len(exceptions), 6),
                "mean_denied_endpoint_rate": round(sum(denied_rates) / len(denied_rates), 6),
                "fake_endpoint_accepted": attack_row["fake_endpoint_accepted"],
                "false_grant_rate": attack_row["false_grant_rate"],
            }
        )
    return rows


def _canonical_policy(
    policy: frozenset[EndpointKey], target_device_type: str
) -> set[tuple[str, str, str, str, int]]:
    # Returns the 5-field (device, direction, endpoint, protocol, port) tuple
    # dib.evaluation.profiles.semantic_match_metrics()/endpoint_satisfies_rule()
    # require -- PREDICTED_DIRECTION since every observation feeding this
    # policy is device-initiated (from-device). This is a distinct, wider
    # tuple than this module's own EndpointKey (registry-key domain, no
    # direction needed there -- see profiles.py's PREDICTED_DIRECTION
    # docstring for why the two domains are kept separate).
    device = canonical_device_name(target_device_type)
    return {
        (device, PREDICTED_DIRECTION, endpoint.lower(), normalize_profile_protocol(protocol, port), port)
        for _, endpoint, protocol, port in policy
    }


def _normalized_profile_bytes(policy: frozenset[EndpointKey], target_device_type: str) -> int:
    payload = {
        "device_type": canonical_device_name(target_device_type),
        "rules": [
            {"endpoint": endpoint, "port": port, "protocol": protocol}
            for _, endpoint, protocol, port in sorted(policy)
        ],
    }
    return len(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _mean(metrics: list[dict[str, float]], key: str) -> float:
    return sum(metric[key] for metric in metrics) / len(metrics) if metrics else 0.0
