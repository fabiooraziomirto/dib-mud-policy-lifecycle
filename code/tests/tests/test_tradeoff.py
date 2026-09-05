from __future__ import annotations

from dib.core.models import EndpointScore
from dib.experiments.tradeoff import (
    TradeoffVariant,
    churn_metrics,
    first_accepted_budget,
    one_at_a_time_variants,
    static_tradeoff_metrics,
)


def score(endpoint: str, site: float, temporal: float = 0.0, graph: float = 0.0) -> EndpointScore:
    # endpoint_class="vendor-cloud": these fixtures use FQDNs with no
    # dns/ntp/update-keyword match, matching how classify_core() would
    # actually classify them (e.g. "evil-c2.net", same as
    # dib.experiments.poisoning.inject_fake_endpoint's real default) --
    # an eligible class, so these tests exercise the theta/weight logic in
    # accepted_keys()/first_accepted_budget(), not the typed gate itself.
    return EndpointScore("camera", endpoint, "https", 443, site, temporal, graph, 0.0, False, 1, 1, "vendor-cloud")


def test_variants_change_exactly_one_parameter() -> None:
    base = {"alpha": 0.5, "beta": 0.3, "gamma": 0.2, "theta": 0.65}
    variants = one_at_a_time_variants(base, {k: [v] for k, v in base.items()})
    assert len(variants) == 4
    assert {variant.parameter for variant in variants} == set(base)


def test_static_metrics_and_churn_use_reweighted_components() -> None:
    variant = TradeoffVariant("theta", 0.5, 1.0, 0.0, 0.0, 0.5)
    truth = {"camera": {("camera", "from-device", "api.example", "tcp", 443)}}
    metrics = static_tradeoff_metrics([score("api.example", 0.8), score("noise.example", 0.2)], truth, variant)
    assert metrics["accepted_normalized_endpoint_count"] == 1
    assert metrics["mean_semantic_f1"] == 1.0
    churn = churn_metrics([[score("api.example", 0.8)], [score("api.example", 0.4)]], variant)
    assert churn["total_policy_updates"] == 2


def test_attack_budget_returns_first_acceptance_or_censored_bound() -> None:
    variant = TradeoffVariant("theta", 0.5, 1.0, 0.0, 0.0, 0.5)
    budgets = [(0.1, score("evil-c2.net", 0.2)), (0.3, score("evil-c2.net", 0.6))]
    assert first_accepted_budget(budgets, variant) == "0.3"
    strict = TradeoffVariant("theta", 0.9, 1.0, 0.0, 0.0, 0.9)
    assert first_accepted_budget(budgets, strict) == ">0.3"
