from __future__ import annotations

import csv
from datetime import datetime, timezone

from dib.core.models import Observation
from dib.evaluation.dib import ScoringConfig
from dib.experiments.management_attack import (
    evaluate_management_strategies,
    management_auditability_rows,
    management_strategy_rows,
)
from dib.experiments.poisoning import inject_adaptive_sybil_endpoint, inject_fake_endpoint, inject_sybil_endpoint
from dib.experiments.runner import run_management_attack


def obs(site: str, fqdn: str, day: int = 1) -> Observation:
    return Observation(
        site_id=site,
        device_id=f"{site}-camera",
        device_type="camera",
        fqdn=fqdn,
        remote_ip=None,
        protocol="https",
        port=443,
        timestamp=datetime(2026, 1, day, tzinfo=timezone.utc),
        source_dataset="unit_fixture",
        evidence_type="flow",
    )


def clean_fixture() -> list[Observation]:
    return [obs(site, "api.vendor.example") for site in ("site-a", "site-b", "site-c")]


def by_strategy(rows: list[dict[str, object]]) -> dict[str, dict[str, object]]:
    return {str(row["strategy"]): row for row in rows}


def test_bounded_attack_separates_local_only_from_pooled_union() -> None:
    clean = clean_fixture()
    poisoned = inject_fake_endpoint(clean, malicious_fraction=1 / 3, seed=2)
    rows = management_strategy_rows(
        poisoned,
        clean,
        "camera",
        "bounded_poisoning",
        1 / 3,
        ScoringConfig(graph_enabled=False),
    )
    strategies = by_strategy(rows)
    assert set(strategies) == {
        "local_only",
        "pooled_union",
        "majority_registry",
        "frequency_filtered_registry",
        "reputation_weighted_voting",
        "dib_vanilla",
        "dib_trust_weighted",
        "dib_independence_aware",
    }
    assert strategies["local_only"]["evaluated_unit_count"] == 3
    assert strategies["local_only"]["false_grant_rate"] == 0.333333
    assert strategies["pooled_union"]["fake_endpoint_accepted"] is True
    assert strategies["majority_registry"]["fake_endpoint_accepted"] is False


def test_sybil_sites_are_not_counted_as_local_deployment_sites() -> None:
    clean = clean_fixture()
    poisoned = inject_sybil_endpoint(clean, 4, "camera", seed=1)
    rows = management_strategy_rows(
        poisoned,
        clean,
        "camera",
        "sybil",
        4,
        ScoringConfig(graph_enabled=False),
    )
    strategies = by_strategy(rows)
    assert strategies["local_only"]["evaluated_unit_count"] == 3
    assert strategies["local_only"]["false_grant_rate"] == 0.0
    assert strategies["pooled_union"]["fake_endpoint_accepted"] is True
    assert strategies["majority_registry"]["fake_endpoint_accepted"] is True
    assert strategies["frequency_filtered_registry"]["fake_endpoint_accepted"] is True


def test_adaptive_sybil_budget_is_reported_without_changing_strategy_semantics() -> None:
    clean = clean_fixture()
    poisoned = inject_adaptive_sybil_endpoint(clean, 4, "camera", spread_days=5, seed=1)
    rows = management_strategy_rows(
        poisoned,
        clean,
        "camera",
        "adaptive_sybil_4_sites",
        5,
        ScoringConfig(graph_enabled=False),
    )
    assert all(row["attack_type"] == "adaptive_sybil_4_sites" for row in rows)
    assert all(row["attack_budget"] == 5 for row in rows)
    assert by_strategy(rows)["local_only"]["false_grant_rate"] == 0.0


def test_unknown_target_is_rejected() -> None:
    try:
        management_strategy_rows(
            clean_fixture(),
            clean_fixture(),
            "thermostat",
            "clean",
            0,
            ScoringConfig(graph_enabled=False),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError for an unknown target device")


def test_auditability_reports_fidelity_size_and_monitor_only_exceptions() -> None:
    clean = clean_fixture()
    poisoned = inject_fake_endpoint(clean, malicious_fraction=1 / 3, seed=2)
    evaluations = evaluate_management_strategies(
        poisoned,
        clean,
        "camera",
        ScoringConfig(graph_enabled=False),
    )
    truth = {("camera", "from-device", "api.vendor.example", "tcp", 443)}
    rows = management_auditability_rows(
        evaluations,
        truth,
        "bounded_poisoning",
        1 / 3,
        "camera",
    )
    strategies = by_strategy(rows)
    pooled = strategies["pooled_union"]
    majority = strategies["majority_registry"]
    local = strategies["local_only"]
    assert pooled["mean_policy_endpoint_count"] == 2.0
    assert pooled["mean_estimated_acl_entries"] == 2.0
    assert pooled["mean_semantic_precision"] == 0.5
    assert pooled["mean_semantic_recall"] == 1.0
    assert majority["mean_semantic_f1"] == 1.0
    assert majority["mean_monitor_only_exception_candidates"] == 0.333333
    assert local["mean_monitor_only_exception_candidates"] == 0.0
    assert local["mean_normalized_profile_bytes"] > 0


def test_normalized_profile_size_is_strategy_neutral_and_deterministic() -> None:
    clean = clean_fixture()
    evaluations = evaluate_management_strategies(
        clean,
        clean,
        "camera",
        ScoringConfig(graph_enabled=False),
    )
    truth = {("camera", "from-device", "api.vendor.example", "tcp", 443)}
    first = management_auditability_rows(evaluations, truth, "clean", 0, "camera")
    second = management_auditability_rows(evaluations, truth, "clean", 0, "camera")
    assert first == second


def test_runner_writes_additive_management_attack_artifact(tmp_path) -> None:
    config = {
        "experiments": {
            "seed": 7,
            "malicious_site_fractions": [1 / 3],
            "sybil_site_counts": [2],
            "adaptive_sybil_spread_days": [1],
            "management_attack_adaptive_days": [1],
        },
        "scoring": {"alpha": 0.5, "beta": 0.3, "gamma": 0.2, "theta": 0.65, "min_reporting_sites": 1},
        "baselines": {"frequency_min_count": 2},
    }
    run_management_attack(clean_fixture(), tmp_path, config)
    output = tmp_path / "experiments" / "management_attack" / "management_strategies_under_attack.csv"
    audit_output = tmp_path / "experiments" / "management_attack" / "policy_auditability_under_attack.csv"
    with output.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 3 * 8
    assert {row["attack_type"] for row in rows} == {
        "bounded_poisoning",
        "sybil",
        "adaptive_sybil_2_sites",
    }
    with audit_output.open(newline="", encoding="utf-8") as handle:
        audit_rows = list(csv.DictReader(handle))
    assert len(audit_rows) == len(rows)
    assert "mean_monitor_only_exception_candidates" in audit_rows[0]
