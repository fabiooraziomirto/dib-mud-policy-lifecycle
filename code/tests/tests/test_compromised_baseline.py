from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from dib.adapters.unsw_attack_2018 import MaliciousEndpoint
from dib.core.models import EndpointScore, Observation
from dib.evaluation.dib import ScoringConfig
from dib.experiments.compromised_baseline import (
    STRATEGIES,
    admission_exception_curve,
    dib_scores_at_k,
    evaluate_compromised_baseline,
    inject_compromised_baseline,
)

DEVICE_TYPE = "TestCam"
SITE_COUNT = 10


def _clean_observations() -> list[Observation]:
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    rows = []
    for site_index in range(SITE_COUNT):
        site_id = f"site-{site_index:04d}"
        for day in range(20):
            rows.append(
                Observation(
                    site_id=site_id,
                    device_id=f"{site_id}-cam",
                    device_type=DEVICE_TYPE,
                    fqdn=f"benign-{site_index}.example.net",
                    remote_ip=None,
                    protocol="https",
                    port=443,
                    timestamp=base + timedelta(days=day),
                    source_dataset="unit_fixture",
                    evidence_type="flow",
                )
            )
    return rows


def _malicious_endpoints() -> list[MaliciousEndpoint]:
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return [
        MaliciousEndpoint(
            device_type=DEVICE_TYPE,
            remote_ip="203.0.113.5",
            protocol="tcp",
            port=4444,
            timestamp=base + timedelta(hours=1),
            attack_label="unit-fixture",
        ),
        MaliciousEndpoint(
            device_type=DEVICE_TYPE,
            remote_ip="203.0.113.6",
            protocol="tcp",
            port=4445,
            timestamp=base + timedelta(hours=2),
            attack_label="unit-fixture",
        ),
    ]


def test_inject_adds_real_endpoints_only_to_chosen_sites() -> None:
    clean = _clean_observations()
    malicious = _malicious_endpoints()
    poisoned, compromised_sites = inject_compromised_baseline(clean, malicious, DEVICE_TYPE, k=3, seed=1)

    assert len(compromised_sites) == 3
    injected = [o for o in poisoned if o.evidence_type == "compromised_baseline_real_attack"]
    assert len(injected) == 3 * len(malicious)
    assert {o.site_id for o in injected} == set(compromised_sites)
    assert {(o.remote_ip, o.port) for o in injected} == {(m.remote_ip, m.port) for m in malicious}


def test_inject_rejects_k_larger_than_hosting_sites() -> None:
    clean = _clean_observations()
    malicious = _malicious_endpoints()
    with pytest.raises(ValueError):
        inject_compromised_baseline(clean, malicious, DEVICE_TYPE, k=SITE_COUNT + 1, seed=1)


def test_local_only_and_pooled_union_admit_all_malicious_endpoints_by_construction() -> None:
    clean = _clean_observations()
    malicious = _malicious_endpoints()
    rows = evaluate_compromised_baseline(
        clean, malicious, DEVICE_TYPE, k=3, scoring_config=ScoringConfig(), ground_truth={}, seed=1
    )
    by_strategy = {r["strategy"]: r for r in rows}
    assert set(by_strategy) == set(STRATEGIES)
    assert by_strategy["local_only"]["malicious_admission_rate"] == pytest.approx(0.3)
    assert by_strategy["pooled_union"]["malicious_admission_rate"] == pytest.approx(1.0)


def test_dib_vanilla_rejects_malicious_endpoint_below_theta_budget() -> None:
    # k=1 of 10 sites -> f=0.10, well under the shipped theta=0.65 budget:
    # Cs(fake)=0.10 exactly, so score <= 0.5*0.10+0.3+0.2=0.55 < 0.65.
    clean = _clean_observations()
    malicious = _malicious_endpoints()
    rows = evaluate_compromised_baseline(
        clean, malicious, DEVICE_TYPE, k=1, scoring_config=ScoringConfig(), ground_truth={}, seed=1
    )
    by_strategy = {r["strategy"]: r for r in rows}
    assert by_strategy["dib_vanilla"]["malicious_admission_rate"] == pytest.approx(0.0)


def test_zero_compromised_sites_yields_zero_admission_everywhere() -> None:
    clean = _clean_observations()
    malicious = _malicious_endpoints()
    rows = evaluate_compromised_baseline(
        clean, malicious, DEVICE_TYPE, k=0, scoring_config=ScoringConfig(), ground_truth={}, seed=1
    )
    assert all(r["malicious_admission_rate"] == 0.0 for r in rows)


def test_admission_exception_curve_applies_typed_gate_not_just_theta() -> None:
    # Regression for the Fase 3 bug: admission_exception_curve() used to
    # re-threshold via `s.score >= theta` alone, silently bypassing
    # admit_auto()'s typed-class gate once that gate started mattering
    # (Fase 2.3a). The injected malicious endpoints here are IP literals
    # with no FQDN -- classify_core() classifies them "other" (ineligible) --
    # so even at k = every site (malicious score forced to its maximum),
    # the curve must show zero admission at every theta, including the
    # thetas low enough that raw score >= theta would have been True.
    clean = _clean_observations()
    malicious = _malicious_endpoints()
    scores, malicious_keys, benign_local_profile = dib_scores_at_k(
        clean, malicious, DEVICE_TYPE, k=SITE_COUNT, scoring_config=ScoringConfig(alpha=0.6, beta=0.4, gamma=0.0), seed=1
    )
    thetas = [0.10, 0.30, 0.50, 0.65]
    rows = admission_exception_curve(scores, malicious_keys, benign_local_profile, thetas)
    assert all(row["malicious_admission_rate"] == 0.0 for row in rows), rows


def test_admission_exception_curve_applies_quorum_guard_not_just_theta_and_gate() -> None:
    # Same bug class as the typed-gate regression above (review fix
    # 2026-07-24): admission_exception_curve() re-thresholds via
    # admit_auto() at each swept theta, so it must also apply the
    # corroboration quorum (|S_e| >= min_reporting_sites) or a single-site
    # fabricated fact with a class-eligible, high-scoring endpoint would
    # slip through the theta sweep even though the base scoring_config
    # requires min_reporting_sites=2.
    fake_key = (DEVICE_TYPE, "evil.example.net", "https", 443)
    fake_score = EndpointScore(
        device_type=fake_key[0], endpoint=fake_key[1], protocol=fake_key[2], port=fake_key[3],
        site_confidence=1.0, temporal_confidence=1.0, graph_confidence=0.0,
        score=0.9, accepted=True, supporting_sites=1, eligible_sites=1, endpoint_class="vendor-cloud",
    )
    thetas = [0.10, 0.50, 0.65]

    unguarded = admission_exception_curve([fake_score], {fake_key}, {}, thetas)
    assert all(row["malicious_admission_rate"] == 1.0 for row in unguarded), unguarded

    guarded = admission_exception_curve([fake_score], {fake_key}, {}, thetas, min_reporting_sites=2)
    assert all(row["malicious_admission_rate"] == 0.0 for row in guarded), guarded
