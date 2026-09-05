from __future__ import annotations

from datetime import datetime, timezone

from dib.core.models import Observation
from dib.evaluation.dib import ScoringConfig
from dib.experiments.drift import drift_classification_rows, inject_drift_endpoint, summarize_drift
from dib.experiments.lifecycle import lifecycle_churn_rows, summarize_lifecycle


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


def sample_observations() -> list[Observation]:
    rows: list[Observation] = []
    for site in ("site-a", "site-b", "site-c", "site-d"):
        rows.append(obs(site, "api.vendor.example", 1))
        rows.append(obs(site, "time.vendor.example", 2))
    rows.append(obs("site-a", "late.vendor.example", 20))
    rows.append(obs("site-b", "late.vendor.example", 20))
    rows.append(obs("site-c", "late.vendor.example", 20))
    rows.append(obs("site-d", "late.vendor.example", 20))
    return rows


def test_drift_rows_promote_fleet_drift_and_quarantine_isolated_drift() -> None:
    rows = drift_classification_rows(
        sample_observations(),
        ScoringConfig(theta=0.55),
        adoption_fractions=[0.25, 1.0],
        promote_fraction=0.6,
        attack_spread_days=[1, 30],
        legitimate_spread_days=1,
        seed=1,
    )
    by_case = {(row["scenario"], row["adoption_fraction"], row["spread_days"]): row for row in rows}
    assert by_case[("legitimate_firmware", 1.0, 1)]["predicted_decision"] == "promote"
    assert by_case[("isolated_compromise", 0.25, 30)]["predicted_decision"] == "quarantine"
    assert all(row["correct"] for row in rows)
    summary = summarize_drift(rows)
    assert {row["scenario"] for row in summary} == {"isolated_compromise", "legitimate_firmware"}


def test_inject_drift_endpoint_rejects_invalid_spread() -> None:
    try:
        inject_drift_endpoint(sample_observations(), {"site-a"}, "camera", "x.example", "drift", spread_days=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError for spread_days < 1")


def test_lifecycle_churn_reports_policy_updates_between_checkpoints() -> None:
    rows = lifecycle_churn_rows(sample_observations(), ScoringConfig(theta=0.55), [0, 7, 30])
    assert [row["checkpoint_day"] for row in rows] == [0, 7, 30]
    assert rows[0]["policy_update_count"] >= 1
    assert rows[-1]["accepted_endpoint_count"] > rows[0]["accepted_endpoint_count"]
    assert rows[-1]["added_endpoint_count"] >= 1
    summary = summarize_lifecycle(rows)
    assert summary[0]["total_policy_updates"] >= rows[-1]["added_endpoint_count"]
