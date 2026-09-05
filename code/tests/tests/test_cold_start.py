from __future__ import annotations

from datetime import datetime, timezone

from dib.core.models import Observation
from dib.evaluation.dib import ScoringConfig
from dib.experiments.cold_start import cold_start_rows, summarize_cold_start


def obs(site: str, device: str, fqdn: str, day: int = 1) -> Observation:
    return Observation(
        site_id=site,
        device_id=f"{site}-{device}",
        device_type=device,
        fqdn=fqdn,
        remote_ip=None,
        protocol="https",
        port=443,
        timestamp=datetime(2026, 1, day, tzinfo=timezone.utc),
        source_dataset="unit_fixture",
        evidence_type="flow",
    )


def test_registry_seeded_profile_improves_day_zero_cold_start() -> None:
    observations = [
        obs("site-a", "camera", "api.vendor.example"),
        obs("site-b", "camera", "api.vendor.example"),
        obs("site-c", "camera", "api.vendor.example"),
        obs("site-new", "camera", "api.vendor.example", day=10),
    ]
    truth = {"camera": {("camera", "from-device", "api.vendor.example", "tcp", 443)}}

    rows = cold_start_rows(
        observations,
        truth,
        ScoringConfig(alpha=1.0, beta=0.0, gamma=0.0, theta=0.6),
        windows=[0, 1],
    )

    day_zero = {
        row["method"]: row
        for row in rows
        if row["site_id"] == "site-new" and row["window_days"] == 0
    }
    assert day_zero["local_only"]["mean_semantic_f1"] == 0.0
    assert day_zero["registry_seeded"]["mean_semantic_f1"] == 1.0


def test_pooled_union_and_nearest_site_priors_seed_day_zero() -> None:
    observations = [
        obs("site-a", "camera", "api.vendor.example"),
        obs("site-b", "camera", "api.vendor.example"),
        obs("site-new", "camera", "api.vendor.example", day=10),
    ]
    truth = {"camera": {("camera", "from-device", "api.vendor.example", "tcp", 443)}}

    rows = cold_start_rows(
        observations,
        truth,
        ScoringConfig(alpha=1.0, beta=0.0, gamma=0.0, theta=0.6),
        windows=[0],
    )

    day_zero = {
        row["method"]: row
        for row in rows
        if row["site_id"] == "site-new" and row["window_days"] == 0
    }
    assert day_zero["pooled_union_seeded"]["mean_semantic_f1"] == 1.0
    assert day_zero["nearest_site_seeded"]["mean_semantic_f1"] == 1.0


def test_mismatched_fingerprint_prior_does_not_recover_truth() -> None:
    observations = [
        obs("site-a", "camera", "api.vendor.example"),
        obs("site-b", "thermostat", "api.other.example"),
        obs("site-new", "camera", "api.vendor.example", day=10),
    ]
    truth = {
        "camera": {("camera", "from-device", "api.vendor.example", "tcp", 443)},
        "thermostat": {("thermostat", "from-device", "api.other.example", "tcp", 443)},
    }

    rows = cold_start_rows(
        observations,
        truth,
        ScoringConfig(alpha=1.0, beta=0.0, gamma=0.0, theta=0.6),
        windows=[0],
    )

    day_zero = {
        row["method"]: row
        for row in rows
        if row["site_id"] == "site-new" and row["window_days"] == 0
    }
    assert day_zero["mismatched_fingerprint_seeded"]["mean_semantic_f1"] == 0.0
    assert day_zero["registry_seeded"]["mean_semantic_f1"] == 1.0


def test_cold_start_summary_averages_by_window_and_method() -> None:
    rows = [
        {
            "site_id": "site-a",
            "window_days": 0,
            "method": "local_only",
            "device_count": 1,
            "predicted_endpoint_count": 0,
            "mean_semantic_precision": 0.0,
            "mean_semantic_recall": 0.0,
            "mean_semantic_f1": 0.0,
        },
        {
            "site_id": "site-b",
            "window_days": 0,
            "method": "local_only",
            "device_count": 1,
            "predicted_endpoint_count": 2,
            "mean_semantic_precision": 0.5,
            "mean_semantic_recall": 1.0,
            "mean_semantic_f1": 0.5,
        },
    ]

    summary = summarize_cold_start(rows)

    assert len(summary) == 1
    assert summary[0]["site_count"] == 2
    assert summary[0]["mean_semantic_f1"] == 0.25
    assert summary[0]["mean_predicted_endpoint_count"] == 1.0
