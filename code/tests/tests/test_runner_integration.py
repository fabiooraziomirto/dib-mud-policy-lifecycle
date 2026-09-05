from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path

from dib.core.models import Observation
from dib.evaluation.dib import DIBScorer, ScoringConfig
from dib.experiments.runner import run_reconstruction


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


def sample_observations() -> list[Observation]:
    return [
        obs("site-a", "camera", "api.vendor.example"),
        obs("site-b", "camera", "api.vendor.example"),
        obs("site-c", "camera", "api.vendor.example"),
        obs("site-a", "camera", "rare.example"),
        obs("site-a", "thermostat", "thermo.vendor.example"),
        obs("site-b", "thermostat", "thermo.vendor.example"),
    ]


def minimal_config() -> dict:
    return {
        "scoring": {"alpha": 0.5, "beta": 0.3, "gamma": 0.2, "theta": 0.65, "min_reporting_sites": 1},
        "baselines": {"weighted_threshold": 0.6, "frequency_min_count": 1},
    }


def test_run_reconstruction_writes_final_scores_matching_direct_scorer_call(tmp_path: Path) -> None:
    observations = sample_observations()
    config = minimal_config()
    run_reconstruction(observations, tmp_path, config)

    final_scores_path = tmp_path / "final_scores.csv"
    assert final_scores_path.exists()

    with final_scores_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    direct_scores = DIBScorer(ScoringConfig(**config["scoring"])).score(observations)
    assert len(rows) == len(direct_scores)

    by_endpoint = {row["endpoint"]: row for row in rows}
    for score in direct_scores:
        row = by_endpoint[score.endpoint]
        assert row["device_type"] == score.device_type
        assert float(row["site_confidence"]) == round(score.site_confidence, 6)
        assert float(row["score"]) == round(score.score, 6)
        assert (row["accepted"] == "True") == score.accepted


def test_run_reconstruction_writes_baseline_comparison_files(tmp_path: Path) -> None:
    run_reconstruction(sample_observations(), tmp_path, minimal_config())
    baselines_dir = tmp_path / "experiments" / "reconstruction" / "baselines"
    assert (baselines_dir / "local_profiling_profile.csv").exists()
    assert (baselines_dir / "majority_voting_profile.csv").exists()
    summary_path = tmp_path / "experiments" / "reconstruction" / "profile_reconstruction_summary.csv"
    assert summary_path.exists()


def test_run_reconstruction_writes_graph_and_global_profile_outputs(tmp_path: Path) -> None:
    run_reconstruction(sample_observations(), tmp_path, minimal_config())
    assert (tmp_path / "graph.gml").exists()
    assert (tmp_path / "graph_confidence.csv").exists()
    assert (tmp_path / "global_profiles").exists()
    assert (tmp_path / "local_profiles").exists()
