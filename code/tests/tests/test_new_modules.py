from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from dib.core.models import Observation
from dib.evaluation.dib import DIBScorer, ScoringConfig
from dib.evaluation.global_profiles import build_global_profiles
from dib.evaluation.graph import build_graph, graph_confidence
from dib.evaluation.local_profiling import build_all_local_profiles
from dib.evaluation.statistics import compare_paired, confidence_interval


def obs(site: str, device: str, fqdn: str, day: int = 1) -> Observation:
    return Observation(
        site_id=site,
        device_id=f"{site}-{device}",
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
    return [
        obs("site-a", "cam", "api.vendor.example"),
        obs("site-b", "cam", "api.vendor.example"),
        obs("site-c", "cam", "api.vendor.example"),
        obs("site-a", "cam", "rare.example"),
    ]


def test_build_graph_connects_endpoints_sharing_sites() -> None:
    sites_by_endpoint = {
        ("camera", "api.vendor.example", "https", 443): {"site-a", "site-b"},
        ("camera", "rare.example", "https", 443): {"site-a"},
    }
    graph = build_graph(sites_by_endpoint)
    assert graph.number_of_nodes() == 2
    assert graph.has_edge("camera|api.vendor.example|https|443", "camera|rare.example|https|443")


def test_graph_confidence_is_normalized_zero_to_one() -> None:
    sites_by_endpoint = {
        ("camera", "a.example", "https", 443): {"site-a", "site-b"},
        ("camera", "b.example", "https", 443): {"site-a"},
    }
    graph = build_graph(sites_by_endpoint)
    scores = graph_confidence(graph)
    assert all(0.0 <= value <= 1.0 for value in scores.values())


def test_build_all_local_profiles_has_first_last_seen_and_count() -> None:
    profiles = build_all_local_profiles(sample_observations())
    profile = next(p for p in profiles if p.site_id == "site-a")
    endpoint = next(e for e in profile.endpoints if e.fqdn == "api.vendor.example")
    assert endpoint.count == 1
    assert endpoint.first_seen == endpoint.last_seen


def test_global_profiles_carry_explanation_breakdown() -> None:
    scores = DIBScorer(ScoringConfig(theta=0.6)).score(sample_observations())
    profiles = build_global_profiles(scores, ScoringConfig(theta=0.6))
    endpoint = next(e for e in profiles["camera"]["endpoints"] if e["endpoint"] == "api.vendor.example")
    assert endpoint["accepted"] is True
    assert set(endpoint["explanation"]) >= {"site_confidence", "temporal_confidence", "graph_confidence", "formula"}


def test_confidence_interval_widens_with_more_variance() -> None:
    tight = confidence_interval([0.5, 0.5, 0.5, 0.5])
    wide = confidence_interval([0.1, 0.9, 0.2, 0.8])
    assert (tight[1] - tight[0]) <= (wide[1] - wide[0])


def test_compare_paired_identical_samples_has_zero_mean_diff() -> None:
    result = compare_paired("a", [0.5, 0.6, 0.7], "b", [0.5, 0.6, 0.7])
    assert result.mean_diff == 0.0
