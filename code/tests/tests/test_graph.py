from __future__ import annotations

from pathlib import Path

from dib.evaluation.graph import (
    build_graph,
    export_graph,
    export_graph_confidence,
    export_graph_explanations,
    graph_confidence,
    update_graph,
)


def test_build_graph_empty_input_has_no_nodes() -> None:
    graph = build_graph({})
    assert graph.number_of_nodes() == 0
    assert graph.number_of_edges() == 0


def test_build_graph_does_not_connect_endpoints_across_device_types() -> None:
    sites_by_endpoint = {
        ("camera", "a.example", "https", 443): {"site-a"},
        ("thermostat", "b.example", "https", 443): {"site-a"},
    }
    graph = build_graph(sites_by_endpoint)
    assert graph.number_of_edges() == 0


def test_isolated_endpoint_has_zero_graph_confidence_relative_to_connected_one() -> None:
    sites_by_endpoint = {
        ("camera", "popular-a.example", "https", 443): {"site-a", "site-b", "site-c"},
        ("camera", "popular-b.example", "https", 443): {"site-a", "site-b", "site-c"},
        ("camera", "isolated.example", "https", 443): {"site-a"},
    }
    graph = build_graph(sites_by_endpoint)
    scores = graph_confidence(graph)
    assert scores["camera|isolated.example|https|443"] < scores["camera|popular-a.example|https|443"]


def test_graph_confidence_empty_graph_returns_empty_dict() -> None:
    assert graph_confidence(build_graph({})) == {}


def test_graph_confidence_personalization_favors_trusted_seed() -> None:
    sites_by_endpoint = {
        ("camera", "a.example", "https", 443): {"site-a", "site-b"},
        ("camera", "b.example", "https", 443): {"site-a"},
    }
    graph = build_graph(sites_by_endpoint)
    unbiased = graph_confidence(graph)
    biased = graph_confidence(graph, trusted_seeds={"camera|b.example|https|443"})
    # personalizing toward b should raise its relative confidence vs the unbiased run
    assert biased["camera|b.example|https|443"] >= unbiased["camera|b.example|https|443"]


def test_update_graph_merges_new_endpoint_keys() -> None:
    sites_by_endpoint = {("camera", "a.example", "https", 443): {"site-a"}}
    graph = build_graph(sites_by_endpoint)
    expanded = update_graph(graph, {**sites_by_endpoint, ("camera", "b.example", "https", 443): {"site-a"}})
    assert expanded.number_of_nodes() == 2


def test_update_graph_is_noop_when_no_new_keys() -> None:
    sites_by_endpoint = {("camera", "a.example", "https", 443): {"site-a"}}
    graph = build_graph(sites_by_endpoint)
    same = update_graph(graph, sites_by_endpoint)
    assert same is graph


def test_export_graph_writes_gml_and_summary_csv(tmp_path: Path) -> None:
    sites_by_endpoint = {
        ("camera", "a.example", "https", 443): {"site-a", "site-b"},
        ("camera", "b.example", "https", 443): {"site-a"},
    }
    graph = build_graph(sites_by_endpoint)
    export_graph(graph, tmp_path)
    assert (tmp_path / "graph.gml").exists()
    assert (tmp_path / "graph_summary.csv").exists()
    content = (tmp_path / "graph_summary.csv").read_text()
    assert "node_count" in content


def test_export_graph_confidence_and_explanations_write_csv(tmp_path: Path) -> None:
    sites_by_endpoint = {
        ("camera", "a.example", "https", 443): {"site-a", "site-b"},
        ("camera", "b.example", "https", 443): {"site-a"},
    }
    graph = build_graph(sites_by_endpoint)
    scores = graph_confidence(graph)
    export_graph_confidence(scores, tmp_path)
    export_graph_explanations(graph, scores, tmp_path)
    assert (tmp_path / "graph_confidence.csv").exists()
    explanations = (tmp_path / "graph_explanations.csv").read_text()
    assert "camera|a.example|https|443" in explanations
