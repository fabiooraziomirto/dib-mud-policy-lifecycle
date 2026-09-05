from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import networkx as nx

from dib.core.io import write_csv
from dib.core.models import endpoint_to_string


EndpointKey = tuple[str, str, str, int]


def build_graph(sites_by_endpoint: dict[EndpointKey, set[str]]) -> nx.Graph:
    """Co-occurrence graph: nodes are endpoint keys, edges weighted by shared supporting sites."""
    graph = nx.Graph()
    keys = list(sites_by_endpoint)
    for key in keys:
        graph.add_node(endpoint_to_string(key), device_type=key[0])
    by_device: dict[str, list[EndpointKey]] = defaultdict(list)
    for key in keys:
        by_device[key[0]].append(key)
    for device_type, device_keys in by_device.items():
        for i, key_a in enumerate(device_keys):
            for key_b in device_keys[i + 1 :]:
                shared = len(sites_by_endpoint[key_a] & sites_by_endpoint[key_b])
                if shared > 0:
                    graph.add_edge(endpoint_to_string(key_a), endpoint_to_string(key_b), weight=shared)
    return graph


def update_graph(graph: nx.Graph, sites_by_endpoint: dict[EndpointKey, set[str]]) -> nx.Graph:
    """Rebuild edges for any endpoint keys not already present in the graph."""
    new_keys = [key for key in sites_by_endpoint if endpoint_to_string(key) not in graph]
    if not new_keys:
        return graph
    merged = build_graph(sites_by_endpoint)
    return merged


def graph_confidence(
    graph: nx.Graph,
    trusted_seeds: set[str] | None = None,
) -> dict[str, float]:
    """Weighted (optionally personalized) PageRank over the endpoint co-occurrence graph."""
    if graph.number_of_nodes() == 0:
        return {}
    personalization = None
    if trusted_seeds:
        seeds = trusted_seeds & set(graph.nodes)
        if seeds:
            personalization = {node: (1.0 if node in seeds else 0.0) for node in graph.nodes}
    try:
        scores = nx.pagerank(graph, weight="weight", personalization=personalization)
    except nx.PowerIterationFailedConvergence:
        scores = {node: 1.0 / graph.number_of_nodes() for node in graph.nodes}
    max_score = max(scores.values(), default=0.0)
    if max_score == 0:
        return {node: 0.0 for node in scores}
    return {node: value / max_score for node, value in scores.items()}


def export_graph(graph: nx.Graph, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    nx.write_gml(graph, output_dir / "graph.gml")
    write_csv(
        output_dir / "graph_summary.csv",
        [
            {
                "node_count": graph.number_of_nodes(),
                "edge_count": graph.number_of_edges(),
                "density": round(nx.density(graph), 6) if graph.number_of_nodes() > 1 else 0.0,
                "connected_components": nx.number_connected_components(graph),
            }
        ],
        ["node_count", "edge_count", "density", "connected_components"],
    )


def export_graph_confidence(scores: dict[str, float], output_dir: Path) -> None:
    rows = [{"endpoint_key": node, "graph_confidence": round(value, 6)} for node, value in sorted(scores.items())]
    write_csv(output_dir / "graph_confidence.csv", rows, ["endpoint_key", "graph_confidence"])


def export_graph_explanations(graph: nx.Graph, scores: dict[str, float], output_dir: Path, top_n: int = 5) -> None:
    rows = []
    for node in sorted(graph.nodes):
        neighbors = sorted(
            graph[node].items(), key=lambda item: item[1].get("weight", 0), reverse=True
        )[:top_n]
        explanation = "; ".join(f"{neighbor}(w={data.get('weight', 0)})" for neighbor, data in neighbors)
        rows.append(
            {
                "endpoint_key": node,
                "graph_confidence": round(scores.get(node, 0.0), 6),
                "degree": graph.degree(node),
                "top_neighbors": explanation,
            }
        )
    write_csv(
        output_dir / "graph_explanations.csv",
        rows,
        ["endpoint_key", "graph_confidence", "degree", "top_neighbors"],
    )
