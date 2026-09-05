from __future__ import annotations

from collections import defaultdict

import networkx as nx

from dib.core.models import Observation


def compute_site_endpoint_sets(
    observations: list[Observation], device_type: str
) -> dict[str, frozenset[tuple[str, str, str, int]]]:
    """Each site's set of distinct endpoint keys observed for `device_type`."""
    by_site: dict[str, set[tuple[str, str, str, int]]] = defaultdict(set)
    for obs in observations:
        if obs.device_type != device_type:
            continue
        by_site[obs.site_id].add(obs.endpoint_key)
    return {site_id: frozenset(keys) for site_id, keys in by_site.items()}


def jaccard_similarity(a: frozenset, b: frozenset) -> float:
    if not a and not b:
        return 0.0
    union = len(a | b)
    if union == 0:
        return 0.0
    return len(a & b) / union


def build_site_similarity_graph(
    site_endpoints: dict[str, frozenset], similarity_threshold: float = 0.8
) -> nx.Graph:
    """Sites are nodes; an edge connects two sites whose endpoint sets for this
    device type are near-identical (Jaccard similarity at or above the threshold).
    Templated, cookie-cutter Sybils observing the same fabricated endpoint look
    near-identical to each other and cluster together; independently-operated
    real sites naturally diverge (different regional endpoints, different subsets
    of a device's full behaviour) and stay separate.
    """
    graph = nx.Graph()
    sites = list(site_endpoints)
    graph.add_nodes_from(sites)
    for i, site_a in enumerate(sites):
        for site_b in sites[i + 1 :]:
            similarity = jaccard_similarity(site_endpoints[site_a], site_endpoints[site_b])
            if similarity >= similarity_threshold:
                graph.add_edge(site_a, site_b, weight=similarity)
    return graph


def compute_site_clusters(graph: nx.Graph) -> dict[str, int]:
    """Maps each site to a cluster id (connected component index). Sites with
    no near-identical peers form their own singleton cluster."""
    cluster_by_site: dict[str, int] = {}
    for cluster_id, component in enumerate(nx.connected_components(graph)):
        for site_id in component:
            cluster_by_site[site_id] = cluster_id
    return cluster_by_site


def effective_independent_count(sites: set[str], cluster_by_site: dict[str, int]) -> int:
    """Number of distinct clusters represented among `sites`, instead of len(sites).
    A hundred near-identical Sybils sharing one cluster count as one independent
    source; genuinely independent sites each count separately."""
    clusters = {cluster_by_site.get(site_id, site_id) for site_id in sites}
    return len(clusters)
