from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date
from typing import Iterable

from dib.core.models import EndpointScore, Observation, endpoint_to_string
from dib.evaluation.graph import build_graph, graph_confidence
from dib.evaluation.independence import (
    build_site_similarity_graph,
    compute_site_clusters,
    compute_site_endpoint_sets,
    effective_independent_count,
)
from dib.evaluation.intent_overlap import classify_core
from dib.evaluation.trust import compute_site_breadth, compute_site_trust_weights

ELIGIBLE_CLASSES = {"dns", "ntp", "update", "vendor-cloud"}


def admit_auto(
    score: float,
    theta: float,
    endpoint_class: str,
    open_dispute: bool = False,
    supporting_sites: int | None = None,
    min_reporting_sites: int = 1,
) -> bool:
    """[A(e)=1] AND [score(e,d)>=theta] AND [openDispute(e)=0] AND [|S_e|>=min_reporting_sites]
    (main.tex Sec. VI-A/IV-B: "corroboration requires reports from multiple sites").

    open_dispute defaults to False: no registry->scorer channel for a live
    openDispute signal exists yet (see PLAN.md Fase 2.3(e), not yet built).

    supporting_sites defaults to None, which SKIPS the quorum check
    entirely (equivalent to min_reporting_sites=1 regardless of the
    min_reporting_sites argument) so existing callers that only ever cared
    about score/class/dispute keep their exact pre-fix behavior unless they
    opt in by passing |S_e|. Callers that reproduce headline paper numbers
    must pass both supporting_sites and min_reporting_sites explicitly
    (currently min_reporting_sites=2, matching the locked configs'
    corroboration prose) -- see configs/LOCKED_CONFIGS.md.
    """
    if supporting_sites is not None and supporting_sites < min_reporting_sites:
        return False
    return endpoint_class in ELIGIBLE_CLASSES and score >= theta and not open_dispute


@dataclass(frozen=True, slots=True)
class ScoringConfig:
    alpha: float = 0.5
    beta: float = 0.3
    gamma: float = 0.2
    theta: float = 0.65
    # Minimum distinct, authenticated, eligible sites (|S_e|, counted from
    # sites_by_endpoint -- a set[str] of site_id, so a single site reporting
    # the same fact repeatedly never inflates this count) required for
    # admit_auto() to admit a fact. Default 1 preserves pre-fix behavior for
    # any caller that does not set this explicitly; callers reproducing
    # headline paper numbers must set it explicitly (see admit_auto's
    # docstring and configs/LOCKED_CONFIGS.md).
    min_reporting_sites: int = 1
    graph_enabled: bool = True
    graph_max_endpoints_per_device: int | None = None
    trust_weighted: bool = False
    # Must be calibrated on trusted/pre-attack data via
    # dib.evaluation.trust.calibrate_reference_breadth, never on the live
    # population being scored (see trust.py for why).
    trust_reference_breadth: float = 0.0
    independence_aware: bool = False
    independence_similarity_threshold: float = 0.8
    # Combined mitigation: cluster sites by endpoint-set similarity (as
    # independence_aware does), then weight each cluster by the *maximum*
    # trust weight among its members rather than counting each cluster as
    # one vote. This is deliberately not a sum-over-cluster-members: summing
    # would let a large Sybil cluster's individual low weights add back up
    # to a large aggregate, defeating the point of clustering them together
    # in the first place. Mutually exclusive with trust_weighted and
    # independence_aware, which remain available as standalone baselines.
    combined_mitigation: bool = False
    # Sec. VI-D's proposed fix for the channel trust_weighted does not cover: a
    # site on probation still contributes to sites_by_device/sites_by_endpoint
    # (so it still counts, declassed via trust_weighted, toward site_confidence),
    # but its observations are excluded from counts_by_device/days_by_device (so
    # it cannot dilute temporal_confidence for the rest of the profile). Requires
    # trust_weighted or combined_mitigation, since "on probation" is only
    # meaningful relative to a trust signal.
    #
    # "On probation" is deliberately NOT "trust_weight < 1.0" (i.e. breadth below
    # trust_reference_breadth, the median-calibrated target used for Cs): on a
    # homogeneous clean population that median split puts roughly half of
    # genuine, non-adversarial sites below it, which would quarantine them too
    # and move clean-population counts -- measured directly (MEAS 310->234,
    # REF 498->426 on the real corpus) before this floor was introduced.
    # temporal_quarantine_floor must instead be calibrated as the MINIMUM
    # breadth in the trusted/reference population (percentile=0 via
    # dib.evaluation.trust.calibrate_reference_breadth), so that, by
    # construction, no site in that same calibration population can ever fall
    # below it -- clean counts are provably unaffected, not just empirically
    # close.
    temporal_quarantine: bool = False
    temporal_quarantine_floor: float = 0.0
    # Alternative predicate matching what Sec. VI-D actually proposes ("new
    # identities ... until they survive probation"): a site is on probation
    # for temporal_quarantine_tenure_days after its first-seen date, not
    # below a breadth floor. The registry knows a site's registration date
    # by construction, so this needs no clean/attacked oracle and cannot be
    # forged by the contributor the way breadth can be padded. When set
    # (not None), takes precedence over temporal_quarantine_floor entirely.
    temporal_quarantine_tenure_days: int | None = None

    def __post_init__(self) -> None:
        if self.min_reporting_sites < 1:
            raise ValueError("min_reporting_sites must be >= 1")
        if self.graph_max_endpoints_per_device is not None and self.graph_max_endpoints_per_device < 1:
            raise ValueError("graph_max_endpoints_per_device must be positive")
        enabled_mitigations = sum(
            [self.trust_weighted, self.independence_aware, self.combined_mitigation]
        )
        if enabled_mitigations > 1:
            raise ValueError(
                "trust_weighted, independence_aware, and combined_mitigation are mutually "
                "exclusive scoring modes; enable at most one at a time"
            )
        if self.temporal_quarantine and not (self.trust_weighted or self.combined_mitigation):
            raise ValueError(
                "temporal_quarantine requires trust_weighted or combined_mitigation, since "
                "probation status is defined by trust weight"
            )


class DIBScorer:
    def __init__(self, config: ScoringConfig | None = None) -> None:
        self.config = config or ScoringConfig()
        self.last_graph = None

    def score(
        self,
        observations: Iterable[Observation],
        trust_observations: Iterable[Observation] | None = None,
        target_device_type: str | None = None,
        graph_confidence_override: dict[tuple[str, str, str, int], float] | None = None,
    ) -> list[EndpointScore]:
        """Score observations, optionally calibrating live site breadth elsewhere.

        ``target_device_type`` limits only emitted scores and independence-cluster
        construction; all sufficient statistics and the graph still use the full
        observation population. This matters because graph co-occurrence is not
        device-isolated. ``graph_confidence_override`` allows that full graph result
        to be reused across scoring variants evaluated on the same population.
        Existing callers retain the original behavior when these are omitted.
        """
        observations = list(observations)

        trust_weight: dict[str, float] = {}
        if self.config.trust_weighted or self.config.combined_mitigation:
            trust_weight = compute_site_trust_weights(
                trust_observations if trust_observations is not None else observations,
                reference_breadth=self.config.trust_reference_breadth,
            )
        quarantined_sites: set[str] = set()
        if self.config.temporal_quarantine:
            ref_pop = trust_observations if trust_observations is not None else observations
            if self.config.temporal_quarantine_tenure_days is not None:
                first_seen: dict[str, date] = {}
                as_of: date | None = None
                for obs in ref_pop:
                    d = obs.timestamp.date()
                    if as_of is None or d > as_of:
                        as_of = d
                    if obs.site_id not in first_seen or d < first_seen[obs.site_id]:
                        first_seen[obs.site_id] = d
                if as_of is not None:
                    quarantined_sites = {
                        site_id
                        for site_id, fs in first_seen.items()
                        if (as_of - fs).days < self.config.temporal_quarantine_tenure_days
                    }
            else:
                breadth = compute_site_breadth(ref_pop)
                quarantined_sites = {
                    site_id for site_id, b in breadth.items() if b < self.config.temporal_quarantine_floor
                }

        sites_by_device: dict[str, set[str]] = defaultdict(set)
        sites_by_endpoint: dict[tuple[str, str, str, int], set[str]] = defaultdict(set)
        days_by_endpoint: dict[tuple[str, str, str, int], set[date]] = defaultdict(set)
        counts: Counter[tuple[str, str, str, int]] = Counter()
        days_by_device: dict[str, set[date]] = defaultdict(set)
        counts_by_device: Counter[str] = Counter()

        for obs in observations:
            key = obs.endpoint_key
            # Site membership (Se, drives site_confidence) always counts a
            # probationary site, declassed via trust_weight -- quarantine only
            # removes it from the temporal aggregates below.
            sites_by_device[obs.device_type].add(obs.site_id)
            sites_by_endpoint[key].add(obs.site_id)
            if obs.site_id in quarantined_sites:
                continue
            days_by_endpoint[key].add(obs.timestamp.date())
            counts[key] += 1
            days_by_device[obs.device_type].add(obs.timestamp.date())
            counts_by_device[obs.device_type] += 1

        if not sites_by_endpoint:
            return []

        cluster_by_site_by_device: dict[str, dict[str, int]] = {}
        if self.config.independence_aware or self.config.combined_mitigation:
            cluster_device_types = [target_device_type] if target_device_type is not None else sites_by_device
            for device_type in cluster_device_types:
                site_endpoints = compute_site_endpoint_sets(observations, device_type)
                similarity_graph = build_site_similarity_graph(
                    site_endpoints, similarity_threshold=self.config.independence_similarity_threshold
                )
                cluster_by_site_by_device[device_type] = compute_site_clusters(similarity_graph)

        graph_conf: dict[tuple[str, str, str, int], float] = graph_confidence_override or {}
        if self.config.graph_enabled and graph_confidence_override is None:
            graph_inputs = sites_by_endpoint
            limit = self.config.graph_max_endpoints_per_device
            if limit is not None:
                selected: dict[tuple[str, str, str, int], set[str]] = {}
                keys_by_device: dict[str, list[tuple[str, str, str, int]]] = defaultdict(list)
                for key in sites_by_endpoint:
                    keys_by_device[key[0]].append(key)
                for device_keys in keys_by_device.values():
                    ranked = sorted(
                        device_keys,
                        key=lambda key: (-len(sites_by_endpoint[key]), -counts[key], key),
                    )
                    for key in ranked[:limit]:
                        selected[key] = sites_by_endpoint[key]
                graph_inputs = selected
            co_occurrence_graph = build_graph(graph_inputs)
            self.last_graph = co_occurrence_graph
            graph_conf_by_node = graph_confidence(co_occurrence_graph)
            graph_conf = {
                key: graph_conf_by_node.get(endpoint_to_string(key), 0.0) for key in sites_by_endpoint
            }
        elif not self.config.graph_enabled:
            self.last_graph = None
        scores: list[EndpointScore] = []
        # Iterate over every observed endpoint (sites_by_endpoint), not just those
        # with non-quarantined temporal evidence (counts): an endpoint reported
        # solely by sites still on probation must still be scored -- with
        # temporal_confidence correctly at/near 0 until that evidence is vouched
        # for, rather than silently dropped from the output.
        for key in sorted(sites_by_endpoint):
            device_type, endpoint, protocol, port = key
            if target_device_type is not None and device_type != target_device_type:
                continue
            eligible_sites = len(sites_by_device[device_type])
            supporting_sites = len(sites_by_endpoint[key])
            if self.config.trust_weighted:
                eligible_weight = sum(trust_weight.get(s, 0.0) for s in sites_by_device[device_type])
                supporting_weight = sum(trust_weight.get(s, 0.0) for s in sites_by_endpoint[key])
                site_conf = supporting_weight / eligible_weight if eligible_weight else 0.0
            elif self.config.independence_aware:
                cluster_by_site = cluster_by_site_by_device.get(device_type, {})
                effective_eligible = effective_independent_count(sites_by_device[device_type], cluster_by_site)
                effective_supporting = effective_independent_count(sites_by_endpoint[key], cluster_by_site)
                site_conf = effective_supporting / effective_eligible if effective_eligible else 0.0
            elif self.config.combined_mitigation:
                cluster_by_site = cluster_by_site_by_device.get(device_type, {})
                eligible_weight = max_trust_weight_per_cluster(
                    sites_by_device[device_type], cluster_by_site, trust_weight
                )
                supporting_weight = max_trust_weight_per_cluster(
                    sites_by_endpoint[key], cluster_by_site, trust_weight
                )
                site_conf = supporting_weight / eligible_weight if eligible_weight else 0.0
            else:
                site_conf = supporting_sites / eligible_sites if eligible_sites else 0.0
            active_day_ratio = len(days_by_endpoint[key]) / max(len(days_by_device[device_type]), 1)
            frequency_ratio = counts[key] / max(counts_by_device[device_type], 1)
            temporal_conf = min(1.0, (0.7 * active_day_ratio) + (0.3 * frequency_ratio))
            graph = graph_conf.get(key, 0.0)
            final = (
                self.config.alpha * site_conf
                + self.config.beta * temporal_conf
                + self.config.gamma * graph
            )
            endpoint_class = classify_core(endpoint, protocol, port)
            scores.append(
                EndpointScore(
                    device_type=device_type,
                    endpoint=endpoint,
                    protocol=protocol,
                    port=port,
                    site_confidence=site_conf,
                    temporal_confidence=temporal_conf,
                    graph_confidence=graph,
                    score=final,
                    accepted=admit_auto(
                        final,
                        self.config.theta,
                        endpoint_class,
                        supporting_sites=supporting_sites,
                        min_reporting_sites=self.config.min_reporting_sites,
                    ),
                    supporting_sites=supporting_sites,
                    eligible_sites=eligible_sites,
                    endpoint_class=endpoint_class,
                )
            )
        return scores


def max_trust_weight_per_cluster(
    sites: set[str], cluster_by_site: dict[str, int], trust_weight: dict[str, float]
) -> float:
    """Sum, over each distinct independent cluster represented in ``sites``, the
    maximum trust weight among that cluster's members. Used by the combined
    mitigation: clustering already collapses near-identical (templated Sybil)
    sites into one independent source, so weighting by a per-cluster maximum
    (rather than summing every member's individual weight) avoids double
    counting a single Sybil cluster as if it were many independent voters --
    that would silently undo the clustering step's purpose."""
    best_by_cluster: dict[int | str, float] = {}
    for site_id in sites:
        cluster_id = cluster_by_site.get(site_id, site_id)
        weight = trust_weight.get(site_id, 0.0)
        if weight > best_by_cluster.get(cluster_id, -1.0):
            best_by_cluster[cluster_id] = weight
    return sum(best_by_cluster.values())


def accepted_endpoint_keys(scores: list[EndpointScore]) -> set[tuple[str, str, str, int]]:
    return {score.endpoint_key for score in scores if score.accepted}
