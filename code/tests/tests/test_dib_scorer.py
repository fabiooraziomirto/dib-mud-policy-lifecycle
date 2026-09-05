from __future__ import annotations

from datetime import datetime, timezone

from dib.core.models import Observation, endpoint_to_string
from dib.evaluation.dib import DIBScorer, ScoringConfig, accepted_endpoint_keys
from dib.evaluation.graph import graph_confidence


def obs(site: str, fqdn: str, day: int, device: str = "camera") -> Observation:
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


def test_score_is_empty_for_empty_input() -> None:
    assert DIBScorer().score([]) == []


def test_site_confidence_is_supporting_over_eligible_sites() -> None:
    # 3 sites observe "camera"; only 2 of them see endpoint-a, 1 sees endpoint-b.
    observations = [
        obs("site-a", "endpoint-a.example", day=1),
        obs("site-b", "endpoint-a.example", day=1),
        obs("site-c", "endpoint-b.example", day=1),
    ]
    scores = DIBScorer().score(observations)
    by_endpoint = {s.endpoint: s for s in scores}
    assert by_endpoint["endpoint-a.example"].eligible_sites == 3
    assert by_endpoint["endpoint-a.example"].supporting_sites == 2
    assert by_endpoint["endpoint-a.example"].site_confidence == 2 / 3
    assert by_endpoint["endpoint-b.example"].site_confidence == 1 / 3


def test_temporal_confidence_formula_matches_active_day_and_frequency_ratio() -> None:
    # endpoint-a seen on both observed days (2/2 active-day ratio); endpoint-b on only one.
    # device has 3 total observations, endpoint-a contributes 2 of them.
    observations = [
        obs("site-a", "endpoint-a.example", day=1),
        obs("site-a", "endpoint-a.example", day=2),
        obs("site-a", "endpoint-b.example", day=1),
    ]
    scores = DIBScorer().score(observations)
    by_endpoint = {s.endpoint: s for s in scores}
    expected_a = min(1.0, 0.7 * (2 / 2) + 0.3 * (2 / 3))
    expected_b = min(1.0, 0.7 * (1 / 2) + 0.3 * (1 / 3))
    assert by_endpoint["endpoint-a.example"].temporal_confidence == expected_a
    assert by_endpoint["endpoint-b.example"].temporal_confidence == expected_b


def test_final_score_is_weighted_sum_of_three_confidences() -> None:
    observations = [
        obs("site-a", "endpoint-a.example", day=1),
        obs("site-b", "endpoint-a.example", day=1),
    ]
    config = ScoringConfig(alpha=0.5, beta=0.3, gamma=0.2, theta=0.65)
    score = DIBScorer(config).score(observations)[0]
    expected = (
        config.alpha * score.site_confidence
        + config.beta * score.temporal_confidence
        + config.gamma * score.graph_confidence
    )
    assert abs(score.score - expected) < 1e-9


def test_acceptance_respects_theta_threshold() -> None:
    observations = [
        obs("site-a", "endpoint-a.example", day=1),
        obs("site-b", "endpoint-a.example", day=1),
        obs("site-c", "endpoint-a.example", day=1),
    ]
    lenient = DIBScorer(ScoringConfig(theta=0.0)).score(observations)[0]
    strict = DIBScorer(ScoringConfig(theta=1.01)).score(observations)[0]
    assert lenient.accepted is True
    assert strict.accepted is False


def test_single_reporter_is_admitted_with_default_min_reporting_sites() -> None:
    # Pre-fix / default behavior (min_reporting_sites=1): a lenient theta
    # alone is enough, even with only one reporting site -- this is the
    # exact gap the review flagged (score(fake)=0.70>=0.65 with |S_e|=1).
    # Kept as the explicit default-config baseline so the guarded case below
    # is a genuine before/after contrast, not just a different config.
    observations = [obs("site-a", "endpoint-a.example", day=1)]
    scores = DIBScorer(ScoringConfig(alpha=0.6, beta=0.4, gamma=0.0, theta=0.65)).score(observations)
    assert scores[0].supporting_sites == 1
    assert scores[0].accepted is True


def test_single_reporter_is_rejected_with_min_reporting_sites_two() -> None:
    # "Corroboration requires reports from multiple sites" (Sec. IV-B):
    # with the same score-passing observation as above, min_reporting_sites=2
    # must reject it -- score alone is no longer sufficient.
    observations = [obs("site-a", "endpoint-a.example", day=1)]
    scores = DIBScorer(
        ScoringConfig(alpha=0.6, beta=0.4, gamma=0.0, theta=0.65, min_reporting_sites=2)
    ).score(observations)
    assert scores[0].supporting_sites == 1
    assert scores[0].accepted is False


def test_two_distinct_reporters_pass_the_quorum_guard() -> None:
    observations = [
        obs("site-a", "endpoint-a.example", day=1),
        obs("site-b", "endpoint-a.example", day=1),
    ]
    scores = DIBScorer(
        ScoringConfig(alpha=0.6, beta=0.4, gamma=0.0, theta=0.65, min_reporting_sites=2)
    ).score(observations)
    assert scores[0].supporting_sites == 2
    assert scores[0].accepted is True


def test_repeated_observations_from_the_same_site_do_not_inflate_the_quorum() -> None:
    # |S_e| counts distinct sites, not evidence rows: five observations from
    # one site must still count as supporting_sites=1 and fail a
    # min_reporting_sites=2 guard, exactly like the single-observation case.
    observations = [obs("site-a", "endpoint-a.example", day=d) for d in range(1, 6)]
    scores = DIBScorer(
        ScoringConfig(alpha=0.6, beta=0.4, gamma=0.0, theta=0.65, min_reporting_sites=2)
    ).score(observations)
    assert scores[0].supporting_sites == 1
    assert scores[0].accepted is False


def test_min_reporting_sites_below_one_is_rejected_at_construction() -> None:
    import pytest

    with pytest.raises(ValueError):
        ScoringConfig(min_reporting_sites=0)


def test_accepted_endpoint_keys_filters_to_accepted_only() -> None:
    observations = [
        obs("site-a", "popular.example", day=1),
        obs("site-b", "popular.example", day=1),
        obs("site-c", "popular.example", day=1),
        obs("site-a", "rare.example", day=1),
    ]
    scores = DIBScorer(ScoringConfig(theta=0.6)).score(observations)
    keys = accepted_endpoint_keys(scores)
    endpoints = {key[1] for key in keys}
    assert "popular.example" in endpoints
    assert "rare.example" not in endpoints


def test_score_is_deterministic_across_repeated_calls() -> None:
    observations = [
        obs("site-a", "endpoint-a.example", day=1),
        obs("site-b", "endpoint-a.example", day=2),
        obs("site-c", "endpoint-b.example", day=1),
    ]
    first = DIBScorer().score(observations)
    second = DIBScorer().score(observations)
    assert [s.to_dict() for s in first] == [s.to_dict() for s in second]


def test_graph_can_be_disabled_without_building_edges() -> None:
    observations = [
        obs("site-a", "endpoint-a.example", day=1),
        obs("site-a", "endpoint-b.example", day=1),
    ]
    scorer = DIBScorer(ScoringConfig(graph_enabled=False, gamma=0.0))

    scores = scorer.score(observations)

    assert scorer.last_graph is None
    assert all(score.graph_confidence == 0.0 for score in scores)


def test_graph_candidate_limit_bounds_nodes_per_device() -> None:
    observations = [
        obs("site-a", "frequent.example", day=1),
        obs("site-a", "frequent.example", day=2),
        obs("site-a", "second.example", day=1),
        obs("site-a", "excluded.example", day=1),
    ]
    scorer = DIBScorer(ScoringConfig(graph_max_endpoints_per_device=2))

    scores = scorer.score(observations)

    assert len(scores) == 3
    assert scorer.last_graph is not None
    assert scorer.last_graph.number_of_nodes() == 2
    assert sum(score.graph_confidence == 0.0 for score in scores) == 1


def test_target_scoring_preserves_full_registry_graph_context() -> None:
    observations = [
        obs("site-a", "camera-a.example", day=1, device="camera"),
        obs("site-b", "camera-a.example", day=1, device="camera"),
        obs("site-a", "speaker-a.example", day=1, device="speaker"),
        obs("site-b", "speaker-a.example", day=1, device="speaker"),
        obs("site-c", "speaker-b.example", day=1, device="speaker"),
    ]
    full = DIBScorer().score(observations)
    target = DIBScorer().score(observations, target_device_type="camera")
    expected = [score.to_dict() for score in full if score.device_type == "camera"]
    assert [score.to_dict() for score in target] == expected


def test_precomputed_graph_confidence_reuses_identical_target_scores() -> None:
    observations = [
        obs("site-a", "camera-a.example", day=1, device="camera"),
        obs("site-b", "camera-a.example", day=1, device="camera"),
        obs("site-a", "speaker-a.example", day=1, device="speaker"),
    ]
    first_scorer = DIBScorer()
    first = first_scorer.score(observations, target_device_type="camera")
    assert first_scorer.last_graph is not None
    node_confidence = graph_confidence(first_scorer.last_graph)
    override = {
        observation.endpoint_key: node_confidence.get(endpoint_to_string(observation.endpoint_key), 0.0)
        for observation in observations
        if observation.device_type == "camera"
    }
    reused = DIBScorer().score(
        observations,
        target_device_type="camera",
        graph_confidence_override=override,
    )
    assert [score.to_dict() for score in reused] == [score.to_dict() for score in first]
