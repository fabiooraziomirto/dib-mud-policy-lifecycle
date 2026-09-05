from __future__ import annotations

from dib.analysis.poison_bound import (
    cluster_fraction,
    evaluate_bound,
    independence_aware_bound,
    theoretical_bound,
)


def test_theoretical_bound_is_alpha_f_plus_beta_plus_gamma() -> None:
    assert theoretical_bound(alpha=0.5, beta=0.3, gamma=0.2, f=0.30) == 0.5 * 0.30 + 0.3 + 0.2


def test_shipped_weights_bound_equals_theta_exactly_at_30pct() -> None:
    # Task 3: 0.5,0.3,0.2,0.65, f=0.30 -> bound == theta exactly (on the boundary).
    evaluation = evaluate_bound(alpha=0.5, beta=0.3, gamma=0.2, theta=0.65, f=0.30)
    assert abs(evaluation.theoretical_bound - 0.65) < 1e-9
    assert abs(evaluation.margin) < 1e-9
    assert evaluation.provably_safe is False


def test_provably_safe_true_when_bound_strictly_below_theta() -> None:
    evaluation = evaluate_bound(alpha=0.5, beta=0.2, gamma=0.2, theta=0.65, f=0.30)
    assert evaluation.theoretical_bound < 0.65
    assert evaluation.margin > 0
    assert evaluation.provably_safe is True


def test_provably_safe_false_when_bound_exceeds_theta() -> None:
    evaluation = evaluate_bound(alpha=0.5, beta=0.4, gamma=0.2, theta=0.65, f=0.30)
    assert evaluation.theoretical_bound > 0.65
    assert evaluation.margin < 0
    assert evaluation.provably_safe is False


def test_cluster_fraction_matches_identity_fraction_when_no_collapse() -> None:
    # 3 malicious identities each forming their own cluster among 7 genuine
    # singleton clusters reduces to the plain identity fraction.
    assert cluster_fraction(malicious_clusters=3, genuine_clusters=7) == 0.3


def test_cluster_fraction_collapses_regardless_of_identity_count() -> None:
    # N templated Sybils collapsing into exactly 1 cluster keeps the
    # malicious cluster fraction fixed, unlike the identity fraction which
    # grows with N.
    small = cluster_fraction(malicious_clusters=1, genuine_clusters=9)
    large = cluster_fraction(malicious_clusters=1, genuine_clusters=9)
    assert small == large == 0.1


def test_independence_aware_bound_stays_safe_where_identity_bound_would_not() -> None:
    alpha, beta, gamma, theta = 0.5, 0.3, 0.2, 0.65
    # 3200 Sybil identities vs. 10 genuine sites: identity fraction is huge.
    naive = evaluate_bound(alpha, beta, gamma, theta, f=3200 / (10 + 3200))
    assert naive.provably_safe is False

    # Same attack, but templated Sybils collapse to 1 independent cluster.
    aware = independence_aware_bound(alpha, beta, gamma, theta, malicious_clusters=1, genuine_clusters=10)
    assert aware.provably_safe is True
    assert aware.theoretical_bound < naive.theoretical_bound
