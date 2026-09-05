"""Closed-form worst-case bound for a single-shot bounded poisoner.

This module turns the empirical "396 (alpha,beta,gamma,theta) combinations
tested, zero broke through 30% malicious sites" result
(``scripts/poisoning_weight_grid.py`` / ``outputs/poisoning_weight_grid/``)
into a proved guarantee rather than a grid-search observation. The grid
search still matters -- it is the falsification attempt for the proposition
below, run in ``scripts/poison_bound_validation.py`` -- but the reason
poisoning-rejection generalizes to weight/threshold combinations outside the
396 tested cells is this bound, not the sweep itself.

Proposition (single-shot bounded-poisoning rejection).
-----------------------------------------------------
Let a fake endpoint be reported *only* by malicious sites (never
independently corroborated by a genuine site), and let

    f = |malicious sites reporting it| / |eligible sites for the device type|

be the resulting exact malicious fraction. Because DIBScorer.score()
(``dib/evaluation/dib.py``) computes site confidence as
``supporting_sites / eligible_sites`` and the fake endpoint's supporting set
*is* the malicious-site set by construction, its site confidence is exactly

    Cs(fake) = f            (exact, not merely <= f)

Temporal confidence is clipped at 1 by construction
(``min(1.0, 0.7*active_day_ratio + 0.3*frequency_ratio)``), and graph
confidence is PageRank normalized to its own maximum, so both satisfy
Ct, Cg in [0, 1] regardless of how the poisoner times or interlinks its
injected observations. Substituting into the scoring rule:

    score(fake) = alpha*Cs + beta*Ct + gamma*Cg
                <= alpha*f + beta*1 + gamma*1
                 = alpha*f + beta + gamma
                 =: bound(alpha, beta, gamma, f)

Since acceptance requires score(fake) >= theta, and score(fake) can never
exceed ``bound``, acceptance is *impossible* -- for every possible timing
and graph-linkage strategy available to this adversary model, not just the
ones a sweep happened to sample -- whenever

    alpha*f + beta + gamma < theta        (strict)

At equality (``bound == theta``) the bound is tight but not protective: a
poisoner that also saturates Ct = Cg = 1 reaches exactly ``theta`` and is
accepted by the scorer's ``>=`` rule, so equality must NOT be reported as
provably safe.

Scope of the proposition (do not overclaim beyond this):
  * Applies to the single-shot / sustained-persistence bounded-poisoner
    model of ``dib.experiments.poisoning.inject_fake_endpoint`` /
    ``inject_persistent_fake_endpoint``: the fake endpoint has no genuine
    corroborator anywhere in the eligible population.
  * f must be the *true* malicious fraction of eligible sites for that
    device type; it says nothing about a poisoner who can also grow the
    eligible population (a Sybil attacker) -- see
    ``independence_aware_bound`` below for that case.
  * vanilla (identity-counting) site confidence only. The trust-weighted
    and independence-aware mitigations replace Cs with a different quantity
    (see below); the same derivation applies with that quantity substituted
    for f, since the derivation only used Cs <= (malicious share of
    whatever unit the scorer treats as one vote).
"""

from __future__ import annotations

from dataclasses import dataclass

_TOLERANCE = 1e-9


@dataclass(frozen=True, slots=True)
class PoisonBoundEvaluation:
    """Result of evaluating the worst-case bound for one (alpha,beta,gamma,theta,f) cell."""

    alpha: float
    beta: float
    gamma: float
    theta: float
    f: float
    theoretical_bound: float
    margin: float
    provably_safe: bool


def theoretical_bound(alpha: float, beta: float, gamma: float, f: float) -> float:
    """Worst-case fake-endpoint score: alpha*f + beta + gamma.

    ``f`` is the malicious fraction (identity-based Cs) or, for the
    independence-aware variant, the malicious cluster fraction -- whichever
    quantity upper-bounds the scorer's site-confidence term for a fake
    endpoint with no genuine corroborator. Not clipped to [0, 1]: callers
    passing an out-of-range ``f`` get a mathematically consistent (if
    physically meaningless) result rather than a silently wrong clip.
    """
    return alpha * f + beta + gamma


def evaluate_bound(alpha: float, beta: float, gamma: float, theta: float, f: float) -> PoisonBoundEvaluation:
    """Evaluate the worst-case bound and whether it provably rejects the fake endpoint.

    ``provably_safe`` is True iff the bound is *strictly* below theta: at
    exact equality the scorer's ``score >= theta`` acceptance rule would
    still accept a poisoner that saturates Ct = Cg = 1, so equality is
    reported as unsafe (margin 0), not safe.
    """
    bound = theoretical_bound(alpha, beta, gamma, f)
    margin = theta - bound
    return PoisonBoundEvaluation(
        alpha=alpha,
        beta=beta,
        gamma=gamma,
        theta=theta,
        f=f,
        theoretical_bound=bound,
        margin=margin,
        provably_safe=margin > _TOLERANCE,
    )


def cluster_fraction(malicious_clusters: int, genuine_clusters: int) -> float:
    """Malicious share of independent *clusters* rather than identities.

    Used by the independence-aware bound: ``independence.py``'s
    ``effective_independent_count`` collapses sites whose per-device
    endpoint sets are near-identical (Jaccard >= similarity_threshold) into
    one cluster. A templated Sybil flood that reports only the shared fake
    endpoint is maximally near-identical across every Sybil, so it collapses
    to ``malicious_clusters == 1`` regardless of how many Sybil identities
    were registered -- the whole point of the mitigation.
    """
    if malicious_clusters < 0 or genuine_clusters < 0:
        raise ValueError("cluster counts must be non-negative")
    total = malicious_clusters + genuine_clusters
    if total == 0:
        return 0.0
    return malicious_clusters / total


def independence_aware_bound(
    alpha: float, beta: float, gamma: float, theta: float, malicious_clusters: int, genuine_clusters: int
) -> PoisonBoundEvaluation:
    """Independence-aware analogue of ``evaluate_bound``.

    Same derivation, with the identity-based malicious fraction ``f``
    replaced by the malicious *cluster* fraction: independence-aware scoring
    computes Cs as ``effective_independent_count(supporting) /
    effective_independent_count(eligible)`` (``independence.py``), so a
    templated fake endpoint's site confidence is exactly
    ``malicious_clusters / (genuine_clusters + malicious_clusters)`` -- not
    the identity fraction -- whenever the malicious sites collapse into
    ``malicious_clusters`` clusters and every genuine site is its own
    singleton cluster (the common case: independently-operated real sites
    diverge enough in endpoint coverage to stay below the Jaccard
    threshold).
    """
    f_cluster = cluster_fraction(malicious_clusters, genuine_clusters)
    return evaluate_bound(alpha, beta, gamma, theta, f_cluster)
