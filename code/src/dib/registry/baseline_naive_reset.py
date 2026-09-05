"""Measured baseline for Table I's "Approval + review reset" workflow.

Table I (main.tex, Sec. II) compares three defined workflows for one fact on
the same scenario -- local revoke at site s, a peer dispute, then a global
restore -- as a *semantic* comparison, not a measured implementation. This
module makes the middle row (naive review-reset) executable against the same
registry schema and lifecycle primitives DIB itself uses, so the claim that
DIB's provenance check is load-bearing can be measured, not just argued.

The only behavioral difference from services.restore_score() is the removal
of the provenance check in services._transition_all_decisions(): DIB's
restore only resets a REVOKED local decision if the audit history shows the
revocation came from a confirming cross-site dispute (event == "revoke"), and
leaves a site's own local_revoke() decision untouched. This baseline resets
every REVOKED (and DISPUTED) local decision unconditionally -- exactly the
"Reset all revoked records to review" rule Table I attributes to that
workflow. Everything else (schema, seeding, dispute/local-revoke semantics,
optimistic-retry loop) is reused unmodified from services.py so the two are
comparable on identical state transitions.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from dib.registry import services
from dib.registry.db import (
    DECISION_DISPUTED,
    DECISION_MONITOR_ONLY,
    DECISION_REVOKED,
    STATUS_ACTIVE,
    STATUS_DISPUTED,
    STATUS_REVOKED,
    Score,
    ScoreVersion,
)


def _transition_all_decisions_naive_reset(
    session: Session,
    score: Score,
    state: str,
    event: str,
    actor_site_id: str | None,
    reason: str | None,
    *,
    from_states: set[str],
) -> None:
    """services._transition_all_decisions() without the provenance check:
    every local decision in from_states is reset, including one a site set
    itself via local_revoke()."""
    for decision in list(score.local_decisions):
        if decision.state not in from_states:
            continue
        decision.state = state
        decision.flagged_for_review = False
        session.flush()
        services._snapshot_decision(session, decision, event, actor_site_id=actor_site_id, reason=reason)


def restore_score_naive_reset(
    session: Session,
    device_type: str,
    endpoint: str,
    protocol: str,
    port: int,
    actor_site_id: str | None = None,
    reason: str | None = None,
) -> Score | None:
    """Baseline global restore: identical preconditions and score-level
    rollback to services.restore_score(), but fans out to *every* local
    decision in {DISPUTED, REVOKED} unconditionally -- it does not
    distinguish a site's own local_revoke() from a consortium-confirmed
    revoke. This is the "Approval + review reset" row of Table I."""

    def attempt() -> Score | None:
        score = services.get_score(session, device_type, endpoint, protocol, port)
        if score is None:
            return None
        if score.status not in {STATUS_DISPUTED, STATUS_REVOKED}:
            raise services.InvalidStateTransition(
                f"cannot restore {device_type}/{endpoint}/{protocol}/{port}: "
                f"status is {score.status!r}, expected {STATUS_DISPUTED!r} or {STATUS_REVOKED!r}"
            )
        predecessor = session.scalar(
            select(ScoreVersion)
            .where(ScoreVersion.score_id == score.id, ScoreVersion.status == STATUS_ACTIVE)
            .order_by(ScoreVersion.id.desc())
        )
        assert predecessor is not None, "disputed/revoked score has no prior active version to restore"
        score.site_confidence = predecessor.site_confidence
        score.temporal_confidence = predecessor.temporal_confidence
        score.graph_confidence = predecessor.graph_confidence
        score.score = predecessor.score
        score.accepted = predecessor.accepted
        score.tier = predecessor.tier
        score.status = STATUS_ACTIVE
        score.disputed_by = None
        _transition_all_decisions_naive_reset(
            session, score, DECISION_MONITOR_ONLY, "restore_naive", actor_site_id, reason,
            from_states={DECISION_DISPUTED, DECISION_REVOKED},
        )
        session.flush()
        services._snapshot_version(session, score, "restore", actor_site_id, reason)
        return score

    return services._retry_on_conflict(session, attempt)
