"""G4 (non-destructive rescoring), checked as one property rather than per case.

The individual rescore tests in test_registry.py each pin one situation (an
Active record flagged, a stale flag cleared, a MonitorOnly record left alone).
The paper's G4 is the stronger, general statement: *no* rescoring path writes
site-local authority state. Evolving evidence may set or clear a review flag
and append audit history, and it may do nothing else -- it may not change a
decision's state, create a decision, delete one, or change what a site exports.

This module checks that across the decision states rescoring can encounter, at
three sites at once, under repeated up-and-down score movement.
"""
from __future__ import annotations

import os
import tempfile

import dib.registry.db as db
from dib.registry import services

FACT = ("camera", "api.vendor.com", "https", 443)


def _fresh_session():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.environ["DIB_DATABASE_URL"] = f"sqlite:///{path}"
    db._engine = None
    db._SessionLocal = None
    return db.get_session()


def _rescore(session, *, accepted: bool) -> None:
    """One routine evidence recompute, in whichever direction."""
    high = {"site_confidence": 0.9, "temporal_confidence": 0.8, "graph_confidence": 0.7, "score": 0.85}
    low = {"site_confidence": 0.1, "temporal_confidence": 0.1, "graph_confidence": 0.0, "score": 0.2}
    services.upsert_score(session, {
        "device_type": FACT[0], "endpoint": FACT[1], "protocol": FACT[2], "port": FACT[3],
        **(high if accepted else low), "accepted": accepted,
    })
    session.commit()


def _authority(session) -> dict[str, tuple[str, int]]:
    """Every site's authority state for the fact: (state, number of history entries)."""
    score = services.get_score(session, *FACT)
    out = {}
    for decision in score.local_decisions:
        history = services.get_local_decision_history(session, decision.id)
        out[decision.site_id] = (decision.state, len(history))
    return out


def _exported_aces(session, site_id: str) -> list:
    """The site's exported from-device ACEs, as a comparable list of endpoint keys."""
    mud = services.export_active_mud(session, site_id, FACT[0])
    return sorted(
        (e.device_type, e.endpoint, e.protocol, e.port) for e in mud.exported_endpoints
    )


def _three_site_fixture(session):
    """site-a Active, site-b MonitorOnly, site-c Revoked (Local)."""
    services.upsert_score(session, {
        "device_type": FACT[0], "endpoint": FACT[1], "protocol": FACT[2], "port": FACT[3],
        "site_confidence": 0.9, "temporal_confidence": 0.8, "graph_confidence": 0.7,
        "score": 0.85, "accepted": True,
    })
    session.commit()
    services.query_score(session, "site-a", *FACT)
    services.operator_commit(session, "site-a", *FACT)
    services.query_score(session, "site-b", *FACT)
    services.query_score(session, "site-c", *FACT)
    services.operator_commit(session, "site-c", *FACT)
    services.local_revoke(session, "site-c", *FACT, reason="local policy")
    session.commit()


def test_rescoring_never_changes_a_decision_state_at_any_site() -> None:
    session = _fresh_session()
    try:
        _three_site_fixture(session)
        before = _authority(session)
        assert {site: state for site, (state, _) in before.items()} == {
            "site-a": db.DECISION_ACTIVE,
            "site-b": db.DECISION_MONITOR_ONLY,
            "site-c": db.DECISION_REVOKED,
        }

        for accepted in (False, True, False, True, False):
            _rescore(session, accepted=accepted)
            states = {site: state for site, (state, _) in _authority(session).items()}
            assert states == {
                "site-a": db.DECISION_ACTIVE,
                "site-b": db.DECISION_MONITOR_ONLY,
                "site-c": db.DECISION_REVOKED,
            }, f"rescoring to accepted={accepted} moved a local authority record"
    finally:
        session.close()


def test_rescoring_neither_creates_nor_deletes_local_authority_records() -> None:
    session = _fresh_session()
    try:
        _three_site_fixture(session)
        sites_before = set(_authority(session))
        for accepted in (False, True, False):
            _rescore(session, accepted=accepted)
            assert set(_authority(session)) == sites_before
        # A site that never queried the fact gains no record from any rescore.
        assert "site-d" not in sites_before
    finally:
        session.close()


def test_rescoring_leaves_the_exported_policy_unchanged() -> None:
    session = _fresh_session()
    try:
        _three_site_fixture(session)
        exported_before = _exported_aces(session, "site-a")
        assert exported_before, "fixture must export something for the check to mean anything"
        for accepted in (False, True, False):
            _rescore(session, accepted=accepted)
            assert _exported_aces(session, "site-a") == exported_before
            # A flagged Active fact stays exported; a MonitorOnly one never exports.
            assert _exported_aces(session, "site-b") == []
            assert _exported_aces(session, "site-c") == []
    finally:
        session.close()


def test_rescoring_only_appends_review_flag_events_to_the_audit_history() -> None:
    session = _fresh_session()
    try:
        _three_site_fixture(session)
        score = services.get_score(session, *FACT)
        decisions = {d.site_id: d for d in score.local_decisions}
        baseline = {
            site: [e.event for e in services.get_local_decision_history(session, d.id)]
            for site, d in decisions.items()
        }

        for accepted in (False, True, False):
            _rescore(session, accepted=accepted)

        for site, d in decisions.items():
            events = [e.event for e in services.get_local_decision_history(session, d.id)]
            assert events[: len(baseline[site])] == baseline[site], "rescoring rewrote history"
            appended = set(events[len(baseline[site]):])
            assert appended <= {db.EVENT_AUTO_FLAG_FOR_REVIEW, "auto_clear_review"}, (
                f"rescoring appended a non-flag event at {site}: {appended}"
            )
        # Only the Active record is flagged; review pressure is not applied to
        # records that hold no permission.
        assert decisions["site-a"].flagged_for_review is True
        assert decisions["site-b"].flagged_for_review is False
        assert decisions["site-c"].flagged_for_review is False
    finally:
        session.close()


def test_rescoring_upward_does_not_manufacture_a_grant() -> None:
    """Evidence improving is not approval: nothing may become Active on its own."""
    session = _fresh_session()
    try:
        _three_site_fixture(session)
        _rescore(session, accepted=False)
        _rescore(session, accepted=True)
        states = {site: state for site, (state, _) in _authority(session).items()}
        assert states["site-b"] == db.DECISION_MONITOR_ONLY
        assert states["site-c"] == db.DECISION_REVOKED
        # And the locally revoked record still refuses to export after any rescore.
        assert _exported_aces(session, "site-c") == []
    finally:
        session.close()
