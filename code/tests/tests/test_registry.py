from __future__ import annotations

import os
import tempfile
import threading
from datetime import datetime, timezone

import dib.registry.db as db
from dib.registry import services
from dib.registry.api import health


def _fresh_session():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.environ["DIB_DATABASE_URL"] = f"sqlite:///{path}"
    db._engine = None
    db._SessionLocal = None
    return db.get_session()


def test_health_endpoint() -> None:
    assert health() == {"status": "ok"}


def test_observation_write_is_idempotent() -> None:
    session = _fresh_session()
    payload = {
        "site_id": "site-a",
        "device_id": "cam1",
        "device_type": "camera",
        "fqdn": "api.vendor.com",
        "remote_ip": None,
        "protocol": "https",
        "port": 443,
        "timestamp": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "source_dataset": "test",
        "evidence_type": "flow",
    }
    try:
        first, first_created = services.record_observation(session, payload)
        session.commit()
        second, second_created = services.record_observation(session, payload)
        assert first_created is True
        assert second_created is False
        assert first.id == second.id
    finally:
        session.close()


def test_profile_and_global_profile_and_score_roundtrip() -> None:
    session = _fresh_session()
    profile = {
        "site_id": "site-a",
        "device_type": "camera",
        "endpoints": [
            {"fqdn": "api.vendor.com", "protocol": "https", "port": 443, "count": 5}
        ],
    }
    try:
        stored = services.upsert_profile(
            session,
            profile["site_id"],
            profile["device_type"],
            profile["endpoints"],
        )
        assert stored.site_id == "site-a"
        session.commit()

        global_profile = services.global_profile(session, "camera")
        assert global_profile["site_count"] == 1
        assert global_profile["endpoints"][0]["fqdn"] == "api.vendor.com"

        score = {
            "device_type": "camera",
            "endpoint": "api.vendor.com",
            "protocol": "https",
            "port": 443,
            "site_confidence": 0.9,
            "temporal_confidence": 0.8,
            "graph_confidence": 0.7,
            "score": 0.85,
            "accepted": True,
        }
        services.upsert_score(session, score)
        session.commit()
        fetched = services.get_score(session, "camera", "api.vendor.com", "https", 443)
        missing = services.get_score(session, "camera", "missing", "https", 443)
        assert fetched is not None
        assert fetched.accepted is True
        assert fetched.tier == db.TIER_CORROBORATED
        assert fetched.status == db.STATUS_ACTIVE
        assert missing is None
    finally:
        session.close()


def _seeded_score(session) -> None:
    services.upsert_profile(
        session, "site-a", "camera",
        [{"fqdn": "api.vendor.com", "protocol": "https", "port": 443, "count": 5}],
    )
    services.upsert_score(session, {
        "device_type": "camera",
        "endpoint": "api.vendor.com",
        "protocol": "https",
        "port": 443,
        "site_confidence": 0.9,
        "temporal_confidence": 0.8,
        "graph_confidence": 0.7,
        "score": 0.85,
        "accepted": True,
    })
    session.commit()


def test_attest_score_returns_none_for_missing_score() -> None:
    session = _fresh_session()
    try:
        assert services.attest_score(session, "camera", "missing", "https", 443, "site-b") is None
    finally:
        session.close()


def test_attest_promotes_tier_after_threshold_distinct_sites() -> None:
    session = _fresh_session()
    try:
        _seeded_score(session)
        for site in ("site-b", "site-c"):
            score = services.attest_score(session, "camera", "api.vendor.com", "https", 443, site)
            session.commit()
            assert score.tier == db.TIER_CORROBORATED
        score = services.attest_score(session, "camera", "api.vendor.com", "https", 443, "site-d")
        session.commit()
        assert score.positive_attestations == 3
        assert score.tier == db.TIER_CONSORTIUM_ATTESTED

        # Same site re-attesting must not inflate the distinct-site count.
        score = services.attest_score(session, "camera", "api.vendor.com", "https", 443, "site-d")
        session.commit()
        assert score.positive_attestations == 3
    finally:
        session.close()


def test_single_dispute_moves_active_to_disputed_without_revoking() -> None:
    session = _fresh_session()
    try:
        _seeded_score(session)
        score = services.dispute_score(session, "camera", "api.vendor.com", "https", 443, "site-b", reason="unexpected endpoint")
        session.commit()
        assert score.status == db.STATUS_DISPUTED
        assert score.accepted is True
        assert score.disputed_by == "site-b"
    finally:
        session.close()


def test_first_dispute_moves_active_and_monitor_only_records_to_disputed() -> None:
    session = _fresh_session()
    try:
        _seeded_score(session)
        active = services.query_score(
            session, "site-a", "camera", "api.vendor.com", "https", 443
        )
        monitor_only = services.query_score(
            session, "site-b", "camera", "api.vendor.com", "https", 443
        )
        services.operator_commit(
            session, "site-a", "camera", "api.vendor.com", "https", 443
        )
        session.commit()

        services.dispute_score(
            session, "camera", "api.vendor.com", "https", 443, "site-c"
        )
        session.commit()

        assert active.state == db.DECISION_DISPUTED
        assert monitor_only.state == db.DECISION_DISPUTED
    finally:
        session.close()


def test_same_site_redisputing_does_not_confirm_revocation() -> None:
    session = _fresh_session()
    try:
        _seeded_score(session)
        services.dispute_score(session, "camera", "api.vendor.com", "https", 443, "site-b")
        session.commit()
        score = services.dispute_score(session, "camera", "api.vendor.com", "https", 443, "site-b")
        session.commit()
        assert score.status == db.STATUS_DISPUTED
    finally:
        session.close()


def test_second_site_disputing_confirms_revoke_but_does_not_auto_restore() -> None:
    session = _fresh_session()
    try:
        _seeded_score(session)
        decision = services.query_score(
            session, "site-a", "camera", "api.vendor.com", "https", 443
        )
        services.operator_commit(
            session, "site-a", "camera", "api.vendor.com", "https", 443
        )
        session.commit()
        services.dispute_score(session, "camera", "api.vendor.com", "https", 443, "site-b")
        session.commit()
        score = services.dispute_score(session, "camera", "api.vendor.com", "https", 443, "site-c")
        session.commit()

        assert score.status == db.STATUS_REVOKED
        assert decision.state == db.DECISION_REVOKED

        history = services.get_score_history(session, score.id)
        events = [entry.event for entry in history]
        assert events == ["upsert", "dispute", "revoke"]
        assert [entry.version for entry in history] == [1, 2, 3]
    finally:
        session.close()


def test_restore_score_after_explicit_call_reinstates_staged_not_active() -> None:
    session = _fresh_session()
    try:
        _seeded_score(session)
        decision = services.query_score(
            session, "site-a", "camera", "api.vendor.com", "https", 443
        )
        services.operator_commit(
            session, "site-a", "camera", "api.vendor.com", "https", 443
        )
        session.commit()

        services.dispute_score(session, "camera", "api.vendor.com", "https", 443, "site-b")
        session.commit()
        services.dispute_score(session, "camera", "api.vendor.com", "https", 443, "site-c")
        session.commit()

        score = services.restore_score(session, "camera", "api.vendor.com", "https", 443)
        session.commit()

        assert score.status == db.STATUS_ACTIVE
        assert score.accepted is True
        assert score.score == 0.85
        assert score.disputed_by is None
        assert decision.state == db.DECISION_MONITOR_ONLY
        assert decision.flagged_for_review is False

        history = services.get_score_history(session, score.id)
        events = [entry.event for entry in history]
        assert events == ["upsert", "dispute", "revoke", "restore"]
        assert [entry.version for entry in history] == [1, 2, 3, 4]
        local_events = [entry.event for entry in services.get_local_decision_history(session, decision.id)]
        assert local_events == ["query", "operator_commit", "dispute", "revoke", "restore"]
    finally:
        session.close()


def test_restore_resolves_first_dispute_to_monitor_only() -> None:
    session = _fresh_session()
    try:
        _seeded_score(session)
        decision = services.query_score(
            session, "site-a", "camera", "api.vendor.com", "https", 443
        )
        services.operator_commit(
            session, "site-a", "camera", "api.vendor.com", "https", 443
        )
        session.commit()

        services.dispute_score(session, "camera", "api.vendor.com", "https", 443, "site-b")
        session.commit()
        assert decision.state == db.DECISION_DISPUTED

        score = services.restore_score(
            session,
            "camera",
            "api.vendor.com",
            "https",
            443,
            actor_site_id="consortium-admin",
            reason="challenge rejected",
        )
        session.commit()

        assert score.status == db.STATUS_ACTIVE
        assert score.disputed_by is None
        assert decision.state == db.DECISION_MONITOR_ONLY
        assert [entry.event for entry in services.get_score_history(session, score.id)] == [
            "upsert", "dispute", "restore",
        ]
        assert [
            entry.event for entry in services.get_local_decision_history(session, decision.id)
        ] == ["query", "operator_commit", "dispute", "restore"]
    finally:
        session.close()


def test_local_revoke_withdraws_active_without_affecting_other_sites() -> None:
    session = _fresh_session()
    try:
        _seeded_score(session)
        decision_a = services.query_score(session, "site-a", "camera", "api.vendor.com", "https", 443)
        services.operator_commit(session, "site-a", "camera", "api.vendor.com", "https", 443)
        decision_b = services.query_score(session, "site-b", "camera", "api.vendor.com", "https", 443)
        session.commit()

        revoked = services.local_revoke(session, "site-a", "camera", "api.vendor.com", "https", 443)
        session.commit()

        assert revoked.state == db.DECISION_REVOKED
        assert revoked.id == decision_a.id
        # Unlike dispute_score(), local_revoke() never fans out: site-b's own
        # MonitorOnly record and the global Score are both untouched.
        assert decision_b.state == db.DECISION_MONITOR_ONLY
        score = services.get_score(session, "camera", "api.vendor.com", "https", 443)
        assert score.status == db.STATUS_ACTIVE
        assert score.disputed_by is None
        assert [
            entry.event for entry in services.get_local_decision_history(session, decision_a.id)
        ] == ["query", "operator_commit", "local_revoke"]
    finally:
        session.close()


def test_local_restore_returns_locally_revoked_record_to_monitor_only() -> None:
    session = _fresh_session()
    try:
        _seeded_score(session)
        decision = services.query_score(session, "site-a", "camera", "api.vendor.com", "https", 443)
        services.operator_commit(session, "site-a", "camera", "api.vendor.com", "https", 443)
        services.local_revoke(session, "site-a", "camera", "api.vendor.com", "https", 443)
        session.commit()

        restored = services.local_restore(session, "site-a", "camera", "api.vendor.com", "https", 443)
        session.commit()

        assert restored.state == db.DECISION_MONITOR_ONLY
        # local_restore() only ever reaches MonitorOnly: re-enforcement still
        # requires a fresh operator_commit(), exactly like the cross-site path.
        recommitted = services.operator_commit(session, "site-a", "camera", "api.vendor.com", "https", 443)
        session.commit()
        assert recommitted.state == db.DECISION_ACTIVE
        assert [
            entry.event for entry in services.get_local_decision_history(session, decision.id)
        ] == ["query", "operator_commit", "local_revoke", "local_restore", "operator_commit"]
    finally:
        session.close()


def test_local_restore_refuses_while_cross_site_dispute_is_open() -> None:
    session = _fresh_session()
    try:
        _seeded_score(session)
        services.query_score(session, "site-a", "camera", "api.vendor.com", "https", 443)
        services.operator_commit(session, "site-a", "camera", "api.vendor.com", "https", 443)
        services.local_revoke(session, "site-a", "camera", "api.vendor.com", "https", 443)
        session.commit()

        # A later cross-site dispute must not silently pull site-a's own
        # local-revoke decision back into "Disputed" -- it already left.
        services.dispute_score(session, "camera", "api.vendor.com", "https", 443, "site-b")
        session.commit()
        decision = services.get_local_decision(
            session, services.get_score(session, "camera", "api.vendor.com", "https", 443).id, "site-a"
        )
        assert decision.state == db.DECISION_REVOKED

        try:
            services.local_restore(session, "site-a", "camera", "api.vendor.com", "https", 443)
            assert False, "expected InvalidStateTransition while a dispute episode is open"
        except services.InvalidStateTransition:
            pass
        session.rollback()
    finally:
        session.close()


def test_local_revoke_raises_on_absent_or_already_revoked() -> None:
    session = _fresh_session()
    try:
        _seeded_score(session)
        assert services.local_revoke(session, "site-a", "camera", "api.vendor.com", "https", 443) is None
        services.query_score(session, "site-a", "camera", "api.vendor.com", "https", 443)
        session.commit()
        services.local_revoke(session, "site-a", "camera", "api.vendor.com", "https", 443)
        session.commit()
        try:
            services.local_revoke(session, "site-a", "camera", "api.vendor.com", "https", 443)
            assert False, "expected InvalidStateTransition on an already-Revoked record"
        except services.InvalidStateTransition:
            pass
        session.rollback()
    finally:
        session.close()


def test_global_restore_preserves_local_veto_and_its_history() -> None:
    for dispute_count in (1, 2):
        session = _fresh_session()
        key = ("camera", "api.vendor.com", "https", 443)
        try:
            _seeded_score(session)
            for site in ("site-a", "site-b"):
                services.query_score(session, site, *key)
                services.operator_commit(session, site, *key)
            services.local_revoke(session, "site-a", *key)
            session.commit()
            score = services.get_score(session, *key)
            decision = services.get_local_decision(session, score.id, "site-a")
            history_before = [v.id for v in services.get_local_decision_history(session, decision.id)]
            for site in ("site-b", "site-c")[:dispute_count]:
                services.dispute_score(session, *key, site)
                session.commit()
            services.restore_score(session, *key, actor_site_id="site-c")
            session.commit()
            assert decision.state == db.DECISION_REVOKED
            assert [v.id for v in services.get_local_decision_history(session, decision.id)] == history_before
            assert services.get_local_decision(session, score.id, "site-b").state == db.DECISION_MONITOR_ONLY
            # A local veto remains effective across a second dispute episode.
            services.dispute_score(session, *key, "site-c")
            services.restore_score(session, *key, actor_site_id="site-b")
            session.commit()
            assert decision.state == db.DECISION_REVOKED
            services.local_restore(session, "site-a", *key)
            session.commit()
            assert decision.state == db.DECISION_MONITOR_ONLY
        finally:
            session.close()


def test_veto_recorded_during_shared_withdrawal_survives_restoration() -> None:
    for dispute_count in (1, 2):
        session = _fresh_session()
        key = ("camera", "api.vendor.com", "https", 443)
        try:
            _seeded_score(session)
            for site in ("site-a", "site-b"):
                services.query_score(session, site, *key)
                services.operator_commit(session, site, *key)
            for reporter in ("site-b", "site-c")[:dispute_count]:
                services.dispute_score(session, *key, reporter)
                session.commit()
            score = services.get_score(session, *key)
            peer_state = services.get_local_decision(session, score.id, "site-b").state
            shared_status = score.status
            services.local_revoke(session, "site-a", *key)
            session.commit()
            assert score.status == shared_status
            assert services.get_local_decision(session, score.id, "site-b").state == peer_state
            try:
                services.local_restore(session, "site-a", *key)
                assert False, "local restore must not close a shared episode"
            except services.InvalidStateTransition:
                session.rollback()
            services.restore_score(session, *key, actor_site_id="site-c")
            session.commit()
            assert services.get_local_decision(session, score.id, "site-a").state == db.DECISION_REVOKED
            assert services.get_local_decision(session, score.id, "site-b").state == db.DECISION_MONITOR_ONLY
            assert not services.export_active_mud(session, "site-a", key[0]).exported_endpoints
            assert not services.export_active_mud(session, "site-b", key[0]).exported_endpoints
            services.local_restore(session, "site-a", *key)
            session.commit()
            assert not services.export_active_mud(session, "site-a", key[0]).exported_endpoints
            services.operator_commit(session, "site-a", *key)
            session.commit()
            assert len(services.export_active_mud(session, "site-a", key[0]).exported_endpoints) == 1
        finally:
            session.close()


def test_restore_then_operator_commit_reenables_enforcement() -> None:
    session = _fresh_session()
    try:
        _seeded_score(session)
        services.query_score(session, "site-a", "camera", "api.vendor.com", "https", 443)
        services.operator_commit(session, "site-a", "camera", "api.vendor.com", "https", 443)
        session.commit()
        services.dispute_score(session, "camera", "api.vendor.com", "https", 443, "site-b")
        session.commit()
        services.dispute_score(session, "camera", "api.vendor.com", "https", 443, "site-c")
        session.commit()
        services.restore_score(session, "camera", "api.vendor.com", "https", 443)
        session.commit()

        committed = services.operator_commit(
            session, "site-a", "camera", "api.vendor.com", "https", 443
        )
        session.commit()

        assert committed.state == db.DECISION_ACTIVE
        history = services.get_local_decision_history(session, committed.id)
        assert [entry.event for entry in history] == [
            "query", "operator_commit", "dispute", "revoke", "restore", "operator_commit",
        ]
    finally:
        session.close()


def test_restore_does_not_manufacture_local_decisions() -> None:
    session = _fresh_session()
    try:
        _seeded_score(session)
        services.dispute_score(session, "camera", "api.vendor.com", "https", 443, "site-b")
        session.commit()
        services.dispute_score(session, "camera", "api.vendor.com", "https", 443, "site-c")
        session.commit()

        score = services.restore_score(session, "camera", "api.vendor.com", "https", 443)
        session.commit()

        assert score.status == db.STATUS_ACTIVE
        assert score.local_decisions == []
    finally:
        session.close()


def test_revoke_alone_does_not_touch_score_or_tier() -> None:
    # The invariant the old atomic test conflated with restoration: revoke
    # by itself must not roll anything back -- only restore_score() does.
    session = _fresh_session()
    try:
        _seeded_score(session)
        rescored = {
            "device_type": "camera", "endpoint": "api.vendor.com", "protocol": "https", "port": 443,
            "site_confidence": 0.95, "temporal_confidence": 0.9, "graph_confidence": 0.8,
            "score": 0.92, "accepted": True,
        }
        services.upsert_score(session, rescored)
        session.commit()
        services.dispute_score(session, "camera", "api.vendor.com", "https", 443, "site-b")
        session.commit()
        score = services.dispute_score(session, "camera", "api.vendor.com", "https", 443, "site-c")
        session.commit()

        assert score.status == db.STATUS_REVOKED
        assert score.score == 0.92  # untouched by revoke, still the rescored value
        assert score.tier == db.TIER_CORROBORATED
    finally:
        session.close()


def test_restore_score_restores_most_recent_active_version_not_the_first() -> None:
    session = _fresh_session()
    try:
        _seeded_score(session)
        rescored = {
            "device_type": "camera", "endpoint": "api.vendor.com", "protocol": "https", "port": 443,
            "site_confidence": 0.95, "temporal_confidence": 0.9, "graph_confidence": 0.8,
            "score": 0.92, "accepted": True,
        }
        services.upsert_score(session, rescored)
        session.commit()
        services.dispute_score(session, "camera", "api.vendor.com", "https", 443, "site-b")
        session.commit()
        services.dispute_score(session, "camera", "api.vendor.com", "https", 443, "site-c")
        session.commit()

        score = services.restore_score(session, "camera", "api.vendor.com", "https", 443)
        session.commit()

        assert score.status == db.STATUS_ACTIVE
        assert score.score == 0.92  # the most recent active version (rescored), not the first (0.85)
    finally:
        session.close()


def test_restore_score_raises_on_active_fact() -> None:
    session = _fresh_session()
    try:
        _seeded_score(session)
        try:
            services.restore_score(session, "camera", "api.vendor.com", "https", 443)
            assert False, "expected InvalidStateTransition on a still-ACTIVE fact"
        except services.InvalidStateTransition:
            pass

    finally:
        session.close()


def test_restore_score_returns_none_for_missing_score() -> None:
    session = _fresh_session()
    try:
        assert services.restore_score(session, "camera", "missing", "https", 443) is None
    finally:
        session.close()


def test_admitted_fact_has_no_local_authority_until_query() -> None:
    session = _fresh_session()
    try:
        _seeded_score(session)
        score = services.get_score(session, "camera", "api.vendor.com", "https", 443)
        assert score.local_decisions == []
        decision = services.query_score(
            session, "site-a", "camera", "api.vendor.com", "https", 443
        )
        assert decision.state == db.DECISION_MONITOR_ONLY
    finally:
        session.close()


def test_rejected_fact_cannot_be_queried() -> None:
    session = _fresh_session()
    try:
        services.upsert_score(session, {
            "device_type": "camera", "endpoint": "rejected.vendor.com", "protocol": "https", "port": 443,
            "site_confidence": 0.1, "temporal_confidence": 0.1, "graph_confidence": 0.0,
            "score": 0.2, "accepted": False,
        })
        session.commit()
        assert services.query_score(
            session, "site-a", "camera", "rejected.vendor.com", "https", 443
        ) is None
    finally:
        session.close()


def test_reconfirming_fact_does_not_reset_active_local_decision() -> None:
    session = _fresh_session()
    try:
        _seeded_score(session)
        services.query_score(session, "site-a", "camera", "api.vendor.com", "https", 443)
        decision = services.operator_commit(
            session, "site-a", "camera", "api.vendor.com", "https", 443
        )
        session.commit()

        rescored = {
            "device_type": "camera", "endpoint": "api.vendor.com", "protocol": "https", "port": 443,
            "site_confidence": 0.95, "temporal_confidence": 0.9, "graph_confidence": 0.8,
            "score": 0.92, "accepted": True,
        }
        services.upsert_score(session, rescored)
        session.commit()

        assert decision.state == db.DECISION_ACTIVE
    finally:
        session.close()


def test_rescore_below_threshold_flags_committed_fact_instead_of_deenforcing() -> None:
    # The bug this test guards against: a routine rescore that drops
    # accepted to False must NOT silently clear import_state (and therefore
    # enforcement) on a fact an operator already committed. It must instead
    # flag it for review and leave import_state/status untouched, recording
    # a distinct history event -- the corrected Sec. IV-B invariant ("only a
    # local OPERATOR_COMMIT may enable access; safety transitions must be
    # explicit and recorded, never implicit in a routine score recompute").
    session = _fresh_session()
    try:
        _seeded_score(session)
        services.query_score(session, "site-a", "camera", "api.vendor.com", "https", 443)
        decision = services.operator_commit(
            session, "site-a", "camera", "api.vendor.com", "https", 443
        )
        session.commit()

        rescored = {
            "device_type": "camera", "endpoint": "api.vendor.com", "protocol": "https", "port": 443,
            "site_confidence": 0.1, "temporal_confidence": 0.1, "graph_confidence": 0.0,
            "score": 0.2, "accepted": False,
        }
        services.upsert_score(session, rescored)
        session.commit()

        score = services.get_score(session, "camera", "api.vendor.com", "https", 443)
        assert decision.state == db.DECISION_ACTIVE
        assert score.status == db.STATUS_ACTIVE
        assert decision.flagged_for_review is True
        assert score.accepted is False

        history = services.get_local_decision_history(session, decision.id)
        events = [entry.event for entry in history]
        assert events == ["query", "operator_commit", "auto_flag_for_review"]
    finally:
        session.close()


def test_rescore_above_threshold_clears_a_stale_review_flag() -> None:
    session = _fresh_session()
    try:
        _seeded_score(session)
        services.query_score(session, "site-a", "camera", "api.vendor.com", "https", 443)
        decision = services.operator_commit(
            session, "site-a", "camera", "api.vendor.com", "https", 443
        )
        session.commit()
        services.upsert_score(session, {
            "device_type": "camera", "endpoint": "api.vendor.com", "protocol": "https", "port": 443,
            "site_confidence": 0.1, "temporal_confidence": 0.1, "graph_confidence": 0.0,
            "score": 0.2, "accepted": False,
        })
        session.commit()
        assert decision.flagged_for_review is True

        services.upsert_score(session, {
            "device_type": "camera", "endpoint": "api.vendor.com", "protocol": "https", "port": 443,
            "site_confidence": 0.9, "temporal_confidence": 0.8, "graph_confidence": 0.7,
            "score": 0.85, "accepted": True,
        })
        session.commit()
        assert decision.flagged_for_review is False
        assert decision.state == db.DECISION_ACTIVE
    finally:
        session.close()


def test_rescore_below_threshold_leaves_monitor_only_decision_unflagged() -> None:
    session = _fresh_session()
    try:
        _seeded_score(session)
        decision = services.query_score(
            session, "site-a", "camera", "api.vendor.com", "https", 443
        )

        services.upsert_score(session, {
            "device_type": "camera", "endpoint": "api.vendor.com", "protocol": "https", "port": 443,
            "site_confidence": 0.1, "temporal_confidence": 0.1, "graph_confidence": 0.0,
            "score": 0.2, "accepted": False,
        })
        session.commit()
        assert decision.state == db.DECISION_MONITOR_ONLY
        assert decision.flagged_for_review is False
        try:
            services.operator_commit(
                session, "site-a", "camera", "api.vendor.com", "https", 443
            )
            assert False, "stale MonitorOnly evidence must not be activatable"
        except services.InvalidStateTransition:
            pass
    finally:
        session.close()


def test_operator_commit_moves_staged_to_active_and_snapshots_event() -> None:
    session = _fresh_session()
    try:
        _seeded_score(session)
        staged = services.query_score(
            session, "site-a", "camera", "api.vendor.com", "https", 443
        )
        version_before = staged.version
        committed = services.operator_commit(
            session, "site-a", "camera", "api.vendor.com", "https", 443
        )
        session.commit()

        assert committed.state == db.DECISION_ACTIVE
        assert committed.version == version_before + 1
        history = services.get_local_decision_history(session, committed.id)
        assert history[-1].event == "operator_commit"
        assert history[-1].state == db.DECISION_ACTIVE
    finally:
        session.close()


def test_operator_commit_returns_none_for_missing_score() -> None:
    session = _fresh_session()
    try:
        assert services.operator_commit(
            session, "site-a", "camera", "missing", "https", 443
        ) is None
    finally:
        session.close()


def test_operator_commit_raises_on_non_staged_fact() -> None:
    # Covers both invalid transitions with one rule: not-yet-admitted
    # (import_state is None) and already-committed (import_state == ACTIVE)
    # are both rejected explicitly rather than silently no-op-ing -- see
    # operator_commit()'s docstring for why re-commit is not idempotent.
    session = _fresh_session()
    try:
        _seeded_score(session)
        services.query_score(session, "site-a", "camera", "api.vendor.com", "https", 443)
        services.operator_commit(session, "site-a", "camera", "api.vendor.com", "https", 443)
        session.commit()

        try:
            services.operator_commit(session, "site-a", "camera", "api.vendor.com", "https", 443)
            assert False, "expected InvalidImportStateTransition on re-commit"
        except services.InvalidImportStateTransition:
            pass

        services.upsert_score(session, {
            "device_type": "camera", "endpoint": "rejected.vendor.com", "protocol": "https", "port": 443,
            "site_confidence": 0.1, "temporal_confidence": 0.1, "graph_confidence": 0.0,
            "score": 0.2, "accepted": False,
        })
        session.commit()
        try:
            result = services.operator_commit(
                session, "site-a", "camera", "rejected.vendor.com", "https", 443
            )
            assert result is None
        except services.InvalidImportStateTransition:
            assert False, "a missing local decision is not a malformed transition"
    finally:
        session.close()


def test_site_decisions_are_isolated_and_export_is_active_only() -> None:
    session = _fresh_session()
    try:
        _seeded_score(session)
        a = services.query_score(session, "site-a", "camera", "api.vendor.com", "https", 443)
        b = services.query_score(session, "site-b", "camera", "api.vendor.com", "https", 443)
        services.operator_commit(session, "site-a", "camera", "api.vendor.com", "https", 443)
        session.commit()

        assert a.state == db.DECISION_ACTIVE
        assert b.state == db.DECISION_MONITOR_ONLY
        assert services.export_active_mud(session, "site-a", "camera").exported_ace_count == 1
        assert services.export_active_mud(session, "site-b", "camera").exported_ace_count == 0
    finally:
        session.close()


def test_concurrent_distinct_site_commits_do_not_lose_or_cross_updates() -> None:
    session = _fresh_session()
    try:
        _seeded_score(session)
    finally:
        session.close()

    barrier = threading.Barrier(2)
    errors = []

    def commit_for(site_id: str) -> None:
        local = db.get_session()
        try:
            services.query_score(local, site_id, "camera", "api.vendor.com", "https", 443)
            local.commit()
            barrier.wait(timeout=5)
            services.operator_commit(local, site_id, "camera", "api.vendor.com", "https", 443)
            local.commit()
        except Exception as exc:  # pragma: no cover - retained for diagnostic assertion
            local.rollback()
            errors.append(exc)
        finally:
            local.close()

    threads = [threading.Thread(target=commit_for, args=(site,)) for site in ("site-a", "site-b")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    check = db.get_session()
    try:
        score = services.get_score(check, "camera", "api.vendor.com", "https", 443)
        assert errors == []
        assert services.get_local_decision(check, score.id, "site-a").state == db.DECISION_ACTIVE
        assert services.get_local_decision(check, score.id, "site-b").state == db.DECISION_ACTIVE
        assert services.export_active_mud(check, "site-a", "camera").exported_ace_count == 1
        assert services.export_active_mud(check, "site-b", "camera").exported_ace_count == 1
    finally:
        check.close()
