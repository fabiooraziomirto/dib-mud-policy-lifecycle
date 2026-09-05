"""Admission trust boundary (Sec. IV-A of the paper).

Before this fix, ``services.upsert_score`` wrote whatever
site_confidence/temporal_confidence/score/accepted a caller supplied,
including over the network via POST /score: an authenticated but dishonest
contributor could stage an ineligible fact for later commit merely by
asserting ``accepted=True``. These tests exercise the closed boundary: the
registry now recomputes the verdict from its own stored ``observations``
(Sec. IV-B's selected operating point: alpha=0.6, beta=0.4, theta=0.65, m=2)
on the network-facing path, and a claimed verdict that disagrees with that
evidence is overridden -- fail-closed when there is no evidence at all.

Kept separate from test_registry.py (which exercises the FSM using
pre-seeded score payloads with the default trust_client_verdict=True, i.e.
the offline/batch-pipeline path that must keep behaving exactly as before)
so the two trust regimes are never accidentally conflated in one file.
"""
from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone

import dib.registry.db as db
from dib.registry import services


def _fresh_session():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.environ["DIB_DATABASE_URL"] = f"sqlite:///{path}"
    db._engine = None
    db._SessionLocal = None
    return db.get_session()


def _observe(session, site_id: str, fqdn: str, day_offset: int) -> None:
    services.record_observation(
        session,
        {
            "site_id": site_id,
            "device_id": None,
            "device_type": "camera",
            "fqdn": fqdn,
            "remote_ip": None,
            "protocol": "https",
            "port": 443,
            "timestamp": datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(days=day_offset),
            "source_dataset": "test",
            "evidence_type": "flow",
        },
    )


def test_single_reporter_claiming_accepted_is_rejected_regardless_of_claimed_score() -> None:
    """A lone, dishonest contributor cannot buy admission by lying about its
    own score: quorum (m=2) is checked against the registry's own evidence,
    not against the caller's assertion."""
    session = _fresh_session()
    try:
        for day in range(10):
            _observe(session, "site-a", "fake.vendor.com", day)
        session.commit()

        stored = services.upsert_score(
            session,
            {
                "device_type": "camera",
                "endpoint": "fake.vendor.com",
                "protocol": "https",
                "port": 443,
                "site_confidence": 0.95,
                "temporal_confidence": 0.90,
                "graph_confidence": 0.0,
                "score": 0.92,
                "accepted": True,
            },
            trust_client_verdict=False,
        )
        session.commit()

        assert stored.accepted is False
        assert services.query_score(session, "site-a", "camera", "fake.vendor.com", "https", 443) is None
    finally:
        session.close()


def test_no_stored_evidence_fails_closed_even_if_claimed_accepted() -> None:
    """A contributor that never reports through /observation at all cannot
    stage a fact by only ever calling /score."""
    session = _fresh_session()
    try:
        stored = services.upsert_score(
            session,
            {
                "device_type": "camera",
                "endpoint": "ghost.vendor.com",
                "protocol": "https",
                "port": 443,
                "site_confidence": 0.99,
                "temporal_confidence": 0.99,
                "graph_confidence": 0.0,
                "score": 0.99,
                "accepted": True,
            },
            trust_client_verdict=False,
        )
        session.commit()
        assert stored.accepted is False
    finally:
        session.close()


def test_genuine_two_site_support_is_admitted_from_recomputed_evidence() -> None:
    """The boundary is not "always reject": a fact genuinely corroborated by
    two distinct sites is admitted from the registry's own recomputation,
    even if the caller under-states it."""
    session = _fresh_session()
    try:
        for day in range(10):
            _observe(session, "site-a", "api.vendor.com", day)
            _observe(session, "site-b", "api.vendor.com", day)
        session.commit()

        stored = services.upsert_score(
            session,
            {
                "device_type": "camera",
                "endpoint": "api.vendor.com",
                "protocol": "https",
                "port": 443,
                "site_confidence": 0.0,
                "temporal_confidence": 0.0,
                "graph_confidence": 0.0,
                "score": 0.0,
                "accepted": False,
            },
            trust_client_verdict=False,
        )
        session.commit()

        assert stored.accepted is True
        assert stored.site_confidence == 1.0
        decision = services.query_score(session, "site-a", "camera", "api.vendor.com", "https", 443)
        assert decision.state == db.DECISION_MONITOR_ONLY
    finally:
        session.close()


def test_http_post_score_endpoint_enforces_the_same_boundary() -> None:
    """The actual network entry point (not just the service function) must
    not trust a remote caller's verdict."""
    from fastapi.testclient import TestClient

    from dib.registry.api import app

    session = _fresh_session()
    try:
        for day in range(10):
            _observe(session, "site-a", "fake.vendor.com", day)
        session.commit()
    finally:
        session.close()

    client = TestClient(app)
    response = client.post(
        "/score",
        json={
            "device_type": "camera",
            "endpoint": "fake.vendor.com",
            "protocol": "https",
            "port": 443,
            "site_confidence": 0.95,
            "temporal_confidence": 0.90,
            "graph_confidence": 0.0,
            "score": 0.92,
            "accepted": True,
        },
    )
    assert response.status_code == 200
    stored_id = response.json()["id"]

    fetch = client.get("/score/camera/fake.vendor.com|https|443")
    assert fetch.status_code == 200
    assert fetch.json()["accepted"] is False, "server must recompute, not trust, the POSTed verdict"
    assert stored_id is not None
