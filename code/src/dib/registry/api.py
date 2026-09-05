from __future__ import annotations

from datetime import datetime
from typing import Generator

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from dib.registry import services
from dib.registry.db import get_session

app = FastAPI(title="DIB Registry", version="1.0.0")


def session_dependency() -> Generator[Session, None, None]:
    session = get_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


class ObservationIn(BaseModel):
    site_id: str
    device_id: str | None = None
    device_type: str
    fqdn: str | None = None
    remote_ip: str | None = None
    protocol: str
    port: int
    timestamp: datetime
    source_dataset: str
    evidence_type: str
    response_observed: bool = False
    direction: str = "out"


class EndpointIn(BaseModel):
    fqdn: str
    protocol: str
    port: int
    count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class ProfileIn(BaseModel):
    site_id: str
    device_type: str
    endpoints: list[EndpointIn]


class ScoreIn(BaseModel):
    device_type: str
    endpoint: str
    protocol: str
    port: int
    site_confidence: float
    temporal_confidence: float
    graph_confidence: float
    score: float
    accepted: bool


class AttestationIn(BaseModel):
    device_type: str
    endpoint: str
    protocol: str
    port: int
    site_id: str
    reason: str | None = None


class FactIn(BaseModel):
    device_type: str
    endpoint: str
    protocol: str
    port: int


class SiteFactIn(FactIn):
    site_id: str


class RestoreIn(FactIn):
    actor_site_id: str | None = None
    reason: str | None = None


class LocalRevokeIn(SiteFactIn):
    reason: str | None = None


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/observation")
def post_observation(observation: ObservationIn, session: Session = Depends(session_dependency)) -> dict:
    row, created = services.record_observation(session, observation.model_dump())
    return {"id": row.id, "created": created}


@app.post("/profile")
def post_profile(profile: ProfileIn, session: Session = Depends(session_dependency)) -> dict:
    stored = services.upsert_profile(
        session,
        profile.site_id,
        profile.device_type,
        [endpoint.model_dump() for endpoint in profile.endpoints],
    )
    return {"id": stored.id, "site_id": stored.site_id, "device_type": stored.device_type}


@app.get("/global-profile/{device_type}")
def get_global_profile(device_type: str, session: Session = Depends(session_dependency)) -> dict:
    return services.global_profile(session, device_type)


@app.post("/score")
def post_score(score: ScoreIn, session: Session = Depends(session_dependency)) -> dict:
    # trust_client_verdict=False: this is the network-facing trust boundary.
    # The registry recomputes admission from its own stored observations
    # instead of accepting a remote contributor's claimed verdict verbatim
    # (see services.upsert_score / services.recompute_admission).
    stored = services.upsert_score(session, score.model_dump(), trust_client_verdict=False)
    return {"id": stored.id}


@app.get("/score/{device_type}/{endpoint_key}")
def get_score(device_type: str, endpoint_key: str, session: Session = Depends(session_dependency)) -> dict:
    score = _lookup_score(device_type, endpoint_key, session)
    return _score_dict(score)


@app.get("/score/{device_type}/{endpoint_key}/history")
def get_score_history(device_type: str, endpoint_key: str, session: Session = Depends(session_dependency)) -> dict:
    score = _lookup_score(device_type, endpoint_key, session)
    history = services.get_score_history(session, score.id)
    return {
        "device_type": score.device_type,
        "endpoint": score.endpoint,
        "protocol": score.protocol,
        "port": score.port,
        "versions": [
            {
                "version": entry.version,
                "score": entry.score,
                "accepted": entry.accepted,
                "tier": entry.tier,
                "status": entry.status,
                "event": entry.event,
                "actor_site_id": entry.actor_site_id,
                "reason": entry.reason,
                "created_at": entry.created_at.isoformat(),
            }
            for entry in history
        ],
    }


@app.post("/attest")
def post_attest(attestation: AttestationIn, session: Session = Depends(session_dependency)) -> dict:
    score = services.attest_score(
        session,
        attestation.device_type,
        attestation.endpoint,
        attestation.protocol,
        attestation.port,
        attestation.site_id,
        attestation.reason,
    )
    if score is None:
        raise HTTPException(status_code=404, detail="score not found")
    return _score_dict(score)


@app.post("/dispute")
def post_dispute(attestation: AttestationIn, session: Session = Depends(session_dependency)) -> dict:
    score = services.dispute_score(
        session,
        attestation.device_type,
        attestation.endpoint,
        attestation.protocol,
        attestation.port,
        attestation.site_id,
        attestation.reason,
    )
    if score is None:
        raise HTTPException(status_code=404, detail="score not found")
    return _score_dict(score)


@app.post("/commit")
def post_commit(commit: SiteFactIn, session: Session = Depends(session_dependency)) -> dict:
    try:
        decision = services.operator_commit(
            session,
            commit.site_id,
            commit.device_type,
            commit.endpoint,
            commit.protocol,
            commit.port,
        )
    except services.InvalidStateTransition as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    if decision is None:
        raise HTTPException(status_code=404, detail="local MonitorOnly decision not found")
    return _decision_dict(decision)


@app.post("/query")
def post_query(query: SiteFactIn, session: Session = Depends(session_dependency)) -> dict:
    decision = services.query_score(
        session,
        query.site_id,
        query.device_type,
        query.endpoint,
        query.protocol,
        query.port,
    )
    if decision is None:
        raise HTTPException(status_code=404, detail="fact is absent or not currently admissible")
    return _decision_dict(decision)


@app.post("/local-revoke")
def post_local_revoke(revoke: LocalRevokeIn, session: Session = Depends(session_dependency)) -> dict:
    try:
        decision = services.local_revoke(
            session,
            revoke.site_id,
            revoke.device_type,
            revoke.endpoint,
            revoke.protocol,
            revoke.port,
            revoke.reason,
        )
    except services.InvalidStateTransition as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    if decision is None:
        raise HTTPException(status_code=404, detail="local decision not found")
    return _decision_dict(decision)


@app.post("/local-restore")
def post_local_restore(restore: LocalRevokeIn, session: Session = Depends(session_dependency)) -> dict:
    try:
        decision = services.local_restore(
            session,
            restore.site_id,
            restore.device_type,
            restore.endpoint,
            restore.protocol,
            restore.port,
            restore.reason,
        )
    except services.InvalidStateTransition as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    if decision is None:
        raise HTTPException(status_code=404, detail="local decision not found")
    return _decision_dict(decision)


@app.post("/restore")
def post_restore(commit: RestoreIn, session: Session = Depends(session_dependency)) -> dict:
    try:
        score = services.restore_score(
            session,
            commit.device_type,
            commit.endpoint,
            commit.protocol,
            commit.port,
            commit.actor_site_id,
            commit.reason,
        )
    except services.InvalidStateTransition as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    if score is None:
        raise HTTPException(status_code=404, detail="score not found")
    return _score_dict(score)


@app.get("/decision/{site_id}/{device_type}/{endpoint_key}")
def get_decision(
    site_id: str, device_type: str, endpoint_key: str, session: Session = Depends(session_dependency)
) -> dict:
    score = _lookup_score(device_type, endpoint_key, session)
    decision = services.get_local_decision(session, score.id, site_id)
    if decision is None:
        raise HTTPException(status_code=404, detail="local decision not found")
    return _decision_dict(decision)


@app.get("/decision/{site_id}/{device_type}/{endpoint_key}/history")
def get_decision_history(
    site_id: str, device_type: str, endpoint_key: str, session: Session = Depends(session_dependency)
) -> dict:
    score = _lookup_score(device_type, endpoint_key, session)
    decision = services.get_local_decision(session, score.id, site_id)
    if decision is None:
        raise HTTPException(status_code=404, detail="local decision not found")
    return {
        **_decision_dict(decision),
        "versions": [
            {
                "version": entry.version,
                "state": entry.state,
                "flagged_for_review": entry.flagged_for_review,
                "event": entry.event,
                "actor_site_id": entry.actor_site_id,
                "reason": entry.reason,
                "created_at": entry.created_at.isoformat(),
            }
            for entry in services.get_local_decision_history(session, decision.id)
        ],
    }


@app.get("/export/{site_id}/{device_type}")
def get_export(site_id: str, device_type: str, session: Session = Depends(session_dependency)) -> dict:
    return services.export_active_mud(session, site_id, device_type).document


def _lookup_score(device_type: str, endpoint_key: str, session: Session):
    try:
        endpoint, protocol, port = endpoint_key.split("|")
    except ValueError:
        raise HTTPException(status_code=400, detail="endpoint_key must be 'endpoint|protocol|port'")
    score = services.get_score(session, device_type, endpoint, protocol, int(port))
    if score is None:
        raise HTTPException(status_code=404, detail="score not found")
    return score


def _score_dict(score) -> dict:
    return {
        "device_type": score.device_type,
        "endpoint": score.endpoint,
        "protocol": score.protocol,
        "port": score.port,
        "site_confidence": score.site_confidence,
        "temporal_confidence": score.temporal_confidence,
        "graph_confidence": score.graph_confidence,
        "score": score.score,
        "accepted": score.accepted,
        "tier": score.tier,
        "status": score.status,
        "version": score.version,
        "positive_attestations": score.positive_attestations,
        "negative_attestations": score.negative_attestations,
    }


def _decision_dict(decision) -> dict:
    score = decision.score_row
    return {
        "site_id": decision.site_id,
        "device_type": score.device_type,
        "endpoint": score.endpoint,
        "protocol": score.protocol,
        "port": score.port,
        "state": decision.state,
        "flagged_for_review": decision.flagged_for_review,
        "version": decision.version,
    }
