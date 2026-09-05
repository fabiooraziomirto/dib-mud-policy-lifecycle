from __future__ import annotations

import os
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    create_engine,
    inspect,
)
from sqlalchemy import event
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker


def database_url() -> str:
    return os.environ.get("DIB_DATABASE_URL", "sqlite:///./dib_registry.db")


class Base(DeclarativeBase):
    pass


class Site(Base):
    __tablename__ = "sites"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[str] = mapped_column(String, unique=True, index=True)
    trust_score: Mapped[float] = mapped_column(Float, default=1.0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class ObservationRow(Base):
    __tablename__ = "observations"
    __table_args__ = (
        UniqueConstraint(
            "site_id", "device_id", "device_type", "fqdn", "remote_ip", "protocol", "port", "timestamp", "evidence_type",
            name="uq_observation_identity",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[str] = mapped_column(String, index=True)
    device_id: Mapped[str | None] = mapped_column(String, nullable=True)
    device_type: Mapped[str] = mapped_column(String, index=True)
    fqdn: Mapped[str | None] = mapped_column(String, nullable=True)
    remote_ip: Mapped[str | None] = mapped_column(String, nullable=True)
    protocol: Mapped[str] = mapped_column(String)
    port: Mapped[int] = mapped_column(Integer)
    timestamp: Mapped[datetime] = mapped_column(DateTime)
    source_dataset: Mapped[str] = mapped_column(String)
    evidence_type: Mapped[str] = mapped_column(String)
    response_observed: Mapped[bool] = mapped_column(Boolean, default=False)
    direction: Mapped[str] = mapped_column(String, default="out")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class Profile(Base):
    __tablename__ = "profiles"
    __table_args__ = (UniqueConstraint("site_id", "device_type", name="uq_profile_identity"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[str] = mapped_column(String, index=True)
    device_type: Mapped[str] = mapped_column(String, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    endpoints: Mapped[list["Endpoint"]] = relationship(back_populates="profile", cascade="all, delete-orphan")


class Endpoint(Base):
    __tablename__ = "endpoints"
    __table_args__ = (
        UniqueConstraint("profile_id", "fqdn", "protocol", "port", name="uq_endpoint_identity"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    profile_id: Mapped[int] = mapped_column(ForeignKey("profiles.id"))
    fqdn: Mapped[str] = mapped_column(String)
    protocol: Mapped[str] = mapped_column(String)
    port: Mapped[int] = mapped_column(Integer)
    count: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    profile: Mapped[Profile] = relationship(back_populates="endpoints")


TIER_LOCAL = "local"
TIER_CORROBORATED = "corroborated"
TIER_CONSORTIUM_ATTESTED = "consortium-attested"
TIER_MANUFACTURER_RATIFIED = "manufacturer-ratified"

STATUS_ACTIVE = "active"
STATUS_DISPUTED = "disputed"
STATUS_REVOKED = "revoked"

DECISION_MONITOR_ONLY = "monitor-only"
DECISION_ACTIVE = "active"
DECISION_DISPUTED = "disputed"
DECISION_REVOKED = "revoked"

# Distinct positive-attesting sites required to promote corroborated -> consortium-attested (Sec. III-A).
ATTESTATION_PROMOTE_THRESHOLD = 3

# Event written to LocalDecisionVersion when a routine rescore drops below
# threshold while that site still has the fact Active. The local decision is
# retained and flagged; only an explicit lifecycle action changes enforcement.
EVENT_AUTO_FLAG_FOR_REVIEW = "auto_flag_for_review"


class Score(Base):
    """version doubles as SQLAlchemy's optimistic-concurrency token
    (__mapper_args__ below): every UPDATE is issued as
    ``... WHERE id=? AND version=?`` and SQLAlchemy bumps ``version``
    itself on a successful flush, raising StaleDataError if a concurrent
    session already moved it first. This is the CAS fix from Experiment C
    (fsm_concurrency_harness.py) -- callers no longer increment
    ``score.version`` by hand (see services.py); that would double-count
    against SQLAlchemy's own bump and defeat the token's purpose.
    """

    __tablename__ = "scores"
    __table_args__ = (
        UniqueConstraint("device_type", "endpoint", "protocol", "port", name="uq_score_identity"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_type: Mapped[str] = mapped_column(String, index=True)
    endpoint: Mapped[str] = mapped_column(String)
    protocol: Mapped[str] = mapped_column(String)
    port: Mapped[int] = mapped_column(Integer)
    site_confidence: Mapped[float] = mapped_column(Float)
    temporal_confidence: Mapped[float] = mapped_column(Float)
    graph_confidence: Mapped[float] = mapped_column(Float)
    score: Mapped[float] = mapped_column(Float)
    accepted: Mapped[bool] = mapped_column(Boolean)
    tier: Mapped[str] = mapped_column(String, default=TIER_CORROBORATED)
    status: Mapped[str] = mapped_column(String, default=STATUS_ACTIVE)
    version: Mapped[int] = mapped_column(Integer, default=1)
    __mapper_args__ = {"version_id_col": version}
    positive_attestations: Mapped[int] = mapped_column(Integer, default=0)
    negative_attestations: Mapped[int] = mapped_column(Integer, default=0)
    disputed_by: Mapped[str | None] = mapped_column(String, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    versions: Mapped[list["ScoreVersion"]] = relationship(back_populates="score_row", cascade="all, delete-orphan")
    local_decisions: Mapped[list["LocalDecision"]] = relationship(
        back_populates="score_row", cascade="all, delete-orphan"
    )


class ScoreVersion(Base):
    """Append-only history row, written on every upsert/attest/dispute/revoke/restore."""

    __tablename__ = "score_versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    score_id: Mapped[int] = mapped_column(ForeignKey("scores.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    site_confidence: Mapped[float] = mapped_column(Float)
    temporal_confidence: Mapped[float] = mapped_column(Float)
    graph_confidence: Mapped[float] = mapped_column(Float)
    score: Mapped[float] = mapped_column(Float)
    accepted: Mapped[bool] = mapped_column(Boolean)
    tier: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String)
    event: Mapped[str] = mapped_column(String)
    actor_site_id: Mapped[str | None] = mapped_column(String, nullable=True)
    reason: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    score_row: Mapped[Score] = relationship(back_populates="versions")


class LocalDecision(Base):
    """One site's import/enforcement decision for one globally scored fact."""

    __tablename__ = "local_decisions"
    __table_args__ = (UniqueConstraint("score_id", "site_id", name="uq_local_decision_site_score"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    score_id: Mapped[int] = mapped_column(ForeignKey("scores.id"), index=True)
    site_id: Mapped[str] = mapped_column(String, index=True)
    state: Mapped[str] = mapped_column(String, default=DECISION_MONITOR_ONLY)
    flagged_for_review: Mapped[bool] = mapped_column(Boolean, default=False)
    version: Mapped[int] = mapped_column(Integer, default=1)
    __mapper_args__ = {"version_id_col": version}
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    score_row: Mapped[Score] = relationship(back_populates="local_decisions")
    versions: Mapped[list["LocalDecisionVersion"]] = relationship(
        back_populates="decision_row", cascade="all, delete-orphan"
    )


class LocalDecisionVersion(Base):
    __tablename__ = "local_decision_versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    decision_id: Mapped[int] = mapped_column(ForeignKey("local_decisions.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String)
    flagged_for_review: Mapped[bool] = mapped_column(Boolean, default=False)
    event: Mapped[str] = mapped_column(String)
    actor_site_id: Mapped[str | None] = mapped_column(String, nullable=True)
    reason: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    decision_row: Mapped[LocalDecision] = relationship(back_populates="versions")


class Attestation(Base):
    """One site's current stance (positive/negative) on a Score; upserted per (score, site)."""

    __tablename__ = "attestations"
    __table_args__ = (UniqueConstraint("score_id", "site_id", name="uq_attestation_site"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    score_id: Mapped[int] = mapped_column(ForeignKey("scores.id"), index=True)
    site_id: Mapped[str] = mapped_column(String, index=True)
    kind: Mapped[str] = mapped_column(String)
    reason: Mapped[str | None] = mapped_column(String, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class Experiment(Base):
    __tablename__ = "experiments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, index=True)
    status: Mapped[str] = mapped_column(String, default="completed")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


_engine = None
_SessionLocal: sessionmaker | None = None


def _sqlite_wal_enabled() -> bool:
    """Opt-in only (DIB_SQLITE_WAL=1): default engine construction is
    unchanged so existing tests/experiments keep their prior behavior.
    Added to quantify (not silently fix) the p99-latency finding in the
    100-writer concurrency benchmark -- see fsm_concurrency_harness.py."""
    return os.environ.get("DIB_SQLITE_WAL", "") == "1"


def _pool_kwargs() -> dict:
    """Opt-in only (DIB_SQLITE_POOL_SIZE): default engine construction is
    unchanged (SQLAlchemy's QueuePool defaults, pool_size=5/max_overflow=10)
    so existing tests/experiments keep their prior behavior. Added to
    isolate whether pool-checkout queueing, not SQLite file locking, drives
    the p99-latency finding in the 100-writer concurrency benchmark."""
    raw = os.environ.get("DIB_SQLITE_POOL_SIZE", "")
    if not raw:
        return {}
    size = int(raw)
    return {"pool_size": size, "max_overflow": size}


def get_engine():
    global _engine
    if _engine is None:
        candidate = create_engine(database_url(), connect_args=_connect_args(), **_pool_kwargs())
        if database_url().startswith("sqlite") and _sqlite_wal_enabled():
            synchronous = os.environ.get("DIB_SQLITE_SYNCHRONOUS", "FULL")

            @event.listens_for(candidate, "connect")
            def _set_sqlite_pragmas(dbapi_connection, connection_record):  # noqa: ANN001
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA busy_timeout=30000")
                cursor.execute(f"PRAGMA synchronous={synchronous}")
                cursor.close()
        inspector = inspect(candidate)
        if inspector.has_table("scores") and not inspector.has_table("local_decisions"):
            candidate.dispose()
            raise RuntimeError(
                "legacy global-state registry detected; create a fresh database for the "
                "site-scoped lifecycle (automatic assignment to sites is intentionally unsupported)"
            )
        _engine = candidate
        Base.metadata.create_all(_engine)
    return _engine


def _connect_args() -> dict:
    return {"check_same_thread": False} if database_url().startswith("sqlite") else {}


def get_session() -> Session:
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(bind=get_engine())
    return _SessionLocal()
