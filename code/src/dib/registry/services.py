from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import StaleDataError

from dib.registry.db import (
    ATTESTATION_PROMOTE_THRESHOLD,
    DECISION_ACTIVE,
    DECISION_DISPUTED,
    DECISION_MONITOR_ONLY,
    DECISION_REVOKED,
    EVENT_AUTO_FLAG_FOR_REVIEW,
    STATUS_ACTIVE,
    STATUS_DISPUTED,
    STATUS_REVOKED,
    TIER_CONSORTIUM_ATTESTED,
    TIER_CORROBORATED,
    TIER_LOCAL,
    Attestation,
    Endpoint,
    LocalDecision,
    LocalDecisionVersion,
    ObservationRow,
    Profile,
    Score,
    ScoreVersion,
    Site,
)

from dib.core.models import EndpointScore, Observation
from dib.evaluation.dib import DIBScorer, ScoringConfig

# The paper's selected, non-mitigated operating point (Sec. IV-B): alpha=0.6,
# beta=0.4, gamma=0, theta=0.65, m=2, graph disabled. This is the
# configuration Criterion 1's analytical bound is stated for, and is what
# recompute_admission() below uses to check a claimed verdict against the
# registry's own stored evidence -- trust-weighting/clustering are empirical
# mitigations layered on top in the evaluation, not part of this boundary.
_REGISTRY_ADMISSION_CONFIG = ScoringConfig(
    alpha=0.6, beta=0.4, gamma=0.0, theta=0.65, min_reporting_sites=2, graph_enabled=False
)


def upsert_site(session: Session, site_id: str, trust_score: float = 1.0) -> Site:
    """Two sessions racing to first-register the same new site_id both pass the
    SELECT-finds-nothing check before either commits; the loser's INSERT then
    hits Site.site_id's unique constraint. Caught and treated as "someone else
    already created it" rather than left to crash the caller -- found via
    Experiment C's throughput sweep (record_observation from concurrent
    workers reporting a brand-new site), same race shape as
    _upsert_attestation's, fixed the same way.
    """
    site = session.scalar(select(Site).where(Site.site_id == site_id))
    if site is not None:
        return site
    site = Site(site_id=site_id, trust_score=trust_score)
    session.add(site)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        site = session.scalar(select(Site).where(Site.site_id == site_id))
        assert site is not None, "unique-constraint conflict on site_id but no row found after rollback"
    return site


def record_observation(session: Session, payload: dict) -> tuple[ObservationRow, bool]:
    """Idempotently store an observation. Returns (row, created)."""
    upsert_site(session, payload["site_id"])
    existing = session.scalar(
        select(ObservationRow).where(
            ObservationRow.site_id == payload["site_id"],
            ObservationRow.device_id == payload.get("device_id"),
            ObservationRow.device_type == payload["device_type"],
            ObservationRow.fqdn == payload.get("fqdn"),
            ObservationRow.remote_ip == payload.get("remote_ip"),
            ObservationRow.protocol == payload["protocol"],
            ObservationRow.port == payload["port"],
            ObservationRow.timestamp == payload["timestamp"],
            ObservationRow.evidence_type == payload["evidence_type"],
        )
    )
    if existing is not None:
        return existing, False
    row = ObservationRow(
        site_id=payload["site_id"],
        device_id=payload.get("device_id"),
        device_type=payload["device_type"],
        fqdn=payload.get("fqdn"),
        remote_ip=payload.get("remote_ip"),
        protocol=payload["protocol"],
        port=payload["port"],
        timestamp=payload["timestamp"],
        source_dataset=payload["source_dataset"],
        evidence_type=payload["evidence_type"],
        response_observed=bool(payload.get("response_observed", False)),
        direction=str(payload.get("direction", "out")),
    )
    session.add(row)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        existing = session.scalar(
            select(ObservationRow).where(
                ObservationRow.site_id == payload["site_id"],
                ObservationRow.device_type == payload["device_type"],
                ObservationRow.fqdn == payload.get("fqdn"),
                ObservationRow.protocol == payload["protocol"],
                ObservationRow.port == payload["port"],
                ObservationRow.timestamp == payload["timestamp"],
                ObservationRow.evidence_type == payload["evidence_type"],
            )
        )
        return existing, False
    return row, True


def upsert_profile(session: Session, site_id: str, device_type: str, endpoints: list[dict]) -> Profile:
    """Idempotently store/refresh a profile and its endpoint aggregates."""
    upsert_site(session, site_id)
    profile = session.scalar(
        select(Profile).where(Profile.site_id == site_id, Profile.device_type == device_type)
    )
    if profile is None:
        profile = Profile(site_id=site_id, device_type=device_type)
        session.add(profile)
        session.flush()

    existing_by_key = {(ep.fqdn, ep.protocol, ep.port): ep for ep in profile.endpoints}
    for item in endpoints:
        key = (item["fqdn"], item["protocol"], item["port"])
        first_seen = _parse_optional_datetime(item.get("first_seen"))
        last_seen = _parse_optional_datetime(item.get("last_seen"))
        if key in existing_by_key:
            endpoint = existing_by_key[key]
            endpoint.count = max(endpoint.count, int(item.get("count", 0)))
            endpoint.first_seen = min(filter(None, [endpoint.first_seen, first_seen]), default=endpoint.first_seen)
            endpoint.last_seen = max(filter(None, [endpoint.last_seen, last_seen]), default=endpoint.last_seen)
        else:
            session.add(
                Endpoint(
                    profile_id=profile.id,
                    fqdn=item["fqdn"],
                    protocol=item["protocol"],
                    port=int(item["port"]),
                    count=int(item.get("count", 0)),
                    first_seen=first_seen,
                    last_seen=last_seen,
                )
            )
    session.flush()
    return profile


def global_profile(session: Session, device_type: str) -> dict:
    profiles = session.scalars(select(Profile).where(Profile.device_type == device_type)).all()
    merged: dict[tuple[str, str, int], dict] = {}
    for profile in profiles:
        for endpoint in profile.endpoints:
            key = (endpoint.fqdn, endpoint.protocol, endpoint.port)
            if key not in merged:
                merged[key] = {
                    "fqdn": endpoint.fqdn,
                    "protocol": endpoint.protocol,
                    "port": endpoint.port,
                    "supporting_sites": 0,
                    "total_count": 0,
                }
            merged[key]["supporting_sites"] += 1
            merged[key]["total_count"] += endpoint.count
    return {
        "device_type": device_type,
        "site_count": len(profiles),
        "endpoints": sorted(merged.values(), key=lambda item: (-item["supporting_sites"], item["fqdn"])),
    }


_MAX_OPTIMISTIC_RETRIES = 10


def _retry_on_conflict(session: Session, attempt):
    """Re-run ``attempt`` (a read-validate-write closure) on a lost optimistic-lock
    race (StaleDataError, from Score's version_id_col -- see db.py) or a lost
    insert race on a unique constraint (IntegrityError, e.g. two sessions both
    inserting the first Attestation row for the same (score_id, site_id)).
    Both mean "another concurrent session committed first"; the fix is to roll
    back (which expires the session's cached objects) and retry from a fresh
    read, not to surface a crash to the caller for a race the caller did
    nothing wrong to trigger. Business-rule exceptions (InvalidStateTransition)
    are not caught here and propagate immediately -- those are not races.

    Found empirically in Experiment C (fsm_concurrency_harness.py): before
    this fix, concurrent same-site attestations crashed with an unhandled
    IntegrityError, and concurrent distinct-site disputes lost updates (both
    read status=ACTIVE before either committed, so neither ever reached the
    revoke branch) -- 100% and 10% violation rates respectively over 200
    trials. See CHANGES_FROM_DIAGNOSTIC.md / NEW_EXPERIMENTS_LOG.md for the
    before/after remeasurement.
    """
    for attempt_number in range(_MAX_OPTIMISTIC_RETRIES):
        try:
            return attempt()
        except (StaleDataError, IntegrityError):
            session.rollback()
            if attempt_number == _MAX_OPTIMISTIC_RETRIES - 1:
                raise
    raise AssertionError("unreachable")


def _observations_for_device(session: Session, device_type: str) -> list[Observation]:
    """Load this registry instance's own stored evidence for one device type,
    keyed exactly as dib.core.models.Observation.endpoint_key expects. Scoped
    to one device type (not the whole table) both because that is all
    DIBScorer needs for site_confidence's/temporal_confidence's denominators
    (Sec. IV-B) and to keep this bounded under the full observation volume
    (see KNOWN_LIMITATIONS.md on memory use of the graph-augmented path,
    which this deliberately does not touch: graph_enabled=False above)."""
    rows = session.scalars(select(ObservationRow).where(ObservationRow.device_type == device_type))
    observations: list[Observation] = []
    for row in rows:
        if not row.fqdn and not row.remote_ip:
            continue  # Observation.endpoint_key requires one of the two; nothing to score.
        observations.append(
            Observation(
                site_id=row.site_id,
                device_id=row.device_id,
                device_type=row.device_type,
                fqdn=row.fqdn,
                remote_ip=row.remote_ip,
                protocol=row.protocol,
                port=row.port,
                timestamp=row.timestamp,
                source_dataset=row.source_dataset,
                evidence_type=row.evidence_type,
                response_observed=row.response_observed,
                direction=row.direction,
            )
        )
    return observations


def recompute_admission(
    session: Session, device_type: str, endpoint: str, protocol: str, port: int
) -> EndpointScore | None:
    """Recompute the admission verdict for one fact strictly from evidence the
    registry itself holds, rather than trusting a caller's claim about it.

    This closes the admission trust boundary the paper's design describes but
    the prototype previously did not enforce (Sec. IV-A): an authenticated
    but dishonest contributor could otherwise stage an ineligible fact for
    later commit merely by asserting ``accepted=True`` in a /score payload,
    since upsert_score wrote that field verbatim. Returns None if the
    registry holds no observations at all for this device type -- there is
    then nothing to recompute from, and the caller (upsert_score) treats that
    as "not admitted" on the network-facing path rather than as license to
    fall back to the claimed verdict.
    """
    observations = _observations_for_device(session, device_type)
    if not observations:
        return None
    scores = DIBScorer(_REGISTRY_ADMISSION_CONFIG).score(observations, target_device_type=device_type)
    key = (device_type, endpoint.lower(), protocol.lower(), port)
    for entry in scores:
        if entry.endpoint_key == key:
            return entry
    return None


def upsert_score(session: Session, payload: dict, trust_client_verdict: bool = True) -> Score:
    """Store global evidence without creating or changing local authority.

    ``trust_client_verdict`` gates whether the caller's own
    site_confidence/temporal_confidence/score/accepted fields are written as
    given, or checked against ``recompute_admission`` first. It defaults to
    True so offline pipelines and existing tests that write pre-computed
    batch scores -- without ever populating this registry's ``observations``
    table row by row -- keep their exact prior behavior; only the
    network-facing endpoint (``registry.api.post_score``) opts out and passes
    False, which is the actual trust boundary a remote, possibly dishonest
    contributor crosses. When False and the registry holds observation
    evidence for this fact's device type, the recomputed verdict overrides
    whatever the caller sent; when it holds none, the fact is written as not
    admitted (fail closed) instead of trusting the unverifiable claim.
    """
    if not trust_client_verdict:
        recomputed = recompute_admission(
            session, payload["device_type"], payload["endpoint"], payload["protocol"], payload["port"]
        )
        if recomputed is not None:
            payload = {
                **payload,
                "site_confidence": recomputed.site_confidence,
                "temporal_confidence": recomputed.temporal_confidence,
                "graph_confidence": recomputed.graph_confidence,
                "score": recomputed.score,
                "accepted": recomputed.accepted,
            }
        else:
            payload = {**payload, "accepted": False}

    def attempt() -> Score:
        score = session.scalar(
            select(Score).where(
                Score.device_type == payload["device_type"],
                Score.endpoint == payload["endpoint"],
                Score.protocol == payload["protocol"],
                Score.port == payload["port"],
            )
        )
        if score is None:
            score = Score(
                device_type=payload["device_type"],
                endpoint=payload["endpoint"],
                protocol=payload["protocol"],
                port=payload["port"],
                site_confidence=payload["site_confidence"],
                temporal_confidence=payload["temporal_confidence"],
                graph_confidence=payload["graph_confidence"],
                score=payload["score"],
                accepted=payload["accepted"],
                tier=TIER_CORROBORATED if payload["accepted"] else TIER_LOCAL,
                status=STATUS_ACTIVE,
                version=1,
            )
            session.add(score)
            session.flush()
        else:
            score.site_confidence = payload["site_confidence"]
            score.temporal_confidence = payload["temporal_confidence"]
            score.graph_confidence = payload["graph_confidence"]
            score.score = payload["score"]
            score.accepted = payload["accepted"]
            if payload["accepted"] and score.tier == TIER_LOCAL:
                score.tier = TIER_CORROBORATED
            elif not payload["accepted"]:
                score.tier = TIER_LOCAL
            session.flush()

        for decision in list(score.local_decisions):
            should_flag = not score.accepted and decision.state == DECISION_ACTIVE
            if decision.flagged_for_review != should_flag:
                decision.flagged_for_review = should_flag
                session.flush()
                _snapshot_decision(
                    session,
                    decision,
                    EVENT_AUTO_FLAG_FOR_REVIEW if should_flag else "auto_clear_review",
                )
        _snapshot_version(session, score, event="upsert")
        return score

    return _retry_on_conflict(session, attempt)


def get_score(session: Session, device_type: str, endpoint: str, protocol: str, port: int) -> Score | None:
    return session.scalar(
        select(Score).where(
            Score.device_type == device_type,
            Score.endpoint == endpoint,
            Score.protocol == protocol,
            Score.port == port,
        )
    )


def get_score_history(session: Session, score_id: int) -> list[ScoreVersion]:
    return list(
        session.scalars(
            select(ScoreVersion).where(ScoreVersion.score_id == score_id).order_by(ScoreVersion.id)
        ).all()
    )


class InvalidStateTransition(ValueError):
    """Raised when an explicit lifecycle transition guard fails."""


# Backward-compatible alias: operator_commit() (Fase 2.3c) originally
# introduced this under the narrower name before restore_score() (Fase
# 2.3d) generalized the same guard-and-raise pattern to a second,
# orthogonal field (status, not import_state). Same class, not a subclass:
# existing `except InvalidImportStateTransition` call sites keep working
# unchanged for both guards.
InvalidImportStateTransition = InvalidStateTransition


def get_local_decision(session: Session, score_id: int, site_id: str) -> LocalDecision | None:
    return session.scalar(
        select(LocalDecision).where(LocalDecision.score_id == score_id, LocalDecision.site_id == site_id)
    )


def get_local_decision_history(session: Session, decision_id: int) -> list[LocalDecisionVersion]:
    return list(
        session.scalars(
            select(LocalDecisionVersion)
            .where(LocalDecisionVersion.decision_id == decision_id)
            .order_by(LocalDecisionVersion.id)
        ).all()
    )


def list_local_decisions(
    session: Session,
    site_id: str,
    device_type: str | None = None,
    state: str | None = None,
) -> list[LocalDecision]:
    statement = (
        select(LocalDecision)
        .join(Score, LocalDecision.score_id == Score.id)
        .where(LocalDecision.site_id == site_id)
        .order_by(Score.device_type, Score.endpoint, Score.protocol, Score.port)
    )
    if device_type is not None:
        statement = statement.where(Score.device_type == device_type)
    if state is not None:
        statement = statement.where(LocalDecision.state == state)
    return list(session.scalars(statement).all())


def query_score(
    session: Session,
    site_id: str,
    device_type: str,
    endpoint: str,
    protocol: str,
    port: int,
) -> LocalDecision | None:
    """Create a site's MonitorOnly record only for currently admissible evidence."""

    def attempt() -> LocalDecision | None:
        score = get_score(session, device_type, endpoint, protocol, port)
        if score is None or not score.accepted or score.status != STATUS_ACTIVE:
            return None
        upsert_site(session, site_id)
        decision = get_local_decision(session, score.id, site_id)
        if decision is not None:
            return decision
        decision = LocalDecision(score_id=score.id, site_id=site_id, state=DECISION_MONITOR_ONLY)
        session.add(decision)
        session.flush()
        _snapshot_decision(session, decision, "query", actor_site_id=site_id)
        return decision

    return _retry_on_conflict(session, attempt)


def operator_commit(
    session: Session,
    site_id: str,
    device_type: str,
    endpoint: str,
    protocol: str,
    port: int,
) -> LocalDecision | None:
    """The only transition that enables one site's enforcement."""

    def attempt() -> LocalDecision | None:
        score = get_score(session, device_type, endpoint, protocol, port)
        if score is None:
            return None
        decision = get_local_decision(session, score.id, site_id)
        if decision is None:
            return None
        if not score.accepted or score.status != STATUS_ACTIVE:
            raise InvalidImportStateTransition(
                f"cannot commit {site_id}/{device_type}/{endpoint}/{protocol}/{port}: "
                "global evidence is no longer admissible"
            )
        if decision.state != DECISION_MONITOR_ONLY:
            raise InvalidImportStateTransition(
                f"cannot commit {site_id}/{device_type}/{endpoint}/{protocol}/{port}: "
                f"state is {decision.state!r}, expected {DECISION_MONITOR_ONLY!r}"
            )
        decision.state = DECISION_ACTIVE
        decision.flagged_for_review = False
        session.flush()
        _snapshot_decision(session, decision, "operator_commit", actor_site_id=site_id)
        return decision

    return _retry_on_conflict(session, attempt)


def local_revoke(
    session: Session,
    site_id: str,
    device_type: str,
    endpoint: str,
    protocol: str,
    port: int,
    reason: str | None = None,
) -> LocalDecision | None:
    """Record a local veto, including during a shared withdrawal episode.

    Unlike dispute_score(), this touches only site_id's LocalDecision row: it
    never fans out over score.local_decisions, and it leaves score.status and
    disputed_by untouched, so it cannot open or close a cross-site dispute
    episode. It requires no vote from, and has no effect on, any other site --
    the site-local negative-authority counterpart to operator_commit().
    """

    def attempt() -> LocalDecision | None:
        score = get_score(session, device_type, endpoint, protocol, port)
        if score is None:
            return None
        decision = get_local_decision(session, score.id, site_id)
        if decision is None:
            return None
        if decision.state == DECISION_REVOKED:
            last_revoke = session.scalar(
                select(LocalDecisionVersion.event)
                .where(LocalDecisionVersion.decision_id == decision.id,
                       LocalDecisionVersion.event.in_({"local_revoke", "revoke"}))
                .order_by(LocalDecisionVersion.id.desc()).limit(1)
            )
            if last_revoke != "revoke":
                raise InvalidImportStateTransition("record is already locally revoked or has unknown provenance")
        elif decision.state not in {DECISION_MONITOR_ONLY, DECISION_ACTIVE, DECISION_DISPUTED}:
            raise InvalidImportStateTransition(
                f"cannot local-revoke {site_id}/{device_type}/{endpoint}/{protocol}/{port}: "
                f"state is {decision.state!r}"
            )
        decision.state = DECISION_REVOKED
        decision.flagged_for_review = False
        session.flush()
        _snapshot_decision(session, decision, "local_revoke", actor_site_id=site_id, reason=reason)
        return decision

    return _retry_on_conflict(session, attempt)


def local_restore(
    session: Session,
    site_id: str,
    device_type: str,
    endpoint: str,
    protocol: str,
    port: int,
    reason: str | None = None,
) -> LocalDecision | None:
    """Return site_id's own locally revoked record to MonitorOnly.

    Refuses while a cross-site dispute episode is open for this fact (score.status
    in {DISPUTED, REVOKED}): closing that episode is restore_score()'s job, issued
    once for every site, not this site-scoped action's. Without that guard, a site
    could unilaterally exit a live consortium dispute it does not control -- this
    is the guard whose absence a formal-model mutation control (see formal/DIB.tla,
    mutation m4) confirms is load-bearing. Either way, enforcement resumes only
    after a fresh operator_commit(), never automatically.
    """

    def attempt() -> LocalDecision | None:
        score = get_score(session, device_type, endpoint, protocol, port)
        if score is None:
            return None
        decision = get_local_decision(session, score.id, site_id)
        if decision is None:
            return None
        if score.status in {STATUS_DISPUTED, STATUS_REVOKED}:
            raise InvalidImportStateTransition(
                f"cannot local-restore {site_id}/{device_type}/{endpoint}/{protocol}/{port}: "
                f"a cross-site dispute episode is open (status is {score.status!r})"
            )
        if decision.state != DECISION_REVOKED:
            raise InvalidImportStateTransition(
                f"cannot local-restore {site_id}/{device_type}/{endpoint}/{protocol}/{port}: "
                f"state is {decision.state!r}, expected {DECISION_REVOKED!r}"
            )
        decision.state = DECISION_MONITOR_ONLY
        session.flush()
        _snapshot_decision(session, decision, "local_restore", actor_site_id=site_id, reason=reason)
        return decision

    return _retry_on_conflict(session, attempt)


def attest_score(
    session: Session,
    device_type: str,
    endpoint: str,
    protocol: str,
    port: int,
    site_id: str,
    reason: str | None = None,
) -> Score | None:
    """Record a positive attestation; promotes corroborated -> consortium-attested at the threshold."""

    def attempt() -> Score | None:
        score = get_score(session, device_type, endpoint, protocol, port)
        if score is None:
            return None
        upsert_site(session, site_id)
        _upsert_attestation(session, score.id, site_id, kind="positive", reason=reason)
        score.positive_attestations = _count_attestations(session, score.id, "positive")
        score.negative_attestations = _count_attestations(session, score.id, "negative")
        if (
            score.status == STATUS_ACTIVE
            and score.tier == TIER_CORROBORATED
            and score.positive_attestations >= ATTESTATION_PROMOTE_THRESHOLD
        ):
            score.tier = TIER_CONSORTIUM_ATTESTED
        session.flush()
        _snapshot_version(session, score, event="attest", actor_site_id=site_id, reason=reason)
        return score

    return _retry_on_conflict(session, attempt)


def dispute_score(
    session: Session,
    device_type: str,
    endpoint: str,
    protocol: str,
    port: int,
    site_id: str,
    reason: str | None = None,
) -> Score | None:
    """First negative attestation disputes; a second from a different site
    confirms revoke. Revoke is terminal here -- it does NOT restore.

    Opzione B (Fase 2.3d): restoring a disputed or revoked fact to ACTIVE is a
    deliberate, separate action (restore_score()), never an automatic
    consequence of remote evidence (a confirming dispute). This mirrors
    operator_commit() (STAGED -> ACTIVE): remote evidence can strengthen
    and stage a fact, or revoke it, but cannot by itself activate or
    reactivate one -- an auto-restore triggered by a network event would
    violate that invariant in substance, not just in naming. Formally
    consistent with main.tex's FSM alphabet (DISPUTE and RESTORE are
    distinct symbols, Sec. III). Fase 3 additionally corrected
    restore_score() itself so it can no longer reinstate ACTIVE directly
    either -- see its docstring and _restore_pinned_predecessor().
    """
    def attempt() -> Score | None:
        score = get_score(session, device_type, endpoint, protocol, port)
        if score is None:
            return None
        upsert_site(session, site_id)
        _upsert_attestation(session, score.id, site_id, kind="negative", reason=reason)
        score.positive_attestations = _count_attestations(session, score.id, "positive")
        score.negative_attestations = _count_attestations(session, score.id, "negative")

        if score.status == STATUS_ACTIVE:
            score.status = STATUS_DISPUTED
            score.disputed_by = site_id
            _transition_all_decisions(
                session, score, DECISION_DISPUTED, "dispute", site_id, reason,
                from_states={DECISION_MONITOR_ONLY, DECISION_ACTIVE, DECISION_DISPUTED},
            )
            session.flush()
            _snapshot_version(session, score, event="dispute", actor_site_id=site_id, reason=reason)
        elif score.status == STATUS_DISPUTED and site_id != score.disputed_by:
            score.status = STATUS_REVOKED
            _transition_all_decisions(
                session, score, DECISION_REVOKED, "revoke", site_id, reason,
                from_states={DECISION_MONITOR_ONLY, DECISION_ACTIVE, DECISION_DISPUTED},
            )
            session.flush()
            _snapshot_version(session, score, event="revoke", actor_site_id=site_id, reason=reason)
        return score

    return _retry_on_conflict(session, attempt)


def restore_score(
    session: Session,
    device_type: str,
    endpoint: str,
    protocol: str,
    port: int,
    actor_site_id: str | None = None,
    reason: str | None = None,
) -> Score | None:
    """Resolve an episode and reset only dispute-derived records to MonitorOnly.

    Restoring never reinstates local authorization: whether the fact was
    DISPUTED after one challenge or REVOKED after two, each site must issue a
    fresh operator_commit() before enforcement can resume.
    """
    def attempt() -> Score | None:
        score = get_score(session, device_type, endpoint, protocol, port)
        if score is None:
            return None
        if score.status not in {STATUS_DISPUTED, STATUS_REVOKED}:
            raise InvalidStateTransition(
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
        _transition_all_decisions(
            session, score, DECISION_MONITOR_ONLY, "restore", actor_site_id, reason,
            from_states={DECISION_DISPUTED, DECISION_REVOKED},
        )
        session.flush()
        _snapshot_version(session, score, "restore", actor_site_id, reason)
        return score

    return _retry_on_conflict(session, attempt)


def _transition_all_decisions(
    session: Session,
    score: Score,
    state: str,
    event: str,
    actor_site_id: str | None,
    reason: str | None,
    *,
    from_states: set[str],
) -> None:
    """Fan out a cross-site dispute/revoke/restore over every extant local
    record for this fact -- but only those currently in ``from_states``,
    mirroring the TLA+ model's guard (formal/DIB.tla, Dispute/Restore actions).
    A record a site already moved out of that set itself (e.g. via
    local_revoke(), which sets DECISION_REVOKED without going through this
    fan-out) is left untouched: a later cross-site dispute must not silently
    overwrite a site's own local-revoke decision, and restore must not touch
    a record that was never disputed/revoked in the first place. Global
    restore additionally checks revocation provenance in the audit history:
    both local and consortium withdrawals share DECISION_REVOKED.
    """
    for decision in list(score.local_decisions):
        if decision.state not in from_states:
            continue
        if event == "restore" and decision.state == DECISION_REVOKED:
            revocation_event = session.scalar(
                select(LocalDecisionVersion.event)
                .where(
                    LocalDecisionVersion.decision_id == decision.id,
                    LocalDecisionVersion.state == DECISION_REVOKED,
                    LocalDecisionVersion.event.in_({"local_revoke", "revoke"}),
                )
                .order_by(LocalDecisionVersion.id.desc())
                .limit(1)
            )
            # Only positively identified consortium revocations can reset.
            # Missing provenance is conservatively left for local review.
            if revocation_event != "revoke":
                continue
        decision.state = state
        decision.flagged_for_review = False
        session.flush()
        _snapshot_decision(session, decision, event, actor_site_id, reason)


def export_active_mud(
    session: Session, site_id: str, device_type: str, mud_url: str | None = None
):
    """Serialize only representable facts explicitly activated at ``site_id``.

    The local decision is authoritative for routine rescoring: an Active fact
    remains exported while flagged for review even when its current global
    score falls below the admission threshold. A consortium dispute/revoke is
    different: it changes the decision state and therefore removes the fact.
    """
    from dib.evaluation.mud_export import export_mud_file

    decisions = list_local_decisions(session, site_id, device_type, DECISION_ACTIVE)
    scores = [
        EndpointScore(
            device_type=decision.score_row.device_type,
            endpoint=decision.score_row.endpoint,
            protocol=decision.score_row.protocol,
            port=decision.score_row.port,
            site_confidence=decision.score_row.site_confidence,
            temporal_confidence=decision.score_row.temporal_confidence,
            graph_confidence=decision.score_row.graph_confidence,
            score=decision.score_row.score,
            accepted=True,
            supporting_sites=max(0, decision.score_row.positive_attestations),
            eligible_sites=0,
        )
        for decision in decisions
    ]
    response_rows = session.scalars(
        select(ObservationRow).where(
            ObservationRow.site_id == site_id,
            ObservationRow.device_type == device_type,
            ObservationRow.direction == "out",
            ObservationRow.response_observed.is_(True),
        )
    ).all()
    response_keys = {
        (
            row.device_type,
            str(row.fqdn or row.remote_ip).lower(),
            row.protocol.lower(),
            row.port,
        )
        for row in response_rows
        if row.fqdn or row.remote_ip
    }
    return export_mud_file(
        device_type, scores, mud_url=mud_url, response_leg_endpoints=response_keys
    )


def _upsert_attestation(session: Session, score_id: int, site_id: str, kind: str, reason: str | None) -> Attestation:
    attestation = session.scalar(
        select(Attestation).where(Attestation.score_id == score_id, Attestation.site_id == site_id)
    )
    if attestation is None:
        attestation = Attestation(score_id=score_id, site_id=site_id, kind=kind, reason=reason)
        session.add(attestation)
    else:
        attestation.kind = kind
        attestation.reason = reason
        attestation.updated_at = datetime.now(timezone.utc)
    session.flush()
    return attestation


def _count_attestations(session: Session, score_id: int, kind: str) -> int:
    count = session.scalar(
        select(func.count()).select_from(Attestation).where(Attestation.score_id == score_id, Attestation.kind == kind)
    )
    return int(count or 0)


def _snapshot_version(
    session: Session, score: Score, event: str, actor_site_id: str | None = None, reason: str | None = None
) -> ScoreVersion:
    row = ScoreVersion(
        score_id=score.id,
        version=score.version,
        site_confidence=score.site_confidence,
        temporal_confidence=score.temporal_confidence,
        graph_confidence=score.graph_confidence,
        score=score.score,
        accepted=score.accepted,
        tier=score.tier,
        status=score.status,
        event=event,
        actor_site_id=actor_site_id,
        reason=reason,
    )
    session.add(row)
    session.flush()
    return row


def _snapshot_decision(
    session: Session,
    decision: LocalDecision,
    event: str,
    actor_site_id: str | None = None,
    reason: str | None = None,
) -> LocalDecisionVersion:
    row = LocalDecisionVersion(
        decision_id=decision.id,
        version=decision.version,
        state=decision.state,
        flagged_for_review=decision.flagged_for_review,
        event=event,
        actor_site_id=actor_site_id,
        reason=reason,
    )
    session.add(row)
    session.flush()
    return row


def _parse_optional_datetime(value: object) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
