"""Distributed prototype: N site processes + 1 evidence process, each a
real OS process (a Docker container in the deployed version), talking over
HTTP instead of sharing SQLite files. This replaces the ATTACH-based
sharded_prototype.py, whose cross-process file-sharing caused pathological
contention under real multi-process load (measured: N_SITES=10 performed
*worse* than N_SITES=1 once workers were genuine OS processes, not GIL-bound
threads -- see sharded_concurrency_benchmark_mp.py's results).

Design, addressing the reviewer-style critique that a naive ATTACH-to-HTTP
swap would just relocate the same bug class:

  - Single writer per site. The evidence service never touches a site's
    database. It only sends "apply this transition" requests over HTTP; each
    site is the only writer of its own local_decisions table, and applies
    the SAME provenance rule production services.py enforces centrally
    (Sec. III): a REVOKED decision whose origin is this site's own
    local_revoke is never overwritten by a fan-out event, only by this
    site's own local_restore. That check now lives where the record lives.

  - Idempotent, ordered fan-out. Every dispute/restore bumps a per-score
    monotonic fanout_seq at the evidence service. Each HTTP fan-out call
    carries that seq; a site ignores (no-ops) any call whose seq is <= the
    last one it already applied for that score_id -- a retried or duplicated
    call is a safe no-op, not a double-apply.

  - Explicit CP choice, not silent AP. A dispute/restore fans out
    synchronously with bounded retries per site (see _FANOUT_RETRIES/
    _FANOUT_TIMEOUT_S below). A site that is still unreachable after that
    budget is recorded in the evidence service's pending-fanout outbox
    (keyed by (site_id, score_id), overwritten with the latest target state
    -- reconciliation only needs the current truth, not full history) rather
    than blocking forever or silently dropping the update. A site calls
    GET /pending/{site_id} on startup/reconnect and applies whatever is
    queued through the identical idempotent apply path. This means I3
    ("dispute immediately clears export eligibility... across all sites") is
    honest only as "immediately at every reachable site; a partitioned site
    converges on reconnect" -- the fault-injection experiment
    (fault_injection_experiment.py) measures exactly that convergence
    window, rather than leaving it an unstated assumption.
"""
from __future__ import annotations

import os
import sqlite3
import threading
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

STATUS_ACTIVE = "active"
STATUS_DISPUTED = "disputed"
STATUS_REVOKED = "revoked"

DECISION_MONITOR_ONLY = "monitor-only"
DECISION_ACTIVE = "active"
DECISION_DISPUTED = "disputed"
DECISION_REVOKED = "revoked"

ORIGIN_LOCAL = "local"
ORIGIN_FANOUT = "fanout"

_FANOUT_RETRIES = 3
_FANOUT_TIMEOUT_S = 1.0

DATA_DIR = Path(os.environ.get("DIB_DIST_DATA_DIR", "/data"))
N_SITES = int(os.environ.get("DIB_DIST_N_SITES", "10"))
ROLE = os.environ.get("DIB_DIST_ROLE", "site")  # "site" or "evidence"
SITE_INDEX = int(os.environ.get("DIB_DIST_SITE_INDEX", "0"))
EVIDENCE_URL = os.environ.get("DIB_DIST_EVIDENCE_URL", "http://evidence:8000")


def _site_url(index: int) -> str:
    override = os.environ.get(f"DIB_DIST_SITE_URL_{index}")
    return override or f"http://site-{index}:8000"


class _Db:
    def __init__(self, path: Path, schema_sql: list[str]):
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)
        self._con = sqlite3.connect(str(path), check_same_thread=False, timeout=10)
        self._con.execute("PRAGMA journal_mode=WAL")
        self._con.execute("PRAGMA busy_timeout=10000")
        for stmt in schema_sql:
            self._con.execute(stmt)
        self._con.commit()

    def run(self, fn):
        with self._lock:
            try:
                result = fn(self._con)
                self._con.commit()
                return result
            except Exception:
                self._con.rollback()
                raise


app = FastAPI(title=f"DIB distributed prototype ({ROLE})")


# --------------------------------------------------------------------------
# Site role
# --------------------------------------------------------------------------

if ROLE == "site":
    _site_db = _Db(
        DATA_DIR / "site.db",
        [
            "CREATE TABLE IF NOT EXISTS local_decisions ("
            " score_id INTEGER PRIMARY KEY, state TEXT, origin TEXT, last_applied_seq INTEGER DEFAULT 0,"
            " device_type TEXT, endpoint TEXT, protocol TEXT, port INTEGER)",
        ],
    )

    class ApplyFanout(BaseModel):
        score_id: int
        seq: int
        event_type: str  # "dispute" | "revoke" | "restore"
        target_state: str

    class QueryReq(BaseModel):
        device_type: str
        endpoint: str
        protocol: str = "https"
        port: int = 443

    def _site_id() -> str:
        return f"site-{SITE_INDEX}"

    def _evidence_get_score(device_type: str, endpoint: str, protocol: str = "https", port: int = 443) -> dict | None:
        resp = httpx.get(
            f"{EVIDENCE_URL}/scores",
            params={"device_type": device_type, "endpoint": endpoint, "protocol": protocol, "port": port},
            timeout=5.0,
        )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()

    def _apply_fanout_row(con, score_id: int, seq: int, event_type: str, target_state: str) -> None:
        row = con.execute(
            "SELECT state, origin, last_applied_seq FROM local_decisions WHERE score_id=?", (score_id,)
        ).fetchone()
        if row is None:
            # No local record at this site for this fact -- nothing to fan out to.
            return
        state, origin, last_seq = row
        if seq <= last_seq:
            return  # already applied (or stale/duplicate) -- idempotent no-op
        if event_type == "restore" and state == DECISION_REVOKED and origin == ORIGIN_LOCAL:
            # Provenance guard, enforced locally: this site's own local_revoke
            # is never overwritten by a fan-out restore -- only local_restore can.
            con.execute("UPDATE local_decisions SET last_applied_seq=? WHERE score_id=?", (seq, score_id))
            return
        if event_type in ("dispute", "revoke") and state == DECISION_REVOKED and origin == ORIGIN_LOCAL:
            # Same guard for the opening/confirming dispute path (services.py's from_states check).
            con.execute("UPDATE local_decisions SET last_applied_seq=? WHERE score_id=?", (seq, score_id))
            return
        new_origin = None if target_state != DECISION_REVOKED else ORIGIN_FANOUT
        con.execute(
            "UPDATE local_decisions SET state=?, origin=?, last_applied_seq=? WHERE score_id=?",
            (target_state, new_origin, seq, score_id),
        )

    @app.post("/query")
    def query_score(req: QueryReq):
        score = _evidence_get_score(req.device_type, req.endpoint, req.protocol, req.port)
        if score is None or not score["accepted"] or score["status"] != STATUS_ACTIVE:
            return {"applied": False}

        def txn(con):
            existing = con.execute("SELECT 1 FROM local_decisions WHERE score_id=?", (score["id"],)).fetchone()
            if existing is not None:
                return
            con.execute(
                "INSERT INTO local_decisions"
                " (score_id, state, origin, last_applied_seq, device_type, endpoint, protocol, port)"
                " VALUES (?, ?, NULL, ?, ?, ?, ?, ?)",
                (score["id"], DECISION_MONITOR_ONLY, score["fanout_seq"],
                 req.device_type, req.endpoint, req.protocol, req.port),
            )

        _site_db.run(txn)
        return {"applied": True, "score_id": score["id"]}

    @app.post("/commit")
    def operator_commit(req: QueryReq):
        score = _evidence_get_score(req.device_type, req.endpoint, req.protocol, req.port)
        if score is None or not score["accepted"] or score["status"] != STATUS_ACTIVE:
            raise HTTPException(409, "global evidence is not admissible")

        def txn(con):
            row = con.execute("SELECT state FROM local_decisions WHERE score_id=?", (score["id"],)).fetchone()
            if row is None or row[0] != DECISION_MONITOR_ONLY:
                raise HTTPException(409, f"cannot commit: state is {row[0] if row else None!r}")
            con.execute("UPDATE local_decisions SET state=? WHERE score_id=?", (DECISION_ACTIVE, score["id"]))

        _site_db.run(txn)
        return {"applied": True}

    @app.post("/local_revoke")
    def local_revoke(req: QueryReq):
        score = _evidence_get_score(req.device_type, req.endpoint, req.protocol, req.port)
        if score is None:
            raise HTTPException(404, "unknown fact")

        def txn(con):
            row = con.execute("SELECT state FROM local_decisions WHERE score_id=?", (score["id"],)).fetchone()
            if row is None or row[0] not in (DECISION_MONITOR_ONLY, DECISION_ACTIVE):
                raise HTTPException(409, f"cannot local-revoke: state is {row[0] if row else None!r}")
            con.execute(
                "UPDATE local_decisions SET state=?, origin=? WHERE score_id=?",
                (DECISION_REVOKED, ORIGIN_LOCAL, score["id"]),
            )

        _site_db.run(txn)
        return {"applied": True}

    @app.post("/local_restore")
    def local_restore(req: QueryReq):
        score = _evidence_get_score(req.device_type, req.endpoint, req.protocol, req.port)
        if score is None:
            raise HTTPException(404, "unknown fact")
        if score["status"] in (STATUS_DISPUTED, STATUS_REVOKED):
            raise HTTPException(409, "a cross-site dispute episode is open")

        def txn(con):
            row = con.execute("SELECT state, origin FROM local_decisions WHERE score_id=?", (score["id"],)).fetchone()
            if row is None or row[0] != DECISION_REVOKED or row[1] != ORIGIN_LOCAL:
                raise HTTPException(409, "not locally revoked")
            con.execute(
                "UPDATE local_decisions SET state=?, origin=NULL WHERE score_id=?",
                (DECISION_MONITOR_ONLY, score["id"]),
            )

        _site_db.run(txn)
        return {"applied": True}

    @app.post("/apply_fanout")
    def apply_fanout(req: ApplyFanout):
        _site_db.run(lambda con: _apply_fanout_row(con, req.score_id, req.seq, req.event_type, req.target_state))
        return {"applied": True}

    @app.post("/reconcile")
    def reconcile():
        """Called by this site on startup/reconnect: pull any events the
        evidence service could not deliver while this site was unreachable,
        and apply them through the same idempotent path."""
        resp = httpx.get(f"{EVIDENCE_URL}/pending/{_site_id()}", timeout=5.0)
        resp.raise_for_status()
        pending = resp.json()["pending"]
        for item in pending:
            _site_db.run(
                lambda con, item=item: _apply_fanout_row(
                    con, item["score_id"], item["seq"], item["event_type"], item["target_state"]
                )
            )
        if pending:
            httpx.post(f"{EVIDENCE_URL}/pending/{_site_id()}/ack", timeout=5.0)
        return {"reconciled": len(pending)}

    @app.get("/export_mud")
    def export_mud(device_type: str, mud_url: str | None = None):
        """RFC 8520 MUD export for this site alone -- point 5 of the
        reviewer-style critique: reuses the same export_mud_file() the
        centralized registry uses (dib.evaluation.mud_export), fed from THIS
        site's own local_decisions instead of a direct SQLAlchemy session, so
        the OpenWrt/osMUD testbed can be driven from a real site container
        rather than only from the monolithic in-process path."""
        from dib.core.models import EndpointScore
        from dib.evaluation.mud_export import export_mud_file

        rows = _site_db.run(
            lambda con: con.execute(
                "SELECT endpoint, protocol, port FROM local_decisions"
                " WHERE state=? AND device_type=?",
                (DECISION_ACTIVE, device_type),
            ).fetchall()
        )
        scores = [
            EndpointScore(
                device_type=device_type, endpoint=endpoint, protocol=protocol, port=port,
                site_confidence=1.0, temporal_confidence=1.0, graph_confidence=0.0,
                score=1.0, accepted=True, supporting_sites=1, eligible_sites=1,
            )
            for endpoint, protocol, port in rows
        ]
        result = export_mud_file(device_type, scores, mud_url=mud_url)
        return result.document

    @app.get("/state/{score_id}")
    def get_state(score_id: int):
        row = _site_db.run(
            lambda con: con.execute(
                "SELECT state, origin, last_applied_seq FROM local_decisions WHERE score_id=?", (score_id,)
            ).fetchone()
        )
        if row is None:
            raise HTTPException(404, "no local decision")
        return {"state": row[0], "origin": row[1], "last_applied_seq": row[2]}

    @app.get("/health")
    def health():
        return {"status": "ok", "site_id": _site_id()}


# --------------------------------------------------------------------------
# Evidence role
# --------------------------------------------------------------------------

if ROLE == "evidence":
    _evidence_db = _Db(
        DATA_DIR / "evidence.db",
        [
            "CREATE TABLE IF NOT EXISTS scores (id INTEGER PRIMARY KEY, device_type TEXT, endpoint TEXT,"
            " protocol TEXT DEFAULT 'https', port INTEGER DEFAULT 443,"
            " status TEXT, disputed_by TEXT, positive_attestations INTEGER DEFAULT 0, fanout_seq INTEGER DEFAULT 0,"
            " accepted INTEGER DEFAULT 1, UNIQUE(device_type, endpoint, protocol, port))",
            "CREATE TABLE IF NOT EXISTS pending_fanout (site_id TEXT, score_id INTEGER, seq INTEGER,"
            " event_type TEXT, target_state TEXT, PRIMARY KEY (site_id, score_id))",
        ],
    )

    class SeedReq(BaseModel):
        device_type: str
        endpoint: str
        protocol: str = "https"
        port: int = 443

    class ActionReq(BaseModel):
        device_type: str
        endpoint: str
        protocol: str = "https"
        port: int = 443
        site_id: str | None = None

    def _get_score_row(con, device_type: str, endpoint: str, protocol: str, port: int):
        return con.execute(
            "SELECT id, status, disputed_by, fanout_seq, accepted FROM scores"
            " WHERE device_type=? AND endpoint=? AND protocol=? AND port=?",
            (device_type, endpoint, protocol, port),
        ).fetchone()

    def _fan_out(score_id: int, seq: int, event_type: str, target_state: str) -> None:
        for i in range(N_SITES):
            site_id = f"site-{i}"
            delivered = False
            for _attempt in range(_FANOUT_RETRIES):
                try:
                    resp = httpx.post(
                        f"{_site_url(i)}/apply_fanout",
                        json={"score_id": score_id, "seq": seq, "event_type": event_type, "target_state": target_state},
                        timeout=_FANOUT_TIMEOUT_S,
                    )
                    if resp.status_code == 200:
                        delivered = True
                        break
                except httpx.HTTPError:
                    pass
            if not delivered:
                _evidence_db.run(
                    lambda con, site_id=site_id: con.execute(
                        "INSERT INTO pending_fanout (site_id, score_id, seq, event_type, target_state)"
                        " VALUES (?, ?, ?, ?, ?)"
                        " ON CONFLICT(site_id, score_id) DO UPDATE SET seq=excluded.seq,"
                        " event_type=excluded.event_type, target_state=excluded.target_state"
                        " WHERE excluded.seq > pending_fanout.seq",
                        (site_id, score_id, seq, event_type, target_state),
                    )
                )

    @app.post("/seed")
    def seed(req: SeedReq):
        def txn(con):
            cur = con.execute(
                "INSERT INTO scores (device_type, endpoint, protocol, port, status, accepted) VALUES (?, ?, ?, ?, ?, 1)",
                (req.device_type, req.endpoint, req.protocol, req.port, STATUS_ACTIVE),
            )
            return cur.lastrowid

        score_id = _evidence_db.run(txn)
        return {"id": score_id}

    @app.get("/scores")
    def get_score(device_type: str, endpoint: str, protocol: str = "https", port: int = 443):
        row = _evidence_db.run(lambda con: _get_score_row(con, device_type, endpoint, protocol, port))
        if row is None:
            raise HTTPException(404, "unknown fact")
        return {"id": row[0], "status": row[1], "disputed_by": row[2], "fanout_seq": row[3], "accepted": bool(row[4])}

    @app.get("/scores/by_id/{score_id}")
    def get_score_by_id(score_id: int):
        row = _evidence_db.run(
            lambda con: con.execute(
                "SELECT device_type, endpoint, protocol, port FROM scores WHERE id=?", (score_id,)
            ).fetchone()
        )
        if row is None:
            raise HTTPException(404, "unknown fact")
        return {"device_type": row[0], "endpoint": row[1], "protocol": row[2], "port": row[3]}

    @app.post("/attest")
    def attest(req: ActionReq):
        def txn(con):
            row = _get_score_row(con, req.device_type, req.endpoint, req.protocol, req.port)
            if row is None:
                raise HTTPException(404, "unknown fact")
            con.execute(
                "UPDATE scores SET positive_attestations = positive_attestations + 1 WHERE id=?", (row[0],)
            )

        _evidence_db.run(txn)
        return {"applied": True}

    @app.post("/dispute")
    def dispute(req: ActionReq):
        def txn(con):
            row = _get_score_row(con, req.device_type, req.endpoint, req.protocol, req.port)
            if row is None:
                raise HTTPException(404, "unknown fact")
            score_id, status, disputed_by, seq, _accepted = row
            if status == STATUS_ACTIVE:
                new_seq = seq + 1
                con.execute(
                    "UPDATE scores SET status=?, disputed_by=?, fanout_seq=? WHERE id=?",
                    (STATUS_DISPUTED, req.site_id, new_seq, score_id),
                )
                return score_id, new_seq, "dispute", DECISION_DISPUTED
            if status == STATUS_DISPUTED and req.site_id != disputed_by:
                new_seq = seq + 1
                con.execute("UPDATE scores SET status=?, fanout_seq=? WHERE id=?", (STATUS_REVOKED, new_seq, score_id))
                return score_id, new_seq, "revoke", DECISION_REVOKED
            return None

        result = _evidence_db.run(txn)
        if result:
            _fan_out(*result)
        return {"applied": result is not None}

    @app.post("/restore")
    def restore(req: ActionReq):
        def txn(con):
            row = _get_score_row(con, req.device_type, req.endpoint, req.protocol, req.port)
            if row is None:
                raise HTTPException(404, "unknown fact")
            score_id, status, _disputed_by, seq, _accepted = row
            if status not in (STATUS_DISPUTED, STATUS_REVOKED):
                raise HTTPException(409, f"cannot restore: status is {status!r}")
            new_seq = seq + 1
            con.execute(
                "UPDATE scores SET status=?, disputed_by=NULL, fanout_seq=? WHERE id=?",
                (STATUS_ACTIVE, new_seq, score_id),
            )
            return score_id, new_seq

        score_id, new_seq = _evidence_db.run(txn)
        _fan_out(score_id, new_seq, "restore", DECISION_MONITOR_ONLY)
        return {"applied": True}

    @app.get("/pending/{site_id}")
    def get_pending(site_id: str):
        rows = _evidence_db.run(
            lambda con: con.execute(
                "SELECT score_id, seq, event_type, target_state FROM pending_fanout WHERE site_id=?", (site_id,)
            ).fetchall()
        )
        return {"pending": [
            {"score_id": r[0], "seq": r[1], "event_type": r[2], "target_state": r[3]} for r in rows
        ]}

    @app.post("/pending/{site_id}/ack")
    def ack_pending(site_id: str):
        _evidence_db.run(lambda con: con.execute("DELETE FROM pending_fanout WHERE site_id=?", (site_id,)))
        return {"acked": True}

    @app.get("/health")
    def health():
        return {"status": "ok"}
