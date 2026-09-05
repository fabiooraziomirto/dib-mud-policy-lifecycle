"""Per-site sharding prototype for the registry (validates the Sec.
Scalability discussion of an alternative architecture; not wired into the
production FastAPI registry in api.py/services.py).

Design, matching the site-scoped nature of the lifecycle already described
in the paper (Sec. III): shared evidence (Score) lives in one central
SQLite file; each site's own local authority state (LocalDecision) lives in
its own SQLite file. Site-scoped operations (query/commit/contribute) touch
only that site's file, so N sites can write in true parallel -- SQLite's
single-writer lock is per *file*, not per *row* (confirmed experimentally:
distinct files never contend). The rare cross-site fan-out operations
(dispute confirmation, restore) still need one atomic transaction touching
the central Score row and every affected site's LocalDecision row; this
uses SQLite's native ATTACH DATABASE, which gives a genuinely atomic
multi-file commit on one connection (verified: a forced mid-transaction
failure rolls back every attached file together, not just the main one).

Hard limit: a connection can ATTACH at most 10 databases in a stock SQLite
build (SQLITE_LIMIT_ATTACHED default; verified empirically -- the 11th
ATTACH raises "too many attached databases"). This prototype is therefore
sized for N_SITES=10, matching a realistic bounded MUD-sharing consortium
(the threat model already assumes out-of-band-authenticated membership,
i.e., a curated set of organizations, not an open population) and giving
meaningful headroom over the paper's 3-site TLA+ model. Larger consortia
would need SQLite compiled with a raised SQLITE_MAX_ATTACHED (up to 125)
or a backend with native row-level locking (Sec. Scalability's PostgreSQL
discussion).
"""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

STATUS_ACTIVE = "active"
STATUS_DISPUTED = "disputed"
STATUS_REVOKED = "revoked"

DECISION_MONITOR_ONLY = "monitor-only"
DECISION_ACTIVE = "active"
DECISION_DISPUTED = "disputed"
DECISION_REVOKED = "revoked"

N_SITES = 10


class InvalidStateTransition(ValueError):
    pass


class RetryExhausted(RuntimeError):
    pass


_MAX_RETRIES = 10

# One dedicated connection per site file (site-local hot path: query/commit/
# contribute), plus one dedicated connection with the central evidence.db as
# main and all N_SITES site databases ATTACHed (rare cross-site fan-out:
# dispute/restore/attest). Each connection is guarded by its own lock so
# concurrent callers serialize correctly per-connection without relying on
# SQLite's own busy-wait for coordination within this process.
_site_conns: dict[int, sqlite3.Connection] = {}
_site_locks: dict[int, threading.Lock] = {}
_central_conn: sqlite3.Connection | None = None
_central_lock = threading.Lock()


def site_id_for(index: int) -> str:
    return f"site-{index}"


def attach(output_dir: Path) -> None:
    """Open this process's own connections to an already-initialized set of
    databases (created by a prior init() call), without dropping/recreating
    schema or data. For the multiprocess benchmark: each worker OS process
    calls this once at startup so it holds independent sqlite3 connections
    to the same on-disk files -- real concurrent multi-process access to a
    WAL-mode file (what a genuine multi-site deployment looks like), as
    opposed to multiple threads sharing one connection inside one
    GIL-bound process."""
    global _central_conn
    for i in range(N_SITES):
        path = output_dir / f"site_{i}.db"
        con = sqlite3.connect(str(path), check_same_thread=False, timeout=30)
        con.execute("PRAGMA busy_timeout=3000")
        _site_conns[i] = con
        _site_locks[i] = threading.Lock()

    central = sqlite3.connect(str(output_dir / "evidence.db"), check_same_thread=False, timeout=30)
    central.execute("PRAGMA busy_timeout=3000")
    for i in range(N_SITES):
        central.execute(f"ATTACH DATABASE '{output_dir / f'site_{i}.db'}' AS site_{i}")
        central.execute(f"PRAGMA site_{i}.busy_timeout=3000")
    _central_conn = central


def init(output_dir: Path) -> None:
    """(Re)create the central + per-site databases from scratch."""
    global _central_conn
    output_dir.mkdir(parents=True, exist_ok=True)

    evidence_path = output_dir / "evidence.db"
    evidence_path.unlink(missing_ok=True)
    for i in range(N_SITES):
        (output_dir / f"site_{i}.db").unlink(missing_ok=True)

    # Per-site connections: independent files, independent write locks.
    for i in range(N_SITES):
        path = output_dir / f"site_{i}.db"
        con = sqlite3.connect(str(path), check_same_thread=False, timeout=30)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA busy_timeout=3000")
        con.execute(
            "CREATE TABLE local_decisions ("
            " score_id INTEGER, site_id TEXT, state TEXT, version INTEGER,"
            " UNIQUE(score_id, site_id))"
        )
        con.execute("CREATE TABLE observations (site_id TEXT, device_type TEXT, fqdn TEXT)")
        con.commit()
        _site_conns[i] = con
        _site_locks[i] = threading.Lock()

    # Central connection: evidence.db as main, every site file ATTACHed --
    # this is the one connection allowed to run atomic cross-site fan-outs.
    central = sqlite3.connect(str(evidence_path), check_same_thread=False, timeout=30)
    central.execute("PRAGMA journal_mode=WAL")
    central.execute("PRAGMA busy_timeout=3000")
    central.execute(
        "CREATE TABLE scores ("
        " id INTEGER PRIMARY KEY, device_type TEXT, endpoint TEXT, protocol TEXT, port INTEGER,"
        " status TEXT, disputed_by TEXT, positive_attestations INTEGER, negative_attestations INTEGER,"
        " accepted INTEGER, version INTEGER,"
        " UNIQUE(device_type, endpoint, protocol, port))"
    )
    central.commit()
    for i in range(N_SITES):
        central.execute(f"ATTACH DATABASE '{output_dir / f'site_{i}.db'}' AS site_{i}")
        central.execute(f"PRAGMA site_{i}.busy_timeout=3000")
    _central_conn = central


def _central_read(sql: str, params: tuple):
    """A plain sqlite3.Connection is not safe for concurrent statement
    execution from multiple threads even with check_same_thread=False --
    every access to _central_conn (reads included) must go through
    _central_lock, or concurrent threads can hang the underlying C-level
    connection state (observed directly: unguarded concurrent reads here
    hung the benchmark above ~50 workers)."""
    with _central_lock:
        return _central_conn.execute(sql, params).fetchone()


def _retry(lock: threading.Lock, fn):
    for attempt in range(_MAX_RETRIES):
        with lock:
            try:
                return fn()
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc) and "busy" not in str(exc):
                    raise
        if attempt == _MAX_RETRIES - 1:
            raise RetryExhausted(str(exc))


def seed_score(device_type: str, endpoint: str) -> int:
    def attempt():
        cur = _central_conn.execute(
            "INSERT INTO scores (device_type, endpoint, protocol, port, status, disputed_by,"
            " positive_attestations, negative_attestations, accepted, version)"
            " VALUES (?, ?, 'https', 443, ?, NULL, 0, 0, 1, 1)",
            (device_type, endpoint, STATUS_ACTIVE),
        )
        _central_conn.commit()
        return cur.lastrowid

    return _retry(_central_lock, attempt)


def record_observation(site_index: int, device_type: str, fqdn: str) -> None:
    """Site-local hot path: touches only this site's own file."""
    con = _site_conns[site_index]

    def attempt():
        con.execute("INSERT INTO observations VALUES (?, ?, ?)", (site_id_for(site_index), device_type, fqdn))
        con.commit()

    _retry(_site_locks[site_index], attempt)


def query_score(site_index: int, device_type: str, endpoint: str) -> None:
    """Site-local hot path: reads central Score (no write lock needed for a
    read), writes only to this site's own LocalDecision file."""
    row = _central_read(
        "SELECT id, status, accepted FROM scores WHERE device_type=? AND endpoint=? AND protocol='https' AND port=443",
        (device_type, endpoint),
    )
    if row is None or not row[2] or row[1] != STATUS_ACTIVE:
        return
    score_id = row[0]
    con = _site_conns[site_index]

    def attempt():
        existing = con.execute(
            "SELECT state FROM local_decisions WHERE score_id=? AND site_id=?", (score_id, site_id_for(site_index))
        ).fetchone()
        if existing is not None:
            return
        con.execute(
            "INSERT INTO local_decisions VALUES (?, ?, ?, 1)", (score_id, site_id_for(site_index), DECISION_MONITOR_ONLY)
        )
        con.commit()

    _retry(_site_locks[site_index], attempt)


def operator_commit(site_index: int, device_type: str, endpoint: str) -> None:
    """Site-local hot path: MonitorOnly -> Active for this site's own record."""
    row = _central_read(
        "SELECT id, status, accepted FROM scores WHERE device_type=? AND endpoint=? AND protocol='https' AND port=443",
        (device_type, endpoint),
    )
    if row is None or not row[2] or row[1] != STATUS_ACTIVE:
        return
    score_id = row[0]
    con = _site_conns[site_index]

    def attempt():
        cur = con.execute(
            "UPDATE local_decisions SET state=?, version=version+1"
            " WHERE score_id=? AND site_id=? AND state=?",
            (DECISION_ACTIVE, score_id, site_id_for(site_index), DECISION_MONITOR_ONLY),
        )
        con.commit()

    _retry(_site_locks[site_index], attempt)


def attest_score(device_type: str, endpoint: str, actor_site_index: int) -> None:
    """Central path: bumps the shared corroboration counter on Score."""

    def attempt():
        _central_conn.execute(
            "UPDATE scores SET positive_attestations = positive_attestations + 1, version = version + 1"
            " WHERE device_type=? AND endpoint=? AND protocol='https' AND port=443",
            (device_type, endpoint),
        )
        _central_conn.commit()

    _retry(_central_lock, attempt)


def dispute_score(device_type: str, endpoint: str, actor_site_index: int) -> None:
    """Central path: rare cross-site event. Atomically transitions the
    shared Score and fans out to every attached site's LocalDecision in one
    transaction (first dispute opens the episode; a second, distinct-site
    dispute confirms/revokes -- same two-step semantics as services.py)."""

    def attempt():
        row = _central_conn.execute(
            "SELECT id, status, disputed_by FROM scores WHERE device_type=? AND endpoint=? AND protocol='https' AND port=443",
            (device_type, endpoint),
        ).fetchone()
        if row is None:
            return
        score_id, status, disputed_by = row
        actor = site_id_for(actor_site_index)
        _central_conn.execute("BEGIN")
        try:
            if status == STATUS_ACTIVE:
                _central_conn.execute(
                    "UPDATE scores SET status=?, disputed_by=?, version=version+1 WHERE id=?",
                    (STATUS_DISPUTED, actor, score_id),
                )
                for i in range(N_SITES):
                    _central_conn.execute(
                        f"UPDATE site_{i}.local_decisions SET state=?, version=version+1"
                        f" WHERE score_id=? AND state IN (?, ?, ?)",
                        (DECISION_DISPUTED, score_id, DECISION_MONITOR_ONLY, DECISION_ACTIVE, DECISION_DISPUTED),
                    )
            elif status == STATUS_DISPUTED and actor != disputed_by:
                _central_conn.execute(
                    "UPDATE scores SET status=?, version=version+1 WHERE id=?", (STATUS_REVOKED, score_id)
                )
                for i in range(N_SITES):
                    _central_conn.execute(
                        f"UPDATE site_{i}.local_decisions SET state=?, version=version+1"
                        f" WHERE score_id=? AND state IN (?, ?, ?)",
                        (DECISION_REVOKED, score_id, DECISION_MONITOR_ONLY, DECISION_ACTIVE, DECISION_DISPUTED),
                    )
            _central_conn.commit()
        except Exception:
            _central_conn.rollback()
            raise

    _retry(_central_lock, attempt)


def restore_score(device_type: str, endpoint: str) -> None:
    """Central path: rare cross-site event, atomic fan-out back to MonitorOnly."""

    def attempt():
        row = _central_conn.execute(
            "SELECT id, status FROM scores WHERE device_type=? AND endpoint=? AND protocol='https' AND port=443",
            (device_type, endpoint),
        ).fetchone()
        if row is None:
            return
        score_id, status = row
        if status not in (STATUS_DISPUTED, STATUS_REVOKED):
            raise InvalidStateTransition("not disputed/revoked")
        _central_conn.execute("BEGIN")
        try:
            _central_conn.execute(
                "UPDATE scores SET status=?, disputed_by=NULL, version=version+1 WHERE id=?",
                (STATUS_ACTIVE, score_id),
            )
            for i in range(N_SITES):
                _central_conn.execute(
                    f"UPDATE site_{i}.local_decisions SET state=?, version=version+1"
                    f" WHERE score_id=? AND state IN (?, ?)",
                    (DECISION_MONITOR_ONLY, score_id, DECISION_DISPUTED, DECISION_REVOKED),
                )
            _central_conn.commit()
        except Exception:
            _central_conn.rollback()
            raise

    _retry(_central_lock, attempt)
