"""Experiment C -- concurrency and FSM correctness under real load.

Simulates the FastAPI registry's own per-request pattern (session_dependency
in registry/api.py: one Session per unit of work, a single commit at the
end, session closed after) directly against services.py from real OS
threads sharing one SQLAlchemy engine bound to one on-disk SQLite file
(connect_args={"check_same_thread": False} already set in db.py -- this
was clearly anticipated, not accidental). This is deliberately NOT routed
through HTTP/uvicorn: the request-handling layer (Starlette's threadpool)
would only add scheduling noise around the exact same session lifecycle
this script reproduces directly, and the invariants under test live in
services.py, not in routing.

Two kinds of runs:
  1. Throughput/latency sweep at N concurrent workers in {1,10,50,100} over
     a mixed CONTRIBUTE/QUERY/ATTEST/DISPUTE/COMMIT/RESTORE workload.
  2. Five targeted invariant tests (>=200 trials each, fresh fact per
     trial, two competing operations launched via a barrier so both threads
     enter their race window as close to simultaneously as the GIL/OS
     scheduler allows) -- see INVARIANTS below for what each checks.

If a trial violates its invariant, this is reported AND (per instructions)
the minimal fix is applied to services.py, then the same trials are re-run
and both before/after counts are reported -- never silently documented.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import statistics
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dib.registry import services
from dib.registry.db import (
    Base,
    DECISION_ACTIVE,
    DECISION_DISPUTED,
    DECISION_MONITOR_ONLY,
    DECISION_REVOKED,
    STATUS_ACTIVE,
    STATUS_DISPUTED,
    STATUS_REVOKED,
    TIER_CONSORTIUM_ATTESTED,
    ScoreVersion,
    get_engine,
)
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import StaleDataError


def fresh_engine(db_path: Path):
    import os
    os.environ["DIB_DATABASE_URL"] = f"sqlite:///{db_path}"
    import dib.registry.db as db_module
    db_module._engine = None
    db_module._SessionLocal = None
    engine = get_engine()
    return engine


def new_session_factory():
    import dib.registry.db as db_module
    return db_module.get_session


def seed_score(get_session, device_type: str, endpoint: str, accepted: bool = True) -> None:
    session = get_session()
    try:
        services.upsert_score(session, {
            "device_type": device_type, "endpoint": endpoint, "protocol": "https", "port": 443,
            "site_confidence": 0.9, "temporal_confidence": 0.9, "graph_confidence": 0.0,
            "score": 0.9, "accepted": accepted,
        })
        session.commit()
    finally:
        session.close()


def timed_call(get_session, fn_name: str, *args, **kwargs) -> tuple[float, object, Exception | None]:
    session = get_session()
    started = time.perf_counter()
    err = None
    result = None
    try:
        fn = getattr(services, fn_name)
        result = fn(session, *args, **kwargs)
        session.commit()
    except Exception as exc:  # noqa: BLE001 -- deliberately capturing to count, not hide
        session.rollback()
        err = exc
    finally:
        session.close()
    elapsed = time.perf_counter() - started
    return elapsed, result, err


def capture_hardware_info() -> dict:
    """Best-effort snapshot of the machine this run executed on, so
    throughput/latency numbers can be read alongside the hardware that
    produced them rather than assumed portable across machines."""
    cpu_model = platform.processor() or ""
    cpuinfo_path = Path("/proc/cpuinfo")
    if not cpu_model and cpuinfo_path.exists():
        try:
            for line in cpuinfo_path.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.lower().startswith("model name"):
                    cpu_model = line.split(":", 1)[1].strip()
                    break
        except OSError:
            pass
    return {
        "platform": platform.platform(),
        "processor": cpu_model or "unknown",
        "cpu_count": os_cpu_count(),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
    }


def os_cpu_count() -> int | None:
    import os
    return os.cpu_count()


# ---------------------------------------------------------------------------
# Throughput / latency sweep
# ---------------------------------------------------------------------------

def run_throughput_sweep(
    get_session,
    worker_counts: list[int],
    ops_per_worker: int,
    warmup_ops: int = 0,
    repeats: int = 1,
) -> list[dict]:
    rows = []
    for device_type in ("cam-a", "cam-b", "cam-c"):
        for i in range(5):
            seed_score(get_session, device_type, f"ep-{i}.example")

    def do_op(worker_id: int, op_index: int) -> tuple[str, float, bool]:
        device_type = ("cam-a", "cam-b", "cam-c")[worker_id % 3]
        endpoint = f"ep-{op_index % 5}.example"
        op = ["contribute", "query", "attest", "dispute", "commit", "restore"][op_index % 6]
        if op == "contribute":
            elapsed, _, err = timed_call(get_session, "record_observation", {
                "site_id": f"worker-{worker_id}", "device_id": "d1", "device_type": device_type,
                "fqdn": endpoint, "remote_ip": None, "protocol": "https", "port": 443,
                "timestamp": __import__("datetime").datetime(2026, 1, 1 + (op_index % 27), tzinfo=__import__("datetime").timezone.utc),
                "source_dataset": "load_test", "evidence_type": "flow",
            })
        elif op == "query":
            elapsed, _, err = timed_call(
                get_session, "query_score", f"worker-{worker_id}", device_type, endpoint, "https", 443
            )
        elif op == "attest":
            elapsed, _, err = timed_call(get_session, "attest_score", device_type, endpoint, "https", 443, f"worker-{worker_id}")
        elif op == "dispute":
            elapsed, _, err = timed_call(get_session, "dispute_score", device_type, endpoint, "https", 443, f"worker-{worker_id}")
        elif op == "commit":
            elapsed, _, err = timed_call(
                get_session, "operator_commit", f"worker-{worker_id}", device_type, endpoint, "https", 443
            )
        else:
            elapsed, _, err = timed_call(get_session, "restore_score", device_type, endpoint, "https", 443)
        return op, elapsed, err is not None and not isinstance(err, services.InvalidStateTransition)

    def run_one_batch(n_workers: int, n_ops: int) -> tuple[dict[str, list[float]], int, float]:
        latencies: dict[str, list[float]] = {}
        unexpected_errors = 0
        started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=n_workers) as pool:
            futures = [
                pool.submit(do_op, w, o)
                for w in range(n_workers)
                for o in range(n_ops)
            ]
            for fut in as_completed(futures):
                op, elapsed, is_unexpected = fut.result()
                latencies.setdefault(op, []).append(elapsed)
                if is_unexpected:
                    unexpected_errors += 1
        wall = time.perf_counter() - started
        return latencies, unexpected_errors, wall

    def pct(all_lat: list[float], p: float) -> float:
        if not all_lat:
            return 0.0
        idx = min(len(all_lat) - 1, int(round(p * (len(all_lat) - 1))))
        return all_lat[idx]

    for n_workers in worker_counts:
        if warmup_ops > 0:
            print(f"  n_workers={n_workers}: warm-up ({warmup_ops} ops/worker, discarded)...", flush=True)
            run_one_batch(n_workers, warmup_ops)

        total_ops = n_workers * ops_per_worker
        throughputs = []
        p50s, p95s, p99s = [], [], []
        unexpected_errors_total = 0
        wall_total = 0.0
        for rep in range(repeats):
            latencies, unexpected_errors, wall = run_one_batch(n_workers, ops_per_worker)
            all_lat = sorted(v for vals in latencies.values() for v in vals)
            throughputs.append(total_ops / wall if wall else 0.0)
            p50s.append(pct(all_lat, 0.50))
            p95s.append(pct(all_lat, 0.95))
            p99s.append(pct(all_lat, 0.99))
            unexpected_errors_total += unexpected_errors
            wall_total += wall
            print(f"  n_workers={n_workers} rep={rep + 1}/{repeats}: {total_ops} ops in {wall:.2f}s "
                  f"({total_ops/wall:.1f} ops/s), p50={pct(all_lat, 0.50)*1000:.1f}ms "
                  f"p95={pct(all_lat, 0.95)*1000:.1f}ms p99={pct(all_lat, 0.99)*1000:.1f}ms, "
                  f"unexpected_errors={unexpected_errors}", flush=True)

        def mean(xs: list[float]) -> float:
            return statistics.mean(xs) if xs else 0.0

        def stdev(xs: list[float]) -> float:
            return statistics.stdev(xs) if len(xs) > 1 else 0.0

        rows.append({
            "n_workers": n_workers, "total_ops": total_ops, "repeats": repeats,
            "warmup_ops_per_worker": warmup_ops,
            "wall_seconds_mean": round(wall_total / repeats, 4),
            "throughput_ops_per_sec_mean": round(mean(throughputs), 2),
            "throughput_ops_per_sec_std": round(stdev(throughputs), 2),
            "p50_latency_s_mean": round(mean(p50s), 6), "p50_latency_s_std": round(stdev(p50s), 6),
            "p95_latency_s_mean": round(mean(p95s), 6), "p95_latency_s_std": round(stdev(p95s), 6),
            "p99_latency_s_mean": round(mean(p99s), 6), "p99_latency_s_std": round(stdev(p99s), 6),
            "unexpected_errors": unexpected_errors_total,
        })
        print(f"  n_workers={n_workers} SUMMARY over {repeats} rep(s): "
              f"throughput={mean(throughputs):.1f}+/-{stdev(throughputs):.1f} ops/s, "
              f"p50={mean(p50s)*1000:.1f}+/-{stdev(p50s)*1000:.1f}ms "
              f"p95={mean(p95s)*1000:.1f}+/-{stdev(p95s)*1000:.1f}ms "
              f"p99={mean(p99s)*1000:.1f}+/-{stdev(p99s)*1000:.1f}ms, "
              f"unexpected_errors={unexpected_errors_total}", flush=True)
    return rows


# ---------------------------------------------------------------------------
# Targeted invariant trials
# ---------------------------------------------------------------------------

def _race(get_session, fn_a, args_a, fn_b, args_b) -> tuple[Exception | None, Exception | None]:
    barrier = threading.Barrier(2)
    errors: list[Exception | None] = [None, None]

    def worker(idx, fn, args):
        session = get_session()
        try:
            barrier.wait(timeout=5)
            fn = getattr(services, fn)
            fn(session, *args)
            session.commit()
        except Exception as exc:  # noqa: BLE001
            session.rollback()
            errors[idx] = exc
        finally:
            session.close()

    t1 = threading.Thread(target=worker, args=(0, fn_a, args_a))
    t2 = threading.Thread(target=worker, args=(1, fn_b, args_b))
    t1.start(); t2.start()
    t1.join(); t2.join()
    return errors[0], errors[1]


def invariant_same_site_triple_attest(get_session, n_trials: int) -> dict:
    violations = 0
    crashes = 0
    for i in range(n_trials):
        device_type, endpoint = "inv1", f"ep-{i}.example"
        seed_score(get_session, device_type, endpoint)

        def worker():
            session = get_session()
            try:
                services.attest_score(session, device_type, endpoint, "https", 443, "site-X")
                session.commit()
            except Exception:  # noqa: BLE001
                session.rollback()
                nonlocal crashes
                crashes += 1
            finally:
                session.close()

        threads = [threading.Thread(target=worker) for _ in range(3)]
        for t in threads: t.start()
        for t in threads: t.join()

        session = get_session()
        score = services.get_score(session, device_type, endpoint, "https", 443)
        if score.positive_attestations != 1 or score.tier == TIER_CONSORTIUM_ATTESTED:
            violations += 1
        session.close()
    return {"invariant": "same_site_triple_attest_no_double_count", "trials": n_trials,
            "violations": violations, "unhandled_exceptions": crashes}


def invariant_same_site_double_dispute(get_session, n_trials: int) -> dict:
    violations = 0
    for i in range(n_trials):
        device_type, endpoint = "inv2", f"ep-{i}.example"
        seed_score(get_session, device_type, endpoint)
        err_a, err_b = _race(get_session, "dispute_score", (device_type, endpoint, "https", 443, "site-Y"),
                              "dispute_score", (device_type, endpoint, "https", 443, "site-Y"))
        session = get_session()
        score = services.get_score(session, device_type, endpoint, "https", 443)
        if score.status == STATUS_REVOKED:
            violations += 1
        session.close()
    return {"invariant": "same_site_double_dispute_never_revokes", "trials": n_trials, "violations": violations}


def invariant_distinct_site_double_dispute(get_session, n_trials: int) -> dict:
    violations = 0
    inconsistent_history = 0
    for i in range(n_trials):
        device_type, endpoint = "inv3", f"ep-{i}.example"
        seed_score(get_session, device_type, endpoint)
        _race(get_session, "dispute_score", (device_type, endpoint, "https", 443, "site-A"),
              "dispute_score", (device_type, endpoint, "https", 443, "site-B"))
        session = get_session()
        score = services.get_score(session, device_type, endpoint, "https", 443)
        ok = score.status == STATUS_REVOKED
        if not ok:
            violations += 1
        history = services.get_score_history(session, score.id)
        revoke_events = [h for h in history if h.event == "revoke"]
        if len(revoke_events) != 1:
            inconsistent_history += 1
        session.close()
    return {"invariant": "distinct_site_double_dispute_revokes_exactly_once", "trials": n_trials,
            "violations": violations, "inconsistent_history_count": inconsistent_history}


def invariant_commit_vs_confirming_dispute(get_session, n_trials: int) -> dict:
    violations = 0
    for i in range(n_trials):
        device_type, endpoint = "inv4", f"ep-{i}.example"
        seed_score(get_session, device_type, endpoint)
        session = get_session()
        services.query_score(session, "local-site", device_type, endpoint, "https", 443)
        services.dispute_score(session, device_type, endpoint, "https", 443, "site-A")
        session.commit()
        session.close()
        err_commit, err_dispute = _race(
            get_session, "operator_commit", ("local-site", device_type, endpoint, "https", 443),
            "dispute_score", (device_type, endpoint, "https", 443, "site-B"),
        )
        session = get_session()
        score = services.get_score(session, device_type, endpoint, "https", 443)
        decision = services.get_local_decision(session, score.id, "local-site")
        if decision.state == DECISION_ACTIVE and score.status == STATUS_REVOKED:
            violations += 1
        session.close()
    return {"invariant": "operator_commit_vs_confirming_dispute_no_active_and_revoked", "trials": n_trials,
            "violations": violations}


def invariant_restore_isolation(get_session, n_trials: int) -> dict:
    violations = 0
    for i in range(n_trials):
        device_type = "inv5"
        endpoints = [f"ep-{i}-{j}.example" for j in range(4)]
        for ep in endpoints:
            seed_score(get_session, device_type, ep)
            session = get_session()
            services.dispute_score(session, device_type, ep, "https", 443, "site-A")
            services.dispute_score(session, device_type, ep, "https", 443, "site-B")
            session.commit()
            session.close()

        before = {}
        session = get_session()
        for ep in endpoints[2:]:
            s = services.get_score(session, device_type, ep, "https", 443)
            before[ep] = (s.status, s.version)
        session.close()

        threads = []
        for ep in endpoints[:2]:
            def worker(ep=ep):
                session = get_session()
                try:
                    services.restore_score(session, device_type, ep, "https", 443)
                    session.commit()
                finally:
                    session.close()
            threads.append(threading.Thread(target=worker))
        for t in threads: t.start()
        for t in threads: t.join()

        session = get_session()
        for ep in endpoints[2:]:
            s = services.get_score(session, device_type, ep, "https", 443)
            if (s.status, s.version) != before[ep]:
                violations += 1
        session.close()
    return {"invariant": "restore_score_does_not_alter_unrelated_facts", "trials": n_trials, "violations": violations}


def invariant_append_only_history(get_session, n_trials: int) -> dict:
    violations = 0
    for i in range(n_trials):
        device_type, endpoint = "inv6", f"ep-{i}.example"
        seed_score(get_session, device_type, endpoint)

        def worker(site_id):
            session = get_session()
            try:
                services.attest_score(session, device_type, endpoint, "https", 443, site_id)
                session.commit()
            except Exception:  # noqa: BLE001
                session.rollback()
            finally:
                session.close()

        threads = [threading.Thread(target=worker, args=(f"site-{j}",)) for j in range(4)]
        for t in threads: t.start()
        for t in threads: t.join()

        session = get_session()
        score = services.get_score(session, device_type, endpoint, "https", 443)
        history = services.get_score_history(session, score.id)
        versions = [h.version for h in history]
        if versions != sorted(set(versions)) or len(versions) != len(set(versions)):
            violations += 1
        if score.positive_attestations != 4:
            violations += 1
        session.close()
    return {"invariant": "append_only_history_no_lost_or_duplicate_events", "trials": n_trials, "violations": violations}


def invariant_local_revoke_survives_concurrent_dispute(get_session, n_trials: int) -> dict:
    """site-A's local_revoke() races site-B's dispute_score() on the same
    fact. Because both are atomic, single-effect-point transactions, a true
    race must linearize to exactly one of two valid total orders -- local
    revoke first (site-A's record ends Revoked; a still-eligible site-B may
    then be moved to Disputed) or dispute first (site-A's record is already
    Disputed by the time local_revoke re-reads it, so local_revoke correctly
    raises InvalidStateTransition instead of clobbering it). Both outcomes
    are counted as consistent; a violation is any *third* outcome -- site-A
    left Active/MonitorOnly (a lost update) or any unhandled, non-guard
    exception (a crash rather than a rejected transition). This also checks
    the from_states fix in services._transition_all_decisions: without it,
    dispute's fan-out would unconditionally overwrite an already-Revoked
    site-A record (formal/DIB.tla mutation m5's Python analogue).
    """
    violations = 0
    unexpected_errors = 0
    outcomes = {DECISION_REVOKED: 0, DECISION_DISPUTED: 0}
    for i in range(n_trials):
        device_type, endpoint = "inv7", f"ep-{i}.example"
        seed_score(get_session, device_type, endpoint)
        session = get_session()
        services.query_score(session, "site-A", device_type, endpoint, "https", 443)
        services.operator_commit(session, "site-A", device_type, endpoint, "https", 443)
        services.query_score(session, "site-B", device_type, endpoint, "https", 443)
        session.commit()
        session.close()

        err_a, err_b = _race(
            get_session, "local_revoke", ("site-A", device_type, endpoint, "https", 443),
            "dispute_score", (device_type, endpoint, "https", 443, "site-B"),
        )
        for err in (err_a, err_b):
            if err is not None and not isinstance(err, services.InvalidStateTransition):
                unexpected_errors += 1

        session = get_session()
        score = services.get_score(session, device_type, endpoint, "https", 443)
        decision_a = services.get_local_decision(session, score.id, "site-A")
        if decision_a.state == DECISION_REVOKED:
            outcomes[DECISION_REVOKED] += 1
        elif decision_a.state == DECISION_DISPUTED:
            outcomes[DECISION_DISPUTED] += 1
        else:
            violations += 1
        session.close()
    return {
        "invariant": "local_revoke_survives_concurrent_dispute",
        "trials": n_trials,
        "violations": violations,
        "unhandled_exceptions": unexpected_errors,
        "revoked_first": outcomes[DECISION_REVOKED],
        "disputed_first": outcomes[DECISION_DISPUTED],
    }


def invariant_local_revoke_restore_isolation(get_session, n_trials: int) -> dict:
    """local_revoke()/local_restore() at site-A must never change site-B's
    own record for the same fact -- the site-scoped counterpart of
    invariant_restore_isolation, which covers only the fan-out path."""
    violations = 0
    for i in range(n_trials):
        device_type, endpoint = "inv8", f"ep-{i}.example"
        seed_score(get_session, device_type, endpoint)
        session = get_session()
        services.query_score(session, "site-A", device_type, endpoint, "https", 443)
        services.operator_commit(session, "site-A", device_type, endpoint, "https", 443)
        decision_b = services.query_score(session, "site-B", device_type, endpoint, "https", 443)
        session.commit()
        before_b = (decision_b.state, decision_b.version)
        session.close()

        threads = [
            threading.Thread(
                target=lambda: timed_call(get_session, "local_revoke", "site-A", device_type, endpoint, "https", 443)
            ),
            threading.Thread(
                target=lambda: timed_call(get_session, "query_score", "site-B", device_type, endpoint, "https", 443)
            ),
        ]
        for t in threads: t.start()
        for t in threads: t.join()

        session = get_session()
        score = services.get_score(session, device_type, endpoint, "https", 443)
        decision_b_after = services.get_local_decision(session, score.id, "site-B")
        if (decision_b_after.state, decision_b_after.version) != before_b:
            violations += 1
        session.close()
    return {
        "invariant": "local_revoke_does_not_alter_other_sites_decision",
        "trials": n_trials,
        "violations": violations,
    }


def invariant_local_revoke_vs_open_dispute(get_session, n_trials: int) -> dict:
    """site-A's local_revoke() races site-C's *confirming* (second) dispute
    after site-B's first dispute has already opened the episode (site-A's
    decision is already Disputed) before the race begins. Unlike
    invariant_local_revoke_survives_concurrent_dispute (which races
    local_revoke against the *opening* dispute, from Active), here
    local_revoke's own precondition (state in {MonitorOnly, Active}) must
    reject it deterministically once a dispute is already open -- otherwise a
    receiving site could use local_revoke as a backdoor to unilaterally exit
    a live consortium dispute it does not control, the same hazard
    local_restore's docstring calls out and formal/DIB.tla mutation m4 checks
    (there for local_restore; this is its local_revoke analogue). A violation
    is local_revoke succeeding, the confirming dispute's revoke failing or
    being corrupted, or any unhandled exception under the race.
    """
    violations = 0
    unexpected_errors = 0
    revoke_incorrectly_succeeded = 0
    for i in range(n_trials):
        device_type, endpoint = "inv9", f"ep-{i}.example"
        seed_score(get_session, device_type, endpoint)
        session = get_session()
        services.query_score(session, "site-A", device_type, endpoint, "https", 443)
        services.operator_commit(session, "site-A", device_type, endpoint, "https", 443)
        services.dispute_score(session, device_type, endpoint, "https", 443, "site-B")
        session.commit()
        session.close()

        err_revoke, err_dispute = _race(
            get_session, "local_revoke", ("site-A", device_type, endpoint, "https", 443),
            "dispute_score", (device_type, endpoint, "https", 443, "site-C"),
        )
        if err_revoke is not None and not isinstance(err_revoke, services.InvalidStateTransition):
            unexpected_errors += 1
        if err_dispute is not None:
            unexpected_errors += 1
        if err_revoke is None:
            revoke_incorrectly_succeeded += 1

        session = get_session()
        score = services.get_score(session, device_type, endpoint, "https", 443)
        decision_a = services.get_local_decision(session, score.id, "site-A")
        ok = score.status == STATUS_REVOKED and decision_a.state == DECISION_REVOKED
        if not ok:
            violations += 1
        session.close()
    return {
        "invariant": "local_revoke_rejected_during_confirming_dispute",
        "trials": n_trials,
        "violations": violations,
        "unhandled_exceptions": unexpected_errors,
        "local_revoke_incorrectly_succeeded": revoke_incorrectly_succeeded,
    }


def invariant_retry_budget_exhaustion_clean_rejection(get_session, n_trials: int, n_writers: int = 25) -> dict:
    """Deliberately hammer ONE fact with many more concurrent writers than
    services._MAX_OPTIMISTIC_RETRIES=10 (default 25 threads, all racing
    attest_score() on the same (device_type, endpoint, site_id) triple, so
    every thread but the very first is guaranteed to hit at least one
    optimistic-lock conflict on Score.version and some may plausibly exhaust
    all 10 retries) to check the failure mode when the retry budget really
    is exceeded: any operation that fails must do so via a clean, well-typed
    exception raised by _retry_on_conflict's final `raise` (StaleDataError /
    IntegrityError -- the same two exception types the retry loop catches,
    re-raised unchanged on the last attempt, per services.py's own
    docstring), not silently swallowed and not a partial/corrupted write.
    After the race, the fact's Score row must be in exactly one valid FSM
    state (never a mix of committed and half-applied fields) and its
    positive_attestations must equal the number of threads whose commit
    actually succeeded (no lost updates, no phantom double-counts) -- i.e.
    even under contention well beyond the retry budget's design point, a
    caller either gets a clean rejection or a fully-applied write, never a
    third thing.

    n_trials defaults lower than the other invariants (see --invariant-
    trials handling in main()) because each trial now spawns n_writers
    threads instead of 2-4, making this invariant far more expensive per
    trial; 25 trials x 25 threads is already >600 real OS threads total,
    enough to reliably observe retry-budget pressure without the run
    becoming the bottleneck of the whole harness.
    """
    violations = 0
    non_clean_failures = 0
    clean_rejections = 0
    successes = 0
    for i in range(n_trials):
        device_type, endpoint = "inv10", f"ep-{i}.example"
        seed_score(get_session, device_type, endpoint)

        barrier = threading.Barrier(n_writers)
        results: list[tuple[bool, Exception | None]] = [(False, None)] * n_writers

        def worker(idx):
            session = get_session()
            ok = False
            err = None
            try:
                barrier.wait(timeout=10)
                services.attest_score(session, device_type, endpoint, "https", 443, f"site-{idx}")
                session.commit()
                ok = True
            except Exception as exc:  # noqa: BLE001 -- classify below, not hide
                session.rollback()
                err = exc
            finally:
                session.close()
            results[idx] = (ok, err)

        threads = [threading.Thread(target=worker, args=(j,)) for j in range(n_writers)]
        for t in threads: t.start()
        for t in threads: t.join()

        for ok, err in results:
            if ok:
                successes += 1
            else:
                # A "clean" failure is a well-typed exception the retry loop
                # itself understands and re-raises on exhaustion (StaleDataError
                # or IntegrityError), or the business-rule InvalidStateTransition.
                # Anything else (TypeError, AttributeError, a hung thread, ...)
                # would indicate the retry loop let corruption/a bug through.
                if isinstance(err, (StaleDataError, IntegrityError, services.InvalidStateTransition)):
                    clean_rejections += 1
                else:
                    non_clean_failures += 1

        session = get_session()
        score = services.get_score(session, device_type, endpoint, "https", 443)
        valid_states = {STATUS_ACTIVE, STATUS_DISPUTED, STATUS_REVOKED}
        state_ok = score.status in valid_states
        count_ok = score.positive_attestations == sum(1 for ok, _ in results if ok)
        if not (state_ok and count_ok):
            violations += 1
        session.close()
    return {
        "invariant": "retry_budget_exhaustion_clean_rejection",
        "trials": n_trials,
        "violations": violations,
        "unhandled_exceptions": non_clean_failures,
        "n_writers_per_trial": n_writers,
        "successful_writes": successes,
        "clean_rejections": clean_rejections,
    }


INVARIANTS = [
    invariant_same_site_triple_attest,
    invariant_same_site_double_dispute,
    invariant_distinct_site_double_dispute,
    invariant_commit_vs_confirming_dispute,
    invariant_restore_isolation,
    invariant_append_only_history,
    invariant_local_revoke_survives_concurrent_dispute,
    invariant_local_revoke_restore_isolation,
    invariant_local_revoke_vs_open_dispute,
    invariant_retry_budget_exhaustion_clean_rejection,
]


# Retry-budget exhaustion spawns n_writers real OS threads per trial (vs.
# 2-4 for every other invariant), so by default it runs at a reduced trial
# count even when --invariant-trials is left at 200 -- see the docstring on
# invariant_retry_budget_exhaustion_clean_rejection for the reasoning. This
# cap can be overridden directly via --retry-exhaustion-trials.
_RETRY_EXHAUSTION_DEFAULT_TRIALS = 25
_RETRY_EXHAUSTION_DEFAULT_WRITERS = 25


def run_invariants(
    get_session,
    n_trials: int,
    retry_exhaustion_trials: int | None = None,
    retry_exhaustion_writers: int = _RETRY_EXHAUSTION_DEFAULT_WRITERS,
) -> list[dict]:
    rows = []
    for fn in INVARIANTS:
        started = time.perf_counter()
        if fn is invariant_retry_budget_exhaustion_clean_rejection:
            trials = retry_exhaustion_trials if retry_exhaustion_trials is not None else min(
                n_trials, _RETRY_EXHAUSTION_DEFAULT_TRIALS
            )
            result = fn(get_session, trials, n_writers=retry_exhaustion_writers)
        else:
            result = fn(get_session, n_trials)
        result["elapsed_seconds"] = round(time.perf_counter() - started, 2)
        print(f"  {result['invariant']}: {result}", flush=True)
        rows.append(result)
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db-path", default="")
    parser.add_argument("--output-dir", default="outputs/fsm_concurrency")
    parser.add_argument("--worker-counts", default="1,10,50,100")
    parser.add_argument("--ops-per-worker", type=int, default=20)
    parser.add_argument("--warmup-ops", type=int, default=None,
                         help="Ops/worker for an untimed warm-up batch run before each worker-count's "
                              "timed measurement (discarded, not written to the CSV). Defaults to "
                              "--ops-per-worker. Pass 0 to disable warm-up entirely.")
    parser.add_argument("--repeats", type=int, default=3,
                         help="Number of timed repeats per worker count (post-warm-up); CSV reports "
                              "mean/std across repeats. --repeats 1 reproduces the old single-run behavior.")
    parser.add_argument("--invariant-trials", type=int, default=200)
    parser.add_argument("--retry-exhaustion-trials", type=int, default=None,
                         help="Trials for the retry-budget-exhaustion invariant specifically "
                              f"(default: min(--invariant-trials, {_RETRY_EXHAUSTION_DEFAULT_TRIALS}), "
                              "since each trial spawns many more threads than the other invariants).")
    parser.add_argument("--retry-exhaustion-writers", type=int, default=_RETRY_EXHAUSTION_DEFAULT_WRITERS,
                         help="Concurrent writer threads per trial for the retry-budget-exhaustion "
                              "invariant (must exceed services._MAX_OPTIMISTIC_RETRIES=10 to plausibly "
                              "exercise exhaustion).")
    parser.add_argument("--skip-throughput", action="store_true")
    parser.add_argument("--skip-invariants", action="store_true")
    parser.add_argument("--label", default="before_fix")
    args = parser.parse_args(argv)

    warmup_ops = args.warmup_ops if args.warmup_ops is not None else args.ops_per_worker

    output = ROOT / args.output_dir
    output.mkdir(parents=True, exist_ok=True)
    db_path = Path(args.db_path) if args.db_path else output / f"fsm_concurrency_{args.label}_{uuid.uuid4().hex[:8]}.db"
    if db_path.exists():
        db_path.unlink()
    fresh_engine(db_path)
    get_session = new_session_factory()

    from dib.core.io import write_csv

    hardware_info = capture_hardware_info()
    print(f"--- Hardware/platform ({args.label}) --- {hardware_info}", flush=True)

    if not args.skip_throughput:
        print(f"--- Throughput sweep ({args.label}, warmup_ops={warmup_ops}, repeats={args.repeats}) ---", flush=True)
        worker_counts = [int(x) for x in args.worker_counts.split(",")]
        throughput_rows = run_throughput_sweep(
            get_session, worker_counts, args.ops_per_worker,
            warmup_ops=warmup_ops, repeats=args.repeats,
        )
        write_csv(output / f"throughput_{args.label}.csv", throughput_rows,
                  ["n_workers", "total_ops", "repeats", "warmup_ops_per_worker",
                   "wall_seconds_mean",
                   "throughput_ops_per_sec_mean", "throughput_ops_per_sec_std",
                   "p50_latency_s_mean", "p50_latency_s_std",
                   "p95_latency_s_mean", "p95_latency_s_std",
                   "p99_latency_s_mean", "p99_latency_s_std",
                   "unexpected_errors"])

    if not args.skip_invariants:
        retry_trials = args.retry_exhaustion_trials if args.retry_exhaustion_trials is not None else min(
            args.invariant_trials, _RETRY_EXHAUSTION_DEFAULT_TRIALS
        )
        print(f"--- Invariant trials ({args.label}, {args.invariant_trials} trials each, "
              f"retry-exhaustion invariant: {retry_trials} trials x {args.retry_exhaustion_writers} writers) ---",
              flush=True)
        invariant_rows = run_invariants(
            get_session, args.invariant_trials,
            retry_exhaustion_trials=args.retry_exhaustion_trials,
            retry_exhaustion_writers=args.retry_exhaustion_writers,
        )
        write_csv(output / f"invariants_{args.label}.csv", invariant_rows,
                  ["invariant", "trials", "violations", "unhandled_exceptions",
                   "inconsistent_history_count", "revoked_first", "disputed_first",
                   "local_revoke_incorrectly_succeeded",
                   "n_writers_per_trial", "successful_writes", "clean_rejections",
                   "elapsed_seconds"])

    def sha256_of(path: Path) -> str | None:
        if not path.exists():
            return None
        return hashlib.sha256(path.read_bytes()).hexdigest()

    manifest = {
        "experiment": "fsm_concurrency_harness",
        "label": args.label,
        "command": sys.argv,
        "config": {
            "worker_counts": args.worker_counts,
            "ops_per_worker": args.ops_per_worker,
            "warmup_ops_per_worker": warmup_ops,
            "repeats": args.repeats,
            "invariant_trials": args.invariant_trials,
            "retry_exhaustion_trials": (
                args.retry_exhaustion_trials if args.retry_exhaustion_trials is not None
                else min(args.invariant_trials, _RETRY_EXHAUSTION_DEFAULT_TRIALS)
            ),
            "retry_exhaustion_writers": args.retry_exhaustion_writers,
            "optimistic_retry_limit": 10,
            "database": "fresh SQLite database per run",
            "skip_throughput": args.skip_throughput,
            "skip_invariants": args.skip_invariants,
        },
        "hardware": hardware_info,
        "checksums": {
            "harness_sha256": sha256_of(Path(__file__)),
            "services_sha256": sha256_of(ROOT / "src" / "dib" / "registry" / "services.py"),
            "throughput_csv_sha256": sha256_of(output / f"throughput_{args.label}.csv"),
            "invariants_csv_sha256": sha256_of(output / f"invariants_{args.label}.csv"),
        },
    }
    (output / f"manifest_{args.label}.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    db_path.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
