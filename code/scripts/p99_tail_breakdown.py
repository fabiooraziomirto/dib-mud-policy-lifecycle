"""Attribute the single-node registry's p99 tail to its two candidate causes.

fsm_concurrency_harness.py reports that p99 latency grows from ~5 ms at one
writer to ~5.9 s at 100 while the median stays under 4 ms. Two mechanisms in
the corrected registry can produce that tail: the optimistic-lock retry loop in
services._retry_on_conflict (up to _MAX_OPTIMISTIC_RETRIES re-executions of the
same read-validate-write closure) and serialization on the single SQLite file
plus the GIL, which makes an operation wait rather than work.

This script re-runs the *same* sweep (it monkeypatches harness.timed_call and
therefore drives the harness's own do_op / run_one_batch code path, not a copy)
while recording, per timed operation: total latency, time spent inside
Session.commit(), and how many attempts _retry_on_conflict consumed. If the
tail were retries, high-percentile operations would show attempt counts above
1; if it is queueing, attempts stay at 1 and the tail appears as time that is
neither commit work nor useful work.

Usage:
    python code/scripts/p99_tail_breakdown.py --output-dir ../experiments/40_p99_tail_breakdown
"""
from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import threading
import time
import uuid
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import fsm_concurrency_harness as harness  # noqa: E402
from dib.registry import services  # noqa: E402
from sqlalchemy.orm import Session as SASession  # noqa: E402

_tl = threading.local()
_records: list[dict] = []
_records_lock = threading.Lock()
_orig_retry = services._retry_on_conflict
_orig_commit = SASession.commit
_orig_timed_call = harness.timed_call


def _counting_retry(session, attempt):
    """Wrap the production retry loop, counting how many times the closure ran."""
    def counted():
        _tl.attempts = getattr(_tl, "attempts", 0) + 1
        return attempt()
    return _orig_retry(session, counted)


def _timed_commit(self, *a, **k):
    started = time.perf_counter()
    try:
        return _orig_commit(self, *a, **k)
    finally:
        _tl.commit_s = getattr(_tl, "commit_s", 0.0) + (time.perf_counter() - started)


def _instrumented_timed_call(get_session, fn_name, *args, **kwargs):
    _tl.attempts = 0
    _tl.commit_s = 0.0
    started = time.perf_counter()
    elapsed, result, err = _orig_timed_call(get_session, fn_name, *args, **kwargs)
    wall = time.perf_counter() - started
    with _records_lock:
        _records.append({
            "op": fn_name,
            "total_s": elapsed,
            "wall_s": wall,
            "commit_s": getattr(_tl, "commit_s", 0.0),
            "attempts": max(1, getattr(_tl, "attempts", 0)),
            "error": type(err).__name__ if err is not None else "",
        })
    return elapsed, result, err


def pct(xs: list[float], p: float) -> float:
    if not xs:
        return 0.0
    s = sorted(xs)
    return s[min(len(s) - 1, int(round(p * (len(s) - 1))))]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default="../experiments/40_p99_tail_breakdown")
    parser.add_argument("--worker-counts", default="1,10,50,100")
    parser.add_argument("--ops-per-worker", type=int, default=20)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--label", default="v34_tail")
    args = parser.parse_args(argv)

    output = (ROOT / args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    db_path = output / f"tail_{args.label}_{uuid.uuid4().hex[:8]}.db"
    if db_path.exists():
        db_path.unlink()
    harness.fresh_engine(db_path)
    get_session = harness.new_session_factory()

    services._retry_on_conflict = _counting_retry
    SASession.commit = _timed_commit
    harness.timed_call = _instrumented_timed_call

    from dib.core.io import write_csv

    worker_counts = [int(x) for x in args.worker_counts.split(",")]
    rows = []
    per_worker_attempts = {}
    for n in worker_counts:
        _records.clear()
        harness.run_throughput_sweep(
            get_session, [n], args.ops_per_worker,
            warmup_ops=args.ops_per_worker, repeats=args.repeats,
        )
        # run_throughput_sweep discards the warm-up from its CSV but not from our
        # records; keep only the last repeats*n*ops entries (the timed batches).
        timed = _records[-(args.repeats * n * args.ops_per_worker):]
        totals = [r["total_s"] for r in timed]
        commits = [r["commit_s"] for r in timed]
        attempts = Counter(r["attempts"] for r in timed)
        errors = Counter(r["error"] for r in timed if r["error"])
        p99 = pct(totals, 0.99)
        tail = [r for r in timed if r["total_s"] >= p99]
        rows.append({
            "n_workers": n,
            "timed_ops": len(timed),
            "p50_total_ms": round(pct(totals, 0.50) * 1000, 3),
            "p99_total_ms": round(p99 * 1000, 3),
            "p50_commit_ms": round(pct(commits, 0.50) * 1000, 3),
            "p99_commit_ms": round(pct(commits, 0.99) * 1000, 3),
            "mean_commit_ms": round(statistics.mean(commits) * 1000, 3),
            "commit_share_of_p99_pct": round(100 * statistics.mean([r["commit_s"] for r in tail]) / p99, 2) if p99 else 0.0,
            "mean_attempts": round(statistics.mean([r["attempts"] for r in timed]), 4),
            "max_attempts": max(r["attempts"] for r in timed),
            "ops_with_retry": sum(v for k, v in attempts.items() if k > 1),
            "mean_attempts_in_p99_tail": round(statistics.mean([r["attempts"] for r in tail]), 4),
            "max_attempts_in_p99_tail": max(r["attempts"] for r in tail),
            "error_types": ";".join(f"{k}x{v}" for k, v in errors.items()),
        })
        per_worker_attempts[n] = {str(k): v for k, v in sorted(attempts.items())}
        print(f"[breakdown] n={n}: {rows[-1]}", flush=True)

    write_csv(output / f"tail_breakdown_{args.label}.csv", rows, list(rows[0].keys()))
    (output / f"manifest_{args.label}.json").write_text(json.dumps({
        "label": args.label,
        "worker_counts": worker_counts,
        "ops_per_worker": args.ops_per_worker,
        "repeats": args.repeats,
        "max_optimistic_retries": services._MAX_OPTIMISTIC_RETRIES,
        "attempt_histogram_per_worker_count": per_worker_attempts,
        "hardware": harness.capture_hardware_info(),
        "python": platform.python_version(),
        "database_url": f"sqlite:///{db_path}",
    }, indent=2), encoding="utf-8")
    print(f"[breakdown] wrote {output}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
