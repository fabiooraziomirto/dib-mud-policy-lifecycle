"""Throughput/latency benchmark for the per-site sharding prototype
(sharded_prototype.py), directly comparable to fsm_concurrency_harness.py's
throughput sweep (same worker counts, same 6-op mix, same 15-fact working
set, same warm-up/repeat protocol). The only architectural difference: site-
scoped ops (contribute/query/commit) hit one of N_SITES=10 independent
SQLite files instead of one shared file; the rare cross-site ops
(attest/dispute/restore) still serialize through the central evidence file
with an atomic ATTACH-based fan-out (see sharded_prototype.py).

100 workers map to 10 real sites via worker_id % N_SITES -- i.e., each site
handles ~10 concurrent operations, modeling multiple concurrent
sessions/automation jobs at the same organization, not 100 independently
governed organizations writing at the same instant.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dib.registry import sharded_prototype as sp


# Uniform: fsm_concurrency_harness.py's original 1/6-each mix (stresses the
# central path as heavily as the site-local path -- not representative of a
# deployment where disputes/restores are rare governance events).
_MIX_UNIFORM = ["contribute", "query", "attest", "dispute", "commit", "restore"]
# Realistic: 17/20 site-local (contribute/query/commit), 3/20 central
# (attest/dispute/restore), reflecting that day-to-day operation is
# checking/committing profiles, not disputing them.
_MIX_REALISTIC = ["query", "commit", "contribute", "query", "commit", "query", "commit",
                  "contribute", "query", "attest", "commit", "query", "commit", "query",
                  "dispute", "commit", "query", "restore", "query", "commit"]


def do_op(worker_id: int, op_index: int, mix: list[str]) -> tuple[str, float, bool]:
    site_index = worker_id % sp.N_SITES
    device_type = ("cam-a", "cam-b", "cam-c")[worker_id % 3]
    endpoint = f"ep-{op_index % 5}.example"
    op = mix[op_index % len(mix)]
    started = time.perf_counter()
    unexpected = False
    try:
        if op == "contribute":
            sp.record_observation(site_index, device_type, endpoint)
        elif op == "query":
            sp.query_score(site_index, device_type, endpoint)
        elif op == "attest":
            sp.attest_score(device_type, endpoint, site_index)
        elif op == "dispute":
            sp.dispute_score(device_type, endpoint, site_index)
        elif op == "commit":
            sp.operator_commit(site_index, device_type, endpoint)
        else:
            sp.restore_score(device_type, endpoint)
    except sp.InvalidStateTransition:
        pass
    except Exception:
        unexpected = True
    elapsed = time.perf_counter() - started
    return op, elapsed, unexpected


def run_one_batch(n_workers: int, n_ops: int, mix: list[str]) -> tuple[dict[str, list[float]], int, float]:
    latencies: dict[str, list[float]] = {}
    unexpected_errors = 0
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        futures = [pool.submit(do_op, w, o, mix) for w in range(n_workers) for o in range(n_ops)]
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default="outputs/sharded_concurrency")
    parser.add_argument("--worker-counts", default="1,10,50,100")
    parser.add_argument("--ops-per-worker", type=int, default=20)
    parser.add_argument("--warmup-ops", type=int, default=20)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--n-sites", type=int, default=10,
                         help="Override sp.N_SITES -- use 1 to run the identical code path as a "
                              "single-file control, isolating the sharding effect from the "
                              "raw-sqlite3-vs-SQLAlchemy-ORM difference from fsm_concurrency_harness.py.")
    parser.add_argument("--mix", choices=["uniform", "realistic"], default="uniform")
    args = parser.parse_args(argv)

    mix = _MIX_UNIFORM if args.mix == "uniform" else _MIX_REALISTIC
    sp.N_SITES = args.n_sites
    output = ROOT / args.output_dir
    sp.init(output / "db")

    for device_type in ("cam-a", "cam-b", "cam-c"):
        for i in range(5):
            sp.seed_score(device_type, f"ep-{i}.example")

    rows = []
    worker_counts = [int(x) for x in args.worker_counts.split(",")]
    for n_workers in worker_counts:
        if args.warmup_ops > 0:
            print(f"  n_workers={n_workers}: warm-up ({args.warmup_ops} ops/worker, discarded)...", flush=True)
            run_one_batch(n_workers, args.warmup_ops, mix)

        total_ops = n_workers * args.ops_per_worker
        throughputs, p50s, p95s, p99s = [], [], [], []
        unexpected_total = 0
        wall_total = 0.0
        for rep in range(args.repeats):
            latencies, unexpected, wall = run_one_batch(n_workers, args.ops_per_worker, mix)
            all_lat = sorted(v for vals in latencies.values() for v in vals)
            throughputs.append(total_ops / wall if wall else 0.0)
            p50s.append(pct(all_lat, 0.50))
            p95s.append(pct(all_lat, 0.95))
            p99s.append(pct(all_lat, 0.99))
            unexpected_total += unexpected
            wall_total += wall
            print(f"  n_workers={n_workers} rep={rep + 1}/{args.repeats}: {total_ops} ops in {wall:.2f}s "
                  f"({total_ops/wall:.1f} ops/s), p50={pct(all_lat,0.50)*1000:.1f}ms "
                  f"p95={pct(all_lat,0.95)*1000:.1f}ms p99={pct(all_lat,0.99)*1000:.1f}ms, "
                  f"unexpected_errors={unexpected}", flush=True)

        def mean(xs): return statistics.mean(xs) if xs else 0.0
        def stdev(xs): return statistics.stdev(xs) if len(xs) > 1 else 0.0

        rows.append({
            "n_workers": n_workers, "total_ops": total_ops, "repeats": args.repeats,
            "wall_seconds_mean": round(wall_total / args.repeats, 4),
            "throughput_ops_per_sec_mean": round(mean(throughputs), 2),
            "throughput_ops_per_sec_std": round(stdev(throughputs), 2),
            "p50_latency_s_mean": round(mean(p50s), 6),
            "p95_latency_s_mean": round(mean(p95s), 6),
            "p99_latency_s_mean": round(mean(p99s), 6),
            "p99_latency_s_std": round(stdev(p99s), 6),
            "unexpected_errors": unexpected_total,
        })
        print(f"  n_workers={n_workers} SUMMARY over {args.repeats} rep(s): "
              f"throughput={mean(throughputs):.1f}+/-{stdev(throughputs):.1f} ops/s, "
              f"p50={mean(p50s)*1000:.1f}ms p95={mean(p95s)*1000:.1f}ms "
              f"p99={mean(p99s)*1000:.1f}+/-{stdev(p99s)*1000:.1f}ms, "
              f"unexpected_errors={unexpected_total}", flush=True)

    from dib.core.io import write_csv
    write_csv(output / "throughput_sharded.csv", rows,
              ["n_workers", "total_ops", "repeats", "wall_seconds_mean",
               "throughput_ops_per_sec_mean", "throughput_ops_per_sec_std",
               "p50_latency_s_mean", "p95_latency_s_mean",
               "p99_latency_s_mean", "p99_latency_s_std", "unexpected_errors"])
    (output / "manifest.json").write_text(json.dumps({
        "experiment": "sharded_concurrency_benchmark",
        "n_sites": sp.N_SITES,
        "config": vars(args),
    }, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
