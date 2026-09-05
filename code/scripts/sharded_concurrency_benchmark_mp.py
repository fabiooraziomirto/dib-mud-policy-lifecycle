"""Same benchmark as sharded_concurrency_benchmark.py, but using real OS
processes (ProcessPoolExecutor) instead of Python threads, to escape the
GIL. The threaded version showed N_SITES=1 and N_SITES=10 performing
identically -- suspected cause: Python's GIL serializes bytecode execution
regardless of how many independent SQLite files/locks exist, since each
operation is fast enough to rarely release the GIL for long. This variant
tests whether the sharding benefit appears once workers are genuinely
concurrent (separate processes, separate GILs) -- which is also a more
faithful model of a real deployment, where different sites run different
server processes, not threads inside one interpreter.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dib.registry import sharded_prototype as sp

_MIX_UNIFORM = ["contribute", "query", "attest", "dispute", "commit", "restore"]
_MIX_REALISTIC = ["query", "commit", "contribute", "query", "commit", "query", "commit",
                  "contribute", "query", "attest", "commit", "query", "commit", "query",
                  "dispute", "commit", "query", "restore", "query", "commit"]

_OUTPUT_DIR: Path | None = None
_N_SITES: int = 10


def _worker_init(output_dir: str, n_sites: int) -> None:
    """Runs once per worker process (ProcessPoolExecutor initializer):
    attach this process's own connections to the already-created DB files."""
    sp.N_SITES = n_sites
    sp.attach(Path(output_dir))


def _do_op(worker_id: int, op_index: int, mix: list[str]) -> tuple[str, float, bool]:
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


def run_one_batch(pool: ProcessPoolExecutor, n_workers: int, n_ops: int, mix: list[str]):
    latencies: dict[str, list[float]] = {}
    unexpected_errors = 0
    started = time.perf_counter()
    futures = [pool.submit(_do_op, w, o, mix) for w in range(n_workers) for o in range(n_ops)]
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
    parser.add_argument("--output-dir", default="outputs/sharded_concurrency_mp")
    parser.add_argument("--worker-counts", default="1,10,50,100")
    parser.add_argument("--ops-per-worker", type=int, default=20)
    parser.add_argument("--warmup-ops", type=int, default=20)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--n-sites", type=int, default=10)
    parser.add_argument("--n-processes", type=int, default=16)
    parser.add_argument("--mix", choices=["uniform", "realistic"], default="realistic")
    args = parser.parse_args(argv)

    mix = _MIX_UNIFORM if args.mix == "uniform" else _MIX_REALISTIC
    output = ROOT / args.output_dir
    sp.N_SITES = args.n_sites
    sp.init(output / "db")
    for device_type in ("cam-a", "cam-b", "cam-c"):
        for i in range(5):
            sp.seed_score(device_type, f"ep-{i}.example")
    # Close the main process's own connections before spawning workers that
    # attach fresh ones -- avoids holding a stale writer handle in the parent.
    sp._central_conn.close()
    for con in sp._site_conns.values():
        con.close()

    rows = []
    worker_counts = [int(x) for x in args.worker_counts.split(",")]
    with ProcessPoolExecutor(
        max_workers=args.n_processes, initializer=_worker_init, initargs=(str(output / "db"), args.n_sites)
    ) as pool:
        for n_workers in worker_counts:
            if args.warmup_ops > 0:
                print(f"  n_workers={n_workers}: warm-up ({args.warmup_ops} ops/worker, discarded)...", flush=True)
                run_one_batch(pool, n_workers, args.warmup_ops, mix)

            total_ops = n_workers * args.ops_per_worker
            throughputs, p50s, p95s, p99s = [], [], [], []
            unexpected_total = 0
            wall_total = 0.0
            for rep in range(args.repeats):
                latencies, unexpected, wall = run_one_batch(pool, n_workers, args.ops_per_worker, mix)
                all_lat = sorted(v for vals in latencies.values() for v in vals)
                for op_name, vals in latencies.items():
                    v = sorted(vals)
                    print(f"    [{op_name}] n={len(v)} p50={pct(v,0.5)*1000:.1f}ms p99={pct(v,0.99)*1000:.1f}ms",
                          flush=True)
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
                "n_workers": n_workers, "total_ops": total_ops,
                "throughput_ops_per_sec_mean": round(mean(throughputs), 2),
                "p50_latency_s_mean": round(mean(p50s), 6),
                "p99_latency_s_mean": round(mean(p99s), 6),
                "p99_latency_s_std": round(stdev(p99s), 6),
                "unexpected_errors": unexpected_total,
            })
            print(f"  n_workers={n_workers} SUMMARY over {args.repeats} rep(s): "
                  f"throughput={mean(throughputs):.1f}+/-{stdev(throughputs):.1f} ops/s, "
                  f"p50={mean(p50s)*1000:.1f}ms p99={mean(p99s)*1000:.1f}+/-{stdev(p99s)*1000:.1f}ms, "
                  f"unexpected_errors={unexpected_total}", flush=True)

    from dib.core.io import write_csv
    write_csv(output / "throughput_sharded_mp.csv", rows,
              ["n_workers", "total_ops", "throughput_ops_per_sec_mean",
               "p50_latency_s_mean", "p99_latency_s_mean", "p99_latency_s_std", "unexpected_errors"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
