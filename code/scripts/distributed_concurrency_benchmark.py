"""Throughput/latency benchmark against the real, running Docker Compose
cluster (10 site containers + 1 evidence container, service.py). Unlike
sharded_concurrency_benchmark.py (GIL-bound threads) and its multiprocess
variant (pathological same-host multi-process SQLite/ATTACH contention),
this hits genuinely separate OS processes over HTTP/TCP -- the same
mechanism a real multi-organization deployment would use. Thread-based
concurrency is legitimate here because each request blocks on real network
I/O (socket send/recv releases the GIL), not on Python bytecode.

Same 6-op mix and worker-routing convention as the other benchmarks:
worker_id % N_SITES assigns each worker to one of the 10 site containers.
"""
from __future__ import annotations

import argparse
import json
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import httpx

N_SITES = 10
EVIDENCE_URL = "http://localhost:18100"


def site_url(i: int) -> str:
    return f"http://localhost:{18110 + i}"


_MIX_REALISTIC = ["query", "commit", "contribute", "query", "commit", "query", "commit",
                  "contribute", "query", "attest", "commit", "query", "commit", "query",
                  "dispute", "commit", "query", "restore", "query", "commit"]

_client = httpx.Client(timeout=5.0)


def seed_all(device_types=("cam-a", "cam-b", "cam-c"), n_endpoints=5) -> None:
    for dt in device_types:
        for i in range(n_endpoints):
            ep = f"ep-{i}.example"
            try:
                _client.post(f"{EVIDENCE_URL}/seed", json={"device_type": dt, "endpoint": ep})
            except Exception:
                pass
            for s in range(N_SITES):
                try:
                    _client.post(f"{site_url(s)}/query", json={"device_type": dt, "endpoint": ep})
                except Exception:
                    pass


def do_op(worker_id: int, op_index: int, mix: list[str]) -> tuple[str, float, bool]:
    site_index = worker_id % N_SITES
    device_type = ("cam-a", "cam-b", "cam-c")[worker_id % 3]
    endpoint = f"ep-{op_index % 5}.example"
    op = mix[op_index % len(mix)]
    started = time.perf_counter()
    unexpected = False
    try:
        body = {"device_type": device_type, "endpoint": endpoint}
        if op == "contribute":
            pass  # no observation endpoint in this prototype -- site-local write already covered by query/commit
        elif op == "query":
            _client.post(f"{site_url(site_index)}/query", json=body)
        elif op == "attest":
            _client.post(f"{EVIDENCE_URL}/attest", json={**body, "site_id": f"site-{site_index}"})
        elif op == "dispute":
            _client.post(f"{EVIDENCE_URL}/dispute", json={**body, "site_id": f"site-{site_index}"})
        elif op == "commit":
            _client.post(f"{site_url(site_index)}/commit", json=body)
        else:
            _client.post(f"{EVIDENCE_URL}/restore", json=body)
    except Exception:
        unexpected = True
    elapsed = time.perf_counter() - started
    return op, elapsed, unexpected


def run_one_batch(n_workers: int, n_ops: int, mix: list[str]):
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


def pct(all_lat, p):
    if not all_lat:
        return 0.0
    idx = min(len(all_lat) - 1, int(round(p * (len(all_lat) - 1))))
    return all_lat[idx]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker-counts", default="1,10,50,100")
    parser.add_argument("--ops-per-worker", type=int, default=20)
    parser.add_argument("--warmup-ops", type=int, default=20)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--output", default="outputs/distributed_concurrency/throughput_distributed.csv")
    args = parser.parse_args()

    seed_all()
    mix = _MIX_REALISTIC

    rows = []
    for n_workers in [int(x) for x in args.worker_counts.split(",")]:
        if args.warmup_ops > 0:
            print(f"  n_workers={n_workers}: warm-up...", flush=True)
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
            print(f"  n_workers={n_workers} rep={rep+1}/{args.repeats}: {total_ops} ops in {wall:.2f}s "
                  f"({total_ops/wall:.1f} ops/s), p50={pct(all_lat,0.5)*1000:.1f}ms "
                  f"p95={pct(all_lat,0.95)*1000:.1f}ms p99={pct(all_lat,0.99)*1000:.1f}ms, "
                  f"unexpected_errors={unexpected}", flush=True)

        def mean(xs): return statistics.mean(xs) if xs else 0.0
        def stdev(xs): return statistics.stdev(xs) if len(xs) > 1 else 0.0
        rows.append({
            "n_workers": n_workers, "total_ops": total_ops,
            "throughput_ops_per_sec_mean": round(mean(throughputs), 2),
            "p50_latency_s_mean": round(mean(p50s), 6),
            "p95_latency_s_mean": round(mean(p95s), 6),
            "p99_latency_s_mean": round(mean(p99s), 6),
            "p99_latency_s_std": round(stdev(p99s), 6),
            "unexpected_errors": unexpected_total,
        })
        print(f"  n_workers={n_workers} SUMMARY: throughput={mean(throughputs):.1f}+/-{stdev(throughputs):.1f} ops/s, "
              f"p50={mean(p50s)*1000:.1f}ms p99={mean(p99s)*1000:.1f}+/-{stdev(p99s)*1000:.1f}ms, "
              f"unexpected_errors={unexpected_total}", flush=True)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    import csv
    with out_path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
