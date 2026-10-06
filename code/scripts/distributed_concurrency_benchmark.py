"""Throughput/latency benchmark against the real, running Docker Compose
cluster (10 site containers + 1 evidence container, service.py). Unlike
sharded_concurrency_benchmark.py (GIL-bound threads) and its multiprocess
variant (pathological same-host multi-process SQLite/ATTACH contention),
this hits genuinely separate OS processes over HTTP/TCP -- the same
mechanism a real multi-organization deployment would use. Thread-based
concurrency is legitimate here because each request blocks on real network
I/O (socket send/recv releases the GIL), not on Python bytecode.

Worker routing: worker_id % N_SITES assigns each worker to one of the site
containers. The operation mix is _MIX_REALISTIC (40% query, 35% commit, 10%
contribute, 5% each attest/dispute/restore), which is NOT the uniform six-op mix
used by fsm_concurrency_harness.py; the two harnesses are not comparable.
`contribute` is a no-op here (the distributed prototype exposes no observation
endpoint) and is still counted in the throughput denominator.

The site count is read from --n-sites or DIB_DIST_N_SITES (default 10) and must
match the running Compose topology, which generate_compose.py builds from the
same variable.
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import httpx

N_SITES = int(os.environ.get("DIB_DIST_N_SITES", "10"))
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


def do_op(worker_id: int, op_index: int, mix: list[str]) -> tuple[str, float, bool, str]:
    site_index = worker_id % N_SITES
    device_type = ("cam-a", "cam-b", "cam-c")[worker_id % 3]
    endpoint = f"ep-{op_index % 5}.example"
    op = mix[op_index % len(mix)]
    started = time.perf_counter()
    unexpected = False
    error_kind = ""
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
    except Exception as exc:  # noqa: BLE001 -- classified, not hidden: see error_types in the CSV
        unexpected = True
        error_kind = f"{type(exc).__module__.split('.')[0]}.{type(exc).__name__}"
    elapsed = time.perf_counter() - started
    return op, elapsed, unexpected, error_kind


def run_one_batch(n_workers: int, n_ops: int, mix: list[str]):
    latencies: dict[str, list[float]] = {}
    unexpected_errors = 0
    error_kinds: Counter[str] = Counter()
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        futures = [pool.submit(do_op, w, o, mix) for w in range(n_workers) for o in range(n_ops)]
        for fut in as_completed(futures):
            op, elapsed, is_unexpected, error_kind = fut.result()
            latencies.setdefault(op, []).append(elapsed)
            if is_unexpected:
                unexpected_errors += 1
                error_kinds[f"{op}:{error_kind}"] += 1
    wall = time.perf_counter() - started
    return latencies, unexpected_errors, wall, error_kinds


def pct(all_lat, p):
    if not all_lat:
        return 0.0
    idx = min(len(all_lat) - 1, int(round(p * (len(all_lat) - 1))))
    return all_lat[idx]


def main() -> int:
    global N_SITES
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker-counts", default="1,10,50,100")
    parser.add_argument("--ops-per-worker", type=int, default=20)
    parser.add_argument("--warmup-ops", type=int, default=20)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--output", default="outputs/distributed_concurrency/throughput_distributed.csv")
    parser.add_argument("--n-sites", type=int, default=N_SITES,
                        help="site containers in the running topology (default: DIB_DIST_N_SITES or 10)")
    args = parser.parse_args()

    N_SITES = args.n_sites
    print(f"topology: {N_SITES} site container(s) + 1 evidence container", flush=True)
    seed_all()
    mix = _MIX_REALISTIC

    rows = []
    for n_workers in [int(x) for x in args.worker_counts.split(",")]:
        if args.warmup_ops > 0:
            print(f"  n_workers={n_workers}: warm-up...", flush=True)
            run_one_batch(n_workers, args.warmup_ops, mix)  # discarded, including its errors

        total_ops = n_workers * args.ops_per_worker
        throughputs, p50s, p95s, p99s = [], [], [], []
        unexpected_total = 0
        error_kinds_total: Counter[str] = Counter()
        wall_total = 0.0
        for rep in range(args.repeats):
            latencies, unexpected, wall, error_kinds = run_one_batch(n_workers, args.ops_per_worker, mix)
            error_kinds_total.update(error_kinds)
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
            "error_types": ";".join(f"{k}x{v}" for k, v in sorted(error_kinds_total.items())),
        })
        print(f"  n_workers={n_workers} SUMMARY: throughput={mean(throughputs):.1f}+/-{stdev(throughputs):.1f} ops/s, "
              f"p50={mean(p50s)*1000:.1f}ms p99={mean(p99s)*1000:.1f}+/-{stdev(p99s)*1000:.1f}ms, "
              f"unexpected_errors={unexpected_total} {dict(error_kinds_total) or ''}", flush=True)

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
