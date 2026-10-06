"""Cost and blast radius of a dispute flood by one authenticated member.

The lifecycle deliberately lets any consortium member suspend export of a fact
at every site with a single dispute (Sec. III). That makes a dispute flood the
cheapest attack on DIB, and the paper previously asserted its cost without
measuring it. This script measures four things against the running 10-site
Compose deployment:

1. attacker cost -- disputes issued per second by ONE identity on ONE thread,
   and requests per fact suspended;
2. blast radius -- exported ACEs removed per site, i.e. how much enforcement
   one identity withdraws;
3. collateral -- latency and throughput of a concurrent legitimate read
   workload, during the flood against a matched quiet baseline;
4. recovery cost -- requests and wall time to put the fleet back, which is the
   asymmetry that makes restriction the preferred bias: withdrawal is one
   request per fact, restoration is one privileged restore plus one fresh local
   commit at every site that wants the permission back.

Usage (10 site containers + evidence must already be up):
    python code/scripts/dispute_flood.py --facts 100 --output-dir ../experiments/42_dispute_flood
"""
from __future__ import annotations

import argparse
import json
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_URL = "http://localhost:18100"
DEVICE_TYPE = "flood-cam"


def site_url(i: int) -> str:
    return f"http://localhost:{18110 + i}"


def pct(xs, p):
    if not xs:
        return 0.0
    s = sorted(xs)
    return s[min(len(s) - 1, int(round(p * (len(s) - 1))))]


def exported_aces(client, site: int) -> int:
    """Count from-device ACEs the site currently exports for the flooded device type."""
    r = client.get(f"{site_url(site)}/export_mud", params={"device_type": DEVICE_TYPE})
    acls = r.json().get("ietf-access-control-list:access-lists", {}).get("acl", [])
    return sum(
        len(acl.get("aces", {}).get("ace", []))
        for acl in acls
        if acl.get("name", "").endswith("-fr")
    )


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--facts", type=int, default=100)
    ap.add_argument("--sites", type=int, default=10)
    ap.add_argument("--legit-workers", type=int, default=10)
    ap.add_argument("--legit-ops", type=int, default=40, help="read ops per legitimate worker per phase")
    ap.add_argument("--output-dir", default="../experiments/42_dispute_flood")
    args = ap.parse_args(argv)

    out = (ROOT / args.output_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    client = httpx.Client(timeout=10.0)
    endpoints = [f"flood-{i}.example" for i in range(args.facts)]

    # ---- setup: seed facts, then Active at every site -------------------
    ids = {}
    for ep in endpoints:
        r = client.post(f"{EVIDENCE_URL}/seed", json={"device_type": DEVICE_TYPE, "endpoint": ep})
        ids[ep] = r.json()["id"]
    setup_requests = len(endpoints)
    for s in range(args.sites):
        for ep in endpoints:
            client.post(f"{site_url(s)}/query", json={"device_type": DEVICE_TYPE, "endpoint": ep})
            client.post(f"{site_url(s)}/commit", json={"device_type": DEVICE_TYPE, "endpoint": ep})
            setup_requests += 2
    aces_before = [exported_aces(client, s) for s in range(args.sites)]
    print(f"[setup] {args.facts} facts Active at {args.sites} sites; exported ACEs/site={aces_before}", flush=True)

    # ---- legitimate read workload, used in both phases -------------------
    def legit_batch(label: str) -> dict:
        lat: list[float] = []

        def worker(w: int):
            local = []
            with httpx.Client(timeout=10.0) as c:
                for o in range(args.legit_ops):
                    ep = endpoints[(w * 7 + o) % len(endpoints)]
                    t0 = time.perf_counter()
                    try:
                        c.post(f"{site_url(w % args.sites)}/query",
                               json={"device_type": DEVICE_TYPE, "endpoint": ep})
                    except Exception:
                        pass
                    local.append(time.perf_counter() - t0)
            return local

        started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=args.legit_workers) as pool:
            for r in pool.map(worker, range(args.legit_workers)):
                lat.extend(r)
        wall = time.perf_counter() - started
        row = {
            "phase": label,
            "ops": len(lat),
            "wall_s": round(wall, 4),
            "throughput_ops_per_s": round(len(lat) / wall, 2),
            "p50_ms": round(pct(lat, 0.50) * 1000, 2),
            "p99_ms": round(pct(lat, 0.99) * 1000, 2),
        }
        print(f"[legit:{label}] {row}", flush=True)
        return row

    baseline = legit_batch("quiet_baseline")

    # ---- flood: ONE identity, ONE thread, concurrent with legit load ----
    flood_lat: list[float] = []
    applied = 0
    with ThreadPoolExecutor(max_workers=1) as bg:
        legit_future = bg.submit(legit_batch, "under_flood")
        flood_started = time.perf_counter()
        for ep in endpoints:
            t0 = time.perf_counter()
            r = client.post(f"{EVIDENCE_URL}/dispute",
                            json={"device_type": DEVICE_TYPE, "endpoint": ep, "site_id": "attacker-0"})
            flood_lat.append(time.perf_counter() - t0)
            if r.status_code == 200 and r.json().get("applied"):
                applied += 1
        flood_wall = time.perf_counter() - flood_started
        under_flood = legit_future.result()

    aces_after = [exported_aces(client, s) for s in range(args.sites)]
    print(f"[flood] {applied}/{args.facts} disputes applied in {flood_wall:.2f}s; "
          f"exported ACEs/site={aces_after}", flush=True)

    # ---- recovery: privileged restore + fresh local commit per site -----
    rec_started = time.perf_counter()
    recovery_requests = 0
    for ep in endpoints:
        client.post(f"{EVIDENCE_URL}/restore", json={"device_type": DEVICE_TYPE, "endpoint": ep})
        recovery_requests += 1
    restore_wall = time.perf_counter() - rec_started
    for s in range(args.sites):
        for ep in endpoints:
            client.post(f"{site_url(s)}/commit", json={"device_type": DEVICE_TYPE, "endpoint": ep})
            recovery_requests += 1
    recovery_wall = time.perf_counter() - rec_started
    aces_recovered = [exported_aces(client, s) for s in range(args.sites)]
    print(f"[recovery] {recovery_requests} requests in {recovery_wall:.2f}s; "
          f"exported ACEs/site={aces_recovered}", flush=True)

    summary = {
        "facts": args.facts,
        "sites": args.sites,
        "setup_requests": setup_requests,
        "attacker": {
            "identities": 1,
            "threads": 1,
            "requests": args.facts,
            "disputes_applied": applied,
            "wall_s": round(flood_wall, 4),
            "disputes_per_s": round(applied / flood_wall, 2),
            "mean_dispute_ms": round(statistics.mean(flood_lat) * 1000, 2),
            "p99_dispute_ms": round(pct(flood_lat, 0.99) * 1000, 2),
            "requests_per_fact_suspended": round(args.facts / applied, 3) if applied else None,
            "site_records_suspended": applied * args.sites,
        },
        "blast_radius": {
            "exported_aces_per_site_before": aces_before,
            "exported_aces_per_site_after": aces_after,
            "exported_aces_per_site_after_recovery": aces_recovered,
        },
        "legitimate_load": {"baseline": baseline, "under_flood": under_flood},
        "recovery": {
            "requests": recovery_requests,
            "restore_only_wall_s": round(restore_wall, 4),
            "wall_s": round(recovery_wall, 4),
            "requests_per_fact": round(recovery_requests / args.facts, 3),
        },
    }
    (out / "dispute_flood_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
