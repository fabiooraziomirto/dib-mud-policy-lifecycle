"""Automated, repeated fault-injection experiment against the running
Docker Compose cluster (10 sites + evidence, service.py). Measures the
reconciliation-convergence window across N trials per scenario, not a
single anecdotal sample.

Four scenarios. Three correspond to the individual fan-out event types a
site can miss while unreachable (operator_commit is a purely site-local
write with no cross-site fan-out, so a crash during it cannot produce an
inter-site inconsistency to measure, hence no separate "crash during
commit" scenario); the fourth is the compound case where a site misses the
*entire* dispute-confirm-restore episode in one outage:

  - dispute_open:        site is down when the first dispute fires (misses
                          a "dispute" fan-out event).
  - dispute_confirm:     site is down when the confirming (revoking)
                          dispute fires (misses a "revoke" fan-out event).
  - restore:             site is down when the episode is resolved (misses
                          a "restore" fan-out event).
  - dispute_and_restore: site commits (Active) *before* going down, then
                          misses the dispute, the confirming dispute, and
                          the restore in the same outage. Because the
                          evidence service's pending-fanout record is keyed
                          to the latest target state per (site, score_id)
                          (see pending_fanout's PRIMARY KEY and
                          ON CONFLICT ... WHERE excluded.seq > ... below),
                          the site never observes the intermediate Disputed
                          or Revoked states -- it must invalidate its
                          stale Active authorization directly from the
                          final reconciled MonitorOnly target. This is the
                          scenario the pending-fanout mechanism's collapsing
                          behavior is specifically for.

For each trial: kill the target site container, perform the scenario's
central action(s) against the evidence service (which fails fast against
the dead site -- connection refused, not a timeout wait -- and queues the
event in evidence's pending-fanout outbox), restart the container, then
measure (a) time until its HTTP health check responds, (b) time for its own
/reconcile call to complete, and (c) verify its resulting local state
matches the authoritative one the still-up sites already converged to.
Reports mean +/- stdev across trials per scenario, not a single sample.
"""
from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import time
from pathlib import Path

import httpx

EVIDENCE_URL = "http://localhost:18100"
COMPOSE_DIR = Path(__file__).resolve().parents[1] / "src/dib/registry/distributed"


def site_url(i: int) -> str:
    return f"http://localhost:{18110 + i}"


def compose(*args: str) -> None:
    subprocess.run(["docker", "compose", *args], cwd=COMPOSE_DIR, check=True,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def wait_healthy(url: str, timeout_s: float = 10.0) -> float:
    started = time.time()
    while time.time() - started < timeout_s:
        try:
            httpx.get(f"{url}/health", timeout=0.5)
            return time.time() - started
        except Exception:
            time.sleep(0.05)
    raise TimeoutError(f"{url} did not become healthy within {timeout_s}s")


def run_trial(scenario: str, target_site: int, trial_index: int) -> dict:
    device_type = "cam-a"
    endpoint = f"fi-{scenario}-{trial_index}.example"
    httpx.post(f"{EVIDENCE_URL}/seed", json={"device_type": device_type, "endpoint": endpoint})
    for s in range(10):
        httpx.post(f"{site_url(s)}/query", json={"device_type": device_type, "endpoint": endpoint})
    if scenario in ("dispute_confirm", "restore"):
        httpx.post(f"{EVIDENCE_URL}/dispute", json={"device_type": device_type, "endpoint": endpoint, "site_id": "site-1"})
    if scenario == "dispute_and_restore":
        # Target site commits (Active, grantValid) *before* going down, so the
        # compound outage below must invalidate a real prior authorization,
        # not just an unauthorized MonitorOnly record.
        httpx.post(f"{site_url(target_site)}/commit", json={"device_type": device_type, "endpoint": endpoint})

    compose("kill", f"site-{target_site}")

    if scenario == "dispute_open":
        httpx.post(f"{EVIDENCE_URL}/dispute", json={"device_type": device_type, "endpoint": endpoint, "site_id": "site-1"})
        expected_state = "disputed"
    elif scenario == "dispute_confirm":
        httpx.post(f"{EVIDENCE_URL}/dispute", json={"device_type": device_type, "endpoint": endpoint, "site_id": "site-2"})
        expected_state = "revoked"
    elif scenario == "restore":
        httpx.post(f"{EVIDENCE_URL}/restore", json={"device_type": device_type, "endpoint": endpoint})
        expected_state = "monitor-only"
    else:  # dispute_and_restore: site misses the *entire* suspend-confirm-restore
        # episode in one outage -- it must never observe the intermediate
        # Disputed/Revoked states, only the final reconciled target.
        httpx.post(f"{EVIDENCE_URL}/dispute", json={"device_type": device_type, "endpoint": endpoint, "site_id": "site-1"})
        httpx.post(f"{EVIDENCE_URL}/dispute", json={"device_type": device_type, "endpoint": endpoint, "site_id": "site-2"})
        httpx.post(f"{EVIDENCE_URL}/restore", json={"device_type": device_type, "endpoint": endpoint})
        expected_state = "monitor-only"

    pending = httpx.get(f"{EVIDENCE_URL}/pending/site-{target_site}", timeout=5.0).json()["pending"]
    assert pending, f"expected a queued fan-out event for site-{target_site}, got none"

    compose("start", f"site-{target_site}")
    t_restart_issued = time.time()
    t_healthy = wait_healthy(site_url(target_site))

    t0_reconcile = time.time()
    reconcile_resp = httpx.post(f"{site_url(target_site)}/reconcile", timeout=5.0).json()
    t_reconcile = time.time() - t0_reconcile

    score_id = httpx.get(f"{EVIDENCE_URL}/scores", params={"device_type": device_type, "endpoint": endpoint}).json()["id"]
    final = httpx.get(f"{site_url(target_site)}/state/{score_id}", timeout=3.0).json()
    consistent = final["state"] == expected_state

    return {
        "scenario": scenario, "trial": trial_index,
        "health_check_after_restart_s": round(t_healthy, 4),
        "reconcile_call_s": round(t_reconcile, 4),
        "total_convergence_s": round(t_healthy + t_reconcile, 4),
        "events_reconciled": reconcile_resp.get("reconciled"),
        "final_state": final["state"], "expected_state": expected_state,
        "consistent": consistent,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=10)
    parser.add_argument("--target-site", type=int, default=3)
    parser.add_argument("--output", default="outputs/fault_injection/results.csv")
    args = parser.parse_args()

    scenarios = ["dispute_open", "dispute_confirm", "restore", "dispute_and_restore"]
    all_rows = []
    for scenario in scenarios:
        print(f"=== scenario: {scenario} ===", flush=True)
        for t in range(args.trials):
            row = run_trial(scenario, args.target_site, t)
            all_rows.append(row)
            print(f"  trial {t+1}/{args.trials}: health={row['health_check_after_restart_s']}s "
                  f"reconcile={row['reconcile_call_s']}s total={row['total_convergence_s']}s "
                  f"consistent={row['consistent']}", flush=True)

    print("\n=== summary (mean +/- stdev across trials) ===")
    summary = []
    for scenario in scenarios:
        rows = [r for r in all_rows if r["scenario"] == scenario]
        totals = [r["total_convergence_s"] for r in rows]
        healths = [r["health_check_after_restart_s"] for r in rows]
        reconciles = [r["reconcile_call_s"] for r in rows]
        n_consistent = sum(1 for r in rows if r["consistent"])
        s = {
            "scenario": scenario, "trials": len(rows),
            "consistent_trials": n_consistent,
            "health_check_s_mean": round(statistics.mean(healths), 4),
            "health_check_s_std": round(statistics.stdev(healths), 4) if len(healths) > 1 else 0.0,
            "reconcile_s_mean": round(statistics.mean(reconciles), 4),
            "reconcile_s_std": round(statistics.stdev(reconciles), 4) if len(reconciles) > 1 else 0.0,
            "total_convergence_s_mean": round(statistics.mean(totals), 4),
            "total_convergence_s_std": round(statistics.stdev(totals), 4) if len(totals) > 1 else 0.0,
        }
        summary.append(s)
        print(f"  {scenario}: {n_consistent}/{len(rows)} consistent, "
              f"total_convergence={s['total_convergence_s_mean']}+/-{s['total_convergence_s_std']}s "
              f"(health={s['health_check_s_mean']}+/-{s['health_check_s_std']}s, "
              f"reconcile={s['reconcile_s_mean']}+/-{s['reconcile_s_std']}s)")

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    import csv
    with (out_path.parent / "trials.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(all_rows[0].keys()))
        w.writeheader()
        w.writerows(all_rows)
    with out_path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(summary[0].keys()))
        w.writeheader()
        w.writerows(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
