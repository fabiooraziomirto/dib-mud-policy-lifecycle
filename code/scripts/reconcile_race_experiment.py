"""Targeted race test: a site's own /reconcile pull racing a genuinely NEW,
concurrent fan-out push from evidence (not just the last queued state) --
the scenario the reviewer-style critique flagged as the one place the
sequence-number idempotency guard could plausibly have a real bug (e.g. a
new dispute lands at site-3 while its reconciliation of an older, queued
event is still being applied).

Per trial: kill site-3, fire event A (queued in outbox since site-3 is
down), restart site-3, then fire event B (a second, NEWER central action)
and call POST /reconcile on site-3 CONCURRENTLY (two threads, a barrier so
both start as close to simultaneously as Python threading allows) -- so
whichever arrives at site-3 first is genuinely racing the other. Verifies
that regardless of arrival order, site-3 ends up at the state event B
implies (the higher sequence number), never a corrupted or reverted state.
Repeated over N trials, not a single sample.
"""
from __future__ import annotations

import argparse
import statistics
import subprocess
import threading
import time
from pathlib import Path

import httpx

EVIDENCE_URL = "http://localhost:18100"
COMPOSE_DIR = Path(__file__).resolve().parents[1] / "src/dib/registry/distributed"
TARGET_SITE = 3


def site_url(i: int) -> str:
    return f"http://localhost:{18110 + i}"


def compose(*args: str) -> None:
    subprocess.run(["docker", "compose", *args], cwd=COMPOSE_DIR, check=True,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def wait_healthy(url: str, timeout_s: float = 10.0) -> None:
    started = time.time()
    while time.time() - started < timeout_s:
        try:
            httpx.get(f"{url}/health", timeout=0.5)
            return
        except Exception:
            time.sleep(0.02)
    raise TimeoutError(f"{url} not healthy in time")


def run_trial(trial_index: int) -> dict:
    device_type, endpoint = "cam-race", f"race-{trial_index}.example"
    httpx.post(f"{EVIDENCE_URL}/seed", json={"device_type": device_type, "endpoint": endpoint})
    for s in range(10):
        httpx.post(f"{site_url(s)}/query", json={"device_type": device_type, "endpoint": endpoint})

    compose("kill", f"site-{TARGET_SITE}")
    # Event A: queued while site-3 is down.
    httpx.post(f"{EVIDENCE_URL}/dispute", json={"device_type": device_type, "endpoint": endpoint, "site_id": "site-1"})
    compose("start", f"site-{TARGET_SITE}")
    wait_healthy(site_url(TARGET_SITE))

    barrier = threading.Barrier(2)
    results = {}

    def do_reconcile():
        barrier.wait(timeout=5)
        try:
            r = httpx.post(f"{site_url(TARGET_SITE)}/reconcile", timeout=5.0)
            results["reconcile"] = r.json()
        except Exception as exc:
            results["reconcile_error"] = str(exc)

    def do_new_event():
        barrier.wait(timeout=5)
        # Event B: a genuinely NEW, concurrent central action -- the confirming
        # dispute (site-3 is up now, so this delivers directly, racing reconcile).
        try:
            r = httpx.post(f"{EVIDENCE_URL}/dispute",
                            json={"device_type": device_type, "endpoint": endpoint, "site_id": "site-2"}, timeout=5.0)
            results["new_event"] = r.json()
        except Exception as exc:
            results["new_event_error"] = str(exc)

    t1 = threading.Thread(target=do_reconcile)
    t2 = threading.Thread(target=do_new_event)
    t1.start(); t2.start()
    t1.join(); t2.join()

    score = httpx.get(f"{EVIDENCE_URL}/scores", params={"device_type": device_type, "endpoint": endpoint}).json()
    final = httpx.get(f"{site_url(TARGET_SITE)}/state/{score['id']}", timeout=3.0).json()

    # Truth after both events landed: dispute (site-1) then confirming dispute
    # (site-2, distinct site) => revoked, at the highest fanout_seq.
    expected_state = "revoked"
    expected_seq = score["fanout_seq"]
    consistent = final["state"] == expected_state and final["last_applied_seq"] == expected_seq
    return {
        "trial": trial_index, "final_state": final["state"], "final_seq": final["last_applied_seq"],
        "expected_state": expected_state, "expected_seq": expected_seq, "consistent": consistent,
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=20)
    args = parser.parse_args()

    rows = []
    for t in range(args.trials):
        row = run_trial(t)
        rows.append(row)
        print(f"  trial {t+1}/{args.trials}: state={row['final_state']} seq={row['final_seq']} "
              f"(expected state={row['expected_state']} seq={row['expected_seq']}) "
              f"consistent={row['consistent']}", flush=True)

    n_consistent = sum(1 for r in rows if r["consistent"])
    print(f"\n=== {n_consistent}/{len(rows)} trials consistent ===")
    if n_consistent < len(rows):
        print("INCONSISTENT TRIALS:")
        for r in rows:
            if not r["consistent"]:
                print(" ", r)
    return 0 if n_consistent == len(rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
