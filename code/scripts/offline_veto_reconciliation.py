"""Exercise missed-episode recovery on unmodified services over loopback HTTP.

Three site processes and one evidence process use isolated SQLite stores.
Each trial kills the site holding a local veto, completes two shared withdrawal
episodes while it is down, and restarts it against its existing database.
The second subject is an Active control; a third fact remains unrelated.
No gateway or WAN timing is measured. All processes are cleaned up on exit.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import tempfile
import time

import httpx

CODE = Path(__file__).resolve().parents[1]
SOURCE = CODE / "src/dib/registry/distributed/service.py"


def run(trials: int) -> dict:
    reservations = []
    for _ in range(4):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        reservations.append(sock)
    ports = [sock.getsockname()[1] for sock in reservations]
    urls = [f"http://127.0.0.1:{port}" for port in ports]
    for sock in reservations:
        sock.close()
    processes = {}
    logs = []
    records = []
    with tempfile.TemporaryDirectory(prefix="dib-offline-veto-") as temp, httpx.Client(timeout=30, trust_env=False) as client:
        def start(index):
            env = dict(os.environ, PYTHONPATH=str(CODE / "src"),
                       DIB_DIST_ROLE="evidence" if index == 0 else "site",
                       DIB_DIST_N_SITES="3", DIB_DIST_SITE_INDEX=str(index - 1),
                       DIB_DIST_DATA_DIR=str(Path(temp) / str(index)),
                       DIB_DIST_EVIDENCE_URL=urls[0], DIB_DIST_SUSPENSION_QUORUM="1")
            for i in range(3):
                env[f"DIB_DIST_SITE_URL_{i}"] = urls[i + 1]
            log = (Path(temp) / f"process-{index}.log").open("a")
            logs.append(log)
            processes[index] = subprocess.Popen(
                [sys.executable, "-m", "uvicorn", "dib.registry.distributed.service:app",
                 "--host", "127.0.0.1", "--port", str(ports[index]), "--log-level", "warning"],
                env=env, stdout=log, stderr=log)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if processes[index].poll() is not None:
                    raise RuntimeError((Path(temp) / f"process-{index}.log").read_text())
                try:
                    if client.get(urls[index] + "/health").status_code == 200:
                        return
                except httpx.ConnectError:
                    pass
                time.sleep(.05)
            raise TimeoutError(f"service {index} failed to start")

        def request(index, method, path, **kwargs):
            response = client.request(method, urls[index] + path, **kwargs)
            response.raise_for_status()
            return response.json()

        def post(index, path, payload):
            return request(index, "POST", path, json=payload)

        def aces(index, fact):
            mud = request(index, "GET", "/export_mud", params={"device_type": fact["device_type"]})
            return sum(len(acl["aces"]["ace"]) for acl in mud["ietf-access-control-list:access-lists"]["acl"])

        try:
            for index in range(4):
                start(index)
            for trial in range(trials):
                facts = {name: dict(device_type=f"{name}-{trial}", endpoint=f"{name}-{trial}.example.org",
                                    protocol="tcp", port=443) for name in ("veto", "active", "unrelated")}
                ids = {}
                for name, fact in facts.items():
                    post(0, "/seed", fact)
                    ids[name] = request(0, "GET", "/scores", params=fact)["id"]
                    for index in range(1, 4):
                        post(index, "/query", fact)
                        post(index, "/commit", fact)
                        assert aces(index, fact) == 1
                post(3, "/local_revoke", facts["veto"])
                before = {name: request(3, "GET", f"/state/{ids[name]}") for name in facts}
                assert before["veto"]["state"] == "revoked" and before["veto"]["origin"] == "local"
                assert aces(3, facts["veto"]) == 0
                processes[3].kill()
                processes[3].wait(timeout=10)
                for name in ("veto", "active"):
                    fact = facts[name]
                    post(0, "/dispute", dict(fact, site_id="site-0"))
                    post(0, "/dispute", dict(fact, site_id="site-1"))
                    post(0, "/restore", dict(fact, site_id="admin"))
                pending = request(0, "GET", "/pending/site-2")["pending"]
                assert len(pending) == 2
                assert {r["score_id"] for r in pending} == {ids["veto"], ids["active"]}
                assert all(r["event_type"] == "restore" and r["target_state"] == "monitor-only" and r["seq"] == 3 for r in pending)
                start(3)
                # Verify persistence and that no intermediate event was applied.
                assert {name: request(3, "GET", f"/state/{ids[name]}") for name in facts} == before
                assert post(3, "/reconcile", {})["reconciled"] == 2
                after = {name: request(3, "GET", f"/state/{ids[name]}") for name in facts}
                assert after["veto"] == dict(state="revoked", origin="local", last_applied_seq=3)
                assert after["active"] == dict(state="monitor-only", origin=None, last_applied_seq=3)
                assert after["unrelated"] == before["unrelated"]
                exports = {name: [aces(index, fact) for index in range(1, 4)] for name, fact in facts.items()}
                assert exports == {"veto": [0, 0, 0], "active": [0, 0, 0], "unrelated": [1, 1, 1]}
                assert post(3, "/reconcile", {})["reconciled"] == 0
                for name in ("veto", "active"):
                    post(3, "/apply_fanout", dict(score_id=ids[name], seq=1, event_type="dispute", target_state="disputed"))
                    assert request(3, "GET", f"/state/{ids[name]}") == after[name]
                    assert aces(3, facts[name]) == 0
                blocked = client.post(urls[3] + "/commit", json=facts["veto"])
                assert blocked.status_code == 409
                post(3, "/local_restore", facts["veto"])
                assert aces(3, facts["veto"]) == 0
                for name in ("veto", "active"):
                    for index in range(1, 4):
                        post(index, "/commit", facts[name])
                        assert aces(index, facts[name]) == 1
                records.append(dict(trial=trial, before=before, pending=pending, after=after,
                                    exports_after_reconcile=exports, repeated_reconcile_noop=True,
                                    stale_replay_ignored=True, direct_commit_over_veto_blocked=True,
                                    explicit_recovery_passed=True))
                print(f"trial {trial + 1}/{trials}: passed", flush=True)
        finally:
            for process in processes.values():
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
            for log in logs:
                log.close()
    return dict(scope="three site processes plus evidence; loopback HTTP; process kill/restart; persistent SQLite; MUD export; no gateway timing",
                python=platform.python_version(), service_sha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), trials=records,
                summary=dict(trials=trials, vetoes_preserved=len(records), stale_approvals_cleared=len(records),
                             unrelated_facts_preserved=len(records), explicit_recoveries_passed=len(records)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=10)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.trials < 1:
        parser.error("--trials must be positive")
    result = run(args.trials)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
