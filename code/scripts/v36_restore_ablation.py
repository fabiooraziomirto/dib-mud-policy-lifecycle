"""Controlled restoration-policy ablation on the real API/SQLite/MUD path.

Alternatives are experimental policy adapters, NOT published systems. Only
restore handling differs; the persistent-bit adapter also records successful
local commits/revocations in an auxiliary SQLite table. Sequential cases only.
Transport is in-process; disconnection is injected as HTTP transport failure.
No timing, authentication, gateway or production-reliability claim is made.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import tempfile
from urllib.parse import urlsplit

import httpx

from v35_lifecycle_experiment import Deployment, SOURCE

POLICIES = ("persistent_approval", "review_reset", "dib")
FACT = dict(device_type="camera", endpoint="subject.example.org", protocol="tcp", port=443)
CONTROL = dict(device_type="sensor", endpoint="control.example.org", protocol="tcp", port=443)


class PolicyDeployment(Deployment):
    def __init__(self, root, policy):
        self.offline = set()
        self.policy = policy
        super().__init__(root, quorum=1, sites=3)
        self.sites = {f"site-{i}": mod for i, mod in enumerate(self.modules[1:])}
        for mod in self.sites.values():
            mod._site_db.run(lambda con: con.execute(
                "CREATE TABLE experiment_approval (score_id INTEGER PRIMARY KEY, valid INTEGER)"))
            original = mod._apply_fanout_row

            def apply(con, score_id, seq, event_type, target_state, original=original, mod=mod):
                if event_type != "restore" or policy == "dib":
                    return original(con, score_id, seq, event_type, target_state)
                row = con.execute("SELECT state, origin, last_applied_seq FROM local_decisions WHERE score_id=?",
                                  (score_id,)).fetchone()
                if row is None or seq <= row[2]:
                    return
                if policy == "persistent_approval":
                    # Give this alternative the same local-veto protection as DIB.
                    if row[:2] == (mod.DECISION_REVOKED, mod.ORIGIN_LOCAL):
                        return original(con, score_id, seq, event_type, target_state)
                    bit = con.execute("SELECT valid FROM experiment_approval WHERE score_id=?", (score_id,)).fetchone()
                    target_state = mod.DECISION_ACTIVE if bit and bit[0] else mod.DECISION_MONITOR_ONLY
                # review_reset returns ALL records to review, including local vetoes.
                con.execute("UPDATE local_decisions SET state=?, origin=NULL, last_applied_seq=? WHERE score_id=?",
                            (target_state, seq, score_id))

            mod._apply_fanout_row = apply

    def route(self, method, url, **kw):
        if urlsplit(url).hostname in self.offline:
            raise httpx.ConnectError("controlled offline-site injection")
        return super().route(method, url, **kw)

    def post(self, site, path, payload):
        result = super().post(site, path, payload)
        if site in self.sites and path in ("/commit", "/local_revoke"):
            mod = self.sites[site]
            score = mod._evidence_get_score(**payload)
            mod._site_db.run(lambda con: con.execute(
                "INSERT INTO experiment_approval VALUES (?, ?) ON CONFLICT(score_id) DO UPDATE SET valid=excluded.valid",
                (score["id"], int(path == "/commit"))))
        return result

    def snapshot(self, label):
        states = [self.state(f"site-{i}", 1) for i in range(3)]
        subject_exports = self.aces()
        control_exports = []
        for i in range(3):
            response = self.clients[f"site-{i}"].get("/export_mud", params={"device_type": "sensor"})
            assert response.status_code == 200
            control_exports.append(sum(len(a["aces"]["ace"]) for a in
                response.json()["ietf-access-control-list:access-lists"]["acl"]))
        assert control_exports == [1, 1, 1], "unrelated fact changed"
        return dict(event=label, states=states, subject_aces=subject_exports, control_aces=control_exports)


def case(policy, veto_time, disconnected):
    with tempfile.TemporaryDirectory(prefix="dib-v36-") as temp:
        dep = PolicyDeployment(Path(temp), policy)
        try:
            for fact in (FACT, CONTROL):
                dep.post("evidence", "/seed", fact)
                for i in range(3):
                    dep.post(f"site-{i}", "/query", fact)
                    dep.post(f"site-{i}", "/commit", fact)
            trace = [dep.snapshot("initial_commit")]
            if disconnected:
                dep.offline.add("site-2")
            if veto_time == "before":
                dep.post("site-0", "/local_revoke", FACT)
                trace.append(dep.snapshot("local_veto"))
            dep.post("evidence", "/dispute", dict(FACT, site_id="reporter-a"))
            trace.append(dep.snapshot("first_dispute"))
            if veto_time == "during":
                dep.post("site-0", "/local_revoke", FACT)
                trace.append(dep.snapshot("local_veto"))
            dep.post("evidence", "/dispute", dict(FACT, site_id="reporter-b"))
            trace.append(dep.snapshot("confirming_dispute"))
            if veto_time == "confirmed":
                dep.post("site-0", "/local_revoke", FACT)
                trace.append(dep.snapshot("local_veto"))
            blocked = dep.clients["site-0"].post("/local_restore", json=FACT)
            assert blocked.status_code == 409
            dep.post("evidence", "/restore", dict(FACT, site_id="admin"))
            trace.append(dep.snapshot("global_restore"))
            if disconnected:
                pending = dep.clients["evidence"].get("/pending/site-2").json()["pending"]
                assert len(pending) == 1 and pending[0]["event_type"] == "restore"
                dep.offline.clear()
                assert dep.post("site-2", "/reconcile", {})["reconciled"] == 1
                assert dep.post("site-2", "/reconcile", {})["reconciled"] == 0
            final = dep.snapshot("restored_and_reconciled")
            trace.append(final)
            # Replaying an older event must not overwrite the restored target.
            for i in range(3):
                dep.post(f"site-{i}", "/apply_fanout", dict(score_id=1, seq=1,
                         event_type="dispute", target_state="disputed"))
            assert dep.snapshot("replayed")["states"] == final["states"]
            assert dep.aces() == final["subject_aces"]
            exported_without_commit = sum(final["subject_aces"])
            veto_preserved = final["states"][0]["origin"] == "local" and final["states"][0]["state"] == "revoked"
            assert exported_without_commit == (2 if policy == "persistent_approval" else 0)
            assert veto_preserved == (policy != "review_reset")
            # Positive recovery control: veto needs local restore, then all
            # reviewed sites need a commit; persistent peers already export.
            if veto_preserved:
                dep.post("site-0", "/local_restore", FACT)
            for i, state in enumerate(final["states"]):
                if state["state"] != "active":
                    dep.post(f"site-{i}", "/commit", FACT)
            assert dep.aces() == [1, 1, 1]
            trace.append(dep.snapshot("explicit_recovery"))
            return dict(policy=policy, veto_time=veto_time, disconnected=disconnected,
                        exports_without_fresh_commit=exported_without_commit,
                        local_veto_preserved=veto_preserved, stale_replay_ignored=True,
                        unrelated_fact_preserved=True, explicit_recovery_passed=True, trace=trace)
        finally:
            dep.close()


def run():
    cases = [case(p, t, offline) for p in POLICIES
             for t in ("before", "during", "confirmed") for offline in (False, True)]
    return dict(scope="deterministic sequential API/SQLite/MUD ablation; synthetic facts; no timing or gateway claims",
                service_sha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                cases=cases,
                summary=[dict(policy=p, cases=6,
                              exports_without_fresh_commit=sum(c["exports_without_fresh_commit"] for c in cases if c["policy"] == p),
                              vetoes_preserved=sum(c["local_veto_preserved"] for c in cases if c["policy"] == p)) for p in POLICIES])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(run(), indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(result)
    else:
        print(result, end="")
