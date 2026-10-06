"""Deterministic API/SQLite campaign, no sockets, WAN or gateway timing claims.

Runs the actual distributed service and MUD serializer through TestClient.
Each service has an isolated database; an in-process router replaces transport.
The site identities are trusted test inputs, not authenticated credentials.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from urllib.parse import urlsplit

import httpx
from fastapi.testclient import TestClient

SOURCE = Path(__file__).resolve().parents[1] / "src/dib/registry/distributed/service.py"


class Deployment:
    def __init__(self, root, quorum, sites=10):
        self.clients = {}
        self.modules = []
        settings = {k: v for k, v in os.environ.items() if k.startswith("DIB_DIST_")}
        try:
            for name in ["evidence"] + [f"site-{i}" for i in range(sites)]:
                os.environ.update(DIB_DIST_DATA_DIR=str(root / name), DIB_DIST_ROLE="evidence" if name == "evidence" else "site",
                                  DIB_DIST_SITE_INDEX=name.split("-")[-1] if name != "evidence" else "0",
                                  DIB_DIST_N_SITES=str(sites), DIB_DIST_SUSPENSION_QUORUM=str(quorum),
                                  DIB_DIST_EVIDENCE_URL="http://evidence:8000")
                module_name = f"v35_{root.name}_{name.replace('-', '_')}"
                spec = importlib.util.spec_from_file_location(module_name, SOURCE)
                mod = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = mod
                spec.loader.exec_module(mod)
                self.modules.append(mod)
                self.clients[name] = TestClient(mod.app)
            proxy = SimpleNamespace(get=lambda url, **kw: self.route("get", url, **kw),
                                    post=lambda url, **kw: self.route("post", url, **kw), HTTPError=httpx.HTTPError)
            for mod in self.modules:
                mod.httpx = proxy
        finally:
            for k in list(os.environ):
                if k.startswith("DIB_DIST_"):
                    del os.environ[k]
            os.environ.update(settings)

    def route(self, method, url, **kw):
        parts = urlsplit(url)
        kw.pop("timeout", None)
        return getattr(self.clients[parts.hostname], method)(parts.path, **kw)

    def post(self, site, path, payload):
        response = self.clients[site].post(path, json=payload)
        assert response.status_code == 200, (site, path, response.text)
        return response.json()

    def state(self, site, score_id):
        return self.clients[site].get(f"/state/{score_id}").json()

    def aces(self):
        counts = []
        for site, client in self.clients.items():
            if site == "evidence":
                continue
            response = client.get("/export_mud", params={"device_type": "camera"})
            assert response.status_code == 200, response.text
            doc = response.json()
            counts.append(sum(len(acl["aces"]["ace"]) for acl in doc["ietf-access-control-list:access-lists"]["acl"]))
        return counts

    def close(self):
        for client in self.clients.values():
            client.close()
        for mod in self.modules:
            getattr(mod, "_site_db", getattr(mod, "_evidence_db", None))._con.close()
            sys.modules.pop(mod.__name__, None)


def run():
    summary = {"scope": "in-process API campaign; actual SQLite services and MUD exports; no network timing", "policies": []}
    for quorum in (1, 2):
        with tempfile.TemporaryDirectory(prefix="dib-v35-") as temp:
            dep = Deployment(Path(temp), quorum)
            try:
                facts = [{"device_type": "camera", "endpoint": f"service-{i}.example.org", "protocol": "tcp", "port": 443} for i in range(100)]
                for fact in facts:
                    dep.post("evidence", "/seed", fact)
                    for i in range(10):
                        dep.post(f"site-{i}", "/query", fact)
                        dep.post(f"site-{i}", "/commit", fact)
                before = dep.aces()
                for fact in facts:
                    dep.post("evidence", "/dispute", dict(fact, site_id="member-a"))
                one_reporter = dep.aces()
                for fact in facts:
                    dep.post("evidence", "/dispute", dict(fact, site_id="member-a"))
                assert dep.aces() == one_reporter, "replays must not add votes"
                for fact in facts:
                    dep.post("evidence", "/dispute", dict(fact, site_id="member-b"))
                two_reporters = dep.aces()
                assert before == [100] * 10
                assert one_reporter == ([0] * 10 if quorum == 1 else before)
                assert two_reporters == [0] * 10
                # Veto after suspension (q=2) or confirmed shared revocation (q=1).
                for fact in facts:
                    dep.post("site-0", "/local_revoke", fact)
                    blocked = dep.clients["site-0"].post("/local_restore", json=fact)
                    assert blocked.status_code == 409
                    dep.post("evidence", "/restore", dict(fact, site_id="admin"))
                assert dep.aces() == [0] * 10
                for score_id in range(1, 101):
                    assert dep.state("site-0", score_id)["origin"] == "local"
                    assert dep.state("site-1", score_id)["state"] == "monitor-only"
                for fact in facts:
                    dep.post("site-0", "/local_restore", fact)
                    for i in range(10):
                        dep.post(f"site-{i}", "/commit", fact)
                assert dep.aces() == before
                # Restoration must clear old votes: member-a starts a new episode.
                for fact in facts:
                    dep.post("evidence", "/dispute", dict(fact, site_id="member-a"))
                assert dep.aces() == one_reporter
                summary["policies"].append({"suspension_quorum": quorum, "facts": 100, "sites": 10,
                    "aces_before_per_site": before, "aces_after_one_reporter_per_site": one_reporter,
                    "aces_after_two_reporters_per_site": two_reporters,
                    "duplicate_reports_add_votes": False, "local_vetoes_preserved": 100,
                    "restoration_requires_new_commits": True, "old_votes_cleared": True})
            finally:
                dep.close()
    return summary


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
