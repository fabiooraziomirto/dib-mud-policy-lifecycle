"""Distributed-architecture counterpart of prepare_policy.py (point 5 of the
reviewer-style critique on the distributed-registry work): drives the SAME
commit->dispute->restore lifecycle and the SAME OpenWrt/osMUD/nftables
testbed (run.sh, unmodified), but through the site-0 and evidence HTTP
containers (code/src/dib/registry/distributed/service.py) instead of a
direct in-process SQLAlchemy session against a local SQLite file.

Site mapping: lab-a (the enforcing site, matching prepare_policy.py) ->
site-0; lab-b -> site-1; lab-c -> site-2. Requires the distributed cluster
already running (docker compose up -d in code/src/dib/registry/distributed)
with evidence on localhost:18100 and sites on localhost:1811{0,1,2}.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import httpx

EVIDENCE_URL = "http://localhost:18100"
SITE_A, SITE_B, SITE_C = "http://localhost:18110", "http://localhost:18111", "http://localhost:18112"

FACTS = (("allowed.test", "tcp", 8080), ("allowed.test", "udp", 5353))


def _body(endpoint: str, protocol: str, port: int, **extra) -> dict:
    return {"device_type": "camera", "endpoint": endpoint, "protocol": protocol, "port": port, **extra}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action",
        choices=["init", "commit", "dispute1", "dispute2", "revoke", "restore",
                 "local-revoke", "local-restore"],
    )
    parser.add_argument("--db", required=False, help="unused, kept for run.sh CLI compatibility")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    if args.action == "init":
        for endpoint, protocol, port in FACTS:
            httpx.post(f"{EVIDENCE_URL}/seed", json=_body(endpoint, protocol, port))
            httpx.post(f"{SITE_A}/query", json=_body(endpoint, protocol, port))
    elif args.action == "commit":
        for endpoint, protocol, port in FACTS:
            httpx.post(f"{SITE_A}/commit", json=_body(endpoint, protocol, port)).raise_for_status()
    elif args.action == "dispute1":
        for endpoint, protocol, port in FACTS:
            httpx.post(f"{EVIDENCE_URL}/dispute", json=_body(endpoint, protocol, port, site_id="lab-b")).raise_for_status()
    elif args.action == "dispute2":
        for endpoint, protocol, port in FACTS:
            httpx.post(f"{EVIDENCE_URL}/dispute", json=_body(endpoint, protocol, port, site_id="lab-c")).raise_for_status()
    elif args.action == "revoke":
        for endpoint, protocol, port in FACTS:
            httpx.post(f"{EVIDENCE_URL}/dispute", json=_body(endpoint, protocol, port, site_id="lab-b")).raise_for_status()
            httpx.post(f"{EVIDENCE_URL}/dispute", json=_body(endpoint, protocol, port, site_id="lab-c")).raise_for_status()
    elif args.action == "restore":
        for endpoint, protocol, port in FACTS:
            httpx.post(f"{EVIDENCE_URL}/restore", json=_body(endpoint, protocol, port)).raise_for_status()
    elif args.action == "local-revoke":
        for endpoint, protocol, port in FACTS:
            httpx.post(f"{SITE_A}/local_revoke", json=_body(endpoint, protocol, port)).raise_for_status()
    elif args.action == "local-restore":
        for endpoint, protocol, port in FACTS:
            httpx.post(f"{SITE_A}/local_restore", json=_body(endpoint, protocol, port)).raise_for_status()

    resp = httpx.get(f"{SITE_A}/export_mud", params={"device_type": "camera", "mud_url": "http://mud-server:8000/camera.json"})
    resp.raise_for_status()
    document = resp.json()
    Path(args.output).write_text(json.dumps(document, indent=2) + "\n")
    exported_aces = sum(
        len(acl["aces"]["ace"]) for acl in document["ietf-access-control-list:access-lists"]["acl"]
    )
    print(json.dumps({"action": args.action, "exported_aces": exported_aces}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
