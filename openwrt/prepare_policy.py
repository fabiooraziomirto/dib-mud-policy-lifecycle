from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "code" / "src"))

from dib.evaluation.mud_export import write_mud_file
from dib.registry import db, services


FACTS = (("allowed.test", "tcp", 8080), ("allowed.test", "udp", 5353))


def main() -> int:
    parser = argparse.ArgumentParser()
    # dispute1/dispute2 split what "revoke" used to do in a single call. The
    # design states that the FIRST dispute already suspends authorization and
    # export eligibility (Sec. IV, invariant I3); driving both disputes inside
    # one transaction made that intermediate state unobservable, so the
    # experiment could only ever attribute access removal to the second,
    # revoking dispute. "revoke" is kept as the original both-at-once path.
    parser.add_argument(
        "action",
        choices=[
            "init", "commit", "dispute1", "dispute2", "revoke", "restore", "export",
            "local-revoke", "local-restore",
        ],
    )
    parser.add_argument("--db", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    os.environ["DIB_DATABASE_URL"] = f"sqlite:///{Path(args.db).resolve()}"
    db._engine = None
    db._SessionLocal = None
    session = db.get_session()
    try:
        if args.action == "init":
            for endpoint, protocol, port in FACTS:
                services.upsert_score(session, {
                    "device_type": "camera", "endpoint": endpoint, "protocol": protocol, "port": port,
                    "site_confidence": 1.0, "temporal_confidence": 0.8,
                    "graph_confidence": 0.0, "score": 0.92, "accepted": True,
                })
                services.query_score(session, "lab-a", "camera", endpoint, protocol, port)
        elif args.action == "commit":
            for endpoint, protocol, port in FACTS:
                services.operator_commit(session, "lab-a", "camera", endpoint, protocol, port)
        elif args.action == "dispute1":
            for endpoint, protocol, port in FACTS:
                services.dispute_score(session, "camera", endpoint, protocol, port, "lab-b", "harness first dispute")
        elif args.action == "dispute2":
            for endpoint, protocol, port in FACTS:
                services.dispute_score(session, "camera", endpoint, protocol, port, "lab-c", "harness confirming dispute")
        elif args.action == "revoke":
            for endpoint, protocol, port in FACTS:
                services.dispute_score(session, "camera", endpoint, protocol, port, "lab-b", "harness revoke")
                services.dispute_score(session, "camera", endpoint, protocol, port, "lab-c", "harness confirm")
        elif args.action == "restore":
            for endpoint, protocol, port in FACTS:
                services.restore_score(session, "camera", endpoint, protocol, port, "lab-admin", "harness restore")
        elif args.action == "local-revoke":
            # Site-local negative authority: lab-a (the enforcing site itself)
            # withdraws its own LocalDecision without any other site's vote.
            # Unlike dispute1/dispute2, this never touches score.status, so it
            # cannot open or close a cross-site dispute episode.
            for endpoint, protocol, port in FACTS:
                services.local_revoke(session, "lab-a", "camera", endpoint, protocol, port, "harness local revoke")
        elif args.action == "local-restore":
            # Returns lab-a's own revoked record to MonitorOnly. Enforcement
            # resumes only after a fresh operator_commit(), never automatically.
            for endpoint, protocol, port in FACTS:
                services.local_restore(session, "lab-a", "camera", endpoint, protocol, port, "harness local restore")
        session.commit()
        result = services.export_active_mud(
            session, "lab-a", "camera", mud_url="http://mud-server:8000/camera.json"
        )
        write_mud_file(Path(args.output), result)
        print(json.dumps({"action": args.action, "exported_aces": result.exported_ace_count}))
    finally:
        session.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
