"""Exercise local-veto preservation on the actual registry, without gateway claims."""
from pathlib import Path
import json
import os
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from dib.registry import db, services
from moniotr_cross_lab import sha256


def main():
    root = Path(__file__).resolve().parents[2]
    out = root / "experiments/34_v28_lifecycle"
    out.mkdir(parents=True, exist_ok=True)
    key = ("camera", "api.vendor.com", "https", 443)
    rows = []
    with tempfile.TemporaryDirectory(prefix="dib-v28-lifecycle-") as tmp:
        os.environ["DIB_DATABASE_URL"] = "sqlite:///" + str(Path(tmp) / "registry.db")
        db._engine = None
        db._SessionLocal = None
        session = db.get_session()
        services.upsert_score(session, dict(device_type=key[0], endpoint=key[1],
            protocol=key[2], port=key[3], site_confidence=.9, temporal_confidence=.8,
            graph_confidence=0, score=.86, accepted=True))
        for site in ("receiver", "peer"):
            services.query_score(session, site, *key)
            services.operator_commit(session, site, *key)
        session.commit()

        def record(event, expected):
            score = services.get_score(session, *key)
            states = {s: services.get_local_decision(session, score.id, s).state
                      for s in ("receiver", "peer")}
            assert list(states.values()) == expected, (event, states, expected)
            rows.append(dict(event=event, states=states, global_status=score.status))

        record("approve both", [db.DECISION_ACTIVE, db.DECISION_ACTIVE])
        services.local_revoke(session, "receiver", *key)
        session.commit()
        record("local revoke", [db.DECISION_REVOKED, db.DECISION_ACTIVE])
        services.dispute_score(session, *key, "peer")
        session.commit()
        record("first dispute", [db.DECISION_REVOKED, db.DECISION_DISPUTED])
        try:
            services.local_restore(session, "receiver", *key)
        except services.InvalidStateTransition:
            session.rollback()
        else:
            raise AssertionError("local restore escaped open dispute")
        record("local restore rejected", [db.DECISION_REVOKED, db.DECISION_DISPUTED])
        services.dispute_score(session, *key, "third")
        session.commit()
        record("second dispute", [db.DECISION_REVOKED, db.DECISION_REVOKED])
        services.restore_score(session, *key, actor_site_id="consortium-operator")
        session.commit()
        record("global restore", [db.DECISION_REVOKED, db.DECISION_MONITOR_ONLY])
        services.local_restore(session, "receiver", *key)
        session.commit()
        record("local restore", [db.DECISION_MONITOR_ONLY, db.DECISION_MONITOR_ONLY])
        services.operator_commit(session, "receiver", *key)
        session.commit()
        record("fresh local commit", [db.DECISION_ACTIVE, db.DECISION_MONITOR_ONLY])
        session.close()
        db._engine.dispose()
    (out / "registry_trace.json").write_text(json.dumps(dict(
        status="pass", scope="registry service states; trusted harness; no gateway or role-enforcement test",
        command="python code/scripts/v28_lifecycle_trace.py", steps=rows,
        sha256={str(p.relative_to(root)): sha256(p) for p in
                [Path(__file__), root / "code/src/dib/registry/services.py"]}), indent=2) + "\n")
    print(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()
