"""Measured comparison for Table I (main.tex, Sec. II): DIB's provenance-aware
restore vs. a naive "approval + review reset" baseline, on the exact scenario
Table I describes -- one fact approved at site s, then: local revoke at s,
peer dispute (opens), a second peer's confirming dispute (revokes), global
restore. Table I currently states this comparison is "semantic ... not
measured implementations"; this script measures it directly against the same
registry schema both workflows share (see baseline_naive_reset.py).

For each of n_trials fresh facts, this script runs the identical sequence
through both services.restore_score() (DIB) and
baseline_naive_reset.restore_score_naive_reset() (baseline) and records
whether site s's own local_revoke was erased by the global restore -- the
failure mode Table I's middle row names ("local veto is erased").
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dib.registry import services
from dib.registry.baseline_naive_reset import restore_score_naive_reset
from dib.registry.db import DECISION_MONITOR_ONLY, DECISION_REVOKED, get_engine


def fresh_engine(db_path: Path):
    import os
    os.environ["DIB_DATABASE_URL"] = f"sqlite:///{db_path}"
    import dib.registry.db as db_module
    db_module._engine = None
    db_module._SessionLocal = None
    return get_engine()


def new_session_factory():
    import dib.registry.db as db_module
    return db_module.get_session


def _run_scenario(get_session, device_type: str, endpoint: str, use_naive: bool) -> str:
    """Seeds one fact, approves it at site s, then runs: local revoke at s ->
    peer dispute (site-B, opens) -> confirming peer dispute (site-C, revokes)
    -> global restore (DIB or naive baseline). Returns site s's local decision
    state after restore."""
    session = get_session()
    try:
        services.upsert_score(session, {
            "device_type": device_type, "endpoint": endpoint, "protocol": "https", "port": 443,
            "site_confidence": 0.9, "temporal_confidence": 0.9, "graph_confidence": 0.0,
            "score": 0.9, "accepted": True,
        })
        session.commit()

        services.query_score(session, "site-s", device_type, endpoint, "https", 443)
        services.operator_commit(session, "site-s", device_type, endpoint, "https", 443)
        session.commit()

        services.local_revoke(session, "site-s", device_type, endpoint, "https", 443,
                               reason="site-s withdraws its own approval")
        session.commit()

        services.dispute_score(session, device_type, endpoint, "https", 443, "site-B",
                                reason="peer dispute opens episode")
        session.commit()
        services.dispute_score(session, device_type, endpoint, "https", 443, "site-C",
                                reason="confirming peer dispute revokes")
        session.commit()

        if use_naive:
            restore_score_naive_reset(session, device_type, endpoint, "https", 443,
                                       actor_site_id="registry-operator", reason="episode resolved")
        else:
            services.restore_score(session, device_type, endpoint, "https", 443,
                                    actor_site_id="registry-operator", reason="episode resolved")
        session.commit()

        score = services.get_score(session, device_type, endpoint, "https", 443)
        decision_s = services.get_local_decision(session, score.id, "site-s")
        return decision_s.state
    finally:
        session.close()


def run_comparison(get_session, n_trials: int) -> dict:
    dib_veto_erased = 0
    dib_veto_preserved = 0
    naive_veto_erased = 0
    naive_veto_preserved = 0
    for i in range(n_trials):
        state_dib = _run_scenario(get_session, "dib-workflow", f"ep-{i}.example", use_naive=False)
        if state_dib == DECISION_REVOKED:
            dib_veto_preserved += 1
        elif state_dib == DECISION_MONITOR_ONLY:
            dib_veto_erased += 1
        else:
            raise AssertionError(f"unexpected DIB decision state: {state_dib!r}")

        state_naive = _run_scenario(get_session, "naive-workflow", f"ep-{i}.example", use_naive=True)
        if state_naive == DECISION_REVOKED:
            naive_veto_preserved += 1
        elif state_naive == DECISION_MONITOR_ONLY:
            naive_veto_erased += 1
        else:
            raise AssertionError(f"unexpected naive-baseline decision state: {state_naive!r}")

    return {
        "trials": n_trials,
        "dib_local_veto_preserved": dib_veto_preserved,
        "dib_local_veto_erased": dib_veto_erased,
        "naive_reset_local_veto_preserved": naive_veto_preserved,
        "naive_reset_local_veto_erased": naive_veto_erased,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default="outputs/baseline_naive_reset")
    parser.add_argument("--trials", type=int, default=200)
    args = parser.parse_args(argv)

    output = ROOT / args.output_dir
    output.mkdir(parents=True, exist_ok=True)
    db_path = output / "baseline_naive_reset.db"
    db_path.unlink(missing_ok=True)
    fresh_engine(db_path)
    get_session = new_session_factory()

    result = run_comparison(get_session, args.trials)
    print(json.dumps(result, indent=2))

    from dib.core.io import write_csv
    write_csv(output / "comparison.csv", [result], list(result.keys()))

    def sha256_of(path: Path) -> str | None:
        if not path.exists():
            return None
        return hashlib.sha256(path.read_bytes()).hexdigest()

    manifest = {
        "experiment": "baseline_naive_reset_experiment",
        "command": sys.argv,
        "scenario": "Table I: local revoke at s, peer dispute, confirming peer dispute, global restore",
        "config": {"trials": args.trials},
        "result": result,
        "checksums": {
            "harness_sha256": sha256_of(Path(__file__)),
            "services_sha256": sha256_of(ROOT / "src" / "dib" / "registry" / "services.py"),
            "baseline_sha256": sha256_of(ROOT / "src" / "dib" / "registry" / "baseline_naive_reset.py"),
        },
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    db_path.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
