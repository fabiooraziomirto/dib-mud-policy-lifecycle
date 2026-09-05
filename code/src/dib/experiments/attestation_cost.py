from __future__ import annotations

import math
import os
import time
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from dib.core.models import Observation
from dib.evaluation.dib import DIBScorer, ScoringConfig
from dib.registry.db import Base
from dib.registry.services import attest_score, dispute_score, get_score, get_score_history, restore_score, upsert_score


def attestation_cost_rows(
    observations: list[Observation],
    target_device_type: str,
    scoring_config: ScoringConfig,
    database_path: Path,
    max_endpoints: int = 30,
) -> list[dict[str, object]]:
    """Benchmark real ATTEST/DISPUTE/REVOKE/RESTORE latency and blast radius on SQLite.

    Scores are the real DIBScorer output for target_device_type; nothing here is a
    synthetic score. Every accepted endpoint gets one real attest call, and a subset
    gets a full dispute -> confirming dispute (revoke) -> explicit restore cycle.
    Since Fase 2.3(d) (Opzione B), restore is a deliberate, separate action -- the
    confirming dispute only revokes, it no longer restores automatically -- so this
    benchmark now issues and times restore_score() as its own call, not folded into
    the confirming dispute's latency. Each cycle also records how many of the
    profile's other accepted endpoints changed status, to measure whether a
    dispute-and-restore cycle's blast radius stays scoped to the disputed endpoint.
    """
    device_observations = [obs for obs in observations if obs.device_type == target_device_type]
    if not device_observations:
        raise ValueError(f"no observations for device type {target_device_type!r}")
    scores = DIBScorer(scoring_config).score(device_observations)
    accepted = [score for score in scores if score.accepted][:max_endpoints]
    if len(accepted) < 2:
        raise ValueError("attestation cost experiment requires at least two accepted endpoints")

    database_path.parent.mkdir(parents=True, exist_ok=True)
    if database_path.exists():
        database_path.unlink()
    engine = create_engine(f"sqlite:///{database_path}")
    Base.metadata.create_all(engine)

    rows: list[dict[str, object]] = []
    with Session(engine) as session:
        stored_ids: list[int] = []
        for score in accepted:
            row = upsert_score(session, score.to_dict())
            session.commit()
            stored_ids.append(row.id)

        for index, score_id in enumerate(stored_ids):
            started = time.perf_counter_ns()
            attest_score(session, accepted[index].device_type, accepted[index].endpoint,
                         accepted[index].protocol, accepted[index].port, f"attesting-site-{index}")
            session.commit()
            latency = (time.perf_counter_ns() - started) / 1_000_000
            rows.append(_row("attest", index + 1, latency, 0, database_path))

        dispute_targets = list(enumerate(accepted))[: max(1, len(accepted) // 2)]
        for index, score in dispute_targets:
            siblings_before = _sibling_statuses(session, accepted, exclude_index=index)

            started = time.perf_counter_ns()
            dispute_score(session, score.device_type, score.endpoint, score.protocol, score.port, "disputing-site-a")
            session.commit()
            latency = (time.perf_counter_ns() - started) / 1_000_000
            rows.append(_row("dispute_first", index + 1, latency, 0, database_path))

            started = time.perf_counter_ns()
            dispute_score(session, score.device_type, score.endpoint, score.protocol, score.port, "disputing-site-b")
            session.commit()
            latency = (time.perf_counter_ns() - started) / 1_000_000
            rows.append(_row("dispute_confirm_revoke", index + 1, latency, 0, database_path))

            # Opzione B (Fase 2.3d): restore is a deliberate, separate action,
            # never an automatic consequence of the confirming dispute above.
            started = time.perf_counter_ns()
            restore_score(session, score.device_type, score.endpoint, score.protocol, score.port)
            session.commit()
            latency = (time.perf_counter_ns() - started) / 1_000_000
            siblings_after = _sibling_statuses(session, accepted, exclude_index=index)
            changed = sum(1 for key in siblings_before if siblings_before[key] != siblings_after[key])
            rows.append(_row("restore", index + 1, latency, changed, database_path))

        for index, score_id in enumerate(stored_ids[: min(10, len(stored_ids))]):
            started = time.perf_counter_ns()
            get_score_history(session, score_id)
            latency = (time.perf_counter_ns() - started) / 1_000_000
            rows.append(_row("history_query", index + 1, latency, 0, database_path))
    engine.dispose()
    return rows


def summarize_attestation_cost(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    summaries = []
    for operation in sorted({str(row["operation"]) for row in rows}):
        group = [row for row in rows if row["operation"] == operation]
        latencies = sorted(float(row["latency_ms"]) for row in group)
        summaries.append({
            "operation": operation,
            "sample_count": len(group),
            "mean_latency_ms": round(sum(latencies) / len(latencies), 6),
            "p50_latency_ms": round(_percentile(latencies, 0.50), 6),
            "p95_latency_ms": round(_percentile(latencies, 0.95), 6),
            "total_sibling_endpoints_changed": sum(int(row["sibling_endpoints_changed"]) for row in group),
            "final_registry_db_bytes": max(int(row["registry_db_bytes"]) for row in group),
        })
    return summaries


def _sibling_statuses(session: Session, accepted, exclude_index: int) -> dict[tuple, str]:
    statuses = {}
    for index, score in enumerate(accepted):
        if index == exclude_index:
            continue
        stored = get_score(session, score.device_type, score.endpoint, score.protocol, score.port)
        if stored is not None:
            statuses[score.endpoint_key] = stored.status
    return statuses


def _row(operation: str, sample_index: int, latency: float, sibling_endpoints_changed: int, path: Path) -> dict[str, object]:
    return {
        "operation": operation,
        "sample_index": sample_index,
        "latency_ms": round(latency, 6),
        "sibling_endpoints_changed": sibling_endpoints_changed,
        "registry_db_bytes": os.path.getsize(path),
    }


def _percentile(values: list[float], fraction: float) -> float:
    return values[min(len(values) - 1, max(0, math.ceil(fraction * len(values)) - 1))]
