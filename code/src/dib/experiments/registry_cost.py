from __future__ import annotations

import json
import math
import os
import time
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from dib.core.models import Observation
from dib.evaluation.local_profiling import build_all_local_profiles
from dib.registry.db import Base
from dib.registry.services import global_profile, upsert_profile


def registry_cost_rows(
    observations: list[Observation],
    target_device_type: str,
    database_path: Path,
    query_repeats: int = 30,
) -> list[dict[str, object]]:
    """Benchmark real incremental profile mutations and reads on SQLite.

    One genuine site is held out for onboarding; one real endpoint from every
    other site's profile is held out for an incremental endpoint update.
    Snapshot bytes are a deterministic normalized JSON version size, because the
    current registry schema does not persist historical versions itself.
    """
    profiles = [
        profile for profile in build_all_local_profiles(o for o in observations if o.device_type == target_device_type)
        if profile.endpoints
    ]
    if len(profiles) < 2:
        raise ValueError("registry cost experiment requires at least two non-empty site profiles")
    database_path.parent.mkdir(parents=True, exist_ok=True)
    if database_path.exists():
        database_path.unlink()
    engine = create_engine(f"sqlite:///{database_path}")
    Base.metadata.create_all(engine)
    rows: list[dict[str, object]] = []
    with Session(engine) as session:
        existing, onboarding = profiles[:-1], profiles[-1]
        held_out = []
        for profile in existing:
            endpoints = [endpoint.to_dict() for endpoint in profile.endpoints]
            held_out.append((profile.site_id, endpoints[-1]))
            upsert_profile(session, profile.site_id, target_device_type, endpoints[:-1])
        session.commit()

        version = 0
        for site_id, endpoint in held_out:
            started = time.perf_counter_ns()
            upsert_profile(session, site_id, target_device_type, [endpoint])
            session.commit()
            latency = (time.perf_counter_ns() - started) / 1_000_000
            version += 1
            snapshot = global_profile(session, target_device_type)
            rows.append(_row("existing_site_new_endpoint", version, site_id, 1, latency, snapshot, database_path))

        onboarding_payload = [endpoint.to_dict() for endpoint in onboarding.endpoints]
        started = time.perf_counter_ns()
        upsert_profile(session, onboarding.site_id, target_device_type, onboarding_payload)
        session.commit()
        latency = (time.perf_counter_ns() - started) / 1_000_000
        version += 1
        snapshot = global_profile(session, target_device_type)
        rows.append(_row("new_site_profile", version, onboarding.site_id, len(onboarding_payload), latency, snapshot, database_path))

        for index in range(query_repeats):
            started = time.perf_counter_ns()
            snapshot = global_profile(session, target_device_type)
            latency = (time.perf_counter_ns() - started) / 1_000_000
            rows.append(_row("global_profile_query", index + 1, "", len(snapshot["endpoints"]), latency, snapshot, database_path))

        snapshot = global_profile(session, target_device_type)
        for index in range(query_repeats):
            started = time.perf_counter_ns()
            payload = _snapshot_bytes(snapshot)
            latency = (time.perf_counter_ns() - started) / 1_000_000
            rows.append({
                **_row("profile_export_serialization", index + 1, "", len(snapshot["endpoints"]), latency, snapshot, database_path),
                "version_snapshot_bytes": len(payload),
            })
    engine.dispose()
    return rows


def summarize_registry_cost(rows: list[dict[str, object]]) -> list[dict[str, object]]:
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
            "mean_payload_endpoint_count": round(sum(int(r["payload_endpoint_count"]) for r in group) / len(group), 6),
            "mean_version_snapshot_bytes": round(sum(int(r["version_snapshot_bytes"]) for r in group) / len(group), 6),
            "final_registry_db_bytes": max(int(r["registry_db_bytes"]) for r in group),
        })
    return summaries


def _row(operation: str, sample_index: int, site_id: str, payload_count: int, latency: float, snapshot: dict, path: Path) -> dict[str, object]:
    return {
        "operation": operation,
        "sample_index": sample_index,
        "site_id": site_id,
        "payload_endpoint_count": payload_count,
        "latency_ms": round(latency, 6),
        "version_snapshot_bytes": len(_snapshot_bytes(snapshot)),
        "registry_db_bytes": os.path.getsize(path),
    }


def _snapshot_bytes(snapshot: dict) -> bytes:
    return json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _percentile(values: list[float], fraction: float) -> float:
    return values[min(len(values) - 1, max(0, math.ceil(fraction * len(values)) - 1))]
