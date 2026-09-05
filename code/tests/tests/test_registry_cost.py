from __future__ import annotations

from datetime import datetime, timezone

from dib.core.models import Observation
from dib.experiments.registry_cost import registry_cost_rows, summarize_registry_cost


def obs(site: str, endpoint: str) -> Observation:
    return Observation(site, f"{site}-cam", "camera", endpoint, None, "https", 443,
                       datetime(2026, 1, 1, tzinfo=timezone.utc), "unit_fixture", "flow")


def test_registry_cost_uses_real_profile_updates_and_summarizes(tmp_path) -> None:
    observations = [obs(site, endpoint) for site in ("a", "b", "c") for endpoint in ("api.example", f"{site}.example")]
    rows = registry_cost_rows(observations, "camera", tmp_path / "registry.db", query_repeats=3)
    operations = {row["operation"] for row in rows}
    assert operations == {"existing_site_new_endpoint", "new_site_profile", "global_profile_query", "profile_export_serialization"}
    assert all(int(row["version_snapshot_bytes"]) > 0 for row in rows)
    assert all(float(row["latency_ms"]) >= 0 for row in rows)
    summary = summarize_registry_cost(rows)
    assert {row["operation"] for row in summary} == operations
    assert all(int(row["sample_count"]) >= 1 for row in summary)
