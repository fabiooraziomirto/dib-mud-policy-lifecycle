from __future__ import annotations

from datetime import datetime, timedelta, timezone

from dib.core.models import Observation
from dib.evaluation.dib import ScoringConfig
from dib.experiments.attestation_cost import attestation_cost_rows, summarize_attestation_cost


def obs(site: str, endpoint: str, day: int) -> Observation:
    timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(days=day)
    return Observation(site, f"{site}-cam", "camera", endpoint, None, "https", 443, timestamp, "unit_fixture", "flow")


def _observations() -> list[Observation]:
    sites = ("a", "b", "c", "d")
    endpoints = ("api.example", "cdn.example", "telemetry.example")
    rows = []
    for site in sites:
        for endpoint in endpoints:
            for day in range(5):
                rows.append(obs(site, endpoint, day))
    return rows


def test_attestation_cost_measures_real_attest_dispute_revoke_cycle(tmp_path) -> None:
    rows = attestation_cost_rows(
        _observations(), "camera", ScoringConfig(theta=0.3), tmp_path / "attestation.db", max_endpoints=10,
    )
    operations = {row["operation"] for row in rows}
    # Fase 2.3(d), Opzione B: the confirming dispute only revokes; restore is
    # its own explicit call/row, no longer folded into the dispute latency.
    assert operations == {"attest", "dispute_first", "dispute_confirm_revoke", "restore", "history_query"}
    assert all(float(row["latency_ms"]) >= 0 for row in rows)

    restore_rows = [row for row in rows if row["operation"] == "restore"]
    assert restore_rows
    # Disputes and restores are scoped to the disputed endpoint; the rest of the profile is untouched.
    assert all(int(row["sibling_endpoints_changed"]) == 0 for row in restore_rows)

    summary = summarize_attestation_cost(rows)
    assert {row["operation"] for row in summary} == operations
    restore_summary = next(row for row in summary if row["operation"] == "restore")
    assert restore_summary["total_sibling_endpoints_changed"] == 0


def test_attestation_cost_requires_at_least_two_accepted_endpoints(tmp_path) -> None:
    single = [obs("a", "only.example", day) for day in range(3)]
    try:
        attestation_cost_rows(single, "camera", ScoringConfig(theta=0.3), tmp_path / "attestation.db")
        raised = False
    except ValueError:
        raised = True
    assert raised
