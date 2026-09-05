from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json

from scripts.backfill_fqdn import FIELDNAMES, main as backfill_main
from dib.core.io import write_csv
from dib.core.models import Observation
from dib.evaluation.enrichment import backfill_fqdn, backfill_fqdn_windowed, build_ip_fqdn_index


def make_obs(
    remote_ip: str | None,
    fqdn: str | None,
    evidence_type: str = "flow",
    site_id: str = "site-a",
    timestamp: datetime = datetime(2026, 1, 1, tzinfo=timezone.utc),
) -> Observation:
    return Observation(
        site_id=site_id,
        device_id="dev1",
        device_type="camera",
        fqdn=fqdn,
        remote_ip=remote_ip,
        protocol="udp",
        port=123,
        timestamp=timestamp,
        source_dataset="unit_fixture",
        evidence_type=evidence_type,
    )


def test_build_ip_fqdn_index_only_uses_real_evidence() -> None:
    observations = [
        make_obs("1.1.1.1", "api.vendor.example", evidence_type="flow+tls_sni"),
        make_obs("2.2.2.2", None),
    ]
    index = build_ip_fqdn_index(observations)
    assert index == {"1.1.1.1": "api.vendor.example"}


def test_backfill_fqdn_fills_missing_hostname_from_other_rows() -> None:
    observations = [
        make_obs("1.1.1.1", "api.vendor.example", evidence_type="flow+tls_sni"),
        make_obs("1.1.1.1", None, evidence_type="flow"),
        make_obs("2.2.2.2", None, evidence_type="flow"),
    ]
    enriched = backfill_fqdn(observations)
    assert enriched[1].fqdn == "api.vendor.example"
    assert enriched[1].evidence_type == "flow+ip_backfill"
    assert enriched[2].fqdn is None


def test_backfill_fqdn_does_not_touch_rows_that_already_have_fqdn() -> None:
    observations = [make_obs("1.1.1.1", "already.example")]
    enriched = backfill_fqdn(observations)
    assert enriched[0].fqdn == "already.example"
    assert enriched[0].evidence_type == "flow"


def test_windowed_backfill_resolves_within_window() -> None:
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    observations = [
        make_obs("1.1.1.1", "api.vendor.example", "flow+tls_sni", timestamp=base),
        make_obs("1.1.1.1", None, "flow", timestamp=base + timedelta(hours=2)),
    ]
    enriched, report = backfill_fqdn_windowed(observations, window=timedelta(hours=24))
    assert enriched[1].fqdn == "api.vendor.example"
    assert enriched[1].evidence_type == "flow+ip_backfill_windowed:flow+tls_sni"
    assert report.resolved_within_window == 1
    assert report.total_ip_only == 1


def test_windowed_backfill_rejects_evidence_outside_window() -> None:
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    observations = [
        make_obs("1.1.1.1", "api.vendor.example", "flow+tls_sni", timestamp=base),
        make_obs("1.1.1.1", None, "flow", timestamp=base + timedelta(hours=48)),
    ]
    enriched, report = backfill_fqdn_windowed(observations, window=timedelta(hours=24))
    assert enriched[1].fqdn is None
    assert report.evidence_outside_window == 1
    assert report.resolved_within_window == 0


def test_windowed_backfill_is_site_scoped() -> None:
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    observations = [
        make_obs("1.1.1.1", "api.vendor.example", "flow+tls_sni", site_id="site-a", timestamp=base),
        make_obs("1.1.1.1", None, "flow", site_id="site-b", timestamp=base + timedelta(hours=1)),
    ]
    enriched, report = backfill_fqdn_windowed(observations, window=timedelta(hours=24))
    assert enriched[1].fqdn is None
    assert report.no_evidence_this_site == 1


def test_windowed_backfill_picks_nearest_in_time_among_multiple_names() -> None:
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    observations = [
        make_obs("1.1.1.1", "old-service.example", "flow+http_host", timestamp=base),
        make_obs("1.1.1.1", "new-service.example", "flow+tls_sni", timestamp=base + timedelta(hours=20)),
        make_obs("1.1.1.1", None, "flow", timestamp=base + timedelta(hours=19)),
    ]
    enriched, _report = backfill_fqdn_windowed(observations, window=timedelta(hours=24))
    assert enriched[2].fqdn == "new-service.example"


def test_windowed_backfill_never_uses_a_prior_backfilled_row_as_evidence() -> None:
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    observations = [
        # Already carries a backfilled (not directly observed) fqdn.
        make_obs(
            "1.1.1.1",
            "api.vendor.example",
            "flow+ip_backfill_windowed:flow+tls_sni",
            timestamp=base,
        ),
        make_obs("1.1.1.1", None, "flow", timestamp=base + timedelta(hours=1)),
    ]
    _enriched, report = backfill_fqdn_windowed(observations, window=timedelta(hours=24))
    assert report.resolved_within_window == 0
    assert report.no_evidence_any_site == 1


def test_backfill_command_writes_a_windowed_site_scoped_manifest(tmp_path) -> None:
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    observations = [
        make_obs("1.1.1.1", "same-site.example", "flow+http_host", site_id="site-a", timestamp=base),
        make_obs("1.1.1.1", None, "flow", site_id="site-a", timestamp=base + timedelta(hours=1)),
        make_obs("1.1.1.1", None, "flow", site_id="site-b", timestamp=base + timedelta(hours=1)),
        make_obs("1.1.1.1", None, "flow", site_id="site-a", timestamp=base + timedelta(hours=48)),
    ]
    source = tmp_path / "observations.csv"
    output = tmp_path / "observations_enriched.csv"
    report = tmp_path / "manifest.json"
    write_csv(source, (obs.to_dict() for obs in observations), FIELDNAMES)

    assert backfill_main([
        "--observations", str(source), "--output", str(output), "--report", str(report), "--window-hours", "24",
    ]) == 0

    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["pipeline"] == "site_scoped_time_windowed_fqdn_backfill"
    assert payload["window_hours"] == 24.0
    assert payload["resolved_within_window"] == 1
    assert payload["evidence_outside_window"] == 1
    assert payload["no_evidence_this_site"] == 1
    assert len(payload["input_sha256"]) == 64
    assert len(payload["output_sha256"]) == 64
