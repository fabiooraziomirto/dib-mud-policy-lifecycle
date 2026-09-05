from __future__ import annotations

from datetime import date
import csv
import json

from scripts.moniotr_cross_lab import (
    Aggregate,
    collapse_site_three,
    leave_one_out,
    leave_one_out_generalized,
    load,
    load_label_mapping,
    main,
    workload_distribution,
)


def test_workload_distribution_uses_shared_devices_and_documented_quantiles() -> None:
    values = [0, 0, 0, 0, 0, 0, 0, 1, 4, 4, 5, 7, 8,
              9, 10, 11, 11, 21, 28, 30, 33, 36, 51, 56, 57, 80]
    rows = [
        {
            "site_id": site,
            "device_type": f"device-{index:02d}",
            "method": "dib",
            "monitor_only_queue": value,
            "window": "full-capture",
        }
        for site in ("US", "UK")
        for index, value in enumerate(values)
    ]
    rows.append({
        "site_id": "US",
        "device_type": "us-only-device",
        "method": "dib",
        "monitor_only_queue": 999,
        "window": "full-capture",
    })

    summaries = workload_distribution(rows)

    assert len(summaries) == 2
    for summary in summaries:
        assert summary["device_count"] == 26
        assert summary["queue_total"] == 462
        assert summary["mean"] == 462 / 26
        assert summary["median"] == 8.5
        assert summary["q1"] == 0.0
        assert summary["q3"] == 30.0
        assert summary["p95_nearest_rank"] == 57
        assert summary["maximum"] == 80


def test_leave_one_out_excludes_receiver_and_reports_quorum_boundary() -> None:
    data = Aggregate()
    key = ("camera", "api.vendor.example", "tcp", 443)
    for site in ("US", "UK"):
        data.endpoints[key].add(site)
        data.endpoint_days[key].add(date(2026, 1, 1))
        data.site_endpoint_days[(site, key)].add(date(2026, 1, 1))
        data.site_endpoint_counts[(site, key)] = 1
        data.site_endpoint_date_counts[(site, key, date(2026, 1, 1))] = 1
        data.device_sites["camera"].add(site)
        data.device_days["camera"].add(date(2026, 1, 1))
        data.site_device_days[(site, "camera")].add(date(2026, 1, 1))
        data.site_device_counts[(site, "camera")] = 1
        data.site_device_date_counts[(site, "camera", date(2026, 1, 1))] = 1
        data.profiles[site]["camera"].add(key)

    rows = leave_one_out(data)

    assert len(rows) == 2
    for row in rows:
        assert row["independent_source_deployments"] == 1
        assert row["min_reporting_sites"] == 2
        assert row["admitted_candidates"] == 0
        assert row["target_device_coverage"] == 0.0
        assert row["receiver_excluded_from_scoring"] is True
        assert row["metric_status"] == "not_applicable_no_admitted_candidates"


def test_cross_lab_command_writes_leave_one_out_artifact_and_manifest(tmp_path) -> None:
    source = tmp_path / "moniotr.csv"
    with source.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "site_id", "device_type", "fqdn", "remote_ip", "protocol", "port", "timestamp",
        ])
        writer.writeheader()
        writer.writerows([
            {"site_id": site, "device_type": device, "fqdn": f"{device}.vendor.example", "remote_ip": "1.1.1.1", "protocol": "tcp", "port": 443, "timestamp": "2026-01-01T00:00:00+00:00"}
            for device in ("camera", "speaker", "plug", "sensor")
            for site in ("moniotr-us", "moniotr-uk")
        ])
    output = tmp_path / "result"

    assert main(["--observations", str(source), "--output-dir", str(output)]) == 0

    with (output / "leave_one_out.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert [row["admitted_candidates"] for row in rows] == ["0", "0"]
    assert {row["metric_status"] for row in rows} == {"not_applicable_no_admitted_candidates"}
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["leave_one_out"]["receiver_excluded_from"] == [
        "reporters", "eligible_population", "breadth_denominator", "temporal_days", "temporal_counts",
    ]


def test_collapse_site_three_adds_yourthings_without_changing_us_uk() -> None:
    assert collapse_site_three("moniotr-us") == "US"
    assert collapse_site_three("moniotr-uk-vpn") == "UK"
    assert collapse_site_three("yourthings-gatech-20180321") == "YT"
    assert collapse_site_three("some-other-site") is None


def test_load_label_mapping_covers_both_source_columns(tmp_path) -> None:
    mapping_path = tmp_path / "label_mapping.csv"
    mapping_path.write_text(
        "canonical,yourthings_label,moniotr_label,note\n"
        "camera,camera-yt,camera,exact after alias\n",
        encoding="utf-8",
    )
    mapping = load_label_mapping(mapping_path)
    assert mapping == {"camera-yt": "camera", "camera": "camera"}


def _write_moniotr_uk_us_yt_fixture(tmp_path):
    """A hand-computable three-lab fixture: 'camera' is reported by all three
    organizations with the identical endpoint fact (so any two-source quorum
    admits it); 'widget' is reported only by US and UK, so it never survives
    the three-way device-type intersection required for a target device
    (it is absent from YT's own profile, and absent as a *source* pair
    whenever YT is one of the two sources)."""
    moniotr_path = tmp_path / "moniotr.csv"
    with moniotr_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "site_id", "device_type", "fqdn", "remote_ip", "protocol", "port", "timestamp",
        ])
        writer.writeheader()
        writer.writerows([
            {"site_id": site, "device_type": device, "fqdn": f"{device}.example", "remote_ip": "", "protocol": "tcp", "port": 443, "timestamp": "2026-01-01T00:00:00+00:00"}
            for device in ("camera", "widget")
            for site in ("moniotr-us", "moniotr-uk")
        ])

    yourthings_path = tmp_path / "yourthings.csv"
    with yourthings_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "site_id", "device_type", "fqdn", "remote_ip", "protocol", "port", "timestamp",
        ])
        writer.writeheader()
        writer.writerow({
            "site_id": "yourthings-gatech-20180321", "device_type": "camera-yt",
            "fqdn": "camera.example", "remote_ip": "", "protocol": "tcp", "port": 443,
            "timestamp": "2026-01-01T00:00:00+00:00",
        })

    mapping_path = tmp_path / "label_mapping.csv"
    mapping_path.write_text(
        "canonical,yourthings_label,moniotr_label,note\n"
        "camera,camera-yt,camera,exact after alias\n",
        encoding="utf-8",
    )
    return moniotr_path, yourthings_path, mapping_path


def test_leave_one_out_generalized_three_labs_is_non_trivial(tmp_path) -> None:
    moniotr_path, yourthings_path, mapping_path = _write_moniotr_uk_us_yt_fixture(tmp_path)
    mapping = load_label_mapping(mapping_path)
    data = load(moniotr_path, extra_paths=[yourthings_path], collapse_fn=collapse_site_three, label_map=mapping)

    rows = leave_one_out_generalized(data, ("US", "UK", "YT"))

    assert len(rows) == 3
    by_receiver = {row["receiving_deployment"]: row for row in rows}
    assert set(by_receiver) == {"US", "UK", "YT"}
    for receiver, row in by_receiver.items():
        # Unlike the two-lab case (leave_one_out(), always exactly one source
        # left), every receiver here keeps two independent sources -- the
        # quorum m=2 is therefore satisfiable, not guaranteed to fail.
        assert row["independent_source_deployments"] == 2
        assert row["target_device_types"] == 1  # only "camera" survives the three-way intersection
        assert row["admitted_candidates"] == 1
        assert row["target_device_coverage"] == 1.0
        assert row["precision_macro"] == 1.0
        assert row["recall_macro"] == 1.0
        assert row["f1_macro"] == 1.0
        assert row["metric_status"] == "defined"
        assert row["receiver_excluded_from_scoring"] is True


def test_main_writes_three_lab_artifact_when_yourthings_flag_given(tmp_path) -> None:
    moniotr_path, yourthings_path, mapping_path = _write_moniotr_uk_us_yt_fixture(tmp_path)
    output = tmp_path / "result"

    exit_code = main([
        "--observations", str(moniotr_path),
        "--output-dir", str(output),
        "--yourthings-observations", str(yourthings_path),
        "--label-mapping", str(mapping_path),
    ])
    assert exit_code == 0

    # Two-lab outputs are unaffected by the optional flags.
    with (output / "leave_one_out.csv").open(newline="", encoding="utf-8") as handle:
        two_lab_rows = list(csv.DictReader(handle))
    assert [row["admitted_candidates"] for row in two_lab_rows] == ["0", "0"]

    with (output / "leave_one_out_three_lab.csv").open(newline="", encoding="utf-8") as handle:
        three_lab_rows = list(csv.DictReader(handle))
    assert len(three_lab_rows) == 3
    assert {row["admitted_candidates"] for row in three_lab_rows} == {"1"}
    assert {row["independent_source_deployments"] for row in three_lab_rows} == {"2"}

    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["leave_one_out_three_lab"]["sites"] == ["US", "UK", "YT"]
    assert manifest["leave_one_out_three_lab"]["aligned_device_types"] == ["camera"]


def test_main_omits_three_lab_artifact_without_yourthings_flag(tmp_path) -> None:
    moniotr_path, _, _ = _write_moniotr_uk_us_yt_fixture(tmp_path)
    output = tmp_path / "result"

    assert main(["--observations", str(moniotr_path), "--output-dir", str(output)]) == 0

    assert not (output / "leave_one_out_three_lab.csv").exists()
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert "leave_one_out_three_lab" not in manifest
