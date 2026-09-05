from __future__ import annotations

import json
from pathlib import Path

from dib.adapters.loader import MUDProfileLoader, UNSWIoTrafficLoader, generate_dataset_report


def test_unsw_loader_flags_missing_flows_dir(tmp_path: Path) -> None:
    loader = UNSWIoTrafficLoader(tmp_path / "missing_flows", tmp_path / "missing_protocols")
    issues = loader.validate_dataset()
    assert any("flows directory missing" in issue.reason for issue in issues)


def test_unsw_loader_inventory_counts_flow_files(tmp_path: Path) -> None:
    flows_dir = tmp_path / "flows"
    flows_dir.mkdir()
    (flows_dir / "camera_dev1_flows.csv").write_text("srcIp,dstIp,dstPort,time\n1.1.1.1,2.2.2.2,443,2026-01-01T00:00:00\n")
    loader = UNSWIoTrafficLoader(flows_dir, tmp_path / "protocols")
    entry = loader.inventory()
    assert entry.file_count == 1
    assert entry.record_count == 1


def test_mud_profile_loader_flags_malformed_json(tmp_path: Path) -> None:
    profiles_dir = tmp_path / "profiles"
    profiles_dir.mkdir()
    (profiles_dir / "broken.json").write_text("not json")
    loader = MUDProfileLoader(profiles_dir)
    issues = loader.validate_dataset()
    assert any("malformed profile" in issue.reason for issue in issues)


def test_generate_dataset_report_combines_loaders(tmp_path: Path) -> None:
    flows_dir = tmp_path / "flows"
    flows_dir.mkdir()
    (flows_dir / "camera_dev1_flows.csv").write_text("srcIp,dstIp,dstPort,time\n1.1.1.1,2.2.2.2,443,2026-01-01T00:00:00\n")
    profiles_dir = tmp_path / "profiles"
    profiles_dir.mkdir()
    (profiles_dir / "camera.json").write_text(json.dumps({"rules": []}))

    loaders = [
        UNSWIoTrafficLoader(flows_dir, tmp_path / "protocols"),
        MUDProfileLoader(profiles_dir),
    ]
    summary_rows, inventory_payload = generate_dataset_report(loaders)
    assert len(summary_rows) == 2
    assert inventory_payload["datasets"][0]["dataset"] == "unsw_iotraffic_2025"
