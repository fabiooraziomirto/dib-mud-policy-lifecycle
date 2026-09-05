from __future__ import annotations

import csv
from pathlib import Path

from dib.adapters.unsw_iotraffic import extract_tls_sni, iter_flow_observations


def test_extract_tls_sni_from_client_hello_extensions() -> None:
    extensions = "0000001f001d00001a736f667477617265757064617465732e616d617a6f6e2e636f6d"
    assert extract_tls_sni(extensions) == "softwareupdates.amazon.com"


FLOW_COLUMNS = [
    "time", "srcMac", "dstMac", "ethType", "srcIp", "dstIp", "ipProto",
    "srcPort", "dstPort", "flowSeqNum", "srcNumPackets", "dstNumPackets",
    "srcPayloadSize", "dstPayloadSize", "srcAvgPayloadSize", "dstAvgPayloadSize",
    "srcMaxPayloadSize", "dstMaxPayloadSize", "srcStdDevPayloadSize",
    "dstStdDevPayloadSize", "flowDuration", "srcAvgInterarrivalTime",
    "dstAvgInterarrivalTime", "avgInterarrivalTime", "srcStdDevInterarrivalTime",
    "dstStdDevInterarrivalTime", "stdDevInterarrivalTime", "allMatchedProtocols",
    "protocol",
]


def _flow_row(**overrides: str) -> dict[str, str]:
    row = {column: "0" for column in FLOW_COLUMNS}
    row.update(
        {
            "time": "2016-09-30 19:32:08.06983",
            "srcIp": "192.168.1.10",
            "dstIp": "93.184.216.34",
            "ipProto": "6",
            "dstPort": "443",
            "protocol": "https",
        }
    )
    row.update(overrides)
    return row


def _write_flows_csv(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FLOW_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def test_iter_flow_observations_marks_response_observed_from_dst_num_packets(tmp_path: Path) -> None:
    flows_dir = tmp_path / "flows"
    flows_dir.mkdir()
    _write_flows_csv(
        flows_dir / "TestDevice_aabbccddeeff_flows.csv",
        [
            _flow_row(dstNumPackets="4"),
            _flow_row(dstPort="8080", dstNumPackets="0"),
        ],
    )
    observations = list(iter_flow_observations(flows_dir))
    by_port = {obs.port: obs for obs in observations}
    assert by_port[443].response_observed is True
    assert by_port[8080].response_observed is False


def test_iter_flow_observations_ignores_rows_where_device_is_not_the_source(tmp_path: Path) -> None:
    flows_dir = tmp_path / "flows"
    flows_dir.mkdir()
    _write_flows_csv(
        flows_dir / "TestDevice_aabbccddeeff_flows.csv",
        [
            _flow_row(dstNumPackets="4"),
            _flow_row(srcIp="93.184.216.34", dstIp="192.168.1.10", dstPort="9999"),
        ],
    )
    observations = list(iter_flow_observations(flows_dir))
    assert len(observations) == 1
    assert observations[0].port == 443
