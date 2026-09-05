"""Adapter for the UNSW IoT Attack Dataset
(https://iotanalytics.unsw.edu.au/attack-data.html): real, captured attack
traffic against a subset of the same device types already profiled from
UNSW-IoTraffic 2025 (data/unsw/labels.json).

Used to measure A1 ("poisoned local baseline": a device is already
compromised during a site's local learning window) -- the one adversary in
the paper's threat model with no dedicated experiment. See
dib.experiments.compromised_baseline for the injection driver built on top
of this adapter.

Scope: of the 10 devices in ``attackinfo.xlsx``, only 5 have a per-packet
``<mac>-packet-anomaly.log`` (real captured attacker IP/port/protocol per
packet, during a documented attack window). The other 5 have only coarse
attack-window annotations plus 1-minute aggregate flow counters, not
per-packet attacker endpoints, and are out of scope for this adapter
(explicit project decision, not an oversight -- see conversation record).
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

# ip_proto -> DIB protocol label, matching dib.adapters.unsw_iotraffic.IP_PROTO.
_IP_PROTO = {"1": "icmp", "6": "tcp", "17": "udp"}

# MAC -> (raw device_type string as it appears in
# data/processed/observations_enriched.csv -- NOT the hyphenated
# data/unsw/labels.json key; dib.evaluation.profiles.canonical_device_name
# maps this raw string to the labels.json key for ground-truth comparison,
# but DIBScorer/partition_observations key on the raw string directly, so
# this table must match the CSV exactly. Verified against both
# attackinfo.xlsx's "Attacks" sheet (MAC -> IP -> device type) and the
# distinct device_type values actually present in the enriched CSV.
MAC_TO_DEVICE = {
    "00166cab6b88": ("SamsungCamera", "192.168.1.248"),
    "50c7bf005639": ("TPLinkSmartPlug", "192.168.1.227"),
    "70ee50183443": ("NetatmoWelcome", "192.168.1.241"),
    "ec1a5979f489": ("BelkinWemoSwitch", "192.168.1.223"),
    "ec1a59832811": ("BelkinWemoMotionSensor", "192.168.1.165"),
}


@dataclass(frozen=True, slots=True)
class MaliciousEndpoint:
    """One real, captured, device-initiated packet to an attacker-controlled
    remote endpoint during a documented UNSW attack window."""

    device_type: str
    remote_ip: str
    protocol: str
    port: int
    timestamp: datetime
    attack_label: str


def iter_malicious_endpoints(annotations_dir: Path) -> Iterable[MaliciousEndpoint]:
    """Real attacker endpoints from ``<mac>-packet-anomaly.log`` files.

    Each row is a real captured packet:
    ``timestamp_ms,src_mac,dst_mac,ethertype,src_ip,dst_ip,ip_proto,
    src_port,dst_port,length``. Only rows where the device itself is the
    source are kept, mirroring dib.adapters.unsw_iotraffic's own convention
    (remote endpoint = the other side of a device-initiated flow): this is
    the malicious endpoint a compromised device's own outbound traffic would
    expose to a local learner, not traffic aimed at the device from outside.
    """
    for mac, (device_type, device_ip) in sorted(MAC_TO_DEVICE.items()):
        log_path = annotations_dir / f"{mac}-packet-anomaly.log"
        if not log_path.exists():
            continue
        with log_path.open(newline="", encoding="utf-8") as handle:
            for row in csv.reader(handle):
                if len(row) < 9:
                    continue
                ts_ms, _src_mac, _dst_mac, _ethertype, src_ip, dst_ip, ip_proto, _src_port, dst_port = row[:9]
                if src_ip != device_ip:
                    continue
                protocol = _IP_PROTO.get(ip_proto)
                if protocol is None:
                    continue
                yield MaliciousEndpoint(
                    device_type=device_type,
                    remote_ip=dst_ip,
                    protocol=protocol,
                    port=int(dst_port),
                    timestamp=datetime.fromtimestamp(int(ts_ms) / 1000.0, tz=timezone.utc),
                    attack_label=mac,
                )


def load_malicious_endpoints(annotations_dir: Path) -> list[MaliciousEndpoint]:
    return list(iter_malicious_endpoints(annotations_dir))
