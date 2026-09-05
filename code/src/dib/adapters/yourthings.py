"""Adapter for the YourThings testbed (Alrawi et al., 2019).

Unlike Mon(IoT)r, YourThings captures are whole-network PCAPs (every device in one
trace) whose member files carry no ``.pcap`` extension, and device identity comes
from a static IP -> device-name mapping rather than the filename. The low-level
PCAP/DNS parsing is reused from :mod:`dib.adapters.moniotr` so only the
source iteration and device attribution differ.
"""

from __future__ import annotations

import csv
import ipaddress
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from dib.adapters.moniotr import _dns_answers, _dns_query, _iter_pcap_packets
from dib.core.io import _is_ip_literal_name
from dib.core.models import Observation
from dib.evaluation.profiles import canonical_device_name

# YourThings device labels that do not round-trip through canonical_device_name's
# alias table but do overlap UNSW ground truth; mapped explicitly so the transfer
# evaluation lands on the right reference profile.
YOURTHINGS_CANONICAL = {
    "amazonechogen1": "amazon-echo",
    "philipshuehub": "philips-hue",
    "samsungsmartthingshub": "smartthings",
    "lifxvirtualbulb": "lifx-bulb",
    "belkinnetcam": "belkin-camera",
    "belkinwemomotionsensor": "wemo-motion",
    "belkinwemoswitch": "wemo-switch",
    "ringdoorbell": "ring-doorbell",
}


def canonical_yourthings_device(name: str) -> str:
    key = name.lower().replace("-", "").replace("_", "")
    if key in YOURTHINGS_CANONICAL:
        return YOURTHINGS_CANONICAL[key]
    return canonical_device_name(name)


def load_device_mapping(path: Path) -> dict[str, str]:
    """IP -> device label. The released file is headerless ``Name,IP`` rows."""
    mapping: dict[str, str] = {}
    with path.open(newline="", encoding="utf-8", errors="replace") as handle:
        for row in csv.reader(handle):
            if len(row) < 2:
                continue
            name, ip = row[0].strip(), row[1].strip()
            if not name or not ip:
                continue
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue  # skip a stray header line if present
            mapping[ip] = name
    return mapping


def iter_yourthings_observations(
    archive_path: Path,
    device_mapping: dict[str, str],
    site_id: str,
    max_pcap_files: int | None = None,
    exclude_non_global_ips: bool = True,
) -> Iterator[Observation]:
    """Stream Observations for known devices' external endpoints from a YourThings
    capture archive. ``max_pcap_files`` bounds the parse for a quick subset.
    """
    pcap_count = 0
    with tarfile.open(archive_path, mode="r:*") as archive:
        for member in archive:
            if not member.isfile():
                continue
            if max_pcap_files is not None and pcap_count >= max_pcap_files:
                break
            handle = archive.extractfile(member)
            if handle is None:
                continue
            pcap_count += 1
            ip_to_name: dict[str, str] = {}
            seen: set[tuple[str, str, str, int, int]] = set()
            seen_second: int | None = None
            try:
                for packet in _iter_pcap_packets(handle):
                    if packet["protocol"] == "udp" and packet["src_port"] == 53:
                        ip_to_name.update(_dns_answers(packet["payload"]))
                    src_ip = str(packet["src_ip"])
                    device_label = device_mapping.get(src_ip)
                    if device_label is None:
                        continue
                    dst_ip = str(packet["dst_ip"])
                    port = int(packet["dst_port"])
                    if port == 0:
                        continue
                    fqdn = None
                    evidence = "flow"
                    if packet["protocol"] == "udp" and port == 53:
                        fqdn = _dns_query(packet["payload"])
                        evidence = "dns_query" if fqdn else "flow"
                    elif dst_ip in ip_to_name:
                        fqdn = ip_to_name[dst_ip]
                        evidence = "flow+dns_answer"
                    if exclude_non_global_ips and _is_ip_literal_name(fqdn):
                        try:
                            if not ipaddress.ip_address(dst_ip).is_global:
                                continue
                        except ValueError:
                            continue
                    packet_second = int(packet["timestamp"])
                    if seen_second != packet_second:
                        seen.clear()
                        seen_second = packet_second
                    key = (src_ip, dst_ip, packet["protocol"], port, packet_second)
                    if key in seen:
                        continue
                    seen.add(key)
                    yield Observation(
                        site_id=site_id,
                        device_id=src_ip,
                        device_type=canonical_yourthings_device(device_label),
                        fqdn=fqdn,
                        remote_ip=dst_ip,
                        protocol=packet["protocol"],
                        port=port,
                        timestamp=datetime.fromtimestamp(float(packet["timestamp"]), tz=timezone.utc),
                        source_dataset="yourthings",
                        evidence_type=evidence,
                    )
            except (OSError, ValueError) as exc:  # tolerate a truncated member, keep streaming
                _ = exc
                continue
