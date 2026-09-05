from __future__ import annotations

import csv
import ipaddress
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from dib.core.models import Observation


IP_PROTO = {
    "1": "icmp",
    "2": "igmp",
    "6": "tcp",
    "17": "udp",
}


def iter_flow_observations(
    flows_dir: Path,
    protocols_dir: Path | None = None,
    site_id: str = "unsw-iotraffic-2025",
    max_rows_per_file: int | None = None,
) -> Iterable[Observation]:
    """Normalize UNSW IoTraffic flow CSVs into endpoint observations."""

    fqdn_index = build_fqdn_index(protocols_dir, max_rows_per_file=max_rows_per_file) if protocols_dir else {}
    for path in sorted(flows_dir.glob("*_flows.csv")):
        device_type, device_id = parse_flow_filename(path)
        device_ip = infer_device_ip(path, max_rows=max_rows_per_file)
        if device_ip is None:
            continue
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for index, row in enumerate(reader):
                if max_rows_per_file is not None and index >= max_rows_per_file:
                    break
                if row.get("srcIp") != device_ip:
                    continue
                remote_ip = clean_ip(row.get("dstIp", ""))
                if remote_ip is None:
                    continue
                port = parse_port(row.get("dstPort", ""))
                fqdn, fqdn_evidence = fqdn_index.get((device_id, remote_ip, port), (None, None))
                yield Observation(
                    site_id=site_id,
                    device_id=device_id,
                    device_type=device_type,
                    fqdn=fqdn,
                    remote_ip=remote_ip,
                    protocol=normalize_protocol(row.get("protocol", ""), row.get("ipProto", "")),
                    port=port,
                    timestamp=parse_unsw_timestamp(row["time"]),
                    source_dataset="unsw_iotraffic_2025",
                    evidence_type=f"flow+{fqdn_evidence}" if fqdn_evidence else "flow",
                    response_observed=parse_count(row.get("dstNumPackets", "")) > 0,
                    # Derived directly from the flow, not assumed: the srcIp==device_ip
                    # filter above already selected only device-initiated flows.
                    direction="out",
                )


def parse_flow_filename(path: Path) -> tuple[str, str]:
    stem = path.name.removesuffix("_flows.csv")
    if "_" not in stem:
        return stem, stem
    device_type, device_id = stem.rsplit("_", 1)
    return device_type, device_id


def infer_device_ip(path: Path, max_rows: int | None = None) -> str | None:
    counts: Counter[str] = Counter()
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for index, row in enumerate(reader):
            if max_rows is not None and index >= max_rows:
                break
            for column in ("srcIp", "dstIp"):
                ip = clean_ip(row.get(column, ""))
                if ip is not None and is_candidate_device_ip(ip):
                    counts[ip] += 1
    if not counts:
        return None
    return counts.most_common(1)[0][0]


def build_fqdn_index(
    protocols_dir: Path | None,
    max_rows_per_file: int | None = None,
) -> dict[tuple[str, str, int], tuple[str, str]]:
    if protocols_dir is None or not protocols_dir.exists():
        return {}
    index: dict[tuple[str, str, int], tuple[str, str]] = {}
    parameters_dir = protocols_dir / "parameters"
    if not parameters_dir.exists():
        parameters_dir = protocols_dir
    for device_dir in sorted(path for path in parameters_dir.iterdir() if path.is_dir()):
        _, device_id = parse_parameter_dirname(device_dir.name)
        request_dir = device_dir / "request"
        if not request_dir.exists():
            continue
        load_http_hosts(request_dir / "httpattributes.csv", device_id, index, max_rows_per_file)
        load_tls_sni(request_dir / "tlsattributes.csv", device_id, index, max_rows_per_file)
    return index


def parse_parameter_dirname(value: str) -> tuple[str, str]:
    if "_" not in value:
        return value, value
    device_type, device_id = value.rsplit("_", 1)
    return device_type, device_id


def load_http_hosts(
    path: Path,
    device_id: str,
    index: dict[tuple[str, str, int], tuple[str, str]],
    max_rows: int | None,
) -> None:
    if not path.exists():
        return
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row_index, row in enumerate(reader):
            if max_rows is not None and row_index >= max_rows:
                break
            host = clean_hostname(row.get("host", ""))
            remote_ip = clean_ip(row.get("dstIp", ""))
            port = parse_port(row.get("dstPort", ""))
            if host and remote_ip:
                index[(device_id, remote_ip, port)] = (host, "http_host")


def load_tls_sni(
    path: Path,
    device_id: str,
    index: dict[tuple[str, str, int], tuple[str, str]],
    max_rows: int | None,
) -> None:
    if not path.exists():
        return
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row_index, row in enumerate(reader):
            if max_rows is not None and row_index >= max_rows:
                break
            sni = extract_tls_sni(row.get("client-hello-extensions", ""))
            remote_ip = clean_ip(row.get("dstIp", ""))
            port = parse_port(row.get("dstPort", ""))
            if sni and remote_ip:
                index.setdefault((device_id, remote_ip, port), (sni, "tls_sni"))


def extract_tls_sni(extensions_hex: str) -> str | None:
    try:
        payload = bytes.fromhex(extensions_hex.strip())
    except ValueError:
        return None
    offset = 0
    while offset + 4 <= len(payload):
        extension_type = int.from_bytes(payload[offset : offset + 2], "big")
        extension_length = int.from_bytes(payload[offset + 2 : offset + 4], "big")
        offset += 4
        extension_data = payload[offset : offset + extension_length]
        offset += extension_length
        if extension_type != 0:
            continue
        hostname = parse_sni_extension(extension_data)
        if hostname:
            return hostname
    return None


def parse_sni_extension(data: bytes) -> str | None:
    if len(data) < 5:
        return None
    list_length = int.from_bytes(data[0:2], "big")
    offset = 2
    end = min(len(data), offset + list_length)
    while offset + 3 <= end:
        name_type = data[offset]
        name_length = int.from_bytes(data[offset + 1 : offset + 3], "big")
        offset += 3
        name = data[offset : offset + name_length]
        offset += name_length
        if name_type == 0:
            return clean_hostname(name.decode("ascii", errors="ignore"))
    return None


def clean_ip(value: str) -> str | None:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if ip.is_unspecified or ip.is_multicast or ip.is_loopback:
        return None
    if ip.version == 4 and str(ip) == "255.255.255.255":
        return None
    return str(ip)


def clean_hostname(value: str | None) -> str | None:
    if value is None:
        return None
    hostname = value.strip().strip(".").lower()
    if not hostname or hostname == "null":
        return None
    if "/" in hostname or " " in hostname:
        return None
    return hostname


def is_candidate_device_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    return ip.is_private and not ip.is_link_local


def normalize_protocol(protocol: str, ip_proto: str) -> str:
    cleaned = protocol.strip().lower()
    if cleaned and cleaned != "none":
        return cleaned
    return IP_PROTO.get(ip_proto.strip(), f"ip-{ip_proto.strip() or 'unknown'}")


def parse_port(value: str) -> int:
    try:
        return int(value)
    except ValueError:
        return 0


def parse_count(value: str) -> int:
    try:
        return int(float(value))
    except ValueError:
        return 0


_UNSW_TIMESTAMP_FRACTION_RE = re.compile(r"\.(\d+)")


def parse_unsw_timestamp(value: str) -> datetime:
    stripped = value.strip()

    def _pad_fraction(match: "re.Match[str]") -> str:
        return "." + match.group(1).ljust(6, "0")[:6]

    stripped = _UNSW_TIMESTAMP_FRACTION_RE.sub(_pad_fraction, stripped, count=1)
    parsed = datetime.fromisoformat(stripped)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
