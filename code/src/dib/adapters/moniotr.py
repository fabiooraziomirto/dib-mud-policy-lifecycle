from __future__ import annotations

import csv
import io
import ipaddress
import re
import struct
import tarfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from itertools import chain
from pathlib import Path
from typing import Iterable, Iterator, TextIO

from dib.core.models import Observation
from dib.evaluation.profiles import canonical_device_name


TIMESTAMP_COLUMNS = ("timestamp", "time", "ts", "date_time", "datetime", "start_time", "frame.time_epoch")
SRC_IP_COLUMNS = ("src_ip", "srcip", "srcIp", "id.orig_h", "source_ip", "source", "ip.src", "src")
DST_IP_COLUMNS = ("dst_ip", "dstip", "dstIp", "id.resp_h", "destination_ip", "destination", "ip.dst", "dst")
DST_PORT_COLUMNS = ("dst_port", "dstport", "dstPort", "id.resp_p", "destination_port", "tcp.dstport", "udp.dstport", "port")
PROTOCOL_COLUMNS = ("protocol", "proto", "ip_proto", "ipProto", "ip.proto", "transport_protocol", "service")
DEVICE_COLUMNS = ("device", "device_type", "device_name", "label", "name")
DEVICE_ID_COLUMNS = ("device_id", "mac", "src_mac", "eth.src", "id.orig_l2_addr")
FQDN_COLUMNS = ("fqdn", "hostname", "host", "query", "dns_query", "dns.qry.name", "server_name", "sni", "tls_sni")

# A normal capture record is bounded by the interface snap length (usually far
# below 1 MiB).  Reject implausible lengths before calling read(length), since a
# corrupt or hostile archive could otherwise request a multi-gigabyte allocation.
MAX_CAPTURE_RECORD_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class MoniotrParseStats:
    files_seen: int
    rows_seen: int
    rows_emitted: int
    rows_skipped: int
    devices: tuple[str, ...]
    issues: tuple[str, ...]


@dataclass(slots=True)
class MoniotrParseState:
    files_seen: int = 0
    rows_seen: int = 0
    rows_emitted: int = 0
    devices: set[str] = field(default_factory=set)
    issues: list[str] = field(default_factory=list)

    def snapshot(self) -> MoniotrParseStats:
        return MoniotrParseStats(
            files_seen=self.files_seen,
            rows_seen=self.rows_seen,
            rows_emitted=self.rows_emitted,
            rows_skipped=max(self.rows_seen - self.rows_emitted, 0),
            devices=tuple(sorted(self.devices)),
            issues=tuple(self.issues),
        )


def iter_moniotr_observations(
    input_dir: Path,
    site_id: str = "moniotr",
    max_rows_per_file: int | None = None,
    max_pcap_files: int | None = None,
    max_pcap_files_per_device: int | None = None,
    max_pcap_files_per_site_device: int | None = None,
    archive_filter: str | None = None,
    device_filter: set[str] | None = None,
    pcap_only: bool = False,
    state: MoniotrParseState | None = None,
) -> Iterator[Observation]:
    """Yield normalized observations without retaining packet captures or rows in RAM."""
    state = state or MoniotrParseState()
    if not pcap_only:
        for source_name, handle in _csv_sources(input_dir):
            state.files_seen += 1
            try:
                reader = csv.DictReader(handle)
                fields = tuple(reader.fieldnames or ())
                if not fields:
                    state.issues.append(f"{source_name}: no header")
                    continue
                mapping = _column_mapping(fields)
                if mapping["dst_ip"] is None and mapping["fqdn"] is None:
                    state.issues.append(f"{source_name}: no destination IP/FQDN column recognized")
                    continue
                if mapping["dst_port"] is None:
                    state.issues.append(f"{source_name}: no destination port column recognized")
                    continue
                for index, row in enumerate(reader):
                    if max_rows_per_file is not None and index >= max_rows_per_file:
                        break
                    state.rows_seen += 1
                    obs = _row_to_observation(row, Path(source_name), mapping, site_id)
                    if obs is not None:
                        state.rows_emitted += 1
                        state.devices.add(obs.device_type)
                        yield obs
            except (OSError, UnicodeError, csv.Error) as exc:
                state.issues.append(f"{source_name}: {exc}")

    pcap_count = 0
    pcap_count_by_device: dict[str, int] = {}
    pcap_count_by_site_device: dict[tuple[str, str], int] = {}
    for source_name, handle in _pcap_sources(input_dir, archive_filter=archive_filter):
        device = _device_from_pcap_source(source_name)
        derived_site = _site_from_pcap_source(source_name, site_id)
        if device_filter and device not in device_filter:
            continue
        if max_pcap_files is not None and pcap_count >= max_pcap_files:
            break
        if max_pcap_files_per_device is not None and pcap_count_by_device.get(device, 0) >= max_pcap_files_per_device:
            continue
        site_device = (derived_site, device)
        if (
            max_pcap_files_per_site_device is not None
            and pcap_count_by_site_device.get(site_device, 0) >= max_pcap_files_per_site_device
        ):
            continue
        pcap_count += 1
        state.files_seen += 1
        pcap_count_by_device[device] = pcap_count_by_device.get(device, 0) + 1
        pcap_count_by_site_device[site_device] = pcap_count_by_site_device.get(site_device, 0) + 1
        try:
            for obs in _iter_pcap_observations(handle, source_name, derived_site):
                state.rows_seen += 1
                state.rows_emitted += 1
                state.devices.add(obs.device_type)
                yield obs
        except (OSError, ValueError, struct.error) as exc:
            state.issues.append(f"{source_name}: {exc}")


def load_moniotr_observations(
    input_dir: Path,
    site_id: str = "moniotr",
    max_rows_per_file: int | None = None,
    max_pcap_files: int | None = None,
    max_pcap_files_per_device: int | None = None,
    max_pcap_files_per_site_device: int | None = None,
    archive_filter: str | None = None,
    device_filter: set[str] | None = None,
    pcap_only: bool = False,
) -> tuple[list[Observation], MoniotrParseStats]:
    state = MoniotrParseState()
    observations = list(
        iter_moniotr_observations(
            input_dir,
            site_id,
            max_rows_per_file,
            max_pcap_files,
            max_pcap_files_per_device,
            max_pcap_files_per_site_device,
            archive_filter,
            device_filter,
            pcap_only,
            state,
        )
    )
    return observations, state.snapshot()


def _csv_sources(input_dir: Path) -> Iterator[tuple[str, TextIO]]:
    if not input_dir.exists():
        return
    for path in sorted(input_dir.rglob("*")):
        if not path.is_file():
            continue
        suffixes = [suffix.lower() for suffix in path.suffixes]
        if path.suffix.lower() == ".csv":
            with path.open(encoding="utf-8", errors="replace", newline="") as handle:
                yield str(path), handle
        elif path.suffix.lower() == ".zip":
            yield from _zip_csv_sources(path)
        elif path.suffix.lower() in {".tar", ".tgz", ".tbz2", ".gz", ".bz2", ".xz"} or suffixes[-2:] in (
            [".tar", ".gz"],
            [".tar", ".bz2"],
            [".tar", ".xz"],
        ):
            yield from _tar_csv_sources(path)


def _pcap_sources(input_dir: Path, archive_filter: str | None = None):
    if not input_dir.exists():
        return
    for path in sorted(input_dir.rglob("*")):
        if not path.is_file():
            continue
        if archive_filter and archive_filter not in path.name:
            continue
        if path.suffix.lower() == ".pcap":
            with path.open("rb") as handle:
                yield str(path), handle
        elif path.suffix.lower() in {".tar", ".tgz", ".tbz2", ".gz", ".bz2", ".xz"}:
            try:
                with tarfile.open(path, mode="r:*") as archive:
                    for member in archive:
                        if not member.isfile() or not member.name.lower().endswith(".pcap"):
                            continue
                        handle = archive.extractfile(member)
                        if handle is None:
                            continue
                        yield f"{path}:{member.name}", handle
            except tarfile.TarError:
                continue
        elif path.suffix.lower() == ".zip":
            try:
                with zipfile.ZipFile(path) as archive:
                    for name in sorted(archive.namelist()):
                        if not name.lower().endswith(".pcap"):
                            continue
                        with archive.open(name) as handle:
                            yield f"{path}:{name}", handle
            except zipfile.BadZipFile:
                continue


def _zip_csv_sources(path: Path) -> Iterator[tuple[str, TextIO]]:
    try:
        with zipfile.ZipFile(path) as archive:
            for name in sorted(archive.namelist()):
                if not name.lower().endswith(".csv"):
                    continue
                with archive.open(name) as raw:
                    with io.TextIOWrapper(raw, encoding="utf-8", errors="replace", newline="") as handle:
                        yield f"{path}:{name}", handle
    except zipfile.BadZipFile:
        return


def _tar_csv_sources(path: Path) -> Iterator[tuple[str, TextIO]]:
    try:
        with tarfile.open(path, mode="r:*") as archive:
            for member in archive:
                if not member.isfile() or not member.name.lower().endswith(".csv"):
                    continue
                raw = archive.extractfile(member)
                if raw is None:
                    continue
                with raw:
                    with io.TextIOWrapper(raw, encoding="utf-8", errors="replace", newline="") as handle:
                        yield f"{path}:{member.name}", handle
    except tarfile.TarError:
        return


def _pcap_to_observations(handle, source_name: str, site_id: str) -> list[Observation]:
    """Compatibility wrapper; streaming callers should use _iter_pcap_observations."""
    return list(_iter_pcap_observations(handle, source_name, site_id))


def _iter_pcap_observations(handle, source_name: str, site_id: str) -> Iterator[Observation]:
    packets = iter(_iter_pcap_packets(handle))
    device_type = _device_from_pcap_source(source_name)
    device_ip = _device_ip_from_source(source_name)
    if device_ip is None:
        # A small bounded look-ahead preserves support for captures whose filename
        # does not encode the device address without loading the whole PCAP.
        buffered = []
        for _ in range(10_000):
            packet = next(packets, None)
            if packet is None:
                break
            buffered.append(packet)
        device_ip = _infer_device_ip(buffered)
        packets = chain(buffered, packets)
    if device_ip is None:
        return
    ip_to_name: dict[str, str] = {}
    seen: set[tuple[str, str, int, int]] = set()
    seen_second: int | None = None
    for packet in packets:
        if packet["protocol"] == "udp" and packet["src_port"] == 53:
            ip_to_name.update(_dns_answers(packet["payload"]))
        if packet["src_ip"] != device_ip:
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
        packet_second = int(packet["timestamp"])
        if seen_second != packet_second:
            seen.clear()
            seen_second = packet_second
        key = (dst_ip, packet["protocol"], port, packet_second)
        if key in seen:
            continue
        seen.add(key)
        yield Observation(
            site_id=site_id,
            device_id=device_ip,
            device_type=device_type,
            fqdn=fqdn,
            remote_ip=dst_ip,
            protocol=packet["protocol"],
            port=port,
            timestamp=datetime.fromtimestamp(float(packet["timestamp"]), tz=timezone.utc),
            source_dataset="moniotr",
            evidence_type=evidence,
        )


def _iter_pcap_packets(handle):
    header = handle.read(24)
    if len(header) < 24:
        return
    magic = header[:4]
    if magic == b"\x0a\x0d\x0d\x0a":
        yield from _iter_pcapng_packets(handle, header)
        return
    if magic in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"}:
        endian = "<"
    elif magic in {b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"}:
        endian = ">"
    else:
        raise ValueError("unsupported pcap magic")
    while True:
        packet_header = handle.read(16)
        if len(packet_header) == 0:
            break
        if len(packet_header) < 16:
            break
        ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack(f"{endian}IIII", packet_header)
        if incl_len > MAX_CAPTURE_RECORD_BYTES:
            raise ValueError(f"pcap record too large: {incl_len} bytes")
        packet = handle.read(incl_len)
        if len(packet) < incl_len:
            break
        parsed = _parse_ethernet_ipv4(packet)
        if parsed is None:
            continue
        parsed["timestamp"] = ts_sec
        yield parsed


def _iter_pcapng_packets(handle, first_header: bytes):
    endian = "<"
    ts_resolution = 1_000_000
    pending = first_header
    first = True
    while True:
        header = pending[:8] if first else handle.read(8)
        if len(header) < 8:
            break
        if first and len(pending) >= 12:
            bom = pending[8:12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
        block_type = int.from_bytes(header[:4], endian_to_byteorder(endian))
        block_length = int.from_bytes(header[4:8], endian_to_byteorder(endian))
        if block_length < 12:
            break
        if block_length > MAX_CAPTURE_RECORD_BYTES:
            raise ValueError(f"pcapng block too large: {block_length} bytes")
        already = pending[8:] if first else b""
        remainder = handle.read(block_length - 8 - len(already))
        if len(already) + len(remainder) < block_length - 8:
            break
        block = header + already + remainder
        body = block[8:block_length - 4]
        if block_type == 0x0A0D0D0A and len(body) >= 8:
            bom = body[:4]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
        elif block_type == 1 and len(body) >= 8:
            # Interface Description Block. We use the default timestamp
            # resolution (microseconds) unless an if_tsresol option is present.
            options = body[8:]
            parsed_resolution = _pcapng_ts_resolution(options)
            if parsed_resolution:
                ts_resolution = parsed_resolution
        elif block_type == 6 and len(body) >= 20:
            ts_high, ts_low, captured_len = struct.unpack(f"{endian}III", body[4:16])
            packet = body[20 : 20 + captured_len]
            parsed = _parse_ethernet_ipv4(packet)
            if parsed is not None:
                ticks = (ts_high << 32) | ts_low
                parsed["timestamp"] = ticks / ts_resolution
                yield parsed
        pending = b""
        first = False


def endian_to_byteorder(endian: str) -> str:
    return "little" if endian == "<" else "big"


def _pcapng_ts_resolution(options: bytes) -> int | None:
    offset = 0
    while offset + 4 <= len(options):
        code, length = struct.unpack("<HH", options[offset : offset + 4])
        offset += 4
        if code == 0:
            return None
        value = options[offset : offset + length]
        offset += length
        while offset % 4:
            offset += 1
        if code == 9 and value:
            raw = value[0]
            if raw & 0x80:
                return 2 ** (raw & 0x7F)
            return 10 ** raw
    return None


def _parse_ethernet_ipv4(packet: bytes) -> dict[str, object] | None:
    if len(packet) < 34:
        return None
    eth_type_offset = 12
    eth_type = int.from_bytes(packet[eth_type_offset : eth_type_offset + 2], "big")
    ip_offset = 14
    if eth_type == 0x8100 and len(packet) >= 38:
        eth_type = int.from_bytes(packet[16:18], "big")
        ip_offset = 18
    if eth_type != 0x0800:
        return None
    if len(packet) < ip_offset + 20:
        return None
    version_ihl = packet[ip_offset]
    if version_ihl >> 4 != 4:
        return None
    ihl = (version_ihl & 0x0F) * 4
    proto = packet[ip_offset + 9]
    src_ip = str(ipaddress.ip_address(packet[ip_offset + 12 : ip_offset + 16]))
    dst_ip = str(ipaddress.ip_address(packet[ip_offset + 16 : ip_offset + 20]))
    l4_offset = ip_offset + ihl
    if proto == 6 and len(packet) >= l4_offset + 20:
        src_port = int.from_bytes(packet[l4_offset : l4_offset + 2], "big")
        dst_port = int.from_bytes(packet[l4_offset + 2 : l4_offset + 4], "big")
        data_offset = ((packet[l4_offset + 12] >> 4) & 0x0F) * 4
        payload = packet[l4_offset + data_offset :]
        protocol = "tcp"
    elif proto == 17 and len(packet) >= l4_offset + 8:
        src_port = int.from_bytes(packet[l4_offset : l4_offset + 2], "big")
        dst_port = int.from_bytes(packet[l4_offset + 2 : l4_offset + 4], "big")
        payload = packet[l4_offset + 8 :]
        protocol = "udp"
    elif proto == 1:
        src_port = 0
        dst_port = 0
        payload = b""
        protocol = "icmp"
    else:
        return None
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "payload": payload,
    }


def _dns_query(payload: bytes) -> str | None:
    if len(payload) < 12:
        return None
    qdcount = int.from_bytes(payload[4:6], "big")
    if qdcount < 1:
        return None
    name, _ = _dns_name(payload, 12)
    return _clean_hostname(name or "")


def _dns_answers(payload: bytes) -> dict[str, str]:
    if len(payload) < 12:
        return {}
    qdcount = int.from_bytes(payload[4:6], "big")
    ancount = int.from_bytes(payload[6:8], "big")
    offset = 12
    names: list[str] = []
    for _ in range(qdcount):
        name, offset = _dns_name(payload, offset)
        if name:
            names.append(name)
        offset += 4
    answers: dict[str, str] = {}
    for _ in range(ancount):
        name, offset = _dns_name(payload, offset)
        if offset + 10 > len(payload):
            break
        rtype = int.from_bytes(payload[offset : offset + 2], "big")
        rdlength = int.from_bytes(payload[offset + 8 : offset + 10], "big")
        offset += 10
        rdata = payload[offset : offset + rdlength]
        offset += rdlength
        owner = _clean_hostname(name or (names[0] if names else ""))
        if owner and rtype == 1 and len(rdata) == 4:
            answers[str(ipaddress.ip_address(rdata))] = owner
    return answers


def _dns_name(payload: bytes, offset: int, depth: int = 0) -> tuple[str | None, int]:
    labels: list[str] = []
    jumped = False
    original_offset = offset
    while offset < len(payload) and depth < 8:
        length = payload[offset]
        if length == 0:
            offset += 1
            return ".".join(labels), (original_offset + 2 if jumped else offset)
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(payload):
                return None, offset + 1
            pointer = ((length & 0x3F) << 8) | payload[offset + 1]
            pointed, _ = _dns_name(payload, pointer, depth + 1)
            if pointed:
                labels.append(pointed)
            return ".".join(labels), (original_offset + 2 if jumped else offset + 2)
        offset += 1
        label = payload[offset : offset + length].decode("ascii", errors="ignore")
        labels.append(label)
        offset += length
    return None, offset


def _device_from_pcap_source(source_name: str) -> str:
    member_name = source_name.split(":", 1)[1] if ":" in source_name else source_name
    parts = member_name.replace("\\", "/").split("/")
    for marker in ("iot-data", "iot-idle"):
        if marker in parts:
            index = parts.index(marker)
            if len(parts) > index + 2:
                return canonical_device_name(parts[index + 2])
    return canonical_device_name(Path(source_name.split(":")[-1]).stem)


def _site_from_pcap_source(source_name: str, default: str) -> str:
    member_name = source_name.split(":", 1)[1] if ":" in source_name else source_name
    parts = member_name.replace("\\", "/").split("/")
    for marker in ("iot-data", "iot-idle"):
        if marker in parts:
            index = parts.index(marker)
            if len(parts) > index + 1:
                return f"{default}-{parts[index + 1]}"
    return default


def _device_ip_from_source(source_name: str) -> str | None:
    match = re.search(r"_(\d{1,3}(?:\.\d{1,3}){3})\.pcap$", source_name)
    if not match:
        return None
    return _clean_ip(match.group(1))


def _infer_device_ip(packets: list[dict[str, object]]) -> str | None:
    counts: dict[str, int] = {}
    for packet in packets:
        for key in ("src_ip", "dst_ip"):
            ip = str(packet[key])
            try:
                parsed = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if parsed.is_private:
                counts[ip] = counts.get(ip, 0) + 1
    if not counts:
        return None
    return max(counts.items(), key=lambda item: item[1])[0]


def stats_to_rows(stats: MoniotrParseStats) -> list[dict[str, object]]:
    return [
        {
            "files_seen": stats.files_seen,
            "rows_seen": stats.rows_seen,
            "rows_emitted": stats.rows_emitted,
            "rows_skipped": stats.rows_skipped,
            "device_count": len(stats.devices),
            "devices": ";".join(stats.devices),
            "issue_count": len(stats.issues),
            "issues": " | ".join(stats.issues[:20]),
        }
    ]


def _column_mapping(fields: tuple[str, ...]) -> dict[str, str | None]:
    return {
        "timestamp": _first_present(fields, TIMESTAMP_COLUMNS),
        "src_ip": _first_present(fields, SRC_IP_COLUMNS),
        "dst_ip": _first_present(fields, DST_IP_COLUMNS),
        "dst_port": _first_present(fields, DST_PORT_COLUMNS),
        "protocol": _first_present(fields, PROTOCOL_COLUMNS),
        "device": _first_present(fields, DEVICE_COLUMNS),
        "device_id": _first_present(fields, DEVICE_ID_COLUMNS),
        "fqdn": _first_present(fields, FQDN_COLUMNS),
    }


def _row_to_observation(
    row: dict[str, str],
    path: Path,
    mapping: dict[str, str | None],
    site_id: str,
) -> Observation | None:
    device_type = _device_type(row, path, mapping)
    endpoint = _clean_hostname(_value(row, mapping["fqdn"]))
    remote_ip = _clean_ip(_value(row, mapping["dst_ip"]))
    if endpoint is None and remote_ip is None:
        return None
    port = _parse_port(_value(row, mapping["dst_port"]))
    if port == 0:
        return None
    protocol = _protocol(_value(row, mapping["protocol"]), port)
    timestamp = _timestamp(_value(row, mapping["timestamp"]))
    device_id = _value(row, mapping["device_id"]) or _value(row, mapping["src_ip"]) or device_type
    return Observation(
        site_id=site_id,
        device_id=device_id,
        device_type=device_type,
        fqdn=endpoint,
        remote_ip=remote_ip,
        protocol=protocol,
        port=port,
        timestamp=timestamp,
        source_dataset="moniotr",
        evidence_type="flow",
    )


def _first_present(fields: tuple[str, ...], candidates: tuple[str, ...]) -> str | None:
    exact = {field: field for field in fields}
    lower = {field.lower(): field for field in fields}
    compact = {re.sub(r"[^a-z0-9]+", "", field.lower()): field for field in fields}
    for candidate in candidates:
        if candidate in exact:
            return exact[candidate]
        lowered = candidate.lower()
        if lowered in lower:
            return lower[lowered]
        key = re.sub(r"[^a-z0-9]+", "", lowered)
        if key in compact:
            return compact[key]
    return None


def _value(row: dict[str, str], column: str | None) -> str:
    if column is None:
        return ""
    return str(row.get(column, "")).strip()


def _device_type(row: dict[str, str], path: Path, mapping: dict[str, str | None]) -> str:
    explicit = _value(row, mapping["device"])
    if explicit:
        return canonical_device_name(explicit)
    stem = path.stem
    for suffix in ("_flows", "-flows", "_conn", "-conn", "_dns", "-dns"):
        if stem.lower().endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    return canonical_device_name(stem)


def _clean_ip(value: str) -> str | None:
    if not value:
        return None
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if ip.is_unspecified or ip.is_multicast or ip.is_loopback:
        return None
    if ip.version == 4 and str(ip) == "255.255.255.255":
        return None
    return str(ip)


def _clean_hostname(value: str) -> str | None:
    hostname = value.strip().strip(".").lower()
    if not hostname or hostname in {"-", "null", "none"}:
        return None
    if " " in hostname or "/" in hostname:
        return None
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return hostname
    return None


def _parse_port(value: str) -> int:
    try:
        return int(float(value))
    except ValueError:
        return 0


def _protocol(value: str, port: int) -> str:
    cleaned = value.strip().lower()
    if cleaned in {"6", "tcp"}:
        return "tcp"
    if cleaned in {"17", "udp"}:
        return "udp"
    if cleaned in {"1", "icmp", "icmpv6"}:
        return "icmp"
    if cleaned and cleaned not in {"-", "none", "unknown"}:
        return cleaned
    if port in {53, 67, 68, 123, 1900, 5353}:
        return "udp"
    return "tcp"


def _timestamp(value: str) -> datetime:
    if not value:
        return datetime(1970, 1, 1, tzinfo=timezone.utc)
    stripped = value.strip().replace("Z", "+00:00")
    try:
        numeric = float(stripped)
    except ValueError:
        numeric = None
    if numeric is not None:
        if numeric > 10_000_000_000:
            numeric = numeric / 1000
        return datetime.fromtimestamp(numeric, tz=timezone.utc)
    for candidate in (stripped, stripped.replace(" ", "T")):
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    return datetime(1970, 1, 1, tzinfo=timezone.utc)
