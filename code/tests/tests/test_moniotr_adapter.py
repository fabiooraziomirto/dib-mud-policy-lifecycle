from __future__ import annotations

from pathlib import Path
import struct
import zipfile

from dib.adapters.moniotr import load_moniotr_observations


def test_moniotr_adapter_detects_common_flow_columns(tmp_path: Path) -> None:
    flow = tmp_path / "Amazon Echo_flows.csv"
    flow.write_text(
        "\n".join(
            [
                "timestamp,src_ip,dst_ip,dst_port,protocol,hostname,device",
                "1609459200,192.168.1.10,8.8.8.8,53,udp,dns.google,Amazon Echo",
                "2021-01-01T00:00:01Z,192.168.1.10,52.94.1.1,443,tcp,avs-alexa-na.amazon.com,Amazon Echo",
            ]
        ),
        encoding="utf-8",
    )

    observations, stats = load_moniotr_observations(tmp_path)

    assert stats.files_seen == 1
    assert stats.rows_seen == 2
    assert stats.rows_emitted == 2
    assert stats.devices == ("amazon-echo",)
    assert observations[0].device_type == "amazon-echo"
    assert observations[0].fqdn == "dns.google"
    assert observations[0].remote_ip == "8.8.8.8"
    assert observations[1].port == 443


def test_moniotr_adapter_reports_unusable_csv(tmp_path: Path) -> None:
    bad = tmp_path / "unknown.csv"
    bad.write_text("timestamp,src_ip\n1609459200,192.168.1.10\n", encoding="utf-8")

    observations, stats = load_moniotr_observations(tmp_path)

    assert observations == []
    assert stats.files_seen == 1
    assert stats.issues


def test_moniotr_adapter_reads_csv_inside_zip(tmp_path: Path) -> None:
    archive = tmp_path / "moniotr.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr(
            "flows/LiFX Bulb.csv",
            "time,id.orig_h,id.resp_h,id.resp_p,proto\n1609459200,192.168.1.20,1.1.1.1,123,udp\n",
        )

    observations, stats = load_moniotr_observations(tmp_path)

    assert stats.files_seen == 1
    assert stats.rows_emitted == 1
    assert observations[0].device_type == "lifx-bulb"
    assert observations[0].port == 123


def test_moniotr_adapter_reads_pcapng(tmp_path: Path) -> None:
    pcap_path = tmp_path / "iot-idle" / "us" / "tplink-plug" / "unctrl" / "capture_192.168.1.20.pcap"
    pcap_path.parent.mkdir(parents=True)
    packet = _udp_packet("192.168.1.20", "8.8.8.8", 50000, 53)
    pcap_path.write_bytes(_pcapng(packet))

    observations, stats = load_moniotr_observations(tmp_path, pcap_only=True)

    assert stats.rows_emitted == 1
    assert observations[0].site_id == "moniotr-us"
    assert observations[0].device_type == "tp-link-plug"
    assert observations[0].remote_ip == "8.8.8.8"
    assert observations[0].port == 53


def test_moniotr_adapter_rejects_implausibly_large_pcap_record(tmp_path: Path) -> None:
    pcap_path = tmp_path / "capture_192.168.1.20.pcap"
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    oversized_record = struct.pack("<IIII", 1_600_000_000, 0, 0xFFFFFFFF, 0xFFFFFFFF)
    pcap_path.write_bytes(global_header + oversized_record)

    observations, stats = load_moniotr_observations(tmp_path, pcap_only=True)

    assert observations == []
    assert stats.issues
    assert "record too large" in stats.issues[0]


def test_moniotr_adapter_rejects_implausibly_large_pcapng_block(tmp_path: Path) -> None:
    pcap_path = tmp_path / "capture_192.168.1.20.pcap"
    section_prefix = struct.pack("<II", 0x0A0D0D0A, 0xFFFFFFFF) + bytes.fromhex("4d3c2b1a")
    pcap_path.write_bytes(section_prefix + b"\x00" * 12)

    observations, stats = load_moniotr_observations(tmp_path, pcap_only=True)

    assert observations == []
    assert stats.issues
    assert "block too large" in stats.issues[0]


def _udp_packet(src: str, dst: str, src_port: int, dst_port: int) -> bytes:
    import ipaddress

    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    total_length = 20 + 8
    ip_header = (
        bytes([0x45, 0])
        + struct.pack("!H", total_length)
        + b"\x00\x00\x00\x00"
        + bytes([64, 17])
        + b"\x00\x00"
        + ipaddress.ip_address(src).packed
        + ipaddress.ip_address(dst).packed
    )
    udp_header = struct.pack("!HHHH", src_port, dst_port, 8, 0)
    return ethernet + ip_header + udp_header


def _pcapng(packet: bytes) -> bytes:
    section = (
        struct.pack("<II", 0x0A0D0D0A, 28)
        + bytes.fromhex("4d3c2b1a")
        + struct.pack("<HHq", 1, 0, -1)
        + struct.pack("<I", 28)
    )
    interface = struct.pack("<IIHHII", 1, 20, 1, 0, 65535, 20)
    padding = b"\x00" * ((4 - len(packet) % 4) % 4)
    block_length = 32 + len(packet) + len(padding)
    enhanced = (
        struct.pack("<II", 6, block_length)
        + struct.pack("<IIIII", 0, 0, 1_600_000_000, len(packet), len(packet))
        + packet
        + padding
        + struct.pack("<I", block_length)
    )
    return section + interface + enhanced
