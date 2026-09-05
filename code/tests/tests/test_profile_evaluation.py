from __future__ import annotations

import json
from pathlib import Path

import pytest

from dib.evaluation.profiles import (
    FROM_DEVICE,
    TO_DEVICE,
    _acl_direction_map,
    _mud_endpoints,
    _rule_to_endpoint,
    canonical_device_name,
    load_baseline_profile,
    load_dib_scores,
    load_profile_csv,
    load_profile_json,
)


def test_canonical_device_name_normalizes_common_variants() -> None:
    assert canonical_device_name("Amazon Echo.json") == "amazon-echo"
    assert canonical_device_name("philips-hue-bridge.json") == "philips-hue"


def _mud_payload(from_acls=(), to_acls=(), acls=()) -> dict:
    return {
        "ietf-mud:mud": {
            "from-device-policy": {"access-lists": {"access-list": [{"name": n} for n in from_acls]}},
            "to-device-policy": {"access-lists": {"access-list": [{"name": n} for n in to_acls]}},
        },
        "ietf-access-control-list:acls": {"acl": list(acls)},
    }


def _ace(name: str, dnsname: str, port: int) -> dict:
    return {
        "name": name,
        "matches": {
            "ipv4": {"protocol": 6, "ietf-acldns:dst-dnsname": dnsname},
            "tcp": {"destination-port": {"port": port}, "ietf-mud:direction-initiated": "from-device"},
        },
    }


def test_acl_direction_map_reads_from_and_to_device_policy() -> None:
    payload = _mud_payload(from_acls=["fr"], to_acls=["to"])
    assert _acl_direction_map(payload) == {"fr": FROM_DEVICE, "to": TO_DEVICE}


def test_acl_direction_map_raises_on_contradictory_acl_name() -> None:
    payload = _mud_payload(from_acls=["dup"], to_acls=["dup"])
    with pytest.raises(ValueError):
        _acl_direction_map(payload)


def test_mud_endpoints_tags_aces_with_container_direction_not_direction_initiated() -> None:
    # Both ACEs carry ietf-mud:direction-initiated="from-device" (a real
    # RFC 8520 pattern for the return leg of a device-initiated session --
    # see mud_export.py), but the "to" ACE lives under to-device-policy and
    # must be tagged to-device regardless of that per-ACE field.
    payload = _mud_payload(
        from_acls=["fr"],
        to_acls=["to"],
        acls=[
            {"name": "fr", "aces": {"ace": [_ace("fr-0", "svc.example.com", 443)]}},
            {"name": "to", "aces": {"ace": [_ace("to-0", "svc.example.com", 443)]}},
        ],
    )
    endpoints = set(_mud_endpoints("camera", payload))
    assert ("camera", FROM_DEVICE, "svc.example.com", "tcp", 443) in endpoints
    assert ("camera", TO_DEVICE, "svc.example.com", "tcp", 443) in endpoints
    assert len(endpoints) == 2


def test_mud_endpoints_raises_on_acl_not_referenced_by_either_policy() -> None:
    payload = _mud_payload(
        from_acls=["fr"],
        acls=[{"name": "orphan", "aces": {"ace": [_ace("o-0", "svc.example.com", 443)]}}],
    )
    with pytest.raises(ValueError):
        list(_mud_endpoints("camera", payload))


def test_load_profile_json_end_to_end_derives_direction(tmp_path: Path) -> None:
    payload = _mud_payload(
        from_acls=["fr"],
        to_acls=["to"],
        acls=[
            {"name": "fr", "aces": {"ace": [_ace("fr-0", "svc.example.com", 443)]}},
            {"name": "to", "aces": {"ace": [_ace("to-0", "svc.example.com", 443)]}},
        ],
    )
    path = tmp_path / "camera.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    endpoints = load_profile_json(path)
    assert ("camera", FROM_DEVICE, "svc.example.com", "tcp", 443) in endpoints
    assert ("camera", TO_DEVICE, "svc.example.com", "tcp", 443) in endpoints


def test_rule_to_endpoint_requires_explicit_direction_list_form() -> None:
    with pytest.raises(ValueError):
        _rule_to_endpoint("camera", ["svc.example.com", 443, "tcp"])
    assert _rule_to_endpoint("camera", ["svc.example.com", 443, "tcp", "to-device"]) == (
        "camera", TO_DEVICE, "svc.example.com", "tcp", 443,
    )


def test_rule_to_endpoint_requires_explicit_direction_dict_form() -> None:
    with pytest.raises(ValueError):
        _rule_to_endpoint("camera", {"dst_dnsname": "svc.example.com", "dst_port": 443, "protocol": "tcp"})
    assert _rule_to_endpoint(
        "camera", {"dst_dnsname": "svc.example.com", "dst_port": 443, "protocol": "tcp", "direction": "out"}
    ) == ("camera", FROM_DEVICE, "svc.example.com", "tcp", 443)


def test_load_profile_csv_requires_direction_column(tmp_path: Path) -> None:
    path = tmp_path / "camera.csv"
    path.write_text("dst_dnsname,dst_port,protocol\nsvc.example.com,443,tcp\n", encoding="utf-8")
    with pytest.raises(KeyError):
        load_profile_csv(path)


def test_load_profile_csv_with_direction_column(tmp_path: Path) -> None:
    path = tmp_path / "camera.csv"
    path.write_text(
        "dst_dnsname,dst_port,protocol,direction\nsvc.example.com,443,tcp,to-device\n", encoding="utf-8"
    )
    assert load_profile_csv(path) == {("camera", TO_DEVICE, "svc.example.com", "tcp", 443)}


def test_load_dib_scores_requires_direction_column(tmp_path: Path) -> None:
    path = tmp_path / "scores.csv"
    path.write_text(
        "device_type,endpoint,protocol,port,accepted\ncamera,svc.example.com,tcp,443,true\n", encoding="utf-8"
    )
    with pytest.raises(KeyError):
        load_dib_scores(path)


def test_load_dib_scores_with_direction_column(tmp_path: Path) -> None:
    path = tmp_path / "scores.csv"
    path.write_text(
        "device_type,endpoint,protocol,port,accepted,direction\n"
        "camera,svc.example.com,tcp,443,true,from-device\n",
        encoding="utf-8",
    )
    profiles = load_dib_scores(path)
    assert profiles["camera"] == {("camera", FROM_DEVICE, "svc.example.com", "tcp", 443)}


def test_load_baseline_profile_requires_direction_column(tmp_path: Path) -> None:
    path = tmp_path / "baseline.csv"
    path.write_text(
        "baseline,device_type,endpoint,protocol,port\nlocal,camera,svc.example.com,tcp,443\n", encoding="utf-8"
    )
    with pytest.raises(KeyError):
        load_baseline_profile(path)
