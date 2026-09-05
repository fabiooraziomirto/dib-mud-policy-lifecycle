from __future__ import annotations

from datetime import datetime, timezone

from dib.core.models import EndpointScore, Observation
from dib.evaluation.mud_export import export_mud_file, response_leg_endpoint_keys


def score(endpoint: str, protocol: str, port: int, accepted: bool = True) -> EndpointScore:
    return EndpointScore(
        device_type="camera", endpoint=endpoint, protocol=protocol, port=port,
        site_confidence=0.9, temporal_confidence=0.8, graph_confidence=0.7,
        score=0.85, accepted=accepted, supporting_sites=3, eligible_sites=5,
    )


def test_export_mud_file_produces_from_device_aces_for_accepted_fqdn_endpoints() -> None:
    scores = [
        score("api.vendor.com", "https", 443),
        score("time.vendor.com", "udp", 123),
        score("rejected.vendor.com", "https", 443, accepted=False),
    ]
    result = export_mud_file("camera", scores)
    assert result.exported_ace_count == 2
    assert not result.skipped_endpoints

    document = result.document
    acls = document["ietf-access-control-list:access-lists"]["acl"]
    from_acl = next(acl for acl in acls if acl["name"].endswith("-fr"))
    to_acl = next(acl for acl in acls if acl["name"].endswith("-to"))
    assert len(from_acl["aces"]["ace"]) == 2
    assert to_acl["aces"]["ace"] == []

    dns_names = {ace["matches"]["ipv4"]["ietf-acldns:dst-dnsname"] for ace in from_acl["aces"]["ace"]}
    assert dns_names == {"api.vendor.com", "time.vendor.com"}
    for ace in from_acl["aces"]["ace"]:
        assert ace["actions"]["forwarding"] == "accept"


def test_export_mud_file_skips_non_portable_protocol_and_ip_literal_endpoints() -> None:
    scores = [
        score("api.vendor.com", "https", 443),
        score("8.8.8.8", "udp", 53),
        score("192.168.1.1:5000", "dns", 53),
        score("gateway.local", "icmp", 0),
    ]
    result = export_mud_file("camera", scores)
    assert result.exported_ace_count == 1
    skipped_endpoints = {item.endpoint for item in result.skipped_endpoints}
    assert skipped_endpoints == {"8.8.8.8", "192.168.1.1:5000", "gateway.local"}


def test_export_mud_file_adds_to_device_ace_only_for_endpoints_with_a_response_leg() -> None:
    scores = [
        score("api.vendor.com", "https", 443),
        score("time.vendor.com", "udp", 123),
    ]
    result = export_mud_file(
        "camera",
        scores,
        response_leg_endpoints={("camera", "api.vendor.com", "https", 443)},
    )
    assert result.to_device_ace_count == 1
    assert [item.endpoint for item in result.to_device_endpoints] == ["api.vendor.com"]

    document = result.document
    acls = document["ietf-access-control-list:access-lists"]["acl"]
    to_acl = next(acl for acl in acls if acl["name"].endswith("-to"))
    assert len(to_acl["aces"]["ace"]) == 1
    ace = to_acl["aces"]["ace"][0]
    assert ace["matches"]["ipv4"]["ietf-acldns:src-dnsname"] == "api.vendor.com"
    assert ace["matches"]["tcp"]["source-port-range-or-operator"]["port"] == 443
    assert ace["matches"]["tcp"]["ietf-mud:direction-initiated"] == "from-device"


def test_export_mud_file_ignores_response_leg_for_a_skipped_endpoint() -> None:
    scores = [score("8.8.8.8", "udp", 53)]
    result = export_mud_file(
        "camera",
        scores,
        response_leg_endpoints={("camera", "8.8.8.8", "udp", 53)},
    )
    assert result.exported_ace_count == 0
    assert result.to_device_ace_count == 0


def test_response_leg_endpoint_keys_only_includes_observed_response_legs() -> None:
    def obs(port: int, response_observed: bool) -> Observation:
        return Observation(
            site_id="site-a",
            device_id="dev1",
            device_type="camera",
            fqdn="api.vendor.com",
            remote_ip=None,
            protocol="https",
            port=port,
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            source_dataset="unit_fixture",
            evidence_type="flow",
            response_observed=response_observed,
        )

    keys = response_leg_endpoint_keys([obs(443, True), obs(8080, False)])
    assert keys == {("camera", "api.vendor.com", "https", 443)}


def test_export_mud_file_is_valid_json_serializable_and_schema_shaped() -> None:
    import json

    result = export_mud_file("camera", [score("api.vendor.com", "https", 443)])
    payload = json.loads(json.dumps(result.document))
    mud = payload["ietf-mud:mud"]
    assert mud["mud-version"] == 1
    assert mud["from-device-policy"]["access-lists"]["access-list"][0]["name"]
    assert mud["to-device-policy"]["access-lists"]["access-list"][0]["name"]
