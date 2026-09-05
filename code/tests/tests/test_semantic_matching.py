from __future__ import annotations

import pytest

from dib.evaluation.profiles import (
    FROM_DEVICE,
    TO_DEVICE,
    classify_endpoint,
    endpoint_satisfies_rule,
    semantic_match_metrics,
)


def test_classify_endpoint_recognizes_wildcard_controllers() -> None:
    assert classify_endpoint("urn:ietf:params:mud:dns")[0] == "controller_wildcard"
    assert classify_endpoint("dhcp_service")[0] == "controller_wildcard"


def test_classify_endpoint_recognizes_gateway_controller() -> None:
    assert classify_endpoint("urn:ietf:params:mud:gateway")[0] == "controller_gateway"


def test_classify_endpoint_recognizes_cidr() -> None:
    kind, network = classify_endpoint("8.8.8.8/32")
    assert kind == "cidr"
    assert str(network) == "8.8.8.8/32"


def test_classify_endpoint_falls_back_to_literal() -> None:
    assert classify_endpoint("pool.ntp.org") == ("literal", "pool.ntp.org")


def test_endpoint_satisfies_rule_dns_wildcard_ignores_identity() -> None:
    predicted = ("lifx-bulb", FROM_DEVICE, "1.2.3.4", "udp", 53)
    rule = ("lifx-bulb", FROM_DEVICE, "urn:ietf:params:mud:dns", "udp", 53)
    assert endpoint_satisfies_rule(predicted, rule)


def test_endpoint_satisfies_rule_gateway_requires_private_ip() -> None:
    rule = ("lifx-bulb", FROM_DEVICE, "urn:ietf:params:mud:gateway", "udp", 67)
    assert endpoint_satisfies_rule(("lifx-bulb", FROM_DEVICE, "192.168.1.1", "udp", 67), rule)
    assert not endpoint_satisfies_rule(("lifx-bulb", FROM_DEVICE, "8.8.8.8", "udp", 67), rule)


def test_endpoint_satisfies_rule_cidr_membership() -> None:
    rule = ("lifx-bulb", FROM_DEVICE, "8.8.8.0/24", "udp", 53)
    assert endpoint_satisfies_rule(("lifx-bulb", FROM_DEVICE, "8.8.8.8", "udp", 53), rule)
    assert not endpoint_satisfies_rule(("lifx-bulb", FROM_DEVICE, "9.9.9.9", "udp", 53), rule)


def test_endpoint_satisfies_rule_rejects_other_device_type() -> None:
    rule = ("lifx-bulb", FROM_DEVICE, "urn:ietf:params:mud:dns", "udp", 53)
    assert not endpoint_satisfies_rule(("other-device", FROM_DEVICE, "1.2.3.4", "udp", 53), rule)


def test_endpoint_satisfies_rule_rejects_mismatched_direction() -> None:
    # Review finding #4: a from-device predicted fact must NOT match a
    # to-device reference ACE for the same peer/protocol/port, and
    # direction is never wildcarded (unlike DNS/gateway controller roles).
    rule = ("lifx-bulb", TO_DEVICE, "1.2.3.4", "udp", 53)
    assert not endpoint_satisfies_rule(("lifx-bulb", FROM_DEVICE, "1.2.3.4", "udp", 53), rule)


def test_endpoint_satisfies_rule_matches_when_direction_agrees() -> None:
    rule = ("lifx-bulb", TO_DEVICE, "1.2.3.4", "udp", 53)
    assert endpoint_satisfies_rule(("lifx-bulb", TO_DEVICE, "1.2.3.4", "udp", 53), rule)


def test_endpoint_satisfies_rule_direction_not_wildcarded_by_dns_role() -> None:
    # Even for the DNS-role wildcard (identity ignored), direction is still
    # a required exact match, not a second thing the wildcard subsumes.
    rule = ("lifx-bulb", TO_DEVICE, "urn:ietf:params:mud:dns", "udp", 53)
    assert not endpoint_satisfies_rule(("lifx-bulb", FROM_DEVICE, "1.2.3.4", "udp", 53), rule)


def test_semantic_match_metrics_perfect_match() -> None:
    truth = {("d", FROM_DEVICE, "pool.ntp.org", "udp", 123)}
    predicted = {("d", FROM_DEVICE, "pool.ntp.org", "udp", 123)}
    metrics = semantic_match_metrics(predicted, truth)
    assert metrics["semantic_precision"] == 1.0
    assert metrics["semantic_recall"] == 1.0
    assert metrics["semantic_f1"] == 1.0


def test_semantic_match_metrics_no_overlap() -> None:
    truth = {("d", FROM_DEVICE, "pool.ntp.org", "udp", 123)}
    predicted = {("d", FROM_DEVICE, "1.2.3.4", "udp", 123)}
    metrics = semantic_match_metrics(predicted, truth)
    assert metrics["semantic_precision"] == 0.0
    assert metrics["semantic_recall"] == 0.0


def test_semantic_match_metrics_direction_mismatch_counts_as_no_overlap() -> None:
    # Same peer/protocol/port, opposite direction: must not inflate
    # precision/recall the way the pre-fix 4-tuple matcher did.
    truth = {("d", TO_DEVICE, "pool.ntp.org", "udp", 123)}
    predicted = {("d", FROM_DEVICE, "pool.ntp.org", "udp", 123)}
    metrics = semantic_match_metrics(predicted, truth)
    assert metrics["semantic_precision"] == 0.0
    assert metrics["semantic_recall"] == 0.0
    assert metrics["semantic_f1"] == 0.0


def test_normalize_direction_accepts_both_vocabularies() -> None:
    from dib.evaluation.profiles import _normalize_direction

    assert _normalize_direction("from-device") == FROM_DEVICE
    assert _normalize_direction("out") == FROM_DEVICE
    assert _normalize_direction("to-device") == TO_DEVICE
    assert _normalize_direction("in") == TO_DEVICE
    with pytest.raises(ValueError):
        _normalize_direction("sideways")
