from __future__ import annotations

from collections import Counter

from dib.evaluation.profiles import EndpointKey, classify_endpoint


def protocol_summary(
    truth: dict[str, set[EndpointKey]], observed_devices: set[str]
) -> dict[str, object]:
    # rule[2] is the endpoint field of the 5-tuple (device_type, direction,
    # endpoint, protocol, port) -- not rule[1] (direction), a mistake this
    # module's own test caught (see test_ground_truth_protocol.py).
    kinds = Counter(classify_endpoint(rule[2])[0] for rules in truth.values() for rule in rules)
    return {
        "observed_device_type_count": len(observed_devices),
        "ground_truth_profile_count": len(truth),
        "evaluated_reference_count": len(truth),
        "unobserved_reference_devices": sorted(set(truth) - observed_devices),
        "rule_count_by_match_kind": dict(sorted(kinds.items())),
        "device_key": "canonical exact match",
        "endpoint_matching": {
            "literal": "case-normalized exact FQDN/IP string",
            "cidr": "predicted IP membership in the reference network",
            "controller_wildcard": "DNS/DHCP/mDNS roles only, with compatible protocol and port",
            "controller_gateway": "private predicted IP with compatible protocol and port",
        },
        "protocol_matching": "exact after normalization; reference unknown is wildcard",
        "port_matching": "exact; reference port 0 is wildcard",
        "many_to_many": True,
        "cdn_expansion": False,
        "ambiguous_controller_expansion": False,
        # Fixed 2026-07-24 (review finding #4): direction is now a required,
        # exactly-matched field of the canonical tuple (device key,
        # direction, protocol, remote peer, remote-port semantics), never
        # wildcarded. Reference direction is the RFC 8520 ACL CONTAINER
        # (from-device-policy/to-device-policy) an ACE lives under, not
        # ietf-mud:direction-initiated (a distinct, per-ACE TCP-initiator
        # attribute) -- see dib.evaluation.profiles._acl_direction_map().
        # Predicted direction is from-device for every observation in this
        # codebase today (no adapter emits to-device/"in" rows).
        "direction_available_in_observation_schema": True,
        "direction_matching": "exact (from-device/to-device); never wildcarded",
        "direction_source": "ACL container membership (from-device-policy/to-device-policy), not ietf-mud:direction-initiated",
    }


def coverage_rows(
    truth: dict[str, set[EndpointKey]], observed_devices: set[str]
) -> list[dict[str, object]]:
    devices = sorted(set(truth) | observed_devices)
    return [
        {
            "device_type": device,
            "observed_in_traffic": device in observed_devices,
            "ground_truth_available": device in truth,
            "ground_truth_rule_count": len(truth.get(device, set())),
            "evaluation_prediction_policy": "empty" if device in truth and device not in observed_devices else "scored",
        }
        for device in devices
    ]
