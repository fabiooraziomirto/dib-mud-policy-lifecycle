from __future__ import annotations

import csv
import ipaddress
import json
import re
from pathlib import Path
from typing import Iterable


IP_PROTOCOLS = {
    1: "icmp",
    2: "igmp",
    6: "tcp",
    17: "udp",
}


EndpointKey = tuple[str, str, str, str, int]  # (device_type, direction, endpoint, protocol, port)

# RFC 8520 direction vocabulary used throughout the ground-truth matcher.
# Deliberately distinct from ietf-mud:direction-initiated (which side opens
# the TCP connection -- a per-ACE, transport-level attribute) -- direction
# here is the ACL CONTAINER an ACE lives under (from-device-policy vs
# to-device-policy), which is what actually determines whether an ACE
# governs egress-from-device or ingress-to-device traffic. Conflating the
# two let a from-device predicted fact match a to-device reference ACE
# whenever peer/protocol/port happened to coincide (review finding #4,
# fixed 2026-07-24). See _acl_direction_map() and _mud_endpoints() below.
FROM_DEVICE = "from-device"
TO_DEVICE = "to-device"

# Every current adapter only ever emits Observation(direction="out") rows
# (device-initiated flows -- see dib.core.models.Observation's docstring),
# so every predicted fact in this codebase is, today, unconditionally a
# from-device fact. This constant is the single place that assumption is
# stated; if a future adapter ever emits direction="in" (to-device) rows,
# every predicted-side call site below must switch from this constant to a
# real per-observation lookup instead of silently keeping predictions
# under-matched against to-device references.
PREDICTED_DIRECTION = FROM_DEVICE


# --- Semantic ground-truth matching --------------------------------------------------
#
# UNSW MUD ground-truth ACEs do not always identify an endpoint by FQDN or IP. Some
# matches only carry a `mud:controller` abstraction (e.g. "this rule is about whatever
# acts as the DNS resolver/gateway"), and some carry a CIDR network instead of a single
# host. A literal string-equality matcher can never satisfy these, which silently
# deflates precision/recall/F1 for every method (not just DIB) regardless of how
# accurate the underlying observations are. This is documented and deliberately scoped:
# only abstractions whose real-world identity is protocol-defined (DNS/DHCP/mDNS
# resolution, the local gateway) are treated as wildcards; ambiguous categories like
# "general_internet", "mqtt_broker", or "video_controller" are left as literal (i.e.
# effectively unmatchable without a concrete vendor hostname) because wildcarding them
# would inflate accuracy without genuine corroborating evidence.
WILDCARD_CONTROLLERS = {"urn:ietf:params:mud:dns", "dns_service", "dhcp_service", "mdns_service"}
GATEWAY_CONTROLLERS = {"urn:ietf:params:mud:gateway"}


def classify_endpoint(endpoint: str) -> tuple[str, object]:
    """Classify a ground-truth endpoint string into a matching strategy.

    Returns (kind, data) where kind is one of:
    - "controller_wildcard": matches any predicted endpoint with compatible protocol/port
      (used for DNS/DHCP/mDNS resolution rules that name a role, not a host)
    - "controller_gateway": matches any predicted endpoint that is a private/local IP
    - "cidr": matches any predicted IP address contained in the given ipaddress network
    - "literal": exact (case-insensitive) string match, the pre-existing behavior
    """
    if endpoint in WILDCARD_CONTROLLERS:
        return ("controller_wildcard", None)
    if endpoint in GATEWAY_CONTROLLERS:
        return ("controller_gateway", None)
    try:
        network = ipaddress.ip_network(endpoint, strict=False)
        return ("cidr", network)
    except ValueError:
        return ("literal", endpoint)


def endpoint_satisfies_rule(predicted: EndpointKey, rule: EndpointKey) -> bool:
    """True if a predicted (device_type, direction, endpoint, protocol, port)
    tuple satisfies a ground-truth rule under semantic matching (see
    classify_endpoint).

    Direction is matched exactly (from-device vs to-device, per the ACL
    container the reference ACE lives under -- see _acl_direction_map()) and
    never wildcarded: a from-device predicted fact and a to-device reference
    ACE for the same peer/protocol/port are NOT a match (review finding #4,
    fixed 2026-07-24). Endpoint facts are direction-typed by definition
    (main.tex Sec. I), so this is a required field like device_type, not an
    optional refinement.
    """
    pred_device, pred_direction, pred_endpoint, pred_protocol, pred_port = predicted
    rule_device, rule_direction, rule_endpoint, rule_protocol, rule_port = rule
    if pred_device != rule_device:
        return False
    if pred_direction != rule_direction:
        return False
    if rule_protocol not in ("unknown", pred_protocol) and pred_protocol != "unknown":
        return False
    if rule_port not in (0, pred_port):
        return False
    kind, data = classify_endpoint(rule_endpoint)
    if kind == "literal":
        return pred_endpoint == rule_endpoint
    if kind == "controller_wildcard":
        return True
    if kind == "controller_gateway":
        try:
            return ipaddress.ip_address(pred_endpoint).is_private
        except ValueError:
            return False
    if kind == "cidr":
        try:
            return ipaddress.ip_address(pred_endpoint) in data
        except ValueError:
            return False
    return False


def semantic_match_metrics(predicted: set[EndpointKey], truth: set[EndpointKey]) -> dict[str, float]:
    """Precision/recall/F1 under semantic matching. Many-to-many: a predicted endpoint
    counts toward precision if it satisfies *any* truth rule; a truth rule counts toward
    recall if *any* predicted endpoint satisfies it. Jaccard is not reported here because
    it is not well-defined under many-to-many matching (it would require committing to a
    single bipartite assignment); use F1 instead for a single summary statistic.
    """
    matched_predicted = sum(
        1 for p in predicted if any(endpoint_satisfies_rule(p, t) for t in truth)
    )
    matched_truth = sum(
        1 for t in truth if any(endpoint_satisfies_rule(p, t) for p in predicted)
    )
    precision = matched_predicted / len(predicted) if predicted else 0.0
    recall = matched_truth / len(truth) if truth else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"semantic_precision": precision, "semantic_recall": recall, "semantic_f1": f1}


def canonical_device_name(value: str) -> str:
    stem = Path(value).stem
    normalized = re.sub(r"[^a-z0-9]+", "-", stem.lower()).strip("-")
    aliases = {
        "amazonecho": "amazon-echo",
        "amazon-echo": "amazon-echo",
        "augustdoorbell": "august-doorbell",
        "august-doorbell": "august-doorbell",
        "awairairquality": "awair-air-quality",
        "belkincamera": "belkin-camera",
        "belkin-camera": "belkin-camera",
        "belkinwemomotionsensor": "wemo-motion",
        "belkinwemoswitch": "wemo-switch",
        "blipcarebpmeter": "blipcare-bp-meter",
        "canarycamera": "canary-camera",
        "canary-camera": "canary-camera",
        "hellobarbie": "hello-barbie",
        "hpprinter": "hp-printer",
        "ihome": "ihome-plug",
        "lifxbulb": "lifx-bulb",
        "lifx-bulb": "lifx-bulb",
        "nestdropcam": "dropcam",
        "nest-cam": "dropcam",
        "nestprotect": "nest-smoke-sensor",
        "nest-smoke-sensor": "nest-smoke-sensor",
        "netatmowelcome": "netatmo-camera",
        "netatmoweatherstation": "netatmo-weather",
        "netatmo-weather-station": "netatmo-weather",
        "philips-bulb": "philips-hue",
        "philips-hue": "philips-hue",
        "philipshue": "philips-hue",
        "philips-hue-bridge": "philips-hue",
        "pixstarphotoframe": "pixstar-photo",
        "ringdoorbell": "ring-doorbell",
        "ring-doorbell": "ring-doorbell",
        "samsungcamera": "samsung-smartcam",
        "samsungsmartthings": "smartthings",
        "smartthings": "smartthings",
        "smartthings-hub": "smartthings",
        "t-philips-hub": "philips-hue",
        "tplinkcamera": "tp-link-camera",
        "tp-link-camera": "tp-link-camera",
        "tplink-plug": "tp-link-plug",
        "tplinksmartplug": "tp-link-plug",
        "tp-link-plug": "tp-link-plug",
        "tribyspeaker": "triby-speaker",
        "withingsbabymonitor": "withings-baby",
        "withingssleepsensor": "withings-sleep",
        "withingssmartscale": "withings-cardio",
        "wemo-motion": "wemo-motion",
        "wemo-switch": "wemo-switch",
    }
    return aliases.get(normalized, normalized)


def load_profile_dir(path: Path) -> dict[str, set[EndpointKey]]:
    profiles: dict[str, set[EndpointKey]] = {}
    for item in sorted(path.iterdir()):
        if item.suffix.lower() == ".json":
            profiles[canonical_device_name(item.name)] = load_profile_json(item)
        elif item.suffix.lower() == ".csv":
            profiles[canonical_device_name(item.name)] = load_profile_csv(item)
    return profiles


def load_profile_json(path: Path) -> set[EndpointKey]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    device_type = canonical_device_name(path.name)
    if isinstance(payload, dict) and isinstance(payload.get("rules"), list):
        return {
            _rule_to_endpoint(device_type, rule)
            for rule in payload["rules"]
            if _rule_to_endpoint(device_type, rule) is not None
        }
    return set(_mud_endpoints(device_type, payload))


def load_profile_csv(path: Path) -> set[EndpointKey]:
    """Load a compact CSV ground-truth profile.

    Requires a ``direction`` column (from-device/to-device, or out/in) --
    added 2026-07-24 alongside the ACL-format fix in _mud_endpoints(); a
    CSV without it fails loudly (KeyError) rather than being silently
    assumed from-device, since this loader is also used for reference
    (ground-truth) profiles where that assumption is not always true. No
    shipped ground-truth file currently uses this CSV format (all UNSW
    references are ACL-format JSON via _mud_endpoints).
    """
    device_type = canonical_device_name(path.name)
    endpoints: set[EndpointKey] = set()
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            endpoint = row.get("dst_class") or row.get("dst_dnsname") or row.get("dst_ip")
            port = row.get("dst_port") or row.get("port") or "0"
            protocol = row.get("protocol") or row.get("ip_proto") or "unknown"
            if endpoint:
                normalized_port = _safe_int(port)
                direction = _normalize_direction(row["direction"])
                endpoints.add(
                    (device_type, direction, endpoint.lower(), normalize_profile_protocol(protocol, normalized_port), normalized_port)
                )
    return endpoints


def load_dib_scores(path: Path, accepted_only: bool = True) -> dict[str, set[EndpointKey]]:
    """Load a DIB score CSV emitted by run_experiments.py (predicted side).

    Requires a ``direction`` column -- added 2026-07-24. Every current
    adapter only ever produces from-device observations (see
    PREDICTED_DIRECTION's docstring), so existing CSVs written before this
    column existed can be safely backfilled with "from-device" for every
    row; but that backfill must be an explicit, one-time migration a caller
    performs on the file (see data_provenance.md), not a default this
    loader applies silently -- a CSV missing the column fails loudly here.
    """
    profiles: dict[str, set[EndpointKey]] = {}
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            if accepted_only and str(row.get("accepted", "")).lower() not in {"true", "1", "yes"}:
                continue
            device_type = canonical_device_name(str(row["device_type"]))
            endpoint = str(row["endpoint"]).lower()
            port = _safe_int(row["port"])
            protocol = normalize_profile_protocol(row["protocol"], port)
            direction = _normalize_direction(row["direction"])
            profiles.setdefault(device_type, set()).add((device_type, direction, endpoint, protocol, port))
    return profiles


def load_baseline_profile(path: Path) -> dict[str, set[EndpointKey]]:
    """Load a Baseline.export() CSV (columns: baseline, device_type, endpoint,
    protocol, port, direction). Requires ``direction`` -- see load_dib_scores's
    docstring; the same from-device backfill note applies to pre-existing
    exports.
    """
    profiles: dict[str, set[EndpointKey]] = {}
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            device_type = canonical_device_name(str(row["device_type"]))
            endpoint = str(row["endpoint"]).lower()
            port = _safe_int(row["port"])
            protocol = normalize_profile_protocol(row["protocol"], port)
            direction = _normalize_direction(row["direction"])
            profiles.setdefault(device_type, set()).add((device_type, direction, endpoint, protocol, port))
    return profiles


def _acl_direction_map(payload: dict) -> dict[str, str]:
    """Map each named ACL to FROM_DEVICE/TO_DEVICE per RFC 8520's top-level
    from-device-policy/to-device-policy access-list membership -- the ACL
    CONTAINER, not any ietf-mud:direction-initiated field on individual ACEs
    (those describe TCP-connection-initiator, a distinct, per-ACE attribute;
    see the EndpointKey/FROM_DEVICE docstring above). Raises if an ACL name
    is listed under both policies (a self-contradictory reference document)
    -- never silently picks one.
    """
    mud = payload.get("ietf-mud:mud", {})
    direction_map: dict[str, str] = {}
    for policy_key, direction in (("from-device-policy", FROM_DEVICE), ("to-device-policy", TO_DEVICE)):
        acl_list = mud.get(policy_key, {}).get("access-lists", {}).get("access-list", [])
        for entry in acl_list:
            name = entry.get("name")
            if name is None:
                continue
            if name in direction_map and direction_map[name] != direction:
                raise ValueError(
                    f"ACL {name!r} is listed under both from-device-policy and to-device-policy"
                )
            direction_map[name] = direction
    return direction_map


def _mud_endpoints(device_type: str, payload: dict) -> Iterable[EndpointKey]:
    direction_by_acl = _acl_direction_map(payload)
    acls = payload.get("ietf-access-control-list:acls", {}).get("acl", [])
    for acl in acls:
        acl_name = acl.get("name")
        # Fail loudly rather than guessing a direction: an ACL referenced by
        # neither policy list is a malformed/incomplete reference document,
        # and silently defaulting it (e.g. to from-device) would risk
        # reintroducing review finding #4 through a different code path.
        if acl_name not in direction_by_acl:
            raise ValueError(
                f"ACL {acl_name!r} is not listed under from-device-policy or "
                "to-device-policy in this MUD file; cannot determine direction"
            )
        direction = direction_by_acl[acl_name]
        for ace in acl.get("aces", {}).get("ace", []):
            matches = ace.get("matches", {})
            endpoint = _extract_endpoint(matches)
            if endpoint is None:
                continue
            protocol = _extract_protocol(matches)
            port = _extract_port(matches, protocol)
            yield (device_type, direction, endpoint, protocol, port)


def _rule_to_endpoint(device_type: str, rule: object) -> EndpointKey | None:
    """Parse the compact non-ACL ``{"rules": [...]}`` ground-truth format.

    Unlike the MUD/ACL format (_mud_endpoints), this compact format has no
    structural place to encode direction, so it must be given explicitly
    (a 4th list element, or a "direction" dict key) rather than assumed --
    silently defaulting every rule to from-device would misclassify any
    to-device rule expressed this way and reintroduce review finding #4
    through this loader instead. No shipped ground-truth file currently
    uses this format (all UNSW references are ACL-format), so this is
    intentionally unexercised by default -- see test_semantic_matching.py
    for the explicit-direction contract this enforces.
    """
    if isinstance(rule, list) and len(rule) >= 3:
        port = _safe_int(rule[1])
        if len(rule) < 4:
            raise ValueError(
                f"rule {rule!r} has no direction element (expected "
                "[endpoint, port, protocol, direction])"
            )
        direction = _normalize_direction(rule[3])
        return (device_type, direction, str(rule[0]).lower(), normalize_profile_protocol(rule[2], port), port)
    if isinstance(rule, dict):
        endpoint = rule.get("dst_class") or rule.get("dst_dnsname") or rule.get("dst_ip")
        if endpoint:
            if "direction" not in rule:
                raise ValueError(f"rule {rule!r} has no 'direction' key")
            port = _safe_int(rule.get("dst_port", rule.get("port", 0)))
            return (
                device_type,
                _normalize_direction(rule["direction"]),
                str(endpoint).lower(),
                normalize_profile_protocol(rule.get("protocol", "unknown"), port),
                port,
            )
    return None


def _normalize_direction(value: object) -> str:
    text = str(value).strip().lower()
    if text in ("from-device", "from_device", "out"):
        return FROM_DEVICE
    if text in ("to-device", "to_device", "in"):
        return TO_DEVICE
    raise ValueError(f"unrecognized direction {value!r} (expected from-device/to-device)")


def _extract_endpoint(matches: dict) -> str | None:
    ipv4 = matches.get("ipv4", {})
    ipv6 = matches.get("ipv6", {})
    mud = matches.get("mud:controller") or matches.get("ietf-mud:mud", {}).get("controller")
    return (
        ipv4.get("ietf-acldns:dst-dnsname")
        or ipv4.get("destination-ipv4-network")
        or ipv6.get("ietf-acldns:dst-dnsname")
        or ipv6.get("destination-ipv6-network")
        or mud
    )


def _extract_protocol(matches: dict) -> str:
    if "tcp" in matches:
        return "tcp"
    if "udp" in matches:
        return "udp"
    protocol = matches.get("ipv4", {}).get("protocol") or matches.get("ipv6", {}).get("protocol")
    return IP_PROTOCOLS.get(_safe_int(protocol), f"ip-{protocol or 'unknown'}")


def _extract_port(matches: dict, protocol: str) -> int:
    transport = matches.get(protocol, {})
    port = transport.get("destination-port", {}).get("port")
    return _safe_int(port)


def _safe_int(value: object) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def normalize_profile_protocol(value: object, port: int) -> str:
    protocol = str(value).lower()
    if protocol in {"tls", "https", "http"}:
        return "tcp"
    if protocol in {"dns", "ntp", "ssdp", "mdns", "dhcp"}:
        return "udp"
    if protocol == "tcp" or port in {80, 443, 8443}:
        return "tcp"
    if protocol == "udp" or port in {53, 67, 68, 123, 1900, 5353}:
        return "udp"
    return protocol
