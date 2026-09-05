from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from dib.core.io import write_json
from dib.core.models import EndpointScore, Observation

# RFC 8520 ACEs are portable only for TCP/UDP; DIB observations carry an
# application-layer protocol label rather than an IANA transport number.
_TRANSPORT_BY_PROTOCOL = {
    "tcp": (6, "tcp"),
    "http": (6, "tcp"),
    "https": (6, "tcp"),
    "tls": (6, "tcp"),
    "syslog": (6, "tcp"),
    "mqtt": (6, "tcp"),
    "udp": (17, "udp"),
    "dns": (17, "udp"),
    "dhcp": (17, "udp"),
    "ntp": (17, "udp"),
}


@dataclass
class MudExportResult:
    device_type: str
    document: dict
    exported_endpoints: list[EndpointScore]
    skipped_endpoints: list[EndpointScore]
    to_device_endpoints: list[EndpointScore] = field(default_factory=list)

    @property
    def exported_ace_count(self) -> int:
        return len(self.exported_endpoints)

    @property
    def to_device_ace_count(self) -> int:
        return len(self.to_device_endpoints)


def response_leg_endpoint_keys(observations: Iterable[Observation]) -> set[tuple[str, str, str, int]]:
    """Endpoint keys with an observed response leg (dib.core.models.Observation.response_observed).

    Used to decide which accepted, exported from-device endpoints also get a
    to-device ACE for the return traffic of that same device-initiated session.
    Never used to accept an endpoint the scorer rejected: this only annotates
    endpoints already present in `scores`. Restricted to direction="out"
    observations: a response leg is only meaningful for a flow the device
    itself initiated (see Observation.direction's docstring) -- no shipped
    adapter currently emits direction="in" rows, but this guards against
    misclassifying one as a from-device session's reply if one ever does.
    """
    return {obs.endpoint_key for obs in observations if obs.direction == "out" and obs.response_observed}


def export_mud_file(
    device_type: str,
    scores: list[EndpointScore],
    mud_url: str | None = None,
    response_leg_endpoints: set[tuple[str, str, str, int]] | None = None,
) -> MudExportResult:
    """Emit an RFC 8520 MUD file for a device type's DIB-accepted endpoints.

    from-device-policy ACEs are populated for every exported endpoint.
    to-device-policy ACEs are populated only for the subset of those endpoints
    with an observed response leg (`response_leg_endpoints`, from
    `Observation.response_observed`) -- i.e. traffic returned on a connection
    the device itself opened. DIB does not observe or accept connections the
    remote side initiated, so to-device-policy never expresses more than the
    return leg of an already from-device-accepted endpoint; this is narrower
    than general bidirectional accept. Endpoints are skipped, not guessed, when
    their protocol label has no portable TCP/UDP mapping, or when the
    endpoint is an IP literal rather than an FQDN: RFC 8520 ietf-acldns
    matches are DNS-name matches, and emitting one against a raw IP (e.g. a
    LAN resolver address DIB saw because no reverse FQDN was available) would
    be semantically wrong and, for a DNS-based MUD manager, silently
    unenforceable.
    """
    accepted = [score for score in scores if score.device_type == device_type and score.accepted]
    slug = _slugify(device_type)
    url = mud_url or f"https://dib.example.org/.well-known/mud/{slug}"
    response_leg_endpoints = response_leg_endpoints or set()

    exported: list[EndpointScore] = []
    to_device: list[EndpointScore] = []
    skipped: list[EndpointScore] = []
    from_aces = []
    to_aces = []
    for index, score in enumerate(sorted(accepted, key=lambda item: (item.endpoint, item.protocol, item.port))):
        transport = _TRANSPORT_BY_PROTOCOL.get(score.protocol.lower())
        if transport is None or _is_ip_literal(score.endpoint):
            skipped.append(score)
            continue
        exported.append(score)
        iana_protocol, l4_key = transport
        from_aces.append(
            {
                "rule-name": f"dib-{slug}-fr-{index}",
                "matches": {
                    "ipv4": {
                        "ietf-acldns:dst-dnsname": score.endpoint,
                        "protocol": iana_protocol,
                    },
                    l4_key: {
                        "destination-port-range-or-operator": {"operator": "eq", "port": score.port},
                        "ietf-mud:direction-initiated": "from-device",
                    },
                },
                "actions": {"forwarding": "accept"},
            }
        )

        normalized_key = (score.device_type, score.endpoint.lower(), score.protocol.lower(), score.port)
        if normalized_key not in response_leg_endpoints:
            continue
        to_device.append(score)
        to_aces.append(
            {
                "rule-name": f"dib-{slug}-to-{index}",
                "matches": {
                    "ipv4": {
                        "ietf-acldns:src-dnsname": score.endpoint,
                        "protocol": iana_protocol,
                    },
                    l4_key: {
                        "source-port-range-or-operator": {"operator": "eq", "port": score.port},
                        "ietf-mud:direction-initiated": "from-device",
                    },
                },
                "actions": {"forwarding": "accept"},
            }
        )

    document = {
        "ietf-mud:mud": {
            "mud-version": 1,
            "mud-url": url,
            "last-update": datetime.now(timezone.utc).isoformat(),
            "cache-validity": 48,
            "is-supported": True,
            "systeminfo": f"DIB corroborated policy for {device_type}",
            "from-device-policy": {"access-lists": {"access-list": [{"name": f"dib-{slug}-fr"}]}},
            "to-device-policy": {"access-lists": {"access-list": [{"name": f"dib-{slug}-to"}]}},
        },
        "ietf-access-control-list:access-lists": {
            "acl": [
                {"name": f"dib-{slug}-fr", "acl-type": "ipv4-acl-type", "aces": {"ace": from_aces}},
                {"name": f"dib-{slug}-to", "acl-type": "ipv4-acl-type", "aces": {"ace": to_aces}},
            ]
        },
    }
    return MudExportResult(
        device_type=device_type,
        document=document,
        exported_endpoints=exported,
        skipped_endpoints=skipped,
        to_device_endpoints=to_device,
    )


def write_mud_file(path: Path, result: MudExportResult) -> None:
    write_json(path, result.document)


def _slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _is_ip_literal(value: str) -> bool:
    # Some observations key the endpoint as "ip:port" (e.g. a LAN gateway address);
    # strip a trailing ":<port>" before the IP-literal check so those are caught too.
    head, sep, tail = value.rpartition(":")
    candidate = head if sep and tail.isdigit() else value
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False
