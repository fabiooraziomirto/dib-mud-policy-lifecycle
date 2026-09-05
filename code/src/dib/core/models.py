from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True, slots=True)
class Observation:
    """Normalized endpoint observation used across the DIB pipeline."""

    site_id: str
    device_id: str | None
    device_type: str
    fqdn: str | None
    remote_ip: str | None
    protocol: str
    port: int
    timestamp: datetime
    source_dataset: str
    evidence_type: str
    # True iff the remote endpoint sent packets back on this device-initiated flow
    # (e.g. UNSW dstNumPackets > 0). Absent/False for older CSVs and for any flow
    # the remote itself initiated -- see dib.adapters.unsw_iotraffic.
    response_observed: bool = False
    # "out": the device itself initiated this flow (srcIp == device_ip in the
    # source trace) -- the only direction any current adapter emits, since
    # each adapter keeps only device-initiated flows (see e.g.
    # dib.adapters.unsw_iotraffic.iter_flow_observations's `srcIp != device_ip`
    # filter). "in": the remote side initiated the flow. No shipped adapter
    # currently distinguishes remote-initiated traffic from a device-initiated
    # flow's own reply packets (response_observed already covers that case);
    # "in" is a real, valid value the schema supports for future traces that
    # do carry standalone remote-initiated flows, not a value any adapter
    # emits today. Do not infer "in" from response_observed -- that flag
    # describes packets returned on an out-direction flow, not a second,
    # independently-initiated flow.
    direction: str = "out"

    def __post_init__(self) -> None:
        if self.direction not in ("in", "out"):
            raise ValueError(f"direction must be 'in' or 'out', got {self.direction!r}")

    @property
    def endpoint_key(self) -> tuple[str, str, str, int]:
        endpoint = self.fqdn or self.remote_ip
        if not endpoint:
            raise ValueError("observation requires fqdn or remote_ip for endpoint scoring")
        return (self.device_type, endpoint.lower(), self.protocol.lower(), self.port)

    @classmethod
    def from_dict(cls, row: dict[str, object]) -> "Observation":
        timestamp = _parse_timestamp(str(row["timestamp"]))
        return cls(
            site_id=str(row["site_id"]),
            device_id=_optional(row.get("device_id")),
            device_type=str(row["device_type"]),
            fqdn=_optional(row.get("fqdn")),
            remote_ip=_optional(row.get("remote_ip")),
            protocol=str(row["protocol"]).lower(),
            port=int(row["port"]),
            timestamp=timestamp,
            source_dataset=str(row["source_dataset"]),
            evidence_type=str(row["evidence_type"]),
            response_observed=_parse_bool(row.get("response_observed")),
            direction=str(row["direction"]) if row.get("direction") else "out",
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "site_id": self.site_id,
            "device_id": self.device_id or "",
            "device_type": self.device_type,
            "fqdn": self.fqdn or "",
            "remote_ip": self.remote_ip or "",
            "protocol": self.protocol,
            "port": self.port,
            "timestamp": self.timestamp.astimezone(timezone.utc).isoformat(),
            "source_dataset": self.source_dataset,
            "evidence_type": self.evidence_type,
            "response_observed": self.response_observed,
            "direction": self.direction,
        }


@dataclass(frozen=True, slots=True)
class EndpointScore:
    device_type: str
    endpoint: str
    protocol: str
    port: int
    site_confidence: float
    temporal_confidence: float
    graph_confidence: float
    score: float
    accepted: bool
    supporting_sites: int
    eligible_sites: int
    endpoint_class: str = "other"

    @property
    def endpoint_key(self) -> tuple[str, str, str, int]:
        return (self.device_type, self.endpoint, self.protocol, self.port)

    def to_dict(self) -> dict[str, object]:
        return {
            "device_type": self.device_type,
            "endpoint": self.endpoint,
            "protocol": self.protocol,
            "port": self.port,
            "site_confidence": round(self.site_confidence, 6),
            "temporal_confidence": round(self.temporal_confidence, 6),
            "graph_confidence": round(self.graph_confidence, 6),
            "score": round(self.score, 6),
            "accepted": self.accepted,
            "supporting_sites": self.supporting_sites,
            "eligible_sites": self.eligible_sites,
            "endpoint_class": self.endpoint_class,
            # "from-device" for every row: every current adapter only ever
            # emits Observation(direction="out") rows (device-initiated
            # flows), so every EndpointScore this codebase produces is,
            # today, unconditionally a from-device fact. Kept as a literal
            # here (not imported from dib.evaluation.profiles.
            # PREDICTED_DIRECTION) to avoid a core -> evaluation import;
            # see that constant's docstring for the single source of this
            # assumption and what must change if it is ever violated. This
            # column exists (added 2026-07-24, review finding #4) so CSVs
            # written by this dataclass are directly loadable by
            # dib.evaluation.profiles.load_dib_scores(), which requires it.
            "direction": "from-device",
        }


REQUIRED_OBSERVATION_COLUMNS = {
    "site_id",
    "device_type",
    "protocol",
    "port",
    "timestamp",
    "source_dataset",
    "evidence_type",
}


def endpoint_to_string(key: tuple[str, str, str, int]) -> str:
    device_type, endpoint, protocol, port = key
    return f"{device_type}|{endpoint}|{protocol}|{port}"


def endpoint_from_string(value: str) -> tuple[str, str, str, int]:
    device_type, endpoint, protocol, port = value.split("|", 3)
    return (device_type, endpoint, protocol, int(port))


def _optional(value: object | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _parse_bool(value: object | None) -> bool:
    if value is None:
        return False
    return str(value).strip().lower() in {"true", "1", "yes"}


def _parse_timestamp(value: str) -> datetime:
    cleaned = value.strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(cleaned)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
