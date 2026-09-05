"""Cross-organisational intent overlap: how much of a device's endpoint set
two REAL, independently captured organisations actually agree on, before any
scoring happens. This is a claim about the data, not about DIB, and is
reported as its own result: corroboration only helps if independent
observers' endpoints actually overlap, which is an empirical question, not
an assumption to wave through.

Endpoints are split into "core" (DNS/NTP/update/vendor-cloud infrastructure
-- a device's fixed-function backend, expected to be near-universal across
deployments) vs. the rest (comparatively idiosyncratic per-deployment
traffic: LAN discovery/broadcast protocols, CDN edges that vary by region,
etc.). This split is a documented judgement call based on protocol/port and
FQDN keyword heuristics, not a ground-truth label; see `classify_core`.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from itertools import combinations
from typing import Iterable

import tldextract

from dib.core.models import Observation

EndpointKey = tuple[str, str, str, int]  # (device_type, endpoint, protocol, port)

# Granularities for cross-org overlap measurement, from finest to coarsest.
# "asn" is deliberately absent: no offline IP->ASN mapping is available in
# this environment (checked: no GeoIP/MaxMind/IP2ASN database on disk, and
# fabricating one is out of scope) -- callers must not silently substitute
# a different granularity for it.
GRANULARITIES = ("exact", "etld1", "service_class")

_etld_extractor = tldextract.TLDExtract()  # cached locally after first use, no repeat network access


def etld1_of(endpoint: str) -> str:
    """Registrable domain (eTLD+1) for an FQDN, e.g. "www.meethue.com" ->
    "meethue.com", "foo.s3.amazonaws.com" -> "amazonaws.com" (amazonaws.com
    is not in the public suffix list, so this is intentionally coarse for
    multi-tenant cloud domains -- see the reachability-cone measurement in
    scripts/real_federation_etld1_scoring.py for exactly this cost).

    IP literals have no registrable domain: returns the literal unchanged,
    so grouping by eTLD+1 never merges two different raw IPs together
    (there is no ASN mapping available to do that safely -- see
    GRANULARITIES's docstring note).
    """
    if _looks_like_ip(endpoint):
        return endpoint
    result = _etld_extractor(endpoint)
    if not result.suffix:
        return endpoint
    return f"{result.domain}.{result.suffix}"


def key_at_granularity(key: EndpointKey, granularity: str) -> tuple:
    """Reduce one EndpointKey to the identity used at a coarser granularity
    for overlap/corroboration purposes. "exact" is a no-op; "etld1" replaces
    the endpoint with its registrable domain (port/protocol still
    distinguish, so two services on the same domain at different ports
    remain distinct groups); "service_class" collapses to
    (device_type, classify_core(...)) only -- protocol/port/identity are
    deliberately dropped, since "same service class" is the coarsest
    question this module asks (does this org talk to ANY DNS/update/
    vendor-cloud endpoint for this device, at all).
    """
    device_type, endpoint, protocol, port = key
    if granularity == "exact":
        return key
    if granularity == "etld1":
        return (device_type, etld1_of(endpoint), protocol, port)
    if granularity == "service_class":
        return (device_type, classify_core(endpoint, protocol, port))
    raise ValueError(f"unknown granularity: {granularity!r} (expected one of {GRANULARITIES})")

_UPDATE_KEYWORDS = ("update", "upgrade", "firmware", "ota", "fw.", "-fw", "swupdate")


def classify_core(endpoint: str, protocol: str, port: int) -> str:
    """Classify one endpoint into "dns" / "ntp" / "update" / "vendor-cloud" /
    "other". A documented heuristic, not ground truth:

    - "other": private, reserved, and link-local IP literals; this address-
      scope veto precedes the service tests below.
    - "dns": protocol is dns, or port 53.
    - "ntp": protocol is ntp, or port 123.
    - "update": FQDN contains an update/firmware keyword (_UPDATE_KEYWORDS).
    - "vendor-cloud": has a resolved FQDN and isn't classified above --
      the large majority of named endpoints in these corpora are
      manufacturer API/cloud backends, not literal CDN infrastructure.
    - "other": IP-literal with no FQDN, or a protocol/port that is neither
      infrastructure nor a named service (broadcast/discovery chatter such
      as SSDP/mDNS/LLDP, local-network traffic).
    """
    protocol = protocol.lower()
    parsed_ip = _parse_ip_literal(endpoint)
    if parsed_ip is not None and not parsed_ip.is_global:
        return "other"
    if protocol == "dns" or port == 53:
        return "dns"
    if protocol == "ntp" or port == 123:
        return "ntp"
    is_fqdn = not _looks_like_ip(endpoint)
    if is_fqdn and any(keyword in endpoint.lower() for keyword in _UPDATE_KEYWORDS):
        return "update"
    if is_fqdn:
        return "vendor-cloud"
    return "other"


def _looks_like_ip(value: str) -> bool:
    return _parse_ip_literal(value) is not None


def _parse_ip_literal(value: str):
    import ipaddress

    candidate = value.strip()
    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1:candidate.index("]")]
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        if candidate.count(":") == 1:
            head, tail = candidate.rsplit(":", 1)
            if tail.isdigit():
                try:
                    return ipaddress.ip_address(head)
                except ValueError:
                    pass
        return None


def endpoint_sets_by_org(
    observations: Iterable[Observation], device_type: str
) -> dict[str, set[EndpointKey]]:
    """org (site_id) -> set of endpoint_key for one device_type."""
    result: dict[str, set[EndpointKey]] = defaultdict(set)
    for obs in observations:
        if obs.device_type != device_type:
            continue
        result[obs.site_id].add(obs.endpoint_key)
    return dict(result)


def jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    union = len(a | b)
    return len(a & b) / union if union else 0.0


@dataclass(frozen=True, slots=True)
class OrgPairOverlap:
    device_type: str
    org_a: str
    org_b: str
    jaccard_all: float
    jaccard_core: float
    jaccard_fqdn_only: float
    org_a_size: int
    org_b_size: int
    org_a_core_size: int
    org_b_core_size: int
    org_a_fqdn_size: int
    org_b_fqdn_size: int
    intersection_all: int
    intersection_core: int


def pairwise_org_overlap(
    endpoint_sets: dict[str, set[EndpointKey]], device_type: str
) -> list[OrgPairOverlap]:
    """All-pairs Jaccard overlap (total, core-only, and FQDN-only) across the
    orgs hosting one device_type.

    Core-only Jaccard restricts BOTH sets to their core-classified endpoints
    before comparing, so it answers "of the fixed-function backend traffic,
    how much do independent orgs agree on?" separately from raw endpoint-set
    overlap.

    FQDN-only Jaccard additionally restricts to endpoints with a resolved
    FQDN (excludes bare IP literals) on both sides. FQDN resolution rate
    varies sharply and unevenly across these corpora (as low as ~1--5% for
    some Mon(IoT)r capture trees on some devices) -- comparing raw IPs
    across genuinely different networks conflates "different real endpoint"
    with "same service, different regional/CDN address, never resolved to a
    name," understating true semantic overlap. FQDN-only Jaccard isolates
    the less-confounded signal at the cost of a much smaller, possibly
    unrepresentative sample; both should be read together, not either alone.
    """
    rows = []
    orgs = sorted(endpoint_sets)
    for org_a, org_b in combinations(orgs, 2):
        set_a, set_b = endpoint_sets[org_a], endpoint_sets[org_b]
        core_a = {key for key in set_a if classify_core(key[1], key[2], key[3]) in ("dns", "ntp", "update", "vendor-cloud")}
        core_b = {key for key in set_b if classify_core(key[1], key[2], key[3]) in ("dns", "ntp", "update", "vendor-cloud")}
        fqdn_a = {key for key in set_a if not _looks_like_ip(key[1])}
        fqdn_b = {key for key in set_b if not _looks_like_ip(key[1])}
        rows.append(
            OrgPairOverlap(
                device_type=device_type,
                org_a=org_a,
                org_b=org_b,
                jaccard_all=round(jaccard(set_a, set_b), 6),
                jaccard_core=round(jaccard(core_a, core_b), 6),
                jaccard_fqdn_only=round(jaccard(fqdn_a, fqdn_b), 6),
                org_a_size=len(set_a),
                org_b_size=len(set_b),
                org_a_core_size=len(core_a),
                org_b_core_size=len(core_b),
                org_a_fqdn_size=len(fqdn_a),
                org_b_fqdn_size=len(fqdn_b),
                intersection_all=len(set_a & set_b),
                intersection_core=len(core_a & core_b),
            )
        )
    return rows


@dataclass(frozen=True, slots=True)
class GranularityOverlap:
    device_type: str
    granularity: str
    org_a: str
    org_b: str
    jaccard: float
    org_a_size: int
    org_b_size: int
    intersection: int


def pairwise_org_overlap_at_granularity(
    endpoint_sets: dict[str, set[EndpointKey]], device_type: str, granularity: str
) -> list[GranularityOverlap]:
    """All-pairs Jaccard overlap across orgs hosting one device_type, with
    both sides' endpoint sets reduced to `granularity` (GRANULARITIES) before
    comparing. This answers "how much do independent orgs agree on, if we
    stop discriminating below this level of detail?" -- the coarser the
    granularity, the more two orgs' genuinely different literal endpoints
    can collapse into "the same" group, which is the entire point of
    measuring the curve across granularities rather than trusting exact-key
    Jaccard alone.
    """
    rows = []
    orgs = sorted(endpoint_sets)
    for org_a, org_b in combinations(orgs, 2):
        set_a = {key_at_granularity(key, granularity) for key in endpoint_sets[org_a]}
        set_b = {key_at_granularity(key, granularity) for key in endpoint_sets[org_b]}
        rows.append(
            GranularityOverlap(
                device_type=device_type,
                granularity=granularity,
                org_a=org_a,
                org_b=org_b,
                jaccard=round(jaccard(set_a, set_b), 6),
                org_a_size=len(set_a),
                org_b_size=len(set_b),
                intersection=len(set_a & set_b),
            )
        )
    return rows
