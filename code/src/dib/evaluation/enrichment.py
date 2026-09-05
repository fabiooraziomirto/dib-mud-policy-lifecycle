from __future__ import annotations

import bisect
from collections import defaultdict
from dataclasses import dataclass, replace
from datetime import datetime, timedelta

from dib.core.models import Observation

# Evidence types the UNSW adapter attaches at parse time for a *directly observed*
# HTTP Host header or TLS SNI value (see dib.adapters.unsw_iotraffic). Windowed
# backfill only ever draws on these -- never on a previously backfilled row --
# so evidence cannot compound/launder through multiple hops of inference.
DIRECT_FQDN_EVIDENCE_TYPES = {"flow+http_host", "flow+tls_sni"}

DEFAULT_BACKFILL_WINDOW = timedelta(hours=24)


@dataclass(frozen=True, slots=True)
class FqdnEvidence:
    fqdn: str
    timestamp: datetime
    evidence_type: str


@dataclass(frozen=True, slots=True)
class BackfillReport:
    """Traceable breakdown of what the windowed backfill did and did not resolve."""

    total_ip_only: int
    resolved_within_window: int
    evidence_outside_window: int
    no_evidence_this_site: int
    no_evidence_any_site: int

    def to_dict(self) -> dict[str, int]:
        return {
            "ip_only_endpoints": self.total_ip_only,
            "resolved_within_window": self.resolved_within_window,
            "evidence_outside_window": self.evidence_outside_window,
            "no_evidence_this_site": self.no_evidence_this_site,
            "no_evidence_any_site": self.no_evidence_any_site,
        }


def build_site_ip_fqdn_index(
    observations: list[Observation],
) -> dict[tuple[str, str], list[FqdnEvidence]]:
    """(site_id, remote_ip) -> directly-observed FQDN evidence, sorted by time.

    Scoped per site: the same IP can serve different hostnames at different
    sites (shared CDN/cloud edge), so evidence is never pooled across sites.
    """
    index: dict[tuple[str, str], list[FqdnEvidence]] = defaultdict(list)
    for obs in observations:
        if obs.fqdn and obs.remote_ip and obs.evidence_type in DIRECT_FQDN_EVIDENCE_TYPES:
            index[(obs.site_id, obs.remote_ip)].append(
                FqdnEvidence(obs.fqdn, obs.timestamp, obs.evidence_type)
            )
    for evidence_list in index.values():
        evidence_list.sort(key=lambda e: e.timestamp)
    return index


def build_ip_fqdn_index(observations: list[Observation]) -> dict[str, str]:
    """Map remote_ip -> fqdn using only real evidence already present in the dataset
    (HTTP Host / TLS SNI observed for that IP by *any* device, at *any* time).
    """
    index: dict[str, str] = {}
    for obs in observations:
        if obs.fqdn and obs.remote_ip and obs.remote_ip not in index:
            index[obs.remote_ip] = obs.fqdn
    return index


def backfill_fqdn(observations: list[Observation]) -> list[Observation]:
    """Fill in `fqdn` for observations that only carry a remote_ip, by reusing FQDN
    evidence observed for that same IP elsewhere in the dataset (cross-device/cross-time
    corroboration of IP identity). Does not invent any hostname not already present
    in the real observations; only joins existing evidence across rows.
    """
    index = build_ip_fqdn_index(observations)
    enriched: list[Observation] = []
    for obs in observations:
        if obs.fqdn or not obs.remote_ip:
            enriched.append(obs)
            continue
        fqdn = index.get(obs.remote_ip)
        if fqdn is None:
            enriched.append(obs)
            continue
        enriched.append(replace(obs, fqdn=fqdn, evidence_type=f"{obs.evidence_type}+ip_backfill"))
    return enriched


def _nearest_within_window(
    evidence: list[FqdnEvidence], timestamps: list[datetime], target: datetime, window: timedelta
) -> FqdnEvidence | None:
    """Nearest-in-time evidence to `target`, or None if none falls within `window`.

    `timestamps` must be `[e.timestamp for e in evidence]`, precomputed once per
    (site, IP) by the caller -- rebuilding it per observation made this quadratic
    on IPs with a lot of evidence.

    Ties (equal distance) resolve to the earlier evidence, so the choice is a
    deterministic function of the input rows regardless of iteration order.
    """
    if not evidence:
        return None
    pos = bisect.bisect_left(timestamps, target)
    candidates = [c for c in (pos - 1, pos) if 0 <= c < len(evidence)]
    if not candidates:
        return None
    best = min(
        candidates,
        key=lambda i: (abs(evidence[i].timestamp - target), evidence[i].timestamp),
    )
    if abs(evidence[best].timestamp - target) > window:
        return None
    return evidence[best]


def backfill_fqdn_windowed(
    observations: list[Observation],
    *,
    window: timedelta = DEFAULT_BACKFILL_WINDOW,
) -> tuple[list[Observation], BackfillReport]:
    """Site-scoped, time-windowed FQDN backfill from real HTTP-Host/TLS-SNI evidence.

    Differs from `backfill_fqdn` in three ways, each a documented judgement call
    (see reports/step1a_unsw_backfill.md):

    - Site-scoped: evidence from site A is never used to name an IP seen at site B
      (the same raw IP, e.g. a CDN edge, can serve a different hostname elsewhere).
    - Time-windowed: an IP-only observation only borrows a name from HTTP/TLS
      evidence for the *same* (site, IP) that falls within `window` of its own
      timestamp -- not from evidence recorded arbitrarily far away in time, so a
      later re-assignment of that IP to a different service cannot leak backwards.
    - Nearest-in-time selection when multiple distinct hostnames are seen for the
      same (site, IP): picks the evidence closest in time to the flow being named,
      not "first seen" or "most recent overall".

    Only ever draws on directly-observed evidence (`DIRECT_FQDN_EVIDENCE_TYPES`),
    never on a previously-backfilled row, so no transitive/laundered attribution.
    """
    index = build_site_ip_fqdn_index(observations)
    timestamps_by_key = {key: [e.timestamp for e in ev] for key, ev in index.items()}
    any_site_ips: set[str] = {ip for (_site, ip) in index}

    enriched: list[Observation] = []
    resolved = 0
    evidence_outside_window = 0
    no_evidence_this_site = 0
    no_evidence_any_site = 0
    total_ip_only = 0

    for obs in observations:
        if obs.fqdn or not obs.remote_ip:
            enriched.append(obs)
            continue
        total_ip_only += 1
        key = (obs.site_id, obs.remote_ip)
        candidates = index.get(key, [])
        best = _nearest_within_window(candidates, timestamps_by_key.get(key, []), obs.timestamp, window)
        if best is not None:
            enriched.append(
                replace(
                    obs,
                    fqdn=best.fqdn,
                    evidence_type=f"{obs.evidence_type}+ip_backfill_windowed:{best.evidence_type}",
                )
            )
            resolved += 1
            continue

        enriched.append(obs)
        if candidates:
            evidence_outside_window += 1
        elif obs.remote_ip in any_site_ips:
            no_evidence_this_site += 1
        else:
            no_evidence_any_site += 1

    report = BackfillReport(
        total_ip_only=total_ip_only,
        resolved_within_window=resolved,
        evidence_outside_window=evidence_outside_window,
        no_evidence_this_site=no_evidence_this_site,
        no_evidence_any_site=no_evidence_any_site,
    )
    return enriched, report
