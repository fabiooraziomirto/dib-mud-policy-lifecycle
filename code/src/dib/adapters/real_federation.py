"""A federation of REAL administrative domains, not a synthetic split of one
corpus. Each "site" is one independently captured corpus (or Mon(IoT)r
capture tree): UNSW-IoTraffic, four Mon(IoT)r capture trees, and YourThings.

This directly answers the reviewer objection that the paper's main
federation evidence (a random 10-way split of one UNSW capture) is IID noise
by construction, which is exactly why corroboration looks easy there. Only
device types observed in >=2 of these real corpora are in scope -- there is
no cross-site claim to make about a device only one org happens to own.

Honesty about independence, stated once here rather than re-litigated at
every call site: Mon(IoT)r's `us`/`us-vpn` capture trees are the SAME
physical device population routed two different ways, and so are
`uk`/`uk-vpn` -- confirmed empirically (identical device_type sets, 48 and
37 respectively). They are not independent organisations, only different
network paths for one deployment. This module still labels all four capture
trees as separate ORG_LABELS entries, matching how they're used for scoring
throughout this paper (dib.experiments.management_attack,
scripts/cross_site_heterogeneity_moniotr.py already treat capture trees as
distinct "sites"), but any claim about *organisational* independence
(dib.evaluation.intent_overlap) must collapse `us`+`us-vpn` and
`uk`+`uk-vpn` before counting orgs, or it silently reproduces the same
non-independence critique this module exists to answer.

RAM discipline: source corpora total ~850MB / ~6.4M rows
(moniotr_full_observations.csv alone is 4.16M rows). This module never
materializes an unfiltered corpus as Observation objects -- it filters by
canonical device type at raw-CSV-row granularity while streaming, before
any Observation is constructed, so peak memory scales with the retained
(overlap-device-only) row count, not the source corpus size.
"""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable

from dib.core.models import Observation
from dib.evaluation.profiles import canonical_device_name

# Real administrative domains, per the user-specified mapping. moniotr-us and
# moniotr-us-vpn (respectively moniotr-uk / moniotr-uk-vpn) are the same
# device population -- see module docstring -- kept as distinct ORG_LABELS
# entries because that is how every other experiment in this paper treats
# Mon(IoT)r capture trees, not because they are independently operated.
ORG_LABELS = {
    "unsw": "org_A_unsw",
    "moniotr-us": "org_B_moniotr_us",
    "moniotr-uk": "org_C_moniotr_uk",
    "moniotr-us-vpn": "org_D_moniotr_usvpn",
    "moniotr-uk-vpn": "org_E_moniotr_ukvpn",
    "yourthings": "org_F_yourthings",
}

# Orgs that are NOT independent of another org in this mapping (same
# physical device population, different network path). Used by
# dib.evaluation.intent_overlap to avoid double-counting non-independent
# agreement as cross-organisational evidence.
NON_INDEPENDENT_PAIRS = (
    ("org_B_moniotr_us", "org_D_moniotr_usvpn"),
    ("org_C_moniotr_uk", "org_E_moniotr_ukvpn"),
)


def find_overlap_devices(
    unsw_path: Path,
    moniotr_path: Path,
    yourthings_path: Path,
    min_independent_orgs: int = 2,
) -> dict[str, set[str]]:
    """Canonical device_type -> set of ORG_LABELS values that host it,
    restricted to devices reaching ``min_independent_orgs`` INDEPENDENT orgs
    (moniotr-us/us-vpn count as one for this threshold, likewise uk/uk-vpn,
    per NON_INDEPENDENT_PAIRS) -- so a device present only at
    moniotr-us+moniotr-us-vpn does not qualify, since that is one real
    deployment observed twice, not two.

    Reads only the device_type and site columns of each source file (or
    infers a constant site label for single-site corpora), never
    materializing full rows.
    """
    presence: dict[str, set[str]] = {}

    with unsw_path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            device = canonical_device_name(row["device_type"])
            presence.setdefault(device, set()).add(ORG_LABELS["unsw"])

    with moniotr_path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            device = canonical_device_name(row["device_type"])
            org = ORG_LABELS.get(row["site_id"])
            if org:
                presence.setdefault(device, set()).add(org)

    with yourthings_path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            device = canonical_device_name(row["device_type"])
            presence.setdefault(device, set()).add(ORG_LABELS["yourthings"])

    def independent_org_count(orgs: set[str]) -> int:
        collapsed = set(orgs)
        for a, b in NON_INDEPENDENT_PAIRS:
            if a in collapsed and b in collapsed:
                collapsed.discard(b)
        return len(collapsed)

    return {
        device: orgs
        for device, orgs in presence.items()
        if independent_org_count(orgs) >= min_independent_orgs
    }


def iter_federation_observations(
    unsw_path: Path,
    moniotr_path: Path,
    yourthings_path: Path,
    overlap_devices: set[str],
) -> Iterable[Observation]:
    """Stream all three corpora, filtering to ``overlap_devices`` (canonical
    names) at raw-row granularity and relabelling site_id to ORG_LABELS,
    before constructing any Observation. Device_type on the yielded
    Observation is always the canonical name, so the same device from
    different corpora's differently-spelled raw strings lines up as one key.
    """
    with unsw_path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            device = canonical_device_name(row["device_type"])
            if device not in overlap_devices:
                continue
            row = dict(row)
            row["device_type"] = device
            row["site_id"] = ORG_LABELS["unsw"]
            yield Observation.from_dict(row)

    with moniotr_path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            device = canonical_device_name(row["device_type"])
            if device not in overlap_devices:
                continue
            org = ORG_LABELS.get(row["site_id"])
            if org is None:
                continue
            row = dict(row)
            row["device_type"] = device
            row["site_id"] = org
            yield Observation.from_dict(row)

    with yourthings_path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            device = canonical_device_name(row["device_type"])
            if device not in overlap_devices:
                continue
            row = dict(row)
            row["device_type"] = device
            row["site_id"] = ORG_LABELS["yourthings"]
            yield Observation.from_dict(row)
