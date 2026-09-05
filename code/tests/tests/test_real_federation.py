from __future__ import annotations

import csv
from pathlib import Path

from dib.adapters.real_federation import (
    NON_INDEPENDENT_PAIRS,
    ORG_LABELS,
    find_overlap_devices,
    iter_federation_observations,
)


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    unsw = tmp_path / "unsw.csv"
    moniotr = tmp_path / "moniotr.csv"
    yourthings = tmp_path / "yourthings.csv"

    base = {
        "device_id": "dev1", "fqdn": "api.example.com", "remote_ip": "",
        "protocol": "https", "port": "443", "timestamp": "2026-01-01T00:00:00+00:00",
        "source_dataset": "unit", "evidence_type": "flow",
    }
    fields = ["site_id", "device_id", "device_type", "fqdn", "remote_ip", "protocol", "port", "timestamp", "source_dataset", "evidence_type"]

    _write_csv(unsw, fields, [
        {**base, "site_id": "unsw-iotraffic-2025", "device_type": "PhilipsHue"},
        {**base, "site_id": "unsw-iotraffic-2025", "device_type": "OnlyInUnsw"},
    ])
    _write_csv(moniotr, fields, [
        {**base, "site_id": "moniotr-us", "device_type": "philips-hue"},
        {**base, "site_id": "moniotr-us-vpn", "device_type": "philips-hue"},
        {**base, "site_id": "moniotr-uk", "device_type": "philips-hue"},
        {**base, "site_id": "moniotr-us", "device_type": "only-moniotr-pair"},
        {**base, "site_id": "moniotr-us-vpn", "device_type": "only-moniotr-pair"},
    ])
    _write_csv(yourthings, fields, [
        {**base, "site_id": "yourthings-gatech-20180321", "device_type": "philips-hue"},
    ])
    return unsw, moniotr, yourthings


def test_find_overlap_devices_requires_independent_orgs(tmp_path: Path) -> None:
    unsw, moniotr, yourthings = _fixture(tmp_path)
    overlap = find_overlap_devices(unsw, moniotr, yourthings)

    # philips-hue: UNSW + moniotr-us(+vpn twin, collapsed) + moniotr-uk + yourthings
    # = 4 independent orgs, well above the default threshold of 2.
    assert "philips-hue" in overlap
    assert overlap["philips-hue"] == {
        ORG_LABELS["unsw"], ORG_LABELS["moniotr-us"], ORG_LABELS["moniotr-us-vpn"],
        ORG_LABELS["moniotr-uk"], ORG_LABELS["yourthings"],
    }

    # only-moniotr-pair: present only at moniotr-us and moniotr-us-vpn, which
    # are the SAME device population (a NON_INDEPENDENT_PAIRS entry) -> only
    # 1 independent org -> must NOT qualify at the default threshold of 2.
    assert "only-moniotr-pair" not in overlap

    # devices present in only one org anywhere don't qualify either.
    assert "OnlyInUnsw" not in overlap


def test_iter_federation_observations_relabels_site_and_canonicalizes_device(tmp_path: Path) -> None:
    unsw, moniotr, yourthings = _fixture(tmp_path)
    overlap = find_overlap_devices(unsw, moniotr, yourthings)
    observations = list(iter_federation_observations(unsw, moniotr, yourthings, {"philips-hue"}))

    assert all(o.device_type == "philips-hue" for o in observations)
    sites = {o.site_id for o in observations}
    assert sites == {
        ORG_LABELS["unsw"], ORG_LABELS["moniotr-us"], ORG_LABELS["moniotr-us-vpn"],
        ORG_LABELS["moniotr-uk"], ORG_LABELS["yourthings"],
    }
    # devices outside the requested overlap set are excluded entirely.
    assert all(o.device_type != "OnlyInUnsw" for o in observations)


def test_non_independent_pairs_are_the_declared_vpn_twins() -> None:
    assert (ORG_LABELS["moniotr-us"], ORG_LABELS["moniotr-us-vpn"]) in NON_INDEPENDENT_PAIRS
    assert (ORG_LABELS["moniotr-uk"], ORG_LABELS["moniotr-uk-vpn"]) in NON_INDEPENDENT_PAIRS
