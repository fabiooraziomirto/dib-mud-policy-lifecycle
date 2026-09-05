"""Task 1/2: re-measure cross-org intent overlap at increasing granularity,
testing the hypothesis that T2's near-zero Jaccard (0.006) is measured at
the wrong granularity -- two independently operated Philips Hue deployments
may both talk to Philips' infrastructure while resolving to different
regional FQDNs/IPs, which exact-endpoint Jaccard cannot see.

Granularities (dib.evaluation.intent_overlap.GRANULARITIES):
  a. exact   -- (endpoint, protocol, port) as observed. Baseline, from T2: 0.006.
  b. etld1   -- endpoint reduced to its registrable domain (eTLD+1) via the
                public suffix list (tldextract), e.g. eu.meethue.com and
                us.meethue.com both become meethue.com. IP literals are left
                unchanged (no ASN mapping available -- see next point).
  c. asn     -- NOT COMPUTED. No offline IP->ASN database exists on this
                disk (checked: no GeoIP/MaxMind/IP2ASN files anywhere).
                Fabricating one is out of scope; this granularity is
                reported as unavailable, not silently skipped.
  d. service_class -- dib.evaluation.intent_overlap.classify_core's existing
                taxonomy (dns/ntp/update/vendor-cloud/other), the SAME
                classifier T2 already used for its "core" cut -- not a new
                taxonomy. This collapses port and specific identity too, so
                it is the coarsest cut: "does this org talk to any endpoint
                in this class at all."

Only independent org pairs count (moniotr us/us-vpn and uk/uk-vpn twin
pairs excluded, per dib.adapters.real_federation.NON_INDEPENDENT_PAIRS),
matching T2's methodology exactly.

Usage:
    python3 scripts/real_federation_granularity_overlap.py
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dib.adapters.real_federation import NON_INDEPENDENT_PAIRS
from dib.core.io import read_observations_csv, write_csv
from dib.evaluation.intent_overlap import (
    GRANULARITIES,
    endpoint_sets_by_org,
    pairwise_org_overlap_at_granularity,
)

DEVICE_TYPES = (
    "amazon-echo", "belkin-camera", "lifx-bulb", "netatmo-weather", "philips-hue",
    "ring-doorbell", "smartthings", "tp-link-plug", "wemo-motion", "wemo-switch",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--federation-observations", default="data/processed/real_federation_observations.csv")
    parser.add_argument("--output-dir", default="outputs/real_federation")
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("loading real federation observations ...", flush=True)
    observations = read_observations_csv(Path(args.federation_observations))
    print(f"{len(observations)} observations loaded\n", flush=True)

    detail_rows = []
    for device_type in DEVICE_TYPES:
        endpoint_sets = endpoint_sets_by_org(observations, device_type)
        for granularity in GRANULARITIES:
            pair_overlaps = pairwise_org_overlap_at_granularity(endpoint_sets, device_type, granularity)
            for overlap in pair_overlaps:
                non_independent = any(
                    {overlap.org_a, overlap.org_b} == {a, b} for a, b in NON_INDEPENDENT_PAIRS
                )
                if non_independent:
                    continue
                detail_rows.append(
                    {
                        "device_type": device_type,
                        "granularity": granularity,
                        "org_a": overlap.org_a,
                        "org_b": overlap.org_b,
                        "jaccard": overlap.jaccard,
                        "org_a_group_count": overlap.org_a_size,
                        "org_b_group_count": overlap.org_b_size,
                        "intersection": overlap.intersection,
                    }
                )
        print(f"  {device_type}: done", flush=True)

    write_csv(
        output_dir / "granularity_overlap_pairs.csv",
        detail_rows,
        ["device_type", "granularity", "org_a", "org_b", "jaccard", "org_a_group_count",
         "org_b_group_count", "intersection"],
    )
    print(f"\nwrote {output_dir / 'granularity_overlap_pairs.csv'} ({len(detail_rows)} rows)")

    # [granularity x device_type] mean-Jaccard table.
    by_device_granularity: dict[tuple[str, str], list[float]] = {}
    for row in detail_rows:
        by_device_granularity.setdefault((row["device_type"], row["granularity"]), []).append(row["jaccard"])

    summary_rows = []
    for device_type in DEVICE_TYPES:
        cell = {"device_type": device_type}
        for granularity in GRANULARITIES:
            values = by_device_granularity.get((device_type, granularity), [])
            cell[f"mean_jaccard_{granularity}"] = round(sum(values) / len(values), 6) if values else None
        summary_rows.append(cell)

    fields = ["device_type"] + [f"mean_jaccard_{g}" for g in GRANULARITIES]
    write_csv(output_dir / "granularity_overlap_summary.csv", summary_rows, fields)
    print(f"wrote {output_dir / 'granularity_overlap_summary.csv'}\n")

    header = f"{'device_type':<18}" + "".join(f"{g:>16}" for g in GRANULARITIES)
    print(header)
    for row in summary_rows:
        line = f"{row['device_type']:<18}"
        for granularity in GRANULARITIES:
            value = row[f"mean_jaccard_{granularity}"]
            line += f"{value:>16.4f}" if value is not None else f"{'n/a':>16}"
        print(line)

    print(f"\n{'OVERALL (mean across devices)':<18}", end="")
    for granularity in GRANULARITIES:
        values = [row[f"mean_jaccard_{granularity}"] for row in summary_rows if row[f"mean_jaccard_{granularity}"] is not None]
        overall = sum(values) / len(values) if values else None
        print(f"{overall:>16.4f}" if overall is not None else f"{'n/a':>16}", end="")
    print()
    print("\nasn granularity: NOT COMPUTED -- no offline IP->ASN mapping available on this disk.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
