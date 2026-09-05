"""Task 2: cross-organisational intent overlap on the REAL federation (not
the synthetic 10-way UNSW split). For every device type observed in >=2
genuinely independent real organisations (UNSW, Mon(IoT)r-US, Mon(IoT)r-UK,
YourThings -- moniotr-us/us-vpn and uk/uk-vpn collapse to one independent
org each, see dib.adapters.real_federation's module docstring), computes
all-pairs Jaccard similarity of the endpoint set, both overall and
restricted to "core" infrastructure endpoints (DNS/NTP/update/vendor-cloud).

This is a data-only measurement, reported as a result in its own right: it
answers "how much do independent real organisations actually agree on?"
before any scoring happens.

Usage:
    python3 scripts/real_federation_intent_overlap.py
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dib.adapters.real_federation import NON_INDEPENDENT_PAIRS
from dib.core.io import read_observations_csv, write_csv
from dib.evaluation.intent_overlap import endpoint_sets_by_org, pairwise_org_overlap

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
    print(f"{len(observations)} observations loaded", flush=True)

    rows = []
    for device_type in DEVICE_TYPES:
        endpoint_sets = endpoint_sets_by_org(observations, device_type)
        pair_overlaps = pairwise_org_overlap(endpoint_sets, device_type)
        for overlap in pair_overlaps:
            non_independent = any(
                {overlap.org_a, overlap.org_b} == {a, b} for a, b in NON_INDEPENDENT_PAIRS
            )
            rows.append(
                {
                    "device_type": overlap.device_type,
                    "org_a": overlap.org_a,
                    "org_b": overlap.org_b,
                    "non_independent_pair": non_independent,
                    "org_a_endpoint_count": overlap.org_a_size,
                    "org_b_endpoint_count": overlap.org_b_size,
                    "jaccard_all": overlap.jaccard_all,
                    "jaccard_core": overlap.jaccard_core,
                    "jaccard_fqdn_only": overlap.jaccard_fqdn_only,
                    "org_a_core_count": overlap.org_a_core_size,
                    "org_b_core_count": overlap.org_b_core_size,
                    "org_a_fqdn_count": overlap.org_a_fqdn_size,
                    "org_b_fqdn_count": overlap.org_b_fqdn_size,
                    "intersection_all": overlap.intersection_all,
                    "intersection_core": overlap.intersection_core,
                }
            )
        print(f"  {device_type}: {len(endpoint_sets)} orgs, {len(pair_overlaps)} org pairs", flush=True)

    fields = [
        "device_type", "org_a", "org_b", "non_independent_pair", "org_a_endpoint_count",
        "org_b_endpoint_count", "jaccard_all", "jaccard_core", "jaccard_fqdn_only",
        "org_a_core_count", "org_b_core_count", "org_a_fqdn_count", "org_b_fqdn_count",
        "intersection_all", "intersection_core",
    ]
    write_csv(output_dir / "intent_overlap_pairs.csv", rows, fields)
    print(f"\nwrote {output_dir / 'intent_overlap_pairs.csv'} ({len(rows)} rows)")

    # Summary: independent pairs only (excludes moniotr vpn-twin pairs, which
    # trivially overlap since they are the same device population).
    independent_rows = [r for r in rows if not r["non_independent_pair"]]
    by_device: dict[str, list[dict]] = {}
    for row in independent_rows:
        by_device.setdefault(row["device_type"], []).append(row)

    summary_rows = []
    for device_type, cells in by_device.items():
        mean_all = sum(c["jaccard_all"] for c in cells) / len(cells)
        mean_core = sum(c["jaccard_core"] for c in cells) / len(cells)
        mean_fqdn = sum(c["jaccard_fqdn_only"] for c in cells) / len(cells)
        summary_rows.append(
            {
                "device_type": device_type,
                "independent_org_pairs": len(cells),
                "mean_jaccard_all": round(mean_all, 6),
                "mean_jaccard_core": round(mean_core, 6),
                "mean_jaccard_fqdn_only": round(mean_fqdn, 6),
                "max_jaccard_all": round(max(c["jaccard_all"] for c in cells), 6),
                "max_jaccard_core": round(max(c["jaccard_core"] for c in cells), 6),
            }
        )
    summary_rows.sort(key=lambda r: -r["mean_jaccard_core"])
    write_csv(
        output_dir / "intent_overlap_summary.csv",
        summary_rows,
        ["device_type", "independent_org_pairs", "mean_jaccard_all", "mean_jaccard_core",
         "mean_jaccard_fqdn_only", "max_jaccard_all", "max_jaccard_core"],
    )

    print(f"\n{'device_type':<18} {'pairs':>6} {'mean_jacc_all':>14} {'mean_jacc_core':>15} {'mean_jacc_fqdn':>15}")
    for row in summary_rows:
        print(f"{row['device_type']:<18} {row['independent_org_pairs']:>6} "
              f"{row['mean_jaccard_all']:>14.4f} {row['mean_jaccard_core']:>15.4f} "
              f"{row['mean_jaccard_fqdn_only']:>15.4f}")

    overall_mean_all = sum(r["mean_jaccard_all"] for r in summary_rows) / len(summary_rows)
    overall_mean_core = sum(r["mean_jaccard_core"] for r in summary_rows) / len(summary_rows)
    overall_mean_fqdn = sum(r["mean_jaccard_fqdn_only"] for r in summary_rows) / len(summary_rows)
    print(f"\nAcross all {len(summary_rows)} devices, independent org pairs only "
          f"({len(independent_rows)} pairs, excluding moniotr vpn-twin pairs):")
    print(f"  mean Jaccard (all endpoints): {overall_mean_all:.4f}")
    print(f"  mean Jaccard (core infrastructure only): {overall_mean_core:.4f}")
    print(f"  mean Jaccard (FQDN-resolved endpoints only, both sides): {overall_mean_fqdn:.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
