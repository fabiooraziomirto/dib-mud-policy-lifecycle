from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dib.adapters.unsw_iotraffic import iter_flow_observations
from dib.core.io import write_csv


FIELDNAMES = [
    "site_id",
    "device_id",
    "device_type",
    "fqdn",
    "remote_ip",
    "protocol",
    "port",
    "timestamp",
    "source_dataset",
    "evidence_type",
    "response_observed",
    "direction",
]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Normalize UNSW IoTraffic 2025 flow CSVs into DIB observations.")
    parser.add_argument(
        "--flows-dir",
        default="data/unsw_iotraffic_2025/flows_extracted/flows",
        help="Directory containing *_flows.csv files.",
    )
    parser.add_argument(
        "--protocols-dir",
        default="data/unsw_iotraffic_2025/protocols_extracted/protocols",
        help="Directory containing UNSW protocol parameter folders.",
    )
    parser.add_argument("--no-fqdn-enrichment", action="store_true", help="Disable HTTP host and TLS SNI enrichment.")
    parser.add_argument(
        "--output",
        default="data/processed/observations.csv",
        help="Output CSV path for normalized observations.",
    )
    parser.add_argument("--site-id", default="unsw-iotraffic-2025")
    parser.add_argument("--max-rows-per-file", type=int, help="Optional cap for smoke tests or sampling.")
    args = parser.parse_args(argv)

    observations = (
        observation.to_dict()
        for observation in iter_flow_observations(
            flows_dir=Path(args.flows_dir),
            protocols_dir=None if args.no_fqdn_enrichment else Path(args.protocols_dir),
            site_id=args.site_id,
            max_rows_per_file=args.max_rows_per_file,
        )
    )
    write_csv(Path(args.output), observations, FIELDNAMES)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
