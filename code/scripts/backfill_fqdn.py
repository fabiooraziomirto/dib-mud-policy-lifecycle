from __future__ import annotations

import argparse
import hashlib
import sys
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dib.core.io import read_observations_csv, write_csv, write_json
from dib.evaluation.enrichment import backfill_fqdn_windowed


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
    parser = argparse.ArgumentParser(
        description=(
            "Backfill missing FQDNs from directly observed HTTP-Host/TLS-SNI "
            "evidence for the same site and remote IP within a bounded time window."
        )
    )
    parser.add_argument("--observations", default="data/processed/observations.csv")
    parser.add_argument("--output", default="data/processed/observations_enriched.csv")
    parser.add_argument(
        "--window-hours", type=float, default=24.0,
        help="Maximum distance from an IP-only flow to direct name evidence (default: 24).",
    )
    parser.add_argument(
        "--report",
        help="JSON enrichment manifest. Defaults beside --output.",
    )
    args = parser.parse_args(argv)

    source = Path(args.observations)
    output = Path(args.output)
    report_path = Path(args.report) if args.report else output.with_suffix(".enrichment_report.json")
    if args.window_hours < 0:
        parser.error("--window-hours must be non-negative")

    observations = read_observations_csv(source)
    before = sum(1 for obs in observations if obs.fqdn)
    enriched, report = backfill_fqdn_windowed(
        observations, window=timedelta(hours=args.window_hours)
    )
    after = sum(1 for obs in enriched if obs.fqdn)

    write_csv(output, (obs.to_dict() for obs in enriched), FIELDNAMES)
    write_json(
        report_path,
        {
            "pipeline": "site_scoped_time_windowed_fqdn_backfill",
            "pipeline_version": 1,
            "input": str(source),
            "input_sha256": sha256(source),
            "output": str(output),
            "output_sha256": sha256(output),
            "window_hours": args.window_hours,
            "fqdn_before": before,
            "fqdn_after": after,
            "backfilled": after - before,
            **report.to_dict(),
        },
    )
    print(f"observations={len(observations)}")
    print(f"fqdn_before={before} ({before / len(observations):.2%})")
    print(f"fqdn_after={after} ({after / len(observations):.2%})")
    print(f"backfilled={after - before}")
    print(f"output={output}")
    print(f"report={report_path}")
    return 0


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
