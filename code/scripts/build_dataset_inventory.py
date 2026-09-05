from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dib.adapters.loader import MUDProfileLoader, MoniotrObservationLoader, UNSWIoTrafficLoader, generate_dataset_report
from dib.core.io import write_csv, write_json


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate staged real datasets and emit Phase 1 inventory reports.")
    parser.add_argument("--flows-dir", default="data/unsw_iotraffic_2025/flows_extracted/flows")
    parser.add_argument("--protocols-dir", default="data/unsw_iotraffic_2025/protocols_extracted/protocols")
    parser.add_argument("--mud-profiles-dir", default="data/unsw/profiles/ground_truth")
    parser.add_argument("--moniotr-dir", default="data/public_sites/moniotr")
    parser.add_argument("--summary-output", default="outputs/dataset_summary.csv")
    parser.add_argument("--inventory-output", default="outputs/dataset_inventory.json")
    args = parser.parse_args(argv)

    loaders = [
        UNSWIoTrafficLoader(Path(args.flows_dir), Path(args.protocols_dir)),
        MUDProfileLoader(Path(args.mud_profiles_dir)),
    ]
    moniotr_loader = MoniotrObservationLoader(Path(args.moniotr_dir))
    if moniotr_loader.has_staged_files():
        loaders.append(moniotr_loader)
    summary_rows, inventory_payload = generate_dataset_report(loaders)
    write_csv(
        Path(args.summary_output),
        summary_rows,
        ["dataset", "role", "file_count", "device_count", "record_count", "issue_count", "valid"],
    )
    write_json(Path(args.inventory_output), inventory_payload)
    for row in summary_rows:
        print(f"{row['dataset']}: files={row['file_count']} records={row['record_count']} valid={row['valid']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
