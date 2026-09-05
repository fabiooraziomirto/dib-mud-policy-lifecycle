"""Eligibility gate and frozen normalization for a requested IoT Inspector CSV.

No scoring parameter is fitted here.  If any required condition fails, the
script writes a report, emits no normalized dataset, and exits with status 2.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import defaultdict
from pathlib import Path


GENERIC = {"unknown", "other", "iot", "device", "smart device", "generic", "unclassified", ""}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output-dir", default="outputs/iot_inspector_conditional")
    parser.add_argument("--home-field", default="home_id")
    parser.add_argument("--device-field", default="device_id")
    parser.add_argument("--timestamp-field", default="timestamp")
    parser.add_argument("--hostname-field", default="hostname")
    parser.add_argument("--ip-field", default="remote_ip")
    parser.add_argument("--port-field", default="port")
    parser.add_argument("--protocol-field", default="protocol")
    parser.add_argument("--vendor-field", default="vendor")
    parser.add_argument("--product-field", default="product")
    args = parser.parse_args()
    source = Path(args.input)
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    fields = vars(args)

    device_homes: dict[str, set[str]] = defaultdict(set)
    product_homes: dict[str, set[str]] = defaultdict(set)
    product_labels_by_device: dict[str, set[str]] = defaultdict(set)
    homes: set[str] = set()
    rows = 0
    with source.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {fields[name] for name in (
            "home_field", "device_field", "timestamp_field", "hostname_field", "port_field",
            "protocol_field", "vendor_field", "product_field",
        )}
        missing = sorted(required - set(reader.fieldnames or []))
        if missing:
            report = {"eligible": False, "reason": "missing required fields", "missing_fields": missing}
            write_report(output, source, report)
            return 2
        for row in reader:
            rows += 1
            home = row[args.home_field].strip()
            device = row[args.device_field].strip()
            vendor = row[args.vendor_field].strip()
            product = row[args.product_field].strip()
            label = f"{vendor} {product}".strip()
            if home:
                homes.add(home)
            if device and home:
                device_homes[device].add(home)
            if device and label:
                product_labels_by_device[device].add(label)
            if home and vendor.lower() not in GENERIC and product.lower() not in GENERIC:
                product_homes[label].add(home)

    unstable_devices = sorted(device for device, values in device_homes.items() if len(values) != 1)
    conflicting_devices = sorted(device for device, values in product_labels_by_device.items() if len(values) != 1)
    eligible_products = sorted(label for label, values in product_homes.items() if len(values) >= 5)
    eligible = bool(homes) and not unstable_devices and bool(eligible_products)
    report = {
        "eligible": eligible,
        "rows": rows,
        "home_count": len(homes),
        "stable_home_identifier": bool(homes) and not unstable_devices,
        "unstable_device_count": len(unstable_devices),
        "conflicting_device_label_count": len(conflicting_devices),
        "products_in_at_least_five_homes": eligible_products,
        "decision": "run grouped five-fold evaluation" if eligible else "omit extension and retain cross-lab baseline",
        "frozen_config": {"alpha": 0.6, "beta": 0.4, "gamma": 0.0, "theta": 0.65, "min_reporting_sites": 2},
    }
    write_report(output, source, report)
    if not eligible:
        return 2

    folds = {home: stable_fold(home) for home in homes}
    with (output / "home_folds.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["home_id", "fold"])
        writer.writeheader()
        writer.writerows({"home_id": home, "fold": folds[home]} for home in sorted(homes))
    normalize(source, output / "observations.csv", args, set(eligible_products), set(conflicting_devices))
    return 0


def normalize(source: Path, destination: Path, args, eligible_products: set[str], conflicts: set[str]) -> None:
    columns = ["site_id", "device_id", "device_type", "fqdn", "remote_ip", "protocol", "port", "timestamp", "source_dataset", "evidence_type", "response_observed", "direction"]
    with source.open(newline="", encoding="utf-8") as source_handle, destination.open("w", newline="", encoding="utf-8") as destination_handle:
        reader = csv.DictReader(source_handle)
        writer = csv.DictWriter(destination_handle, fieldnames=columns)
        writer.writeheader()
        for row in reader:
            label = f"{row[args.vendor_field].strip()} {row[args.product_field].strip()}".strip()
            device = row[args.device_field].strip()
            if label not in eligible_products or device in conflicts:
                continue
            writer.writerow({
                "site_id": row[args.home_field].strip(), "device_id": device, "device_type": label,
                "fqdn": row[args.hostname_field].strip(), "remote_ip": row.get(args.ip_field, "").strip(),
                "protocol": row[args.protocol_field].strip().lower(), "port": row[args.port_field],
                "timestamp": row[args.timestamp_field], "source_dataset": "iot-inspector",
                "evidence_type": "flow", "response_observed": "false", "direction": "out",
            })


def stable_fold(home: str) -> int:
    return int.from_bytes(hashlib.sha256(("dib-iot-inspector-fold-v1:" + home).encode()).digest()[:8], "big") % 5


def write_report(output: Path, source: Path, report: dict) -> None:
    report["input"] = str(source)
    report["input_sha256"] = file_sha256(source)
    report["bootstrap_cluster"] = "home_id"
    (output / "eligibility_report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
