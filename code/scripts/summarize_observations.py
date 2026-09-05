from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dib.core.io import write_csv
from dib.evaluation.profiles import canonical_device_name


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize normalized DIB observations.")
    parser.add_argument("--observations", default="datasets/processed/observations.csv")
    parser.add_argument("--output", default="outputs/observation_coverage.csv")
    args = parser.parse_args(argv)

    total_by_device: Counter[str] = Counter()
    fqdn_by_device: Counter[str] = Counter()
    evidence_by_device: dict[str, Counter[str]] = defaultdict(Counter)
    evidence_total: Counter[str] = Counter()
    endpoints_by_device: dict[str, set[tuple[str, str, int]]] = defaultdict(set)

    with Path(args.observations).open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            device_type = canonical_device_name(row["device_type"])
            total_by_device[device_type] += 1
            evidence = row["evidence_type"]
            evidence_by_device[device_type][evidence] += 1
            evidence_total[evidence] += 1
            endpoint = row["fqdn"] or row["remote_ip"]
            if endpoint:
                endpoints_by_device[device_type].add((endpoint.lower(), row["protocol"].lower(), int(row["port"])))
            if row["fqdn"]:
                fqdn_by_device[device_type] += 1

    rows = []
    for device_type in sorted(total_by_device):
        total = total_by_device[device_type]
        fqdn = fqdn_by_device[device_type]
        rows.append(
            {
                "device_type": device_type,
                "observation_count": total,
                "fqdn_observation_count": fqdn,
                "fqdn_coverage": round(fqdn / total, 6) if total else 0.0,
                "unique_endpoint_count": len(endpoints_by_device[device_type]),
                "flow_count": evidence_by_device[device_type]["flow"],
                "http_host_count": evidence_by_device[device_type]["flow+http_host"],
                "tls_sni_count": evidence_by_device[device_type]["flow+tls_sni"],
            }
        )

    write_csv(
        Path(args.output),
        rows,
        [
            "device_type",
            "observation_count",
            "fqdn_observation_count",
            "fqdn_coverage",
            "unique_endpoint_count",
            "flow_count",
            "http_host_count",
            "tls_sni_count",
        ],
    )
    print(f"observations={sum(total_by_device.values())}")
    print(f"fqdn_observations={sum(fqdn_by_device.values())}")
    print(f"evidence={dict(sorted(evidence_total.items()))}")
    print(f"coverage_csv={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
