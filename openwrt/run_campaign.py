#!/usr/bin/env python3
"""Run the frozen OpenWrt/osMUD harness serially without automatic retries."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timezone


MIN_AVAILABLE_KIB = 8 * 1024 * 1024


def mem_available_kib() -> int:
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1])
    raise RuntimeError("MemAvailable is unavailable")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_summary(path: Path, summary: dict[str, object]) -> None:
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--min-available-kib", type=int, default=MIN_AVAILABLE_KIB)
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")

    here = Path(__file__).resolve().parent
    campaign_id = datetime.now(timezone.utc).strftime("campaign-%Y%m%dT%H%M%SZ")
    output_dir = args.output_dir or here / "artifacts" / campaign_id
    output_dir.mkdir(parents=True, exist_ok=False)
    summary_path = output_dir / "campaign_summary.json"
    summary: dict[str, object] = {
        "campaign": "openwrt_osmud_post_freeze",
        "requested_runs": args.runs,
        "minimum_available_kib": args.min_available_kib,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "status": "running",
        "runs": [],
    }
    write_summary(summary_path, summary)

    for index in range(1, args.runs + 1):
        available_kib = mem_available_kib()
        run_dir = output_dir / f"run-{index:02d}"
        run_dir.mkdir()
        log_path = run_dir / "harness.log"
        record: dict[str, object] = {
            "run": index,
            "artifact_dir": run_dir.name,
            "available_kib_before": available_kib,
        }
        cast_runs = summary["runs"]
        assert isinstance(cast_runs, list)
        cast_runs.append(record)
        if available_kib < args.min_available_kib:
            record["status"] = "not_started_low_memory"
            summary["status"] = "stopped_low_memory"
            write_summary(summary_path, summary)
            return 2

        environment = os.environ.copy()
        environment["ARTIFACT_DIR"] = str(run_dir)
        with log_path.open("w") as log:
            completed = subprocess.run(
                [str(here / "run.sh")],
                cwd=here,
                env=environment,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=False,
            )
        record["returncode"] = completed.returncode
        record["available_kib_after"] = mem_available_kib()
        result_path = run_dir / "result.json"
        if completed.returncode != 0 or not result_path.exists():
            record["status"] = "failed"
            summary["status"] = "stopped_failure"
            write_summary(summary_path, summary)
            return completed.returncode or 1
        result = json.loads(result_path.read_text())
        record["status"] = result.get("status", "unknown")
        record["result_sha256"] = sha256(result_path)
        record["manifest_sha256"] = sha256(run_dir / "manifest.json")
        if record["status"] != "pass":
            summary["status"] = "stopped_failure"
            write_summary(summary_path, summary)
            return 1
        write_summary(summary_path, summary)

    summary["status"] = "pass"
    summary["completed_runs"] = args.runs
    summary["finished_utc"] = datetime.now(timezone.utc).isoformat()
    write_summary(summary_path, summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
