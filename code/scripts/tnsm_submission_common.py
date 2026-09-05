"""Shared reproducibility helpers for the TNSM submission reruns."""
from __future__ import annotations

import json
import resource
import shutil
import subprocess
import time
from pathlib import Path
from typing import Sequence


RAM_BUDGET_GIB = 48
RSS_REDUCE_GIB = 12


def write_manifest(output_dir: Path, *, experiment: str, config: dict, inputs: dict, commands: list[list[str]], metrics: dict | None = None) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "experiment": experiment,
        "config": config,
        "inputs": inputs,
        "commands": commands,
        "ram_budget_gib": RAM_BUDGET_GIB,
        "rss_reduce_threshold_gib": RSS_REDUCE_GIB,
        "metrics": metrics or {},
    }
    (output_dir / "manifest.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_timed(command: Sequence[str], *, cwd: Path, log_path: Path) -> dict[str, float | int]:
    """Run one process and parse GNU time's peak RSS without concurrent jobs."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    time_bin = shutil.which("/usr/bin/time") or shutil.which("time")
    if time_bin and Path(time_bin).name == "time":
        completed = subprocess.run([time_bin, "-v", *command], cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        rss_kib = 0
        for line in completed.stderr.splitlines():
            if "Maximum resident set size" in line:
                rss_kib = int(line.rsplit(":", 1)[1].strip())
                break
        log_suffix = "--- /usr/bin/time -v ---"
    else:
        completed = subprocess.run(command, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        # Sandboxed environments can omit GNU time. ru_maxrss still provides a
        # conservative child-process high-water mark for the single-job run.
        # ru_maxrss is already a high-water mark across children.  In the
        # submission runners jobs are deliberately serial, so it is a safe
        # (possibly conservative) per-job cap rather than a subtractable sum.
        rss_kib = int(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
        log_suffix = "--- resource.getrusage fallback (GNU time unavailable) ---"
    log_path.write_text(completed.stdout + "\n" + log_suffix + "\n" + completed.stderr, encoding="utf-8")
    return {"wall_seconds": round(time.monotonic() - started, 3), "peak_rss_kib": rss_kib}
