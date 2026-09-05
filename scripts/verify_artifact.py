#!/usr/bin/env python3
"""Recompute every headline number of the paper from the stored evidence.

Each check reads a file under results/ or formal/ and asserts the value printed
in paper/main.tex (v31.1). Failure means the artifact and the paper disagree.

Usage:  python scripts/verify_artifact.py [--with-tests]
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PASSED: list[str] = []
FAILED: list[str] = []


def rows(relative: str) -> list[dict[str, str]]:
    with (ROOT / relative).open(newline="") as handle:
        return list(csv.DictReader(handle))


def text(relative: str) -> str:
    return (ROOT / relative).read_text(errors="replace")


def check(label: str, actual, expected, tol=0.0):
    try:
        if isinstance(expected, (int, float)) and not isinstance(expected, bool):
            ok = abs(float(actual) - float(expected)) <= tol
        else:
            ok = actual == expected
    except (TypeError, ValueError):
        ok = False
    (PASSED if ok else FAILED).append(f"{label}: got {actual!r}, expected {expected!r}")
    print(("  ok   " if ok else "  FAIL ") + label + f"  [{actual}]")


# --- RQ1: formal model and lifecycle -------------------------------------
def check_formal() -> None:
    print("\nRQ1 finite model and registry")
    base = text("formal/logs/full_lifecycle.log")
    states = int(re.search(r"([\d,]+) states generated, ([\d,]+) distinct", base).group(2).replace(",", ""))
    check("base model distinct reachable states", states, 3837084)
    check("base model has no counterexample", "No error has been found" in base, True)

    ev = text("formal/logs/evidence_only.log")
    ev_states = int(re.search(r"([\d,]+) states generated, ([\d,]+) distinct", ev).group(2).replace(",", ""))
    check("no-commit model distinct states", ev_states, 1749604)

    dist = text("formal/logs/distributed_extension.log")
    gen, distinct = re.search(r"([\d,]+) states generated, ([\d,]+) distinct", dist).groups()
    check("distributed extension states generated", int(gen.replace(",", "")), 718571)
    check("distributed extension distinct states", int(distinct.replace(",", "")), 44610)
    check("distributed extension depth", int(re.search(r"depth of the complete state graph search is (\d+)", dist).group(1)), 18)
    check("distributed extension has no counterexample", "No error has been found" in dist, True)

    for name in ("m1_restore_recreates_grant", "m2_commit_escapes_site", "m3_export_while_disputed",
                 "m4_local_restore_ignores_dispute", "m5_local_revoke_escapes_site",
                 "m6_global_restore_clears_local_revoke"):
        log = text(f"formal/logs/mutation_{name}.log")
        check(f"mutation {name} is refuted", "Error:" in log or "is violated" in log, True)

    check("registry regression passes after the fix", "33 passed" in text("formal/logs/regression_after.log"), True)

    campaign = json.loads(text("results/openwrt/campaign-10runs/campaign_summary.json"))
    check("OpenWrt campaign completed runs", campaign["completed_runs"], 10)
    check("OpenWrt campaign all pass", all(r["status"] == "pass" for r in campaign["runs"]), True)


# --- RQ2: coverage and proposal volume -----------------------------------
def check_utility() -> None:
    print("\nRQ2 coverage and proposal volume")
    funnel = {r["stage"]: r for r in rows("results/recall/recall_funnel.csv")}
    observed = float(funnel["observed_in_capture"]["macro_share"])
    staged = float(funnel["staged_by_dib"]["macro_share"])
    check("observable macro retention (%)", round(100 * staged / observed, 1), 63.2, 0.05)
    check("complete-profile macro recall (%)", round(100 * staged, 1), 7.9, 0.05)
    check("reference ACEs observable after filtering", int(funnel["observed_in_capture"]["matched_aces"]), 55)
    check("reference ACEs staged", int(funnel["staged_by_dib"]["matched_aces"]), 36)
    check("reference ACE base", int(funnel["all_reference_aces"]["total_aces"]), 564)

    abl = [r for r in rows("results/ablation_multiseed/summary.csv")
           if r["config"] == "graph_free" and r["variant"] == "full"]
    accepted = next(r for r in abl if r["metric"] == "accepted_count")
    f1 = next(r for r in abl if r["metric"] == "mean_f1_vs_ground_truth")
    check("graph-free accepted facts (20 seeds)", round(float(accepted["mean"]), 2), 344.55, 0.005)
    check("graph-free macro F1 (20 seeds)", round(float(f1["mean"]), 3), 0.104, 0.0005)

    cold = rows("results/cold_start/cold_start_local_vs_registry_detail.csv")
    mean = lambda k: sum(float(r[k]) for r in cold) / len(cold)
    check("DIB day-0 macro F1", round(mean("dib_day0_f1"), 3), 0.112, 0.0005)
    check("local-only 30-day macro F1", round(mean("local_only_30day_f1"), 3), 0.022, 0.0005)
    check("DIB + 30 days local macro F1", round(mean("dib_plus_30day_local_f1"), 3), 0.114, 0.0005)

    matched = rows("results/three_lab_matched/matched_ablation.csv")
    for receiver, expected_reduction, expected_n in (("US", 96.4, 36), ("UK", 94.4, 43), ("YT", 92.3, 107)):
        row = next(r for r in matched if r["receiver"] == receiver and r["stage"] == "DIB")
        check(f"{receiver} full-DIB candidates", int(row["candidates"]), expected_n)
        check(f"{receiver} reduction vs union (%)", round(100 * float(row["reduction"]), 1), expected_reduction, 0.05)


# --- RQ3: adversarial admission ------------------------------------------
def check_security() -> None:
    print("\nRQ3 adversarial admission")
    masq = rows("results/masquerade/service_masquerade.csv")
    worst_030 = max(float(r["score"]) for r in masq if r["malicious_fraction"] == "0.3" and r["class_eligible"] == "True")
    check("largest quorum-clearing score at f_s=0.30", round(worst_030, 3), 0.562, 0.0005)
    check("rejected at f_s=0.30", worst_030 < 0.65, True)
    staged_050 = [r for r in masq if r["malicious_fraction"] == "0.5" and r["accepted"] == "True"]
    check("stages at f_s=0.50 (outside the assumed region)", len(staged_050) > 0, True)

    quorum = [r for r in rows("results/quorum/site_quorum_sensitivity_rerun.csv") if r["site_count"] == "10"]
    check("quorums tested at N=10", sorted(int(r["quorum"]) for r in quorum), [1, 2, 3, 5])
    check("accepted facts identical across quorums at N=10", len({r["accepted_facts"] for r in quorum}), 1)
    check("accepted facts at N=10", int(quorum[0]["accepted_facts"]), 346)
    check("observable retention at N=10 (%)", float(quorum[0]["observable_retention_pct"]), 63.17, 0.005)

    drift = rows("results/drift/nonstationarity_time_to_admission_summary.csv")[0]
    check("drift cases admitted within horizon", int(drift["n_cases_admitted_within_horizon"]), 69)
    check("drift cases total", int(drift["n_cases_total"]), 162)
    check("median days to admission", float(drift["median_days_to_admission"]), 7.0)


# --- Management path -----------------------------------------------------
def check_scalability() -> None:
    print("\nManagement-path feasibility and reconciliation")
    single = {r["n_workers"]: r for r in rows("results/concurrency/throughput_v28_performance.csv")}
    check("single-node throughput at 100 writers", round(float(single["100"]["throughput_ops_per_sec_mean"]), 1), 317.5, 0.05)
    check("single-node p99 at 100 writers (ms)", round(1000 * float(single["100"]["p99_latency_s_mean"]), 1), 5895.5, 0.05)
    check("single-node p99 at 1 writer (ms)", round(1000 * float(single["1"]["p99_latency_s_mean"]), 1), 5.3, 0.05)
    check("no unexpected errors", all(int(r["unexpected_errors"]) == 0 for r in single.values()), True)

    inv = rows("results/concurrency/invariants_v28_correctness.csv")
    check("correctness trials", sum(int(r["trials"]) for r in inv), 1825)
    check("invariant violations", sum(int(r["violations"]) for r in inv), 0)

    dist = {r["n_workers"]: r for r in rows("results/distributed/throughput_distributed_5rep.csv")}
    check("distributed throughput at 100 writers", round(float(dist["100"]["throughput_ops_per_sec_mean"]), 1), 530.3, 0.05)
    check("distributed p99 at 100 writers (ms)", round(1000 * float(dist["100"]["p99_latency_s_mean"]), 1), 454.8, 0.05)

    fault = rows("results/fault_injection/results.csv")
    check("fault-injection trials", sum(int(r["trials"]) for r in fault), 40)
    check("all trials converge", all(r["trials"] == r["consistent_trials"] for r in fault), True)
    single_event = [r for r in fault if r["scenario"] != "dispute_and_restore"]
    mean_conv = sum(float(r["total_convergence_s_mean"]) * int(r["trials"]) for r in single_event) / 30
    check("single-event convergence (s)", round(mean_conv, 2), 0.51, 0.005)
    compound = next(r for r in fault if r["scenario"] == "dispute_and_restore")
    check("compound-outage convergence (s)", round(float(compound["total_convergence_s_mean"]), 2), 0.50, 0.005)


def check_claims_index() -> None:
    print("\nClaim index")
    claims = json.loads(text("claims.json"))
    check("paper version", claims["paper_version"], "v31.1")
    check("selected configuration is graph-free", "gamma: 0" in text(claims["selected_configuration"]), True)
    missing = [p for c in claims["claims"] for p in (x.strip() for x in c["result"].split(","))
               if not (ROOT / p).exists()]
    check("every claim resolves to a stored evidence file", missing, [])


def run_unit_tests() -> None:
    print("\nUnit suite")
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "code/tests", "-q"],
        cwd=ROOT, env={"PYTHONPATH": str(ROOT / "code" / "src"), "PATH": "/usr/bin:/bin"},
        capture_output=True, text=True,
    )
    tail = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else result.stderr[-200:]
    check("pytest exits cleanly", result.returncode, 0)
    print("  " + tail)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--with-tests", action="store_true", help="also run the unit suite")
    args = parser.parse_args()

    check_claims_index()
    check_formal()
    check_utility()
    check_security()
    check_scalability()
    if args.with_tests:
        run_unit_tests()

    print(f"\n{len(PASSED)} checks passed, {len(FAILED)} failed")
    for line in FAILED:
        print("  FAILED " + line)
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
