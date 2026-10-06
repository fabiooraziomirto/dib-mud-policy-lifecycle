#!/usr/bin/env python3
"""Recompute every headline number of the paper from the stored evidence.

Each check reads a file under results/ or formal/ and asserts the value printed
for v42.0. Checks cover the indexed headline evidence, not every sentence.

Usage:  python scripts/verify_artifact.py [--with-tests]
"""
from __future__ import annotations

import argparse
import csv
import json
import hashlib
import os
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
    check("base model distinct reachable states", states, 4311852)
    check("base model has no counterexample", "No error has been found" in base, True)

    ev = text("formal/logs/evidence_only.log")
    ev_states = int(re.search(r"([\d,]+) states generated, ([\d,]+) distinct", ev).group(2).replace(",", ""))
    check("no-commit model distinct states", ev_states, 2076196)
    check("no-commit model has no counterexample", "No error has been found" in ev, True)

    dist = text("formal/logs/distributed_extension.log")
    gen, distinct = re.search(r"([\d,]+) states generated, ([\d,]+) distinct", dist).groups()
    check("distributed extension states generated", int(gen.replace(",", "")), 815335)
    check("distributed extension distinct states", int(distinct.replace(",", "")), 48960)
    check("distributed extension depth", int(re.search(r"depth of the complete state graph search is (\d+)", dist).group(1)), 18)
    check("distributed extension has no counterexample", "No error has been found" in dist, True)

    for i, prop in enumerate(("AuthorizationStateCoherence", "I2_SiteConfinement", "ExportRequiresActive",
                             "DisputeSuspendsEverywhere", "I2_LocalRevokeConfinement",
                             "I3_GlobalRestorePreservesLocalRevoke"), 1):
        log = text(f"formal/mutations/m{i}/result.log")
        check(f"mutation m{i} violates {prop}", f"{prop} is violated" in log, True)

    check("focused registry/rescoring regression passes", "39 passed" in text("results/lifecycle_v35/regression.log"), True)

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

    cost = {(r["receiver"], r["stage"]): r for r in rows("results/review_cost/review_cost.csv")}
    for receiver, union_cost, dib_cost in (("US", 5.46, 1.03), ("UK", 4.31, 1.16), ("YT", 28.31, 2.89)):
        check(f"{receiver} union entries per confirmed endpoint",
              round(float(cost[(receiver, "union")]["reviews_per_confirmed"]), 2), union_cost, 0.005)
        check(f"{receiver} DIB entries per confirmed endpoint",
              round(float(cost[(receiver, "DIB")]["reviews_per_confirmed"]), 2), dib_cost, 0.005)
    budget = {(r["receiver"], r["stage"]): r for r in rows("results/review_cost/fixed_budget.csv")}
    ratios = []
    for receiver in ("US", "UK", "YT"):
        dib = float(budget[(receiver, "DIB")]["expected_confirmed_at_budget"])
        union = float(budget[(receiver, "union")]["expected_confirmed_at_budget"])
        ratios.append(dib / union)
    check("equal-budget yield ratio, minimum", round(min(ratios), 1), 3.7, 0.05)
    check("equal-budget yield ratio, maximum", round(max(ratios), 1), 9.8, 0.05)

    ranked = {r["receiver"]: r for r in rows("results/union_ranked/union_ranked_budget.csv")}
    concentration = []
    for receiver, exp_ranked, exp_dib, exp_gap in (("US", 35.0, 35, 0), ("UK", 39.0, 37, 2), ("YT", 40.0, 37, 22)):
        row = ranked[receiver]
        check(f"{receiver} score-ranked union yield at budget",
              float(row["union_ranked_expected"]), exp_ranked, 0.05)
        check(f"{receiver} score-ranked union tie-breaking is determinate",
              float(row["union_ranked_best"]) == float(row["union_ranked_worst"]), True)
        check(f"{receiver} full-DIB confirmed at budget", int(row["dib_confirmed"]), exp_dib)
        check(f"{receiver} DIB queue minus shortest ranked prefix at equal yield",
              int(row["dib_queue_minus_ranked_depth"]), exp_gap)
        concentration.append(float(row["union_ranked_expected"]) / float(row["union_arbitrary_expected"]))
    check("score-ranked over arbitrary order, minimum", round(min(concentration), 1), 3.9, 0.05)
    check("score-ranked over arbitrary order, maximum", round(max(concentration), 1), 10.6, 0.05)

    comp = rows("results/union_ranked/ranked_prefix_composition.csv")
    shares = []
    for receiver in ("US", "UK", "YT"):
        pref = {r["stage"]: r for r in comp if r["receiver"] == receiver}
        shares.append(100 * float(pref["admitted by DIB"]["share_of_prefix"]))
        check(f"{receiver} ranked prefix: entries below theta", int(pref["below threshold"]["entries"]), 0)
        check(f"{receiver} ranked prefix: entries failing quorum", int(pref["fails quorum"]["entries"]), 0)
        check(f"{receiver} ranked prefix: single-reporter entries",
              int(pref["single-reporter (subset)"]["entries"]), 0)
    check("ranked prefix admitted by DIB, minimum (%)", round(min(shares), 1), 86.9, 0.05)
    check("ranked prefix admitted by DIB, maximum (%)", round(max(shares), 1), 90.7, 0.05)

    marg = {r["receiver"]: r for r in rows("results/union_ranked/ranked_marginal_return.csv")}
    for receiver, drop in (("US", 1.4), ("UK", 1.4), ("YT", 6.7)):
        check(f"{receiver} marginal drop past the DIB cut",
              round(float(marg[receiver]["marginal_drop_factor"]), 1), drop, 0.05)

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

    sweep = {(int(r["n_sites"]), int(r["n_workers"])): r
             for r in rows("results/site_count/site_count_summary.csv")}
    check("one site container saturates (ops/s at 100 writers)",
          round(float(sweep[(1, 100)]["throughput_ops_per_sec"]), 1), 320.9, 0.05)
    check("one site container gains nothing from 50 to 100 writers",
          float(sweep[(1, 100)]["throughput_ops_per_sec"]) - float(sweep[(1, 50)]["throughput_ops_per_sec"]) < 5.0, True)
    speedups = [float(sweep[(n, w)]["speedup_vs_1_site"]) for n in (2, 5, 10) for w in (50, 100)]
    check("distribution speed-up at 50/100 writers, minimum", round(min(speedups), 2), 1.63, 0.005)
    check("distribution speed-up at 50/100 writers, maximum", round(max(speedups), 2), 1.75, 0.005)
    check("whole gain realized at two sites",
          float(sweep[(2, 100)]["throughput_ops_per_sec"]) >= float(sweep[(10, 100)]["throughput_ops_per_sec"]), True)
    check("ten sites are slower than one at a single writer (%)",
          round(100 * (1 - float(sweep[(10, 1)]["throughput_ops_per_sec"])
                       / float(sweep[(1, 1)]["throughput_ops_per_sec"])), 1), 20.6, 0.05)
    check("sweep unexpected errors", sum(int(r["unexpected_errors"]) for r in
          rows("results/site_count/site_count_summary.csv")), 6)

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
    check("paper version", claims["paper_version"], "v42.0")
    check("selected configuration is graph-free", "gamma: 0" in text(claims["selected_configuration"]), True)
    missing = [p for c in claims["claims"] for p in (x.strip() for x in c["result"].split(","))
               if not (ROOT / p).exists()]
    check("every claim resolves to a stored evidence file", missing, [])


def run_unit_tests() -> None:
    print("\nUnit suite")
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "code/tests", "-q"],
        cwd=ROOT, env={**os.environ, "PYTHONPATH": str(ROOT / "code" / "src")},
        capture_output=True, text=True,
    )
    tail = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else result.stderr[-200:]
    check("pytest exits cleanly", result.returncode, 0)
    print("  " + tail)


def check_new_lifecycle() -> None:
    print("\nRestoration-policy and suspension campaigns")
    result = json.loads(text("results/restore_ablation/results.json"))
    check("ablation source matches packaged service", result["service_sha256"],
          hashlib.sha256((ROOT / "code/src/dib/registry/distributed/service.py").read_bytes()).hexdigest())
    check("ablation script matches packaged generator", result["script_sha256"],
          hashlib.sha256((ROOT / "code/scripts/v36_restore_ablation.py").read_bytes()).hexdigest())
    check("distinct policy/scenario combinations", len({(c['policy'], c['veto_time'], c['disconnected']) for c in result['cases']}), 18)
    check("case count", len(result['cases']), 18)
    for policy, ace_count, veto_count in (("persistent_approval", 12, 6), ("review_reset", 0, 0), ("dib", 0, 6)):
        cases = [c for c in result['cases'] if c['policy'] == policy]
        check(f"{policy}: six sequences", len(cases), 6)
        check(f"{policy}: subject ACEs without new commit", sum(c['exports_without_fresh_commit'] for c in cases), ace_count)
        check(f"{policy}: vetoes preserved", sum(c['local_veto_preserved'] for c in cases), veto_count)
        for c in cases:
            final = next(t for t in c['trace'] if t['event'] == 'restored_and_reconciled')
            check(f"{policy}/{c['veto_time']}/{c['disconnected']}: export trace", sum(final['subject_aces']), c['exports_without_fresh_commit'])
            check(f"{policy}/{c['veto_time']}/{c['disconnected']}: control trace", all(t['control_aces'] == [1, 1, 1] for t in c['trace']), True)
    api = json.loads(text('results/lifecycle_v35/api_campaign.json'))
    for p in api['policies']:
        q = p['suspension_quorum']
        check(f'q={q}: first reporter', p['aces_after_one_reporter_per_site'], [0 if q == 1 else 100] * 10)
        check(f'q={q}: second reporter', p['aces_after_two_reporters_per_site'], [0] * 10)
        check(f'q={q}: local vetoes', p['local_vetoes_preserved'], 100)
        check(f'q={q}: duplicate votes', p['duplicate_reports_add_votes'], False)
        check(f'q={q}: fresh commits', p['restoration_requires_new_commits'], True)
        check(f'q={q}: old votes cleared', p['old_votes_cleared'], True)
    flood = json.loads(text('results/dispute_flood/dispute_flood_summary.json'))
    check('flood: authorizations suspended', flood['attacker']['site_records_suspended'], 1000)
    check('flood: withdrawal seconds', round(flood['attacker']['wall_s'], 1), 11.3)
    check('flood: recovery seconds', round(flood['recovery']['wall_s'], 1), 21.6)
    check('flood: recovery requests per fact', flood['recovery']['requests_per_fact'], 11)


# --- v42.0 additions: A1 resolved-peer counterfactual, Pareto frontier,
# and local veto across a process outage --------------------------------
def check_v42_additions() -> None:
    print("\nv42.0 additions")

    a1 = rows("results/a1_resolvable/a1_resolvable_counterfactual.csv")
    ip_literal = [r for r in a1 if r["peer_form"] == "ip_literal"]
    resolved = [r for r in a1 if r["peer_form"] == "resolved_fqdn"]
    check("A1 counterfactual: ip-literal cells", len(ip_literal), 150)
    check("A1 counterfactual: resolved-name cells", len(resolved), 150)
    check("A1 counterfactual: ip-literal admitted", sum(r["accepted"] == "True" for r in ip_literal), 0)
    check("A1 counterfactual: resolved-name admitted", sum(r["accepted"] == "True" for r in resolved), 21)
    first_admit = min(
        (r for r in resolved if r["accepted"] == "True"),
        key=lambda r: (int(r["k"]), int(r["spread_days"])),
    )
    check("A1 counterfactual: first admission k", int(first_admit["k"]), 7)
    check("A1 counterfactual: first admission spread_days", int(first_admit["spread_days"]), 120)
    check("A1 counterfactual: first admission score", round(float(first_admit["score"]), 3), 0.679)
    a1_manifest = json.loads(text("results/a1_resolvable/manifest.json"))
    check("A1 counterfactual: raw captured packets are IP-literal",
          a1_manifest["format_check"]["ip_literal_destinations"], 354)
    check("A1 counterfactual: total captured packets",
          a1_manifest["format_check"]["total_captured_packets"], 354)

    sweep = rows("results/pareto_frontier/sweep.csv")
    operating = {r["receiver"]: r for r in sweep if r["is_operating_point"] == "True"}
    check("Pareto frontier: sweep cells", len(sweep), 78)
    expected_operating = {
        "US": (36, 0.065, 0.116),
        "UK": (43, 0.064, 0.115),
        "YT": (107, 0.223, 0.247),
    }
    for receiver, (n, recall, f1) in expected_operating.items():
        r = operating[receiver]
        check(f"Pareto frontier {receiver}: operating-point queue size", int(r["queue_size"]), n)
        check(f"Pareto frontier {receiver}: operating-point recall", round(float(r["recall"]), 3), recall, 0.001)
        check(f"Pareto frontier {receiver}: operating-point F1", round(float(r["f1"]), 3), f1, 0.001)

    ov = json.loads(text("results/offline_veto/results.json"))
    check("offline veto: script matches packaged generator", ov["script_sha256"],
          hashlib.sha256((ROOT / "code/scripts/offline_veto_reconciliation.py").read_bytes()).hexdigest())
    check("offline veto: service matches packaged distributed service", ov["service_sha256"],
          hashlib.sha256((ROOT / "code/src/dib/registry/distributed/service.py").read_bytes()).hexdigest())
    check("offline veto: trial count", len(ov["trials"]), 10)
    check("offline veto: vetoes preserved", ov["summary"]["vetoes_preserved"], 10)
    check("offline veto: stale approvals cleared", ov["summary"]["stale_approvals_cleared"], 10)
    check("offline veto: unrelated facts preserved", ov["summary"]["unrelated_facts_preserved"], 10)
    check("offline veto: explicit recoveries passed", ov["summary"]["explicit_recoveries_passed"], 10)
    for t in ov["trials"]:
        check(f"offline veto trial {t['trial']}: veto survives with local origin",
              t["after"]["veto"]["origin"], "local")
        check(f"offline veto trial {t['trial']}: stale Active returns to MonitorOnly",
              t["after"]["active"]["state"], "monitor-only")
        check(f"offline veto trial {t['trial']}: neither vetoed nor stale fact exports",
              t["exports_after_reconcile"]["veto"] == [0, 0, 0] and t["exports_after_reconcile"]["active"] == [0, 0, 0], True)
        check(f"offline veto trial {t['trial']}: unrelated fact exports everywhere",
              t["exports_after_reconcile"]["unrelated"], [1, 1, 1])
        check(f"offline veto trial {t['trial']}: repeated reconcile is a no-op",
              t["repeated_reconcile_noop"], True)
        check(f"offline veto trial {t['trial']}: stale replay ignored",
              t["stale_replay_ignored"], True)
        check(f"offline veto trial {t['trial']}: direct commit over veto blocked",
              t["direct_commit_over_veto_blocked"], True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--with-tests", action="store_true", help="also run the unit suite")
    args = parser.parse_args()

    check_claims_index()
    check_formal()
    check_utility()
    check_security()
    check_scalability()
    check_new_lifecycle()
    check_v42_additions()
    if args.with_tests:
        run_unit_tests()

    print(f"\n{len(PASSED)} checks passed, {len(FAILED)} failed")
    for line in FAILED:
        print("  FAILED " + line)
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
