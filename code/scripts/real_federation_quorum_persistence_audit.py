"""Follow-up diagnostic to real_federation_corroboration_audit.py.

Derives and empirically checks the quorum corollary of Proposition 1 (worst-
case bound alpha*f+beta+gamma, dib.analysis.poison_bound): for a "minority of
one" fake endpoint, f=1/Ed, so the bound is provably safe iff

    Ed > alpha / (theta - beta - gamma)

Shipped config (alpha=0.5, beta=0.3, gamma=0.2, theta=0.65) gives
0.5/0.15 = 3.33, i.e. Ed >= 4. This script:

  1. Prints the per-device quorum table (reusing dib.analysis.poison_bound.
     evaluate_bound with f=1/Ed -- no new formula, this is the existing bound
     evaluated at the "single minority corroborator" case).
  2. Recomputes acceptance under an Ed-quorum gate (device with Ed at or
     below quorum -> monitor-only, no accepted endpoints) and compares F1 to
     shipped and to the earlier ad hoc |Se|>=2 gate.
  3. Replicates the single-org fake endpoint over 1..120 days on each Ed=2
     device to see whether sustained (not one-shot) fake traffic crosses
     theta purely via Ct, confirming the quorum is load-bearing rather than
     an artifact of the one-shot injection being weak.
  4. Dumps raw (pre-max-normalization) PageRank for the one-shot fake
     endpoint's co-occurrence graph on every Ed=2 device, to check whether
     Cg=1.0 on an isolated fake node is a substantive graph-confidence signal
     or a small-graph normalization artifact (dividing by the max score in a
     graph with very few nodes trivially pushes several nodes close to 1.0).

Config is NOT retuned anywhere in this script. Whatever the numbers show is
reported as-is.

Usage:
    python3 scripts/real_federation_quorum_persistence_audit.py
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import networkx as nx

from dib.analysis.poison_bound import evaluate_bound
from dib.core.io import read_observations_csv, write_csv
from dib.evaluation.dib import DIBScorer, ScoringConfig
from dib.evaluation.profiles import (
    canonical_device_name,
    load_profile_dir,
    normalize_profile_protocol,
    semantic_match_metrics,
)

DEVICE_TYPES = (
    "amazon-echo", "belkin-camera", "lifx-bulb", "netatmo-weather", "philips-hue",
    "ring-doorbell", "smartthings", "tp-link-plug", "wemo-motion", "wemo-switch",
)
ED2_DEVICES = ("amazon-echo", "belkin-camera", "lifx-bulb", "wemo-motion", "wemo-switch")
FAKE_ENDPOINT = "evil-c2.federation-test"
SPREAD_DAYS = (1, 3, 7, 14, 30, 60, 90, 120)


def _canonicalize(policy: set[tuple[str, str, str, int]], device_type: str) -> set[tuple[str, str, str, int]]:
    device = canonical_device_name(device_type)
    return {
        (device, endpoint.lower(), normalize_profile_protocol(protocol, port), port)
        for _, endpoint, protocol, port in policy
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--federation-observations", default="data/processed/real_federation_observations.csv")
    parser.add_argument("--ground-truth-dir", default="data/unsw/profiles/normalized")
    parser.add_argument("--output-dir", default="outputs/real_federation")
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    scoring_config = ScoringConfig(graph_max_endpoints_per_device=100)
    alpha, beta, gamma, theta = scoring_config.alpha, scoring_config.beta, scoring_config.gamma, scoring_config.theta
    quorum_ed = alpha / (theta - beta - gamma)
    print(f"shipped config: alpha={alpha} beta={beta} gamma={gamma} theta={theta}")
    print(f"quorum corollary: Ed > alpha/(theta-beta-gamma) = {alpha}/{theta-beta-gamma:.2f} = {quorum_ed:.4f}"
          f"  ->  Ed >= {int(quorum_ed) + 1}\n")

    print("loading real federation observations ...", flush=True)
    observations = read_observations_csv(Path(args.federation_observations))
    print(f"{len(observations)} observations loaded\n", flush=True)
    ground_truth = load_profile_dir(Path(args.ground_truth_dir))

    print("=== 1. Per-device quorum table (Proposition 1 bound at f=1/Ed) ===")
    quorum_rows = []
    orgs_by_device: dict[str, list[str]] = {}
    for device_type in DEVICE_TYPES:
        device_obs = [o for o in observations if o.device_type == device_type]
        orgs = sorted({o.site_id for o in device_obs})
        orgs_by_device[device_type] = orgs
        ed = len(orgs)
        f = 1.0 / ed
        bound = evaluate_bound(alpha, beta, gamma, theta, f)
        quorum_rows.append({
            "device_type": device_type, "Ed": ed, "f_1_over_Ed": round(f, 6),
            "theoretical_bound": round(bound.theoretical_bound, 6),
            "provably_safe": bound.provably_safe,
        })
        print(f"  {device_type:<18} Ed={ed}  f=1/Ed={f:.3f}  bound={bound.theoretical_bound:.3f}  "
              f"provably_safe={bound.provably_safe}")
    write_csv(output_dir / "quorum_audit_per_device.csv", quorum_rows,
              ["device_type", "Ed", "f_1_over_Ed", "theoretical_bound", "provably_safe"])
    print()

    print("=== 2. Ed-quorum gate vs shipped vs ad hoc |Se|>=2 gate ===")
    gate_rows = []
    for device_type in DEVICE_TYPES:
        device_obs = [o for o in observations if o.device_type == device_type]
        orgs = orgs_by_device[device_type]
        ed = len(orgs)
        truth = ground_truth.get(canonical_device_name(device_type), set())
        scores = DIBScorer(scoring_config).score(device_obs, target_device_type=device_type)
        f = 1.0 / ed
        device_provably_safe = evaluate_bound(alpha, beta, gamma, theta, f).provably_safe

        shipped_accepted = {s.endpoint_key for s in scores if s.accepted}
        se_gate_accepted = {s.endpoint_key for s in scores if s.accepted and s.supporting_sites >= 2}
        ed_gate_accepted = shipped_accepted if device_provably_safe else set()

        f1_shipped = semantic_match_metrics(_canonicalize(shipped_accepted, device_type), truth)["semantic_f1"]
        f1_se_gate = semantic_match_metrics(_canonicalize(se_gate_accepted, device_type), truth)["semantic_f1"]
        f1_ed_gate = semantic_match_metrics(_canonicalize(ed_gate_accepted, device_type), truth)["semantic_f1"]

        gate_rows.append({
            "device_type": device_type, "Ed": ed, "provably_safe": device_provably_safe,
            "accepted_shipped": len(shipped_accepted), "accepted_Se_ge_2_gate": len(se_gate_accepted),
            "accepted_Ed_quorum_gate": len(ed_gate_accepted),
            "F1_shipped": round(f1_shipped, 6), "F1_Se_ge_2_gate": round(f1_se_gate, 6),
            "F1_Ed_quorum_gate": round(f1_ed_gate, 6),
        })
        print(f"  {device_type:<18} Ed={ed} safe={str(device_provably_safe):<5} "
              f"accepted: shipped={len(shipped_accepted):<3} Se>=2={len(se_gate_accepted):<3} "
              f"Ed-gate={len(ed_gate_accepted):<3}  F1: shipped={f1_shipped:.3f} "
              f"Se>=2={f1_se_gate:.3f} Ed-gate={f1_ed_gate:.3f}")

    write_csv(output_dir / "quorum_audit_gate_comparison.csv", gate_rows,
              ["device_type", "Ed", "provably_safe", "accepted_shipped", "accepted_Se_ge_2_gate",
               "accepted_Ed_quorum_gate", "F1_shipped", "F1_Se_ge_2_gate", "F1_Ed_quorum_gate"])
    import statistics
    total_shipped = sum(r["accepted_shipped"] for r in gate_rows)
    total_se_gate = sum(r["accepted_Se_ge_2_gate"] for r in gate_rows)
    total_ed_gate = sum(r["accepted_Ed_quorum_gate"] for r in gate_rows)
    mean_f1_shipped = statistics.mean(r["F1_shipped"] for r in gate_rows)
    mean_f1_se_gate = statistics.mean(r["F1_Se_ge_2_gate"] for r in gate_rows)
    mean_f1_ed_gate = statistics.mean(r["F1_Ed_quorum_gate"] for r in gate_rows)
    print(f"\n  TOTALS  accepted: shipped={total_shipped} Se>=2-gate={total_se_gate} Ed-quorum-gate={total_ed_gate}")
    print(f"  MEAN F1: shipped={mean_f1_shipped:.4f} Se>=2-gate={mean_f1_se_gate:.4f} Ed-quorum-gate={mean_f1_ed_gate:.4f}\n")

    print("=== 3. Persistent (sustained) fake endpoint on Ed=2 devices: day at which Ct/score cross theta ===")
    persistence_rows = []
    for device_type in ED2_DEVICES:
        device_obs = [o for o in observations if o.device_type == device_type]
        orgs = orgs_by_device[device_type]
        template = device_obs[0]
        injected_org = orgs[0]
        crossed_at = None
        for spread_days in SPREAD_DAYS:
            fake_obs_list = [
                replace(
                    template, site_id=injected_org, fqdn=FAKE_ENDPOINT, remote_ip=None,
                    protocol="https", port=443,
                    timestamp=template.timestamp + timedelta(days=day, seconds=1),
                    evidence_type="real_federation_persistent_fake_injection_test",
                )
                for day in range(spread_days)
            ]
            poisoned_scores = DIBScorer(scoring_config).score(device_obs + fake_obs_list, target_device_type=device_type)
            fake_key = (device_type, FAKE_ENDPOINT, "https", 443)
            fake = next((s for s in poisoned_scores if s.endpoint_key == fake_key), None)
            if fake is None:
                continue
            row = {
                "device_type": device_type, "spread_days": spread_days,
                "Cs": round(fake.site_confidence, 6), "Ct": round(fake.temporal_confidence, 6),
                "Cg": round(fake.graph_confidence, 6), "score": round(fake.score, 6), "accepted": fake.accepted,
            }
            persistence_rows.append(row)
            print(f"  {device_type:<18} spread_days={spread_days:<4} Cs={row['Cs']:.3f} Ct={row['Ct']:.3f} "
                  f"Cg={row['Cg']:.3f} score={row['score']:.3f} accepted={row['accepted']}")
            if fake.accepted and crossed_at is None:
                crossed_at = spread_days
        print(f"  -> {device_type}: {'crosses theta at spread_days=' + str(crossed_at) if crossed_at else 'never accepted through 120 days'}")
    write_csv(output_dir / "quorum_audit_persistent_fake.csv", persistence_rows,
              ["device_type", "spread_days", "Cs", "Ct", "Cg", "score", "accepted"])
    print()

    print("=== 4. Raw (pre-normalization) PageRank on the one-shot fake endpoint's co-occurrence graph, Ed=2 devices ===")
    graph_rows = []
    for device_type in ED2_DEVICES:
        device_obs = [o for o in observations if o.device_type == device_type]
        orgs = orgs_by_device[device_type]
        template = device_obs[0]
        injected_org = orgs[0]
        fake_obs = replace(
            template, site_id=injected_org, fqdn=FAKE_ENDPOINT, remote_ip=None,
            protocol="https", port=443, timestamp=template.timestamp + timedelta(seconds=1),
            evidence_type="real_federation_fake_injection_test",
        )
        scorer = DIBScorer(scoring_config)
        poisoned_scores = scorer.score(device_obs + [fake_obs], target_device_type=device_type)
        fake_key = (device_type, FAKE_ENDPOINT, "https", 443)
        fake = next((s for s in poisoned_scores if s.endpoint_key == fake_key), None)
        graph = scorer.last_graph
        n_nodes = graph.number_of_nodes() if graph is not None else 0
        n_edges = graph.number_of_edges() if graph is not None else 0
        try:
            raw_pagerank = nx.pagerank(graph, weight="weight") if graph is not None and n_nodes > 0 else {}
        except nx.PowerIterationFailedConvergence:
            raw_pagerank = {node: 1.0 / n_nodes for node in graph.nodes} if n_nodes else {}
        from dib.core.models import endpoint_to_string
        fake_node = endpoint_to_string(fake_key)
        fake_raw_pr = raw_pagerank.get(fake_node, 0.0)
        max_raw_pr = max(raw_pagerank.values(), default=0.0)
        uniform_pr = 1.0 / n_nodes if n_nodes else 0.0
        degree = graph.degree(fake_node) if graph is not None and fake_node in graph else 0
        row = {
            "device_type": device_type, "graph_nodes": n_nodes, "graph_edges": n_edges,
            "fake_node_degree": degree, "fake_raw_pagerank": round(fake_raw_pr, 6),
            "max_raw_pagerank": round(max_raw_pr, 6), "uniform_pagerank_1_over_n": round(uniform_pr, 6),
            "fake_Cg_normalized": round(fake.graph_confidence, 6) if fake else None,
        }
        graph_rows.append(row)
        print(f"  {device_type:<18} nodes={n_nodes:<4} edges={n_edges:<4} fake_degree={degree:<3} "
              f"fake_raw_pr={fake_raw_pr:.5f} max_raw_pr={max_raw_pr:.5f} uniform_1/n={uniform_pr:.5f} "
              f"-> Cg_normalized={row['fake_Cg_normalized']}")
    write_csv(output_dir / "quorum_audit_graph_pathology.csv", graph_rows,
              ["device_type", "graph_nodes", "graph_edges", "fake_node_degree", "fake_raw_pagerank",
               "max_raw_pagerank", "uniform_pagerank_1_over_n", "fake_Cg_normalized"])

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
