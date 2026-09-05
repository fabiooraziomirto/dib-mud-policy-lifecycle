from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dib.core.io import read_observations_csv, write_csv
from dib.evaluation.dib import DIBScorer, ScoringConfig, admit_auto
from dib.experiments.poisoning import inject_persistent_fake_endpoint
from dib.simulator.sites import partition_observations

OUTPUT_DIR = Path("outputs/poisoning_persistence_grid")
FAKE_ENDPOINT = "evil-c2.net"


def _frange(values: str) -> list[float]:
    return [float(v) for v in values.split(",") if v.strip()]


def _irange(values: str) -> list[int]:
    return [int(v) for v in values.split(",") if v.strip()]


def _weight_simplex(step: float) -> list[tuple[float, float, float]]:
    """All (alpha, beta, gamma) on the probability simplex at the given step."""
    n = round(1.0 / step)
    combos = []
    for a in range(n + 1):
        for b in range(n + 1 - a):
            c = n - a - b
            combos.append((round(a * step, 4), round(b * step, 4), round(c * step, 4)))
    return combos


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Joint grid of (alpha,beta,gamma,theta) x sustained bounded-poisoner "
        "persistence (spread_days), at a fixed malicious fraction. Complements "
        "poisoning_weight_grid.py, which only tests a single-observation-per-site fake: "
        "this asks whether a bounded poisoner willing to sustain its fake endpoint over "
        "several days, rather than submit it once, can cross a tested threshold that the "
        "single-shot injection cannot."
    )
    parser.add_argument("--observations", default="data/processed/observations_enriched.csv")
    parser.add_argument("--output-dir", default=str(OUTPUT_DIR))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--site-count", type=int, default=10)
    parser.add_argument("--partition-strategy", default="random")
    parser.add_argument("--malicious-fraction", type=float, default=0.30)
    parser.add_argument("--spread-days", default="1,2,3,5,7,10,14,21,30,45,60")
    parser.add_argument("--weight-step", type=float, default=0.1)
    parser.add_argument("--thetas", default="0.50,0.55,0.60,0.65,0.70,0.75")
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    observations = read_observations_csv(Path(args.observations))
    if args.site_count:
        sites = partition_observations(
            observations, args.site_count, strategy=args.partition_strategy, seed=args.seed
        )
        observations = [o for site in sites for o in site.observations]

    spread_days_values = _irange(args.spread_days)
    thetas = _frange(args.thetas)
    weights = _weight_simplex(args.weight_step)
    print(f"{len(observations)} obs, {args.site_count} sites; {len(weights)} weight combos x "
          f"{len(thetas)} thetas x {len(spread_days_values)} persistence levels = "
          f"{len(weights) * len(thetas) * len(spread_days_values)} grid cells", flush=True)

    # Score each persistence level once; capture every fake endpoint instance's
    # three component confidences (one per device type present at a malicious site)
    # plus its endpoint_class, so the re-thresholding below can apply admit_auto()'s
    # typed gate instead of a raw score>=theta comparison (Fase 3, Gruppo c: same
    # bug class as dib.experiments.compromised_baseline.admission_exception_curve
    # and scripts/tune_dib_weights.py, fixed here too).
    components_by_spread: dict[int, list[tuple[float, float, float, str, str]]] = {}
    for spread_days in spread_days_values:
        started = time.perf_counter()
        poisoned = inject_persistent_fake_endpoint(
            observations, args.malicious_fraction, spread_days, seed=args.seed
        )
        scores = DIBScorer(ScoringConfig()).score(poisoned)
        components_by_spread[spread_days] = [
            (s.site_confidence, s.temporal_confidence, s.graph_confidence, s.device_type, s.endpoint_class)
            for s in scores
            if s.endpoint == FAKE_ENDPOINT
        ]
        print(f"  spread_days={spread_days}: {len(components_by_spread[spread_days])} fake "
              f"endpoints scored in {time.perf_counter() - started:.1f}s", flush=True)

    rows = []
    for (alpha, beta, gamma) in weights:
        for theta in thetas:
            for spread_days in spread_days_values:
                comps = components_by_spread[spread_days]
                if comps:
                    worst_device, fake_score, fake_class = max(
                        ((device, alpha * cs + beta * ct + gamma * cg, cls) for cs, ct, cg, device, cls in comps),
                        key=lambda item: item[1],
                    )
                else:
                    worst_device, fake_score, fake_class = "", 0.0, "other"
                rows.append({
                    "alpha": alpha, "beta": beta, "gamma": gamma, "theta": theta,
                    "spread_days": spread_days,
                    "worst_case_device_type": worst_device,
                    "max_fake_score": round(fake_score, 6),
                    "fake_accepted": admit_auto(fake_score, theta, fake_class),
                })

    write_csv(
        output_dir / "poisoning_persistence_grid.csv",
        rows,
        ["alpha", "beta", "gamma", "theta", "spread_days", "worst_case_device_type",
         "max_fake_score", "fake_accepted"],
    )

    # Per (weights,theta): first spread_days at which the fake is accepted, if any.
    summary = []
    for (alpha, beta, gamma) in weights:
        for theta in thetas:
            cells = [r for r in rows if r["alpha"] == alpha and r["beta"] == beta
                     and r["gamma"] == gamma and r["theta"] == theta]
            broken = [r for r in cells if r["fake_accepted"]]
            summary.append({
                "alpha": alpha, "beta": beta, "gamma": gamma, "theta": theta,
                "resists_through_max_spread": len(broken) == 0,
                "first_break_spread_days": min((r["spread_days"] for r in broken), default=""),
                "max_fake_score_at_max_spread": max(
                    (r["max_fake_score"] for r in cells if r["spread_days"] == max(spread_days_values)),
                    default=0.0,
                ),
            })
    write_csv(
        output_dir / "poisoning_persistence_grid_summary.csv",
        summary,
        ["alpha", "beta", "gamma", "theta", "resists_through_max_spread",
         "first_break_spread_days", "max_fake_score_at_max_spread"],
    )

    total = len(summary)
    resisting = sum(1 for s in summary if s["resists_through_max_spread"])
    print(f"\n{resisting}/{total} (weights,theta) combinations resist the persistent bounded "
          f"fake through {max(spread_days_values)} days of sustained presence at "
          f"{args.malicious_fraction:.0%} malicious sites.")
    breaks = [s for s in summary if not s["resists_through_max_spread"]]
    if breaks:
        print("Combinations that DO accept the fake at some tested persistence level:")
        for s in sorted(breaks, key=lambda r: r["first_break_spread_days"])[:20]:
            print(f"  a={s['alpha']} b={s['beta']} g={s['gamma']} theta={s['theta']} "
                  f"-> first break at spread_days={s['first_break_spread_days']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
