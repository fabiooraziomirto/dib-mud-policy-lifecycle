from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dib.core.io import read_observations_csv, write_csv
from dib.evaluation.dib import DIBScorer, ScoringConfig, admit_auto
from dib.experiments.poisoning import inject_fake_endpoint
from dib.simulator.sites import partition_observations

OUTPUT_DIR = Path("outputs/tnsm_review_2026-06-20/experiments/poisoning_weight_grid")
FAKE_ENDPOINT = "evil-c2.net"


def _frange(values: str) -> list[float]:
    return [float(v) for v in values.split(",") if v.strip()]


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
        description="Systematic joint grid of (alpha,beta,gamma,theta) x bounded-poisoning "
        "fraction. Site/temporal/graph confidences are weight-independent, so each fraction "
        "is scored once and every weight/threshold combination is recombined analytically."
    )
    parser.add_argument("--observations", default="data/processed/observations_enriched.csv")
    parser.add_argument("--output-dir", default=str(OUTPUT_DIR))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--site-count", type=int, default=10)
    parser.add_argument("--partition-strategy", default="random")
    parser.add_argument("--fractions", default="0.01,0.05,0.10,0.20,0.30")
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

    fractions = _frange(args.fractions)
    thetas = _frange(args.thetas)
    weights = _weight_simplex(args.weight_step)
    print(f"{len(observations)} obs, {args.site_count} sites; {len(weights)} weight combos x "
          f"{len(thetas)} thetas x {len(fractions)} fractions = "
          f"{len(weights)*len(thetas)*len(fractions)} grid cells", flush=True)

    # Score each fraction once; capture every fake endpoint's three component confidences.
    components_by_fraction: dict[float, list[tuple[float, float, float]]] = {}
    for fraction in fractions:
        started = time.perf_counter()
        poisoned = inject_fake_endpoint(observations, fraction, seed=args.seed)
        scores = DIBScorer(ScoringConfig()).score(poisoned)
        components_by_fraction[fraction] = [
            (s.site_confidence, s.temporal_confidence, s.graph_confidence, s.endpoint_class)
            for s in scores
            if s.endpoint == FAKE_ENDPOINT
        ]
        print(f"  fraction={fraction}: {len(components_by_fraction[fraction])} fake endpoints "
              f"scored in {time.perf_counter() - started:.1f}s", flush=True)

    rows = []
    for (alpha, beta, gamma) in weights:
        for theta in thetas:
            for fraction in fractions:
                comps = components_by_fraction[fraction]
                if comps:
                    fake_score, fake_class = max(
                        ((alpha * cs + beta * ct + gamma * cg, cls) for cs, ct, cg, cls in comps),
                        key=lambda item: item[0],
                    )
                else:
                    fake_score, fake_class = 0.0, "other"
                rows.append({
                    "alpha": alpha, "beta": beta, "gamma": gamma, "theta": theta,
                    "malicious_fraction": fraction,
                    "max_fake_score": round(fake_score, 6),
                    "fake_accepted": admit_auto(fake_score, theta, fake_class),
                })

    write_csv(
        output_dir / "poisoning_weight_grid.csv",
        rows,
        ["alpha", "beta", "gamma", "theta", "malicious_fraction", "max_fake_score", "fake_accepted"],
    )

    # Per (weights,theta): does it resist the fake through every tested fraction?
    summary = []
    for (alpha, beta, gamma) in weights:
        for theta in thetas:
            cells = [r for r in rows if r["alpha"] == alpha and r["beta"] == beta
                     and r["gamma"] == gamma and r["theta"] == theta]
            broken = [r for r in cells if r["fake_accepted"]]
            summary.append({
                "alpha": alpha, "beta": beta, "gamma": gamma, "theta": theta,
                "resists_through_30pct": len(broken) == 0,
                "first_break_fraction": min((r["malicious_fraction"] for r in broken), default=""),
                "max_fake_score_at_30pct": max(
                    (r["max_fake_score"] for r in cells if r["malicious_fraction"] == max(fractions)), default=0.0),
            })
    write_csv(
        output_dir / "poisoning_weight_grid_summary.csv",
        summary,
        ["alpha", "beta", "gamma", "theta", "resists_through_30pct", "first_break_fraction", "max_fake_score_at_30pct"],
    )

    total = len(summary)
    resisting = sum(1 for s in summary if s["resists_through_30pct"])
    print(f"\n{resisting}/{total} (weights,theta) combinations resist the bounded fake through 30%.")
    breaks = [s for s in summary if not s["resists_through_30pct"]]
    if breaks:
        print("Combinations that DO accept the fake at some fraction <= 30%:")
        for s in sorted(breaks, key=lambda r: r["first_break_fraction"])[:20]:
            print(f"  a={s['alpha']} b={s['beta']} g={s['gamma']} theta={s['theta']} "
                  f"-> first break at fraction {s['first_break_fraction']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
