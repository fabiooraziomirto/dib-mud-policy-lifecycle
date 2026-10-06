# Equal-stack site-count sweep

The comparison `REVISION_PLAN_v32.md` §2.3 called option A, and the reason the
single-node-vs-distributed throughput ratio was withdrawn in v32: that ratio
differed on four axes at once (stack, transport, operation mix, and a no-op
`contribute` counted in the denominator), so it could not attribute anything to
distribution. Here stack, transport, mix, worker counts, ops-per-worker, warm-up,
repeats and hardware are all held fixed, and `DIB_DIST_N_SITES` is the single
independent variable.

```sh
bash code/scripts/distributed_site_count_sweep.sh
```

The driver regenerates `docker-compose.yml` for each N via `generate_compose.py`,
rebuilds, waits on `/health` for the evidence container and every site container,
runs the benchmark with `--n-sites N`, then tears the topology down with its
volumes before the next N. The canonical 10-site compose file is restored at the
end.

## Throughput (ops/s, mean of 5 repetitions)

| Sites | 1 writer | 10 writers | 50 writers | 100 writers |
|---|---|---|---|---|
| 1  | 125.7 | 291.1 | 319.0 | 320.9 |
| 2  | 125.4 | 338.1 | 551.4 | **557.7** |
| 5  | 118.0 | 323.2 | **559.4** | 539.5 |
| 10 | 99.8  | 324.1 | 553.3 | 523.1 |

`site_count_summary.csv` adds p50/p99 latency and the speed-up against the
one-site baseline at the same writer count.

## What the sweep shows

- **A single site container saturates at ~320 ops/s.** It gains nothing from 50
  to 100 writers (319.0 -> 320.9) while p50 latency doubles (188.5 -> 387.0 ms):
  it is fully backed up.
- **Distribution is worth 1.63--1.75x** at 50 and 100 writers. This is the
  number the withdrawn comparison was trying to state, now measured at equal
  stack.
- **The entire gain is realized at N=2.** N=5 and N=10 do not improve on it and
  drift slightly down at 100 writers (557.7 -> 539.5 -> 523.1). Every site
  contacts the shared evidence service for attestation, dispute and restore, so
  that service is the remaining bottleneck — the same component the deployment
  already identifies as a single point of failure. This is a measurement of it,
  not a new limitation.
- **Distribution costs something at low load.** With one writer, ten sites are
  20.6% slower than one (99.8 against 125.7 ops/s), because dispute and restore
  fan out synchronously to every site. The cost is paid per event and is
  invisible once concurrency saturates a single site.

## Honest scope

- **6 unexpected errors across 64,400 timed operations** of the sweep (N=2: 1 at
  100 writers; N=5: 1 at 50 and 3 at 100; N=10: 1 at 100). The sweep is not
  error-free; do not generalise the zero-error rows.
- `contribute` is a no-op in this harness (no observation endpoint in the
  distributed prototype) and still counts in the throughput denominator: 2 of
  every 20 timed operations perform no work. This inflates every row equally, so
  it does not affect the ratios between topologies.
- **One host, 16 cores, no WAN.** Site containers share a machine's CPU and page
  cache. This measures process-level separation, not geographic distribution,
  and the saturation point of a real consortium would differ.
- **N=1 is a degenerate baseline**, retained to anchor the sweep, not a
  supported deployment: a one-site consortium cannot satisfy the two-site quorum.
- Not comparable to `experiments/35_v28_concurrency` (in-process SQLAlchemy
  service calls, uniform six-operation mix) — that is the comparison this
  experiment replaces.
