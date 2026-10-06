# Distributed management-path throughput (promoted)

The ten-site distributed deployment benchmark reported in Sec.
`sec:scalability-results`. Until this promotion it was the only paper result
living outside `experiments/`: it existed only as
`code/outputs/distributed_concurrency/*.csv`, with no manifest, no input
hashes and no hardware record. The CSVs here are byte-identical copies; the
manifest was written at promotion time and **no benchmark was re-run**.

```sh
docker compose -f code/src/dib/registry/distributed/docker-compose.yml up -d --build
python3 code/scripts/distributed_concurrency_benchmark.py \
    --worker-counts 1,10,50,100 --ops-per-worker 20 --warmup-ops 20 \
    --repeats 5 --output outputs/distributed_concurrency/throughput_distributed_5rep.csv
```

## Files

- `throughput_distributed_5rep.csv` — the run cited in the paper (5 repetitions).
- `throughput_distributed_3rep.csv` — an earlier 3-repetition run, kept for
  comparison. It records 3 unexpected errors at 100 writers.
- `manifest.json` — configuration, hardware, sha256 of harness, service,
  Dockerfile, compose file and both CSVs.

## What is measured

The management path under HTTP: one evidence container holding shared Score
state plus ten site containers holding their own LocalDecision records, with
synchronous dispute and restore fan-out to all ten sites. Each worker is pinned
to one site container by `worker_id % 10`.

| Writers | Throughput (ops/s) | p50 (ms) | p99 (ms) | Unexpected errors |
|---|---|---|---|---|
| 1 | 112.63 | 9.5 | 19.4 ± 1.4 | 0 |
| 10 | 305.53 | 35.9 | 70.4 ± 6.4 | 0 |
| 50 | 547.95 | 90.7 | 176.7 ± 8.4 | **1** |
| 100 | 530.30 | 168.7 | 454.8 ± 9.1 | 0 |

`total_ops` in the CSV is the count **per repetition**; `unexpected_errors` is
summed over all five. The 100-writer row therefore covers 5 × 2,000 = 10,000
timed operations.

## Honest scope

- **One unexpected error at 50 writers.** The run is not error-free overall.
  Only the 1-, 10- and 100-writer load points recorded zero.
- **No throughput standard deviation exists.** The CSV stores only
  `p99_latency_s_std`. A `±` on any throughput figure cannot be reproduced from
  these files.
- **`contribute` is a no-op** in this harness (`do_op`: *"no observation
  endpoint in this prototype"*) and is still counted in the throughput
  denominator. Two of every twenty timed operations perform no work.
- **Not comparable to `experiments/35_v28_concurrency`.** That harness measures
  in-process SQLAlchemy service calls with audit history under a uniform
  six-operation mix (16.7% disputes, 16.7% restores); this one measures HTTP to
  containers using raw `sqlite3` under a read-heavy mix (40% queries, 5%
  disputes, 5% restores). Four axes differ: stack, transport, operation mix,
  and the no-op `contribute`. The two are reported independently for that
  reason, and no cross-harness ratio is stated in the paper.
- **The script docstring is wrong.** It claims the "same 6-op mix as the other
  benchmarks"; `_MIX_REALISTIC` contradicts it. The code is authoritative.
- **Single host, no WAN.** One 16-core machine; a single-host operating point,
  not a distributed-scalability limit.
- **Distribution's own contribution is not isolated.** All rows use
  `DIB_DIST_N_SITES=10`. A site-count sweep holding stack, transport and mix
  fixed (`generate_compose.py` already parameterises the topology) would isolate
  it; it has not been run.
