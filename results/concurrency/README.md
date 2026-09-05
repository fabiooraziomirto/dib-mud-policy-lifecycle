# Corrected-registry concurrency characterization

Commands run from the repository root:

```sh
python code/scripts/fsm_concurrency_harness.py --skip-throughput --invariant-trials 200 --output-dir ../experiments/35_v28_concurrency --label v28_correctness
python code/scripts/fsm_concurrency_harness.py --skip-invariants --worker-counts 1,10,50,100 --repeats 3 --ops-per-worker 20 --output-dir ../experiments/35_v28_concurrency --label v28_performance
```

The performance run started after both formal checking and correctness runs
finished. It measures service calls against SQLite, not HTTP throughput. The
manifest records Python 3.10.13 and a 16-CPU x86_64 Linux environment.

Results:

- Nine correctness scenarios with 200 trials and one with 25 trials: all 1,825
  report zero violations. The 25-writer scenario completed 625 successful writes
  and did not actually exhaust the retry budget; it does not prove behavior
  under observed exhaustion.
- Three timed repetitions at each writer count, after a discarded warm-up of
  20 operations per writer: 9,660 timed operations, zero unexpected errors.
- At 100 writers: 317.49 ± 10.76 operations/s, median 3.783 ± 0.185 ms,
  p99 5895.513 ± 191.420 ms (sample standard deviations across repetitions).

These are short contention measurements, not a sustained-load scalability
study. The corrected source hash is stored in each manifest. Expected final
states in a set of schedules are not a proof of distributed linearizability.
