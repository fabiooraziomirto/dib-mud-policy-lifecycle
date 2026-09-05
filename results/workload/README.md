# Mon(IoT)r cross-lab transfer and candidate load

Reproduce from `code/`:

```bash
python3 scripts/moniotr_cross_lab.py \
  --observations data/processed/moniotr_full_observations.csv \
  --output-dir ../experiments/17_moniotr_cross_lab
```

The script collapses US/US-VPN and UK/UK-VPN before every support count,
uses the frozen `(0.6,0.4,0,0.65,m=2)` configuration, and writes directional
transfer, full-capture per-site/device workload, 32 cumulative daily-window
workloads, support distribution, and a manifest with the input SHA-256.

The directional and leave-one-site-out DIB results are intentionally zero: once
the receiving deployment is excluded, one independent source remains and cannot
satisfy the locked two-site quorum. `leave_one_out.csv` records this result and
the resulting zero candidate coverage explicitly. This is the tested boundary
of the baseline, not a missing-data workaround: a cold-start receiver needs at
least two external sources, hence at least three independent deployments in
total for `m=2`.
