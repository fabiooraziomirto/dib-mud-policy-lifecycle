# Three-organization leave-one-out (v16 revision)

Extends the two-laboratory leave-one-out of `17_moniotr_cross_lab` (US/UK
Mon(IoT)r only, which is zero by construction: holding one receiver out
always leaves exactly one source, and the locked quorum `m=2` cannot be
satisfied by one source) with YourThings (Alrawi et al. 2019, Georgia Tech
capture) as a third, organizationally independent deployment. This makes
the leave-one-out boundary a real experiment rather than an arithmetic
guarantee: with three sites, holding one out leaves *two* sources, which
can satisfy `m=2`.

## What this tests

For each receiver in {US, UK, YT}, the other two deployments act as
sources under the locked admission rule (`alpha=0.6, beta=0.4, gamma=0.0,
theta=0.65, min_reporting_sites=2`). Device-type labels differ by naming
convention across the three corpora (Mon(IoT)r uses hyphenated names like
`insteon-hub`; YourThings uses `insteonhub`), so a label-alignment mapping
(`label_mapping_v16.csv`, frozen *before* this experiment ran) is applied.
It contains three exact string matches (`philips-hue`, `ring-doorbell`,
`smartthings`) and three mechanical hyphen/case normalizations
(`insteon-hub`, `google-home-mini`, `roku-tv`). Only six device types
survive this alignment and are observed at all three organizations --
this small shared-type set is a limitation of cross-corpus label
alignment (an assumption DIB states explicitly, Sec. III-A / Sec. IV-A of
the paper: "contributors must align labels before evidence merges"), not
of the admission rule itself.

## Result

| Receiver | Sources | Target types | Admitted candidates | Coverage | Macro F1 |
|---|---|---|---|---|---|
| US | UK+YT | 6 | 36 | 83.3% | 0.116 |
| UK | US+YT | 6 | 43 | 83.3% | 0.115 |
| YT | US+UK | 6 | 107 | 100% | 0.247 |

Unlike the two-laboratory case, quorum is satisfiable and every receiver
admits real candidates with above-zero F1. This is reported as a
preliminary, small-scope result (six shared device types), not a general
claim that three sources are always sufficient -- the shared-type set is
small precisely because label alignment across three unrelated corpora is
hard in practice.

## Data provenance

YourThings and Mon(IoT)r observation CSVs were not staged as raw archives
in this checkout; the experiment was run against already-processed CSVs
from the predecessor project `DIB/` (`data/processed/yourthings_observations.csv`,
`data/processed/moniotr_full_observations.csv`). The YourThings adapter in
this repository (`code/src/dib/adapters/yourthings.py`) was verified
byte-identical to the predecessor's before reuse (see `data_provenance.md`,
"Nota v16"). Exact input SHA-256 hashes are in `manifest.json`.

## How to reproduce

```bash
python3 code/scripts/moniotr_cross_lab.py \
  --observations /path/to/moniotr_full_observations.csv \
  --yourthings-observations /path/to/yourthings_observations.csv \
  --label-mapping data/label_mapping_v16.csv \
  --output-dir outputs/moniotr_cross_lab_threelab
```
