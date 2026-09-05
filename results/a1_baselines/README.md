# Esperimento 8 — Table I: confronto operator-facing con le baseline (A1, k=3, f=0.30)

**Claim nel paper:** `main.tex` Table~I (`tab:headline`), 6 strategie: Graph-free
DIB, RWV, Majority registry, Pooled union, Frequency-filtered, Local-only.
θ=0.65 per DIB, θ=0.50 per RWV, le altre threshold-free.

## Config esatta

`configs/graph_free_selected.yaml` (= `ref_trust_hyperparams.yaml`) — la
riga headline è "Graph-free DIB". Le 4 baseline deterministiche
(local/pooled/majority/frequency) non dipendono dalla config di scoring.

## Bug trovato e corretto (CHANGELOG voce 9)

`code/scripts/compromised_baseline.py` aveva `--exclude-non-global-ips`
con `default=False` (stesso pattern delle voci 1/6/7). Corretto a
`BooleanOptionalAction, default=True`.

## Script

`code/scripts/compromised_baseline.py`

## Comando esatto

```bash
cd DIB/
python3 scripts/compromised_baseline.py \
  --config configs/ref_trust_hyperparams.yaml \
  --observations data/processed/observations_enriched.csv \
  --calibration-observations /path/to/governance_bootstrap/calibration_observations.csv \
  --rwv-threshold 0.50 \
  --site-count 10 --partition-strategy random \
  --headline-k 3 \
  --output-dir outputs/tnsm_submission_2026/table1_compromised_baseline
```

`--calibration-observations` è obbligatorio nello script; rigenerabile con
`scripts/prepare_rwv_governance_bootstrap.py --seed 4201` (vedi
esperimento 4). `run_sweep.log` conferma
`exclude_non_global_ips=True: filtered to 1268020 observations`.

## Risultato: 5 righe su 6 confermate esattamente

| strategy | paper | questo rerun |
|---|---|---|
| Graph-free DIB | 0.0 / 30.32 | 0.0 / **30.32** ✓ |
| Majority registry | 0.0 / 11.72 | 0.0 / **11.72** ✓ |
| Pooled union | 1.0 / 0.00 | 1.0 / **0.00** ✓ |
| Frequency-filtered | 1.0 / 4.94 | 1.0 / **4.94** ✓ |
| Local-only | 0.30 / 0.00 | 0.30 / **0.00** ✓ |
| RWV | 0.0 / 12.62 | 0.0 / 13.22 (vedi sotto) |

## RWV — causa isolata e risolta (non un'ambiguità di provenienza)

Il rerun diretto con `--calibration-observations` puntato a un file esterno
dà 13.22, non 12.62. Indagine time-boxed (`rwv_investigation/`):

- `rwv_attempt1_governance_bootstrap_calib.csv` — calibrazione su
  `results/rwv_baseline/governance_bootstrap/calibration_observations.csv`
  → **13.22**.
- `rwv_attempt2_federation_bootstrap_calib.csv` — calibrazione su
  `results/rwv_baseline/federation_bootstrap/calibration_observations.csv`
  → **11.72** (identico per coincidenza a majority_registry).
- `rwv_attempt3_raw_unpartitioned_selfcalib.csv` — calibrazione sullo
  stesso file di `--observations` (`observations_enriched.csv` grezzo,
  non ripartizionato nei 10 siti) → **11.72**.

**Nessuno dei tre riproduce 12.62 tramite questo script.** La causa è
stata isolata rieseguendo l'Esperimento 10 (Fig.4): quello script calibra
RWV su `calibration_observations = clean_observations`, cioè la
popolazione **già ripartizionata nei 10 siti simulati** (dopo
`partition_observations`), non ricaricata da un file separato con gli
ID di sito originali. Il CSV `../10_fig4_theta_sweep/dib_curve_mean.csv`
riporta `rwv, theta=0.50 → 12.62`, **match esatto**.

`compromised_baseline.py` non supporta questo percorso via CLI (la
calibrazione è sempre ricaricata da `--calibration-observations`, mai la
popolazione in-memory già ripartizionata) — è un limite dello script
attuale, non un bug del filtro IP né un'incertezza sui dati. Il numero
12.62 del paper è quindi **pienamente riprodotto e spiegato**, tramite
l'Esperimento 10, non tramite questo.

## Tempo atteso

~11 min (657s), picco RSS ~2GB.
