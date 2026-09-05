# Esperimento 5 — Breakdown A1 per i due device esclusi dal bound aggregato

**Claim nel paper:** disclosure separata per NetatmoWeatherStation e
BlipCareBPMeter, esclusi dal bound aggregato perché il filtro IP privati
(`exclude_non_global_ips=True`) li riduce a un solo sito idoneo
(f_eff = 1) — condizione degenere per il bound Proposizione 1, che richiede
più siti indipendenti.

**Stato all'inizio di questa sessione: script pronto, mai eseguito.** È
stato lanciato per la prima volta per popolare questa cartella (vedi
`CHANGELOG.md`).

## Config esatta

Config-inline nello script stesso: `ScoringConfig(alpha=.6, beta=.4,
gamma=0.0, theta=.65, graph_enabled=False)` — identica a
`configs/graph_free_selected.yaml`.

## Script

`code/scripts/a1_excluded_device_breakdown.py`. Inietta un endpoint
malevolo sintetico RFC 5737 TEST-NET-1/2 (`203.0.113.11`/`.12`, mai in
collisione con endpoint pubblici reali) per ciascuno dei due device, dopo
il filtro IP privati, e misura l'ammissione al variare del numero di siti
malevoli `k`.

## Input

`data/processed/observations_enriched.csv` (derivato, va rigenerato).

## Comando esatto

```bash
cd DIB/
python3 scripts/a1_excluded_device_breakdown.py \
  --observations data/processed/observations_enriched.csv \
  --ground-truth-dir data/unsw/profiles/normalized \
  --output-dir outputs/tnsm_submission_2026/a1_excluded_devices \
  --seed 42
```

## Output in questa cartella

- `manifest.json` — conferma config graph-free selezionata, nota
  `"synthetic A1 disclosure; never aggregate with captured-A1 results"`.
- `a1_excluded_devices.csv`:

  | device_type | k | eligible_sites_after_filter | effective_f | malicious_admission_rate |
  |---|---|---|---|---|
  | NetatmoWeatherStation | 0 | 1 | 0.0 | 0 |
  | NetatmoWeatherStation | 1 | 1 | 1.0 | 1 |
  | BlipCareBPMeter | 0 | 1 | 0.0 | 0 |
  | BlipCareBPMeter | 1 | 1 | 1.0 | 0 |

  Conferma numericamente `eligible_sites_after_filter = 1` per entrambi i
  device (da cui f_eff=1 con anche un solo sito malevolo, k=1) — questo è
  esattamente il motivo per cui sono esclusi dal bound aggregato. A k=1,
  NetatmoWeatherStation viene ammesso (malicious_admission_rate=1),
  BlipCareBPMeter no — la differenza dipende dallo score risultante
  (`score` 0.733 vs 0.642 contro θ=0.65).
- `exportability_breakdown_by_device_context.csv` — copia di
  `DIB_reframe/results/tnsm_extra/exportability_breakdown_by_device.csv`,
  incluso solo come contesto sul perché questi due device hanno pochi
  endpoint accettati in generale (non è lo stesso esperimento, ma spiega
  perché sono candidati naturali per questa disclosure).

## Nota per il testo del paper

Questa è una **disclosure separata**, non va mai aggregata con il bound
principale su tutto il corpus: comunica esplicitamente il limite
"f_eff=1 quando resta un solo sito idoneo dopo il filtro IP privati", non
una violazione del bound.

## Tempo atteso

~32s.
