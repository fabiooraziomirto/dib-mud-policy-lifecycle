# Esperimento 13 — Non-stazionarietà legittima (Esperimento A)

Generalizza il check A3 esistente (`drift.py`, che copriva solo il device
type più comune) a tutti i 27 device type UNSW effettivamente presenti in
`observations_enriched.csv` (il prompt originale citava 28 — discrepanza
verificata e dichiarata, non un errore di questo esperimento).

## Setup

Pipeline identica al resto della Fase 3 (`--exclude-non-global-ips`,
`site_count=10`, `partition_strategy=random`, `seed=42`), config graph-free
selezionata (alpha=0.6, beta=0.4, gamma=0, theta=0.65, trust_weighted=True).
Reimpiega `dib.experiments.drift.inject_drift_endpoint` e
`DIBScorer.score()`/`admit_auto()` invariati — nessuna soglia di ammissione
reimplementata localmente (verificato in Step 0, vedi
`NEW_EXPERIMENTS_LOG.md`).

Script: `code/scripts/nonstationarity_drift_sweep.py`. Comando:
```
python3 scripts/nonstationarity_drift_sweep.py \
  --output-dir outputs/nonstationarity_drift_sweep
```

## Assunzioni

- Adozione simulata come rollout firmware legittimo (classe "update",
  keyword `firmware` in `_UPDATE_KEYWORDS`) su una frazione p di siti
  eleggibili per quel device type, distribuito su D giorni.
- Griglia tempo-all'ammissione: checkpoint a 1,3,7,14,30,60,90,120 giorni
  (non ogni singolo giorno, per contenere il costo computazionale — scelta
  dichiarata, non silenziosa).
- Ottimizzazione: score() chiamato sul sottoinsieme di osservazioni del
  solo device type target (non sul corpus intero), con
  `trust_observations=` che punta comunque alla popolazione intera per i
  pesi di trust. Equivalenza numerica verificata esplicitamente contro un
  run non-sliced prima di fidarsene per l'intero sweep (vedi
  `NEW_EXPERIMENTS_LOG.md`).
- Controfattuale isolato (A3 puro): stesso sito singolo per entrambi i
  bracci (legittimo/malevolo), stessa griglia spread_days — non un secondo
  sweep di frazione (interpretazione dichiarata esplicitamente, non
  l'unica possibile).

## Risultato

Vedi `NEW_EXPERIMENTS_LOG.md` per i numeri e la loro interpretazione, e i
CSV in `outputs/nonstationarity_drift_sweep/` (non versionati in questa
cartella per dimensione — rigenerabili col comando sopra).

## Cosa questo risultato NON dimostra

- Non dimostra che il tempo-all'ammissione misurato generalizzi a pattern
  di adozione reali (qui il rollout è sintetico: un'osservazione al giorno
  per sito adottante, non un modello di traffico realistico).
- La non-separazione delle due curve isolate (legittimo vs. malevolo a un
  solo sito) è una conseguenza NECESSARIA della formula di scoring
  (site_confidence e temporal_confidence non dipendono dal contenuto
  semantico dell'endpoint, solo da dove/quando arrivano le osservazioni),
  non una scoperta empirica specifica di questo dataset — non generalizza
  necessariamente a formule di scoring diverse.
- Non copre l'interazione col registry/FSM (staging, dispute) durante il
  rollout — solo la decisione di ammissione dello scorer.
