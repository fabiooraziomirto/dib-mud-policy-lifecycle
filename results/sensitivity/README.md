# Esperimento 15 — Sensibilità parametri fuori da UNSW (Esperimento B)

B1 (sweep theta), B2 (sweep alpha/beta + margine analitico), B3 (sweep
soglia Jaccard independence-aware, stress Sybil).

## Setup

**B1/B2**: `code/scripts/parameter_sensitivity_external.py` (nuovo). Un
solo `score()` per corpus (Mon(IoT)r: `moniotr_full_observations.csv`, 4
capture tree reali; YourThings: `yourthings_observations.csv`), config
graph-free (`graph_enabled=False`) così le componenti site/temporal
confidence non dipendono da alpha/beta/theta ("weight-independent",
proprietà già usata da `poisoning_weight_grid.py`, verificata leggendo
`dib.py` prima di scriverlo, non assunta). Ogni cella ricombina le stesse
componenti grezze e ri-applica `admit_auto()` reale (mai reimplementato
localmente). F1 semantica contro il ground truth UNSW normalizzato,
tramite `dib.evaluation.profiles.semantic_match_metrics` (stesso codice
usato da `external_validity_moniotr.py`, Fase 3 Gruppo b).

Comando:
```
python3 scripts/parameter_sensitivity_external.py \
  --moniotr-observations data/processed/moniotr_full_observations.csv \
  --ground-truth-dir data/unsw/profiles/normalized \
  --output-dir outputs/parameter_sensitivity_external
```

**B3**: `code/scripts/jaccard_threshold_sweep.py` — copiato da
`DIB/scripts/` (non presente in precedenza), verificato pulito prima della
copia (usa `.accepted`, nessuna soglia reimplementata). Nota: il prompt
indicava di riusare `tenure_quarantine_sweep.py`, che però copre un asse
diverso (tenure/probation, non Jaccard/independence-aware) — sostituito
esplicitamente con lo script effettivamente costruito per questo asse,
dichiarato qui.

## Assunzioni

- B1: alpha/beta fissi al punto operativo selezionato (0.6/0.4) mentre
  theta varia in [0.50,0.80] passo 0.025.
- B2: theta fisso a 0.65 (baseline) mentre alpha varia in [0.4,0.9] passo
  0.05, beta=1-alpha, gamma=0.
- Margine analitico: riusa `dib.analysis.poison_bound.evaluate_bound()`
  invariato (bound già dimostrato altrove in questa sessione, non
  ri-derivato qui).
- B3: parametri di default dello script copiato (soglie
  0.5/0.6/0.7/0.8/0.9/0.95, sybil_site_counts 1..1600, target device = il
  più comune nel corpus UNSW partizionato).

## Risultato

Vedi `NEW_EXPERIMENTS_LOG.md` per numeri e interpretazione, CSV in
`outputs/parameter_sensitivity_external/` e `outputs/jaccard_threshold_sweep/`.

**Risultato sfavorevole riportato in evidenza**: su YourThings (singolo
sito reale), `site_confidence` è banalmente 1.0 per ogni endpoint
eleggibile — lo sweep theta/alpha è vacuo per questo corpus (non un bug,
verificato via ispezione diretta della distribuzione). Solo Mon(IoT)r (4
siti reali) produce uno sweep informativo.

## Cosa questo risultato NON dimostra

- Il margine analitico B2 vale per il modello di poisoner a singolo-shot
  già dimostrato (`poison_bound.py`); non è una garanzia per Mon(IoT)r/
  YourThings specificamente (nessun attacco è stato iniettato in questi
  due corpora in questo esperimento, solo osservazioni benigne reali).
- La vacuità dello sweep su YourThings non dimostra che il sistema sia
  insensibile a theta/alpha in generale — è specifica della struttura a
  sito singolo di quel corpus.
- B3 misura la resistenza allo static-Sybil-frontier esistente
  (`inject_sybil_endpoint`), non a un attaccante adattivo.
