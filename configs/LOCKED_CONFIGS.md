# Configurazioni bloccate

Questo repository ha **una sola copia canonica** di ciascuna configurazione,
usata da tutti gli esperimenti sotto `experiments/`. Non duplicare questi
parametri altrove: qualsiasi script che ne abbia bisogno deve puntare a uno
di questi quattro file (o alla copia originale in `DIB/configs/`, di cui
questi sono copie verbatim).

| File | Origine in DIB/ | α | β | γ | θ | min_reporting_sites | graph_enabled | trust_weighted | Uso |
|---|---|---|---|---|---|---|---|---|---|
| `graph_augmented.yaml` | `configs/default_hyperparams.yaml` | 0.5 | 0.3 | 0.2 | 0.65 | 2 | true | — | Riferimento "graph-augmented", confronto empirico |
| `graph_free_selected.yaml` | `configs/ref_trust_hyperparams.yaml` | 0.6 | 0.4 | 0.0 | 0.65 | 2 | false | true | **Configurazione selezionata**, garanzia analitica. Usata per Table II, ablation multi-seed (20 seed), osMUD export, A1 breakdown, sensitivity |
| `graph_free_unweighted_federation.yaml` | `configs/tnsm_graph_free_unweighted.yaml` | 0.6 | 0.4 | 0.0 | 0.65 | 2 | false | false | Variante graph-free usata **solo** dallo script di confronto federazione multi-corpus (`tnsm_federation_comparison.py`) |
| `strict_alternative.yaml` | `configs/ref_strict_hyperparams.yaml` | 0.7 | 0.3 | 0.0 | 0.65 | 2 | false | true | Alternativa strict, validata con lo stesso rigore ma **mai** sostituita silenziosamente alla config selezionata |

`min_reporting_sites` (aggiunto 2026-07-24, fix review): guardia di quorum
in `admit_auto()` (`src/dib/evaluation/dib.py`) -- richiede almeno questo
numero di siti distinti, autenticati ed eleggibili (`|S_e|`, contati come
`set[str]` di `site_id`, quindi un sito che ripete la stessa evidenza non si
conta due volte) prima che un fatto possa essere ammesso automaticamente.
Prima di questo fix, `admit_auto()` non imponeva alcun minimo: con la
config selezionata, un singolo sito con evidenza temporale massima otteneva
`score=0.70≥0.65` ed entrava in monitor-only nonostante la prosa del paper
("corroboration requires reports from multiple sites"). Il campo è
**obbligatorio** nel blocco `scoring:` di ciascuno di questi quattro file
(chiave mancante → `KeyError` esplicito nei loader, mai un default silenzioso
-- vedi `runner.py:_scoring_config()` e gli script elencati sotto "Script che
leggono `min_reporting_sites` da uno di questi YAML"). Il default Python di
`ScoringConfig.min_reporting_sites` resta `1` (nessun vincolo aggiuntivo) e
si applica **solo** a chiamate che non passano il campo esplicitamente --
cioè agli script sensitivity/ablation esplorativi non elencati qui, il cui
comportamento resta quindi invariato rispetto a prima del fix (vedi
`KNOWN_LIMITATIONS.md`).

### Script che leggono `min_reporting_sites` da uno di questi YAML

Aggiornati per propagare il campo obbligatoriamente (`KeyError` se assente):
`scripts/compromised_baseline.py` (Table I), `scripts/ablation_multiseed.py`
(Table II), `scripts/real_federation_scoring.py` (federazione multi-corpus,
il caso a popolazione piccola citato dalla review), `scripts/sybil_sensitivity_surface.py`,
`scripts/tenure_quarantine_sweep.py`, `scripts/cold_start_multiseed.py`
(day-0 F1, citato in abstract), `scripts/cross_site_heterogeneity_moniotr.py`,
`scripts/compromised_baseline_persistence.py` (Esp. 09).

### Script con pesi hard-codati inline (letterale `min_reporting_sites=2`, da tenere sincronizzato a mano)

`scripts/admission_exception_tradeoff_v2.py` (Fig. 3, sweep di θ),
`scripts/external_validity_moniotr.py` (transfer Mon(IoT)r),
`scripts/nonstationarity_drift_sweep.py` (churn 349→139, Sec. VI-nonstationarity),
`scripts/adaptive_sybil_whole_registry.py` (Fig. Sybil-persistence),
`scripts/jaccard_threshold_sweep.py` (soglia Jaccard 0.50–0.95),
`scripts/a1_excluded_device_breakdown.py` (Esp. 05),
`scripts/fingerprint_robustness_moniotr.py` (Sec. VI-federation, fingerprint quality).

### Script deliberatamente esclusi (default Python `min_reporting_sites=1`, comportamento pre-fix)

- **Script diagnostici/investigativi, non nella mappa esperimento→script di `README.md`**:
  `scripts/real_federation_corroboration_audit.py`,
  `scripts/real_federation_quorum_persistence_audit.py` (nomi che suggeriscono
  attinenza al quorum, ma sono audit interni pre-fix, non gli script che
  producono numeri citati nel paper).
- **Sweep esplorativi di sensitivity/tuning**, già dichiarati "non
  direttamente comparabili alla configurazione selezionata" nel paper
  (Sec. VI-hyperparams): `scripts/poisoning_weight_grid.py`,
  `scripts/poisoning_persistence_grid.py`,
  `scripts/parameter_sensitivity_external.py`, `scripts/tune_dib_weights.py`,
  `scripts/gamma0_candidate_comparison.py`,
  `scripts/fingerprint_classifier_experiment.py`.

## Nota importante: due varianti "graph-free"

Il codice sorgente definisce **due** file graph-free con identici α,β,γ,θ ma
un flag interno diverso (`trust_weighted`):

- `graph_free_selected.yaml` (`trust_weighted: true`) è quella usata per
  produrre i numeri della tabella component-ablation (349 accettati,
  F1 0.1686 single-run/seed-42 post-gate -- vedi
  `regression_test/test_table2_regression.py`, sincronizzato 2026-07-24) e
  per l'export osMUD (51/349, 14.6%).
- `graph_free_unweighted_federation.yaml` (`trust_weighted: false`) è quella
  con cui è stato scritto ed eseguito lo script di confronto federazione
  (`scripts/tnsm_federation_comparison.py`), che la definisce esplicitamente
  come `VARIANTS["graph_free"]`.

Questa non è un'incongruenza nascosta: sono due configurazioni
**deliberatamente distinte**, entrambe coerenti con (α,β,γ,θ)=(0.6,0.4,0,0.65)
ma con una scelta diversa sulla ponderazione di fiducia dei siti. Il paper
deve riferirsi esplicitamente a quale delle due sta usando in ciascuna
tabella/figura — vedi la colonna "Config esatta" in `README.md`. Se in fase
di revisione si decide di unificarle, il punto di modifica è
`src/dib/experiments/runner.py:_scoring_config()` (che legge
`trust_weighted`) e va rieseguita la federazione con
`graph_free_selected.yaml` al posto dell'unweighted.

## Perché non generarle da un unico "master" con override

`ref_strict_hyperparams.yaml` e le altre copiano lo stesso scaffolding di
sweep (site_counts, seed range, ecc.) da `default_hyperparams.yaml` e
sovrascrivono solo il blocco `scoring:` (e a volte `outputs.root` /
`observations_csv`). Non è stato introdotto un meccanismo di ereditarietà
per restare fedeli a come gli esperimenti sono stati effettivamente
eseguiti — un sistema di override introdurrebbe un grado di libertà in più
rispetto a ciò che è stato realmente lanciato per il paper.
