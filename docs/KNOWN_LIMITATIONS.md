# Limiti noti

Elenco esplicito dei punti in cui questa cartella di riproducibilità non è
completa al 100%, con la ragione precisa e cosa servirebbe per chiuderli.
Preferibile dichiararli qui piuttosto che lasciarli emergere in revisione.

## 1. Numeri YourThings ancora calcolati con la logica di filtro pre-fix

Il bug di codice descritto in `CHANGELOG.md` §3 (`src/dib/adapters/yourthings.py`
aveva una propria implementazione non allineata di `exclude_non_global_ips`)
è stato **corretto** in questa sessione. Tuttavia:

- `data/processed/yourthings_observations.csv` (il CSV derivato già
  presente nel repository) è stato generato **prima** del fix, con la
  logica di filtro vecchia.
- L'archivio grezzo necessario per rigenerarlo
  (`data/yourthings/iot_traffic20180321.tgz`, Alrawi et al. 2019) non è
  staged in questo checkout e richiede accesso/registrazione esterna che
  non è stato possibile completare in questa sessione.

**Conseguenza per il paper:** qualunque numero che coinvolga YourThings
(incluso il suo contributo alla federazione multi-corpus
dell'Esperimento 2, che usa `real_federation_observations.csv` — a sua
volta costruito includendo YourThings) va trattato come **non ancora
verificato post-fix**. Se un reviewer chiede coerenza cross-dataset tra i
tre corpora federati, questo è il punto da menzionare esplicitamente.

**Per chiudere questo limite:** ottenere l'archivio YourThings, rilanciare
`scripts/prepare_yourthings.py` (userà automaticamente il fix già
applicato), poi rigenerare `real_federation_observations.csv` e rieseguire
l'Esperimento 2.

## 2. Benchmark "1000 siti, 1.811.240 osservazioni" citato ma non rintracciabile

Un numero citato altrove nel materiale del paper (batch sintetico a 1000
siti) non ha uno script generatore identificabile in nessuno dei due
repository. Non è stato ri-eseguito per questa cartella di riproducibilità
— farlo richiederebbe inventare un nuovo benchmark, il che snaturerebbe lo
scopo di "riproducibilità" di questa cartella. Se questo numero compare nel
paper, va o rimosso o accompagnato da uno script ricostruito e validato
separatamente prima della sottomissione.

## 3. Estensione sintetica della copertura A1 — bloccata

Vedi `experiments/06_synthetic_a1_blocked/`. Non è un limite di questa
cartella di riproducibilità in sé, ma un esperimento del paper
esplicitamente non completato per mancanza di dati (annotazioni
packet-level raw). Documentato qui per completezza dell'elenco.

## 4. Nessun controllo di versione (git) in nessuno dei due repository — RISOLTO 2026-07-24

`reproducibility/` è ora un repository git (`git init` eseguito in questa
sessione, prima del fix di quorum/direzione/FSM), con un commit per ogni
fix applicato — vedi `git log`. `DIB_reframe/` (la cartella superiore, con
`main.tex` e le altre bozze) resta senza controllo di versione proprio.

## 5. UNSW IoT Attack Dataset 2018 — provenienza/licenza non riverificata qui

`data/unsw_attack_2018/` (14MB nel repository DIB) è usato dagli esperimenti
A1/compromised-baseline ma non è chiaro dalla documentazione esistente se
sia dato "checked-in" o "da scaricare" nel senso di `data/README.md`. Non è
stato incluso in questa cartella; verificarne la licenza di ridistribuzione
prima di un'eventuale inclusione futura nel materiale supplementare.

## 6. CSV con `direction` pre-esistenti: da rigenerare, non da riparare al volo

Fix del 2026-07-24 (review finding #4, direzione RFC 8520 nel matcher di
fidelity): `dib.evaluation.profiles.load_dib_scores()`,
`load_baseline_profile()` e `load_profile_csv()` richiedono ora una colonna
`direction` esplicita e falliscono con `KeyError` se assente — per design,
non c'è un default silenzioso (vedi i docstring delle tre funzioni).

- I CSV generati dagli script del rerun consolidato (`compromised_baseline.py`,
  `ablation_multiseed.py`, `real_federation_scoring.py`,
  `external_validity_moniotr.py`, `run_experiments.py`/`runner.py`) sono
  **già corretti**: costruiscono il predicted set inline da `EndpointScore`
  dentro lo stesso processo (mai tramite `load_dib_scores()`), e
  `EndpointScore.to_dict()`/`_write_scores()` scrivono ora sempre
  `direction=from-device` (ogni osservazione in questo codebase è
  device-initiated).
- Qualunque **CSV di score o baseline scritto prima di questo fix**
  (`outputs/**/dib_scores.csv`, `outputs/**/*_profile.csv`, ecc., se mai
  riletto con `scripts/evaluate_profiles.py` o `scripts/compute_statistics.py`)
  non ha la colonna e fallirà al caricamento. Non esiste un default
  automatico "assumi from-device" intenzionalmente: per un file di score
  reale (non ground truth) l'assunzione è sempre vera oggi, ma va applicata
  come migrazione esplicita e verificabile (`csv` con una colonna
  `direction` aggiunta a valore costante `from-device`), non come
  comportamento implicito del loader — un domani in cui un adapter emette
  osservazioni `to-device` renderebbe quel default silenzioso sbagliato in
  modo silenzioso.
- Nessun ground-truth reale in questo checkout usa i formati compatti
  (`{"rules": [...]}` JSON o CSV `dst_dnsname,...`) gestiti da
  `_rule_to_endpoint()`/`load_profile_csv()` — tutti i 28 file in
  `data/unsw/profiles/normalized/` sono nel formato ACL
  (`ietf-mud:mud`/`ietf-access-control-list:acls`), l'unico effettivamente
  esercitato da `_mud_endpoints()`. Se in futuro si aggiunge un ground
  truth in formato compatto, deve includere `direction` esplicitamente
  (4° elemento di lista o chiave dict) — vedi i test in
  `test_profile_evaluation.py`.

## 7. Guardia del quorum (`min_reporting_sites`) non propagata a tutti gli script di sensitivity

Fix del 2026-07-24: `admit_auto()`/`ScoringConfig` supportano ora
`min_reporting_sites` (default Python `1` = comportamento pre-fix). È
propagato esplicitamente ovunque servisse per riprodurre i numeri
headline del paper (vedi `configs/LOCKED_CONFIGS.md`). Non è stato
propagato a `scripts/poisoning_weight_grid.py`,
`scripts/poisoning_persistence_grid.py`, `scripts/parameter_sensitivity_external.py`
e `scripts/tune_dib_weights.py` (sweep esplorativi di sensitivity/tuning
già dichiarati "non direttamente comparabili alla configurazione
selezionata" nel paper, Sec. VI-hyperparams) — questi restano al default
`min_reporting_sites=1` e vanno trattati come tali se mai citati.

## 8. Numeri non ri-verificati dopo il fix di quorum/direzione/FSM (2026-07-24) — quasi tutti chiusi 2026-07-24

Il rerun consolidato (`experiments/16_combined_bugfix_rerun/`, dettaglio in
`CHANGELOG.md` voce 11) ha ricalcolato tutti i numeri headline del paper
(Table I, Table II, Fig. 3, federazione, Mon(IoT)r, Sybil, nonstationarity,
day-0 F1). Un secondo giro nello stesso giorno ha chiuso quasi tutti i
numeri secondari rimasti:

- **F1 RWV in federazione — chiuso.** Il primo tentativo di rilancio dava
  `fake_accepted=False` per tutti i dispositivi, in contraddizione con il
  claim "5 di 10". Causa: `--calibration-observations` era stato passato
  puntando al bootstrap UNSW (dati non pertinenti) invece di lasciare il
  default dello script, che si autocalibra sugli stessi dati di
  federazione. Con l'invocazione corretta: F1 medio 0.256 (era 0.439),
  score 0.839 (era 0.958), 5/10 dispositivi — pattern qualitativo
  confermato. Vedi `experiments/16_combined_bugfix_rerun/02b_federation_rwv_v2/`.
- **Capture-tree transfer — confermato invariato.** `cross_site_heterogeneity_moniotr.py`
  confronta i fatti predetti direttamente contro il profilo di ogni sito
  escluso (non contro il ground truth MUD), quindi non dipende dal fix di
  direzione: precision 0.726, recall 0.250, F1 0.336, 540/9.672 fatti —
  match esatto con i valori già pubblicati.
- **Address-filtering — confermato invariato.** Verificato direttamente
  da `real_federation_scoring.py` con/senza `--exclude-non-global-ips`:
  1216.94→127.61 (era 1.216→128), lifx-bulb 636.5 esatto, media
  esclusa lifx 71.07 (era 71) — nessun cambiamento, come atteso (l'exception
  burden non passa dal matcher di ground truth).
- **Fingerprint quality — chiuso.** `fingerprint_robustness_moniotr.py`:
  fragmentation a 30% errore F1 0.302 (era 0.418, baseline 0.314 invece di
  0.431); collision a 20%/30% F1 0.314/0.254 (era 0.430/0.348). Stesso
  pattern qualitativo, valori scalati come ovunque dal fix di direzione.
- **F1 reference-weighted di Mon(IoT)r — chiuso.** Ricalcolato direttamente
  dai dati già raccolti in `11_moniotr_transfer{,_nograph}/moniotr_external_validity.csv`
  pesando il F1 per dispositivo per `truth_endpoint_count`: 0.314→0.270 con
  grafo (era 0.406→0.371), 0.363→0.362 senza (era 0.489→0.461).

**Resta aperto:**
- **F1 stratificato per numero di organizzazioni nell'"Operating Envelope"**
  (0.329 vs 0.312, "due-dieci organizzazioni") — indagine fatta ma
  inconclusiva: `audit_numeri.md` attribuisce questo numero a
  `intent_overlap.py`/`classify_core`, ma quel modulo non calcola F1 (solo
  classificazione tipata e overlap Jaccard, verificato per grep). Nessuno
  script in questo pacchetto riproduce chiaramente "due-dieci
  organizzazioni" (il conteggio reale di organizzazioni nella federazione
  varia 2-6, mai fino a 10). Il numero resta marcato "pre-fix" nel `.tex`
  senza una controparte ricalcolata verificata; va tracciato manualmente
  (probabilmente in uno script del repository `DIB/` originale non copiato
  qui) prima della submission finale.
- Ricerca esplorativa iperparametri non vincolata (Sec. VI-hyperparams,
  F1=0.231 a seed 42) — script di tuning esplicitamente fuori scopo (voce
  7 sopra), non chiuso per scelta.
- Sweep di persistenza A1 (Esperimento 09) — già noto non riprodotto per
  un motivo indipendente (voce 9 del CHANGELOG), non ri-tentato qui.
