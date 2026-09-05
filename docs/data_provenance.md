# Provenienza dei dati

Questa cartella non contiene dataset grezzi o CSV derivati pesanti. Segue la
mappa completa di cosa serve, da dove, e cosa manca — coerente con
`DIB/data/README.md` e `DIB/artifact_manifest.json`.

## Dati inclusi in questa cartella (`code/data/`)

Piccoli artefatti derivati, necessari per la valutazione contro ground
truth e già parte del repository originale (non generati dagli esperimenti
qui documentati):

- `code/data/unsw/profiles/ground_truth/`, `code/data/unsw/profiles/normalized/` —
  profili MUD di riferimento UNSW usati come ground truth (JSON).
- `code/data/unsw/labels.json` — etichette device.
- `code/data/unsw/mudgee/` — materiale di riferimento MUDgee.
- `code/data/public_sites/README.md` — documentazione formato input per
  l'esperimento di corroborazione cross-dataset (non i profili stessi).

Dimensione totale: ~450KB.

## Dati esterni da scaricare manualmente

Nessuno di questi dataset è ridistribuito qui; verificare la licenza di
ciascuno prima di ridistribuire qualunque cosa ne derivi.

| Dataset | Path atteso | Usato da | Note |
|---|---|---|---|
| UNSW-IoTraffic 2025 (flows + protocols) | `data/unsw_iotraffic_2025/{flows,protocols}/` | `scripts/prepare_unsw_iotraffic.py` | Fonte primaria di `observations.csv` |
| Mon(IoT)r Lab | `data/public_sites/moniotr/iot-data.tar`, `iot-idle.tgz` | `scripts/prepare_moniotr.py` | Federazione (Esperimento 2), transfer cross-corpus |
| YourThings (Alrawi et al. 2019) | `data/yourthings/iot_traffic20180321.tgz` + `device_mapping.csv` | `scripts/prepare_yourthings.py` | Federazione (Esperimento 2); dal v16 anche il LOO a tre laboratori (Sec. V-D). Archivio grezzo **non staged in questo checkout** — vedi nota v16 sotto per come è stato comunque possibile eseguire l'esperimento |
| UNSW IoT Attack Dataset 2018 | `data/unsw_attack_2018/` | esperimenti A1/compromised-baseline | Verificare provenienza/licenza prima di includere anche solo un estratto nel materiale supplementare |

`DIB/data/download_traces.sh` stampa istruzioni ma **non include un URL
hardcoded** per nessuno di questi archivi — va verificato il link
canonico corrente sulla pagina di ciascun dataset prima del download.

## Dati generati (derivati, non inclusi qui per dimensione)

Prodotti dagli adapter a partire dai dati esterni sopra. Necessari per
rieseguire gli esperimenti 1, 2, 3, 5 e il test di regressione:

| File | Dimensione | Generato da | Serve a |
|---|---|---|---|
| `data/processed/observations_enriched.csv` | 39M | `prepare_unsw_iotraffic.py` + `backfill_fqdn.py` | Esperimenti UNSW, test di regressione |
| `data/processed/observations_enriched_respfix.csv` | 39M | come sopra + fix `response_observed` | Esperimento 1 (export MUD, direzione ACE) |
| `data/processed/real_federation_observations.csv` | 186M | combinazione UNSW+Mon(IoT)r+YourThings | Esperimento 2, sweep Sybil dell'Esperimento 4 |
| `data/processed/moniotr_full_observations.csv` | 60M | `prepare_moniotr.py` | Transfer cross-corpus dell'Esperimento 4 |

Rigenerazione end-to-end (dopo aver staged i dati esterni):

```bash
cd DIB/
python3 scripts/build_dataset_inventory.py
python3 scripts/prepare_unsw_iotraffic.py
python3 scripts/backfill_fqdn.py \
  --observations data/processed/observations.csv \
  --output data/processed/observations_enriched.csv \
  --window-hours 24 \
  --report data/processed/observations_enriched.enrichment_report.json
python3 scripts/summarize_observations.py --observations data/processed/observations_enriched.csv
```

`backfill_fqdn.py` is the canonical enrichment stage. It accepts only directly
observed HTTP Host/TLS SNI evidence from the same site and remote IP within the
configured window; its JSON manifest records input/output SHA-256, the window,
and the full resolution breakdown. Do not reuse aggregates produced from the
old global-IP backfill. After regenerating this file, rerun every
UNSW-dependent artifact before copying values into the paper: recall funnel,
multi-seed ablations, pseudo-site/quorum sensitivity, poisoning, Sybil, drift,
parameter sensitivity, and cold-start partition experiments.

Per `real_federation_observations.csv` e `moniotr_full_observations.csv`
vedere rispettivamente `scripts/prepare_moniotr.py`,
`scripts/prepare_yourthings.py` e lo script (non incluso qui, verificarne
l'esistenza in `DIB/scripts/`) che combina i tre corpora in un unico file
di federazione.

## Limite noto: annotazioni packet-level raw mancanti

Le annotazioni packet-level raw per l'UNSW Attack Dataset 2018, necessarie
per l'estensione sintetica della copertura A1 (Esperimento 6), non sono
presenti in questo repository. Vedi
`experiments/06_synthetic_a1_blocked/BLOCKER.md`.

## Nota v16: riuso dei CSV già processati in `DIB/` per il LOO a tre laboratori

Per l'esperimento di Sec. V-D (leave-one-out a tre organizzazioni, aggiunta
di YourThings come terzo "laboratorio" indipendente a Mon(IoT)r US/UK), gli
archivi grezzi YourThings e Mon(IoT)r non erano disponibili in questo
checkout, ma i CSV derivati risultavano già presenti, generati in una
sessione precedente dello stesso progetto predecessore `DIB/`:

- `/root/Desktop/DIB/data/processed/yourthings_observations.csv`
  (104.246 righe; una cattura Georgia Tech del 21/3/2018, limitata dallo
  script sorgente a 40 file PCAP via `--max-pcap-files 40` — un sottoinsieme
  limitato, non l'intero corpus YourThings).
- `/root/Desktop/DIB/data/processed/moniotr_full_observations.csv`.

**Verifica di equivalenza prima del riuso** (Fase 6, step 1 del piano di
revisione v16): `code/src/dib/adapters/yourthings.py` in questo repository
è **byte-per-byte identico** a `DIB/src/dib/adapters/yourthings.py`
(verificato con `diff`, nessuna differenza). Il CSV di `DIB/` è quindi
l'output dello stesso identico codice di parsing/normalizzazione presente
in questo repository, non di una pipeline diversa: il riuso non introduce
una fonte di dati alternativa, solo un output già calcolato dello stesso
adapter. Lo stesso vale per `observations_enriched.csv` usato dagli
esperimenti Jaccard-threshold e cold-start multiseed di questa revisione.

Lo script generalizzato `scripts/moniotr_cross_lab.py` (flag
`--yourthings-observations` e `--label-mapping`) e lo script
`scripts/cold_start_local_vs_registry_multiseed.py` sono stati eseguiti
puntando direttamente a questi path assoluti in `DIB/`, senza copiare i
CSV in questo repository (per non appesantire il repository di
riproducibilità con file da 40-60MB). Chi rigenera i risultati da zero deve
ripetere `prepare_yourthings.py`/`prepare_moniotr.py` con gli archivi
grezzi originali; gli hash SHA-256 esatti dei CSV effettivamente usati sono
registrati nei manifest di output di ciascun esperimento
(`outputs/moniotr_cross_lab_v16_threelab/manifest.json`,
`outputs/cold_start_local_vs_registry_multiseed/manifest.json`).

Il mapping di allineamento delle etichette dispositivo tra corpora
(`data/label_mapping_v16.csv`) è stato fissato **prima** di eseguire
l'esperimento a tre laboratori: contiene tre corrispondenze esatte
(`philips-hue`, `ring-doorbell`, `smartthings`) e tre normalizzazioni
puramente meccaniche di trattino/maiuscole (`insteon-hub`,
`google-home-mini`, `roku-tv`), non scelte dopo aver visto il risultato.

## Nota v17: diagnostiche threelab, run OpenWrt local-revoke, benchmark concorrenza esteso

Per la revisione v16→v17 (risoluzione dei 20 punti di review su
`last_review/main_v17.0.tex`), tre esperimenti sono stati estesi con dati
reali generati in questa sessione:

**1. Diagnostiche sull'asimmetria threelab** (Sec. V-D). Nuovo script
`code/scripts/moniotr_three_lab_diagnostics.py` (riusa `load`,
`load_label_mapping`, `collapse_site_three`, `per_device_metrics`,
`leave_one_out_generalized` da `moniotr_cross_lab.py`, che ha ricevuto un
parametro `only_day` per il filtro temporale). Output in
`experiments/30_three_lab_loo/`:
- `reference_set_sizes.csv` — dimensione del reference set per ricevente/
  device type; conferma l'ipotesi che YT (cattura di un giorno, 40 PCAP)
  abbia reference set 4-6× più piccoli di US/UK, causa principale
  dell'asimmetria F1 osservata nella tabella principale.
- `bootstrap_ci.csv` — intervalli di confidenza bootstrap (1000 resample,
  seed 42) sul macro-F1 a 6 device type.
- `leave_one_device_out.csv` — sensibilità del macro-F1 alla rimozione di
  ciascun singolo device type.
- `leave_one_out_three_lab_single_day.csv` — troncamento a data
  calendariale identica (degenere: Mon(IoT)r copre 2019-03-29/2019-05-08,
  YourThings solo 2018-03-21, zero sovrapposizione).
- `leave_one_out_three_lab_single_day_window_matched.csv` — variante a
  finestra normalizzata per lunghezza (un giorno per sito, non stessa data),
  usata nel paper per il confronto onesto sulla sensibilità alla finestra
  temporale.

Stessi CSV grezzi di provenienza della nota v16 sopra (`DIB/data/processed/`,
path assoluti, hash registrati nei manifest).

**2. Run OpenWrt con local-revoke/local-restore** (Sec. V-A). Estensione di
`experiments/18_openwrt_enforcement/prepare_policy.py` e `run.sh` con due
nuove fasi dopo il recommit esistente: `local-revoke` (sito lab-a, nessun
voto remoto) e `local-restore`. Eseguito realmente via Docker/OpenWrt
23.05.5/osMUD; artifact in
`experiments/18_openwrt_enforcement/artifacts/20260903T122309Z-2757281/`.
Risultato: local-revoke azzera le ACE esportate e le regole nftables attive
(collassando la configurazione firewall a una singola regola reject-all)
senza bisogno di un secondo sito; local-restore riporta MonitorOnly senza
riattivare l'accesso.

**3. Benchmark di concorrenza esteso** (Sec. V-H). `code/scripts/
fsm_concurrency_harness.py` esteso con: fase di warm-up scartata dalle
misure, logging hardware (`platform.platform()`, `os.cpu_count()`, versione
Python) nel manifest, tre run ripetuti per configurazione (media±std di
throughput e percentili p50/p95/p99), e un decimo invariant dedicato
(`retry_budget_exhaustion_clean_rejection`) che fa competere 25 thread sullo
stesso fact per testare l'esaurimento del budget di retry. Output in
`code/outputs/fsm_concurrency_v17/` (le directory `code/outputs/
fsm_concurrency*/` precedenti restano intatte per confronto). Hardware
registrato: 16 core, Linux x86_64, CPython 3.10.13. Risultato onesto: con
questa metodologia a caldo (post warm-up) non si osservano più fallimenti
da esaurimento retry al carico misto originale (0 errori a tutti i livelli
di concorrenza, contro 1/200, 4/1000, 4/2000 del run singolo non riscaldato
precedente); il test dedicato a 25 writer concorrenti sullo stesso fact
completa comunque tutte le 625 operazioni senza esaurire il budget,
suggerendo che i fallimenti originari fossero un artefatto di cold-start
della prima misurazione piuttosto che una proprietà stazionaria del carico.

## Nota sulla mancanza di controllo di versione

Né `DIB/` né `DIB_reframe/` sono repository git in questo checkout — non
esiste un commit hash da registrare come riferimento di provenienza per il
codice sorgente. Questa cartella di riproducibilità è quindi l'unico
riferimento stabile allo stato del codice usato per produrre i risultati:
se in futuro il codice sorgente cambia, `code/` qui dentro resta la
versione esatta usata. Si raccomanda di inizializzare un repository git per
`DIB/` (`git init && git add -A && git commit`) prima della sottomissione
finale, per avere un hash di riferimento citabile nel paper.
