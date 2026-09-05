# Esperimento 7 — Sweep Sybil persistente, configurazione selezionata (graph-free)

**Claim nel paper:** sweep Sybil persistente (200-3200 identità × 20-400
giorni di persistenza) sulla config graph-free selezionata
(α,β,γ,θ)=(0.6,0.4,0,0.65), a supporto delle righe 458-490 di `main.tex`
(mitigazioni trust-weighted e independence-aware). Prima di questa sessione
questo claim non era coperto da nessun esperimento in `experiments/`: solo
la config strict alternativa (`experiments/04_strict_alternative_config/`)
aveva uno sweep Sybil salvato.

## Config esatta

`configs/graph_free_selected.yaml` (= `ref_trust_hyperparams.yaml`).

## Script

`code/scripts/sybil_sensitivity_surface.py` — lo stesso script usato per
`experiments/04_strict_alternative_config/sybil/`, mai lanciato prima con
questa config. Eseguito con il fix di `CHANGELOG.md` voce 6 già applicato
(il filtro `exclude_non_global_ips` è ora attivo di default).

## Input

- `data/processed/observations_enriched.csv` (derivato, va rigenerato —
  vedi `data_provenance.md`).
- `--calibration-observations`: CSV derivato di 68MB, non incluso per
  dimensione; rigenerabile deterministicamente con
  `scripts/prepare_rwv_governance_bootstrap.py --seed 4201` (vedi comando
  completo in `experiments/04_strict_alternative_config/README.md`).

## Comando esatto

```bash
cd DIB/
python3 scripts/sybil_sensitivity_surface.py \
  --config configs/ref_trust_hyperparams.yaml \
  --observations data/processed/observations_enriched.csv \
  --calibration-observations /path/to/governance_bootstrap/calibration_observations.csv \
  --output-dir outputs/tnsm_submission_2026/sybil_selected
```

`--exclude-non-global-ips` non è stato passato esplicitamente: dopo il fix
ha `default=True` (`BooleanOptionalAction`), quindi è comunque attivo —
confermato a runtime in `run.log` (`exclude_non_global_ips=True`).

## Output in questa cartella

- `sybil_sensitivity_surface.csv` — 48 celle (6 conteggi Sybil × 8 finestre
  di persistenza), colonne per vanilla / trust / independence / RWV.
- `run.log` — log completo, incluso `loaded 1268020 observations (10
  genuine sites)`.
- `manifest.json` — comando esatto, timing (846.2s, ~14.1 min), picco RSS
  3.51GB, seed=42.

## Risultato aggregato (verificato dal CSV, non dal testo del paper)

Su tutte le 48 celle dello sweep: il fake endpoint (`evil-c2.net`) non
viene **mai** accettato sotto trust-weighting (0/48) né sotto
independence-awareness (0/48); il vanilla scorer lo accetta in 45/48 celle
(nessuna mitigazione, come atteso). RWV lo accetta sempre (48/48) — stesso
comportamento qualitativo già osservato per la config strict in
`experiments/04_strict_alternative_config/`.

## Tempo atteso (seriale)

~846s (~14 minuti), picco RSS ~3.5GB.
