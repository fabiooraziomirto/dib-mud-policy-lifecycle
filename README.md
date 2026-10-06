# DIB — Managing Local MUD Policy Lifecycles with Shared IoT Traffic Evidence

Reproducibility artifact for the IEEE TNSM submission *DIB: Managing Local MUD Policy
Lifecycles with Shared IoT Traffic Evidence* (paper version v42.0, `paper/main.pdf`).
The directory name `dib-tnsm-artifact-v36` is retained for continuity; the current
paper and claim index are v42.0. This is a local pre-submission package, not an
archived public release.

Device Intent Blueprint (DIB) separates shared traffic evidence from per-site
authorization for MUD policy management across independently administered networks.
This repository contains the TLA+ models and their model-checking logs, the registry
implementation and its test suite, the OpenWrt/osMUD enforcement harness, and the
compact evidence for the indexed paper claims.

## Quick verification

```bash
python3 -m venv .venv
.venv/bin/pip install -e 'code[dev]'
.venv/bin/python scripts/verify_artifact.py --with-tests
```

`scripts/verify_artifact.py` checks the indexed headline values against the
stored evidence files and fails on a mismatch: model
sizes and mutation counterexamples, retention and recall, the matched cold-start
ablation, adversarial admission scores, concurrency and reconciliation timings. It needs
no third-party trace data and runs in seconds. `--with-tests` additionally runs the unit
suite. It does not rerun TLC, traffic processing or gateway campaigns, and is not
a verification of every sentence in the paper.

## New in v36.0

- `results/restore_ablation/`: six event sequences per restoration policy,
  executed through the same API, SQLite service and MUD serializer; full traces
  distinguish recreated exports from erased local vetoes.
- `results/lifecycle_v35/`: suspension-threshold API campaign and current
  focused registry/rescoring regression log.
- `formal/base/`, `formal/distributed/`, `formal/mutations/`: current models,
  including local veto during shared withdrawal, with their completed TLC logs.
- `results/dispute_flood/`: earlier networked availability measurements,
  explicitly separate from the in-process API campaigns.
- `docs/RELATED_WORK_SCOPE.md`: primary-source positioning and comparison limits.

Re-run the new ablation without third-party data:

```sh
PYTHONPATH=code/src python3 code/scripts/v36_restore_ablation.py --output /tmp/restore-ablation.json
PYTHONPATH=code/src python3 code/scripts/v35_lifecycle_experiment.py
```

The two alternatives are controlled experimental adapters, not published systems.
No production service transition is changed by the v36 ablation. Tests assume
trusted caller identities and make no WAN or gateway-timing claim.

The selected configuration is graph-free (`gamma: 0`). Do not enable graph-augmented
reconstruction in this workflow: it is intentionally excluded and is substantially more
memory-hungry.

## New in v42.0

- `results/a1_resolvable/`: resolved-peer counterfactual for the captured A1
  replay. All 354 raw captured packets are IP-literal, so all 59 facts fail
  endpoint eligibility regardless of score (0/150 admitted cells); replacing
  the captured IP with a resolvable name, holding devices/sites/timing fixed,
  raises admission to 21/150 cells, first at $k=7$ sites over a 120-day
  window. This isolates a class-gate artifact of the dataset's peer format
  from an admission-score result.
- `results/pareto_frontier/`: theta/m sweep on the three-lab leave-one-out
  setting, placing quorum, quorum+score, DIB, and the ranked-union curve on
  one queue-size/recall frontier (paper Fig. 4). The operating point
  (theta=0.65, m=2) reproduces the matched-ablation DIB row exactly.
- `results/offline_veto/`: ten trials over real loopback HTTP with
  independent site/evidence processes. A local veto recorded before a site is
  killed survives a complete missed dispute/confirmation/restore episode for
  that fact; the same site's stale Active fact returns to MonitorOnly on
  reconciliation; neither exports before a fresh commit; an unrelated Active
  fact stays exportable throughout.

Re-run the three new experiments without third-party data (the first two need
UNSW/Mon(IoT)r/YourThings traces obtained separately under their terms; the
third needs none):

```sh
PYTHONPATH=code/src python3 code/scripts/a1_resolvable_counterfactual.py
PYTHONPATH=code/src python3 code/scripts/pareto_frontier.py
PYTHONPATH=code/src python3 code/scripts/offline_veto_reconciliation.py --trials 10
```

The lifecycle table's retention-window transition (`MonitorOnly` to `Absent`
after prolonged sub-threshold evidence) is specified in the paper but not yet
implemented in the registry or included in the TLA+ model; it carries no
entry in `claims.json` and no result under `results/` for that reason.

## Layout

| Path | Contents |
|---|---|
| `paper/` | Paper source and compiled PDF |
| `claims.json` | Machine-readable map: claim → evidence file → generator → input |
| `scripts/verify_artifact.py` | Checks indexed headline evidence, including the new campaigns |
| `formal/base/` | TLA+ lifecycle model (`DIB.tla`), configurations, TLC runner |
| `formal/distributed/` | Extended model with site reachability and reconciliation |
| `formal/logs/` | TLC logs, six mutation controls, registry regression traces |
| `code/` | Registry, distributed services, evaluation pipeline, experiment scripts and tests |
| `configs/` | Locked scoring configurations |
| `openwrt/` | OpenWrt 23.05.5 + osMUD enforcement harness (Docker) |
| `results/` | Compact per-claim evidence (CSV/JSON/logs) |
| `docs/` | Data provenance, known limitations, device label mapping |

## Reproducing the formal results

Requires Java and `tla2tools.jar`.

```bash
python3 scripts/run_formal.py --jar /path/to/tla2tools.jar --output /tmp/dib-tlc-rerun
# Faster check of the six frozen mutation controls only:
python3 scripts/run_formal.py --jar /path/to/tla2tools.jar --mutations-only --output /tmp/dib-tlc-mutations
```

The stored full-model logs report 4,311,852 reachable states, or 2,076,196
without commit. The distributed extension reports 815,335 generated states,
48,960 distinct, depth 18. The runner checks the specific expected violation for
each mutation and runs each job in its own temporary directory. Historical
mutation/regression logs with older names are retained for provenance; current
paths are identified in `claims.json`.

Both models are finite (three sites, one or two endpoint facts). They check lifecycle
transitions under authenticated identities; gateway enforcement, distributed
linearizability, message loss and evidence-service failure are outside their scope.

## Reproducing the OpenWrt enforcement case study

Requires Linux, Docker, and the images declared in `openwrt/docker-compose.yml`. The
driver runs one harness instance at a time, requires at least 8 GiB `MemAvailable`
before each run, cleans up containers and networks through the harness, and never
retries a failed run.

```bash
cd openwrt && python3 run_campaign.py --runs 10
```

Only a complete 10/10 campaign is a final result; on failure keep the campaign directory
and log, diagnose, and start a clean campaign. The supplied campaign
(`results/openwrt/campaign-10runs/`) is a functional case study, not a reliability
estimate: one device, one FQDN, containerized OpenWrt, unsigned MUD export, forced
reload. Production deployment requires signed MUD profiles and PKI.

## Data and licensing

**No third-party trace data is redistributed here.** Full regeneration of the
data-derived results requires obtaining UNSW-IoTraffic, Mon(IoT)r and YourThings
separately under their respective terms and configuring local paths outside this
repository. `claims.json` records, for every claim, whether it needs licensed input;
claims marked `"input": "none"` (the formal models, the concurrency, reconciliation and
architectural results) are fully reproducible from this repository alone.
`docs/data_provenance.md` documents each corpus, its adapter, and the input hashes.

Repository code is MIT-licensed (`LICENSE`). Third-party datasets and Docker images
retain their own licenses.

TLC logs, run manifests and checksum files under `formal/logs/` and `results/` retain the
absolute paths of the machine on which they were produced. They are records of actual
runs and are deliberately left unedited; rewriting them would invalidate the provenance
they document. No code or configuration in this repository depends on those paths.

## Scope

DIB manages partial MUD policy proposals under authenticated-consortium assumptions. It
does not establish that approved traffic is benign, does not guarantee immediate
withdrawal at an unreachable gateway, and does not implement caller authentication or
role enforcement — those are deployment assumptions, stated in the paper's threat model
and listed in `docs/KNOWN_LIMITATIONS.md`.
