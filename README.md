# DIB — Managing Local MUD Policy Lifecycles with Shared IoT Traffic Evidence

Reproducibility artifact for the IEEE TNSM submission *DIB: Managing Local MUD Policy
Lifecycles with Shared IoT Traffic Evidence* (paper version v31.1, `paper/main.pdf`).

Device Intent Blueprint (DIB) separates shared traffic evidence from per-site
authorization for MUD policy management across independently administered networks.
This repository contains the TLA+ models and their model-checking logs, the registry
implementation and its test suite, the OpenWrt/osMUD enforcement harness, and the
compact evidence backing every number printed in the paper.

## Quick verification

```bash
python3 -m venv .venv
.venv/bin/pip install -e 'code[dev]'
.venv/bin/python scripts/verify_artifact.py --with-tests
```

`scripts/verify_artifact.py` recomputes **every headline number of the paper** from the
stored evidence files and fails if any of them disagrees with the published value: model
sizes and mutation counterexamples, retention and recall, the matched cold-start
ablation, adversarial admission scores, concurrency and reconciliation timings. It needs
no third-party trace data and runs in seconds. `--with-tests` additionally runs the unit
suite (275 tests).

The selected configuration is graph-free (`gamma: 0`). Do not enable graph-augmented
reconstruction in this workflow: it is intentionally excluded and is substantially more
memory-hungry.

## Layout

| Path | Contents |
|---|---|
| `paper/` | Paper source and compiled PDF |
| `claims.json` | Machine-readable map: claim → evidence file → generator → input |
| `scripts/verify_artifact.py` | Recomputes every claim from the evidence |
| `formal/base/` | TLA+ lifecycle model (`DIB.tla`), configurations, TLC runner |
| `formal/distributed/` | Extended model with site reachability and reconciliation |
| `formal/logs/` | TLC logs, six mutation controls, registry regression traces |
| `code/` | Registry (FastAPI, SQLAlchemy 2, SQLite), evaluation pipeline, 59 experiment scripts, 275 tests |
| `configs/` | Locked scoring configurations |
| `openwrt/` | OpenWrt 23.05.5 + osMUD enforcement harness (Docker) |
| `results/` | Compact per-claim evidence (CSV/JSON/logs) |
| `docs/` | Data provenance, known limitations, device label mapping |

## Reproducing the formal results

Requires Java and `tla2tools.jar`.

```bash
# Base lifecycle model: 3,837,084 reachable states, six mutation controls
TLA_TOOLS=/path/to/tla2tools.jar JAVA_TOOL_OPTIONS='-Xmx4g -XX:+UseParallelGC' \
  sh formal/base/run_tlc.sh formal/logs

# Distributed extension: 718,571 states generated, 44,610 distinct, depth 18
cd formal/distributed && java -cp /path/to/tla2tools.jar tlc2.TLC \
  -workers 4 -config DIB_Distributed.cfg DIB_Distributed.tla
```

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
