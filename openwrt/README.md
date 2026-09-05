# OpenWrt + osMUD enforcement harness

Run `./run.sh`. The harness pins OpenWrt 23.05.5 by image digest and osMUD
commit `852918e`, creates a fresh site-scoped registry, and checks MonitorOnly,
commit, TCP/UDP allow, wrong-port and wrong-destination deny, revoke, restore,
recommit, and site-local revoke/restore. It exits at the first policy/traffic
mismatch and retains the MUD,
osMUD log, UCI configuration, effective nftables ruleset, connection results,
database, and checksums under `artifacts/<UTC timestamp>/`.

The final `result.json` contains `claim_level=end-to-end enforcement` only after
both rule inspection and all traffic probes pass. A failed/incomplete run must
be described only up to its last verified stage.

## Dispute sequence, observed one step at a time (2026-08-11)

Earlier runs collapsed both disputes into a single `revoke` action, executed in
one transaction with one export afterwards, so the state *between* them was
never observed. The paper could therefore only attribute access removal to the
second, revoking dispute — while the design claims the **first** dispute already
suspends authorization and export eligibility. `revoke` is retained, but the
harness now drives `dispute1` and `dispute2` separately, exporting, reloading
osMUD, and probing after each.

Measured in `artifacts/20260811T135937Z-583864/`:

| Phase | Exported ACEs | nft rules for 8080/5353 | TCP probe |
|---|---|---|---|
| `01_monitor` (MonitorOnly) | 0 | — | — |
| `02_commit` (Active) | 2 | 2 | permitted |
| `03a_dispute1` (first dispute → Disputed) | **0** | **0** | **blocked** |
| `03b_dispute2` (second distinct site → Revoked) | 0 | 0 | blocked |
| `04_restore` (→ MonitorOnly) | 0 | 0 | blocked |
| `05_recommit` (fresh local commit → Active) | 2 | 2 | permitted |

So enforcement is withdrawn at the **first** dispute, not the second: the
`uci_after_dispute1.txt` / `ruleset_after_dispute1.txt` artifacts record the
gateway state at that point. `run.sh` now fails loudly
(`first dispute did not suspend enforcement`) if the packet filter still permits
the fact after `dispute1`, so this is a checked invariant rather than an
observation.

## Site-local revoke/restore, observed on the real gateway (2026-09-03)

`prepare_policy.py` gained two actions, `local-revoke` and `local-restore`,
wrapping `services.local_revoke()` / `services.local_restore()` (site
`lab-a`, the enforcing site itself). Unlike `dispute1`/`dispute2`, these touch
only `lab-a`'s own `LocalDecision` row: no second site's vote is needed to
suspend enforcement, and `score.status` (the cross-site dispute state) is left
untouched. `run.sh` now drives this sequence after the existing recommit step,
reloading osMUD and probing after each action exactly as for the dispute
phases.

Measured in `artifacts/20260903T122309Z-2757281/`:

| Phase | Exported ACEs | nft rules for 8080/5353 | TCP probe |
|---|---|---|---|
| `05_recommit` (fresh local commit → Active) | 2 | 2 | permitted |
| `06_local_revoke` (lab-a local-revoke, no second site → Revoked) | **0** | **0** | **refused** |
| `07_local_restore` (lab-a local-restore → MonitorOnly) | 0 | 0 | refused |

`uci_after_local_revoke.txt` shows the firewall config collapsed to a single
`mud_camera_REJECT-ALL` rule (the two `ACCEPT` rules present in
`uci_final.txt` are gone), matching `ruleset_local_revoke.txt`, which has zero
matches for ports 8080/5353. `local-restore` does not reintroduce them
(`ruleset_local_restore.txt` also has zero matches): restoring returns the
decision to MonitorOnly, and only a fresh `operator_commit()` grants Active
again, confirming the design's stated invariant that restore never
auto-reactivates enforcement. `run.sh` fails loudly
(`local-revoke did not suspend enforcement` / `local-restore reactivated
without commit`) if either check does not hold, so this is a checked
invariant, not just an observation. The run completed end-to-end
(`result.json`: `status: pass`) on the first attempt.

## Environment, disclosed

- **Not physical hardware**: a privileged Docker container running the OpenWrt
  23.05.5 rootfs (`sha256:a44cce5d…`), with veth pairs created by the harness.
- osMUD is built from source at commit `852918eb…` and run as
  `osmud -d -i -m DEBUG -e … -w … -b … -x … -l …` (see
  `router-entrypoint.sh`).
  **Resolved 2026-08-11**: querying the binary built from the pinned commit
  (`docker run --rm --entrypoint /usr/sbin/osmud 18_openwrt_enforcement-router -h`)
  gives its own documentation of the flag:

  ```
  -i: Do not fail processing when the MUD file p7s file does not validate
  ```

  So `-i` **is** the signature-validation bypass. The exported MUD file is
  unsigned and its signature is deliberately not checked. "Without source
  modification" remains true, but this is **not** a production-authenticated
  MUD path, and the paper now states that rather than leaving it open.
- There is **no native reload trigger**: each policy change kills and restarts
  osMUD, then waits 12 s. The DHCP event is a static file written by the
  harness, not a real lease.
- `firewall4`, `nftables-json`, `uci`, `curl`, `ca-bundle` are installed via
  opkg and pinned only indirectly, through the base image digest.
- One device (`camera`, site `lab-a`), one FQDN (`allowed.test`), two facts
  (TCP/8080, UDP/5353). Negative probes: wrong port 8081, wrong destination
  `blocked.test`.
- **Repetitions**: `artifacts/` holds 9 run directories. Eight are from
  2026-08-08: one complete (`20260808T143049Z-233884`) and seven truncated by
  `set -eu` during harness development. The 2026-08-11 run above is complete.
  The 2026-09-03 run (`20260903T122309Z-2757281`), which adds the
  local-revoke/local-restore phases, is also complete. The claim rests on
  complete runs only.
