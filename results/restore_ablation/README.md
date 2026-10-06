# Restoration-policy ablation (v36.0)

Run from the repository root:

```sh
PYTHONPATH=code/src python3 code/scripts/v36_restore_ablation.py --output /tmp/restore-ablation.json
```

`results.json` contains the completed run, source/script SHA-256 digests,
all state/export-count traces, and a summary. No external data, sockets,
gateway, or timing measurement is involved. FastAPI TestClient, real SQLite
databases, and the existing MUD serializer execute each case.

## Controlled alternatives

All policies start with the same two admitted and locally approved facts at
three sites, use immediate suspension, and share the original service code.
The subject is a camera endpoint; an unrelated sensor endpoint is the control.

- `persistent_approval`: an auxiliary SQLite bit records a successful local
  commit and is cleared by a successful local revoke. Shared withdrawal does
  not clear this bit; restore reuses it. Local-veto protection is retained,
  giving this alternative the same veto semantics as DIB.
- `review_reset`: restore resets every staged record to MonitorOnly, including
  locally revoked records. It does not recreate approval.
- `dib`: the original service transition implementation, without a restore adapter.

Adapters are installed only in isolated experiment module instances. Production
service source is not modified. These are deliberately defined design alternatives,
not implementations of POLARIS, FIDEM, or any other published system. They are
sequential semantic controls, not concurrent transactional implementations.

## Six sequences per policy

A veto at site-0 occurs before the opening dispute, between opening and
confirmation, or after confirmation. Each ordering runs both with full delivery
and with site-2 missing the entire dispute/confirmation/restore episode.
Disconnection is a deterministic injected HTTP transport exception, exercising
the real pending-outbox and reconciliation paths without latency simulation.

At final restore/reconciliation, before any new commit:

| Policy | Subject ACEs exported / 18 site-case opportunities | Vetoes preserved / 6 |
| --- | --- | --- |
| Persistent approval | 12/18 | 6/6 |
| Blanket review reset | 0/18 | 0/6 |
| DIB | 0/18 | 6/6 |

The two non-vetoing sites account for the persistent policy's exports. Offline
sites may retain an active stale record during the outage under every policy;
the table reports the state after reconciliation, not instantaneous withdrawal.
The experiment also asserts that local restore is blocked during the episode,
the unrelated fact remains exported, duplicate reconciliation and stale event
replay do not change the final state, and explicit recovery restores all exports.

These counts describe selected deterministic cases, not failure rates or a
statistical generalization. The experiment isolates the consequence of restore
semantics, complementing the finite-model guard mutations.
