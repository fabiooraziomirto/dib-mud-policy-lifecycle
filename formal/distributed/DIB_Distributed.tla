------------------------- MODULE DIB_Distributed -------------------------
(***************************************************************************)
(* Extension of DIB.tla (paper Sec. IV-B) modeling the one new mechanism    *)
(* the distributed prototype (10 site containers + 1 evidence container,   *)
(* code/src/dib/registry/distributed/service.py) actually introduces:      *)
(* a site can be unreachable when a Dispute/Restore fan-out fires, in       *)
(* which case its update is queued (pending) instead of applied, and later *)
(* applied by an explicit Reconcile action when the site reconnects --     *)
(* exactly the outbox/reconcile mechanism implemented and measured in      *)
(* fault_injection_experiment.py (30/30 trials converged, ~0.51s mean).     *)
(*                                                                         *)
(* This is a minimal-cost extension, not a full network model: it does not *)
(* model message loss, reordering of *distinct* pending events, or         *)
(* evidence-service failure (a declared, undischarged limitation -- see    *)
(* Discussion). It models exactly the one scenario implemented and tested: *)
(* a site is down for some stretch of time spanning one or more            *)
(* Dispute/Restore fan-outs, then reconnects and reconciles to current     *)
(* truth in one step (matching the real design: the outbox holds only the  *)
(* latest target state, not a replayed history -- see service.py's         *)
(* ON CONFLICT ... WHERE excluded.seq > pending_fanout.seq).               *)
(*                                                                         *)
(* Key modeling choice, corresponding directly to the reviewer-style        *)
(* observation that "conservative reversal is not instantaneous end-to-end,*)
(* only instantaneous in the registry's view for reachable sites": for an  *)
(* unreachable site t, Dispute/Restore leave state[t][f], revokeReason[t][f]*)
(* AND exported[t][f]/grantValid[t][f] entirely unchanged -- t's own       *)
(* gateway keeps enforcing the stale policy until Reconcile fires. This is *)
(* a deliberately stronger (more honest) choice than only queuing state:   *)
(* it is why DisputeSuspendsEverywhere (unchanged from DIB.tla) is         *)
(* expected, and shown below, to FAIL once sites can be unreachable -- a   *)
(* deliberate negative control, in the same spirit as the paper's Table IV *)
(* mutation controls, that motivates the new ReachableOnly reformulation.  *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Sites, Facts, AllowCommit, NoSite, NoFact,
    PartitionableSites  \* SUBSET Sites allowed to ever go down -- scopes the
                        \* model to "some designated site(s) can experience a
                        \* network partition", not every site toggling
                        \* reachability arbitrarily and independently, which
                        \* blew the state space up past tens of millions of
                        \* states with no sign of closing at this model's
                        \* scale (3 sites, 2 facts). Restricting to one site
                        \* keeps the extension genuinely minimal-cost while
                        \* still exercising every actual mechanism (queuing,
                        \* reconciliation, the provenance guard under it).

VARIABLES
    state, disputers, admissible, exported, grantValid, revokeReason, lastOp,
    unreachable,  \* SUBSET Sites: sites currently offline
    pending,      \* pending[s][f]: TRUE iff s missed a Dispute/Restore fan-out for f
    toggleCount   \* counts SiteDown+SiteUp actions so far, for the TLC CONSTRAINT
                  \* below -- bounds the model to a small, fixed number of
                  \* partition/reconnect cycles per behavior (unrestricted
                  \* toggling made the state space grow past 30M states with
                  \* no sign of closing even with only one partitionable site;
                  \* this is a standard, explicitly-declared model-checking
                  \* bound, not a silent restriction -- see DIB_Distributed.cfg).

vars == <<state, disputers, admissible, exported, grantValid, revokeReason, lastOp, unreachable, pending, toggleCount>>

States == {"Absent", "MonitorOnly", "Active", "Disputed", "Revoked"}
RevokeReasons == {"None", "Local", "Dispute"}
Ops == {"Init", "Contribute", "Rescore", "Query", "Commit", "Dispute", "Restore",
        "Export", "LocalRevoke", "LocalRestore", "SiteDown", "SiteUp", "Reconcile"}

OpRecord == [op: Ops, site: Sites \cup {NoSite}, fact: Facts \cup {NoFact}]

TypeOK ==
    /\ state      \in [Sites -> [Facts -> States]]
    /\ disputers  \in [Facts -> SUBSET Sites]
    /\ admissible \in [Facts -> BOOLEAN]
    /\ exported   \in [Sites -> [Facts -> BOOLEAN]]
    /\ grantValid \in [Sites -> [Facts -> BOOLEAN]]
    /\ revokeReason \in [Sites -> [Facts -> RevokeReasons]]
    /\ lastOp     \in OpRecord
    /\ unreachable \in SUBSET Sites
    /\ pending    \in [Sites -> [Facts -> BOOLEAN]]
    /\ toggleCount \in Nat

OpenDispute(f) == disputers[f] # {}

\* TLC state constraint (see DIB_Distributed.cfg): bounds exploration to at
\* most two full SiteDown/SiteUp cycles per behavior. Declared explicitly,
\* not a silent restriction -- see the toggleCount VARIABLES comment above.
ToggleBound == toggleCount <= 4

Note(o, s, f) == lastOp' = [op |-> o, site |-> s, fact |-> f]

Init ==
    /\ state      = [s \in Sites |-> [f \in Facts |-> "Absent"]]
    /\ disputers  = [f \in Facts |-> {}]
    /\ admissible \in [Facts -> BOOLEAN]
    /\ exported   = [s \in Sites |-> [f \in Facts |-> FALSE]]
    /\ grantValid = [s \in Sites |-> [f \in Facts |-> FALSE]]
    /\ revokeReason = [s \in Sites |-> [f \in Facts |-> "None"]]
    /\ lastOp     = [op |-> "Init", site |-> NoSite, fact |-> NoFact]
    /\ unreachable = {}
    /\ pending    = [s \in Sites |-> [f \in Facts |-> FALSE]]
    /\ toggleCount = 0

Contribute(s, f) ==
    /\ admissible' = [admissible EXCEPT ![f] = TRUE]
    /\ UNCHANGED <<state, disputers, exported, grantValid, revokeReason, unreachable, pending, toggleCount>>
    /\ Note("Contribute", s, f)

Rescore(f) ==
    /\ \E b \in BOOLEAN : admissible' = [admissible EXCEPT ![f] = b]
    /\ UNCHANGED <<state, disputers, exported, grantValid, revokeReason, unreachable, pending, toggleCount>>
    /\ Note("Rescore", NoSite, f)

Query(s, f) ==
    /\ state[s][f] = "Absent"
    /\ admissible[f]
    /\ ~OpenDispute(f)
    /\ state' = [state EXCEPT ![s][f] = "MonitorOnly"]
    /\ UNCHANGED <<disputers, admissible, exported, grantValid, revokeReason, unreachable, pending, toggleCount>>
    /\ Note("Query", s, f)

OperatorCommit(s, f) ==
    /\ AllowCommit
    /\ state[s][f] = "MonitorOnly"
    /\ state' = [state EXCEPT ![s][f] = "Active"]
    /\ grantValid' = [grantValid EXCEPT ![s][f] = TRUE]
    /\ revokeReason' = [revokeReason EXCEPT ![s][f] = "None"]
    /\ UNCHANGED <<disputers, admissible, exported, unreachable, pending, toggleCount>>
    /\ Note("Commit", s, f)

Export(s, f) ==
    /\ state[s][f] = "Active"
    /\ exported' = [exported EXCEPT ![s][f] = TRUE]
    /\ UNCHANGED <<state, disputers, admissible, grantValid, revokeReason, unreachable, pending, toggleCount>>
    /\ Note("Export", s, f)

(***************************************************************************)
(* Dispute/Restore now split their fan-out: a reachable site is updated     *)
(* immediately, exactly as in DIB.tla. An unreachable site's state,        *)
(* revokeReason, exported and grantValid are all left unchanged (its own   *)
(* gateway keeps enforcing whatever it last knew) and pending[t][f] is set *)
(* so Reconcile can catch it up later.                                     *)
(***************************************************************************)
Dispute(s, f) ==
    /\ s \notin disputers[f]
    /\ disputers' = [disputers EXCEPT ![f] = @ \cup {s}]
    /\ LET votes == Cardinality(disputers[f] \cup {s})
           target == IF votes >= 2 THEN "Revoked" ELSE "Disputed"
           reach(t) == t \notin unreachable
       IN /\ state' = [t \in Sites |-> [g \in Facts |->
                    IF g = f /\ reach(t) /\ state[t][g] \in {"MonitorOnly", "Active", "Disputed"}
                    THEN target ELSE state[t][g]]]
          /\ revokeReason' = [t \in Sites |-> [g \in Facts |->
                    IF g = f /\ reach(t) /\ state[t][g] \in {"MonitorOnly", "Active", "Disputed"}
                    THEN "Dispute" ELSE revokeReason[t][g]]]
          /\ exported' = [t \in Sites |-> [g \in Facts |->
                    IF g = f /\ reach(t) THEN FALSE ELSE exported[t][g]]]
          /\ grantValid' = [t \in Sites |-> [g \in Facts |->
                    IF g = f /\ reach(t) THEN FALSE ELSE grantValid[t][g]]]
          /\ pending' = [t \in Sites |-> [g \in Facts |->
                    IF g = f /\ ~reach(t) THEN TRUE ELSE pending[t][g]]]
    /\ UNCHANGED <<admissible, unreachable, toggleCount>>
    /\ Note("Dispute", s, f)

Restore(s, f) ==
    /\ OpenDispute(f)
    /\ LET reach(t) == t \notin unreachable
           shouldReset(t) == state[t][f] = "Disputed" \/
                             (state[t][f] = "Revoked" /\ revokeReason[t][f] = "Dispute")
       IN /\ state' = [t \in Sites |-> [g \in Facts |->
                    IF g = f /\ reach(t) /\ shouldReset(t) THEN "MonitorOnly" ELSE state[t][g]]]
          /\ revokeReason' = [t \in Sites |-> [g \in Facts |->
                    IF g = f /\ reach(t) /\ revokeReason[t][g] = "Dispute" THEN "None" ELSE revokeReason[t][g]]]
          /\ exported' = [t \in Sites |-> [g \in Facts |->
                    IF g = f /\ reach(t) THEN FALSE ELSE exported[t][g]]]
          /\ pending' = [t \in Sites |-> [g \in Facts |->
                    IF g = f /\ ~reach(t) THEN TRUE ELSE pending[t][g]]]
    /\ disputers' = [disputers EXCEPT ![f] = {}]
    /\ UNCHANGED <<admissible, grantValid, unreachable, toggleCount>>
    /\ Note("Restore", s, f)

LocalRevoke(s, f) ==
    /\ \/ state[s][f] \in {"MonitorOnly", "Active", "Disputed"}
       \/ /\ state[s][f] = "Revoked"
          /\ revokeReason[s][f] = "Dispute"
    /\ state' = [state EXCEPT ![s][f] = "Revoked"]
    /\ exported' = [exported EXCEPT ![s][f] = FALSE]
    /\ grantValid' = [grantValid EXCEPT ![s][f] = FALSE]
    /\ revokeReason' = [revokeReason EXCEPT ![s][f] = "Local"]
    /\ UNCHANGED <<disputers, admissible, unreachable, pending, toggleCount>>
    /\ Note("LocalRevoke", s, f)

LocalRestore(s, f) ==
    /\ state[s][f] = "Revoked"
    /\ revokeReason[s][f] = "Local"
    /\ ~OpenDispute(f)
    /\ state' = [state EXCEPT ![s][f] = "MonitorOnly"]
    /\ revokeReason' = [revokeReason EXCEPT ![s][f] = "None"]
    /\ UNCHANGED <<disputers, admissible, exported, grantValid, unreachable, pending, toggleCount>>
    /\ Note("LocalRestore", s, f)

(***************************************************************************)
(* New actions. SiteDown/SiteUp toggle reachability alone -- no authority   *)
(* state changes just because a site's network reachability changes.       *)
(* Reconcile(t, f) is the single-step model of GET /pending + POST         *)
(* /reconcile: it recomputes, from CURRENT global truth (not from any      *)
(* remembered stale intermediate value -- matching the real outbox's       *)
(* latest-wins design), whatever a fresh Dispute or Restore would have     *)
(* applied to site t alone, using the SAME guards (from_states, and the    *)
(* provenance check that a Local revoke is never overwritten) as those     *)
(* actions apply to every other site.                                      *)
(***************************************************************************)
SiteDown(s) ==
    /\ s \in PartitionableSites
    /\ s \notin unreachable
    /\ toggleCount' = toggleCount + 1
    /\ unreachable' = unreachable \cup {s}
    /\ UNCHANGED <<state, disputers, admissible, exported, grantValid, revokeReason, pending>>
    /\ Note("SiteDown", s, NoFact)

SiteUp(s) ==
    /\ s \in unreachable
    /\ toggleCount' = toggleCount + 1
    /\ unreachable' = unreachable \ {s}
    /\ UNCHANGED <<state, disputers, admissible, exported, grantValid, revokeReason, pending>>
    /\ Note("SiteUp", s, NoFact)

Reconcile(t, f) ==
    /\ pending[t][f]
    /\ t \notin unreachable
    /\ pending' = [pending EXCEPT ![t][f] = FALSE]
    /\ \/ /\ OpenDispute(f)
          /\ LET votes == Cardinality(disputers[f])
                 target == IF votes >= 2 THEN "Revoked" ELSE "Disputed"
             IN \/ /\ state[t][f] \in {"MonitorOnly", "Active", "Disputed"}
                   /\ state' = [state EXCEPT ![t][f] = target]
                   /\ revokeReason' = [revokeReason EXCEPT ![t][f] = "Dispute"]
                   /\ exported' = [exported EXCEPT ![t][f] = FALSE]
                   /\ grantValid' = [grantValid EXCEPT ![t][f] = FALSE]
                \/ /\ state[t][f] \notin {"MonitorOnly", "Active", "Disputed"}
                   /\ UNCHANGED <<state, revokeReason, exported, grantValid>>
       \/ /\ ~OpenDispute(f)
          /\ \/ /\ (state[t][f] = "Disputed" \/ (state[t][f] = "Revoked" /\ revokeReason[t][f] = "Dispute"))
                /\ state' = [state EXCEPT ![t][f] = "MonitorOnly"]
                /\ revokeReason' = [revokeReason EXCEPT ![t][f] = "None"]
                /\ exported' = [exported EXCEPT ![t][f] = FALSE]
                /\ UNCHANGED grantValid
             \/ /\ ~(state[t][f] = "Disputed" \/ (state[t][f] = "Revoked" /\ revokeReason[t][f] = "Dispute"))
                /\ UNCHANGED <<state, revokeReason, exported, grantValid>>
    /\ UNCHANGED <<disputers, admissible, unreachable, toggleCount>>
    /\ Note("Reconcile", t, f)

Next ==
    \E s \in Sites, f \in Facts :
        \/ Contribute(s, f)
        \/ Rescore(f)
        \/ Query(s, f)
        \/ OperatorCommit(s, f)
        \/ Export(s, f)
        \/ Dispute(s, f)
        \/ Restore(s, f)
        \/ LocalRevoke(s, f)
        \/ LocalRestore(s, f)
        \/ SiteDown(s)
        \/ SiteUp(s)
        \/ Reconcile(s, f)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants carried over unchanged from DIB.tla.                         *)
(***************************************************************************)
ExportRequiresActive ==
    \A s \in Sites, f \in Facts : exported[s][f] => state[s][f] = "Active"

FreshLocalAuthorization(s, f) == grantValid[s][f]

ExportRequiresFreshAuthorization ==
    \A s \in Sites, f \in Facts : exported[s][f] => FreshLocalAuthorization(s, f)

AuthorizationStateCoherence ==
    \A s \in Sites, f \in Facts : FreshLocalAuthorization(s, f) <=> state[s][f] = "Active"

(***************************************************************************)
(* DisputeSuspendsEverywhere is carried over VERBATIM from DIB.tla and is   *)
(* EXPECTED TO FAIL here -- a deliberate negative control. An unreachable   *)
(* site keeps whatever state it had when the dispute opened; DIB.tla's     *)
(* implicit "everywhere" silently assumed every site is always reachable.  *)
(* This is the honest, falsifiable version of the "immediately... across   *)
(* all sites" claim the paper's I3 discussion previously left unstated for *)
(* the distributed deployment.                                             *)
(***************************************************************************)
DisputeSuspendsEverywhere ==
    \A f \in Facts : OpenDispute(f) =>
        \A s \in Sites : state[s][f] \in {"Absent", "Disputed", "Revoked"}

(* The reachable-only reformulation: what the model DOES guarantee. A site  *)
(* must be BOTH reachable AND already reconciled (~pending) to be held to   *)
(* the suspension guarantee -- a site that just came back up (SiteUp) but   *)
(* has not yet run Reconcile is, correctly, still in the same brief stale   *)
(* window the real system measures between a container's health check      *)
(* passing and its own /reconcile call completing (~0.06s empirically, see  *)
(* fault_injection_experiment.py). The first version of this invariant      *)
(* (reachable alone, not also requiring ~pending) was itself violated by    *)
(* TLC in exactly this window -- caught by the model, not asserted away.    *)
DisputeSuspendsAtReachableSites ==
    \A f \in Facts : OpenDispute(f) =>
        \A s \in Sites \ unreachable : ~pending[s][f] => state[s][f] \in {"Absent", "Disputed", "Revoked"}

NoActiveWithoutCommit ==
    \A s \in Sites, f \in Facts : state[s][f] # "Active"

I1_NonEscalation ==
    [][ \A s \in Sites, f \in Facts :
            (state[s][f] # "Active" /\ state'[s][f] = "Active") =>
                /\ lastOp'.op = "Commit"
                /\ lastOp'.site = s
                /\ state[s][f] = "MonitorOnly" ]_vars

FreshAuthorizationCreatedLocally ==
    [][ \A s \in Sites, f \in Facts :
            (~FreshLocalAuthorization(s, f) /\ grantValid'[s][f]) =>
                /\ lastOp'.op = "Commit"
                /\ lastOp'.site = s
                /\ state[s][f] = "MonitorOnly" ]_vars

I2_SiteConfinement ==
    [][ (lastOp'.op = "Commit") =>
            \A t \in Sites \ {lastOp'.site}, g \in Facts :
                state'[t][g] = state[t][g] ]_vars

(* Carried over from DIB.tla, but restricted to sites that are reachable   *)
(* AND already reconciled at the moment Restore fires (t \notin unreachable *)
(* /\ ~pending'[t][...]) -- TLC found the unrestricted version (checked     *)
(* first) genuinely violated: a site unreachable through an entire          *)
(* Dispute-then-Restore episode never has its Active/grantValid state      *)
(* touched by either action, so it remains Active with a valid grant the    *)
(* whole time it is offline. This is not a bug in Restore -- it is the      *)
(* formal confirmation of the exact risk flagged for Discussion: the        *)
(* registry's own bookkeeping is invalidated immediately only for reachable *)
(* sites; a partitioned site's actual local enforcement stays stale (and    *)
(* would keep exporting an already-revoked-at-the-registry rule) for        *)
(* however long it remains unreachable, not just for the ~0.5s             *)
(* reconciliation window measured once it reconnects.                       *)
I3_ConservativeRestore ==
    [][ (lastOp'.op = "Restore") =>
            \A t \in Sites : (t \notin unreachable' /\ ~pending'[t][lastOp'.fact]) =>
                /\ state'[t][lastOp'.fact] # "Active"
                /\ ~grantValid'[t][lastOp'.fact] ]_vars

I3_DisputeClearsExport ==
    [][ (lastOp'.op = "Dispute") =>
            \A t \in Sites \ unreachable' : exported'[t][lastOp'.fact] = FALSE ]_vars

I3_DisputeInvalidatesAuthorization ==
    [][ (lastOp'.op = "Dispute") =>
            \A t \in Sites \ unreachable' : ~grantValid'[t][lastOp'.fact] ]_vars

UnrelatedFactIsolation ==
    [][ (lastOp'.op \in {"Query", "Commit", "Dispute", "Restore", "Export",
                          "LocalRevoke", "LocalRestore", "Reconcile"}) =>
            \A t \in Sites, g \in Facts \ {lastOp'.fact} :
                state'[t][g] = state[t][g] ]_vars

I2_LocalRevokeConfinement ==
    [][ (lastOp'.op \in {"LocalRevoke", "LocalRestore"}) =>
            \A t \in Sites \ {lastOp'.site}, g \in Facts :
                state'[t][g] = state[t][g] ]_vars

I3_LocalRestoreConservative ==
    [][ (lastOp'.op = "LocalRestore") =>
            state'[lastOp'.site][lastOp'.fact] = "MonitorOnly" ]_vars

(* Carried over, now also guarding the Reconcile step itself: a Reconcile   *)
(* that finally applies a queued Restore must still never touch a site     *)
(* that (by the time it reconnected) had already done its own LocalRevoke. *)
I3_GlobalRestorePreservesLocalRevoke ==
    [][ (lastOp'.op \in {"Restore", "Reconcile"}) =>
            \A t \in Sites :
                (state[t][lastOp'.fact] = "Revoked" /\
                 revokeReason[t][lastOp'.fact] = "Local") =>
                /\ state'[t][lastOp'.fact] = "Revoked"
                /\ revokeReason'[t][lastOp'.fact] = "Local" ]_vars

EvidenceNeverMovesState ==
    [][ (lastOp'.op \in {"Contribute", "Rescore"}) =>
            /\ state' = state
            /\ grantValid' = grantValid
            /\ revokeReason' = revokeReason ]_vars

(* New: Reconcile is confined to the one (site, fact) it targets, exactly   *)
(* like Commit/LocalRevoke -- it must not touch any other site's state.     *)
I2_ReconcileConfinement ==
    [][ (lastOp'.op = "Reconcile") =>
            \A t \in Sites \ {lastOp'.site}, g \in Facts :
                state'[t][g] = state[t][g] ]_vars

=============================================================================
