-------------------------------- MODULE DIB --------------------------------
(***************************************************************************)
(* Mechanized model of the DIB site-local authority lifecycle (paper        *)
(* Sec. IV-B): the import machine M_s = (S, Sigma, delta, Absent) together  *)
(* with dispute episodes, evidence-only operations, export, and a current  *)
(* local-authorization token.                                              *)
(*                                                                         *)
(* What is modeled: the transition function, the fan-out of dispute and     *)
(* restore over every extant local record of one fact, the one-vote /       *)
(* two-distinct-sites dispute thresholds, the openDispute staging block,    *)
(* export eligibility, authorization invalidation, and local-revoke         *)
(* provenance.                                                              *)
(*                                                                         *)
(* What is abstracted: candidate admission (eligibility class, score,       *)
(* quorum) collapses into the boolean admissible[f], since the invariants   *)
(* are claimed to hold for *any* admission verdict; serializer support is   *)
(* likewise not modeled beyond requiring Active. The model checks safety    *)
(* over committed states, not linearizability of concurrent requests.       *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Sites,        \* authenticated site identities
    Facts,        \* endpoint facts (d,e)
    AllowCommit,  \* FALSE removes OPERATOR-COMMIT, leaving Sigma_ev only
    NoSite,       \* placeholder actor for operations with no acting site
    NoFact        \* placeholder subject for the initial step

VARIABLES
    state,        \* state[s][f] in States: the site-local import state
    disputers,    \* disputers[f]: sites that voted in the open episode
    admissible,   \* admissible[f]: current admission verdict (abstracted)
    exported,     \* exported[s][f]: serializer has emitted an ACE for f
    grantValid,   \* fresh site-local authorization not yet invalidated
    revokeReason, \* "None", "Local", or "Dispute" for a revoked record
    lastOp        \* provenance of the last step, for the action properties

vars == <<state, disputers, admissible, exported, grantValid, revokeReason, lastOp>>

States == {"Absent", "MonitorOnly", "Active", "Disputed", "Revoked"}
RevokeReasons == {"None", "Local", "Dispute"}
Ops    == {"Init", "Contribute", "Rescore", "Query", "Commit",
           "Dispute", "Restore", "Export", "LocalRevoke", "LocalRestore"}

OpRecord == [op: Ops, site: Sites \cup {NoSite}, fact: Facts \cup {NoFact}]

TypeOK ==
    /\ state      \in [Sites -> [Facts -> States]]
    /\ disputers  \in [Facts -> SUBSET Sites]
    /\ admissible \in [Facts -> BOOLEAN]
    /\ exported   \in [Sites -> [Facts -> BOOLEAN]]
    /\ grantValid \in [Sites -> [Facts -> BOOLEAN]]
    /\ revokeReason \in [Sites -> [Facts -> RevokeReasons]]
    /\ lastOp     \in OpRecord

OpenDispute(f) == disputers[f] # {}

Note(o, s, f) == lastOp' = [op |-> o, site |-> s, fact |-> f]

Init ==
    /\ state      = [s \in Sites |-> [f \in Facts |-> "Absent"]]
    /\ disputers  = [f \in Facts |-> {}]
    /\ admissible \in [Facts -> BOOLEAN]
    /\ exported   = [s \in Sites |-> [f \in Facts |-> FALSE]]
    /\ grantValid = [s \in Sites |-> [f \in Facts |-> FALSE]]
    /\ revokeReason = [s \in Sites |-> [f \in Facts |-> "None"]]
    /\ lastOp     = [op |-> "Init", site |-> NoSite, fact |-> NoFact]

(***************************************************************************)
(* Evidence-only operations. CONTRIBUTE and ATTEST are indistinguishable at *)
(* this granularity: both add global support and may flip the admission     *)
(* verdict, and neither touches any site's authority state.                 *)
(***************************************************************************)
Contribute(s, f) ==
    /\ admissible' = [admissible EXCEPT ![f] = TRUE]
    /\ UNCHANGED <<state, disputers, exported, grantValid, revokeReason>>
    /\ Note("Contribute", s, f)

Rescore(f) ==
    /\ \E b \in BOOLEAN : admissible' = [admissible EXCEPT ![f] = b]
    /\ UNCHANGED <<state, disputers, exported, grantValid, revokeReason>>
    /\ Note("Rescore", NoSite, f)

(***************************************************************************)
(* QUERY stages a MonitorOnly record at the receiving site. It is the only  *)
(* operation a remote party can drive that creates local state at all.      *)
(***************************************************************************)
Query(s, f) ==
    /\ state[s][f] = "Absent"
    /\ admissible[f]
    /\ ~OpenDispute(f)
    /\ state' = [state EXCEPT ![s][f] = "MonitorOnly"]
    /\ UNCHANGED <<disputers, admissible, exported, grantValid, revokeReason>>
    /\ Note("Query", s, f)

(***************************************************************************)
(* OPERATOR-COMMIT creates a fresh local authorization token and is issued  *)
(* by the local operator of s alone.                                        *)
(***************************************************************************)
OperatorCommit(s, f) ==
    /\ AllowCommit
    /\ state[s][f] = "MonitorOnly"
    /\ state' = [state EXCEPT ![s][f] = "Active"]
    /\ grantValid' = [grantValid EXCEPT ![s][f] = TRUE]
    /\ revokeReason' = [revokeReason EXCEPT ![s][f] = "None"]
    /\ UNCHANGED <<disputers, admissible, exported>>
    /\ Note("Commit", s, f)

Export(s, f) ==
    /\ state[s][f] = "Active"
    /\ exported' = [exported EXCEPT ![s][f] = TRUE]
    /\ UNCHANGED <<state, disputers, admissible, grantValid, revokeReason>>
    /\ Note("Export", s, f)

(***************************************************************************)
(* One vote suspends every extant local record of the fact; a second vote   *)
(* from a *different* site revokes them. Duplicate votes are idempotent     *)
(* (the s \notin disputers[f] guard). Either way export eligibility is      *)
(* withdrawn everywhere. Local revocations remain locally revoked through   *)
(* a later global restore.                                                   *)
(***************************************************************************)
Dispute(s, f) ==
    /\ s \notin disputers[f]
    /\ disputers' = [disputers EXCEPT ![f] = @ \cup {s}]
    /\ LET votes == Cardinality(disputers[f] \cup {s})
           target(cur) == IF votes >= 2 THEN "Revoked" ELSE "Disputed"
       IN state' = [t \in Sites |-> [g \in Facts |->
                        IF g = f /\ state[t][g] \in {"MonitorOnly", "Active", "Disputed"}
                        THEN target(state[t][g])
                        ELSE state[t][g]]]
    /\ exported' = [t \in Sites |-> [g \in Facts |->
                        IF g = f THEN FALSE ELSE exported[t][g]]]
    /\ grantValid' = [t \in Sites |-> [g \in Facts |->
                        IF g = f THEN FALSE ELSE grantValid[t][g]]]
    /\ revokeReason' = [t \in Sites |-> [g \in Facts |->
                        IF g = f /\ state[t][g] \in {"MonitorOnly", "Active", "Disputed"}
                        THEN "Dispute" ELSE revokeReason[t][g]]]
    /\ UNCHANGED admissible
    /\ Note("Dispute", s, f)

(***************************************************************************)
(* RESTORE closes the episode and returns only dispute-derived records to   *)
(* MonitorOnly. It never recreates a grant, nor clears a LocalRevoke.       *)
(***************************************************************************)
Restore(s, f) ==
    /\ OpenDispute(f)
    /\ state' = [t \in Sites |-> [g \in Facts |->
                     IF g = f /\ (state[t][g] = "Disputed" \/
                         (state[t][g] = "Revoked" /\ revokeReason[t][g] = "Dispute"))
                     THEN "MonitorOnly"
                     ELSE state[t][g]]]
    /\ disputers' = [disputers EXCEPT ![f] = {}]
    /\ exported' = [t \in Sites |-> [g \in Facts |->
                        IF g = f THEN FALSE ELSE exported[t][g]]]
    /\ revokeReason' = [t \in Sites |-> [g \in Facts |->
                        IF g = f /\ revokeReason[t][g] = "Dispute" THEN "None"
                        ELSE revokeReason[t][g]]]
    /\ UNCHANGED <<admissible, grantValid>>
    /\ Note("Restore", s, f)

(***************************************************************************)
(* LOCAL-REVOKE and LOCAL-RESTORE give the receiving site itself a negative *)
(* authority path that does not depend on any remote dispute episode: the   *)
(* site that holds a MonitorOnly or Active record may withdraw it alone,    *)
(* with immediate effect and no second vote, and later restore it alone.    *)
(* Both are strictly site-scoped -- unlike Dispute/Restore, which fan out   *)
(* over every site holding the fact -- so they touch neither disputers[f]   *)
(* nor any other site's state or export flag.                              *)
(***************************************************************************)
LocalRevoke(s, f) ==
    /\ \/ state[s][f] \in {"MonitorOnly", "Active", "Disputed"}
       \/ /\ state[s][f] = "Revoked"
          /\ revokeReason[s][f] = "Dispute"
    /\ state' = [state EXCEPT ![s][f] = "Revoked"]
    /\ exported' = [exported EXCEPT ![s][f] = FALSE]
    /\ grantValid' = [grantValid EXCEPT ![s][f] = FALSE]
    /\ revokeReason' = [revokeReason EXCEPT ![s][f] = "Local"]
    /\ UNCHANGED <<disputers, admissible>>
    /\ Note("LocalRevoke", s, f)

LocalRestore(s, f) ==
    /\ state[s][f] = "Revoked"
    /\ revokeReason[s][f] = "Local"
    /\ state' = [state EXCEPT ![s][f] = "MonitorOnly"]
    /\ revokeReason' = [revokeReason EXCEPT ![s][f] = "None"]
    /\ UNCHANGED <<disputers, admissible, exported, grantValid>>
    /\ Note("LocalRestore", s, f)

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

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* State invariants.                                                        *)
(***************************************************************************)

\* G1: only a locally Active fact can be exported.
ExportRequiresActive ==
    \A s \in Sites, f \in Facts : exported[s][f] => state[s][f] = "Active"

\* The current authorization token is the model-level meaning of a fresh
\* local authorization: a commit creates it; revoke/dispute invalidates it.
FreshLocalAuthorization(s, f) == grantValid[s][f]

ExportRequiresFreshAuthorization ==
    \A s \in Sites, f \in Facts :
        exported[s][f] => FreshLocalAuthorization(s, f)

AuthorizationStateCoherence ==
    \A s \in Sites, f \in Facts :
        FreshLocalAuthorization(s, f) <=> state[s][f] = "Active"

\* An open episode leaves no record of that fact enforceable anywhere.
DisputeSuspendsEverywhere ==
    \A f \in Facts : OpenDispute(f) =>
        \A s \in Sites : state[s][f] \in {"Absent", "Disputed", "Revoked"}

\* I1, checked with AllowCommit = FALSE: no sequence of evidence-only
\* operations reaches Active from Absent. This is the model-checked form of
\* \hat\delta_s(Absent, sigma) # Active for all sigma in Sigma_ev^*.
NoActiveWithoutCommit ==
    \A s \in Sites, f \in Facts : state[s][f] # "Active"

(***************************************************************************)
(* Action properties: the invariants that are about transitions rather      *)
(* than about reachable states.                                             *)
(***************************************************************************)

\* I1: Active is entered only from MonitorOnly, only by COMMIT, and only at
\* the committing site.
I1_NonEscalation ==
    [][ \A s \in Sites, f \in Facts :
            (state[s][f] # "Active" /\ state'[s][f] = "Active") =>
                /\ lastOp'.op = "Commit"
                /\ lastOp'.site = s
                /\ state[s][f] = "MonitorOnly" ]_vars

\* A fresh authorization can only be created by the receiving site's commit.
FreshAuthorizationCreatedLocally ==
    [][ \A s \in Sites, f \in Facts :
            (~FreshLocalAuthorization(s, f) /\ grantValid'[s][f]) =>
                /\ lastOp'.op = "Commit"
                /\ lastOp'.site = s
                /\ state[s][f] = "MonitorOnly" ]_vars

\* I2: a commit at s changes nothing at any other site.
I2_SiteConfinement ==
    [][ (lastOp'.op = "Commit") =>
            \A t \in Sites \ {lastOp'.site}, g \in Facts :
                state'[t][g] = state[t][g] ]_vars

\* I3: restoration never recreates authorization, and a dispute withdraws
\* export everywhere. A LocalRevoke remains Revoked.
I3_ConservativeRestore ==
    [][ (lastOp'.op = "Restore") =>
            \A t \in Sites :
                /\ state'[t][lastOp'.fact] # "Active"
                /\ ~grantValid'[t][lastOp'.fact] ]_vars

I3_DisputeClearsExport ==
    [][ (lastOp'.op = "Dispute") =>
            \A t \in Sites : exported'[t][lastOp'.fact] = FALSE ]_vars

I3_DisputeInvalidatesAuthorization ==
    [][ (lastOp'.op = "Dispute") =>
            \A t \in Sites : ~grantValid'[t][lastOp'.fact] ]_vars

\* Operations act on one fact: unrelated facts keep their authority state.
UnrelatedFactIsolation ==
    [][ (lastOp'.op \in {"Query", "Commit", "Dispute", "Restore", "Export",
                          "LocalRevoke", "LocalRestore"}) =>
            \A t \in Sites, g \in Facts \ {lastOp'.fact} :
                state'[t][g] = state[t][g] ]_vars

\* I2 extended: a local revoke or local restore at s changes nothing at any
\* other site -- the negative-authority counterpart of I2_SiteConfinement.
I2_LocalRevokeConfinement ==
    [][ (lastOp'.op \in {"LocalRevoke", "LocalRestore"}) =>
            \A t \in Sites \ {lastOp'.site}, g \in Facts :
                state'[t][g] = state[t][g] ]_vars

\* I3 extended: local restore lands only in MonitorOnly, never in Active.
I3_LocalRestoreConservative ==
    [][ (lastOp'.op = "LocalRestore") =>
            state'[lastOp'.site][lastOp'.fact] = "MonitorOnly" ]_vars

I3_GlobalRestorePreservesLocalRevoke ==
    [][ (lastOp'.op = "Restore") =>
            \A t \in Sites :
                (state[t][lastOp'.fact] = "Revoked" /\
                 revokeReason[t][lastOp'.fact] = "Local") =>
                /\ state'[t][lastOp'.fact] = "Revoked"
                /\ revokeReason'[t][lastOp'.fact] = "Local" ]_vars

\* Evidence-only operations never move any authority state at all.
EvidenceNeverMovesState ==
    [][ (lastOp'.op \in {"Contribute", "Rescore"}) =>
            /\ state' = state
            /\ grantValid' = grantValid
            /\ revokeReason' = revokeReason ]_vars

=============================================================================
