#!/bin/sh
# Model-check the DIB lifecycle model with TLC.
#
#   TLA_TOOLS=/path/to/tla2tools.jar ./run_tlc.sh [output-dir]
#
# tla2tools.jar is not redistributed here; fetch it from
# https://github.com/tlaplus/tlaplus/releases (TLA+ 1.8 or later).
#
# Runs:
#   1. DIB.cfg              -- full lifecycle, all invariants and action
#                              properties, with -coverage so the log records
#                              how often each action fired
#   2. DIBEvidenceOnly.cfg  -- OPERATOR-COMMIT removed; exhausts the evidence-only
#                              state space and checks that Active is unreachable
#   3. three mutation controls -- each breaks one mechanism; TLC must report the
#                              expected violation, so the properties are known
#                              not to be vacuous
set -eu

JAR="${TLA_TOOLS:-tla2tools.jar}"
HERE=$(cd "$(dirname "$0")" && pwd)
OUT="${1:-$HERE/logs}"
mkdir -p "$OUT"
cd "$HERE"

if [ "${SKIP_BASELINE:-0}" -ne 1 ]; then
    echo "== full lifecycle (with coverage) =="
    java -cp "$JAR" tlc2.TLC -config DIB.cfg -workers 4 -coverage 1 -cleanup DIB.tla \
        2>&1 | tee "$OUT/full_lifecycle.log"

    echo "== evidence-only (Sigma_ev) =="
    java -cp "$JAR" tlc2.TLC -config DIBEvidenceOnly.cfg -workers 4 -cleanup DIB.tla \
        2>&1 | tee "$OUT/evidence_only.log"
fi

# Mutation controls. Each applies one targeted edit to DIB.tla and re-runs the
# full configuration; the named property must be reported as violated. TLC
# stops at the first violation, so each mutation is written to break exactly
# one mechanism.
#   M1  restore recreates fresh authorization   -> AuthorizationStateCoherence
#   M2  commit clears other sites' candidates   -> I2_SiteConfinement
#   M3  export accepts a Disputed record        -> ExportRequiresActive
#   M4  local restore ignores an open dispute   -> DisputeSuspendsEverywhere
#   M5  local revoke fans out to every site      -> I2_LocalRevokeConfinement
#   M6  global restore clears a local revoke     -> I3_GlobalRestorePreservesLocalRevoke
MUTATION_FAILURES=0

mutate() {
    name=$1; expect=$2; old=$3; new=$4
    MUT=$(mktemp -d)
    OLD="$old" NEW="$new" SRC="$MUT/DIBMutant.tla" python3 - <<'EOF'
import os
src = open("DIB.tla").read()
old, new = os.environ["OLD"], os.environ["NEW"]
assert src.count(old) == 1, "mutation target must be unique: %r" % old[:60]
open(os.environ["SRC"], "w").write(src.replace(old, new).replace("MODULE DIB ", "MODULE DIBMutant "))
EOF
    cp DIB.cfg "$MUT/DIBMutant.cfg"
    echo "== mutation $name (expected: $expect violated) =="
    java -cp "$JAR" tlc2.TLC -config "$MUT/DIBMutant.cfg" -workers 4 -cleanup \
        "$MUT/DIBMutant.tla" 2>&1 | tee "$OUT/mutation_$name.log" || true
    if grep -q "$expect is violated" "$OUT/mutation_$name.log"; then
        echo "mutation $name: $expect violated, as expected"
    else
        echo "mutation $name: FAILED to violate $expect" >&2
        MUTATION_FAILURES=$((MUTATION_FAILURES + 1))
    fi
    rm -rf "$MUT"
}

mutate m1_restore_recreates_grant AuthorizationStateCoherence \
    '/\ UNCHANGED <<admissible, grantValid>>' \
    '/\ grantValid'"'"' = [t \in Sites |-> [g \in Facts |-> IF g = f THEN TRUE ELSE grantValid[t][g]]]
    /\ UNCHANGED admissible'

mutate m2_commit_escapes_site I2_SiteConfinement \
    '/\ state'"'"' = [state EXCEPT ![s][f] = "Active"]' \
    '/\ state'"'"' = [t \in Sites |-> [g \in Facts |-> IF g # f THEN state[t][g] ELSE IF t = s THEN "Active" ELSE IF state[t][g] = "MonitorOnly" THEN "Absent" ELSE state[t][g]]]'

mutate m3_export_while_disputed ExportRequiresActive \
    '    /\ state[s][f] = "Active"
    /\ exported'"'"' = [exported EXCEPT ![s][f] = TRUE]' \
    '    /\ state[s][f] \in {"Active", "Disputed"}
    /\ exported'"'"' = [exported EXCEPT ![s][f] = TRUE]'

mutate m4_local_restore_ignores_dispute DisputeSuspendsEverywhere \
    'LocalRestore(s, f) ==
    /\ state[s][f] = "Revoked"
    /\ revokeReason[s][f] = "Local"
    /\ ~OpenDispute(f)' \
    'LocalRestore(s, f) ==
    /\ state[s][f] = "Revoked"
    /\ revokeReason[s][f] = "Local"'

mutate m5_local_revoke_escapes_site I2_LocalRevokeConfinement \
    'LocalRevoke(s, f) ==
    /\ state[s][f] \in {"MonitorOnly", "Active"}
    /\ state'"'"' = [state EXCEPT ![s][f] = "Revoked"]' \
    'LocalRevoke(s, f) ==
    /\ state[s][f] \in {"MonitorOnly", "Active"}
    /\ state'"'"' = [t \in Sites |-> [g \in Facts |-> IF g = f THEN "Revoked" ELSE state[t][g]]]'

mutate m6_global_restore_clears_local_revoke I3_GlobalRestorePreservesLocalRevoke \
    '(state[t][g] = "Revoked" /\ revokeReason[t][g] = "Dispute")' \
    'state[t][g] = "Revoked"'

echo
echo "== summary =="
grep -h -E "Model checking completed|is violated|distinct states found" "$OUT"/*.log

if [ "$MUTATION_FAILURES" -ne 0 ]; then
    echo "$MUTATION_FAILURES mutation control(s) not detected" >&2
    exit 1
fi
