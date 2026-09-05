#!/bin/sh
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ARTIFACT_DIR=${ARTIFACT_DIR:-$HERE/artifacts/$RUN_ID}
export ARTIFACT_DIR
# OpenWrt's rootfs image ships /etc/resolv.conf in a form BuildKit cannot use
# as its injected mountpoint; the classic builder handles the image correctly.
export DOCKER_BUILDKIT=0
mkdir -p "$ARTIFACT_DIR"
MUD="$ARTIFACT_DIR/camera.json"
DIST_DIR="$HERE/../../code/src/dib/registry/distributed"
DIST_COMPOSE="docker compose -f $DIST_DIR/docker-compose.yml"
$DIST_COMPOSE down -v >/dev/null 2>&1 || true
$DIST_COMPOSE up -d --build
for i in $(seq 1 30); do
  curl -fsS http://localhost:18100/health >/dev/null 2>&1 && curl -fsS http://localhost:18110/health >/dev/null 2>&1 && break
  sleep 1
done
if docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose -f $HERE/docker-compose.yml"
else
  COMPOSE_BIN="$HERE/.tools/docker-compose-v2.29.7"
  if [ ! -x "$COMPOSE_BIN" ]; then
    mkdir -p "$HERE/.tools"
    curl -fsSL -o "$COMPOSE_BIN.tmp" https://github.com/docker/compose/releases/download/v2.29.7/docker-compose-linux-x86_64
    echo '383ce6698cd5d5bbf958d2c8489ed75094e34a77d340404d9f32c4ae9e12baf0  '"$COMPOSE_BIN.tmp" | sha256sum -c -
    mv "$COMPOSE_BIN.tmp" "$COMPOSE_BIN"
    chmod +x "$COMPOSE_BIN"
  fi
  COMPOSE="$COMPOSE_BIN -f $HERE/docker-compose.yml"
fi

cleanup() {
  $COMPOSE down --remove-orphans >/dev/null 2>&1 || true
  $DIST_COMPOSE down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

python3 "$HERE/prepare_policy_distributed.py" init --output "$MUD" | tee "$ARTIFACT_DIR/01_monitor.json"
test "$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(sum(len(a["aces"]["ace"]) for a in d["ietf-access-control-list:access-lists"]["acl"]))' "$MUD")" -eq 0
python3 "$HERE/prepare_policy_distributed.py" commit --output "$MUD" | tee "$ARTIFACT_DIR/02_commit.json"
cat > "$ARTIFACT_DIR/dhcp_event.txt" <<EOF
2026-08-08T12:00:00|NEW|OpenWRT.lan|DHCP|1,3,6,15|MUD|http://mud-server:8000/camera.json|-|02:42:ac:1e:00:02|172.30.0.2|camera|
EOF

$COMPOSE up -d --build

container_pid() { docker inspect -f '{{.State.Pid}}' "$($COMPOSE ps -q "$1")"; }
ROUTER_PID=$(container_pid router)
link_pair() {
  service=$1 router_if=$2 peer_if=$3 router_cidr=$4 peer_cidr=$5
  peer_pid=$(container_pid "$service")
  ip link add "h-$router_if" type veth peer name "h-$peer_if"
  ip link set "h-$router_if" netns "$ROUTER_PID"
  ip link set "h-$peer_if" netns "$peer_pid"
  nsenter -t "$ROUTER_PID" -n ip link set "h-$router_if" name "$router_if"
  nsenter -t "$peer_pid" -n ip link set "h-$peer_if" name "$peer_if"
  nsenter -t "$ROUTER_PID" -n ip addr add "$router_cidr" dev "$router_if"
  nsenter -t "$peer_pid" -n ip addr add "$peer_cidr" dev "$peer_if"
  nsenter -t "$ROUTER_PID" -n ip link set "$router_if" up
  nsenter -t "$peer_pid" -n ip link set "$peer_if" up
}
link_pair device lan0 eth0 172.30.0.254/24 172.30.0.2/24
link_pair allowed-service wan0 eth0 172.31.0.9/30 172.31.0.10/30
link_pair blocked-service wan1 eth0 172.31.0.13/30 172.31.0.14/30
link_pair mud-server wan2 eth0 172.31.0.17/30 172.31.0.18/30
$COMPOSE exec -T device sh -c "ip route add default via 172.30.0.254; echo '172.31.0.10 allowed.test' >> /etc/hosts; echo '172.31.0.14 blocked.test' >> /etc/hosts"
$COMPOSE exec -T allowed-service ip route add default via 172.31.0.9
$COMPOSE exec -T blocked-service ip route add default via 172.31.0.13
$COMPOSE exec -T mud-server ip route add default via 172.31.0.17
$COMPOSE exec -T -d allowed-service python /echo_service.py --tcp 8080 --udp 5353
$COMPOSE exec -T -d blocked-service python /echo_service.py --tcp 8080
$COMPOSE exec -T -d mud-server python -m http.server 8000 --directory /artifacts
$COMPOSE exec -T router sh -c "echo '172.31.0.10 allowed.test' >> /etc/hosts; echo '172.31.0.14 blocked.test' >> /etc/hosts; echo '172.31.0.18 mud-server' >> /etc/hosts"
$COMPOSE exec -T router ping -c 1 172.31.0.18 >/dev/null
$COMPOSE exec -T router sh -c 'i=0; until curl -fsS http://mud-server:8000/camera.json >/dev/null; do i=$((i+1)); test "$i" -lt 20; sleep 1; done'
$COMPOSE exec -T -d router /usr/local/bin/router-entrypoint.sh
sleep 12
$COMPOSE exec -T router uci show firewall > "$ARTIFACT_DIR/uci_active.txt"
$COMPOSE exec -T router nft list ruleset > "$ARTIFACT_DIR/ruleset_active.txt"
$COMPOSE logs router > "$ARTIFACT_DIR/router_active.log"

probe_tcp() { $COMPOSE exec -T device sh -c "printf ping | nc -w 2 $1 $2"; }
probe_udp() { test "$($COMPOSE exec -T device sh -c "printf ping | nc -u -w 2 $1 $2" 2>/dev/null)" = ping; }
probe_tcp allowed.test 8080 > "$ARTIFACT_DIR/tcp_allowed.txt"
probe_udp allowed.test 5353
if probe_tcp allowed.test 8081 >/dev/null 2>&1; then echo 'wrong port unexpectedly allowed' >&2; exit 1; fi
if probe_tcp blocked.test 8080 >/dev/null 2>&1; then echo 'wrong destination unexpectedly allowed' >&2; exit 1; fi

# First dispute, observed on its own: the design claims Disputed already
# suspends authorization and export eligibility, so the packet filter must
# stop permitting the fact here, before any revoking second dispute exists.
python3 "$HERE/prepare_policy_distributed.py" dispute1 --output "$MUD" | tee "$ARTIFACT_DIR/03a_dispute1.json"
$COMPOSE exec -T router sh -c 'test ! -f /run/osmud/osmud.pid || kill $(cat /run/osmud/osmud.pid)' || true
$COMPOSE exec -T -d router /usr/local/bin/router-entrypoint.sh
sleep 12
$COMPOSE exec -T router uci show firewall > "$ARTIFACT_DIR/uci_after_dispute1.txt"
$COMPOSE exec -T router nft list ruleset > "$ARTIFACT_DIR/ruleset_after_dispute1.txt"
if probe_tcp allowed.test 8080 >/dev/null 2>&1; then echo 'first dispute did not suspend enforcement' >&2; exit 1; fi

python3 "$HERE/prepare_policy_distributed.py" dispute2 --output "$MUD" | tee "$ARTIFACT_DIR/03b_dispute2.json"
$COMPOSE exec -T router sh -c 'test ! -f /run/osmud/osmud.pid || kill $(cat /run/osmud/osmud.pid)' || true
$COMPOSE exec -T -d router /usr/local/bin/router-entrypoint.sh
sleep 12
if probe_tcp allowed.test 8080 >/dev/null 2>&1; then echo 'revoked traffic unexpectedly allowed' >&2; exit 1; fi

python3 "$HERE/prepare_policy_distributed.py" restore --output "$MUD" | tee "$ARTIFACT_DIR/04_restore.json"
$COMPOSE exec -T router sh -c 'test ! -f /run/osmud/osmud.pid || kill $(cat /run/osmud/osmud.pid)' || true
$COMPOSE exec -T -d router /usr/local/bin/router-entrypoint.sh
sleep 12
if probe_tcp allowed.test 8080 >/dev/null 2>&1; then echo 'restore reactivated without commit' >&2; exit 1; fi

python3 "$HERE/prepare_policy_distributed.py" commit --output "$MUD" | tee "$ARTIFACT_DIR/05_recommit.json"
$COMPOSE exec -T router sh -c 'test ! -f /run/osmud/osmud.pid || kill $(cat /run/osmud/osmud.pid)' || true
$COMPOSE exec -T -d router /usr/local/bin/router-entrypoint.sh
sleep 12
probe_tcp allowed.test 8080 > "$ARTIFACT_DIR/tcp_recommitted.txt"
$COMPOSE exec -T router uci show firewall > "$ARTIFACT_DIR/uci_final.txt"
$COMPOSE exec -T router nft list ruleset > "$ARTIFACT_DIR/ruleset_final.txt"

# Site-local revoke/restore: lab-a (the enforcing site itself) withdraws and
# restores its own LocalDecision, with no second site's confirmation needed
# (unlike the dispute1/dispute2 cross-site path above).
python3 "$HERE/prepare_policy_distributed.py" local-revoke --output "$MUD" | tee "$ARTIFACT_DIR/06_local_revoke.json"
$COMPOSE exec -T router sh -c 'test ! -f /run/osmud/osmud.pid || kill $(cat /run/osmud/osmud.pid)' || true
$COMPOSE exec -T -d router /usr/local/bin/router-entrypoint.sh
sleep 12
$COMPOSE exec -T router uci show firewall > "$ARTIFACT_DIR/uci_after_local_revoke.txt"
$COMPOSE exec -T router nft list ruleset > "$ARTIFACT_DIR/ruleset_local_revoke.txt"
if probe_tcp allowed.test 8080 > "$ARTIFACT_DIR/tcp_after_local_revoke.txt" 2>&1; then echo 'local-revoke did not suspend enforcement' >&2; exit 1; fi

python3 "$HERE/prepare_policy_distributed.py" local-restore --output "$MUD" | tee "$ARTIFACT_DIR/07_local_restore.json"
$COMPOSE exec -T router sh -c 'test ! -f /run/osmud/osmud.pid || kill $(cat /run/osmud/osmud.pid)' || true
$COMPOSE exec -T -d router /usr/local/bin/router-entrypoint.sh
sleep 12
$COMPOSE exec -T router uci show firewall > "$ARTIFACT_DIR/uci_after_local_restore.txt"
$COMPOSE exec -T router nft list ruleset > "$ARTIFACT_DIR/ruleset_local_restore.txt"
if probe_tcp allowed.test 8080 > "$ARTIFACT_DIR/tcp_after_local_restore.txt" 2>&1; then echo 'local-restore reactivated without commit' >&2; exit 1; fi

$COMPOSE logs > "$ARTIFACT_DIR/compose.log"
sha256sum "$MUD" > "$ARTIFACT_DIR/checksums.sha256"
printf '{"claim_level":"end-to-end enforcement","status":"pass","osmud_commit":"852918eb33f3e15225da4de21d440b5b9a5d875f","openwrt":"23.05.5"}\n' > "$ARTIFACT_DIR/result.json"
cat > "$ARTIFACT_DIR/manifest.json" <<EOF
{
  "experiment": "openwrt_osmud_end_to_end_distributed",
  "command": ["./run.sh"],
  "seed": 0,
  "config": {"site_id": "lab-a", "device_type": "camera", "tcp_port": 8080, "udp_port": 5353},
  "dispute_sequence": ["dispute1 (lab-b, Active->Disputed)", "dispute2 (lab-c, Disputed->Revoked)", "local-revoke (lab-a, Active->Revoked, no second site)", "local-restore (lab-a, Revoked->MonitorOnly)"],
  "probes_per_phase": ["01 monitor", "02 commit", "03a first dispute", "03b second dispute", "04 restore", "05 recommit", "06 local revoke", "07 local restore"],
  "openwrt": "23.05.5@sha256:a44cce5d8f3619e30b0b7cf74e236d4e62cb3bf118953f57e044dc684d7cfc36",
  "osmud_commit": "852918eb33f3e15225da4de21d440b5b9a5d875f",
  "checksums": "checksums.sha256",
  "result": "result.json"
}
EOF
echo "PASS: artifacts in $ARTIFACT_DIR"
