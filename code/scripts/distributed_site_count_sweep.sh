#!/usr/bin/env bash
# Equal-stack site-count sweep: vary only the number of site containers.
#
# Stack, transport, operation mix, worker counts, ops-per-worker, warm-up and
# repeat count are all held fixed; DIB_DIST_N_SITES is the single independent
# variable. This isolates the contribution of distribution itself, which the
# withdrawn cross-harness comparison could not.
#
# Usage:  bash code/scripts/distributed_site_count_sweep.sh [out_dir]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIST="$ROOT/code/src/dib/registry/distributed"
OUT="${1:-$ROOT/experiments/39_distributed_site_count}"
WORKERS="${WORKERS:-1,10,50,100}"
REPEATS="${REPEATS:-5}"
mkdir -p "$OUT"

for N in 1 2 5 10; do
  echo "=============== N_SITES=$N ==============="
  ( cd "$DIST" && DIB_DIST_N_SITES=$N python3 generate_compose.py > docker-compose.yml )
  ( cd "$DIST" && docker compose down -v --remove-orphans >/dev/null 2>&1 || true )
  ( cd "$DIST" && DIB_DIST_N_SITES=$N docker compose up -d --build )
  echo "waiting for evidence + $N site container(s) to answer..."
  for _ in $(seq 1 60); do
    ok=1
    curl -sf "http://localhost:18100/health" >/dev/null 2>&1 || ok=0
    for i in $(seq 0 $((N-1))); do
      curl -sf "http://localhost:$((18110+i))/health" >/dev/null 2>&1 || ok=0
    done
    [ "$ok" = 1 ] && break
    sleep 2
  done
  ( cd "$ROOT/code" && python3 scripts/distributed_concurrency_benchmark.py \
      --n-sites "$N" --worker-counts "$WORKERS" --ops-per-worker 20 \
      --warmup-ops 20 --repeats "$REPEATS" \
      --output "$OUT/throughput_n${N}.csv" )
  ( cd "$DIST" && docker compose down -v --remove-orphans >/dev/null 2>&1 || true )
done

# restore the canonical 10-site compose file
( cd "$DIST" && DIB_DIST_N_SITES=10 python3 generate_compose.py > docker-compose.yml )
echo "sweep complete -> $OUT"
