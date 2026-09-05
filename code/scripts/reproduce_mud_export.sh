#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

FINAL_SCORES="${1:-outputs/full_unsw/final_scores.csv}"
OUTPUT_DIR="${2:-outputs/mud_export}"
BUILD_DIR="${3:-/tmp/dib_osmud_build}"
# observations_enriched_respfix.csv, not observations_enriched.csv: the latter
# predates the response_observed column (missing entirely -> defaults False for
# every row -> to-device-policy ACEs are always empty), the former is
# byte-identical on every other column with response_observed correctly
# populated. Does not affect FINAL_SCORES / the accepted-endpoint set.
OBSERVATIONS="${4:-data/processed/observations_enriched_respfix.csv}"

echo "== Exporting RFC 8520 MUD files from $FINAL_SCORES (direction/response-leg from $OBSERVATIONS) =="
python3 scripts/mud_export_demo.py --final-scores "$FINAL_SCORES" --output-dir "$OUTPUT_DIR" --observations "$OBSERVATIONS"

if ! command -v gcc >/dev/null 2>&1; then
  echo "gcc not found; skipping the real-osMUD interoperability probe (export files above are still produced)."
  exit 0
fi

echo "== Building the real osMUD reference parser (github.com/osmud/osmud) =="
mkdir -p "$BUILD_DIR"
if [ ! -d "$BUILD_DIR/osmud" ]; then
  git clone --depth 1 https://github.com/osmud/osmud.git "$BUILD_DIR/osmud"
fi

# osMUD links against libjson-c; we only need its headers to compile the parser,
# and json-c ships no compiled binaries in its -dev package beyond a static lib we
# don't use, so apt-get download + dpkg -x avoids requiring root just to build a probe.
if [ ! -f "$BUILD_DIR/jsonc-root/usr/include/json-c/json.h" ]; then
  (cd "$BUILD_DIR" && apt-get download libjson-c-dev && dpkg -x libjson-c-dev_*.deb jsonc-root)
fi
JSONC_INCLUDE="$BUILD_DIR/jsonc-root/usr/include"
JSONC_RUNTIME_LIB="$(find /usr/lib/x86_64-linux-gnu /usr/lib -maxdepth 2 -name 'libjson-c.so.*' 2>/dev/null | sort | tail -1)"
if [ -z "$JSONC_RUNTIME_LIB" ]; then
  echo "libjson-c runtime library not found on this system; skipping the osMUD probe."
  exit 0
fi

CFLAGS=(-Wall -std=c99 -D_XOPEN_SOURCE=600 -I"$BUILD_DIR/osmud/src" -I"$JSONC_INCLUDE")
gcc "${CFLAGS[@]}" -c "$BUILD_DIR/osmud/src/mudparser.c" -o "$BUILD_DIR/mudparser.o"
gcc "${CFLAGS[@]}" -c "$BUILD_DIR/osmud/src/oms_utils.c" -o "$BUILD_DIR/oms_utils.o"
gcc "${CFLAGS[@]}" -c "$BUILD_DIR/osmud/src/oms_logging.c" -o "$BUILD_DIR/oms_logging.o"
gcc "${CFLAGS[@]}" -c scripts/osmud_probe/dib_mud_probe.c -o "$BUILD_DIR/dib_mud_probe.o"
gcc "$BUILD_DIR/dib_mud_probe.o" "$BUILD_DIR/mudparser.o" "$BUILD_DIR/oms_utils.o" "$BUILD_DIR/oms_logging.o" \
  "$JSONC_RUNTIME_LIB" -o "$BUILD_DIR/dib_mud_probe"

echo "== Feeding real DIB-exported MUD files to the compiled osMUD parser =="
PROBE_LOG="$OUTPUT_DIR/osmud_probe_output.txt"
: > "$PROBE_LOG"
for mud_file in "$OUTPUT_DIR"/mud_files/*.json; do
  echo "--- $mud_file ---" | tee -a "$PROBE_LOG"
  "$BUILD_DIR/dib_mud_probe" "$mud_file" | tee -a "$PROBE_LOG"
done

echo "MUD export and osMUD interoperability probe complete. Output: $OUTPUT_DIR"
