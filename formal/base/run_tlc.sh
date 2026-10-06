#!/bin/sh
# Compatibility entry point: run the current frozen models and all six mutations.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
exec python3 "$HERE/../../scripts/run_formal.py" --jar "${TLA_TOOLS:?Set TLA_TOOLS to tla2tools.jar}" --output "${1:-formal-rerun}"
