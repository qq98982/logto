#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
export ASTER_PHASE1_RUNTIME_GATE='differential'
exec "${SCRIPT_DIR}/run-phase1-runtime-candidate.sh"
