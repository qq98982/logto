#!/usr/bin/env bash

set -euo pipefail
umask 077
export LC_ALL=C

readonly FAILURE='Aster candidate PostgreSQL initialization failed'
temporary_hba=''

fail() {
  printf '%s\n' "$FAILURE" >&2
  exit 1
}

cleanup() {
  local exit_status=$?
  trap - EXIT
  if [[ -n "$temporary_hba" && -e "$temporary_hba" && ! -L "$temporary_hba" ]]; then
    rm -f -- "$temporary_hba" || exit_status=1
  fi
  exit "$exit_status"
}

validate_host_cidr() {
  local value=$1 address octet
  [[ "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/32$ ]] || fail
  address=${value%/32}
  local -a octets=()
  IFS=. read -r -a octets <<<"$address"
  [[ "${#octets[@]}" -eq 4 ]] || fail
  for octet in "${octets[@]}"; do
    [[ "$octet" == 0 || "$octet" =~ ^[1-9][0-9]{0,2}$ ]] || fail
    ((10#$octet <= 255)) || fail
  done
}

for key in ASTER_PHASE1_INIT_CIDR ASTER_PHASE1_CORE_CIDR ASTER_PHASE1_COORDINATOR_CIDR; do
  [[ -n "${!key+x}" && -n "${!key}" && "${!key}" != *$'\n'* ]] || fail
  validate_host_cidr "${!key}"
done
[[ "$ASTER_PHASE1_INIT_CIDR" != "$ASTER_PHASE1_CORE_CIDR" \
  && "$ASTER_PHASE1_INIT_CIDR" != "$ASTER_PHASE1_COORDINATOR_CIDR" \
  && "$ASTER_PHASE1_CORE_CIDR" != "$ASTER_PHASE1_COORDINATOR_CIDR" ]] || fail
[[ "${PGDATA-}" == /* && -d "$PGDATA" && ! -L "$PGDATA" ]] || fail

readonly hba_file="$PGDATA/pg_hba.conf"
temporary_hba="$PGDATA/.pg_hba.conf.aster-new"
[[ -f "$hba_file" && ! -L "$hba_file" && ! -e "$temporary_hba" ]] || fail
trap cleanup EXIT

cat >"$temporary_hba" <<EOF
# Aster Phase 1 candidate acceptance topology.
local all all trust
host all postgres ${ASTER_PHASE1_INIT_CIDR} trust
host all aster_migrator,aster_admin,aster_maintainer ${ASTER_PHASE1_INIT_CIDR} trust
host all aster_control_resolver,aster_request,aster_key_runtime,aster_maintainer ${ASTER_PHASE1_CORE_CIDR} trust
host all postgres,aster_admin ${ASTER_PHASE1_COORDINATOR_CIDR} trust
host all all 0.0.0.0/0 reject
host all all ::/0 reject
EOF
chmod 0600 "$temporary_hba"
mv -- "$temporary_hba" "$hba_file"
temporary_hba=''
chmod 0600 "$PGDATA/pg_hba.conf"
