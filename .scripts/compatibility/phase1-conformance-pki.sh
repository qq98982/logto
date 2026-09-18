#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly OPENSSL_BIN='/usr/bin/openssl'
readonly TIMEOUT_BIN='/usr/bin/timeout'
readonly REALPATH_BIN='/usr/bin/realpath'
readonly STAT_BIN='/usr/bin/stat'
readonly ID_BIN='/usr/bin/id'
readonly MKDIR_BIN='/usr/bin/mkdir'
readonly MKTEMP_BIN='/usr/bin/mktemp'
readonly CHOWN_BIN='/usr/bin/chown'
readonly CHMOD_BIN='/usr/bin/chmod'
readonly MV_BIN='/usr/bin/mv'
readonly RM_BIN='/usr/bin/rm'
readonly CANDIDATE_HOST='aster-server.aster-phase1-conformance.svc.cluster.local'
readonly SUITE_HOST='conformance.aster-phase1-conformance.svc.cluster.local'

fail() {
  printf '%s\n' 'phase 1 conformance PKI generation failed' >&2
  exit 1
}

require_trusted_tool() {
  local tool=$1 resolved mode

  [[ -x "$tool" && -f "$tool" && ! -L "$tool" ]] || fail
  resolved="$($REALPATH_BIN -e -- "$tool" 2>/dev/null || true)"
  mode="$($STAT_BIN -c %a -- "$tool" 2>/dev/null || true)"
  [[ "$resolved" == "$tool" && "$($STAT_BIN -c %u -- "$tool")" == 0 ]] || fail
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] || fail
  (( (8#$mode & 8#022) == 0 )) || fail
}

validate_run_root() {
  local root=$1 runtime_uid=$2 runtime_gid=$3 resolved metadata

  [[ "$root" == /* && "$root" != / && "$root" != */ && "$root" != *//* ]] || fail
  [[ "$root" != */../* && "$root" != */./* && ! "$root" =~ [[:cntrl:]] ]] || fail
  [[ "$runtime_uid" =~ ^[0-9]+$ && "$runtime_gid" =~ ^[0-9]+$ ]] || fail
  [[ "$runtime_uid" == "$($ID_BIN -u)" && "$runtime_gid" == "$($ID_BIN -g)" ]] || fail
  [[ -d "$root" && ! -L "$root" ]] || fail
  resolved="$($REALPATH_BIN -e -- "$root" 2>/dev/null || true)"
  metadata="$($STAT_BIN -c '%u|%g|%a|%F' -- "$root" 2>/dev/null || true)"
  [[ "$resolved" == "$root" && "$metadata" == "$runtime_uid|$runtime_gid|700|directory" ]] || fail
  [[ ! -e "$root/pki" && ! -L "$root/pki" ]] || fail
}

run_openssl() {
  "$TIMEOUT_BIN" --signal=TERM --kill-after=5s 30s "$OPENSSL_BIN" "$@" \
    >/dev/null 2>&1 || fail
}

write_leaf_config() {
  local output=$1 host=$2

  printf '%s\n' \
    '[req]' \
    'distinguished_name = distinguished_name' \
    'prompt = no' \
    'req_extensions = leaf_extensions' \
    '[distinguished_name]' \
    "CN = $host" \
    '[leaf_extensions]' \
    'basicConstraints = critical,CA:FALSE' \
    'keyUsage = critical,digitalSignature,keyEncipherment' \
    'extendedKeyUsage = serverAuth' \
    "subjectAltName = DNS:$host" >"$output"
}

generate_leaf() {
  local pki_workspace=$1 output=$2 host=$3 name=$4 config csr san

  config="$pki_workspace/$name.cnf"
  csr="$pki_workspace/$name.csr"
  write_leaf_config "$config" "$host"
  run_openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$output/tls.key"
  run_openssl req -new -sha256 -key "$output/tls.key" -out "$csr" -config "$config"
  run_openssl x509 -req -sha256 -days 2 \
    -in "$csr" \
    -CA "$pki_workspace/pki/root-ca.crt" \
    -CAkey "$pki_workspace/pki/host-only/root-ca.key" \
    -CAserial "$pki_workspace/root-ca.srl" \
    -CAcreateserial \
    -out "$output/tls.crt" \
    -extfile "$config" \
    -extensions leaf_extensions
  run_openssl verify -CAfile "$pki_workspace/pki/root-ca.crt" "$output/tls.crt"
  run_openssl x509 -checkend 3600 -noout -in "$output/tls.crt"
  san="$("$TIMEOUT_BIN" --signal=TERM --kill-after=5s 10s "$OPENSSL_BIN" \
    x509 -in "$output/tls.crt" -noout -ext subjectAltName 2>/dev/null)" || fail
  [[ "$san" == $'X509v3 Subject Alternative Name: \n    DNS:'"$host" ]] || fail
}

[[ "$#" -eq 3 ]] || fail
readonly RUN_ROOT=$1
readonly RUNTIME_UID=$2
readonly RUNTIME_GID=$3

require_trusted_tool "$OPENSSL_BIN"
require_trusted_tool "$TIMEOUT_BIN"
require_trusted_tool "$REALPATH_BIN"
require_trusted_tool "$STAT_BIN"
require_trusted_tool "$ID_BIN"
require_trusted_tool "$MKDIR_BIN"
require_trusted_tool "$MKTEMP_BIN"
require_trusted_tool "$CHOWN_BIN"
require_trusted_tool "$CHMOD_BIN"
require_trusted_tool "$MV_BIN"
require_trusted_tool "$RM_BIN"
validate_run_root "$RUN_ROOT" "$RUNTIME_UID" "$RUNTIME_GID"

workspace="$($MKTEMP_BIN -d "$RUN_ROOT/.phase1-conformance-pki.XXXXXX")"
readonly workspace
cleanup() {
  local exit_code=$?
  trap - EXIT INT TERM HUP
  "$RM_BIN" -rf -- "$workspace"
  exit "$exit_code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

"$MKDIR_BIN" -m 0700 -- \
  "$workspace/pki" \
  "$workspace/pki/host-only" \
  "$workspace/pki/aster" \
  "$workspace/pki/suite"

run_openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out "$workspace/pki/host-only/root-ca.key"
run_openssl req -new -x509 -sha256 -days 2 \
  -key "$workspace/pki/host-only/root-ca.key" \
  -out "$workspace/pki/root-ca.crt" \
  -subj '/CN=Aster Phase 1 Local Conformance CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -addext 'subjectKeyIdentifier=hash'
run_openssl x509 -checkend 3600 -noout -in "$workspace/pki/root-ca.crt"

generate_leaf "$workspace" "$workspace/pki/aster" "$CANDIDATE_HOST" aster
generate_leaf "$workspace" "$workspace/pki/suite" "$SUITE_HOST" suite

"$CHOWN_BIN" -R "$RUNTIME_UID:$RUNTIME_GID" "$workspace/pki"
"$CHMOD_BIN" 0400 \
  "$workspace/pki/host-only/root-ca.key" \
  "$workspace/pki/aster/tls.key" \
  "$workspace/pki/suite/tls.key"
"$CHMOD_BIN" 0444 \
  "$workspace/pki/root-ca.crt" \
  "$workspace/pki/aster/tls.crt" \
  "$workspace/pki/suite/tls.crt"
"$CHMOD_BIN" 0700 \
  "$workspace/pki" \
  "$workspace/pki/host-only" \
  "$workspace/pki/aster" \
  "$workspace/pki/suite"
"$MV_BIN" -- "$workspace/pki" "$RUN_ROOT/pki"
