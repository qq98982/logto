#!/usr/bin/env bash
set -euo pipefail
umask 077

[[ $# -eq 1 && ( "$1" == minimal || "$1" == lifecycle ) ]] || exit 2

readonly root='/var/tmp/henry-build/aster-phase2-token-status-oracle'
readonly runroot='/var/tmp/henry-build/a2ts-run'
readonly oracle_image='sha256:76a9977bfc5ea3ed5b7623b879c27256670e377e27b987e8af99b53d55b30bbd'
readonly postgres_image='docker.io/library/postgres:17-alpine@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73'
readonly redis_image='docker.io/library/redis:6-alpine@sha256:d0c875bdacfb5c4d2c2d9124de3f53cee1dc9ceff8936bd459fabc135cb33015'

mkdir -p "${root}" "${root}/home" "${root}/tmp"
chmod 700 "${root}" "${root}/home" "${root}/tmp"
readonly -a engine=(
  env -i PATH=/usr/bin:/bin HOME="${root}/home" TMPDIR="${root}/tmp"
  XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
  podman --root "${root}/graph" --runroot "${runroot}" --events-backend=file
)

if ss -H -ltn | awk '$4 ~ /:3312$/ { found=1 } END { exit found ? 0 : 1 }'; then
  exit 1
fi

suffix="$(node -e "process.stdout.write(require('node:crypto').randomBytes(6).toString('hex'))")"
network="a2ts-${suffix}"
postgres_name="a2ts-postgres-${suffix}"
redis_name="a2ts-redis-${suffix}"
core_name="a2ts-core-${suffix}"
pgpass="$(node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('hex'))")"
kek="$(node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('hex'))")"
status_key="$(node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('hex'))")"
env_file="${root}/core.env"

cleanup() {
  local result=$?
  trap - EXIT INT TERM HUP
  "${engine[@]}" stop --time 1 "${core_name}" "${redis_name}" "${postgres_name}" >/dev/null 2>&1 || true
  "${engine[@]}" rm "${core_name}" "${redis_name}" "${postgres_name}" >/dev/null 2>&1 || true
  "${engine[@]}" network rm "${network}" >/dev/null 2>&1 || true
  if [[ -f "${env_file}" ]]; then
    unlink "${env_file}"
  fi
  exit "${result}"
}
trap cleanup EXIT INT TERM HUP

printf 'DB_URL=postgres://aster:%s@postgres:5432/aster\nREDIS_URL=redis://redis:6379\nENDPOINT=http://localhost:3312\nADMIN_ENDPOINT=http://localhost:3412\nADMIN_PORT=3412\nSECRET_VAULT_KEK=%s\nSTATUS_API_KEY=%s\nTRUST_PROXY_HEADER=1\n' \
  "${pgpass}" "${kek}" "${status_key}" >"${env_file}"
chmod 600 "${env_file}"

"${engine[@]}" network create "${network}" >/dev/null
"${engine[@]}" run --detach --name "${postgres_name}" --network "${network}" \
  --network-alias postgres --env POSTGRES_USER=aster --env POSTGRES_PASSWORD="${pgpass}" \
  --env POSTGRES_DB=aster "${postgres_image}" >/dev/null
"${engine[@]}" run --detach --name "${redis_name}" --network "${network}" \
  --network-alias redis "${redis_image}" redis-server --appendonly yes >/dev/null

for attempt in $(seq 1 120); do
  if "${engine[@]}" exec "${postgres_name}" pg_isready -U aster -d aster >/dev/null 2>&1 && \
    "${engine[@]}" exec "${redis_name}" redis-cli ping 2>/dev/null | grep -qx PONG; then
    break
  fi
  [[ "${attempt}" != 120 ]] || exit 1
  sleep 1
done

"${engine[@]}" run --detach --name "${core_name}" --network "${network}" \
  --env-file "${env_file}" --publish 127.0.0.1:3312:3001 "${oracle_image}" >/dev/null
unlink "${env_file}"

for attempt in $(seq 1 180); do
  if curl --fail --silent --show-error --max-time 2 \
      http://localhost:3312/oidc/.well-known/openid-configuration \
      >"${root}/discovery-ready.json" 2>/dev/null && \
    curl --fail --silent --show-error --max-time 2 \
      --header 'development-user-id: integration-test-admin-user' \
      http://localhost:3312/api/applications >"${root}/management-ready.json" 2>/dev/null; then
    break
  fi
  "${engine[@]}" container exists "${core_name}" || exit 1
  [[ "${attempt}" != 180 ]] || exit 1
  sleep 1
done

[[ "$("${engine[@]}" inspect "${core_name}" --format '{{.Image}}')" == "${oracle_image#sha256:}" ]]
node "/home/henry/repo/logto/.scripts/compatibility/phase2-token-status-${1/minimal/probe}.mjs"
