#!/bin/sh
set -eu

fail() {
  exit 1
}

if [ "$#" -ne 2 ]; then
  fail
fi
case "$1:$2" in
  --adapter-control-id:oidf-basic-1|--adapter-control-id:oidf-basic-2|--adapter-control-id:oidf-post-1) ;;
  --plan-id:oidcc-basic-certification-test-plan|--plan-id:oidcc-config-certification-test-plan) ;;
  *) fail ;;
esac

STAT_BIN=''
STAT_APPLET=''
if [ -f /usr/bin/stat ] && [ ! -L /usr/bin/stat ] && [ -x /usr/bin/stat ] && \
  [ "$(/usr/bin/stat -c %u -- /usr/bin/stat 2>/dev/null || true)" = 0 ] && \
  [ "$(/usr/bin/stat -c %a -- /usr/bin/stat 2>/dev/null || true)" = 755 ]; then
  STAT_BIN=/usr/bin/stat
elif [ -f /bin/busybox ] && [ ! -L /bin/busybox ] && [ -x /bin/busybox ] && \
  [ "$(/bin/busybox stat -c %u -- /bin/busybox 2>/dev/null || true)" = 0 ] && \
  [ "$(/bin/busybox stat -c %a -- /bin/busybox 2>/dev/null || true)" = 755 ]; then
  STAT_BIN=/bin/busybox
  STAT_APPLET=stat
else
  fail
fi
readonly STAT_BIN STAT_APPLET

stat_value() {
  format=$1
  file=$2
  if [ -n "${STAT_APPLET}" ]; then
    "${STAT_BIN}" "${STAT_APPLET}" -c "${format}" -- "${file}" 2>/dev/null || true
  else
    "${STAT_BIN}" -c "${format}" -- "${file}" 2>/dev/null || true
  fi
}

NODE_BIN=''
for candidate in /usr/local/bin/node /usr/bin/node; do
  if [ -f "${candidate}" ] && [ ! -L "${candidate}" ] && [ -x "${candidate}" ] && \
    [ "$(stat_value %u "${candidate}")" = 0 ] && [ "$(stat_value %a "${candidate}")" = 755 ]; then
    NODE_BIN=${candidate}
    break
  fi
done
[ -n "${NODE_BIN}" ] || fail
readonly NODE_BIN

if [ "$1" = '--plan-id' ]; then
  case "$0" in
    /*) driver_path=$0 ;;
    *) fail ;;
  esac
  runner_path=${driver_path%/*}/phase1-conformance-runner.mjs
  driver_owner=$(stat_value %u "${driver_path}")
  if [ ! -f "${runner_path}" ] || [ -L "${runner_path}" ] || \
    [ "$(stat_value %u "${runner_path}")" != "${driver_owner}" ] || \
    [ "$(stat_value %a "${runner_path}")" != 644 ]; then
    fail
  fi
  exec "${NODE_BIN}" "${runner_path}" "$@"
fi

exec "${NODE_BIN}" -e '
const fs = require("node:fs");

const fail = () => process.exit(1);
const args = process.argv.slice(1);

if (args.length !== 2 || args[0] !== "--adapter-control-id") {
  fail();
}

const input = fs.readFileSync(0);
if (input.length < 1 || input.length > 65_536) {
  fail();
}

let config;
try {
  config = JSON.parse(input.toString("utf8"));
} catch {
  fail();
}

const clientId = args[1];
const client = config?.staticClient;
const callbackUri = config?.target?.callbackUri;
const expectedMethods = {
  "oidf-basic-1": "client_secret_basic",
  "oidf-basic-2": "client_secret_basic",
  "oidf-post-1": "client_secret_post",
};
const expectedMethod = expectedMethods[clientId];

if (
  config?.schemaVersion !== 1 ||
  typeof config?.suite?.commit !== "string" ||
  client?.id !== clientId ||
  typeof expectedMethod !== "string" ||
  client.tokenEndpointAuthMethod !== expectedMethod ||
  !Array.isArray(client.redirectUris) ||
  client.redirectUris.length !== 1 ||
  typeof callbackUri !== "string" ||
  client.redirectUris[0] !== callbackUri
) {
  fail();
}

process.stdout.write(JSON.stringify({
  schemaVersion: 1,
  kind: "phase1-conformance-adapter-control-terminal",
  suiteCommit: config.suite.commit,
  adapterControlId: clientId,
  status: "PASSED",
  result: {
    configured: true,
    redirectUriMatches: true,
  },
}));
' -- "$@"
