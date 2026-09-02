#!/bin/sh
set -eu

NODE_BIN=/usr/bin/node

node_mode=$(stat -c %a -- "${NODE_BIN}" 2>/dev/null || true)
case "${node_mode}" in
  [0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) ;;
  *) exit 1 ;;
esac
case "${node_mode}" in
  [0-7][2367][0-7]|[0-7][0-7][2367]|[0-7][0-7][2367][0-7]|[0-7][0-7][0-7][2367])
    exit 1
    ;;
esac
if [ ! -x "${NODE_BIN}" ] || [ -L "${NODE_BIN}" ] || \
  [ "$(stat -c %u -- "${NODE_BIN}" 2>/dev/null || true)" != 0 ]; then
  exit 1
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
