/* eslint-disable max-lines, no-await-in-loop, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- One private fake-engine harness exercises both shell protocols, lifecycle state, restoration, and secret argv containment. */
import { spawn } from 'node:child_process';
import { chmod, link, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import net, { type Server } from 'node:net';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const repositoryRoot = path.resolve(process.cwd(), '../..');
const stateDriver = path.join(
  repositoryRoot,
  '.scripts/compatibility/phase2-client-credentials-state-driver.sh'
);
const invariantDriver = path.join(
  repositoryRoot,
  '.scripts/compatibility/phase2-client-credentials-invariant-driver.sh'
);
const roots = new Set<string>();
const servers = new Set<Server>();
const projectName = 'aster-phase2-client-credentials-0123456789abcdef';
const ids = {
  primaryCore: '1'.repeat(64),
  foreignCore: '2'.repeat(64),
  primaryPostgres: '3'.repeat(64),
  foreignPostgres: '4'.repeat(64),
};
const rawImageId = 'a'.repeat(64);
const imageDigest = `sha256:${'a'.repeat(64)}`;
const oracleSigningKeyId = 'o'.repeat(43);
const fixture = {
  allocationId: 'phase2-live-driver',
  clients: {
    basic: { id: 'phase2-m2m-basic', method: 'client_secret_basic' },
    post: { id: 'phase2-m2m-post', method: 'client_secret_post' },
  },
  deviceClients: {
    firstParty: {
      id: 'phase2-device-first',
      applicationType: 'Native',
      authenticationMethod: 'none',
      isThirdParty: false,
      deviceGrantEnabled: true,
    },
    thirdParty: {
      id: 'phase2-device-third',
      applicationType: 'Native',
      authenticationMethod: 'none',
      isThirdParty: true,
      deviceGrantEnabled: true,
    },
    missingGrant: {
      id: 'phase2-device-nogrant',
      applicationType: 'Native',
      authenticationMethod: 'none',
      isThirdParty: false,
      deviceGrantEnabled: false,
    },
    ineligibleWeb: {
      id: 'phase2-device-web',
      applicationType: 'SPA',
      authenticationMethod: 'none',
      isThirdParty: false,
      deviceGrantEnabled: false,
    },
  },
  resources: {
    primary: {
      id: 'phase2-resource-primary',
      indicator: 'https://phase2.example.invalid/api-primary',
    },
    default: { id: 'phase2-resource', indicator: 'https://phase2.example.invalid/api-default' },
  },
  organization: { id: 'phase2-org', scopeName: 'organization:read' },
  scopes: {
    read: { id: 'read-scope', name: 'read' },
    write: { id: 'write-scope', name: 'write' },
    unassigned: { id: 'unassigned-scope', name: 'unassigned' },
  },
  boundary: { primary: 'provisioned', foreign: 'unchanged' },
} as const;
const candidateTarget = {
  label: 'candidate',
  coreUrl: 'http://localhost:3321/',
  adminUrl: 'http://localhost:3421/',
} as const;
const candidateForeignTarget = {
  label: 'candidate',
  coreUrl: 'http://localhost:3322/',
  adminUrl: 'http://localhost:3422/',
} as const;
const oracleTarget = {
  label: 'oracle',
  coreUrl: 'http://localhost:3311/',
  adminUrl: 'http://localhost:3411/',
} as const;
const oracleForeignTarget = {
  label: 'oracle',
  coreUrl: 'http://localhost:3312/',
  adminUrl: 'http://localhost:3412/',
} as const;
const basicSecret = 'basic-secret-0123456789abcdef';
const postSecret = 'post-secret-0123456789abcdef';

type Invocation = Readonly<{ code: number | undefined; stdout: string; stderr: string }>;
type Harness = Readonly<{
  state: string;
  invariant: string;
  socket: string;
  root: string;
  calls: string;
  sql: string;
  usage: string;
  mutation: string;
  fault: string;
  flipCount: string;
  acceptRole: string;
  noOpFault: string;
  restoreFailure: string;
  decision: string;
  postAuthorityMissing: string;
  malformedJwks: string;
  hang: string;
  hangReached: string;
  unlinkRace: string;
  unlinkEvidence: string;
  quarantineCollision: string;
  postVerifyRace: string;
  postVerifyEvidence: string;
  deviceStatus: string;
  secretLeak: string;
  normalizedInitialLeak: string;
  env: Readonly<Record<string, string>>;
}>;

const invoke = async (
  executable: string,
  input: string,
  environment: Readonly<Record<string, string>>
): Promise<Invocation> =>
  new Promise((resolve, reject) => {
    const child = spawn(executable, [], {
      env: { ...environment },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    const timeout = setTimeout(() => child.kill('SIGKILL'), 10_000);
    child.stdout.setEncoding('utf8').on('data', (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.setEncoding('utf8').on('data', (chunk: string) => {
      stderr += chunk;
    });
    child.once('error', reject);
    child.once('close', (code, signal) => {
      clearTimeout(timeout);
      if (signal !== null) {
        reject(new Error(`driver terminated by ${signal}`));
        return;
      }
      resolve({ code: code ?? undefined, stdout, stderr });
    });
    child.stdin.end(input);
  });

const listen = async (socket: string): Promise<Server> => {
  const server = net.createServer((connection) => connection.end());
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(socket, resolve);
  });
  servers.add(server);
  return server;
};

const patchedDriver = async (
  sourcePath: string,
  destination: string,
  tools: Readonly<{ docker: string; jq: string; curl: string; python: string }>
) => {
  const uid = process.getuid?.() ?? 0;
  const original = await readFile(sourcePath, 'utf8');
  const source = original
    .replaceAll('/usr/bin/docker', tools.docker)
    .replaceAll('/usr/bin/jq', tools.jq)
    .replaceAll('/usr/bin/curl', tools.curl)
    .replaceAll('/usr/bin/python3.12', tools.python)
    .replace('^0\\|[0-7]{3,4}', `^(0|${uid})\\|[0-7]{3,4}`);
  await writeFile(destination, source, { mode: 0o700 });
  await chmod(destination, 0o700);
};

const createHarness = async (kind: 'candidate' | 'oracle' = 'candidate'): Promise<Harness> => {
  const root = await mkdtemp('/var/tmp/henry-build/phase2-live-driver-');
  roots.add(root);
  await chmod(root, 0o700);
  const socket = path.join(root, 'control.sock');
  await listen(socket);
  const calls = path.join(root, 'calls');
  const sql = path.join(root, 'sql');
  const usage = path.join(root, 'usage');
  const mutation = path.join(root, 'mutation');
  const fault = path.join(root, 'fault');
  const flipCount = path.join(root, 'flip-count');
  const acceptRole = path.join(root, 'accept-role');
  const noOpFault = path.join(root, 'noop-fault');
  const restoreFailure = path.join(root, 'restore-failure');
  const decision = path.join(root, 'decision');
  const postAuthorityMissing = path.join(root, 'post-authority-missing');
  const malformedJwks = path.join(root, 'malformed-jwks');
  const hang = path.join(root, 'hang');
  const hangReached = path.join(root, 'hang-reached');
  const unlinkRace = path.join(root, 'unlink-race');
  const unlinkEvidence = path.join(root, 'unlink-evidence');
  const quarantineCollision = path.join(root, 'quarantine-collision');
  const postVerifyRace = path.join(root, 'post-verify-race');
  const postVerifyEvidence = path.join(root, 'post-verify-evidence');
  const deviceStatus = path.join(root, 'device-status');
  const secretLeak = path.join(root, 'secret-leak');
  const normalizedInitialLeak = path.join(root, 'normalized-initial-leak');
  const primaryCoreService = `${kind}-primary-core`;
  const foreignCoreService = `${kind}-foreign-core`;
  const primaryPostgresService = `${kind}-primary-postgres`;
  const foreignPostgresService = `${kind}-foreign-postgres`;
  const fakeDocker = path.join(root, 'docker');
  const fakeJq = path.join(root, 'jq');
  const fakeCurl = path.join(root, 'curl');
  const fakePython = path.join(root, 'python');
  const dockerScript = `#!/usr/bin/env bash
set -euo pipefail
printf 'docker:' >>'${calls}'
printf ' %q' "$@" >>'${calls}'
printf '\n' >>'${calls}'
if [[ "$1" == ps ]]; then
  args="$*"
  emit_id() {
    if [[ " $args " == *' --no-trunc '* ]]; then
      printf '%s' "$1"
    else
      printf '%.12s' "$1"
    fi
  }
  case "$args" in
    *candidate-primary-core*) emit_id '${ids.primaryCore}' ;;
    *candidate-foreign-core*) emit_id '${ids.foreignCore}' ;;
    *candidate-primary-postgres*) emit_id '${ids.primaryPostgres}' ;;
    *candidate-foreign-postgres*) emit_id '${ids.foreignPostgres}' ;;
    *oracle-primary-core*) emit_id '${ids.primaryCore}' ;;
    *oracle-foreign-core*) emit_id '${ids.foreignCore}' ;;
    *oracle-primary-postgres*) emit_id '${ids.primaryPostgres}' ;;
    *oracle-foreign-postgres*) emit_id '${ids.foreignPostgres}' ;;
    *) exit 1 ;;
  esac
  exit 0
fi
  if [[ "$1" == inspect ]]; then
  id="${'$'}{*: -1}"
  case "$id" in
    '${ids.primaryCore}') service='${primaryCoreService}' ;;
    '${ids.foreignCore}') service='${foreignCoreService}' ;;
    '${ids.primaryPostgres}') service='${primaryPostgresService}' ;;
    '${ids.foreignPostgres}') service='${foreignPostgresService}' ;;
    *) exit 1 ;;
  esac
  if [[ "$*" == *'.Config.Image'* ]]; then
    printf '%s|%s|%s|%s|running' "$id" "$service" '${projectName}' '${rawImageId}'
  else
    printf '%s|%s|%s|running' "$id" "$service" '${projectName}'
  fi
  exit 0
fi
if [[ "$1" == exec ]]; then
  client_id=''
  general_key_id='${kind === 'oracle' ? 'general-db-id' : 'general'}'
  command_query=''
  for argument in "$@"; do
    case "$argument" in
      --set=client_id=*) client_id="${'$'}{argument#--set=client_id=}" ;;
      --set=general_key_id=*) general_key_id="${'$'}{argument#--set=general_key_id=}" ;;
      --command=*) command_query+="${'$'}{argument#--command=}"$'\n' ;;
    esac
  done
  input="$(cat)"
  if [[ -n "$command_query" ]]; then
    input="$command_query"
    printf '%s\n[COPY DATA OMITTED]\n-- invocation --\n' "$input" >>'${sql}'
  else
    printf '%s\n-- invocation --\n' "$input" >>'${sql}'
  fi
  if [[ "$input" == *'SET ROLE aster_request'* || "$input" == *'SET ROLE aster_admin'* || "$input" == *'SET ROLE aster_worker'* ]]; then
    if [[ -f '${acceptRole}' ]]; then exit 0; fi
    printf '%s\n' 'ERROR:  42501: request role write rejected' >&2
    exit 1
  fi
  if [[ "$input" == *'set_byte(ciphertext'* ]]; then
    count=0
    [[ -f '${flipCount}' ]] && read -r count <'${flipCount}'
    count=$((count + 1)); printf '%s\n' "$count" >'${flipCount}'
    if [[ -f '${restoreFailure}' && "$count" -gt 1 ]]; then exit 1; fi
    if [[ ! -f '${noOpFault}' ]]; then
      if [[ -f '${fault}' ]]; then rm -f '${fault}'; else : >'${fault}'; fi
    fi
    exit 0
  fi
  if [[ "$input" == *'UPDATE resources SET is_default'* || "$input" == *'UPDATE aster_tenant.api_resources SET is_default'* ]]; then
    printf '%s' ok
    exit 0
  fi
  if [[ "$input" == *'jsonb_agg(id ORDER BY id)'* || "$input" == *'jsonb_agg(device_uid ORDER BY device_uid)'* ]]; then
    if [[ -f '${root}/device-ids-mode' && "$(cat '${root}/device-ids-mode')" == expired-cleanup ]]; then
      if [[ -f '${root}/device-ids-seen' ]]; then
        printf '%s' '["device-uid-new"]'
      else
        printf '%s' one >'${root}/device-ids-seen'
        if [[ "$input" == *'expires_at>now()'* || "$input" == *'expires_at>floor(extract(epoch from now()))::bigint'* ]]; then
          printf '%s' '[]'
        else
          printf '%s' '["device-uid-expired"]'
        fi
      fi
    elif [[ -f '${root}/device-ids-mode' && "$(cat '${root}/device-ids-mode')" == active-loss ]]; then
      if [[ -f '${root}/device-ids-seen' ]]; then
        printf '%s' '["device-uid-new"]'
      else
        printf '%s' one >'${root}/device-ids-seen'
        printf '%s' '["device-uid-active"]'
      fi
    elif [[ -f '${root}/device-ids-seen' && "$(cat '${root}/device-ids-seen')" == multi ]]; then
      printf '%s' '["device-uid-a","device-uid-b"]'
    elif [[ -f '${root}/device-ids-seen' ]]; then
      printf '%s' '["device-uid"]'
    else
      printf '%s' one >'${root}/device-ids-seen'
      printf '%s' '[]'
    fi
    exit 0
  fi
  if [[ "$input" == *'WITH client_row AS'* && -f '${hang}' ]]; then
    : >'${hangReached}'
    /usr/bin/sleep 30
  fi
  if [[ "$input" == *'relforcerowsecurity'* && "$input" == *'account_verification_records'* ]]; then
    printf '%s' '{"forcedRls":true,"columns":["tenant_id","verification_digest","account_id","verification_method","issued_at","expires_at"],"privileges":["INSERT","SELECT"],"recordCount":0}'
    exit 0
  fi
  if [[ "$input" == *'relforcerowsecurity'* && "$input" == *"relname='device_authorizations'"* ]]; then
    printf '%s' '{"rowSecurity":true,"forcedRowSecurity":true,"requestPrivileges":["DELETE","INSERT","SELECT","UPDATE"],"adminPrivileges":false,"workerPrivileges":false,"inserted":1}'
    exit 0
  fi
  if [[ "$input" == *'SELECT deployment_id::text FROM aster_control.deployment_state'* ]]; then
    printf '%s' '00000000-0000-4000-8000-000000000001'
    exit 0
  fi
  if [[ "$input" == *'run_tenant_maintenance'* || "$input" == *'mint_tenant_binding'* ]]; then
    exit 0
  fi
  if [[ "$input" == *'activate_tenant_binding'* && "$input" == *"'visible'"* ]]; then
    if [[ "$input" == *"WHERE tenant_id='default' AND device_uid=:'probe_uid')"* ]]; then
      printf '%s' '{"visible":0,"updated":0}'
    else
      printf '%s' '{"visible":1,"updated":1}'
    fi
    exit 0
  fi
  if [[ "$input" == *"'uid',device_uid"* && "$input" == *'device_digest=sha256'* ]]; then
    device_status=pending
    [[ -f '${deviceStatus}' ]] && device_status="$(cat '${deviceStatus}')"
    if [[ "$device_status" == pending ]]; then grant_id=null; else grant_id='"phase2-device-grant"'; fi
    clear_absent=true
    [[ -f '${normalizedInitialLeak}' ]] && clear_absent=false
    printf '{"uid":"device-uid","status":"%s","grantId":%s,"deviceBytes":32,"userBytes":32,"clearAbsent":%s,"row":{"tenant_id":"default","device_uid":"device-uid","device_digest":"stored-device-credential","user_digest":"stored-user-credential","client_id":"phase2-device-first","request_context":{},"status":"%s","grant_id":%s}}' "$device_status" "$grant_id" "$clear_absent" "$device_status" "$grant_id"
    exit 0
  fi
  if [[ "$input" == *"'rowHash'"* && "$input" == *"'deviceDigest'"* ]]; then
    printf '{"rowHash":"%064d","deviceDigest":"%064d"}' 0 0 | tr '0' a
    exit 0
  fi
  if [[ "$input" == *"SELECT encode(sha256(convert_to(to_jsonb(row)::text"* ]]; then
    printf '%064d' 0 | tr '0' a
    exit 0
  fi
  if [[ "$input" == *"information_schema.columns"* && "$input" == *"device_authorizations"* ]]; then
    printf '%s' 0
    exit 0
  fi
  if [[ "$input" == *'WITH device AS ('* && "$input" == *"'interactions'"* ]]; then
    device_status=approved
    [[ -f '${deviceStatus}' ]] && device_status="$(cat '${deviceStatus}')"
    printf '{"device":{"tenant_id":"default","device_uid":"device-uid","status":"%s","grant_id":"phase2-device-grant"},"interactions":[],"grant":[{"grant_id":"phase2-device-grant"}],"session":[],"families":[],"refresh":[],"access":[]}' "$device_status"
    exit 0
  fi
  if [[ "$input" == *"SELECT encode(device_digest,'hex')"* ]]; then
    printf '%064d' 0 | tr '0' a
    exit 0
  fi
  if [[ "$input" == *'phase2_device_transition_failure'* ]]; then
    exit 0
  fi
  if [[ "$input" == *"status='consumed'"* && "$input" == *'consumed_at IS NOT NULL'* ]]; then
    printf '%s' 1
    exit 0
  fi
  if [[ "$input" == *'generate_series(0,64)'* ]]; then
    printf '%s' '{"expired":65,"sentinel":1}'
    exit 0
  fi
  if [[ "$input" == *"'newRow'"* && "$input" == *"device_uid LIKE"* ]]; then
    printf '%s' '{"expired":1,"sentinel":1,"newRow":1}'
    exit 0
  fi
  if [[ "$input" == *"'device',(SELECT count(*)"* && "$input" == *"'families'"* ]]; then
    printf '%s' '{"device":0,"grant":0,"families":0,"access":0,"refresh":0}'
    exit 0
  fi
  if [[ "$input" == *"'familyIds'"* && "$input" == *"'refreshIds'"* && "$input" == *"'accessDigests'"* ]]; then
    printf '%s' '{"familyIds":["family-id"],"refreshIds":[{"tokenId":"refresh-id","digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"accessDigests":["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]}'
    exit 0
  fi
  if [[ "$input" == *'octet_length(body)<=49152'* && "$input" == *"encode(convert_to(body,'UTF8'),'base64')"* ]]; then
    if [[ -f '${secretLeak}' ]]; then
      printf '%s' 'eyJlbWJlZGRlZCI6IkJDREZHSEpLIn0='
    else
      printf '%s' 'e30='
    fi
    exit 0
  fi
  if [[ "$input" == *'SELECT count(*) FROM aster_tenant.device_authorizations'* && "$*" == *'aster_phase1_candidate_foreign'* ]]; then
    printf '%s' 0
    exit 0
  fi
  if [[ "$input" == *'oidc_model_instances'*'DeviceCode'* || "$input" == *'aster_tenant.device_authorizations'* ]]; then
    printf '%s' ok
    exit 0
  fi
  general=10
  [[ -f '${usage}' ]] && general=20
  users=u
  [[ -f '${mutation}' ]] && users=changed
  db_decision=authorized
  [[ -f '${decision}' ]] && db_decision="$(cat '${decision}')"
  if [[ -f '${postAuthorityMissing}' && "$client_id" == '${fixture.clients.post.id}' ]]; then
    db_decision=unauthorized-client
  fi
  if [[ "$db_decision" == authorized ]]; then
    target_kind=resource
    target_json='"https://phase2.example.invalid/api-primary"'
  else
    target_kind=none
    target_json=null
  fi
  if [[ "$input" == *'WITH client_row AS'* ]]; then
    printf '{"authority":{"decision":"%s","targetKind":"%s","target":%s,"availableScopes":["read","write"],"effectiveScopes":[]},"browser":{"users":"%s","sessions":"s","grants":"g","authorizationCodes":"c","interactions":"i","tokenFamilies":"f","refreshTokens":"r"},"machine":"machine","signing":{"static":"static","generalKeyId":"%s","generalLastSignedAt":%s,"oidcIdTokenKeyId":"oidc","oidcIdTokenLastSignedAt":5}}' "$db_decision" "$target_kind" "$target_json" "$users" "$general_key_id" "$general"
  else
    printf '{"browser":{"users":"%s","sessions":"s","grants":"g","authorizationCodes":"c","interactions":"i","tokenFamilies":"f","refreshTokens":"r"},"machine":"machine","signing":{"static":"static","generalKeyId":"%s","generalLastSignedAt":%s,"oidcIdTokenKeyId":"oidc","oidcIdTokenLastSignedAt":5}}' "$users" "$general_key_id" "$general"
  fi
  exit 0
fi
exit 1
`;
  const jqScript = `#!/usr/bin/env bash
set -euo pipefail
printf 'jq:' >>'${calls}'
printf ' %q' "$@" >>'${calls}'
printf '\n' >>'${calls}'
exec /usr/bin/jq "$@"
`;
  const curlScript = `#!/usr/bin/env bash
set -euo pipefail
printf 'curl:' >>'${calls}'
printf ' %q' "$@" >>'${calls}'
printf '\n' >>'${calls}'
args="$*"
if [[ "$args" == *'/oidc/jwks'* ]]; then
  if [[ -f '${malformedJwks}' ]]; then
    printf '%s' '{"keys":[{"kid":"${oracleSigningKeyId}\\n"}]}'
  else
    printf '{"keys":[{"kid":"${oracleSigningKeyId}"}]}'
  fi
  exit 0
fi
if [[ "$args" == *'.well-known/openid-configuration'* ]]; then
  case "$args" in
    *localhost:3311*) issuer='http://localhost:3311/oidc' ;;
    *localhost:3411*) issuer='http://localhost:3411/oidc' ;;
    *localhost:3312*) issuer='http://localhost:3312/oidc' ;;
    *localhost:3412*) issuer='http://localhost:3412/oidc' ;;
    *localhost:3321*) issuer='http://localhost:3321/oidc' ;;
    *localhost:3421*) issuer='http://localhost:3421/oidc' ;;
    *localhost:3322*) issuer='http://localhost:3322/oidc' ;;
    *localhost:3422*) issuer='http://localhost:3422/oidc' ;;
    *) exit 1 ;;
  esac
  printf '{"issuer":"%s"}' "$issuer"
  exit 0
fi
config=''
while (($#)); do
  case "$1" in
    --config) config=$2; shift 2 ;;
    *) shift ;;
  esac
done
[[ "$config" == - ]] || exit 1
config_input="$(cat)"
if grep -q 'localhost:3322/oidc/token' <<<"$config_input"; then
  printf '%s\n%s' '{"error":"invalid_client"}' 400
elif [[ -f '${fault}' ]]; then
  printf '%s\n%s' '{"error":"temporarily_unavailable"}' 503
else
  : >'${usage}'
  printf '%s\n%s' '{"access_token":"opaque-test-token","expires_in":3600,"token_type":"Bearer"}' 200
fi
`;
  const pythonScript = `#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == *'renameat2(-100'* && -f '${quarantineCollision}' ]]; then
  quarantine_path="${'$'}{*: -1}"
  printf '%s' 'collision-must-survive' >"$quarantine_path"
  /usr/bin/chmod 0600 -- "$quarantine_path"
fi
if [[ "$*" == *'renameat2(-100'* && -f '${unlinkRace}' ]]; then
  source_path="${'$'}{*: -2:1}"
  /usr/bin/mv -- "$source_path" '${unlinkEvidence}'
  printf '%s' 'replacement-must-survive' >"$source_path"
  /usr/bin/chmod 0600 -- "$source_path"
fi
if [[ "$*" == *'os.ftruncate(fd, 0)'* && -f '${postVerifyRace}' ]]; then
  quarantine_path=''
  for candidate in '${root}/phase2-client-credentials-state'/.quarantine.*; do
    [[ -f "$candidate" ]] || continue
    quarantine_path=$candidate
  done
  [[ -n "$quarantine_path" ]]
  /usr/bin/mv -- "$quarantine_path" '${postVerifyEvidence}'
  printf '%s' 'post-verify-replacement-must-survive' >"$quarantine_path"
  /usr/bin/chmod 0600 -- "$quarantine_path"
fi
exec /usr/bin/python3.12 "$@"
`;
  await Promise.all([
    writeFile(fakeDocker, dockerScript, { mode: 0o700 }),
    writeFile(fakeJq, jqScript, { mode: 0o700 }),
    writeFile(fakeCurl, curlScript, { mode: 0o700 }),
    writeFile(fakePython, pythonScript, { mode: 0o700 }),
  ]);
  await Promise.all([
    chmod(fakeDocker, 0o700),
    chmod(fakeJq, 0o700),
    chmod(fakeCurl, 0o700),
    chmod(fakePython, 0o700),
  ]);
  const state = path.join(root, 'state-driver');
  const invariant = path.join(root, 'invariant-driver');
  await patchedDriver(stateDriver, state, {
    docker: fakeDocker,
    jq: fakeJq,
    curl: fakeCurl,
    python: fakePython,
  });
  await patchedDriver(invariantDriver, invariant, {
    docker: fakeDocker,
    jq: fakeJq,
    curl: fakeCurl,
    python: fakePython,
  });
  return {
    state,
    invariant,
    socket,
    root,
    calls,
    sql,
    usage,
    mutation,
    fault,
    flipCount,
    acceptRole,
    noOpFault,
    restoreFailure,
    decision,
    postAuthorityMissing,
    malformedJwks,
    hang,
    hangReached,
    unlinkRace,
    unlinkEvidence,
    quarantineCollision,
    postVerifyRace,
    postVerifyEvidence,
    deviceStatus,
    secretLeak,
    normalizedInitialLeak,
    env: {
      ASTER_PHASE2_CONTROL_SOCKET: socket,
      ASTER_CORE_URL: candidateTarget.coreUrl,
      ASTER_ADMIN_URL: candidateTarget.adminUrl,
      ASTER_FOREIGN_CORE_URL: candidateForeignTarget.coreUrl,
      ASTER_FOREIGN_ADMIN_URL: candidateForeignTarget.adminUrl,
      LC_ALL: 'C',
      PATH: '/usr/bin:/bin',
    },
  };
};

const stateRequest = (
  operation: string,
  extra: Readonly<Record<string, unknown>> = {},
  kind: 'candidate' | 'oracle' = 'candidate'
) =>
  ({
    schemaVersion: 1,
    kind: 'phase2-client-credentials-state-request',
    operation,
    scenarioId: 'client-credentials.basic-explicit-resource',
    target: kind === 'candidate' ? candidateTarget : oracleTarget,
    foreignTarget: kind === 'candidate' ? candidateForeignTarget : oracleForeignTarget,
    fixture,
    ...(operation === 'finish'
      ? {
          signingKeyId:
            extra.tokenIssued === true
              ? kind === 'oracle'
                ? oracleSigningKeyId
                : 'general'
              : null,
        }
      : {}),
    ...extra,
  }) as const;

const retiredTombstones = async (handleRoot: string): Promise<readonly string[]> => {
  const directoryEntries = await readdir(handleRoot);
  const entries = directoryEntries.filter((name) => name.startsWith('.quarantine.'));
  for (const name of entries) {
    const file = path.join(handleRoot, name);
    const state = await stat(file);
    expect(state.mode % 0o1000).toBe(0o600);
    expect(await readFile(file, 'utf8')).toBe('{"schemaVersion":1,"retired":true}');
  }
  return entries;
};

const invariantRequest = (invariantId: string) => ({
  schemaVersion: 1,
  kind: 'phase2-client-credentials-candidate-invariant-request',
  invariantId,
  target: { primary: candidateTarget, foreign: candidateForeignTarget },
  fixture,
  credentials: { basic: basicSecret, post: postSecret },
});

const deviceInvariantRequest = (
  invariantId: string,
  operation: string,
  privateValues: Readonly<Record<string, unknown>> = {},
  observation: Readonly<Record<string, unknown>> = {},
  handle?: string
) => ({
  schemaVersion: 1,
  kind: 'phase2-client-credentials-candidate-invariant-request',
  invariantId,
  operation,
  target: { primary: candidateTarget, foreign: candidateForeignTarget },
  fixture,
  private: privateValues,
  observation,
  ...(handle === undefined ? {} : { handle }),
});

afterEach(async () => {
  for (const server of servers) {
    await new Promise<void>((resolve) => {
      server.close(() => {
        resolve();
      });
    });
  }
  servers.clear();
  await Promise.all([...roots].map(async (root) => rm(root, { recursive: true, force: true })));
  roots.clear();
});

describe('Phase 2 live client-credentials shell drivers', () => {
  it.each([stateDriver, invariantDriver])(
    'pins the private engine boundary and trusted command paths in %s',
    async (driver) => {
      const source = await readFile(driver, 'utf8');

      expect(source).toContain('ASTER_PHASE2_CONTROL_SOCKET');
      expect(source).toContain('/usr/bin/docker');
      expect(source).toContain('/usr/bin/jq');
      expect(source).toMatch(/DOCKER_HOST="unix:\/\/\$\{ASTER_PHASE2_CONTROL_SOCKET\}"/u);
      expect(source).toContain('aster-phase2-client-credentials-[0-9a-f]{16}');
      expect(source).toContain('com.docker.compose.service');
      expect(source).toContain('com.docker.compose.project');
      expect(source).not.toMatch(/--argjson\s+(?:request|descriptor)\b/u);
      expect(source).not.toContain('--filter "publish=');
      expect(source).toContain('http://localhost:');
      expect(source).toContain('ps --no-trunc -q');
      expect(source).toContain('normalize_image_id');
      if (driver === stateDriver) {
        expect(source).toContain('oracle_signing_key_id');
      }
    }
  );

  it('fails both drivers when container discovery omits --no-trunc and receives short IDs', async () => {
    const harness = await createHarness();
    const unsafeState = path.join(harness.root, 'state-driver-short-id');
    const unsafeInvariant = path.join(harness.root, 'invariant-driver-short-id');
    await Promise.all([
      readFile(harness.state, 'utf8').then(async (driver) =>
        writeFile(unsafeState, driver.replaceAll('ps --no-trunc -q', 'ps -q'), { mode: 0o700 })
      ),
      readFile(harness.invariant, 'utf8').then(async (driver) =>
        writeFile(unsafeInvariant, driver.replaceAll('ps --no-trunc -q', 'ps -q'), {
          mode: 0o700,
        })
      ),
    ]);
    await Promise.all([chmod(unsafeState, 0o700), chmod(unsafeInvariant, 0o700)]);

    const [stateResult, invariantResult] = await Promise.all([
      invoke(unsafeState, JSON.stringify(stateRequest('begin')), harness.env),
      invoke(
        unsafeInvariant,
        JSON.stringify(invariantRequest('client-credentials.user-authority-unchanged')),
        harness.env
      ),
    ]);

    expect(stateResult.code).not.toBe(0);
    expect(stateResult.stdout).toBe('');
    expect(stateResult.stderr).toBe('Phase 2 client credentials state driver failed.\n');
    expect(invariantResult.code).not.toBe(0);
    expect(invariantResult.stdout).toBe('');
    expect(invariantResult.stderr).toBe('Phase 2 client credentials invariant driver failed.\n');
  });

  it('reads real oracle and candidate state instead of emitting scenario constants', async () => {
    const source = await readFile(stateDriver, 'utf8');

    for (const relation of [
      'applications',
      'resources',
      'scopes',
      'roles',
      'applications_roles',
      'roles_scopes',
      'organization_application_relations',
      'organization_role_application_relations',
      'oidc_model_instances',
      'logto_configs',
      'aster_tenant.oidc_client_grants',
      'aster_tenant.m2m_client_resource_scopes',
      'aster_tenant.organization_m2m_clients',
      'aster_tenant.organization_m2m_scopes',
      'aster_tenant.organization_m2m_resource_scopes',
      'aster_tenant.users',
      'aster_tenant.sessions',
      'aster_tenant.grants',
      'aster_tenant.authorization_codes',
      'aster_tenant.interactions',
      'aster_tenant.token_families',
      'aster_tenant.refresh_tokens',
      'aster_tenant.signing_key_metadata',
      'aster_tenant.oidc_id_token_signing_key_metadata',
    ]) {
      expect(source).toContain(relation);
    }
    expect(source).toContain('set-default-resource');
    expect(source).toContain('responseError');
    expect(source).toContain('signingKeyId');
    expect(source).toContain('case "$response_error" in');
    expect(source).toContain('published_decision=invalid-request');
    expect(source).not.toContain('if [[ "$request_target" == duplicate-resource');
    expect(source).not.toContain('db_decision=unauthorized-client');
    expect(source).toContain('0600');
    expect(source).toContain('0700');
    expect(source).not.toContain('expectedProjection');
    expect(source).not.toContain('if [[ "$response_error" == access_denied ]]');
  });

  it('selects the SQL authority client from the actual scenario request', async () => {
    const harness = await createHarness();
    const expectedClients = new Map<string, string>([
      ['client-credentials.post-explicit-resource', fixture.clients.post.id],
      ['client-credentials.wrong-secret-post', fixture.clients.post.id],
      ['client-credentials.unassociated-organization', fixture.clients.post.id],
      ['client-credentials.unknown-client-basic', 'phase2-unknown-client-basic'],
      ['client-credentials.unknown-client-post', 'phase2-unknown-client-post'],
      ['client-credentials.basic-explicit-resource', fixture.clients.basic.id],
      ['client-credentials.wrong-secret-basic', fixture.clients.basic.id],
    ]);

    for (const [scenarioId, expectedClientId] of expectedClients) {
      await rm(harness.calls, { force: true });
      const begun = await invoke(
        harness.state,
        JSON.stringify(stateRequest('begin', { scenarioId })),
        harness.env
      );
      expect(begun).toMatchObject({ code: 0, stderr: '' });
      expect(await readFile(harness.calls, 'utf8')).toContain(
        `--set=client_id=${expectedClientId}`
      );
      if (scenarioId === 'client-credentials.unassociated-organization') {
        const calls = await readFile(harness.calls, 'utf8');
        expect(calls).toContain(`--set=organization_id=${fixture.organization.id}`);
        expect(calls).toContain('--set=request_target=organization');
      }
      const { handle } = JSON.parse(begun.stdout) as { handle: string };
      const aborted = await invoke(
        harness.state,
        JSON.stringify(stateRequest('abort', { scenarioId, handle })),
        harness.env
      );
      expect(aborted).toMatchObject({ code: 0, stderr: '' });
    }
  });

  it('detects missing POST authority instead of querying the BASIC client during finish', async () => {
    const harness = await createHarness();
    await writeFile(harness.postAuthorityMissing, 'missing', { mode: 0o600 });
    const scenarioId = 'client-credentials.post-explicit-resource';
    const begun = await invoke(
      harness.state,
      JSON.stringify(stateRequest('begin', { scenarioId })),
      harness.env
    );
    expect(begun).toMatchObject({ code: 0, stderr: '' });
    const { handle } = JSON.parse(begun.stdout) as { handle: string };
    await writeFile(harness.usage, 'advanced', { mode: 0o600 });

    const finished = await invoke(
      harness.state,
      JSON.stringify(
        stateRequest('finish', {
          scenarioId,
          handle,
          responseStatus: 200,
          tokenIssued: true,
          responseError: null,
        })
      ),
      harness.env
    );

    expect(finished.code).not.toBe(0);
    expect(finished.stdout).toBe('');
    expect(finished.stderr).toBe('Phase 2 client credentials state driver failed.\n');
  });

  it('contains all four live candidate probes and explicit restoration paths', async () => {
    const source = await readFile(invariantDriver, 'utf8');

    for (const marker of [
      'cross-tenant-authority-rejected',
      'request-role-write-rejected',
      'signing-failure-rolls-back',
      'user-authority-unchanged',
      'SET ROLE aster_request',
      'signing_key_material',
      'temporarily_unavailable',
      'restore_signing_material',
      '--config',
    ]) {
      expect(source).toContain(marker);
    }
    expect(source).not.toMatch(/curl[^\n]*(?:Authorization|client_secret)/u);
    expect(source).toContain('http_token_request "$ASTER_FOREIGN_CORE_URL"');
    expect(source).toContain('WHERE false;');
    expect(source).not.toContain("RAISE EXCEPTION USING ERRCODE='42501'");
  });

  it('passes private command-query identifiers through COPY instead of psql variables', async () => {
    const source = await readFile(invariantDriver, 'utf8');
    const commandLines = source.split('\n').filter((line) => line.includes('--command='));

    expect(commandLines).not.toEqual([]);
    expect(commandLines.every((line) => !line.includes(":\\'"))).toBe(true);
    expect(source).toContain(
      'CREATE TEMP TABLE phase2_private_codes(device_code text,user_code text,client_id text)'
    );
    expect(source).toContain(
      'CREATE TEMP TABLE phase2_private_device_code(device_code text,client_id text)'
    );
    expect(source).toContain(
      'CREATE TEMP TABLE phase2_private_codes(device_code text,user_code text,prefix text)'
    );
    expect(source).toContain('CREATE TEMP TABLE phase2_private_code(device_code text,prefix text)');
  });

  it('persists a private baseline, publishes DB-derived facts, and keeps abort idempotent', async () => {
    const harness = await createHarness();
    const stateEnv = {
      ASTER_PHASE2_CONTROL_SOCKET: harness.socket,
      LC_ALL: 'C',
      PATH: '/usr/bin:/bin',
    };
    const begun = await invoke(harness.state, JSON.stringify(stateRequest('begin')), stateEnv);

    expect(begun).toMatchObject({ code: 0, stderr: '' });
    expect(begun.stdout).not.toContain('\n');
    const beginTerminal = JSON.parse(begun.stdout) as Record<string, unknown>;
    const { handle } = beginTerminal;
    expect(handle).toEqual(expect.stringMatching(/^[0-9a-f]{32}$/u));
    expect(beginTerminal).toEqual({
      handle,
      schemaVersion: 1,
      kind: 'phase2-client-credentials-state',
      operation: 'begin',
      scenarioId: 'client-credentials.basic-explicit-resource',
      attestation: {
        projectName,
        primary: {
          containerId: ids.primaryCore,
          service: 'candidate-primary-core',
          imageDigest,
        },
        foreign: {
          containerId: ids.foreignCore,
          service: 'candidate-foreign-core',
          imageDigest,
        },
      },
    });
    expect(begun.stdout).not.toContain(fixture.allocationId);
    expect(begun.stdout).not.toContain(candidateTarget.coreUrl);
    const handleFile = path.join(
      harness.root,
      'phase2-client-credentials-state',
      `${String(handle)}.json`
    );
    const handleState = await stat(handleFile);
    expect(handleState.mode % 0o1000).toBe(0o600);

    await writeFile(harness.usage, 'advanced', { mode: 0o600 });
    const finished = await invoke(
      harness.state,
      JSON.stringify(
        stateRequest('finish', {
          handle,
          responseStatus: 200,
          tokenIssued: true,
          responseError: null,
        })
      ),
      stateEnv
    );
    expect(finished).toMatchObject({ code: 0, stderr: '' });
    expect(JSON.parse(finished.stdout)).toMatchObject({
      handle,
      authority: {
        decision: 'authorized',
        targetKind: 'resource',
        target: fixture.resources.primary.indicator,
      },
      signingUse: { generalKeyUse: 'verified', oidcIdTokenKeyUse: 'unchanged' },
      sideEffects: {
        users: 0,
        sessions: 0,
        grants: 0,
        authorizationCodes: 0,
        interactions: 0,
        refreshTokens: 0,
        tokenFamilies: 0,
      },
    });
    await expect(stat(handleFile)).rejects.toThrow();
    await expect(retiredTombstones(path.dirname(handleFile))).resolves.toHaveLength(1);

    for (const abortHandle of [handle, null]) {
      const aborted = await invoke(
        harness.state,
        JSON.stringify(stateRequest('abort', { handle: abortHandle })),
        stateEnv
      );
      expect(aborted).toMatchObject({ code: 0, stderr: '' });
      expect(JSON.parse(aborted.stdout)).toMatchObject({ operation: 'abort', ok: true });
    }
    for (const enabled of [false, true]) {
      const switched = await invoke(
        harness.state,
        JSON.stringify(
          stateRequest('set-default-resource', {
            scenarioId: 'client-credentials.missing-target',
            enabled,
          })
        ),
        stateEnv
      );
      expect(switched).toMatchObject({ code: 0, stderr: '' });
      expect(JSON.parse(switched.stdout)).toMatchObject({
        operation: 'set-default-resource',
        ok: true,
      });
    }
    const scenarioId = 'device-verification.expired-code';
    const deviceBegun = await invoke(
      harness.state,
      JSON.stringify(stateRequest('device-begin', { scenarioId })),
      stateEnv
    );
    expect(deviceBegun).toMatchObject({ code: 0, stderr: '' });
    const deviceHandle = (JSON.parse(deviceBegun.stdout) as { handle: string }).handle;
    for (const [operation, extra] of [
      ['device-capture', { handle: deviceHandle }],
      ['device-transition', { handle: deviceHandle, action: 'expire' }],
      ['device-abort', { handle: deviceHandle }],
    ] as const) {
      const transitioned = await invoke(
        harness.state,
        JSON.stringify(stateRequest(operation, { scenarioId, ...extra })),
        stateEnv
      );
      expect(transitioned).toMatchObject({ code: 0, stderr: '' });
      expect(JSON.parse(transitioned.stdout)).toMatchObject({ operation, scenarioId, ok: true });
    }
    const calls = await readFile(harness.calls, 'utf8');
    expect(calls).toContain('--single-transaction');
    expect(calls).not.toContain('--filter publish=');
  });

  it('expires the oracle DeviceCode payload and catalog row together', async () => {
    const harness = await createHarness('oracle');
    const scenarioId = 'device-verification.expired-code';
    const begun = await invoke(
      harness.state,
      JSON.stringify(stateRequest('device-begin', { scenarioId }, 'oracle')),
      harness.env
    );
    expect(begun).toMatchObject({ code: 0, stderr: '' });
    const { handle } = JSON.parse(begun.stdout) as { handle: string };
    for (const operation of ['device-capture', 'device-transition', 'device-abort'] as const) {
      const result = await invoke(
        harness.state,
        JSON.stringify(
          stateRequest(
            operation,
            {
              scenarioId,
              handle,
              ...(operation === 'device-transition' ? { action: 'expire' } : {}),
            },
            'oracle'
          )
        ),
        harness.env
      );
      expect(result).toMatchObject({ code: 0, stderr: '' });
    }
    const calls = await readFile(harness.sql, 'utf8');
    expect({
      selectedDevice: calls.includes("model_name='DeviceCode' AND id=:'selected_id'"),
      payloadExpired: calls.includes(
        "payload=pg_catalog.jsonb_set(payload,'{exp}','0'::jsonb,false)"
      ),
      typedPayload: calls.includes("pg_catalog.jsonb_typeof(payload->'exp')='number'"),
      bothExpiriesChecked: calls.includes("bool_and(expires_at<now() AND payload_exp='0')"),
    }).toEqual({
      selectedDevice: true,
      payloadExpired: true,
      typedPayload: true,
      bothExpiriesChecked: true,
    });
  });

  it.each(['oracle', 'candidate'] as const)(
    'ignores a preexisting expired %s row when capturing one new live authorization',
    async (kind) => {
      const harness = await createHarness(kind);
      await writeFile(path.join(harness.root, 'device-ids-mode'), 'expired-cleanup', {
        mode: 0o600,
      });
      const scenarioId = 'device-verification.already-used-code';
      const begun = await invoke(
        harness.state,
        JSON.stringify(stateRequest('device-begin', { scenarioId }, kind)),
        harness.env
      );
      expect(begun).toMatchObject({ code: 0, stderr: '' });
      const { handle } = JSON.parse(begun.stdout) as { handle: string };

      const captured = await invoke(
        harness.state,
        JSON.stringify(stateRequest('device-capture', { scenarioId, handle }, kind)),
        harness.env
      );

      expect(captured).toMatchObject({ code: 0, stderr: '' });
      expect(JSON.parse(captured.stdout)).toMatchObject({ operation: 'device-capture', ok: true });
      const aborted = await invoke(
        harness.state,
        JSON.stringify(stateRequest('device-abort', { scenarioId, handle }, kind)),
        harness.env
      );
      expect(aborted).toMatchObject({ code: 0, stderr: '' });
    }
  );

  it.each(['zero-new', 'multiple-new', 'active-loss', 'cross-scenario'] as const)(
    'rejects %s device capture and removes the private handle',
    async (failureMode) => {
      const harness = await createHarness();
      const scenarioId = 'device-verification.expired-code';
      if (failureMode === 'active-loss') {
        await writeFile(path.join(harness.root, 'device-ids-mode'), failureMode, { mode: 0o600 });
      }
      const begun = await invoke(
        harness.state,
        JSON.stringify(stateRequest('device-begin', { scenarioId })),
        harness.env
      );
      expect(begun).toMatchObject({ code: 0, stderr: '' });
      const { handle } = JSON.parse(begun.stdout) as { handle: string };
      const handleFile = path.join(
        harness.root,
        'phase2-client-credentials-state',
        `${handle}.json`
      );
      const handleStats = await stat(handleFile);
      expect(handleStats.mode % 0o1000).toBe(0o600);
      const saved = await readFile(handleFile, 'utf8');
      expect(saved).not.toMatch(/device.?code|user.?code|cookie|xsrf/iu);
      if (failureMode === 'zero-new') {
        await rm(path.join(harness.root, 'device-ids-seen'));
      } else if (failureMode === 'multiple-new') {
        await writeFile(path.join(harness.root, 'device-ids-seen'), 'multi', { mode: 0o600 });
      }
      const captured = await invoke(
        harness.state,
        JSON.stringify(
          stateRequest('device-capture', {
            scenarioId:
              failureMode === 'cross-scenario'
                ? 'device-verification.already-used-code'
                : scenarioId,
            handle,
          })
        ),
        harness.env
      );
      expect(captured).toMatchObject({
        code: 1,
        stdout: '',
        stderr: 'Phase 2 client credentials state driver failed.\n',
      });
      if (failureMode === 'cross-scenario') {
        await expect(stat(handleFile)).resolves.toBeDefined();
        const cleaned = await invoke(
          harness.state,
          JSON.stringify(stateRequest('device-abort', { scenarioId, handle })),
          harness.env
        );
        expect(cleaned).toMatchObject({ code: 0, stderr: '' });
      }
      await expect(stat(handleFile)).rejects.toThrow();
    }
  );

  it('rejects hardlinked and oversized handle files without deleting them', async () => {
    for (const failureMode of ['hardlink', 'oversize'] as const) {
      const harness = await createHarness();
      const begun = await invoke(harness.state, JSON.stringify(stateRequest('begin')), harness.env);
      expect(begun).toMatchObject({ code: 0, stderr: '' });
      const { handle } = JSON.parse(begun.stdout) as { handle: string };
      const handleFile = path.join(
        harness.root,
        'phase2-client-credentials-state',
        `${handle}.json`
      );
      const second = `${handleFile}.second`;
      await (failureMode === 'hardlink'
        ? link(handleFile, second)
        : writeFile(handleFile, 'x'.repeat(65_537), { mode: 0o600 }));
      const aborted = await invoke(
        harness.state,
        JSON.stringify(stateRequest('abort', { handle })),
        harness.env
      );
      expect(aborted).toMatchObject({
        code: 1,
        stdout: '',
        stderr: 'Phase 2 client credentials state driver failed.\n',
      });
      await expect(stat(handleFile)).resolves.toBeDefined();
      if (failureMode === 'hardlink') {
        await expect(stat(second)).resolves.toBeDefined();
      }
    }
  });

  it('quarantines but never deletes a replacement raced into unlink', async () => {
    const harness = await createHarness();
    const begun = await invoke(harness.state, JSON.stringify(stateRequest('begin')), harness.env);
    const { handle } = JSON.parse(begun.stdout) as { handle: string };
    await writeFile(harness.unlinkRace, 'race', { mode: 0o600 });
    const aborted = await invoke(
      harness.state,
      JSON.stringify(stateRequest('abort', { handle })),
      harness.env
    );
    expect(aborted).toMatchObject({
      code: 1,
      stdout: '',
      stderr: 'Phase 2 client credentials state driver failed.\n',
    });
    const evidence = await readFile(harness.unlinkEvidence, 'utf8');
    expect(evidence).toContain(`"handle":"${handle}"`);
    const handleRoot = path.join(harness.root, 'phase2-client-credentials-state');
    const handleEntries = await readdir(handleRoot);
    const quarantines = handleEntries.filter((name) => name.startsWith('.quarantine.'));
    expect(quarantines).toHaveLength(1);
    const replacement = await readFile(path.join(handleRoot, quarantines[0] ?? ''), 'utf8');
    expect(replacement).toBe('replacement-must-survive');
  });

  it('preserves both source and an atomically colliding quarantine target', async () => {
    const harness = await createHarness();
    const begun = await invoke(harness.state, JSON.stringify(stateRequest('begin')), harness.env);
    const { handle } = JSON.parse(begun.stdout) as { handle: string };
    const handleRoot = path.join(harness.root, 'phase2-client-credentials-state');
    const handleFile = path.join(handleRoot, `${handle}.json`);
    await writeFile(harness.quarantineCollision, 'collision', { mode: 0o600 });
    const aborted = await invoke(
      harness.state,
      JSON.stringify(stateRequest('abort', { handle })),
      harness.env
    );
    expect(aborted).toMatchObject({
      code: 1,
      stdout: '',
      stderr: 'Phase 2 client credentials state driver failed.\n',
    });
    expect(await readFile(handleFile, 'utf8')).toContain(`"handle":"${handle}"`);
    const directoryEntries = await readdir(handleRoot);
    const entries = directoryEntries.filter((name) => name.startsWith('.quarantine.'));
    expect(entries).toHaveLength(1);
    expect(await readFile(path.join(handleRoot, entries[0] ?? ''), 'utf8')).toBe(
      'collision-must-survive'
    );
  });

  it('writes the retired tombstone through the held fd without deleting a post-verify replacement', async () => {
    const harness = await createHarness();
    const begun = await invoke(harness.state, JSON.stringify(stateRequest('begin')), harness.env);
    const { handle } = JSON.parse(begun.stdout) as { handle: string };
    await writeFile(harness.postVerifyRace, 'race', { mode: 0o600 });
    const aborted = await invoke(
      harness.state,
      JSON.stringify(stateRequest('abort', { handle })),
      harness.env
    );
    expect(aborted).toMatchObject({
      code: 1,
      stdout: '',
      stderr: 'Phase 2 client credentials state driver failed.\n',
    });
    expect(await readFile(harness.postVerifyEvidence, 'utf8')).toBe(
      '{"schemaVersion":1,"retired":true}'
    );
    const handleRoot = path.join(harness.root, 'phase2-client-credentials-state');
    const directoryEntries = await readdir(handleRoot);
    const entries = directoryEntries.filter((name) => name.startsWith('.quarantine.'));
    expect(entries).toHaveLength(1);
    expect(await readFile(path.join(handleRoot, entries[0] ?? ''), 'utf8')).toBe(
      'post-verify-replacement-must-survive'
    );
  });

  it('allows exactly one concurrent finish to claim and consume a handle', async () => {
    const harness = await createHarness();
    const begun = await invoke(harness.state, JSON.stringify(stateRequest('begin')), harness.env);
    const { handle } = JSON.parse(begun.stdout) as { handle: string };
    await writeFile(harness.usage, 'advanced', { mode: 0o600 });
    const request = JSON.stringify(
      stateRequest('finish', {
        handle,
        responseStatus: 200,
        tokenIssued: true,
        responseError: null,
      })
    );

    const results = await Promise.all([
      invoke(harness.state, request, harness.env),
      invoke(harness.state, request, harness.env),
    ]);

    expect(results.filter(({ code }) => code === 0)).toHaveLength(1);
    expect(results.filter(({ code }) => code !== 0)).toHaveLength(1);
    expect(results.find(({ code }) => code === 0)?.stderr).toBe('');
    expect(results.find(({ code }) => code !== 0)?.stderr).toBe(
      'Phase 2 client credentials state driver failed.\n'
    );
    await expect(
      retiredTombstones(path.join(harness.root, 'phase2-client-credentials-state'))
    ).resolves.toHaveLength(1);
  });

  it('lets finish and abort race for one claim while keeping abort idempotent', async () => {
    const harness = await createHarness();
    const begun = await invoke(harness.state, JSON.stringify(stateRequest('begin')), harness.env);
    const { handle } = JSON.parse(begun.stdout) as { handle: string };
    await writeFile(harness.usage, 'advanced', { mode: 0o600 });

    const [finished, aborted] = await Promise.all([
      invoke(
        harness.state,
        JSON.stringify(
          stateRequest('finish', {
            handle,
            responseStatus: 200,
            tokenIssued: true,
            responseError: null,
          })
        ),
        harness.env
      ),
      invoke(harness.state, JSON.stringify(stateRequest('abort', { handle })), harness.env),
    ]);

    expect(aborted).toMatchObject({ code: 0, stderr: '' });
    expect(JSON.parse(aborted.stdout)).toMatchObject({ operation: 'abort', ok: true });
    expect([0, 1]).toContain(finished.code);
    const repeatedAbort = await invoke(
      harness.state,
      JSON.stringify(stateRequest('abort', { handle })),
      harness.env
    );
    expect(repeatedAbort).toMatchObject({ code: 0, stderr: '' });
    await expect(
      retiredTombstones(path.join(harness.root, 'phase2-client-credentials-state'))
    ).resolves.toHaveLength(1);
  });

  it('releases a killed finish lock so abort can reclaim the original handle', async () => {
    const harness = await createHarness();
    const stateEnv = {
      ASTER_PHASE2_CONTROL_SOCKET: harness.socket,
      LC_ALL: 'C',
      PATH: '/usr/bin:/bin',
    };
    const begun = await invoke(harness.state, JSON.stringify(stateRequest('begin')), stateEnv);
    const { handle } = JSON.parse(begun.stdout) as { handle: string };
    const handleFile = path.join(harness.root, 'phase2-client-credentials-state', `${handle}.json`);
    await writeFile(harness.usage, 'verified', { mode: 0o600 });
    await writeFile(harness.hang, 'hang', { mode: 0o600 });
    const child = spawn(harness.state, [], {
      detached: true,
      env: stateEnv,
      stdio: ['pipe', 'ignore', 'ignore'],
    });
    const closed = new Promise<NodeJS.Signals | undefined>((resolve, reject) => {
      child.once('error', reject);
      child.once('close', (_code, signal) => {
        resolve(signal ?? undefined);
      });
    });
    child.stdin.end(
      JSON.stringify(
        stateRequest('finish', {
          handle,
          responseStatus: 200,
          tokenIssued: true,
          responseError: null,
        })
      )
    );
    for (let attempt = 0; attempt < 200; attempt += 1) {
      try {
        await stat(harness.hangReached);
        break;
      } catch {
        if (attempt === 199) {
          throw new Error('finish did not acquire the handle lock');
        }
        await delay(10);
      }
    }
    const childPid = child.pid;
    if (childPid === undefined) {
      throw new Error('finish process did not start');
    }
    process.kill(-childPid, 'SIGKILL');
    await expect(closed).resolves.toBe('SIGKILL');
    const handleState = await stat(handleFile);
    expect(handleState.isFile()).toBe(true);
    expect(handleState.mode % 0o1000).toBe(0o600);

    const aborted = await invoke(
      harness.state,
      JSON.stringify(stateRequest('abort', { handle })),
      stateEnv
    );
    expect(aborted).toMatchObject({ code: 0, stderr: '' });
    await expect(retiredTombstones(path.dirname(handleFile))).resolves.toHaveLength(1);
  });

  it('rejects changed persisted state instead of accepting a prebuilt projection', async () => {
    const harness = await createHarness();
    const stateEnv = {
      ASTER_PHASE2_CONTROL_SOCKET: harness.socket,
      LC_ALL: 'C',
      PATH: '/usr/bin:/bin',
    };
    const begun = await invoke(harness.state, JSON.stringify(stateRequest('begin')), stateEnv);
    const { handle } = JSON.parse(begun.stdout) as { handle: string };
    await writeFile(harness.mutation, 'changed', { mode: 0o600 });
    await writeFile(harness.usage, 'advanced', { mode: 0o600 });

    const finished = await invoke(
      harness.state,
      JSON.stringify(
        stateRequest('finish', {
          handle,
          responseStatus: 200,
          tokenIssued: true,
          responseError: null,
        })
      ),
      stateEnv
    );
    expect(finished.code).not.toBe(0);
    expect(finished.stdout).toBe('');
    expect(finished.stderr).toBe('Phase 2 client credentials state driver failed.\n');
    await expect(
      stat(path.join(harness.root, 'phase2-client-credentials-state', `${handle}.json`))
    ).rejects.toThrow();
    await expect(
      retiredTombstones(path.join(harness.root, 'phase2-client-credentials-state'))
    ).resolves.toHaveLength(1);
  });

  it('cross-validates candidate finish outcomes from responseError and DB authority', async () => {
    const harness = await createHarness();
    const stateEnv = {
      ASTER_PHASE2_CONTROL_SOCKET: harness.socket,
      LC_ALL: 'C',
      PATH: '/usr/bin:/bin',
    };
    const cases = [
      {
        name: 'success',
        scenarioId: 'client-credentials.basic-explicit-resource',
        dbDecision: 'authorized',
        status: 200,
        tokenIssued: true,
        responseError: null,
        expectedDecision: 'authorized',
      },
      {
        name: 'unknown client',
        scenarioId: 'client-credentials.unknown-client-basic',
        dbDecision: 'unauthorized-client',
        status: 400,
        tokenIssued: false,
        responseError: 'invalid_client',
        expectedDecision: 'unauthorized-client',
      },
      {
        name: 'wrong secret',
        scenarioId: 'client-credentials.wrong-secret-basic',
        dbDecision: 'authorized',
        status: 401,
        tokenIssued: false,
        responseError: 'invalid_client',
        expectedDecision: 'unauthorized-client',
      },
      {
        name: 'missing target',
        scenarioId: 'client-credentials.missing-target',
        dbDecision: 'invalid-target',
        status: 400,
        tokenIssued: false,
        responseError: 'invalid_target',
        expectedDecision: 'invalid-target',
      },
      {
        name: 'duplicate form target',
        scenarioId: 'client-credentials.duplicate-resource',
        dbDecision: 'authorized',
        status: 400,
        tokenIssued: false,
        responseError: 'invalid_target',
        expectedDecision: 'invalid-target',
      },
      {
        name: 'unassociated organization',
        scenarioId: 'client-credentials.unassociated-organization',
        dbDecision: 'access-denied',
        status: 403,
        tokenIssued: false,
        responseError: 'access_denied',
        expectedDecision: 'access-denied',
      },
      {
        name: 'mixed proof',
        scenarioId: 'client-credentials.mixed-authentication',
        dbDecision: 'authorized',
        status: 400,
        tokenIssued: false,
        responseError: 'invalid_request',
        expectedDecision: 'invalid-request',
      },
    ] as const;

    for (const testCase of cases) {
      await Promise.all([
        rm(harness.usage, { force: true }),
        writeFile(harness.decision, `${testCase.dbDecision}\n`, { mode: 0o600 }),
      ]);
      const begun = await invoke(
        harness.state,
        JSON.stringify(stateRequest('begin', { scenarioId: testCase.scenarioId })),
        stateEnv
      );
      expect(begun).toMatchObject({ code: 0, stderr: '' });
      const { handle } = JSON.parse(begun.stdout) as { handle: string };
      if (testCase.tokenIssued) {
        await writeFile(harness.usage, 'advanced', { mode: 0o600 });
      }
      const finished = await invoke(
        harness.state,
        JSON.stringify(
          stateRequest('finish', {
            scenarioId: testCase.scenarioId,
            handle,
            responseStatus: testCase.status,
            tokenIssued: testCase.tokenIssued,
            responseError: testCase.responseError,
          })
        ),
        stateEnv
      );
      expect(finished).toMatchObject({ code: 0, stderr: '' });
      expect(JSON.parse(finished.stdout)).toMatchObject({
        authority: { decision: testCase.expectedDecision },
      });
    }
  });

  it('executes the Oracle success path with Oracle topology and unchanged DB key metadata', async () => {
    const harness = await createHarness('oracle');
    const stateEnv = {
      ASTER_PHASE2_CONTROL_SOCKET: harness.socket,
      LC_ALL: 'C',
      PATH: '/usr/bin:/bin',
    };
    await writeFile(harness.decision, 'authorized\n', { mode: 0o600 });
    const begun = await invoke(
      harness.state,
      JSON.stringify(stateRequest('begin', {}, 'oracle')),
      stateEnv
    );
    expect(begun).toMatchObject({ code: 0, stderr: '' });
    const { handle } = JSON.parse(begun.stdout) as { handle: string };
    const finished = await invoke(
      harness.state,
      JSON.stringify(
        stateRequest(
          'finish',
          {
            handle,
            responseStatus: 200,
            tokenIssued: true,
            responseError: null,
          },
          'oracle'
        )
      ),
      stateEnv
    );
    expect(finished).toMatchObject({ code: 0, stderr: '' });
    expect(JSON.parse(finished.stdout)).toMatchObject({
      authority: { decision: 'authorized' },
      signingUse: { generalKeyUse: 'verified', oidcIdTokenKeyUse: 'unchanged' },
      attestation: {
        primary: { service: 'oracle-primary-core' },
        foreign: { service: 'oracle-foreign-core' },
      },
    });
    expect(await readFile(harness.calls, 'utf8')).toContain('localhost:3311/oidc/jwks');
  });

  it('rejects a newline-suffixed Oracle JWKS kid without making abort depend on JWKS', async () => {
    const harness = await createHarness('oracle');
    const stateEnv = {
      ASTER_PHASE2_CONTROL_SOCKET: harness.socket,
      LC_ALL: 'C',
      PATH: '/usr/bin:/bin',
    };
    await writeFile(harness.decision, 'authorized\n', { mode: 0o600 });
    const begun = await invoke(
      harness.state,
      JSON.stringify(stateRequest('begin', {}, 'oracle')),
      stateEnv
    );
    expect(begun).toMatchObject({ code: 0, stderr: '' });
    const { handle } = JSON.parse(begun.stdout) as { handle: string };
    await writeFile(harness.malformedJwks, 'malformed\n', { mode: 0o600 });

    const finished = await invoke(
      harness.state,
      JSON.stringify(
        stateRequest(
          'finish',
          { handle, responseStatus: 200, tokenIssued: true, responseError: null },
          'oracle'
        )
      ),
      stateEnv
    );
    expect(finished).toMatchObject({ code: 1, stdout: '' });
    expect(finished.stderr).toBe('Phase 2 client credentials state driver failed.\n');

    const aborted = await invoke(
      harness.state,
      JSON.stringify(stateRequest('abort', { handle }, 'oracle')),
      stateEnv
    );
    expect(aborted).toMatchObject({ code: 0, stderr: '' });
    const calls = await readFile(harness.calls, 'utf8');
    expect(calls.match(/localhost:3311\/oidc\/jwks/gu)).toHaveLength(1);
  });

  it.each([
    {
      name: 'candidate success without last_signed_at advance',
      tokenIssued: true,
      responseError: null,
      signingKeyId: 'general',
      advanceUsage: false,
    },
    {
      name: 'success with a different verified kid',
      tokenIssued: true,
      responseError: null,
      signingKeyId: 'different-key',
      advanceUsage: true,
    },
    {
      name: 'failure with a non-null signing kid',
      tokenIssued: false,
      responseError: 'invalid_client',
      signingKeyId: 'general',
      advanceUsage: false,
    },
  ] as const)(
    'rejects untruthful signing use: $name',
    async ({ tokenIssued, responseError, signingKeyId, advanceUsage }) => {
      const harness = await createHarness();
      const begun = await invoke(harness.state, JSON.stringify(stateRequest('begin')), harness.env);
      expect(begun).toMatchObject({ code: 0, stderr: '' });
      const { handle } = JSON.parse(begun.stdout) as { handle: string };
      if (advanceUsage) {
        await writeFile(harness.usage, 'advanced', { mode: 0o600 });
      }
      const finished = await invoke(
        harness.state,
        JSON.stringify(
          stateRequest('finish', {
            handle,
            responseStatus: tokenIssued ? 200 : 401,
            tokenIssued,
            responseError,
            signingKeyId,
          })
        ),
        harness.env
      );
      expect(finished.code).not.toBe(0);
      expect(finished.stdout).toBe('');
      expect(finished.stderr).toBe('Phase 2 client credentials state driver failed.\n');
    }
  );

  it.each([
    ['invalid_client versus invalid-target DB', 'invalid-target', 400, 'invalid_client'],
    ['invalid_target versus access-denied DB', 'access-denied', 400, 'invalid_target'],
    ['access_denied versus authorized DB', 'authorized', 403, 'access_denied'],
    ['invalid_request versus invalid-target DB', 'invalid-target', 400, 'invalid_request'],
  ] as const)(
    'rejects finish mismatch: %s',
    async (_name, databaseDecision, responseStatus, responseError) => {
      const harness = await createHarness();
      const stateEnv = {
        ASTER_PHASE2_CONTROL_SOCKET: harness.socket,
        LC_ALL: 'C',
        PATH: '/usr/bin:/bin',
      };
      await writeFile(harness.decision, `${databaseDecision}\n`, { mode: 0o600 });
      const begun = await invoke(harness.state, JSON.stringify(stateRequest('begin')), stateEnv);
      const { handle } = JSON.parse(begun.stdout) as { handle: string };
      const finished = await invoke(
        harness.state,
        JSON.stringify(
          stateRequest('finish', {
            handle,
            responseStatus,
            tokenIssued: false,
            responseError,
          })
        ),
        stateEnv
      );
      expect(finished.code).not.toBe(0);
      expect(finished.stdout).toBe('');
      expect(finished.stderr).toBe('Phase 2 client credentials state driver failed.\n');
    }
  );

  it.each([
    ['unknown field', JSON.stringify({ ...stateRequest('begin'), unexpected: true })],
    [
      'duplicate field',
      JSON.stringify(stateRequest('begin')).replace(
        '{"schemaVersion":1,',
        '{"schemaVersion":1,"schemaVersion":1,'
      ),
    ],
    [
      'generic operation with device scenario',
      JSON.stringify(stateRequest('begin', { scenarioId: 'device-verification.expired-code' })),
    ],
    ['device operation with legacy scenario', JSON.stringify(stateRequest('device-begin'))],
    [
      'wrong device transition action',
      JSON.stringify(
        stateRequest('device-transition', {
          scenarioId: 'device-token.session-bound-expiry',
          handle: 'a'.repeat(32),
          action: 'expire',
        })
      ),
    ],
    [
      'default-resource operation with wrong scenario',
      JSON.stringify(
        stateRequest('set-default-resource', {
          scenarioId: 'client-credentials.basic-explicit-resource',
          enabled: true,
        })
      ),
    ],
  ])('rejects a malicious %s before invoking Docker, jq, or curl', async (_name, input) => {
    const harness = await createHarness();
    const result = await invoke(harness.state, input, {
      ASTER_PHASE2_CONTROL_SOCKET: harness.socket,
      LC_ALL: 'C',
      PATH: '/usr/bin:/bin',
    });

    expect(result.code).not.toBe(0);
    expect(result.stdout).toBe('');
    expect(result.stderr).toBe('Phase 2 client credentials state driver failed.\n');
    await expect(readFile(harness.calls, 'utf8')).rejects.toThrow();
  });

  it.each([
    [
      'unknown field',
      JSON.stringify({
        ...invariantRequest('client-credentials.cross-tenant-authority-rejected'),
        unexpected: true,
      }),
    ],
    [
      'duplicate field',
      JSON.stringify(
        invariantRequest('client-credentials.cross-tenant-authority-rejected')
      ).replace('{"schemaVersion":1,', '{"schemaVersion":1,"schemaVersion":1,'),
    ],
  ])('rejects an invariant request with an %s before tool invocation', async (_name, input) => {
    const harness = await createHarness();
    const result = await invoke(harness.invariant, input, harness.env);

    expect(result.code).not.toBe(0);
    expect(result.stdout).toBe('');
    expect(result.stderr).toBe('Phase 2 client credentials invariant driver failed.\n');
    await expect(readFile(harness.calls, 'utf8')).rejects.toThrow();
  });

  it.each([
    [
      'device extra field',
      JSON.stringify({
        ...deviceInvariantRequest('device-authorization.forced-rls-isolation', 'probe'),
        unexpected: true,
      }),
    ],
    [
      'device duplicate field',
      JSON.stringify(
        deviceInvariantRequest('device-authorization.forced-rls-isolation', 'probe')
      ).replace('{"schemaVersion":1,', '{"schemaVersion":1,"schemaVersion":1,'),
    ],
    [
      'device wrong operation',
      JSON.stringify(
        deviceInvariantRequest('device-authorization.credentials-digest-only', 'arm', {
          deviceCode: 'private-device-code',
          userCode: 'ABCD-EFGH',
          xsrf: 'private-xsrf',
        })
      ),
    ],
    [
      'device private key missing',
      JSON.stringify(
        deviceInvariantRequest('device-authorization.credentials-digest-only', 'probe', {
          deviceCode: 'private-device-code',
          userCode: 'ABCD-EFGH',
        })
      ),
    ],
    [
      'device private key extra',
      JSON.stringify(
        deviceInvariantRequest('device-authorization.credentials-digest-only', 'probe', {
          deviceCode: 'private-device-code',
          userCode: 'ABCD-EFGH',
          xsrf: 'private-xsrf',
          password: 'private-password',
        })
      ),
    ],
    [
      'device invalid handle',
      JSON.stringify(
        deviceInvariantRequest(
          'device-authorization.transition-failure-rolls-back',
          'restore',
          {},
          { failureStatus: 500, tokenPublished: false },
          '../wrong'
        )
      ),
    ],
  ])('rejects a hostile %s before tool invocation', async (_name, input) => {
    const harness = await createHarness();
    const result = await invoke(harness.invariant, input, harness.env);

    expect(result).toEqual({
      code: 1,
      stdout: '',
      stderr: 'Phase 2 client credentials invariant driver failed.\n',
    });
    await expect(readFile(harness.calls, 'utf8')).rejects.toThrow();
  });

  it('proves digest-only state from a real code-bound row without putting clear codes in argv', async () => {
    const harness = await createHarness();
    const deviceCode = 'private-device-code-0123456789';
    const userCode = 'BCDF-GHJK';
    const xsrf = 'private-xsrf-0123456789';
    const result = await invoke(
      harness.invariant,
      JSON.stringify(
        deviceInvariantRequest('device-authorization.credentials-digest-only', 'probe', {
          deviceCode,
          userCode,
          xsrf,
        })
      ),
      harness.env
    );

    if (result.code !== 0 || result.stderr !== '') {
      throw new Error(
        JSON.stringify({
          result,
          calls: await readFile(harness.calls, 'utf8').catch(() => ''),
          sql: await readFile(harness.sql, 'utf8').catch(() => ''),
        })
      );
    }
    expect(JSON.parse(result.stdout)).toMatchObject({
      invariantId: 'device-authorization.credentials-digest-only',
      projection: {
        invariant: 'credentials-digest-only',
        schemaClearColumns: 'absent',
        row: { deviceDigestBytes: 32, userDigestBytes: 32, clearMaterial: 'absent' },
      },
    });
    const calls = await readFile(harness.calls, 'utf8');
    const sql = await readFile(harness.sql, 'utf8');
    const copyInvocation = calls.split('\n').find((line) => line.includes('phase2_private_codes'));
    expect(copyInvocation?.match(/--command=/gu)).toHaveLength(3);
    expect(copyInvocation).toContain('COPY');
    expect(copyInvocation).toContain('phase2_private_codes');
    expect(copyInvocation).toContain('client_id\\ text');
    expect(copyInvocation).not.toContain('--set=client_id');
    for (const secret of [deviceCode, userCode, xsrf]) {
      expect(calls).not.toContain(secret);
      expect(calls).not.toContain(Buffer.from(secret).toString('base64'));
      expect(sql).not.toContain(secret);
      expect(sql).not.toContain(Buffer.from(secret).toString('base64'));
      expect(result.stdout).not.toContain(secret);
      expect(result.stderr).not.toContain(secret);
    }
  });

  it('rejects a normalized clear user code in the initial device row', async () => {
    const harness = await createHarness();
    await writeFile(harness.normalizedInitialLeak, 'present', { mode: 0o600 });
    const result = await invoke(
      harness.invariant,
      JSON.stringify(
        deviceInvariantRequest('device-authorization.credentials-digest-only', 'probe', {
          deviceCode: 'private-device-code-normalized-row',
          userCode: 'BCDF-GHJK',
          xsrf: 'private-xsrf-normalized-row',
        })
      ),
      harness.env
    );
    expect(result).toEqual({
      code: 41,
      stdout: '',
      stderr: 'Phase 2 client credentials invariant driver failed (device-1-row-facts).\n',
    });
  });

  it('arms, restores, and finishes the device transition rollback through one claimed handle', async () => {
    const harness = await createHarness();
    await writeFile(harness.deviceStatus, 'approved', { mode: 0o600 });
    const privateValues = {
      deviceCode: 'private-device-code-rollback',
      userCode: 'BCDF-GHJK',
      xsrf: 'private-xsrf-rollback',
    };
    const arm = await invoke(
      harness.invariant,
      JSON.stringify(
        deviceInvariantRequest('device-authorization.transition-failure-rolls-back', 'arm', {
          deviceCode: privateValues.deviceCode,
        })
      ),
      harness.env
    );
    if (arm.code !== 0 || arm.stderr !== '') {
      throw new Error(
        JSON.stringify({
          arm,
          calls: await readFile(harness.calls, 'utf8').catch(() => ''),
          sql: await readFile(harness.sql, 'utf8').catch(() => ''),
        })
      );
    }
    const { handle } = JSON.parse(arm.stdout) as { handle: string };
    expect(handle).toMatch(/^[0-9a-f]{32}$/u);
    const handleRoot = path.join(harness.root, 'phase2-device-invariants');
    const handleState = await stat(path.join(handleRoot, handle));
    expect(handleState.mode % 0o1000).toBe(0o600);

    const restore = await invoke(
      harness.invariant,
      JSON.stringify(
        deviceInvariantRequest(
          'device-authorization.transition-failure-rolls-back',
          'restore',
          {},
          { failureStatus: 500, tokenPublished: false },
          handle
        )
      ),
      harness.env
    );
    if (restore.code !== 0 || restore.stderr !== '') {
      throw new Error(
        JSON.stringify({
          restore,
          calls: await readFile(harness.calls, 'utf8').catch(() => ''),
          sql: await readFile(harness.sql, 'utf8').catch(() => ''),
        })
      );
    }
    expect(JSON.parse(restore.stdout)).toMatchObject({ operation: 'restore', ok: true });

    await writeFile(harness.deviceStatus, 'consumed', { mode: 0o600 });
    const finish = await invoke(
      harness.invariant,
      JSON.stringify(
        deviceInvariantRequest(
          'device-authorization.transition-failure-rolls-back',
          'finish',
          {},
          { retryStatus: 200 },
          handle
        )
      ),
      harness.env
    );
    if (finish.code !== 0 || finish.stderr !== '') {
      throw new Error(
        JSON.stringify({
          finish,
          calls: await readFile(harness.calls, 'utf8').catch(() => ''),
          sql: await readFile(harness.sql, 'utf8').catch(() => ''),
        })
      );
    }
    expect(JSON.parse(finish.stdout)).toMatchObject({
      invariantId: 'device-authorization.transition-failure-rolls-back',
      projection: {
        invariant: 'transition-failure-rolls-back',
        injectedFailure: 'observed',
        retry: 'issued',
      },
    });
    await expect(stat(path.join(handleRoot, handle))).rejects.toThrow();
    const rollbackTombstones = await retiredTombstones(handleRoot);
    expect(rollbackTombstones.length).toBe(1);
  });

  it('seeds sixty-five expired rows and proves one authorization deletes exactly sixty-four', async () => {
    const harness = await createHarness();
    const arm = await invoke(
      harness.invariant,
      JSON.stringify(deviceInvariantRequest('device-authorization.expired-cleanup-bounded', 'arm')),
      harness.env
    );
    expect(arm).toMatchObject({ code: 0, stderr: '' });
    const { handle } = JSON.parse(arm.stdout) as { handle: string };
    const finish = await invoke(
      harness.invariant,
      JSON.stringify(
        deviceInvariantRequest(
          'device-authorization.expired-cleanup-bounded',
          'finish',
          {
            deviceCode: 'private-device-code-cleanup',
            userCode: 'BCDF-GHJK',
            xsrf: 'private-xsrf-cleanup',
          },
          { authorizationStatus: 200 },
          handle
        )
      ),
      harness.env
    );
    expect(finish).toMatchObject({ code: 0, stderr: '' });
    expect(JSON.parse(finish.stdout)).toMatchObject({
      projection: {
        invariant: 'expired-cleanup-bounded',
        cleanup: {
          seededExpired: 65,
          deletedExpired: 64,
          remainingExpired: 1,
          sentinel: 'preserved',
          foreignTenant: 'unchanged',
          newAuthorization: 'published',
        },
      },
    });
    const handleRoot = path.join(harness.root, 'phase2-device-invariants');
    await expect(stat(path.join(handleRoot, handle))).rejects.toThrow();
    const cleanupTombstones = await retiredTombstones(handleRoot);
    expect(cleanupTombstones.length).toBe(1);
    const calls = await readFile(harness.calls, 'utf8');
    expect(calls).toContain('phase2_private_codes');
    expect(calls).toContain('phase2_private_code');
    expect(calls.match(/prefix\\ text/gu)).toHaveLength(2);
    expect(
      calls
        .split('\n')
        .filter((line) => line.includes('phase2_private_code'))
        .every((line) => !line.includes('--set=prefix'))
    ).toBe(true);
  });

  it('proves forced RLS with live catalog, ACL, and bound-role SQL observations', async () => {
    const harness = await createHarness();
    const result = await invoke(
      harness.invariant,
      JSON.stringify(deviceInvariantRequest('device-authorization.forced-rls-isolation', 'probe')),
      harness.env
    );
    if (result.code !== 0 || result.stderr !== '') {
      throw new Error(
        JSON.stringify({
          result,
          calls: await readFile(harness.calls, 'utf8').catch(() => ''),
          sql: await readFile(harness.sql, 'utf8').catch(() => ''),
        })
      );
    }
    expect(JSON.parse(result.stdout)).toMatchObject({
      projection: {
        invariant: 'forced-rls-isolation',
        catalog: { rowSecurity: true, forcedRowSecurity: true },
        requestRole: { primaryVisible: true, foreignVisible: false, foreignUpdate: 'rejected' },
      },
    });
    const sql = await readFile(harness.sql, 'utf8');
    expect(sql).toContain("relname='device_authorizations'");
    expect(sql).toContain('activate_tenant_binding');
    expect(sql).toContain('SET ROLE aster_admin');
    expect(sql).toContain('SET ROLE aster_worker');
  });

  it('cross-validates foreign invalid_grant with foreign absence and unchanged primary pending state', async () => {
    const harness = await createHarness();
    const privateValues = {
      deviceCode: 'private-device-code-cross',
      userCode: 'BCDF-GHJK',
      xsrf: 'private-xsrf-cross',
    };
    const armed = await invoke(
      harness.invariant,
      JSON.stringify(
        deviceInvariantRequest(
          'device-authorization.cross-tenant-lookup-rejected',
          'arm',
          privateValues
        )
      ),
      harness.env
    );
    if (armed.code !== 0 || armed.stderr !== '') {
      throw new Error(
        JSON.stringify({
          armed,
          calls: await readFile(harness.calls, 'utf8').catch(() => ''),
          sql: await readFile(harness.sql, 'utf8').catch(() => ''),
        })
      );
    }
    expect(armed).toMatchObject({ code: 0, stderr: '' });
    const { handle } = JSON.parse(armed.stdout) as { handle: string };
    const result = await invoke(
      harness.invariant,
      JSON.stringify(
        deviceInvariantRequest(
          'device-authorization.cross-tenant-lookup-rejected',
          'finish',
          {},
          { foreignStatus: 400, foreignError: 'invalid_grant' },
          handle
        )
      ),
      harness.env
    );
    expect(result).toMatchObject({ code: 0, stderr: '' });
    expect(JSON.parse(result.stdout)).toMatchObject({
      projection: {
        invariant: 'cross-tenant-lookup-rejected',
        foreignPoll: { status: 400, error: 'invalid_grant' },
        foreignRow: 'not-visible',
        primaryState: 'unchanged',
      },
    });
  });

  it('binds replay revocation to the pre-issue grant and proves every retained authority is absent', async () => {
    const harness = await createHarness();
    await writeFile(harness.deviceStatus, 'consumed', { mode: 0o600 });
    const privateValues = {
      deviceCode: 'private-device-code-replay',
      userCode: 'BCDF-GHJK',
      xsrf: 'private-xsrf-replay',
    };
    const arm = await invoke(
      harness.invariant,
      JSON.stringify(
        deviceInvariantRequest(
          'device-token.consumed-replay-revokes-grant',
          'arm',
          { deviceCode: privateValues.deviceCode },
          { issuedStatus: 200 }
        )
      ),
      harness.env
    );
    expect(arm).toMatchObject({ code: 0, stderr: '' });
    const { handle } = JSON.parse(arm.stdout) as { handle: string };
    const finish = await invoke(
      harness.invariant,
      JSON.stringify(
        deviceInvariantRequest(
          'device-token.consumed-replay-revokes-grant',
          'finish',
          {},
          {
            replayStatus: 400,
            replayError: 'invalid_grant',
            accessActive: false,
            refreshActive: false,
            refreshStatus: 400,
            refreshError: 'invalid_grant',
          },
          handle
        )
      ),
      harness.env
    );
    expect(finish).toMatchObject({ code: 0, stderr: '' });
    expect(JSON.parse(finish.stdout)).toMatchObject({
      projection: {
        invariant: 'consumed-replay-revokes-grant',
        authority: {
          device: 'removed',
          grant: 'revoked',
          family: 'inactive',
          access: 'inactive',
          refresh: 'inactive',
        },
      },
    });
  });

  it('scans all callback secrets against closed schema and persisted device authority', async () => {
    const harness = await createHarness();
    const privateValues = {
      deviceCode: 'private-device-code-evidence',
      userCode: 'BCDF-GHJK',
      xsrf: 'private-xsrf-evidence',
      password: 'private-password-evidence',
      clientSecrets: ['private-client-a', 'private-client-b', 'private-client-c'],
      tokens: ['private-access-value', 'private-refresh-value', 'private-id-value'],
    };
    await writeFile(harness.deviceStatus, 'consumed', { mode: 0o600 });
    const result = await invoke(
      harness.invariant,
      JSON.stringify(
        deviceInvariantRequest('device-evidence.secret-material-absent', 'probe', privateValues, {
          issuedStatus: 200,
        })
      ),
      harness.env
    );
    expect(result).toMatchObject({ code: 0, stderr: '' });
    expect(JSON.parse(result.stdout)).toMatchObject({
      projection: {
        invariant: 'secret-material-absent',
        database: 'clear-material-absent',
        schema: 'closed',
        evidence: 'sanitized',
        driverOutput: 'sanitized',
      },
    });
    const calls = await readFile(harness.calls, 'utf8');
    const sql = await readFile(harness.sql, 'utf8');
    for (const secret of [
      privateValues.deviceCode,
      privateValues.userCode,
      privateValues.xsrf,
      privateValues.password,
      ...privateValues.clientSecrets,
      ...privateValues.tokens,
    ]) {
      expect(calls).not.toContain(secret);
      for (const variant of [
        secret,
        Buffer.from(secret).toString('hex'),
        Buffer.from(secret).toString('base64'),
        encodeURIComponent(secret),
        new URLSearchParams([['value', secret]]).toString().slice('value='.length),
      ]) {
        expect(calls).not.toContain(variant);
        expect(sql).not.toContain(variant);
      }
      expect(result.stdout).not.toContain(secret);
      expect(result.stderr).not.toContain(secret);
    }
  });

  it('rejects a normalized clear user code planted in final-state material', async () => {
    const harness = await createHarness();
    await writeFile(harness.deviceStatus, 'consumed', { mode: 0o600 });
    await writeFile(harness.secretLeak, 'present', { mode: 0o600 });
    const finish = await invoke(
      harness.invariant,
      JSON.stringify(
        deviceInvariantRequest(
          'device-evidence.secret-material-absent',
          'probe',
          {
            deviceCode: 'private-device-code-late-write',
            userCode: 'BCDF-GHJK',
            xsrf: 'private-xsrf-late-write',
            password: 'private-password-late-write',
            clientSecrets: ['private-client-late-write'],
            tokens: ['private-token-late-write'],
          },
          { issuedStatus: 200 }
        )
      ),
      harness.env
    );
    expect(finish).toEqual({
      code: 1,
      stdout: '',
      stderr: 'Phase 2 client credentials invariant driver failed.\n',
    });
  });

  it('executes all five invariant probes, restores faults, and keeps secrets out of argv', async () => {
    const harness = await createHarness();
    const expected = new Map<string, string>([
      ['client-credentials.cross-tenant-authority-rejected', 'cross-tenant-authority-rejected'],
      ['client-credentials.request-role-write-rejected', 'request-role-write-rejected'],
      ['client-credentials.signing-failure-rolls-back', 'signing-failure-rolls-back'],
      ['client-credentials.user-authority-unchanged', 'user-authority-unchanged'],
      ['logout-session.verification-storage-closed', 'verification-storage-closed'],
    ]);

    for (const [id, projectionName] of expected) {
      await Promise.all([
        rm(harness.usage, { force: true }),
        rm(harness.fault, { force: true }),
        rm(harness.flipCount, { force: true }),
      ]);
      const result = await invoke(
        harness.invariant,
        JSON.stringify(invariantRequest(id)),
        harness.env
      );
      expect(result).toMatchObject({ code: 0, stderr: '' });
      expect(result.stdout).not.toContain('\n');
      const terminal = JSON.parse(result.stdout) as {
        invariantId: string;
        projection: { invariant: string };
      };
      expect(terminal.invariantId).toBe(id);
      expect(terminal.projection.invariant).toBe(projectionName);
      expect(result.stdout).not.toContain(basicSecret);
      expect(result.stdout).not.toContain(postSecret);
      expect(result.stdout).not.toContain(fixture.allocationId);
      expect(result.stdout).not.toContain(candidateTarget.coreUrl);
      await expect(stat(harness.fault)).rejects.toThrow();
    }

    const [calls, sql] = await Promise.all([
      readFile(harness.calls, 'utf8'),
      readFile(harness.sql, 'utf8'),
    ]);
    expect(calls).not.toContain(basicSecret);
    expect(calls).not.toContain(postSecret);
    expect(calls).not.toContain('opaque-test-token');
    expect(calls).toContain('curl:');
    expect(calls).toContain('--config');
    expect(sql).toContain('SET ROLE aster_request');
    expect(sql.match(/set_byte\(ciphertext/gu)).toHaveLength(2);
  });

  it('fails closed when a probe is a no-op or signing restoration fails', async () => {
    const harness = await createHarness();
    await writeFile(harness.acceptRole, 'allow', { mode: 0o600 });
    const acceptedRole = await invoke(
      harness.invariant,
      JSON.stringify(invariantRequest('client-credentials.request-role-write-rejected')),
      harness.env
    );
    expect(acceptedRole.code).not.toBe(0);
    expect(acceptedRole.stderr).toBe('Phase 2 client credentials invariant driver failed.\n');
    await rm(harness.acceptRole, { force: true });

    await writeFile(harness.noOpFault, 'noop', { mode: 0o600 });
    const noOpFault = await invoke(
      harness.invariant,
      JSON.stringify(invariantRequest('client-credentials.signing-failure-rolls-back')),
      harness.env
    );
    expect(noOpFault.code).not.toBe(0);
    expect(noOpFault.stderr).toBe('Phase 2 client credentials invariant driver failed.\n');
    await rm(harness.noOpFault, { force: true });
    await rm(harness.flipCount, { force: true });

    await writeFile(harness.restoreFailure, 'fail', { mode: 0o600 });
    const failedRestore = await invoke(
      harness.invariant,
      JSON.stringify(invariantRequest('client-credentials.signing-failure-rolls-back')),
      harness.env
    );
    expect(failedRestore.code).not.toBe(0);
    expect(failedRestore.stdout).toBe('');
    expect(failedRestore.stderr).toBe('Phase 2 client credentials invariant driver failed.\n');
  });
});

/* eslint-enable max-lines, no-await-in-loop, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
