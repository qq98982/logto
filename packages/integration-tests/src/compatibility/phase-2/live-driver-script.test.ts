/* eslint-disable max-lines, no-await-in-loop, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- One private fake-engine harness exercises both shell protocols, lifecycle state, restoration, and secret argv containment. */
import { spawn } from 'node:child_process';
import { chmod, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
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
  tools: Readonly<{ docker: string; jq: string; curl: string }>
) => {
  const uid = process.getuid?.() ?? 0;
  const original = await readFile(sourcePath, 'utf8');
  const source = original
    .replaceAll('/usr/bin/docker', tools.docker)
    .replaceAll('/usr/bin/jq', tools.jq)
    .replaceAll('/usr/bin/curl', tools.curl)
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
  const primaryCoreService = `${kind}-primary-core`;
  const foreignCoreService = `${kind}-foreign-core`;
  const primaryPostgresService = `${kind}-primary-postgres`;
  const foreignPostgresService = `${kind}-foreign-postgres`;
  const fakeDocker = path.join(root, 'docker');
  const fakeJq = path.join(root, 'jq');
  const fakeCurl = path.join(root, 'curl');
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
  for argument in "$@"; do
    case "$argument" in
      --set=client_id=*) client_id="${'$'}{argument#--set=client_id=}" ;;
      --set=general_key_id=*) general_key_id="${'$'}{argument#--set=general_key_id=}" ;;
    esac
  done
  input="$(cat)"
  printf '%s\n-- invocation --\n' "$input" >>'${sql}'
  if [[ "$input" == *'SET ROLE aster_request'* ]]; then
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
  if [[ "$input" == *'WITH client_row AS'* && -f '${hang}' ]]; then
    : >'${hangReached}'
    /usr/bin/sleep 30
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
  await Promise.all([
    writeFile(fakeDocker, dockerScript, { mode: 0o700 }),
    writeFile(fakeJq, jqScript, { mode: 0o700 }),
    writeFile(fakeCurl, curlScript, { mode: 0o700 }),
  ]);
  await Promise.all([chmod(fakeDocker, 0o700), chmod(fakeJq, 0o700), chmod(fakeCurl, 0o700)]);
  const state = path.join(root, 'state-driver');
  const invariant = path.join(root, 'invariant-driver');
  await patchedDriver(stateDriver, state, { docker: fakeDocker, jq: fakeJq, curl: fakeCurl });
  await patchedDriver(invariantDriver, invariant, {
    docker: fakeDocker,
    jq: fakeJq,
    curl: fakeCurl,
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

const invariantRequest = (invariantId: string) => ({
  schemaVersion: 1,
  kind: 'phase2-client-credentials-candidate-invariant-request',
  invariantId,
  target: { primary: candidateTarget, foreign: candidateForeignTarget },
  fixture,
  credentials: { basic: basicSecret, post: postSecret },
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
    const calls = await readFile(harness.calls, 'utf8');
    expect(calls).toContain('--single-transaction');
    expect(calls).not.toContain('--filter publish=');
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
    expect(await readdir(path.join(harness.root, 'phase2-client-credentials-state'))).toEqual([]);
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
    expect(await readdir(path.join(harness.root, 'phase2-client-credentials-state'))).toEqual([]);
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
    await expect(readdir(path.dirname(handleFile))).resolves.toEqual([]);
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
    expect(await readdir(path.join(harness.root, 'phase2-client-credentials-state'))).toEqual([]);
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

  it('executes all four invariant probes, restores faults, and keeps secrets out of argv', async () => {
    const harness = await createHarness();
    const expected = new Map<string, string>([
      ['client-credentials.cross-tenant-authority-rejected', 'cross-tenant-authority-rejected'],
      ['client-credentials.request-role-write-rejected', 'request-role-write-rejected'],
      ['client-credentials.signing-failure-rolls-back', 'signing-failure-rolls-back'],
      ['client-credentials.user-authority-unchanged', 'user-authority-unchanged'],
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
