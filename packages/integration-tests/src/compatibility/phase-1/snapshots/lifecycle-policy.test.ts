import { execFile } from 'node:child_process';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

const repositoryRoot = path.resolve(process.cwd(), '../..');
const composePath = path.join(repositoryRoot, 'docker-compose.phase1-compatibility.yml');
const runnerPath = path.join(repositoryRoot, '.scripts/compatibility/run-phase1.sh');
const executeFile = promisify(execFile);
const temporaryRoots = new Set<string>();

const stackNames = ['oracle-primary', 'oracle-foreign', 'candidate-primary', 'candidate-foreign'];
const phase0StackNames = ['oracle-phase0', 'candidate-phase0'];
const isolatedStackNames = [...stackNames, ...phase0StackNames];
const hostBoundaryNetworks = [
  'candidate-connector-boundary',
  'candidate-saml-boundary',
  'candidate-script-boundary',
];
const baseServices = stackNames.flatMap((stack) => [
  `${stack}-postgres`,
  `${stack}-redis`,
  `${stack}-core`,
]);
const phase0Services = phase0StackNames.flatMap((stack) => [
  `${stack}-postgres`,
  `${stack}-redis`,
  `${stack}-core`,
]);

type LifecycleComposeDocument = {
  services: Record<string, Record<string, unknown>>;
  networks: Record<string, unknown>;
  volumes: Record<string, unknown>;
};

const assertInternalNetworkPolicy = (document: LifecycleComposeDocument): void => {
  const expectedNetworks = [...isolatedStackNames, ...hostBoundaryNetworks];

  expect(Object.keys(document.networks)).toEqual(expectedNetworks);
  for (const network of expectedNetworks) {
    expect(document.networks[network]).toEqual({ internal: true });
  }
};

afterEach(async () => {
  await Promise.all(
    [...temporaryRoots].map(async (root) => rm(root, { recursive: true, force: true }))
  );
  temporaryRoots.clear();
});

describe('Phase 1 lifecycle source policy', () => {
  it('defines four measured stacks, two disposable Phase 0 stacks, and three authority-free hosts', async () => {
    const document = JSON.parse(await readFile(composePath, 'utf8')) as LifecycleComposeDocument;

    expect(Object.keys(document.services)).toEqual([
      ...baseServices,
      ...phase0Services,
      'candidate-connector-host',
      'candidate-saml-host',
      'candidate-script-host',
    ]);
    assertInternalNetworkPolicy(document);
    expect(Object.keys(document.volumes)).toEqual(
      isolatedStackNames.flatMap((stack) => [`${stack}-postgres`, `${stack}-redis`])
    );

    for (const stack of isolatedStackNames) {
      const postgres = document.services[`${stack}-postgres`];
      const redis = document.services[`${stack}-redis`];
      const core = document.services[`${stack}-core`];
      expect(postgres?.networks).toEqual([stack]);
      expect(redis?.networks).toEqual([stack]);
      expect(core?.networks).toEqual(
        stack === 'candidate-primary' ? [stack, ...hostBoundaryNetworks] : [stack]
      );
      expect(postgres).not.toHaveProperty('ports');
      expect(redis).not.toHaveProperty('ports');
      expect(core).not.toHaveProperty('ports');
      expect(JSON.stringify(core)).toContain(`${stack.toUpperCase().replaceAll('-', '_')}_`);
    }

    for (const [index, host] of [
      document.services['candidate-connector-host'],
      document.services['candidate-saml-host'],
      document.services['candidate-script-host'],
    ].entries()) {
      expect(host?.profiles).toHaveLength(1);
      expect(host?.networks).toEqual([hostBoundaryNetworks[index]]);
      expect(host).not.toHaveProperty('ports');
      expect(host).not.toHaveProperty('volumes');
      expect(JSON.stringify(host)).not.toMatch(/DB_URL|REDIS_URL|COOKIE|SIGNING|SECRET_VAULT/iu);
    }
    expect(document.services['oracle-phase0-core']?.image).toBe(
      ['$', '{ASTER_PHASE1_ORACLE_IMAGE:?required}'].join('')
    );
    expect(document.services['candidate-phase0-core']?.image).toBe(
      ['$', '{ASTER_PHASE1_CANDIDATE_IMAGE:?required}'].join('')
    );
  });

  it('uses digest-injected images and delegates all loopback exposure to the runner', async () => {
    const source = await readFile(composePath, 'utf8');
    const document = JSON.parse(source) as { services: Record<string, Record<string, unknown>> };
    const ports = [...baseServices, ...phase0Services].flatMap((name) => {
      const value = document.services[name]?.ports;
      return Array.isArray(value) ? value : [];
    });

    expect(ports).toEqual([]);
    expect(source).not.toMatch(
      /\bbuild:|host-gateway|docker\.sock|network_mode:|privileged:|cap_add:/u
    );
    for (const service of Object.values(document.services)) {
      expect(service.image).toEqual(
        expect.stringMatching(/^\$\{ASTER_PHASE1_[A-Z0-9_]+(?:[:?]-?.*)?\}$/u)
      );
    }
  });

  it('pins lifecycle ordering, security gates, artifact closure, and reverse cleanup', async () => {
    const source = await readFile(runnerPath, 'utf8');

    expect(source.startsWith('#!/usr/bin/env bash\nset -euo pipefail\numask 077\n')).toBe(true);
    for (const required of [
      '/var/tmp/henry-build',
      'ASTER_PHASE1_BUILD_ROOT',
      'require_safe_build_root',
      '--prepare-mirror-image',
      '6852a7b8c8984c5c12b2061e8c51faa310a36412',
      'prepared-mirror.json',
      'verify-prepared-mirror',
      'CLOSED_NODE_ENV',
      'CLOSED_BUILD_ENV',
      'phase-1-differential.json',
      'phase-1-browser.json',
      'phase-1-candidate-invariants.json',
      'phase-1-conformance.json',
      'evidence-manifest.json',
      'harness-result.json',
      '--record-oracle',
      '--observation-controls',
      '--discovery-extra-control',
      '--candidate-invariant-controls',
      'run-phase1-conformance.sh',
      'ASTER_PHASE1_TOPOLOGY_ID',
      'ASTER_PHASE1_CONFORMANCE_ROOT',
      'ASTER_PHASE1_PHASE0_ORACLE_URL',
      'ASTER_PHASE1_PHASE0_ORACLE_ADMIN_URL',
      'ASTER_PHASE1_PHASE0_CANDIDATE_URL',
      'ASTER_PHASE1_PHASE0_CANDIDATE_ADMIN_URL',
      'ASTER_PHASE1_ORACLE_SNAPSHOT_PATH',
      'oracle-snapshots.json',
      'ASTER_PHASE1_ORACLE_PRIMARY_POSTGRES_CONTAINER_ID',
      'ASTER_PHASE1_ORACLE_FOREIGN_POSTGRES_CONTAINER_ID',
      'ASTER_PHASE1_CANDIDATE_PRIMARY_POSTGRES_CONTAINER_ID',
      'ASTER_PHASE1_CANDIDATE_FOREIGN_POSTGRES_CONTAINER_ID',
      'ASTER_PHASE1_ORACLE_DATA_COOKIE_KEY_SET_SHA256',
      'ASTER_PHASE1_CANDIDATE_FOREIGN_SIGNING_KEY_SET_SHA256',
      'key_set_sha256',
      'phase1-reference-state-driver.sh',
      'PLAYWRIGHT_BROWSERS_PATH',
      'TMPDIR',
      'XDG_RUNTIME_DIR',
      'canonical_image_id',
      'http_ready',
      'GIT_NO_REPLACE_OBJECTS',
      '--no-replace-objects',
      '/usr/bin/docker',
      '/usr/bin/setsid',
      '/usr/bin/socat',
      'LOOPBACK_PROXY_BINDINGS',
      'container_network_ipv4',
      'start_loopback_proxy',
      'TCP4-LISTEN:',
      'bind=127.0.0.1',
      'PROXY_PIDS',
      'PROXY_PGIDS',
      "'v22.23.2'",
      "'10.15.1'",
      'compose.env',
    ]) {
      expect(source).toContain(required);
    }
    expect(source.indexOf('phase-1-differential.json')).toBeLessThan(
      source.indexOf('evidence-manifest.json')
    );
    expect(source.indexOf('evidence-manifest.json')).toBeLessThan(
      source.indexOf('harness-result.json')
    );
    expect(source).not.toMatch(/docker compose logs|docker-compose logs|\blog[s]?\s*>/u);
    expect(source).not.toContain('/dev/shm');
    expect(source).not.toMatch(/export ASTER_PHASE1_.*(?:PASSWORD|KEK|COOKIE|SIGNING)/u);
    expect(source).toContain(['--image-digest "', '$', '{ORACLE_IMAGE_DIGEST}', '"'].join(''));
    for (const required of [
      'oracle-phase0-postgres oracle-phase0-redis oracle-phase0-core',
      'candidate-phase0-postgres candidate-phase0-redis candidate-phase0-core',
      'ORACLE_PHASE0 CANDIDATE_PHASE0',
      "ASTER_PHASE1_PHASE0_ORACLE_URL='http://localhost:3331'",
      "ASTER_PHASE1_PHASE0_ORACLE_ADMIN_URL='http://localhost:3431'",
      "ASTER_PHASE1_PHASE0_CANDIDATE_URL='http://localhost:3341'",
      "ASTER_PHASE1_PHASE0_CANDIDATE_ADMIN_URL='http://localhost:3441'",
    ]) {
      expect(source).toContain(required);
    }
    const publicEnvironment = source.slice(
      source.indexOf('PUBLIC_ENV=('),
      source.indexOf('\n)', source.indexOf('PUBLIC_ENV=('))
    );

    expect(publicEnvironment).not.toMatch(
      /PHASE0_(?:POSTGRES_PASSWORD|SECRET_VAULT_KEK|STATUS_API_KEY)/u
    );

    const nodeInvocationLines = source
      .split('\n')
      .filter(
        (line) =>
          line.includes(['"', '$', '{NODE_BIN}"'].join('')) &&
          !line.includes('NODE_BIN=') &&
          !line.includes('dirname --')
      );

    expect(nodeInvocationLines).not.toEqual([]);
    expect(
      nodeInvocationLines.every(
        (line) => line.includes('CLOSED_NODE_ENV') || line.includes('PUBLIC_ENV')
      )
    ).toBe(true);
    expect(source).toContain('capture_build_root_identity');
    expect(source).toContain('assert_build_root_identity');
    expect(source).toContain('owned_process_group_exists');
    expect(source).toContain('terminate_owned_process_group');
    const nodeRunPid = ['"', '$', '{NODE_RUN_PID}"'].join('');
    const nodeWait = source.indexOf(`wait ${nodeRunPid} || node_run_status=$?`);

    expect(nodeWait).toBeGreaterThan(0);
    expect(source.indexOf(`terminate_owned_process_group ${nodeRunPid}`, nodeWait)).toBeLessThan(
      source.indexOf("NODE_RUN_PID=''", nodeWait)
    );
  });

  it('pins a custom private build root to its original filesystem identity', async () => {
    const source = await readFile(runnerPath, 'utf8');
    const start = source.indexOf('require_safe_build_root()');
    const end = source.indexOf('\ntrusted_binary()', start);

    expect(start).toBeGreaterThan(0);
    expect(end).toBeGreaterThan(start);
    const root = await mkdtemp('/var/tmp/henry-build/phase1-build-root-test-');
    temporaryRoots.add(root);
    const buildRoot = path.join(root, 'custom-build-root');
    const replacedRoot = `${buildRoot}.replaced`;
    const scriptPath = path.join(root, 'verify-build-root.sh');
    const functions = source.slice(start, end);
    const harness = `#!/usr/bin/env bash
set -euo pipefail
fail() { exit 97; }
BUILD_ROOT=${JSON.stringify(buildRoot)}
BUILD_ROOT_DEVICE=''
BUILD_ROOT_INODE=''
${functions}
/usr/bin/mkdir -m 700 -- "\${BUILD_ROOT}"
capture_build_root_identity
assert_build_root_identity
/usr/bin/mv -- "\${BUILD_ROOT}" ${JSON.stringify(replacedRoot)}
/usr/bin/mkdir -m 700 -- "\${BUILD_ROOT}"
if (assert_build_root_identity); then
  exit 31
fi
`;
    await writeFile(scriptPath, harness, { mode: 0o700 });
    await chmod(scriptPath, 0o700);

    await expect(
      executeFile('/bin/bash', [scriptPath], { timeout: 10_000 })
    ).resolves.toMatchObject({ stderr: '' });
  });

  it('reaps an owned process group after its leader has already exited', async () => {
    const source = await readFile(runnerPath, 'utf8');
    const start = source.indexOf('owned_process_group_exists()');
    const end = source.indexOf('\ncleanup()', start);

    expect(start).toBeGreaterThan(0);
    expect(end).toBeGreaterThan(start);
    const root = await mkdtemp('/var/tmp/henry-build/phase1-owned-group-test-');
    temporaryRoots.add(root);
    const scriptPath = path.join(root, 'verify-owned-group.sh');
    const pidPath = path.join(root, 'pids');
    const functions = source.slice(start, end);
    const ownershipToken = 'a'.repeat(64);
    const harness = `#!/usr/bin/env bash
set -euo pipefail
PS_BIN=/usr/bin/ps
AWK_BIN=/usr/bin/awk
${functions}
/usr/bin/setsid /usr/bin/env -i PATH=/usr/bin:/bin ASTER_PHASE1_PROCESS_TOKEN=${ownershipToken} /bin/sh -c 'printf "%s %s\\n" "$$" "$(/usr/bin/ps -o pgid= -p $$ | tr -d "[:space:]")" > "$1"; trap "" HUP TERM; /usr/bin/sleep 300 &' sh ${JSON.stringify(pidPath)} &
launcher=$!
for ((attempt=0; attempt<200; attempt++)); do
  [[ -s ${JSON.stringify(pidPath)} ]] && break
  /usr/bin/sleep 0.01
done
read -r leader pgid < ${JSON.stringify(pidPath)}
wait "\${launcher}" || true
owned_process_group_exists "\${pgid}"
terminate_owned_process_group "\${leader}" "\${pgid}" ${ownershipToken}
! owned_process_group_exists "\${pgid}"
`;
    await writeFile(scriptPath, harness, { mode: 0o700 });
    await chmod(scriptPath, 0o700);

    await expect(
      executeFile('/bin/bash', [scriptPath], { timeout: 10_000 })
    ).resolves.toMatchObject({
      stderr: '',
    });
  });
});
