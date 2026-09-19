/* eslint-disable no-use-extend-native/no-use-extend-native -- Exact service, network, and volume authority comparisons use ES2023 non-mutating sorting. */
import { execFile } from 'node:child_process';
import { chmod, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { createServer, type Socket } from 'node:net';
import path from 'node:path';
import { promisify } from 'node:util';

const executeFile = promisify(execFile);

type ComposeService = Readonly<Record<string, unknown>>;
type ComposeDocument = Readonly<{
  services: Readonly<Record<string, ComposeService>>;
  networks: Readonly<Record<string, unknown>>;
  volumes: Readonly<Record<string, unknown>>;
}>;

const repositoryRoot = path.resolve(process.cwd(), '../..');
const topologyPath = path.join(
  repositoryRoot,
  'docker-compose.phase1-runtime-candidate-differential.yml'
);
const formalPath = path.join(repositoryRoot, 'docker-compose.phase1-compatibility.yml');
const candidatePath = path.join(repositoryRoot, 'docker-compose.phase1-aster-candidate.yml');
const runtimeRunnerPath = path.join(
  repositoryRoot,
  '.scripts/compatibility/run-phase1-runtime-candidate.sh'
);
const differentialWrapperPath = path.join(
  repositoryRoot,
  '.scripts/compatibility/test-runtime-candidate-differential.sh'
);

const readCompose = async (filePath: string): Promise<ComposeDocument> =>
  JSON.parse(await readFile(filePath, 'utf8')) as ComposeDocument;

const oracleServices = [
  'oracle-primary-postgres',
  'oracle-primary-redis',
  'oracle-primary-core',
  'oracle-foreign-postgres',
  'oracle-foreign-redis',
  'oracle-foreign-core',
  'oracle-phase0-postgres',
  'oracle-phase0-redis',
  'oracle-phase0-core',
] as const;
const measuredCandidateServices = [
  'candidate-primary-postgres',
  'candidate-primary-init',
  'candidate-primary-core',
  'candidate-foreign-postgres',
  'candidate-foreign-init',
  'candidate-foreign-core',
  'candidate-fixture-coordinator',
  'candidate-connector-host',
  'candidate-saml-host',
  'candidate-script-host',
] as const;
const phase0CandidateServices = [
  'candidate-phase0-postgres',
  'candidate-phase0-redis',
  'candidate-phase0-core',
] as const;

describe('runtime-candidate differential topology', () => {
  it('accepts only an owned socket in a private canonical directory', async () => {
    const source = await readFile(runtimeRunnerPath, 'utf8');
    const functionStart = source.indexOf('validate_engine_socket() {');
    const functionEnd = source.indexOf('\n}\n', functionStart) + 3;
    expect(functionStart).toBeGreaterThan(0);
    const script = `fail() { exit 1; }; ${source.slice(functionStart, functionEnd)}\nvalidate_engine_socket "$1"`;
    const root = await mkdtemp('/var/tmp/henry-build/phase1-engine-socket-');
    const socket = path.join(root, 'engine.sock');
    const alias = path.join(root, 'alias.sock');
    const server = createServer();
    try {
      await chmod(root, 0o700);
      await new Promise<void>((resolve) => {
        server.listen(socket, resolve);
      });
      await executeFile('/usr/bin/bash', ['-c', script, '--', socket]);
      await symlink(socket, alias);
      await expect(executeFile('/usr/bin/bash', ['-c', script, '--', alias])).rejects.toThrow();
      await chmod(root, 0o755);
      await expect(executeFile('/usr/bin/bash', ['-c', script, '--', socket])).rejects.toThrow();
      await expect(
        executeFile('/usr/bin/bash', ['-c', script, '--', 'tcp://127.0.0.1:2375'])
      ).rejects.toThrow();
    } finally {
      await new Promise<void>((resolve) => {
        server.close(() => {
          resolve();
        });
      });
      await rm(root, { recursive: true, force: true });
    }
  });

  it('routes only an explicit socket through closed Docker and Node environments', async () => {
    const source = await readFile(runtimeRunnerPath, 'utf8');
    expect(source).toContain(['ENGINE_SOCKET="', '$', '{ASTER_PHASE1_ENGINE_SOCKET-}"'].join(''));
    expect(source).toContain(
      ['DOCKER_HOST="unix://', '$', '{ENGINE_SOCKET}" "', '$', '{DOCKER_BIN}"'].join('')
    );
    expect(source).toContain(
      ['PUBLIC_ENV+=(ASTER_PHASE1_ENGINE_SOCKET="', '$', '{ENGINE_SOCKET}")'].join('')
    );
    expect(source).toContain(['validate_engine_socket "', '$', '{ENGINE_SOCKET}"'].join(''));
    expect(source).toContain('trusted_system_binary /usr/bin/docker');
    expect(source).toContain(
      ['ENGINE_SOCKET_EXPLICIT="', '$', '{ASTER_PHASE1_ENGINE_SOCKET+x}"'].join('')
    );
    expect(source).not.toContain('--root /dev/shm');
  });

  it('routes each state and invariant driver through an explicit socket and rejects aliases', async () => {
    const root = await mkdtemp('/var/tmp/henry-build/phase1-driver-socket-');
    const socket = path.join(root, 'engine.sock');
    const alias = path.join(root, 'alias.sock');
    const fakeDocker = path.join(root, 'docker');
    const calls = path.join(root, 'fake-calls');
    const requests = new Set<Socket>();
    const connections = new Set<Socket>();
    const server = createServer((connection) => {
      connections.add(connection);
      connection.once('data', () => {
        requests.add(connection);
        connection.end('HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
      });
      connection.on('close', () => connections.delete(connection));
    });
    const projectArgs = ['--project-name', 'aster-phase1-0123456789abcdef'];
    const drivers = [
      {
        name: 'phase1-reference-state-driver.sh',
        args: [
          '--container-id',
          '1'.repeat(64),
          ...projectArgs,
          '--expected-service',
          'oracle-primary-postgres',
          '--scenario-id',
          'token.authorization-code',
          '--step-id',
          'state',
        ],
      },
      {
        name: 'phase1-candidate-state-driver.sh',
        args: [
          '--container-id',
          '1'.repeat(64),
          ...projectArgs,
          '--expected-service',
          'candidate-primary-postgres',
          '--scenario-id',
          'token.authorization-code',
          '--step-id',
          'state',
        ],
      },
      {
        name: 'phase1-candidate-invariants-driver.sh',
        args: [
          '--invariant-id',
          'database.owner-role-membership-boundary',
          ...projectArgs,
          '--primary-container-id',
          '1'.repeat(64),
          '--foreign-container-id',
          '2'.repeat(64),
        ],
      },
    ];
    try {
      await chmod(root, 0o700);
      await writeFile(fakeDocker, `#!/usr/bin/env bash\nprintf 'called\\n' >> '${calls}'\n`, {
        mode: 0o700,
      });
      await new Promise<void>((resolve) => {
        server.listen(socket, resolve);
      });
      await symlink(socket, alias);
      await Promise.all(
        drivers.map(async ({ name, args }) => {
          const driver = path.join(repositoryRoot, '.scripts/compatibility', name);
          await expect(
            executeFile(driver, args, {
              env: { PATH: `${root}:/usr/bin:/bin`, ASTER_PHASE1_ENGINE_SOCKET: alias },
              timeout: 3000,
            })
          ).rejects.toThrow();
          await expect(
            executeFile(driver, args, {
              env: { PATH: `${root}:/usr/bin:/bin`, ASTER_PHASE1_ENGINE_SOCKET: '' },
              timeout: 3000,
            })
          ).rejects.toThrow();
          await expect(
            executeFile(driver, args, {
              env: { PATH: `${root}:/usr/bin:/bin`, ASTER_PHASE1_ENGINE_SOCKET: socket },
              timeout: 3000,
            })
          ).rejects.toThrow();
        })
      );
      expect(requests.size).toBeGreaterThanOrEqual(drivers.length);
      await expect(readFile(calls, 'utf8')).rejects.toThrow();
    } finally {
      for (const connection of connections) {
        connection.destroy();
      }
      await new Promise<void>((resolve) => {
        server.close(() => {
          resolve();
        });
      });
      await rm(root, { recursive: true, force: true });
    }
  });

  it('forwards the socket to both state drivers without changing other fixture environments', async () => {
    const runtime = await readFile(
      path.join(
        repositoryRoot,
        'packages/integration-tests/src/compatibility/phase-1/differential/runtime.ts'
      ),
      'utf8'
    );
    const state = await readFile(
      path.join(
        repositoryRoot,
        'packages/integration-tests/src/compatibility/phase-1/differential/reference-state.ts'
      ),
      'utf8'
    );
    expect(
      runtime.match(/ASTER_PHASE1_ENGINE_SOCKET: process\.env\.ASTER_PHASE1_ENGINE_SOCKET/gu)
    ).toHaveLength(2);
    expect(state).toContain(
      'ASTER_PHASE1_ENGINE_SOCKET: options.environment.ASTER_PHASE1_ENGINE_SOCKET'
    );
    expect(state).toContain('...(options.environment?.ASTER_PHASE1_ENGINE_SOCKET && {');
  });

  it('copies reviewed Oracle and measured candidate services exactly', async () => {
    const [document, formal, candidate] = await Promise.all([
      readCompose(topologyPath),
      readCompose(formalPath),
      readCompose(candidatePath),
    ]);

    expect(Object.keys(document.services).toSorted()).toEqual(
      [...oracleServices, ...measuredCandidateServices, ...phase0CandidateServices].toSorted()
    );
    for (const service of oracleServices) {
      expect(document.services[service]).toEqual(formal.services[service]);
    }
    for (const service of measuredCandidateServices) {
      expect(document.services[service]).toEqual(candidate.services[service]);
    }
  });

  it('defines one isolated reference-mirror Phase 0 candidate stack', async () => {
    const document = await readCompose(topologyPath);
    const postgres = document.services['candidate-phase0-postgres'];
    const redis = document.services['candidate-phase0-redis'];
    const core = document.services['candidate-phase0-core'];

    expect(document.networks['candidate-phase0']).toEqual({
      internal: true,
      ipam: { config: [{ subnet: '172.30.243.0/24' }] },
    });
    expect(postgres).toMatchObject({
      image: ['$', '{ASTER_PHASE1_POSTGRES_IMAGE:?required}'].join(''),
      environment: {
        POSTGRES_USER: 'aster',
        POSTGRES_DB: 'aster',
      },
      networks: { 'candidate-phase0': { ipv4_address: '172.30.243.10' } },
      volumes: ['candidate-phase0-postgres:/var/lib/postgresql/data'],
    });
    expect(redis).toMatchObject({
      image: ['$', '{ASTER_PHASE1_REDIS_IMAGE:?required}'].join(''),
      command: ['redis-server', '--appendonly', 'yes'],
      networks: { 'candidate-phase0': { ipv4_address: '172.30.243.11' } },
      volumes: ['candidate-phase0-redis:/data'],
    });
    expect(core).toMatchObject({
      image: ['$', '{ASTER_PHASE1_PHASE0_CONTROL_IMAGE:?required}'].join(''),
      networks: { 'candidate-phase0': { ipv4_address: '172.30.243.12' } },
      environment: {
        ENDPOINT: 'http://localhost:3341',
        ADMIN_ENDPOINT: 'http://localhost:3441',
        ADMIN_PORT: '3441',
      },
    });
    expect(JSON.stringify(core)).not.toContain('ASTER_PHASE1_CANDIDATE_IMAGE');
    expect(JSON.stringify(document.services)).not.toContain('fixture-coordinator phase0');
  });

  it('uses exact closed networks volumes and rootless service policy', async () => {
    const [source, document] = await Promise.all([
      readFile(topologyPath, 'utf8'),
      readCompose(topologyPath),
    ]);

    expect(Object.keys(document.networks).toSorted()).toEqual(
      [
        'oracle-primary',
        'oracle-foreign',
        'oracle-phase0',
        'candidate-primary',
        'candidate-foreign',
        'candidate-phase0',
        'candidate-connector-boundary',
        'candidate-saml-boundary',
        'candidate-script-boundary',
      ].toSorted()
    );
    expect(Object.keys(document.volumes).toSorted()).toEqual(
      [
        'oracle-primary-postgres',
        'oracle-primary-redis',
        'oracle-foreign-postgres',
        'oracle-foreign-redis',
        'oracle-phase0-postgres',
        'oracle-phase0-redis',
        'candidate-primary-postgres',
        'candidate-foreign-postgres',
        'candidate-phase0-postgres',
        'candidate-primary-keyring',
        'candidate-foreign-keyring',
        'candidate-phase0-redis',
      ].toSorted()
    );
    for (const service of Object.values(document.services)) {
      expect(service).not.toHaveProperty('ports');
      expect(service).not.toHaveProperty('privileged');
      expect(service).not.toHaveProperty('cap_add');
      expect(service).not.toHaveProperty('network_mode');
      expect(JSON.stringify(service)).not.toContain('docker.sock');
    }
    expect(source).not.toMatch(/\b(?:anchors|extends|include|profiles):/u);
    expect(source).not.toContain('/dev/shm');
    expect(Object.keys(document.services)).toContain('candidate-phase0-redis');
  });

  it('runs only explicit non-publishable runtime gates with owned cleanup', async () => {
    const [source, wrapper] = await Promise.all([
      readFile(runtimeRunnerPath, 'utf8'),
      readFile(differentialWrapperPath, 'utf8'),
    ]);

    expect(source.startsWith('#!/usr/bin/env bash\nset -euo pipefail\numask 077\n')).toBe(true);
    for (const required of [
      '/var/tmp/henry-build',
      'docker-compose.phase1-runtime-candidate-differential.yml',
      'prepare-review-profile',
      'run-differential',
      'run-candidate-invariants',
      'run-browser',
      "ASTER_PHASE1_MODE='runtime-candidate'",
      ['HOST_BIN_DIRECTORY="', '$', '{RUN_DIR}/host-bin"'].join(''),
      'docker_cli cp',
      '/usr/local/bin/aster-admin',
      ['PATH="', '$', '{HOST_BIN_DIRECTORY}:/usr/bin:/bin"'].join(''),
      ['FIXTURE_DIRECTORY="', '$', '{RUN_DIR}/fx"'].join(''),
      ['BROWSER_CACHE="', '$', '{BUILD_ROOT}/aster-playwright-browsers"'].join(''),
      ['PLAYWRIGHT_BROWSERS_PATH="', '$', '{BROWSER_CACHE}"'].join(''),
      ['require_private_root "', '$', '{BROWSER_CACHE}"'].join(''),
      ['[[ "', '$', '{#FIXTURE_SOCKET}" -le 107 ]] || fail'].join(''),
      'ASTER_FIXTURE_SOCKET=',
      'ASTER_PHASE1_PHASE0_CANDIDATE_IMAGE_DIGEST=',
      'phase-1-differential.json',
      'phase-1-candidate-invariants.json',
      'phase-1-browser.json',
      'value.scenarios.length !== 22',
      'scenario.differences.length !== 0',
      'value.outcomes.length !== 18',
      'value.observationNegativeControls.length !== 6',
      'value.flows.length !== 4',
      'aster-phase1-candidate-invariant-evidence',
      'aster-phase1-browser-evidence',
      'terminate_owned_process_group',
      ['container_id="$(compose ps --all -q "', '$', '{service}" 2>/dev/null || true)"'].join(''),
      ['container_id="$(compose ps --all -q "', '$', '{service}")"'].join(''),
      'label=com.docker.compose.project=',
      '^[A-Za-z0-9._/:-]+@sha256:',
      ['rm -rf -- "', '$', '{RUN_DIR}"'].join(''),
      ['"', '$', '{exit_code}" != 0 || "', '$', '{cleanup_failed}" != 0'].join(''),
      ['rm -rf -- "', '$', '{RESULT_DIR}"'].join(''),
    ]) {
      expect(source).toContain(required);
    }
    for (const forbidden of [
      '--record-oracle',
      'evidence-manifest.json',
      'harness-result.json',
      'phase-1-conformance.json',
      'docker.sock',
      '/dev/shm',
      'ASTER_PHASE1_PHASE0_CANDIDATE_FIXTURE_SOCKET=',
    ]) {
      expect(source).not.toContain(forbidden);
    }
    expect(wrapper).toContain("export ASTER_PHASE1_RUNTIME_GATE='differential'");
    expect(wrapper).toContain(
      ['exec "', '$', '{SCRIPT_DIR}/run-phase1-runtime-candidate.sh"'].join('')
    );
    expect(wrapper).not.toContain('run-candidate-invariants');
  });
});

/* eslint-enable no-use-extend-native/no-use-extend-native */
