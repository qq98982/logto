/* eslint-disable max-lines, no-await-in-loop, no-use-extend-native/no-use-extend-native -- Keep topology and actual export-guard contracts together; shared temporary artifacts require sequential checks and exact authority comparisons use non-mutating sorting. */
import { execFile } from 'node:child_process';
import { chmod, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { createServer, type Socket } from 'node:net';
import path from 'node:path';
import { promisify } from 'node:util';

const executeFile = promisify(execFile);

type ComposeService = Readonly<Record<string, unknown>>;
type ComposeDocument = Readonly<{
  services: Readonly<Record<string, ComposeService>>;
  'x-phase2-services'?: Readonly<Record<string, ComposeService>>;
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

const artifactEntries = (count: number) =>
  Array.from({ length: count }, (_, index) => ({
    id: `case-${String(index).padStart(2, '0')}`,
    differences: [],
    detected: true,
    positiveControl: { detected: true },
    negativeControl: { detected: true },
  }));

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
  'candidate-primary-smtp',
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
  it('defines the isolated Phase 2 fetch observer and real script host slice', async () => {
    const document = await readCompose(topologyPath);
    const fixtures = document['x-phase2-services'];
    const oracleObserver = fixtures?.['oracle-fetch-observer'];
    const candidateObserver = fixtures?.['candidate-fetch-observer'];
    const supervisor = fixtures?.['candidate-script-supervisor'];
    const executor = fixtures?.['candidate-script-executor'];

    expect(oracleObserver).toMatchObject({
      image: ['$', '{ASTER_PHASE1_ORACLE_IMAGE:?required}'].join(''),
      entrypoint: ['node'],
      command: ['/opt/aster-fixture/phase2-fetch-observer.mjs'],
      networks: {
        'oracle-primary': {
          ipv4_address: '172.30.231.50',
          aliases: ['fetch-observer.aster.test'],
        },
      },
    });
    expect(candidateObserver).toMatchObject({
      networks: {
        'candidate-primary': {
          ipv4_address: '172.30.241.50',
          aliases: ['fetch-observer.aster.test'],
        },
      },
      pids_limit: 32,
      mem_limit: '192m',
      cpus: 0.25,
      cap_drop: ['ALL'],
    });
    expect(JSON.stringify(oracleObserver)).toContain("host:'fetch-observer.aster.test:8443'");
    expect(JSON.stringify(candidateObserver)).toContain("host:'fetch-observer.aster.test:8443'");
    expect(JSON.stringify(oracleObserver)).not.toContain('rejectUnauthorized:false');
    expect(JSON.stringify(candidateObserver)).not.toContain('rejectUnauthorized:false');
    expect(supervisor).toMatchObject({
      image: [
        '$',
        '{ASTER_PHASE2_SCRIPT_SUPERVISOR_IMAGE:-$',
        '{ASTER_PHASE1_CANDIDATE_IMAGE:?required}}',
      ].join(''),
      environment: {
        ASTER_SCRIPT_HOST_ADDRESS: '0.0.0.0:50051',
        ASTER_SCRIPT_SIDECAR_ADDRESS: '127.0.0.1:50052',
        ASTER_SCRIPT_CA_FILE: '/run/aster-script-host/tls/ca.pem',
        ASTER_SCRIPT_CERTIFICATE_FILE: '/run/aster-script-host/tls/server.pem',
        ASTER_SCRIPT_PRIVATE_KEY_FILE: '/run/aster-script-host/tls/server.key',
        ASTER_SCRIPT_EXPECTED_CLIENT_URI: 'spiffe://aster.test/server',
      },
      networks: {
        'candidate-primary': {
          ipv4_address: '172.30.241.51',
          aliases: ['candidate-script-supervisor'],
        },
      },
    });
    expect(executor).toMatchObject({
      image: [
        '$',
        '{ASTER_PHASE2_SCRIPT_EXECUTOR_IMAGE:-$',
        '{ASTER_PHASE1_CANDIDATE_IMAGE:?required}}',
      ].join(''),
      network_mode: 'service:candidate-script-supervisor',
      environment: { ASTER_SCRIPT_SUPERVISOR_ADDRESS: '127.0.0.1:50052' },
    });
    expect(JSON.stringify(executor)).not.toContain('process.exit(0)');
    expect(document.services['oracle-primary-core']).toMatchObject({
      networks: { 'oracle-primary': { ipv4_address: '172.30.231.12' } },
      extra_hosts: [
        'oracle-primary-postgres=172.30.231.10',
        'oracle-primary-redis=172.30.231.11',
        'oracle-primary-smtp=172.30.231.49',
        'fetch-observer.aster.test=172.30.231.50',
      ],
    });
    expect(document.services['candidate-primary-core']).toMatchObject({
      extra_hosts: [
        'fetch-observer.aster.test=172.30.241.50',
        'candidate-script-supervisor=172.30.241.51',
      ],
    });
    for (const [name, network, subnet] of [
      ['oracle-foreign', 'oracle-foreign', '172.30.232'],
      ['oracle-phase0', 'oracle-phase0', '172.30.233'],
    ] as const) {
      expect(document.services[`${name}-postgres`]).toMatchObject({
        networks: { [network]: { ipv4_address: `${subnet}.10` } },
      });
      expect(document.services[`${name}-redis`]).toMatchObject({
        networks: { [network]: { ipv4_address: `${subnet}.11` } },
      });
      expect(document.services[`${name}-core`]).toMatchObject({
        networks: { [network]: { ipv4_address: `${subnet}.12` } },
        extra_hosts: [`${name}-postgres=${subnet}.10`, `${name}-redis=${subnet}.11`],
      });
    }
    expect(document.networks).toMatchObject({
      'oracle-primary': { internal: true, ipam: { config: [{ subnet: '172.30.231.0/24' }] } },
      'oracle-foreign': { internal: true, ipam: { config: [{ subnet: '172.30.232.0/24' }] } },
      'oracle-phase0': { internal: true, ipam: { config: [{ subnet: '172.30.233.0/24' }] } },
    });
    expect(document.services['candidate-foreign-core']?.environment).not.toHaveProperty(
      'ASTER_SCRIPT_HOST_ADDRESS'
    );
  });

  it('exports only artifacts bound to both owned image roles', async () => {
    const source = await readFile(runtimeRunnerPath, 'utf8');
    const marker = source.indexOf('const gate = process.argv[3];');
    const start = source.lastIndexOf("import { readFile } from 'node:fs/promises';", marker);
    const end = source.indexOf('\nNODE', marker);
    expect(start).toBeGreaterThan(0);
    expect(end).toBeGreaterThan(start);
    const guard = source.slice(start, end);
    const root = await mkdtemp('/var/tmp/henry-build/phase1-artifact-image-');
    const file = path.join(root, 'artifact.json');
    const oracle = `sha256:${'a'.repeat(64)}`;
    const candidate = `sha256:${'b'.repeat(64)}`;
    try {
      for (const gate of ['differential', 'browser', 'candidate-invariants']) {
        const primary = gate === 'candidate-invariants' ? candidate : oracle;
        const artifact = {
          schemaVersion: 1,
          mode: 'runtime-candidate',
          sanitizerSuccess: true,
          provenance: { imageDigest: primary, candidateImageDigest: candidate },
          ...(gate === 'differential'
            ? { scenarios: artifactEntries(22) }
            : gate === 'browser'
              ? { flows: artifactEntries(4) }
              : {
                  outcomes: artifactEntries(18),
                  observationNegativeControls: artifactEntries(6),
                  discoveryExtraControl: { detected: true },
                }),
        };
        const run = async () =>
          executeFile(process.execPath, [
            '--input-type=module',
            '--eval',
            guard,
            '-',
            file,
            gate,
            oracle,
            candidate,
          ]);
        await writeFile(file, JSON.stringify(artifact), { mode: 0o600 });
        await expect(run()).resolves.toMatchObject({ stdout: '', stderr: '' });
        for (const provenance of [
          { imageDigest: primary },
          { imageDigest: primary, candidateImageDigest: oracle },
          { imageDigest: primary === oracle ? candidate : oracle, candidateImageDigest: candidate },
        ]) {
          await writeFile(file, JSON.stringify({ ...artifact, provenance }), { mode: 0o600 });
          await expect(run()).rejects.toThrow();
        }
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

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
    expect(source).toContain('http://localhost/libpod/_ping');
    expect(source).toContain('404) ;;');
    expect(source).toContain('readonly COMPOSE_FILE');
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
      const {
        networks: _actualNetworks,
        extra_hosts: _actualHosts,
        ...actual
      } = document.services[service] ?? {};
      const {
        networks: _formalNetworks,
        extra_hosts: _formalHosts,
        ...reviewed
      } = formal.services[service] ?? {};
      expect(actual).toEqual(reviewed);
    }
    for (const service of measuredCandidateServices) {
      if (service === 'candidate-primary-smtp') {
        continue;
      } else if (service === 'candidate-primary-core') {
        const {
          extra_hosts: _hosts,
          environment: actualEnvironment,
          ...actual
        } = document.services[service] ?? {};
        const { environment: reviewedEnvironment, ...reviewed } = candidate.services[service] ?? {};
        const { ASTER_ISOLATED_EMAIL_FIXTURE: _emailFixture, ...actualBaseEnvironment } =
          (actualEnvironment ?? {}) as Record<string, unknown>;
        expect(actual).toEqual(reviewed);
        expect(actualBaseEnvironment).toEqual(reviewedEnvironment);
      } else {
        expect(document.services[service]).toEqual(candidate.services[service]);
      }
    }
    expect(document.services['candidate-primary-smtp']).toMatchObject({
      image: ['$', '{ASTER_PHASE2_SCRIPT_SUPERVISOR_IMAGE:?required}'].join(''),
      network_mode: 'service:candidate-primary-core',
      environment: {
        ASTER_SMTP_BIND: '127.0.0.1',
        ASTER_SMTP_CONTROL_SOCKET: [
          '$',
          '{ASTER_PHASE1_FIXTURE_DIRECTORY:?required}/verification-smtp.sock',
        ].join(''),
      },
      read_only: true,
      security_opt: ['no-new-privileges:true'],
    });
    expect(JSON.stringify(document.services['candidate-primary-smtp'])).not.toMatch(
      /(?:DB_URL|POSTGRES|REDIS_URL|SECRET_VAULT|STATUS_API_KEY)/u
    );
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
    for (const [name, service] of Object.entries(document.services)) {
      expect(service).not.toHaveProperty('ports');
      expect(service).not.toHaveProperty('privileged');
      expect(service).not.toHaveProperty('cap_add');
      if (name === 'candidate-primary-smtp') {
        expect(service).toHaveProperty('network_mode', 'service:candidate-primary-core');
      } else {
        expect(service).not.toHaveProperty('network_mode');
      }
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
      'aster-phase1-differential-evidence',
      ['RESULT_DIR="$(/usr/bin/mktemp -d "', '$', '{RESULT_ROOT}/result.XXXXXX")"'].join(''),
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

/* eslint-enable max-lines, no-await-in-loop, no-use-extend-native/no-use-extend-native */
