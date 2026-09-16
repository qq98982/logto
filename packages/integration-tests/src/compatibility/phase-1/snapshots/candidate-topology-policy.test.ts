/* eslint-disable max-lines -- One policy file keeps the standalone Compose, PostgreSQL HBA, smoke runner, mutation, and live file-behavior contracts reviewed together. */
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

const repositoryRoot = path.resolve(process.cwd(), '../..');
const composePath = path.join(repositoryRoot, 'docker-compose.phase1-aster-candidate.yml');
const postgresInitPath = path.join(
  repositoryRoot,
  '.scripts/compatibility/phase1-candidate-postgres-init.sh'
);
const smokePath = path.join(repositoryRoot, '.scripts/compatibility/test-candidate-topology.sh');
const formalRunnerPath = path.join(repositoryRoot, '.scripts/compatibility/run-phase1.sh');
const executeFile = promisify(execFile);
const composeRequired = (name: string): string => ['$', `{${name}:?required}`].join('');
const shellVariable = (name: string): string => ['$', `{${name}}`].join('');

const serviceNames = [
  'candidate-primary-postgres',
  'candidate-primary-init',
  'candidate-primary-core',
  'candidate-foreign-postgres',
  'candidate-foreign-init',
  'candidate-foreign-core',
  'candidate-fixture-coordinator',
] as const;
const networkSpecs = Object.freeze({
  'candidate-primary': Object.freeze({
    subnet: '172.30.241.0/24',
    addresses: Object.freeze({
      'candidate-primary-postgres': '172.30.241.10',
      'candidate-primary-init': '172.30.241.11',
      'candidate-primary-core': '172.30.241.12',
      'candidate-fixture-coordinator': '172.30.241.13',
    }),
  }),
  'candidate-foreign': Object.freeze({
    subnet: '172.30.242.0/24',
    addresses: Object.freeze({
      'candidate-foreign-postgres': '172.30.242.10',
      'candidate-foreign-init': '172.30.242.11',
      'candidate-foreign-core': '172.30.242.12',
      'candidate-fixture-coordinator': '172.30.242.13',
    }),
  }),
});

type Service = Readonly<{
  image?: string;
  command?: readonly string[];
  depends_on?: Readonly<Record<string, Readonly<{ condition?: string }>>>;
  environment?: Readonly<Record<string, unknown>>;
  networks?: Readonly<Record<string, Readonly<{ ipv4_address?: string }>>>;
  volumes?: readonly string[];
  tmpfs?: readonly string[];
  user?: string;
  userns_mode?: string;
  read_only?: boolean;
  security_opt?: readonly string[];
  healthcheck?: Readonly<{ test?: readonly string[] }>;
  ports?: unknown;
  privileged?: unknown;
  network_mode?: unknown;
  cap_add?: unknown;
}>;

type ComposeDocument = Readonly<{
  services: Readonly<Record<string, Service>>;
  networks: Readonly<
    Record<
      string,
      Readonly<{
        internal?: boolean;
        ipam?: Readonly<{ config?: ReadonlyArray<Readonly<{ subnet?: string }>> }>;
      }>
    >
  >;
  volumes: Readonly<
    Record<
      string,
      Readonly<{
        driver?: string;
        driver_opts?: Readonly<Record<string, string>>;
      }>
    >
  >;
}>;

const assertCandidateTopology = (
  document: ComposeDocument,
  postgresInitSource: string,
  smokeSource: string
): void => {
  expect(Object.keys(document.services)).toEqual(serviceNames);
  expect(Object.keys(document.networks)).toEqual(Object.keys(networkSpecs));
  expect(Object.keys(document.volumes)).toEqual([
    'candidate-primary-postgres',
    'candidate-foreign-postgres',
    'candidate-primary-keyring',
    'candidate-foreign-keyring',
  ]);

  for (const [networkName, spec] of Object.entries(networkSpecs)) {
    const network = document.networks[networkName];

    expect(network).toEqual({ internal: true, ipam: { config: [{ subnet: spec.subnet }] } });
    for (const [serviceName, address] of Object.entries(spec.addresses)) {
      expect(document.services[serviceName]?.networks?.[networkName]).toEqual({
        ipv4_address: address,
      });
    }
  }
  expect(networkSpecs['candidate-primary'].subnet).not.toBe(
    networkSpecs['candidate-foreign'].subnet
  );

  for (const service of Object.values(document.services)) {
    expect(service).not.toHaveProperty('ports');
    expect(service).not.toHaveProperty('privileged');
    expect(service).not.toHaveProperty('network_mode');
    expect(service).not.toHaveProperty('cap_add');
    expect(service.image).toEqual(
      expect.stringMatching(/^\$\{ASTER_PHASE1_(?:POSTGRES|CANDIDATE)_IMAGE:\?required\}$/u)
    );
  }

  const primaryInit = document.services['candidate-primary-init'];
  const foreignInit = document.services['candidate-foreign-init'];
  const primaryCore = document.services['candidate-primary-core'];
  const foreignCore = document.services['candidate-foreign-core'];
  const coordinator = document.services['candidate-fixture-coordinator'];

  expect(primaryInit?.command).toEqual(['init', 'primary']);
  expect(foreignInit?.command).toEqual(['init', 'foreign']);
  expect(primaryCore?.command).toEqual(['core', 'primary']);
  expect(foreignCore?.command).toEqual(['core', 'foreign']);
  expect(coordinator?.command).toEqual(['fixture-coordinator']);
  expect(primaryCore?.depends_on?.['candidate-primary-init']?.condition).toBe(
    'service_completed_successfully'
  );
  expect(foreignCore?.depends_on?.['candidate-foreign-init']?.condition).toBe(
    'service_completed_successfully'
  );
  expect(coordinator?.depends_on).toEqual({
    'candidate-primary-init': { condition: 'service_completed_successfully' },
    'candidate-foreign-init': { condition: 'service_completed_successfully' },
    'candidate-primary-core': { condition: 'service_healthy' },
    'candidate-foreign-core': { condition: 'service_healthy' },
  });
  expect(Object.keys(coordinator?.networks ?? {})).toEqual([
    'candidate-primary',
    'candidate-foreign',
  ]);

  for (const service of [primaryInit, foreignInit, primaryCore, foreignCore, coordinator]) {
    expect(service?.user).toBe(
      `${composeRequired('ASTER_PHASE1_RUNTIME_UID')}:${composeRequired(
        'ASTER_PHASE1_RUNTIME_GID'
      )}`
    );
    expect(service?.userns_mode).toBe('host');
    expect(service?.read_only).toBe(true);
    expect(service?.security_opt).toEqual(['no-new-privileges:true']);
    expect(service?.tmpfs).toEqual(
      expect.arrayContaining([
        expect.stringContaining('/tmp:rw,'),
        expect.stringContaining('/run/aster:rw,'),
      ])
    );
  }

  for (const core of [primaryCore, foreignCore]) {
    const serializedEnvironment = JSON.stringify(core?.environment ?? {});

    expect(serializedEnvironment).not.toMatch(
      /ASTER_(?:ADMIN|MIGRATOR|MAINTAINER|REQUEST|RESOLVER|KEY_RUNTIME)_DATABASE_URL|ASTER_FIXTURE_/u
    );
  }
  expect(primaryCore?.environment).toMatchObject({
    ASTER_PHASE1_DATA_ISSUER: 'http://localhost:3321/oidc',
    ASTER_PHASE1_ADMIN_ISSUER: 'http://localhost:3421/oidc',
    ASTER_PHASE1_ADMIN_ORIGIN: 'http://localhost:3421',
  });
  expect(foreignCore?.environment).toMatchObject({
    ASTER_PHASE1_DATA_ISSUER: 'http://localhost:3322/oidc',
    ASTER_PHASE1_ADMIN_ISSUER: 'http://localhost:3422/oidc',
    ASTER_PHASE1_ADMIN_ORIGIN: 'http://localhost:3002',
  });
  expect(primaryCore?.healthcheck?.test).toEqual([
    'CMD-SHELL',
    "test -f /run/aster/maintainer-ready && printf 'GET /readyz HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n' | nc -w 2 127.0.0.1 3001 | grep -q ' 200 OK' && printf 'GET /readyz HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n' | nc -w 2 127.0.0.1 3421 | grep -q ' 200 OK'",
  ]);
  expect(foreignCore?.healthcheck?.test).toEqual([
    'CMD-SHELL',
    "test -f /run/aster/maintainer-ready && printf 'GET /readyz HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n' | nc -w 2 127.0.0.1 3001 | grep -q ' 200 OK' && printf 'GET /readyz HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n' | nc -w 2 127.0.0.1 3002 | grep -q ' 200 OK'",
  ]);

  expect(document.volumes['candidate-primary-keyring']).toEqual({
    driver: 'local',
    driver_opts: {
      type: 'none',
      o: 'bind',
      device: composeRequired('ASTER_PHASE1_PRIMARY_KEYRING_DIRECTORY'),
    },
  });
  expect(document.volumes['candidate-foreign-keyring']).toEqual({
    driver: 'local',
    driver_opts: {
      type: 'none',
      o: 'bind',
      device: composeRequired('ASTER_PHASE1_FOREIGN_KEYRING_DIRECTORY'),
    },
  });

  for (const required of [
    'local all all trust',
    `host all postgres ${shellVariable('ASTER_PHASE1_INIT_CIDR')} trust`,
    `host all aster_migrator,aster_admin,aster_maintainer ${shellVariable(
      'ASTER_PHASE1_INIT_CIDR'
    )} trust`,
    `host all aster_control_resolver,aster_request,aster_key_runtime,aster_maintainer ${shellVariable(
      'ASTER_PHASE1_CORE_CIDR'
    )} trust`,
    `host all postgres,aster_admin ${shellVariable('ASTER_PHASE1_COORDINATOR_CIDR')} trust`,
    'host all all 0.0.0.0/0 reject',
    'host all all ::/0 reject',
    'chmod 0600 "$PGDATA/pg_hba.conf"',
  ]) {
    expect(postgresInitSource).toContain(required);
  }
  expect(postgresInitSource).not.toMatch(/host\s+all\s+all\s+[^\n]+\s+trust/u);
  expect(postgresInitSource).not.toContain('POSTGRES_PASSWORD');
  expect(postgresInitSource).toContain('validate_host_cidr');

  const hbaBody = postgresInitSource.slice(
    postgresInitSource.indexOf('local all all trust'),
    postgresInitSource.indexOf('\nEOF', postgresInitSource.indexOf('local all all trust'))
  );
  expect(hbaBody.trimEnd().endsWith('host all all ::/0 reject')).toBe(true);

  expect(smokeSource.startsWith('#!/usr/bin/env bash\n\nset -euo pipefail\numask 077\n')).toBe(
    true
  );
};

const assertCandidateSmoke = (source: string, formalRunnerSource: string): void => {
  for (const required of [
    "readonly FORMAL_RUNNER_SHA256='1abd98577e593303ac19809b69e3c8592c479d25a7c4f9e0de179599260dfa4f'",
    '/var/tmp/henry-build',
    'require_private_root',
    'capture_path_identity',
    'assert_path_identity',
    'ASTER_PHASE1_FIXTURE_DIRECTORY',
    'ASTER_PHASE1_FIXTURE_SOCKET',
    'ASTER_PHASE1_NODE_BIN',
    'v22.23.2',
    '/usr/bin/timeout',
    'DOCKER_COMMAND_TIMEOUT',
    'candidate-primary.conf',
    'candidate-foreign.conf',
    'chmod 0400',
    'candidate-primary-keys',
    'candidate-foreign-keys',
    'compose.env',
    'candidate-primary-postgres candidate-primary-init candidate-primary-core',
    'candidate-foreign-postgres candidate-foreign-init candidate-foreign-core',
    'candidate-fixture-coordinator',
    "'candidate-primary-core|candidate-primary|172.30.241.12|3321|3001'",
    "'candidate-primary-core|candidate-primary|172.30.241.12|3421|3421'",
    "'candidate-foreign-core|candidate-foreign|172.30.242.12|3322|3001'",
    "'candidate-foreign-core|candidate-foreign|172.30.242.12|3422|3002'",
    'container_network_ipv4',
    'start_loopback_proxy',
    'port_is_listened_by_pid',
    'terminate_owned_process_group',
    'usr/local/bin/aster-admin',
    'docker_cli export',
    'readelf',
    'ldd',
    'ASTER_ADMIN_LDD_ALLOWLIST',
    'master-key active-id',
    '/oidc/.well-known/openid-configuration',
    'fullPhase1 corsBoundary none dataProtocol passwordMatrix adminConsole consentBoundary',
    'env: { PATH: fixtureCommandPath, ASTER_FIXTURE_SOCKET: fixtureSocket }',
    'projectState',
    'phase1-candidate-state-driver.sh',
    'readReferenceStateDriver',
    "scenarioId: 'management.application-read'",
    "expectedService: 'candidate-primary-postgres'",
    'cleanup',
    'fixture_socket_device="$($STAT_BIN -c %d -- "$FIXTURE_SOCKET")"',
    'fixture_socket_inode="$($STAT_BIN -c %i -- "$FIXTURE_SOCKET")"',
    'compose stop -t 20 candidate-fixture-coordinator',
    'compose down --volumes --remove-orphans',
    'docker_cli container inspect "$extract_container_name"',
  ]) {
    expect(source).toContain(required);
  }
  expect(source).not.toContain('Aster candidate topology smoke is not implemented');
  expect(source).not.toContain('docker.sock');
  expect(source).not.toContain('/dev/shm');
  expect(source).not.toMatch(/docker exec|compose exec/u);
  const fixtureNodeStart = source.indexOf('cat >"$fixture_node_script"');
  const fixtureNodeEnd = source.indexOf('\nNODE', fixtureNodeStart);

  expect(fixtureNodeStart).toBeGreaterThan(0);
  expect(fixtureNodeEnd).toBeGreaterThan(fixtureNodeStart);
  const fixtureNodeSource = source.slice(fixtureNodeStart, fixtureNodeEnd);

  expect(fixtureNodeSource).not.toMatch(/DATABASE_URL|POSTGRES_PASSWORD|docker/u);
  expect(createHash('sha256').update(formalRunnerSource).digest('hex')).toBe(
    '1abd98577e593303ac19809b69e3c8592c479d25a7c4f9e0de179599260dfa4f'
  );
};

describe('Aster candidate standalone topology policy', () => {
  it('pins the closed service, network, HBA, volume, and authority topology', async () => {
    const document = JSON.parse(await readFile(composePath, 'utf8')) as ComposeDocument;
    const [postgresInitSource, smokeSource] = await Promise.all([
      readFile(postgresInitPath, 'utf8'),
      readFile(smokePath, 'utf8'),
    ]);

    assertCandidateTopology(document, postgresInitSource, smokeSource);
  });

  it('rejects broad trust, missing reject, overlapping networks, foreign services, and core authority', async () => {
    const document = JSON.parse(await readFile(composePath, 'utf8')) as ComposeDocument;
    const [postgresInitSource, smokeSource] = await Promise.all([
      readFile(postgresInitPath, 'utf8'),
      readFile(smokePath, 'utf8'),
    ]);
    const mutations: ReadonlyArray<
      Readonly<{ document?: ComposeDocument; postgresInitSource?: string }>
    > = [
      {
        postgresInitSource: postgresInitSource.replace(
          `host all postgres ${shellVariable('ASTER_PHASE1_INIT_CIDR')} trust`,
          `host all all ${shellVariable('ASTER_PHASE1_INIT_CIDR')} trust`
        ),
      },
      {
        postgresInitSource: postgresInitSource.replace('host all all ::/0 reject', ''),
      },
      {
        document: {
          ...document,
          networks: {
            ...document.networks,
            'candidate-foreign': {
              internal: true,
              ipam: { config: [{ subnet: networkSpecs['candidate-primary'].subnet }] },
            },
          },
        },
      },
      {
        document: {
          ...document,
          services: {
            ...document.services,
            'candidate-redis': { image: composeRequired('ASTER_PHASE1_REDIS_IMAGE') },
          },
        },
      },
      {
        document: {
          ...document,
          networks: { ...document.networks, 'candidate-script-boundary': { internal: true } },
        },
      },
      {
        document: {
          ...document,
          services: {
            ...document.services,
            'candidate-primary-core': {
              ...document.services['candidate-primary-core'],
              environment: {
                ...document.services['candidate-primary-core']?.environment,
                ASTER_ADMIN_DATABASE_URL: 'postgres://forbidden',
              },
            },
          },
        },
      },
      {
        document: {
          ...document,
          services: {
            ...document.services,
            'candidate-fixture-coordinator': {
              ...document.services['candidate-fixture-coordinator'],
              networks: {
                ...document.services['candidate-fixture-coordinator']?.networks,
                forbidden: { ipv4_address: '172.30.243.13' },
              },
            },
          },
        },
      },
    ];

    for (const mutation of mutations) {
      expect(() => {
        assertCandidateTopology(
          mutation.document ?? document,
          mutation.postgresInitSource ?? postgresInitSource,
          smokeSource
        );
      }).toThrow();
    }
  });

  it('writes the exact private HBA and rejects an invalid CIDR without changing the file', async () => {
    const root = await mkdtemp('/var/tmp/henry-build/aster-candidate-hba-test-');
    const pgData = path.join(root, 'pgdata');
    const hbaPath = path.join(pgData, 'pg_hba.conf');

    try {
      await mkdir(pgData, { mode: 0o700 });
      await writeFile(hbaPath, 'original-hba\n', { mode: 0o600 });
      await executeFile(postgresInitPath, [], {
        env: {
          PATH: '/usr/bin:/bin',
          PGDATA: pgData,
          ASTER_PHASE1_INIT_CIDR: '172.30.241.11/32',
          ASTER_PHASE1_CORE_CIDR: '172.30.241.12/32',
          ASTER_PHASE1_COORDINATOR_CIDR: '172.30.241.13/32',
        },
        timeout: 10_000,
      });
      expect(await readFile(hbaPath, 'utf8')).toBe(`# Aster Phase 1 candidate acceptance topology.
local all all trust
host all postgres 172.30.241.11/32 trust
host all aster_migrator,aster_admin,aster_maintainer 172.30.241.11/32 trust
host all aster_control_resolver,aster_request,aster_key_runtime,aster_maintainer 172.30.241.12/32 trust
host all postgres,aster_admin 172.30.241.13/32 trust
host all all 0.0.0.0/0 reject
host all all ::/0 reject
`);
      const hbaStats = await stat(hbaPath);
      const hbaMode = hbaStats.mode;

      expect(hbaMode % 0o1000).toBe(0o600);

      await writeFile(hbaPath, 'unchanged-invalid-hba\n', { mode: 0o600 });
      await expect(
        executeFile(postgresInitPath, [], {
          env: {
            PATH: '/usr/bin:/bin',
            PGDATA: pgData,
            ASTER_PHASE1_INIT_CIDR: '999.30.241.11/32',
            ASTER_PHASE1_CORE_CIDR: '172.30.241.12/32',
            ASTER_PHASE1_COORDINATOR_CIDR: '172.30.241.13/32',
          },
          timeout: 10_000,
        })
      ).rejects.toMatchObject({
        stdout: '',
        stderr: 'Aster candidate PostgreSQL initialization failed\n',
      });
      expect(await readFile(hbaPath, 'utf8')).toBe('unchanged-invalid-hba\n');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('pins the private topology smoke without changing the formal Phase 1 runner', async () => {
    const [source, formalRunnerSource] = await Promise.all([
      readFile(smokePath, 'utf8'),
      readFile(formalRunnerPath, 'utf8'),
    ]);

    assertCandidateSmoke(source, formalRunnerSource);
  });

  it('rejects smoke mutations that weaken identity, proxy, fixture, or runner authority', async () => {
    const [source, formalRunnerSource] = await Promise.all([
      readFile(smokePath, 'utf8'),
      readFile(formalRunnerPath, 'utf8'),
    ]);
    const mutations = [
      {
        name: 'socket inode identity',
        source: source.replaceAll('fixture_socket_inode', 'socket_inode_removed'),
      },
      {
        name: 'proxy destination',
        source: source.replace(
          "'candidate-primary-core|candidate-primary|172.30.241.12|3321|3001'",
          "'candidate-primary-core|candidate-primary|172.30.241.99|3321|3001'"
        ),
      },
      {
        name: 'fixture database authority',
        source: source.replace(
          'env: { PATH: fixtureCommandPath, ASTER_FIXTURE_SOCKET: fixtureSocket }',
          "env: { PATH: fixtureCommandPath, ASTER_FIXTURE_SOCKET: fixtureSocket, DATABASE_URL: 'forbidden' }"
        ),
      },
      {
        name: 'formal runner digest',
        source: source.replace(
          "readonly FORMAL_RUNNER_SHA256='1abd98577e593303ac19809b69e3c8592c479d25a7c4f9e0de179599260dfa4f'",
          `readonly FORMAL_RUNNER_SHA256='${'0'.repeat(64)}'`
        ),
      },
    ];

    for (const mutation of mutations) {
      expect(mutation.source).not.toBe(source);
      const rejected = (() => {
        try {
          assertCandidateSmoke(mutation.source, formalRunnerSource);
          return false;
        } catch {
          return true;
        }
      })();

      expect({ name: mutation.name, rejected }).toEqual({ name: mutation.name, rejected: true });
    }
  });
});

/* eslint-enable max-lines */
