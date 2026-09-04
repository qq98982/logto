import { readFile } from 'node:fs/promises';
import path from 'node:path';

const repositoryRoot = path.resolve(process.cwd(), '../..');
const composePath = path.join(repositoryRoot, 'docker-compose.phase1-compatibility.yml');
const runnerPath = path.join(repositoryRoot, '.scripts/compatibility/run-phase1.sh');

type ComposeDocument = Readonly<{
  services: Readonly<
    Record<
      string,
      Readonly<{
        environment?: Readonly<Record<string, unknown>>;
        healthcheck?: Readonly<{ test?: readonly string[] }>;
      }>
    >
  >;
}>;

type ProxyBinding = Readonly<{
  service: string;
  network: string;
  hostPort: string;
  containerPort: string;
}>;

const runtimeUrlEnvironmentNames = Object.freeze({
  'oracle-primary-core': Object.freeze({
    core: 'ASTER_PHASE1_ORACLE_URL',
    admin: 'ASTER_PHASE1_ORACLE_ADMIN_URL',
    adminProcessPort: '3411',
    localhostCors: 'accepted',
  }),
  'oracle-foreign-core': Object.freeze({
    core: 'ASTER_PHASE1_ORACLE_FOREIGN_URL',
    admin: 'ASTER_PHASE1_ORACLE_FOREIGN_ADMIN_URL',
    adminProcessPort: '3002',
    localhostCors: 'rejected',
  }),
  'candidate-primary-core': Object.freeze({
    core: 'ASTER_PHASE1_CANDIDATE_URL',
    admin: 'ASTER_PHASE1_CANDIDATE_ADMIN_URL',
    adminProcessPort: '3421',
    localhostCors: 'accepted',
  }),
  'candidate-foreign-core': Object.freeze({
    core: 'ASTER_PHASE1_CANDIDATE_FOREIGN_URL',
    admin: 'ASTER_PHASE1_CANDIDATE_FOREIGN_ADMIN_URL',
    adminProcessPort: '3002',
    localhostCors: 'rejected',
  }),
  'oracle-phase0-core': Object.freeze({
    core: 'ASTER_PHASE1_PHASE0_ORACLE_URL',
    admin: 'ASTER_PHASE1_PHASE0_ORACLE_ADMIN_URL',
    adminProcessPort: '3431',
    localhostCors: 'accepted',
  }),
  'candidate-phase0-core': Object.freeze({
    core: 'ASTER_PHASE1_PHASE0_CANDIDATE_URL',
    admin: 'ASTER_PHASE1_PHASE0_CANDIDATE_ADMIN_URL',
    adminProcessPort: '3441',
    localhostCors: 'accepted',
  }),
});

const parseProxyBinding = (binding: string): ProxyBinding => {
  const [service, network, hostPort, containerPort, ...extra] = binding.split('|');

  if (!service || !network || !hostPort || !containerPort || extra.length > 0) {
    throw new Error('Invalid Phase 1 loopback proxy binding');
  }

  return Object.freeze({ service, network, hostPort, containerPort });
};

const sourceProxyBindings = (source: string): readonly ProxyBinding[] => {
  const match = /readonly LOOPBACK_PROXY_BINDINGS=\(\n([\s\S]*?)\n\)/u.exec(source);

  if (!match?.[1]) {
    throw new Error('Missing Phase 1 loopback proxy bindings');
  }

  return Object.freeze(
    match[1]
      .split('\n')
      .map((line) => /^ {2}'([^']+)'$/u.exec(line)?.[1])
      .map((binding) => (binding ? parseProxyBinding(binding) : parseProxyBinding('')))
  );
};

const sourcePortList = (source: string, pattern: RegExp): readonly string[] => {
  const match = pattern.exec(source);

  if (!match?.[1]) {
    throw new Error('Missing Phase 1 port list');
  }

  return Object.freeze(match[1].trim().split(/\s+/u));
};

const sourceLiteralEnvironmentValue = (source: string, name: string): string => {
  const matches = [...source.matchAll(new RegExp(`^  ${name}='([^']+)'$`, 'gmu'))];

  expect(matches).toHaveLength(1);
  return matches[0]?.[1] ?? '';
};

const assertEndpointCoupling = (source: string, document: ComposeDocument): void => {
  const bindings = sourceProxyBindings(source);
  const coreBindings = bindings.filter(({ hostPort }) => hostPort.startsWith('33'));
  const adminBindings = bindings.filter(({ hostPort }) => hostPort.startsWith('34'));

  expect(sourcePortList(source, /readonly PORTS=\(([\d ]+)\)/u)).toEqual(
    bindings.map(({ hostPort }) => hostPort)
  );
  expect(sourcePortList(source, /for core_port in ([\d ]+); do/u)).toEqual(
    coreBindings.map(({ hostPort }) => hostPort)
  );
  expect(sourcePortList(source, /for admin_port in ([\d ]+); do/u)).toEqual(
    adminBindings.map(({ hostPort }) => hostPort)
  );

  for (const [service, names] of Object.entries(runtimeUrlEnvironmentNames)) {
    const serviceBindings = bindings.filter((binding) => binding.service === service);
    const coreBinding = serviceBindings.find(({ hostPort }) => hostPort.startsWith('33'));
    const adminBinding = serviceBindings.find(({ hostPort }) => hostPort.startsWith('34'));
    const environment = document.services[service]?.environment;
    const endpoint = typeof environment?.ENDPOINT === 'string' ? environment.ENDPOINT : undefined;
    const adminEndpoint =
      typeof environment?.ADMIN_ENDPOINT === 'string' ? environment.ADMIN_ENDPOINT : undefined;
    const adminPort =
      typeof environment?.ADMIN_PORT === 'string' ? environment.ADMIN_PORT : undefined;
    const healthcheck = document.services[service]?.healthcheck;

    expect(serviceBindings).toHaveLength(2);
    expect(coreBinding?.network).toBe(service.replace(/-core$/u, ''));
    expect(adminBinding?.network).toBe(service.replace(/-core$/u, ''));
    expect(coreBinding?.containerPort).toBe('3001');
    expect(endpoint).toBe(`http://localhost:${coreBinding?.hostPort}`);
    expect(new URL(String(endpoint)).port).toBe(coreBinding?.hostPort);
    expect(adminPort).toBe(names.adminProcessPort);
    expect(adminBinding?.containerPort).toBe(adminPort);
    expect(adminEndpoint).toBe(`http://localhost:${adminBinding?.hostPort}`);
    expect(new URL(String(adminEndpoint)).port).toBe(adminBinding?.hostPort);
    if (names.localhostCors === 'accepted') {
      expect(adminPort).toBe(adminBinding?.hostPort);
    } else {
      expect(adminPort).not.toBe(adminBinding?.hostPort);
    }
    expect(healthcheck?.test).toEqual([
      'CMD-SHELL',
      `nc -z localhost ${coreBinding?.containerPort} && nc -z localhost ${adminPort}`,
    ]);
    expect(sourceLiteralEnvironmentValue(source, names.core)).toBe(endpoint);
    expect(sourceLiteralEnvironmentValue(source, names.admin)).toBe(adminEndpoint);
  }
};

const withServiceEnvironment = (
  document: ComposeDocument,
  service: string,
  patch: Readonly<Record<string, unknown>>
): ComposeDocument => {
  const current = document.services[service];

  if (!current) {
    throw new Error('Missing Phase 1 compose service');
  }

  return {
    ...document,
    services: {
      ...document.services,
      [service]: {
        ...current,
        environment: { ...current.environment, ...patch },
      },
    },
  };
};

const withServiceHealthcheck = (
  document: ComposeDocument,
  service: string,
  test: readonly string[]
): ComposeDocument => {
  const current = document.services[service];

  if (!current) {
    throw new Error('Missing Phase 1 compose service');
  }

  return {
    ...document,
    services: {
      ...document.services,
      [service]: { ...current, healthcheck: { test } },
    },
  };
};

describe('Phase 1 loopback endpoint coupling', () => {
  it('couples compose endpoints, proxy bindings, readiness, and public runtime URLs', async () => {
    const source = await readFile(runnerPath, 'utf8');
    const document = JSON.parse(await readFile(composePath, 'utf8')) as ComposeDocument;

    assertEndpointCoupling(source, document);
  });

  it('rejects endpoint and port drift across compose and runner sources', async () => {
    const source = await readFile(runnerPath, 'utf8');
    const document = JSON.parse(await readFile(composePath, 'utf8')) as ComposeDocument;
    const mutations: ReadonlyArray<Readonly<{ source?: string; document?: ComposeDocument }>> = [
      {
        document: withServiceEnvironment(document, 'oracle-primary-core', {
          ADMIN_PORT: '3999',
        }),
      },
      {
        document: withServiceEnvironment(document, 'oracle-foreign-core', {
          ADMIN_PORT: '3412',
        }),
      },
      {
        document: withServiceHealthcheck(document, 'oracle-foreign-core', [
          'CMD-SHELL',
          'nc -z localhost 3001 && nc -z localhost 3412',
        ]),
      },
      {
        document: withServiceEnvironment(document, 'oracle-primary-core', {
          ADMIN_ENDPOINT: 'http://localhost:3999',
        }),
      },
      {
        document: withServiceEnvironment(document, 'oracle-primary-core', {
          ENDPOINT: 'http://localhost:3999',
        }),
      },
      {
        source: source.replace(
          "'oracle-primary-core|oracle-primary|3411|3411'",
          "'oracle-primary-core|oracle-primary|3411|3999'"
        ),
      },
      {
        source: source.replace(
          "  ASTER_PHASE1_ORACLE_URL='http://localhost:3311'",
          [
            "  ASTER_PHASE1_ORACLE_URL='http://localhost:3311'",
            "  ASTER_PHASE1_ORACLE_URL='http://localhost:3999'",
          ].join('\n')
        ),
      },
      {
        source: source.replace(
          "'oracle-primary-core|oracle-primary|3311|3001'",
          "'oracle-primary-core|oracle-primary|3311|3999'"
        ),
      },
      {
        source: source.replace(
          'for admin_port in 3411 3412 3421 3422 3431 3441; do',
          'for admin_port in 3411 3412 3421 3422 3431; do'
        ),
      },
      {
        source: source.replace(
          'for core_port in 3311 3312 3321 3322 3331 3341; do',
          'for core_port in 3312 3311 3321 3322 3331 3341; do'
        ),
      },
      {
        source: source.replace(
          'readonly PORTS=(3311 3411 3312 3412 3321 3421 3322 3422 3331 3431 3341 3441)',
          'readonly PORTS=(3411 3311 3312 3412 3321 3421 3322 3422 3331 3431 3341 3441)'
        ),
      },
      {
        source: source.replace(
          "ASTER_PHASE1_ORACLE_URL='http://localhost:3311'",
          "ASTER_PHASE1_ORACLE_URL='http://localhost:3999'"
        ),
      },
      {
        source: source.replace(
          "ASTER_PHASE1_ORACLE_ADMIN_URL='http://localhost:3411'",
          "ASTER_PHASE1_ORACLE_ADMIN_URL='http://localhost:3999'"
        ),
      },
    ];

    for (const mutation of mutations) {
      const mutatedSource = mutation.source ?? source;
      const mutatedDocument = mutation.document ?? document;

      expect(mutatedSource !== source || mutatedDocument !== document).toBe(true);
      expect(() => {
        assertEndpointCoupling(mutatedSource, mutatedDocument);
      }).toThrow();
    }
  });
});
