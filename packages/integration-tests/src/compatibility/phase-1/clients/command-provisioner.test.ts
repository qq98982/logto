/* eslint-disable max-lines, @typescript-eslint/ban-types, prefer-destructuring, @silverhand/fp/no-mutating-methods, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/consistent-type-assertions, no-await-in-loop, @typescript-eslint/no-unnecessary-condition, @typescript-eslint/no-unnecessary-boolean-literal-compare -- Process-boundary tests model Node null exits, record invocations, mutate hostile result descriptors, and run closed projection and process-group mutation matrices. */
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { inspect } from 'node:util';

import type { TargetConfig } from '../../model.js';
import {
  createExpectedPhase1FixtureStateProjection,
  createPhase1FixtureMap,
  phase1FixtureEntityKinds,
  type Phase1FixtureMap,
} from '../fixture-map.js';
import type { Phase1Profile } from '../profile-types.js';

import {
  createCommandPhase1FixtureProvisioner,
  runPhase1FixtureCommand,
} from './command-provisioner.js';

const profile = {
  fixtures: {
    dataTenant: {
      id: 'default',
      subject: {
        id: 'phase1-user',
        username: 'phase1-user',
        name: 'phase1-user',
        primaryEmail: 'phase1-user@example.com',
        primaryPhone: '+15555550101',
        profile: { address: { formatted: '1 Aster Way', country: 'US' } },
        applicationId: null,
      },
      applications: [
        {
          id: 'phase1-app',
          name: 'Phase 1 Application',
          type: 'SPA',
          isThirdParty: false,
          oidcClientMetadata: {
            redirectUris: ['http://localhost:3001/demo-app'],
            postLogoutRedirectUris: [],
          },
          customClientMetadata: {},
        },
        {
          id: 'phase1-browser',
          name: 'Phase 1 Consent Client',
          type: 'SPA',
          isThirdParty: true,
          oidcClientMetadata: {
            redirectUris: ['http://localhost:3001/demo-app'],
            postLogoutRedirectUris: [],
          },
          customClientMetadata: {},
          userConsentScopes: ['profile', 'email', 'address', 'phone'],
          resourceConsentScopes: ['phase1-read-profile'],
        },
      ],
      resource: {
        id: 'phase1-api',
        name: 'Phase 1 API',
        indicator: 'https://api.example.com',
        scopes: [
          {
            id: 'phase1-read-profile',
            name: 'read:profile',
            description: "Read the signed-in user's profile",
          },
        ],
      },
      resourceScopeRole: {
        id: 'phase1-reader',
        name: 'Phase 1 Reader',
        description: 'Grants the Phase 1 API read scope',
        type: 'User',
        isDefault: false,
        scopeIds: ['phase1-read-profile'],
        userIds: ['phase1-user'],
      },
    },
    adminTenant: {
      id: 'admin',
      operator: {
        id: 'phase1-admin',
        username: 'phase1-admin',
        primaryEmail: 'phase1-admin@example.com',
        roles: ['default:admin', 'user'],
        customData: { ossOnboarding: { isOnboardingDone: true } },
      },
      application: {
        id: 'admin-console',
        type: 'SPA',
        oidcClientMetadata: {
          redirectUris: ['http://localhost:3002/console/callback'],
          postLogoutRedirectUris: [],
        },
        customClientMetadata: {},
      },
      resources: [
        { indicator: 'https://default.logto.app/api', scopes: ['all'] },
        { indicator: 'https://admin.logto.app/me', scopes: ['all'] },
        {
          indicator: 'urn:logto:resource:organizations',
          scopes: ['urn:logto:scope:organizations'],
        },
      ],
      tenantOrganization: {
        id: 't-default',
        name: 'Tenant default',
        memberUserIds: ['phase1-admin'],
        scopes: ['read:data'],
        organizationRoles: [
          {
            id: 'admin',
            name: 'admin',
            type: 'User',
            scopeNames: ['read:data'],
            userIds: ['phase1-admin'],
          },
        ],
      },
    },
  },
} as unknown as Pick<Phase1Profile, 'fixtures'>;

const target: TargetConfig = {
  label: 'candidate',
  coreUrl: 'http://localhost:3021/',
  adminUrl: 'http://localhost:3022/',
};
const foreignTarget: TargetConfig = {
  label: 'candidate',
  coreUrl: 'http://localhost:3041/',
  adminUrl: 'http://localhost:3042/',
};
const seededPassword = 'command-seeded-password-1842';
const unrelatedCredentialValues = [
  'eyJhbGciOiJIUzI1NiJ9.e30.c2ln',
  'Bearer unrelated-opaque-credential',
  'Cookie: sid=unrelated-opaque-credential',
  'Set-Cookie: sid=unrelated-opaque-credential; Path=/; Secure',
  'sid=unrelated-opaque-credential; Path=/; Secure; HttpOnly',
  '-----BEGIN PRIVATE KEY-----',
] as const;

type RunnerRequest = Readonly<{
  command: string;
  args: readonly string[];
  stdin: string;
  env: Readonly<Record<string, string>>;
  timeoutMs: number;
  maxStdoutBytes: number;
  maxStderrBytes: number;
  shell: false;
}>;

type RunnerResult = Readonly<{
  exitCode: number | null;
  signal: string | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  killed: boolean;
  reaped: boolean;
}>;

const allocation = (role: 'data' | 'admin' | 'foreign', allocationId: string, endpoint: string) => {
  const base = {
    allocationId,
    role,
    target: role === 'foreign' ? ('foreign' as const) : ('primary' as const),
    isolation: {
      persistenceId: `persistence:${endpoint}`,
      cookieKeyId: `cookie-key:${endpoint}`,
      signingKeyId: `signing-key:${endpoint}`,
    },
  };
  const entities =
    role === 'admin'
      ? [
          { kind: 'tenant' as const, logicalId: 'admin', runtimeId: `${allocationId}-tenant` },
          { kind: 'user' as const, logicalId: 'phase1-admin', runtimeId: `${allocationId}-admin` },
          {
            kind: 'application' as const,
            logicalId: 'admin-console',
            runtimeId: `${allocationId}-application`,
          },
          ...Array.from({ length: 3 }, (_, index) => ({
            kind: 'resource' as const,
            logicalId: `admin.resource.${index + 1}`,
            runtimeId: `${allocationId}-resource-${index + 1}`,
          })),
          ...['default:admin', 'user'].map((logicalId, index) => ({
            kind: 'role' as const,
            logicalId,
            runtimeId: `${allocationId}-role-${index + 1}`,
          })),
          {
            kind: 'organization' as const,
            logicalId: 't-default',
            runtimeId: `${allocationId}-organization`,
          },
          {
            kind: 'organization-role' as const,
            logicalId: 'admin',
            runtimeId: `${allocationId}-organization-role`,
          },
        ]
      : role === 'foreign'
        ? [
            { kind: 'tenant' as const, logicalId: 'default', runtimeId: `${allocationId}-tenant` },
            {
              kind: 'user' as const,
              logicalId: 'consent.foreign.user-b',
              runtimeId: `${allocationId}-user`,
            },
            {
              kind: 'application' as const,
              logicalId: 'consent.foreign.client-b',
              runtimeId: `${allocationId}-application`,
            },
          ]
        : [
            { kind: 'tenant' as const, logicalId: 'default', runtimeId: `${allocationId}-tenant` },
            { kind: 'user' as const, logicalId: 'phase1-user', runtimeId: `${allocationId}-user` },
            ...['phase1-app', 'phase1-browser'].map((logicalId, index) => ({
              kind: 'application' as const,
              logicalId,
              runtimeId: `${allocationId}-application-${index + 1}`,
            })),
            {
              kind: 'resource' as const,
              logicalId: 'phase1-api',
              runtimeId: `${allocationId}-resource`,
            },
            {
              kind: 'scope' as const,
              logicalId: 'phase1-read-profile',
              runtimeId: `${allocationId}-scope`,
            },
            {
              kind: 'role' as const,
              logicalId: 'phase1-reader',
              runtimeId: `${allocationId}-role`,
            },
          ];

  return { ...base, entities };
};

const resultMap = (recipe: Phase1FixtureMap['recipe'], base: string): Phase1FixtureMap => {
  const allocations =
    recipe === 'none'
      ? []
      : recipe === 'dataProtocol'
        ? [allocation('data', `${base}-data`, target.coreUrl)]
        : recipe === 'adminConsole'
          ? [allocation('admin', `${base}-admin`, target.adminUrl)]
          : recipe === 'fullPhase1'
            ? [
                allocation('data', `${base}-data`, target.coreUrl),
                allocation('admin', `${base}-admin`, target.adminUrl),
              ]
            : [
                {
                  ...allocation('data', `${base}-data`, target.coreUrl),
                  entities: [
                    ...allocation('data', `${base}-data`, target.coreUrl).entities,
                    {
                      kind: 'user' as const,
                      logicalId: 'consent.primary.user-b',
                      runtimeId: `${base}-primary-peer-user`,
                    },
                    {
                      kind: 'application' as const,
                      logicalId: 'consent.primary.client-b',
                      runtimeId: `${base}-primary-peer-client`,
                    },
                  ],
                },
                allocation('foreign', `${base}-foreign`, foreignTarget.coreUrl),
              ];

  return createPhase1FixtureMap({ schemaVersion: 1, recipe, allocations });
};

const runnerResult = (stdout: unknown, rest: Partial<RunnerResult> = {}): RunnerResult => ({
  exitCode: 0,
  signal: null,
  stdout: typeof stdout === 'string' ? stdout : JSON.stringify(stdout),
  stderr: '',
  timedOut: false,
  killed: false,
  reaped: true,
  ...rest,
});

const provisionResult = (recipe: Phase1FixtureMap['recipe'], base = 'candidate') => ({
  schemaVersion: 1,
  operation: 'provision',
  public: resultMap(recipe, base),
});

const projectStateProjection = (map: Phase1FixtureMap) =>
  createExpectedPhase1FixtureStateProjection(map, profile);

const createHarness = (
  responder: (
    descriptor: Record<string, unknown>,
    request: RunnerRequest
  ) => RunnerResult | Promise<RunnerResult> = (descriptor) => {
    const operation = descriptor.operation;

    if (operation === 'provision') {
      return runnerResult(
        provisionResult(descriptor.recipe as Phase1FixtureMap['recipe'], 'candidate')
      );
    }
    if (operation === 'projectState') {
      return runnerResult({
        schemaVersion: 1,
        operation: 'projectState',
        projection: projectStateProjection(
          resultMap(descriptor.recipe as Phase1FixtureMap['recipe'], 'candidate')
        ),
      });
    }
    if (operation === 'readUserActivityState') {
      return runnerResult({
        schemaVersion: 1,
        operation: 'readUserActivityState',
        activity: { lastSignInState: 'never' },
      });
    }

    return runnerResult({ schemaVersion: 1, operation: 'cleanup', ok: true });
  }
) => {
  const requests: RunnerRequest[] = [];
  const runner = async (request: RunnerRequest): Promise<RunnerResult> => {
    requests.push(request);
    return responder(JSON.parse(request.stdin) as Record<string, unknown>, request);
  };
  let allocation = 0;
  const provisioner = createCommandPhase1FixtureProvisioner({
    profile,
    target,
    foreignTarget,
    runner,
    environment: { PATH: '/approved/bin', HOME: '/must-not-pass', DB_URL: 'must-not-pass' },
    createAllocationId: () => `command-allocation-${++allocation}`,
    createSecret: () => seededPassword,
  });

  return { provisioner, requests };
};

const runnerRequest = (
  commandPath: string,
  overrides: Partial<RunnerRequest> = {}
): RunnerRequest => ({
  command: commandPath,
  args: [],
  stdin: '{}',
  env: { PATH: '/usr/bin:/bin' },
  timeoutMs: 1000,
  maxStdoutBytes: 4096,
  maxStderrBytes: 4096,
  shell: false,
  ...overrides,
});

const withPrivateExecutable = async <Result>(
  body: string,
  use: (commandPath: string, directory: string) => Promise<Result>
): Promise<Result> => {
  const directory = await mkdtemp('/var/tmp/henry-build/aster-phase1-command-');
  const commandPath = path.join(directory, 'aster-admin');

  try {
    await writeFile(commandPath, `#!${process.execPath}\n${body}`, { mode: 0o700 });
    await chmod(commandPath, 0o700);
    return await use(commandPath, directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
};

const processIsGone = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return false;
  } catch (error: unknown) {
    return (
      typeof error === 'object' &&
      error !== null &&
      Object.getOwnPropertyDescriptor(error, 'code')?.value === 'ESRCH'
    );
  }
};

const readOwnedPids = async (directory: string): Promise<readonly number[]> =>
  JSON.parse(await readFile(path.join(directory, 'pids.json'), 'utf8')) as number[];

describe('candidate fixture command descriptor', () => {
  it('invokes exact aster-admin fixture apply with a private descriptor and allowlisted environment', async () => {
    const { provisioner, requests } = createHarness();
    const fixture = await provisioner.provision('fullPhase1');
    const request = requests[0];

    expect(request).toBeDefined();
    expect(request?.command).toBe('aster-admin');
    expect(request?.args).toEqual(['fixture', 'apply']);
    expect(request?.shell).toBe(false);
    expect(request?.timeoutMs).toBe(30_000);
    expect(request?.maxStdoutBytes).toBe(262_144);
    expect(request?.maxStderrBytes).toBe(65_536);
    expect(Object.keys(request?.env ?? {}).toSorted()).toEqual([
      'ASTER_ADMIN_URL',
      'ASTER_CORE_URL',
      'ASTER_FOREIGN_ADMIN_URL',
      'ASTER_FOREIGN_CORE_URL',
      'ASTER_TARGET_LABEL',
      'PATH',
    ]);
    expect(JSON.stringify(request?.args)).not.toContain(seededPassword);
    expect(JSON.stringify(request?.env)).not.toContain(seededPassword);
    const descriptor = JSON.parse(request?.stdin ?? '') as Record<string, unknown>;
    expect(descriptor).toMatchObject({
      schemaVersion: 1,
      operation: 'provision',
      recipe: 'fullPhase1',
      allocationId: 'command-allocation-1',
    });
    expect(request?.stdin).toContain(seededPassword);
    expect(fixture.public.recipe).toBe('fullPhase1');

    await fixture.withSecretLease(async (lease) => {
      expect(lease.getPassword('phase1-user')).toBe(seededPassword);
      expect(lease.getPassword('phase1-admin')).toBe(seededPassword);
    });
  });

  it('uses the same fixed command for state projection and cleanup with no seeded secrets', async () => {
    const { provisioner, requests } = createHarness();
    const fixture = await provisioner.provision('dataProtocol');

    await expect(provisioner.projectState(fixture)).resolves.toEqual(
      projectStateProjection(fixture.public)
    );
    await expect(provisioner.cleanup(fixture)).resolves.toBeUndefined();
    expect(requests).toHaveLength(3);
    expect(requests.map(({ command, args }) => [command, args])).toEqual([
      ['aster-admin', ['fixture', 'apply']],
      ['aster-admin', ['fixture', 'apply']],
      ['aster-admin', ['fixture', 'apply']],
    ]);
    expect(JSON.parse(requests[1]?.stdin ?? '{}')).toMatchObject({
      operation: 'projectState',
      recipe: 'dataProtocol',
      allocationId: 'command-allocation-1',
    });
    expect(JSON.parse(requests[2]?.stdin ?? '{}')).toMatchObject({
      operation: 'cleanup',
      recipe: 'dataProtocol',
      allocationId: 'command-allocation-1',
    });
    expect(requests[1]?.stdin).not.toContain(seededPassword);
    expect(requests[2]?.stdin).not.toContain(seededPassword);
  });

  it('uses an exact closed descriptor and returns only user activity state', async () => {
    const { provisioner, requests } = createHarness((descriptor) =>
      descriptor.operation === 'provision'
        ? runnerResult(provisionResult('fullPhase1'))
        : descriptor.operation === 'readUserActivityState'
          ? runnerResult({
              schemaVersion: 1,
              operation: 'readUserActivityState',
              activity: {
                lastSignInState: descriptor.logicalUserId === 'phase1-user' ? 'never' : 'present',
              },
            })
          : runnerResult({ schemaVersion: 1, operation: 'cleanup', ok: true })
    );
    const fixture = await provisioner.provision('fullPhase1');

    await expect(provisioner.readUserActivityState(fixture, 'phase1-user')).resolves.toEqual({
      lastSignInState: 'never',
    });
    await expect(provisioner.readUserActivityState(fixture, 'phase1-admin')).resolves.toEqual({
      lastSignInState: 'present',
    });
    const descriptors = requests.slice(1).map(({ stdin }) => JSON.parse(stdin) as object);
    expect(descriptors).toEqual([
      {
        schemaVersion: 1,
        operation: 'readUserActivityState',
        recipe: 'fullPhase1',
        allocationId: 'command-allocation-1',
        public: fixture.public,
        logicalUserId: 'phase1-user',
      },
      {
        schemaVersion: 1,
        operation: 'readUserActivityState',
        recipe: 'fullPhase1',
        allocationId: 'command-allocation-1',
        public: fixture.public,
        logicalUserId: 'phase1-admin',
      },
    ]);
    expect(requests[1]?.stdin).not.toContain(seededPassword);
    expect(requests[2]?.stdin).not.toContain(seededPassword);
  });

  it('rejects an unknown command fixture or logical user before invoking the reader', async () => {
    const first = createHarness();
    const second = createHarness();
    const fixture = await first.provisioner.provision('dataProtocol');
    const foreignFixture = await second.provisioner.provision('dataProtocol');
    const requestCount = first.requests.length;

    await expect(
      first.provisioner.readUserActivityState(foreignFixture, 'phase1-user')
    ).rejects.toThrow('Candidate fixture command failed');
    await expect(first.provisioner.readUserActivityState(fixture, 'missing-user')).rejects.toThrow(
      'Candidate fixture command failed'
    );
    expect(first.requests).toHaveLength(requestCount);
  });

  it.each([
    {},
    { lastSignInState: 'unknown' },
    { lastSignInState: 'never', lastSignInAt: 1_725_000_000_000 },
    { lastSignInAt: 1_725_000_000_000 },
  ])('rejects malformed command activity state %p', async (activity) => {
    const { provisioner } = createHarness((descriptor) =>
      descriptor.operation === 'provision'
        ? runnerResult(provisionResult('dataProtocol'))
        : descriptor.operation === 'readUserActivityState'
          ? runnerResult({
              schemaVersion: 1,
              operation: 'readUserActivityState',
              activity,
            })
          : runnerResult({ schemaVersion: 1, operation: 'cleanup', ok: true })
    );
    const fixture = await provisioner.provision('dataProtocol');

    await expect(provisioner.readUserActivityState(fixture, 'phase1-user')).rejects.toThrow(
      'Candidate fixture command failed'
    );
  });

  it('rejects a command activity result with an extra envelope field', async () => {
    const { provisioner } = createHarness((descriptor) =>
      descriptor.operation === 'provision'
        ? runnerResult(provisionResult('dataProtocol'))
        : descriptor.operation === 'readUserActivityState'
          ? runnerResult({
              schemaVersion: 1,
              operation: 'readUserActivityState',
              activity: { lastSignInState: 'never' },
              lastSignInAt: 1_725_000_000_000,
            })
          : runnerResult({ schemaVersion: 1, operation: 'cleanup', ok: true })
    );
    const fixture = await provisioner.provision('dataProtocol');

    await expect(provisioner.readUserActivityState(fixture, 'phase1-user')).rejects.toThrow(
      'Candidate fixture command failed'
    );
  });

  it('rejects a secret-bearing command activity result without exposing it', async () => {
    const credential = 'Bearer unrelated-activity-credential';
    const { provisioner } = createHarness((descriptor) =>
      descriptor.operation === 'provision'
        ? runnerResult(provisionResult('dataProtocol'))
        : descriptor.operation === 'readUserActivityState'
          ? runnerResult({
              schemaVersion: 1,
              operation: 'readUserActivityState',
              activity: { lastSignInState: 'never', note: credential },
            })
          : runnerResult({ schemaVersion: 1, operation: 'cleanup', ok: true })
    );
    const fixture = await provisioner.provision('dataProtocol');
    let caught: unknown;

    try {
      await provisioner.readUserActivityState(fixture, 'phase1-user');
    } catch (error: unknown) {
      caught = error;
    }

    expect(String(caught)).toBe('Error: Candidate fixture command failed');
    expect(inspect(caught)).not.toContain(credential);
    expect(JSON.stringify(caught)).not.toContain(credential);
  });

  it.each(phase1FixtureEntityKinds)(
    'rejects a candidate %s projection with a wrong logical identity',
    async (kind) => {
      const { provisioner } = createHarness((descriptor) => {
        if (descriptor.operation === 'provision') {
          return runnerResult(provisionResult('fullPhase1'));
        }
        if (descriptor.operation === 'cleanup') {
          return runnerResult({ schemaVersion: 1, operation: 'cleanup', ok: true });
        }
        const projection = structuredClone(
          projectStateProjection(resultMap('fullPhase1', 'candidate'))
        ) as unknown as {
          allocations: Array<{
            entities: Array<{
              kind: string;
              logicalId: string;
              snapshot: Record<string, unknown>;
            }>;
          }>;
        };
        const entity = projection.allocations
          .flatMap(({ entities }) => entities)
          .find((candidate) => candidate.kind === kind);
        expect(entity).toBeDefined();
        entity!.logicalId = `${entity!.logicalId}.wrong`;

        return runnerResult({ schemaVersion: 1, operation: 'projectState', projection });
      });
      const fixture = await provisioner.provision('fullPhase1');

      await expect(provisioner.projectState(fixture)).rejects.toThrow(
        'Candidate fixture command failed'
      );
      await provisioner.cleanup(fixture);
    }
  );

  it.each(phase1FixtureEntityKinds)(
    'rejects a candidate %s projection with the right identity but wrong state',
    async (kind) => {
      const { provisioner } = createHarness((descriptor) => {
        if (descriptor.operation === 'provision') {
          return runnerResult(provisionResult('fullPhase1'));
        }
        if (descriptor.operation === 'cleanup') {
          return runnerResult({ schemaVersion: 1, operation: 'cleanup', ok: true });
        }
        const projection = structuredClone(
          projectStateProjection(resultMap('fullPhase1', 'candidate'))
        );
        const entity = projection.allocations
          .flatMap(({ entities }) => entities)
          .find((candidate) => candidate.kind === kind);
        expect(entity).toBeDefined();
        const snapshot = entity!.snapshot as Record<string, unknown>;
        const field = Object.keys(snapshot)[0];
        if (field === undefined) {
          snapshot.unexpected = 'wrong';
        } else {
          const value = snapshot[field];
          snapshot[field] =
            typeof value === 'string'
              ? `${value}.wrong`
              : typeof value === 'boolean'
                ? !value
                : value === null
                  ? 'wrong'
                  : Array.isArray(value)
                    ? [...Array.from(value as readonly unknown[]), 'wrong']
                    : { unexpected: 'wrong' };
        }

        return runnerResult({ schemaVersion: 1, operation: 'projectState', projection });
      });
      const fixture = await provisioner.provision('fullPhase1');

      await expect(provisioner.projectState(fixture)).rejects.toThrow(
        'Candidate fixture command failed'
      );
      await provisioner.cleanup(fixture);
    }
  );

  it('retains failed command cleanup state for retry and releases it only after success', async () => {
    let cleanupAttempts = 0;
    const { provisioner, requests } = createHarness((descriptor) => {
      if (descriptor.operation === 'provision') {
        return runnerResult(provisionResult('dataProtocol'));
      }
      if (descriptor.operation === 'cleanup') {
        cleanupAttempts += 1;
        return cleanupAttempts === 1
          ? runnerResult('transient cleanup failure', { exitCode: 7 })
          : runnerResult({ schemaVersion: 1, operation: 'cleanup', ok: true });
      }
      return runnerResult({ schemaVersion: 1, operation: 'projectState', projection: {} });
    });
    const fixture = await provisioner.provision('dataProtocol');

    await expect(provisioner.cleanup(fixture)).rejects.toThrow(
      'Candidate fixture cleanup command failed'
    );
    await expect(provisioner.cleanup(fixture)).resolves.toBeUndefined();
    await expect(provisioner.cleanup(fixture)).resolves.toBeUndefined();

    expect(cleanupAttempts).toBe(2);
    expect(
      requests
        .map(({ stdin }) => JSON.parse(stdin) as { operation: string })
        .filter(({ operation }) => operation === 'cleanup')
    ).toHaveLength(2);
  });

  it('releases descriptor and public allocation claims after successful compensation', async () => {
    let provisionAttempts = 0;
    const runner = async (request: RunnerRequest): Promise<RunnerResult> => {
      const descriptor = JSON.parse(request.stdin) as { operation: string };

      if (descriptor.operation === 'cleanup') {
        return runnerResult({ schemaVersion: 1, operation: 'cleanup', ok: true });
      }
      if (descriptor.operation === 'provision') {
        provisionAttempts += 1;
        return provisionAttempts === 1
          ? runnerResult('malformed')
          : runnerResult(provisionResult('dataProtocol', 'reusable-public'));
      }

      return runnerResult({
        schemaVersion: 1,
        operation: 'projectState',
        projection: projectStateProjection(resultMap('dataProtocol', 'reusable-public')),
      });
    };
    const provisioner = createCommandPhase1FixtureProvisioner({
      profile,
      target,
      runner,
      createAllocationId: () => 'reusable-descriptor',
      createSecret: () => seededPassword,
    });

    await expect(provisioner.provision('dataProtocol')).rejects.toThrow(
      'Candidate fixture command failed'
    );
    const fixture = await provisioner.provision('dataProtocol');
    await expect(provisioner.cleanup(fixture)).resolves.toBeUndefined();
    expect(provisionAttempts).toBe(2);
  });

  it('retries retained failed compensation before reusing an allocation', async () => {
    let provisionAttempts = 0;
    let cleanupAttempts = 0;
    const operations: string[] = [];
    const provisioner = createCommandPhase1FixtureProvisioner({
      profile,
      target,
      runner: async (request: RunnerRequest): Promise<RunnerResult> => {
        const descriptor = JSON.parse(request.stdin) as { operation: string };
        operations.push(descriptor.operation);
        if (descriptor.operation === 'cleanup') {
          cleanupAttempts += 1;
          return runnerResult({
            schemaVersion: 1,
            operation: 'cleanup',
            ok: cleanupAttempts > 1,
          });
        }
        provisionAttempts += 1;
        return provisionAttempts === 1
          ? runnerResult('malformed')
          : runnerResult(provisionResult('dataProtocol', 'recovered-public'));
      },
      createAllocationId: () => 'retryable-descriptor',
      createSecret: () => seededPassword,
    });

    await expect(provisioner.provision('dataProtocol')).rejects.toBeInstanceOf(AggregateError);
    const fixture = await provisioner.provision('dataProtocol');
    await expect(provisioner.cleanup(fixture)).resolves.toBeUndefined();

    expect(operations).toEqual(['provision', 'cleanup', 'cleanup', 'provision', 'cleanup']);
  });

  it('recovers a failed returned-fixture cleanup before the next provision', async () => {
    let cleanupAttempts = 0;
    let publicAllocation = 0;
    const provisioner = createCommandPhase1FixtureProvisioner({
      profile,
      target,
      runner: async (request: RunnerRequest): Promise<RunnerResult> => {
        const descriptor = JSON.parse(request.stdin) as {
          operation: string;
          recipe: Phase1FixtureMap['recipe'];
        };
        if (descriptor.operation === 'cleanup') {
          cleanupAttempts += 1;
          return runnerResult({
            schemaVersion: 1,
            operation: 'cleanup',
            ok: cleanupAttempts > 2,
          });
        }
        return runnerResult(
          provisionResult(descriptor.recipe, `cleanup-recovery-${++publicAllocation}`)
        );
      },
      createAllocationId: (() => {
        let allocation = 0;
        return () => `cleanup-recovery-descriptor-${++allocation}`;
      })(),
      createSecret: () => seededPassword,
    });
    const first = await provisioner.provision('dataProtocol');

    await expect(provisioner.cleanup(first)).rejects.toThrow(
      'Candidate fixture cleanup command failed'
    );
    await expect(provisioner.provision('none')).rejects.toThrow(
      'Candidate pending fixture cleanup failed'
    );
    const second = await provisioner.provision('none');
    await expect(provisioner.cleanup(second)).resolves.toBeUndefined();
    expect(cleanupAttempts).toBe(4);
  });

  it('serializes concurrent command cleanup calls', async () => {
    let markCleanupStarted: (() => void) | undefined;
    const cleanupStarted = new Promise<void>((resolve) => {
      markCleanupStarted = resolve;
    });
    let releaseCleanup: (() => void) | undefined;
    const cleanupReleased = new Promise<void>((resolve) => {
      releaseCleanup = resolve;
    });
    let cleanupCalls = 0;
    const { provisioner } = createHarness(async (descriptor) => {
      if (descriptor.operation === 'provision') {
        return runnerResult(provisionResult('dataProtocol'));
      }
      if (descriptor.operation === 'cleanup') {
        cleanupCalls += 1;
        markCleanupStarted?.();
        await cleanupReleased;
        return runnerResult({ schemaVersion: 1, operation: 'cleanup', ok: true });
      }
      return runnerResult({ schemaVersion: 1, operation: 'projectState', projection: {} });
    });
    const fixture = await provisioner.provision('dataProtocol');
    const first = provisioner.cleanup(fixture);
    await cleanupStarted;
    const second = provisioner.cleanup(fixture);
    expect(cleanupCalls).toBe(1);
    releaseCleanup?.();

    await expect(Promise.all([first, second])).resolves.toEqual([undefined, undefined]);
    expect(cleanupCalls).toBe(1);
  });
});

describe('candidate fixture command safety', () => {
  it.each([
    ['malformed JSON', () => runnerResult('{not-json')],
    ['wrong operation', () => runnerResult({ schemaVersion: 1, operation: 'cleanup', ok: true })],
    [
      'extra result field',
      () =>
        runnerResult({
          ...provisionResult('dataProtocol'),
          accessToken: 'raw-output-secret-value',
        }),
    ],
    [
      'seeded password in an allowed runtime ID',
      () => {
        const publicMap = resultMap('dataProtocol', 'candidate');
        return runnerResult({
          schemaVersion: 1,
          operation: 'provision',
          public: {
            ...publicMap,
            allocations: [
              {
                ...publicMap.allocations[0],
                entities: publicMap.allocations[0]?.entities.map((entity) =>
                  entity.kind === 'user' && entity.logicalId === 'phase1-user'
                    ? { ...entity, runtimeId: seededPassword }
                    : entity
                ),
              },
            ],
          },
        });
      },
    ],
    ['oversized stdout', () => runnerResult('x'.repeat(262_145))],
    [
      'oversized stderr',
      () => runnerResult(provisionResult('dataProtocol'), { stderr: 'x'.repeat(65_537) }),
    ],
    ['unreaped process', () => runnerResult(provisionResult('dataProtocol'), { reaped: false })],
    [
      'nonzero exit',
      () =>
        runnerResult('raw stdout secret', {
          exitCode: 7,
          stderr: 'raw stderr secret',
        }),
    ],
  ])('rejects %s without exposing process output', async (_name, response) => {
    const rawSecret = 'raw-output-secret-value';
    const { provisioner } = createHarness((descriptor) =>
      descriptor.operation === 'cleanup'
        ? runnerResult({ schemaVersion: 1, operation: 'cleanup', ok: true })
        : response()
    );
    let caught: unknown;

    try {
      await provisioner.provision('dataProtocol');
    } catch (error: unknown) {
      caught = error;
    }

    expect(String(caught)).toContain('Candidate fixture command failed');
    expect(inspect(caught)).not.toContain(rawSecret);
    expect(inspect(caught)).not.toContain('raw stdout secret');
    expect(inspect(caught)).not.toContain('raw stderr secret');
  });

  it.each(unrelatedCredentialValues)(
    'rejects unrelated runtime credentials in allowed values and object keys',
    async (credential) => {
      const publicMap = resultMap('dataProtocol', 'candidate');
      const credentialMap = {
        ...publicMap,
        allocations: [
          {
            ...publicMap.allocations[0],
            entities: publicMap.allocations[0]?.entities.map((entity) =>
              entity.kind === 'user' && entity.logicalId === 'phase1-user'
                ? { ...entity, runtimeId: credential }
                : entity
            ),
          },
        ],
      };
      for (const response of [
        runnerResult({ schemaVersion: 1, operation: 'provision', public: credentialMap }),
        runnerResult({
          schemaVersion: 1,
          operation: 'provision',
          public: publicMap,
          [credential]: 'ordinary-value',
        }),
      ]) {
        const { provisioner } = createHarness((descriptor) =>
          descriptor.operation === 'cleanup'
            ? runnerResult({ schemaVersion: 1, operation: 'cleanup', ok: true })
            : response
        );
        let caught: unknown;
        try {
          await provisioner.provision('dataProtocol');
        } catch (error: unknown) {
          caught = error;
        }
        expect(String(caught)).toContain('Candidate fixture command failed');
        expect(inspect(caught)).not.toContain(credential);
        expect(JSON.stringify(caught)).not.toContain(credential);
      }
    }
  );

  it.each(unrelatedCredentialValues)(
    'rejects unrelated credentials in projectState output',
    async (credential) => {
      const { provisioner } = createHarness((descriptor) =>
        descriptor.operation === 'provision'
          ? runnerResult(provisionResult('dataProtocol'))
          : descriptor.operation === 'projectState'
            ? runnerResult({
                schemaVersion: 1,
                operation: 'projectState',
                projection: (() => {
                  const projection = structuredClone(
                    projectStateProjection(resultMap('dataProtocol', 'candidate'))
                  );
                  const snapshot = projection.allocations[0]!.entities[1]!.snapshot as Record<
                    string,
                    unknown
                  >;
                  snapshot.name = credential;
                  return projection;
                })(),
              })
            : runnerResult({ schemaVersion: 1, operation: 'cleanup', ok: true })
      );
      const fixture = await provisioner.provision('dataProtocol');
      let caught: unknown;
      try {
        await provisioner.projectState(fixture);
      } catch (error: unknown) {
        caught = error;
      }
      expect(String(caught)).toBe('Error: Candidate fixture command failed');
      expect(inspect(caught)).not.toContain(credential);
      expect(JSON.stringify(caught)).not.toContain(credential);
    }
  );

  it('rejects accessor-backed and proxied runner results without invoking accessors', async () => {
    let getterCalls = 0;
    const accessor = {} as Record<string, unknown>;
    Object.defineProperty(accessor, 'stdout', {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return JSON.stringify(provisionResult('dataProtocol'));
      },
    });
    for (const key of ['exitCode', 'signal', 'stderr', 'timedOut', 'killed', 'reaped']) {
      Object.defineProperty(accessor, key, {
        enumerable: true,
        value:
          key === 'exitCode'
            ? 0
            : key === 'stderr'
              ? ''
              : key === 'timedOut' || key === 'killed'
                ? false
                : key === 'reaped'
                  ? true
                  : null,
      });
    }

    for (const response of [
      accessor,
      new Proxy(runnerResult(provisionResult('dataProtocol')), {}),
    ]) {
      const provisioner = createCommandPhase1FixtureProvisioner({
        profile,
        target,
        runner: async (request: RunnerRequest) =>
          (JSON.parse(request.stdin) as { operation: string }).operation === 'cleanup'
            ? runnerResult({ schemaVersion: 1, operation: 'cleanup', ok: true })
            : (response as RunnerResult),
        createAllocationId: () => 'invalid-runner-result',
        createSecret: () => seededPassword,
      });
      await expect(provisioner.provision('dataProtocol')).rejects.toThrow(
        'Candidate fixture command failed'
      );
    }
    expect(getterCalls).toBe(0);
  });

  it('kills and reaps a timed-out apply, then attempts bounded cleanup', async () => {
    const { provisioner, requests } = createHarness((descriptor) =>
      descriptor.operation === 'provision'
        ? runnerResult('', {
            exitCode: null,
            signal: 'SIGKILL',
            timedOut: true,
            killed: true,
            reaped: true,
          })
        : runnerResult({ schemaVersion: 1, operation: 'cleanup', ok: true })
    );

    await expect(provisioner.provision('dataProtocol')).rejects.toThrow(
      'Candidate fixture command failed'
    );
    expect(requests).toHaveLength(2);
    expect(JSON.parse(requests[1]?.stdin ?? '{}')).toMatchObject({ operation: 'cleanup' });
    expect(requests.every(({ shell }) => shell === false)).toBe(true);
  });

  it('preserves the primary error when partial cleanup also fails', async () => {
    const { provisioner } = createHarness((descriptor) =>
      descriptor.operation === 'provision'
        ? runnerResult('invalid')
        : runnerResult('cleanup invalid')
    );
    let caught: unknown;

    try {
      await provisioner.provision('dataProtocol');
    } catch (error: unknown) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(AggregateError);
    expect((caught as AggregateError).errors).toHaveLength(2);
    expect((caught as Error & { cause?: unknown }).cause).toBe(
      (caught as AggregateError).errors[0]
    );
    expect((caught as AggregateError).errors.map(String)).toEqual([
      'Error: Candidate fixture command failed',
      'Error: Candidate fixture cleanup command failed',
    ]);
  });

  it('requires a separately keyed foreign target for consentBoundary results', async () => {
    const { provisioner } = createHarness();
    const fixture = await provisioner.provision('consentBoundary');
    const [primary, foreign] = fixture.public.allocations;

    expect(fixture.foreignTarget).toEqual(foreignTarget);
    expect(primary?.isolation.persistenceId).not.toBe(foreign?.isolation.persistenceId);
    expect(primary?.isolation.cookieKeyId).not.toBe(foreign?.isolation.cookieKeyId);
    expect(primary?.isolation.signingKeyId).not.toBe(foreign?.isolation.signingKeyId);
  });

  it('rejects a foreign target from a different implementation label', () => {
    expect(() =>
      createCommandPhase1FixtureProvisioner({
        profile,
        target,
        foreignTarget: { ...foreignTarget, label: 'oracle' },
        runner: async () => runnerResult({ schemaVersion: 1, operation: 'cleanup', ok: true }),
      })
    ).toThrow('Candidate fixture command failed');
  });

  it.each([
    [
      'foreign core cross-swapped with primary admin',
      { ...foreignTarget, coreUrl: target.adminUrl },
    ],
    [
      'foreign admin cross-swapped with primary core',
      { ...foreignTarget, adminUrl: target.coreUrl },
    ],
    ['foreign core and admin duplicated', { ...foreignTarget, adminUrl: foreignTarget.coreUrl }],
    ['normalized foreign core alias', { ...foreignTarget, coreUrl: 'HTTP://LOCALHOST:3021' }],
  ])('rejects %s', (_name, invalidForeignTarget) => {
    expect(() =>
      createCommandPhase1FixtureProvisioner({
        profile,
        target,
        foreignTarget: invalidForeignTarget,
        runner: async () => runnerResult({ schemaVersion: 1, operation: 'cleanup', ok: true }),
      })
    ).toThrow('Candidate fixture command failed');
  });

  it('rejects a primary target whose canonical core and admin origins alias', () => {
    expect(() =>
      createCommandPhase1FixtureProvisioner({
        profile,
        target: { ...target, adminUrl: 'HTTP://LOCALHOST:3021' },
        foreignTarget,
        runner: async () => runnerResult({ schemaVersion: 1, operation: 'cleanup', ok: true }),
      })
    ).toThrow('Candidate fixture command failed');
  });

  it.each([
    ['exact duplicate', { ...target, adminUrl: target.coreUrl }],
    ['case and trailing-slash alias', { ...target, adminUrl: 'HTTP://LOCALHOST:3021' }],
    [
      'default-port alias',
      { ...target, coreUrl: 'http://localhost:80/', adminUrl: 'HTTP://LOCALHOST' },
    ],
  ])('rejects no-foreign primary origin %s', (_name, invalidTarget) => {
    expect(() =>
      createCommandPhase1FixtureProvisioner({
        profile,
        target: invalidTarget,
        runner: async () => runnerResult({ schemaVersion: 1, operation: 'cleanup', ok: true }),
      })
    ).toThrow('Candidate fixture command failed');
  });

  it('accepts no-foreign primary origins when canonical origins differ', () => {
    expect(() =>
      createCommandPhase1FixtureProvisioner({
        profile,
        target,
        runner: async () => runnerResult({ schemaVersion: 1, operation: 'cleanup', ok: true }),
      })
    ).not.toThrow();
  });

  it('rejects a command result that reuses an allocation from another fixture', async () => {
    const { provisioner } = createHarness();
    await provisioner.provision('dataProtocol');

    await expect(provisioner.provision('dataProtocol')).rejects.toThrow(
      'Candidate fixture command failed'
    );
  });

  it('rejects reuse of the private descriptor allocation ID even with fresh public IDs', async () => {
    let publicAllocation = 0;
    const provisioner = createCommandPhase1FixtureProvisioner({
      profile,
      target,
      runner: async (request: RunnerRequest) => {
        const descriptor = JSON.parse(request.stdin) as { operation: string; recipe: string };
        return descriptor.operation === 'cleanup'
          ? runnerResult({ schemaVersion: 1, operation: 'cleanup', ok: true })
          : runnerResult(
              provisionResult(
                descriptor.recipe as Phase1FixtureMap['recipe'],
                `fresh-${++publicAllocation}`
              )
            );
      },
      createAllocationId: () => 'reused-private-allocation',
      createSecret: () => seededPassword,
    });
    await provisioner.provision('dataProtocol');

    await expect(provisioner.provision('dataProtocol')).rejects.toThrow(
      'Candidate fixture command failed'
    );
    expect(publicAllocation).toBe(1);
  });

  it('rejects a descriptor that collides with another live fixture public allocation', async () => {
    const descriptorIds = ['descriptor-a', 'public-a-data'];
    let provisionCalls = 0;
    const provisioner = createCommandPhase1FixtureProvisioner({
      profile,
      target,
      runner: async (request: RunnerRequest) => {
        const descriptor = JSON.parse(request.stdin) as { operation: string };
        if (descriptor.operation === 'cleanup') {
          return runnerResult({ schemaVersion: 1, operation: 'cleanup', ok: true });
        }
        provisionCalls += 1;
        return runnerResult(
          provisionResult('dataProtocol', `public-${provisionCalls === 1 ? 'a' : 'b'}`)
        );
      },
      createAllocationId: () => descriptorIds.shift() ?? 'unexpected-descriptor',
      createSecret: () => seededPassword,
    });
    const fixture = await provisioner.provision('dataProtocol');

    await expect(provisioner.provision('dataProtocol')).rejects.toThrow(
      'Candidate fixture command failed'
    );
    expect(provisionCalls).toBe(1);
    await provisioner.cleanup(fixture);
  });

  it('rejects a public allocation that collides with another live fixture descriptor', async () => {
    const descriptorIds = ['descriptor-data', 'descriptor-b'];
    let provisionCalls = 0;
    let cleanupCalls = 0;
    const provisioner = createCommandPhase1FixtureProvisioner({
      profile,
      target,
      runner: async (request: RunnerRequest) => {
        const descriptor = JSON.parse(request.stdin) as { operation: string };
        if (descriptor.operation === 'cleanup') {
          cleanupCalls += 1;
          return runnerResult({ schemaVersion: 1, operation: 'cleanup', ok: true });
        }
        provisionCalls += 1;
        return runnerResult(
          provisionResult('dataProtocol', provisionCalls === 1 ? 'public-a' : 'descriptor')
        );
      },
      createAllocationId: () => descriptorIds.shift() ?? 'unexpected-descriptor',
      createSecret: () => seededPassword,
    });
    const fixture = await provisioner.provision('dataProtocol');

    await expect(provisioner.provision('dataProtocol')).rejects.toThrow(
      'Candidate fixture command failed'
    );
    expect(provisionCalls).toBe(2);
    expect(cleanupCalls).toBe(1);
    await provisioner.cleanup(fixture);
  });

  it('allows one fixture to use the same descriptor and public allocation ID', async () => {
    const provisioner = createCommandPhase1FixtureProvisioner({
      profile,
      target,
      runner: async (request: RunnerRequest) => {
        const descriptor = JSON.parse(request.stdin) as { operation: string };
        return descriptor.operation === 'cleanup'
          ? runnerResult({ schemaVersion: 1, operation: 'cleanup', ok: true })
          : runnerResult(provisionResult('dataProtocol', 'same'));
      },
      createAllocationId: () => 'same-data',
      createSecret: () => seededPassword,
    });

    const fixture = await provisioner.provision('dataProtocol');
    await expect(provisioner.cleanup(fixture)).resolves.toBeUndefined();
  });
});

describe('default candidate command process-group fencing', () => {
  const resistantDescendant =
    "process.on('SIGTERM', () => {}); setInterval(() => undefined, 1000);";

  it('fences a TERM-resistant descendant after a normally exiting leader', async () => {
    await withPrivateExecutable(
      [
        "const { spawn } = require('node:child_process');",
        "const { writeFileSync } = require('node:fs');",
        `const child = spawn(process.execPath, ['-e', ${JSON.stringify(
          resistantDescendant
        )}], { stdio: 'ignore' });`,
        'child.unref();',
        "writeFileSync(require('node:path').join(__dirname, 'pids.json'), JSON.stringify([process.pid, child.pid]));",
        "process.stdout.write('{}');",
      ].join('\n'),
      async (commandPath, directory) => {
        const result = await runPhase1FixtureCommand(runnerRequest(commandPath));
        const pids = await readOwnedPids(directory);

        expect(result).toMatchObject({ exitCode: 0, timedOut: false, killed: false, reaped: true });
        expect(pids).toHaveLength(2);
        expect(pids.every((pid) => processIsGone(pid))).toBe(true);
      }
    );
  });

  it('kills and reaps the exact owned group on timeout', async () => {
    await withPrivateExecutable(
      [
        "const { spawn } = require('node:child_process');",
        "const { writeFileSync } = require('node:fs');",
        "process.on('SIGTERM', () => {});",
        `const child = spawn(process.execPath, ['-e', ${JSON.stringify(
          resistantDescendant
        )}], { stdio: 'ignore' });`,
        "writeFileSync(require('node:path').join(__dirname, 'pids.json'), JSON.stringify([process.pid, child.pid]));",
        'setInterval(() => undefined, 1000);',
      ].join('\n'),
      async (commandPath, directory) => {
        const result = await runPhase1FixtureCommand(runnerRequest(commandPath, { timeoutMs: 50 }));
        const pids = await readOwnedPids(directory);

        expect(result).toMatchObject({ timedOut: true, killed: true, reaped: true });
        expect(pids.every((pid) => processIsGone(pid))).toBe(true);
      }
    );
  });

  it('fences output overflow, missing spawn, and stdin EPIPE terminal paths', async () => {
    const overflow = await withPrivateExecutable(
      "process.stdout.write('x'.repeat(8192)); setInterval(() => undefined, 1000);",
      async (commandPath) =>
        runPhase1FixtureCommand(runnerRequest(commandPath, { maxStdoutBytes: 32 }))
    );
    expect(overflow).toMatchObject({ killed: true, reaped: true });
    expect(Buffer.byteLength(overflow.stdout)).toBeLessThanOrEqual(33);

    const missing = await runPhase1FixtureCommand(
      runnerRequest('/var/tmp/henry-build/aster-missing-command')
    );
    expect(missing).toMatchObject({ killed: true, reaped: true });

    const epipe = await withPrivateExecutable(
      "require('node:fs').closeSync(0); setInterval(() => undefined, 1000);",
      async (commandPath) =>
        runPhase1FixtureCommand(
          runnerRequest(commandPath, { stdin: 'x'.repeat(2_000_000), timeoutMs: 2000 })
        )
    );
    expect(epipe).toMatchObject({ timedOut: false, killed: true, reaped: true });
  });
});

/* eslint-enable max-lines, @typescript-eslint/ban-types, prefer-destructuring, @silverhand/fp/no-mutating-methods, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/consistent-type-assertions, no-await-in-loop, @typescript-eslint/no-unnecessary-condition, @typescript-eslint/no-unnecessary-boolean-literal-compare */
