/* eslint-disable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment -- The fake Management API and coordinator journal intentionally model mutable partial-apply and rollback state. */
import type { TargetConfig } from '../model.js';
import type {
  CommandRunnerRequest,
  CommandRunnerResult,
} from '../phase-1/clients/command-provisioner.js';

import { observeClientCredentialsToken } from './clients/client-credentials.js';
import {
  createCandidatePhase2FixtureProvisioner,
  createReferencePhase2FixtureProvisioner,
  phase2FixtureContract,
  runWithPhase2Fixture,
  type Phase2AdminRequest,
} from './fixtures.js';

const oracle: TargetConfig = Object.freeze({
  label: 'oracle',
  coreUrl: 'http://127.0.0.1:4101/',
  adminUrl: 'http://127.0.0.1:4102/',
});

const oracleForeign: TargetConfig = Object.freeze({
  label: 'oracle',
  coreUrl: 'http://127.0.0.1:4103/',
  adminUrl: 'http://127.0.0.1:4104/',
});
const candidate: TargetConfig = Object.freeze({
  label: 'candidate',
  coreUrl: 'http://127.0.0.1:4201/',
  adminUrl: 'http://127.0.0.1:4202/',
});
const candidateForeign: TargetConfig = Object.freeze({
  label: 'candidate',
  coreUrl: 'http://127.0.0.1:4203/',
  adminUrl: 'http://127.0.0.1:4204/',
});

const commandResult = (stdout: string): CommandRunnerResult => ({
  exitCode: 0,
  signal: null,
  stdout,
  stderr: '',
  timedOut: false,
  killed: false,
  reaped: true,
});

const rejectedCommandResult = (): CommandRunnerResult => ({
  ...commandResult(''),
  exitCode: 1,
  stderr: 'Aster compatibility fixture command failed\n',
});

const createReferenceAdmin = () => {
  const calls: Phase2AdminRequest[] = [];
  const ids = new Map<string, number>();
  const entityRows = new Map<string, Array<Record<string, unknown>>>();
  const nextId = (prefix: string) => {
    const next = (ids.get(prefix) ?? 0) + 1;
    ids.set(prefix, next);
    return `${prefix}-${next}`;
  };
  const request = async (input: Phase2AdminRequest): Promise<unknown> => {
    calls.push(input);
    if (input.method === 'GET') {
      if (/^applications\/[^/]+\/secrets$/u.test(input.path)) {
        return [{ value: 'ReferenceSecretValue000000000001' }];
      }
      if (input.path === 'sign-in-exp') {
        return {
          signInMode: 'SignInAndRegister',
          signUp: { identifiers: [], password: false, verify: false },
          signIn: { methods: [] },
          mfa: { factors: [], policy: 'PromptAtSignInAndSignUp' },
        };
      }
      return entityRows.get(input.path) ?? [];
    }
    if (input.method === 'DELETE' || input.method === 'PATCH') {
      if (input.method === 'DELETE') {
        for (const [collection, rows] of entityRows) {
          const prefix = `${collection}/`;
          if (input.path.startsWith(prefix)) {
            const id = decodeURIComponent(input.path.slice(prefix.length).split('/')[0] ?? '');
            entityRows.set(
              collection,
              rows.filter((row) => row.id !== id)
            );
          }
        }
      }
      return input.method === 'DELETE' ? 204 : {};
    }
    if (input.responseKind === 'created') {
      return undefined;
    }
    const prefix = input.path.includes('/scopes')
      ? 'scope'
      : input.path === 'applications'
        ? 'application'
        : input.path === 'users'
          ? 'user'
          : input.path === 'resources'
            ? 'resource'
            : input.path === 'roles'
              ? 'role'
              : input.path === 'organizations'
                ? 'organization'
                : input.path === 'organization-scopes'
                  ? 'organization-scope'
                  : 'organization-role';
    return { id: nextId(prefix) };
  };
  return { calls, entityRows, request };
};

describe('Phase 2 fixture lifecycle', () => {
  it('freezes the exact two-client, two-resource, organization contract', () => {
    expect(phase2FixtureContract).toEqual({
      clients: { basic: 'phase2-m2m-basic', post: 'phase2-m2m-post' },
      resources: {
        primary: 'https://phase2.example.invalid/api-primary',
        default: 'https://phase2.example.invalid/api-default',
      },
      organization: { id: 'phase2-org', scope: 'organization:read' },
      scopes: ['read', 'write', 'unassigned'],
    });
    expect(Object.isFrozen(phase2FixtureContract)).toBe(true);
  });

  it('provisions the reference in dependency order and cleans up in exact reverse order', async () => {
    const admin = createReferenceAdmin();
    const provisioner = createReferencePhase2FixtureProvisioner({
      target: oracle,
      foreignTarget: oracleForeign,
      request: admin.request,
      createAllocationId: () => 'reference-fixture',
    });
    const fixture = await provisioner.provision();
    expect(fixture.public.boundary).toEqual({ primary: 'provisioned', foreign: 'unchanged' });
    await fixture.withSecretLease(async (lease) => {
      expect(lease.getClientSecret('basic')).toBe('ReferenceSecretValue000000000001');
      expect(lease.getSubjectPassword?.()).toMatch(/A1!$/u);
      expect(() => JSON.stringify(lease)).toThrow('Phase 2 fixture operation failed');
    });
    expect(fixture.status).toMatchObject({
      user: { id: 'user-1', username: expect.stringMatching(/^phase1_user_a_[0-9a-f]{16}$/u) },
      client: { id: 'application-3', redirectUri: 'http://localhost:3001/demo-app' },
      resource: { indicator: 'https://api.example.com' },
    });
    expect(Object.keys(fixture.public)).not.toContain('status');
    expect(admin.calls).toContainEqual(
      expect.objectContaining({
        method: 'POST',
        path: 'applications/application-3/user-consent-scopes',
        body: {
          userScopes: ['profile', 'email', 'address', 'phone'],
          resourceScopes: ['scope-4'],
        },
      })
    );
    await provisioner.cleanup(fixture);

    const deletes = admin.calls.filter(({ method }) => method === 'DELETE').map(({ path }) => path);
    expect(deletes.slice(0, 5)).toEqual([
      'applications/application-3',
      'roles/role-2',
      'resources/resource-3/scopes/scope-4',
      'resources/resource-3',
      'users/user-1',
    ]);
    expect(deletes.slice(5, 10)).toEqual([
      'organizations/organization-1/applications/application-1/roles/organization-role-3',
      'organizations/organization-1/applications/application-1',
      'organization-roles/organization-role-3',
      'organization-scopes/organization-scope-1',
      'organizations/organization-1',
    ]);
    expect(deletes).toContain('applications/application-1');
    expect(deletes).toContain('applications/application-2');
    expect(admin.calls).toContainEqual(
      expect.objectContaining({
        method: 'PATCH',
        path: 'sign-in-exp',
        body: {
          signInMode: 'SignInAndRegister',
          signUp: { identifiers: [], password: false, verify: false },
          signIn: { methods: [] },
          mfa: { factors: [], policy: 'PromptAtSignInAndSignUp' },
        },
      })
    );
    expect(JSON.stringify(fixture.public)).not.toContain('ReferenceSecretValue');
    await expect(
      fixture.withSecretLease(async (lease) => lease.getClientSecret('basic'))
    ).rejects.toThrow('Phase 2 fixture operation failed');
  });

  it('routes every reference Management request through the data-tenant core URL', async () => {
    const originalFetch = globalThis.fetch;
    const requestedUrls: string[] = [];
    globalThis.fetch = (async (input) => {
      requestedUrls.push(String(input));
      throw new Error('stop after observing the Management origin');
    }) as typeof fetch;
    try {
      const provisioner = createReferencePhase2FixtureProvisioner({
        target: oracle,
        foreignTarget: oracleForeign,
        createAllocationId: () => 'management-origin',
      });
      await expect(provisioner.provision()).rejects.toThrow('Phase 2 fixture operation failed');
    } finally {
      globalThis.fetch = originalFetch;
    }

    expect(requestedUrls.length).toBeGreaterThan(0);
    expect(requestedUrls.every((url) => url.startsWith(oracle.coreUrl))).toBe(true);
    expect(requestedUrls.some((url) => url.startsWith(oracle.adminUrl))).toBe(false);
  });

  it('reconciles owned reference rows after partial provisioning failure', async () => {
    const admin = createReferenceAdmin();
    let posts = 0;
    admin.entityRows.set('applications', [
      { id: 'orphan-app', name: 'Phase 2 phase2-client-credentials-partial basic client' },
    ]);
    admin.entityRows.set('resources', [
      { id: 'previous-partial-default', name: 'existing default', isDefault: true },
    ]);
    const provisioner = createReferencePhase2FixtureProvisioner({
      target: oracle,
      foreignTarget: oracleForeign,
      createAllocationId: () => 'partial',
      request: async (request) => {
        if (request.method === 'POST') {
          posts += 1;
          if (posts === 2) {
            throw new Error('planted failure');
          }
        }
        return admin.request(request);
      },
    });
    await expect(provisioner.provision()).rejects.toThrow('Phase 2 fixture operation failed');
    expect(admin.calls).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ method: 'DELETE', path: 'applications/orphan-app' }),
      ])
    );
    expect(admin.calls).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          method: 'PATCH',
          path: 'resources/previous-partial-default/is-default',
          body: { isDefault: true },
        }),
      ])
    );
  });

  it('restores the exact previous reference default and rejects multiple defaults', async () => {
    const admin = createReferenceAdmin();
    admin.entityRows.set('resources', [
      { id: 'previous-default', name: 'existing', isDefault: true },
    ]);
    const provisioner = createReferencePhase2FixtureProvisioner({
      target: oracle,
      foreignTarget: oracleForeign,
      request: admin.request,
      createAllocationId: () => 'restore-default',
    });
    const fixture = await provisioner.provision();
    await provisioner.cleanup(fixture);
    expect(admin.calls).toContainEqual(
      expect.objectContaining({
        method: 'PATCH',
        path: 'resources/previous-default/is-default',
        body: { isDefault: true },
      })
    );

    const multiple = createReferenceAdmin();
    multiple.entityRows.set('resources', [
      { id: 'one', isDefault: true },
      { id: 'two', isDefault: true },
    ]);
    const rejected = createReferencePhase2FixtureProvisioner({
      target: oracle,
      foreignTarget: oracleForeign,
      request: multiple.request,
      createAllocationId: () => 'multiple-defaults',
    });
    await expect(rejected.provision()).rejects.toThrow('Phase 2 fixture operation failed');
    expect(multiple.calls.some(({ method }) => method === 'POST')).toBe(false);
  });

  it('uses the Aster fixture coordinator with a secret-safe closed descriptor', async () => {
    const requests: CommandRunnerRequest[] = [];
    let fencedCalls = 0;
    let cleanupCalls = 0;
    const runner = async (request: CommandRunnerRequest): Promise<CommandRunnerResult> => {
      requests.push(request);
      const descriptor = JSON.parse(request.stdin) as Record<string, unknown>;
      const { operation } = descriptor;
      if (operation === 'provision') {
        return commandResult(
          JSON.stringify({
            schemaVersion: 1,
            operation: 'provision',
            public: {
              schemaVersion: 1,
              recipe: 'dataProtocol',
              allocations: [
                {
                  allocationId: 'candidate-fixture',
                  role: 'data',
                  target: 'primary',
                  entities: [],
                },
              ],
            },
          })
        );
      }
      if (operation === 'projectState') {
        return commandResult(
          JSON.stringify({
            schemaVersion: 1,
            operation: 'projectState',
            projection: { allocations: [] },
          })
        );
      }
      cleanupCalls += 1;
      return cleanupCalls === 1
        ? commandResult(JSON.stringify({ schemaVersion: 1, operation: 'cleanup', ok: true }))
        : rejectedCommandResult();
    };
    const secrets = ['a'.repeat(32), 'b'.repeat(32), 'c'.repeat(32)];
    const provisioner = createCandidatePhase2FixtureProvisioner({
      executablePath: '/usr/bin/true',
      target: candidate,
      foreignTarget: candidateForeign,
      environment: { PATH: '/usr/bin:/bin', ASTER_FIXTURE_SOCKET: '/tmp/phase2-fixture.sock' },
      runner,
      createAllocationId: () => 'candidate-fixture',
      createSecret: () => secrets.shift() ?? 'unexpected',
      identityFence: {
        assertStable: async () => {
          // The fake identity remains stable during this coordinator contract test.
        },
        run: async <Result>(operation: () => Promise<Result>) => {
          fencedCalls += 1;
          return operation();
        },
      },
    });
    const fixture = await provisioner.provision();
    expect(fixture.public.clients).toEqual({
      basic: { id: 'phase2-m2m-basic', method: 'client_secret_basic' },
      post: { id: 'phase2-m2m-post', method: 'client_secret_post' },
    });
    expect(fixture.status).toMatchObject({
      user: { id: 'zdata-user', username: expect.stringMatching(/^phase1_user_a_[0-9a-f]{16}$/u) },
      client: { id: 'phase1-browser', redirectUri: 'http://localhost:3001/demo-app' },
      resource: { id: 'phase1-api', indicator: 'https://api.example.com' },
    });
    await fixture.withSecretLease(async (lease) => {
      expect(lease.getSubjectPassword?.()).toBe('c'.repeat(32));
    });
    expect(JSON.stringify(fixture.public)).not.toContain('c'.repeat(32));
    expect(await provisioner.projectState(fixture)).toEqual({ allocations: [] });
    await provisioner.cleanup(fixture);

    const provision = JSON.parse(requests[0]?.stdin ?? '{}');
    expect(provision).toMatchObject({
      schemaVersion: 1,
      operation: 'provision',
      recipe: 'dataProtocol',
      allocationId: 'candidate-fixture',
      profile: {
        fixtures: {
          phase2: {
            machineClients: [
              {
                clientId: 'phase2-m2m-basic',
                grantTypes: ['client_credentials'],
                resourceScopeIds: ['read-scope', 'write-scope'],
              },
              {
                clientId: 'phase2-m2m-post',
                grantTypes: ['client_credentials'],
                resourceScopeIds: ['read-scope', 'write-scope'],
                organizations: [],
              },
            ],
            defaultResourceId: 'phase2-resource',
          },
        },
      },
    });
    expect(
      requests.every(({ env }) =>
        Object.keys(env).every((key) =>
          [
            'ASTER_FIXTURE_SOCKET',
            'ASTER_TARGET_LABEL',
            'ASTER_CORE_URL',
            'ASTER_ADMIN_URL',
            'ASTER_FOREIGN_CORE_URL',
            'ASTER_FOREIGN_ADMIN_URL',
            'LC_ALL',
          ].includes(key)
        )
      )
    ).toBe(true);
    expect(requests.map(({ command, args, shell }) => ({ command, args, shell }))).toEqual([
      { command: '/usr/bin/true', args: ['fixture', 'apply'], shell: false },
      { command: '/usr/bin/true', args: ['fixture', 'apply'], shell: false },
      { command: '/usr/bin/true', args: ['fixture', 'apply'], shell: false },
      { command: '/usr/bin/true', args: ['fixture', 'apply'], shell: false },
    ]);
    expect(fencedCalls).toBe(4);
    const projectDescriptor = JSON.parse(requests[1]?.stdin ?? '{}') as {
      public?: { recipe?: string; allocations?: Array<{ allocationId?: string }> };
    };
    const cleanupDescriptors = [requests[2], requests[3]].map((request) =>
      JSON.parse(request?.stdin ?? '{}')
    ) as Array<{
      public?: { recipe?: string; allocations?: Array<{ allocationId?: string }> };
    }>;
    for (const descriptor of [projectDescriptor, ...cleanupDescriptors]) {
      expect(descriptor.public).toMatchObject({
        recipe: 'dataProtocol',
        allocations: [{ allocationId: 'candidate-fixture' }],
      });
      expect(descriptor.public).not.toHaveProperty('clients');
    }
  });

  it('reconciles one failed candidate provision and retries the exact descriptor once', async () => {
    const requests: CommandRunnerRequest[] = [];
    let provisionAttempts = 0;
    let cleanupCalls = 0;
    const runner = async (request: CommandRunnerRequest): Promise<CommandRunnerResult> => {
      requests.push(request);
      const descriptor = JSON.parse(request.stdin) as { operation?: string };
      if (descriptor.operation === 'provision') {
        provisionAttempts += 1;
        if (provisionAttempts === 1) {
          return {
            ...commandResult(''),
            exitCode: 1,
            stderr: 'Aster compatibility fixture command failed\n',
          };
        }
        return commandResult(
          JSON.stringify({
            schemaVersion: 1,
            operation: 'provision',
            public: {
              schemaVersion: 1,
              recipe: 'dataProtocol',
              allocations: [
                {
                  allocationId: 'candidate-retry',
                  role: 'data',
                  target: 'primary',
                  entities: [],
                },
              ],
            },
          })
        );
      }
      if (descriptor.operation === 'cleanup') {
        cleanupCalls += 1;
        return cleanupCalls % 2 === 1
          ? commandResult(JSON.stringify({ schemaVersion: 1, operation: 'cleanup', ok: true }))
          : rejectedCommandResult();
      }
      return commandResult(
        JSON.stringify({
          schemaVersion: 1,
          operation: 'projectState',
          projection: { allocations: [] },
        })
      );
    };
    const secrets = ['a'.repeat(32), 'b'.repeat(32), 'c'.repeat(32)];
    const provisioner = createCandidatePhase2FixtureProvisioner({
      executablePath: '/usr/bin/true',
      target: candidate,
      foreignTarget: candidateForeign,
      environment: { ASTER_FIXTURE_SOCKET: '/tmp/phase2-fixture.sock' },
      createAllocationId: () => 'candidate-retry',
      createSecret: () => secrets.shift() ?? 'unexpected',
      runner,
    });

    const fixtureValue = await provisioner.provision();
    await provisioner.cleanup(fixtureValue);

    expect(requests.map(({ stdin }) => JSON.parse(stdin).operation)).toEqual([
      'provision',
      'cleanup',
      'cleanup',
      'provision',
      'cleanup',
      'cleanup',
    ]);
    const provisions = requests.filter(({ stdin }) => JSON.parse(stdin).operation === 'provision');
    expect(provisions).toHaveLength(2);
    expect(provisions[0]?.stdin).toBe(provisions[1]?.stdin);
    expect(JSON.parse(requests[1]?.stdin ?? '{}')).not.toHaveProperty('public');
    expect(JSON.parse(requests[2]?.stdin ?? '{}')).not.toHaveProperty('public');
    expect(JSON.parse(requests[4]?.stdin ?? '{}')).toHaveProperty('public');
    expect(JSON.parse(requests[5]?.stdin ?? '{}')).toHaveProperty('public');
  });

  it('rejects coordinator output that leaks the private subject password', async () => {
    const planted = ['a'.repeat(32), 'b'.repeat(32), 'c'.repeat(32)];
    let cleanupCalls = 0;
    const provisioner = createCandidatePhase2FixtureProvisioner({
      executablePath: '/usr/bin/true',
      target: candidate,
      foreignTarget: candidateForeign,
      environment: { PATH: '/usr/bin:/bin', ASTER_FIXTURE_SOCKET: '/tmp/phase2-fixture.sock' },
      createAllocationId: () => 'candidate-leak',
      createSecret: () => planted.shift() ?? 'unexpected',
      runner: async (request) => {
        const descriptor = JSON.parse(request.stdin) as { operation?: string };
        if (descriptor.operation === 'cleanup') {
          cleanupCalls += 1;
          return cleanupCalls % 2 === 1
            ? commandResult(JSON.stringify({ schemaVersion: 1, operation: 'cleanup', ok: true }))
            : rejectedCommandResult();
        }
        return commandResult(
          JSON.stringify({
            schemaVersion: 1,
            operation: 'provision',
            public: { leaked: 'c'.repeat(32) },
          })
        );
      },
    });
    await expect(provisioner.provision()).rejects.toThrow('Phase 2 fixture operation failed');
  });

  it('generates production candidate secrets as exact 32 lowercase alphanumeric characters', async () => {
    let provisionDescriptor: any;
    let cleanupCalls = 0;
    const provisioner = createCandidatePhase2FixtureProvisioner({
      executablePath: '/usr/bin/true',
      target: candidate,
      foreignTarget: candidateForeign,
      environment: { ASTER_FIXTURE_SOCKET: '/tmp/phase2-fixture.sock' },
      createAllocationId: () => 'production-secrets',
      runner: async (request) => {
        const input = JSON.parse(request.stdin);
        if (input.operation === 'provision') {
          provisionDescriptor = input;
          return commandResult(
            JSON.stringify({
              schemaVersion: 1,
              operation: 'provision',
              public: {
                schemaVersion: 1,
                recipe: 'dataProtocol',
                allocations: [
                  {
                    allocationId: 'production-secrets',
                    role: 'data',
                    target: 'primary',
                    entities: [],
                  },
                ],
              },
            })
          );
        }
        if (input.operation === 'projectState') {
          return commandResult(
            JSON.stringify({
              schemaVersion: 1,
              operation: 'projectState',
              projection: { allocations: [] },
            })
          );
        }
        cleanupCalls += 1;
        return cleanupCalls === 1
          ? commandResult(JSON.stringify({ schemaVersion: 1, operation: 'cleanup', ok: true }))
          : rejectedCommandResult();
      },
    });
    const fixtureValue = await provisioner.provision();
    const serialized = JSON.stringify(provisionDescriptor);
    for (const seed of [
      ...provisionDescriptor.seeds.passwords,
      ...provisionDescriptor.seeds.clientSecrets,
    ]) {
      expect(seed.value).toMatch(/^[a-z0-9]{32}$/u);
    }
    expect(
      new Set(
        [...provisionDescriptor.seeds.passwords, ...provisionDescriptor.seeds.clientSecrets].map(
          (seed: any) => seed.value
        )
      ).size
    ).toBe(3);
    expect(JSON.stringify(fixtureValue.public)).not.toContain(
      provisionDescriptor.seeds.clientSecrets[0].value
    );
    expect(serialized).toContain('clientSecrets');
    await provisioner.cleanup(fixtureValue);
  });

  it('rejects reference and candidate cleanup acknowledgements that leave fixture state behind', async () => {
    const admin = createReferenceAdmin();
    const reference = createReferencePhase2FixtureProvisioner({
      target: oracle,
      foreignTarget: oracleForeign,
      createAllocationId: () => 'noop-reference',
      request: async (request) => (request.method === 'DELETE' ? 204 : admin.request(request)),
    });
    const referenceFixture = await reference.provision();
    admin.entityRows.set('applications', [
      {
        id: 'left-behind',
        name: 'Phase 2 phase2-client-credentials-noop-reference basic client',
      },
    ]);
    await expect(reference.cleanup(referenceFixture)).rejects.toThrow(
      'Phase 2 fixture cleanup failed'
    );

    const candidateProvisioner = createCandidatePhase2FixtureProvisioner({
      executablePath: '/usr/bin/true',
      target: candidate,
      foreignTarget: candidateForeign,
      environment: { ASTER_FIXTURE_SOCKET: '/tmp/phase2-fixture.sock' },
      createAllocationId: () => 'noop-candidate',
      createSecret: (() => {
        const values = ['a'.repeat(32), 'b'.repeat(32), 'c'.repeat(32)];
        return () => values.shift() ?? 'unexpected';
      })(),
      runner: async (request) => {
        const descriptor = JSON.parse(request.stdin) as { operation?: string };
        if (descriptor.operation === 'provision') {
          return commandResult(
            JSON.stringify({
              schemaVersion: 1,
              operation: 'provision',
              public: {
                schemaVersion: 1,
                recipe: 'dataProtocol',
                allocations: [
                  {
                    allocationId: 'noop-candidate',
                    role: 'data',
                    target: 'primary',
                    entities: [],
                  },
                ],
              },
            })
          );
        }
        if (descriptor.operation === 'cleanup') {
          return commandResult(
            JSON.stringify({ schemaVersion: 1, operation: 'cleanup', ok: true })
          );
        }
        return commandResult(
          JSON.stringify({
            schemaVersion: 1,
            operation: 'projectState',
            projection: { allocations: [{ allocationId: 'noop-candidate' }] },
          })
        );
      },
    });
    const candidateFixture = await candidateProvisioner.provision();
    await expect(candidateProvisioner.cleanup(candidateFixture)).rejects.toThrow(
      'Phase 2 fixture cleanup failed'
    );
  });

  it('runs cleanup when fixture use fails and does not publish leased secrets', async () => {
    const admin = createReferenceAdmin();
    const provisioner = createReferencePhase2FixtureProvisioner({
      target: oracle,
      foreignTarget: oracleForeign,
      request: admin.request,
      createAllocationId: () => 'use-failure',
    });
    await expect(
      runWithPhase2Fixture(provisioner, async (fixture) =>
        fixture.withSecretLease(async () => {
          throw new Error('scenario failed');
        })
      )
    ).rejects.toThrow('scenario failed');
    expect(admin.calls.some(({ method }) => method === 'DELETE')).toBe(true);
  });

  it('runs fixture cleanup after a hanging token transport reaches its deadline', async () => {
    const admin = createReferenceAdmin();
    const provisioner = createReferencePhase2FixtureProvisioner({
      target: oracle,
      foreignTarget: oracleForeign,
      request: admin.request,
      createAllocationId: () => 'hanging-request',
    });
    await expect(
      runWithPhase2Fixture(provisioner, async (fixtureValue) =>
        fixtureValue.withSecretLease(async (lease) =>
          observeClientCredentialsToken(
            new URL('/oidc/token', oracle.coreUrl),
            { keys: [{ kty: 'EC', kid: 'hanging-key' }] },
            {
              method: 'client_secret_basic',
              clientId: fixtureValue.public.clients.basic.id,
              clientSecret: lease.getClientSecret('basic'),
              resource: fixtureValue.public.resources.primary.indicator,
            },
            {
              fetch: (async () =>
                new Promise<Response>(() => {
                  // Intentionally unresolved to prove fixture cleanup after the deadline.
                })) as typeof fetch,
              timeoutMs: 20,
            }
          )
        )
      )
    ).rejects.toThrow('Client credentials request failed');
    expect(admin.calls.some(({ method }) => method === 'DELETE')).toBe(true);
  });

  it('rejects aliased primary and foreign boundaries', () => {
    expect(() =>
      createReferencePhase2FixtureProvisioner({
        target: oracle,
        foreignTarget: oracle,
      })
    ).toThrow('Phase 2 fixture operation failed');
    expect(() =>
      createCandidatePhase2FixtureProvisioner({
        executablePath: '/usr/bin/true',
        target: candidate,
        foreignTarget: candidate,
        environment: { ASTER_FIXTURE_SOCKET: '/tmp/socket' },
      })
    ).toThrow('Phase 2 fixture operation failed');
  });
});

/* eslint-enable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment */
