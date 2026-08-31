/* eslint-disable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, unicorn/no-useless-undefined, unicorn/consistent-function-scoping, @typescript-eslint/no-confusing-void-expression, no-await-in-loop, @typescript-eslint/no-throw-literal -- Lease and lifecycle tests retain revoked handles, mutate hostile descriptors, record ordered events, and exercise sequential unsafe-value matrices. */
import { inspect } from 'node:util';

import type { TargetConfig } from '../model.js';

import { createPhase1FixtureMap, type Phase1FixtureMap } from './fixture-map.js';
import {
  assertPhase1FixtureAllocationsAreDistinct,
  assertPhase1RuntimeCredentialGraphIsSanitized,
  createProvisionedPhase1Fixture,
  phase1TargetOriginsArePairwiseDisjoint,
  revokeProvisionedPhase1Fixture,
  runWithPhase1Fixture,
  type Phase1FixtureProvisioner,
  type ProvisionedPhase1Fixture,
} from './fixtures.js';

const secret = 'seeded-password-value-7391';
const clientSecret = 'seeded-client-secret-value-8427';
const compactJose = 'eyJhbGciOiJIUzI1NiJ9.e30.c2ln';
const credentialValues = [
  compactJose,
  'Bearer unrelated-opaque-credential',
  'Cookie: sid=unrelated-opaque-credential',
  'Set-Cookie: sid=unrelated-opaque-credential; Path=/; Secure',
  'sid=unrelated-opaque-credential; Path=/; Secure; HttpOnly',
  '  sid=unrelated-opaque-credential  ',
  '-----BEGIN PRIVATE KEY-----',
] as const;

const target = (port: number): TargetConfig => ({
  label: 'oracle',
  coreUrl: `http://localhost:${port}/`,
  adminUrl: `http://localhost:${port + 1}/`,
});

const map = (allocationId = 'experience-fixture-1'): Phase1FixtureMap =>
  createPhase1FixtureMap({
    schemaVersion: 1,
    recipe: 'dataProtocol',
    allocations: [
      {
        allocationId,
        role: 'data',
        target: 'primary',
        isolation: {
          persistenceId: `${allocationId}-persistence`,
          cookieKeyId: `${allocationId}-cookie-key`,
          signingKeyId: `${allocationId}-signing-key`,
        },
        entities: [
          { kind: 'tenant', logicalId: 'default', runtimeId: `${allocationId}-tenant` },
          { kind: 'user', logicalId: 'phase1-user', runtimeId: `${allocationId}-user` },
          {
            kind: 'application',
            logicalId: 'phase1-app',
            runtimeId: `${allocationId}-first-party`,
          },
          {
            kind: 'application',
            logicalId: 'phase1-browser',
            runtimeId: `${allocationId}-client`,
          },
          { kind: 'resource', logicalId: 'phase1-api', runtimeId: `${allocationId}-resource` },
          {
            kind: 'scope',
            logicalId: 'phase1-read-profile',
            runtimeId: `${allocationId}-scope`,
          },
          { kind: 'role', logicalId: 'phase1-reader', runtimeId: `${allocationId}-role` },
        ],
      },
    ],
  });

const provisioned = (allocationId?: string): ProvisionedPhase1Fixture =>
  createProvisionedPhase1Fixture({
    public: map(allocationId),
    passwords: [{ logicalId: 'phase1-user', value: secret }],
    clientSecrets: [{ logicalId: 'phase1-browser', value: clientSecret }],
  });

describe('ProvisionedPhase1Fixture secret leases', () => {
  it('exposes only callback-scoped seeded secrets and revokes the lease on settlement', async () => {
    const fixture = provisioned();
    let retainedLease:
      | Parameters<Parameters<ProvisionedPhase1Fixture['withSecretLease']>[0]>[0]
      | undefined;

    await fixture.withSecretLease(async (lease) => {
      retainedLease = lease;
      expect(lease.getPassword('phase1-user')).toBe(secret);
      expect(lease.getClientSecret('phase1-browser')).toBe(clientSecret);
      expect(lease.getClientSecret('phase1-app')).toBeUndefined();
      expect(inspect(lease)).toBe('Phase1FixtureSecretLease { [REDACTED] }');
      expect(inspect(lease)).not.toContain(secret);
      expect(() => JSON.stringify(lease)).toThrow('Secret lease serialization is forbidden');
      expect(() => structuredClone(lease)).toThrow();
    });

    expect(() => retainedLease?.getPassword('phase1-user')).toThrow('Secret lease is revoked');
    expect(inspect(fixture)).toBe('ProvisionedPhase1Fixture { recipe: dataProtocol }');
    expect(inspect(fixture)).not.toContain(secret);
    expect(JSON.stringify(fixture)).not.toContain(secret);
  });

  it('revokes leases after callback rejection without exposing secret-bearing errors', async () => {
    const fixture = provisioned();
    let retainedLease:
      | Parameters<Parameters<ProvisionedPhase1Fixture['withSecretLease']>[0]>[0]
      | undefined;

    await expect(
      fixture.withSecretLease(async (lease) => {
        retainedLease = lease;
        throw new Error(`failed with ${lease.getPassword('phase1-user')}`);
      })
    ).rejects.toThrow('Secret lease callback failed');
    expect(() => retainedLease?.getPassword('phase1-user')).toThrow('Secret lease is revoked');
  });

  it('rejects returning a seeded secret from the callback', async () => {
    const fixture = provisioned();

    await expect(
      fixture.withSecretLease(async (lease) => lease.getPassword('phase1-user'))
    ).rejects.toThrow('Secret lease result is not redacted');
  });

  it('deep-freezes sanitized results before a retained callback reference can mutate them', async () => {
    const fixture = provisioned();
    let mutationSucceeded: boolean | undefined;
    let markMutationDone: (() => void) | undefined;
    const mutationDone = new Promise<void>((resolve) => {
      markMutationDone = resolve;
    });
    const result = await fixture.withSecretLease(async (lease) => {
      const captured = lease.getPassword('phase1-user');
      const nested: Record<string, unknown> = {};

      setTimeout(() => {
        mutationSucceeded = Reflect.set(nested, 'lateValue', captured);
        markMutationDone?.();
      }, 0);

      return { nested };
    });

    await mutationDone;
    expect(mutationSucceeded).toBe(false);
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.nested)).toBe(true);
    expect(JSON.stringify(result)).not.toContain(secret);
  });

  it('freezes lease and fixture prototypes against captured-secret method replacement', async () => {
    const fixture = provisioned();

    await fixture.withSecretLease(async (lease) => {
      expect(Object.isFrozen(Object.getPrototypeOf(lease))).toBe(true);
      expect(Object.isFrozen(Object.getPrototypeOf(fixture))).toBe(true);
    });
  });

  it('fails closed for internal-slot, boxed, hidden, symbolic, accessor, and proxied results', async () => {
    let getterCalls = 0;
    const hidden = Object.defineProperty({}, 'hidden', { value: secret });
    const symbolic = { [Symbol('hidden')]: secret };
    const accessor = Object.defineProperty({}, 'value', {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return secret;
      },
    });
    const values: readonly unknown[] = [
      new Map([['value', secret]]),
      new Set([secret]),
      new Object(secret),
      hidden,
      symbolic,
      accessor,
      new Proxy({ value: secret }, {}),
    ];

    for (const value of values) {
      const fixture = provisioned();
      await expect(fixture.withSecretLease(async () => value)).rejects.toThrow(
        'Secret lease result is not redacted'
      );
    }
    expect(getterCalls).toBe(0);
  });

  it('redacts seeded secrets in rejection causes and unsafe rejection containers', async () => {
    for (const error of [
      new Error('outer', { cause: new Error(secret) }),
      new Map([['error', secret]]),
      new Object(secret),
    ]) {
      const fixture = provisioned();
      await expect(
        fixture.withSecretLease(async () => {
          throw error;
        })
      ).rejects.toThrow('Secret lease callback failed');
    }
  });

  it('applies the full credential authority to callback results and rejections', async () => {
    for (const credential of credentialValues) {
      await expect(provisioned().withSecretLease(async () => credential)).rejects.toThrow(
        'Secret lease result is not redacted'
      );
      await expect(
        provisioned().withSecretLease(async () => {
          throw new Error(credential);
        })
      ).rejects.toThrow('Secret lease callback failed');
    }
  });

  it('preserves only exact sanitized Error rejections without reading hostile inheritance', async () => {
    const safeError = new Error('ordinary failure', { cause: new Error('ordinary cause') });

    await expect(
      provisioned().withSecretLease(async () => {
        throw safeError;
      })
    ).rejects.toBe(safeError);
    expect(Object.isFrozen(safeError)).toBe(true);
    expect(Object.isFrozen(safeError.cause)).toBe(true);

    let getterCalls = 0;
    const hostilePrototype = Object.create(Error.prototype) as Error;
    Object.defineProperty(hostilePrototype, 'credential', {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return secret;
      },
    });
    const hostileError = new Error('ordinary failure');
    Object.setPrototypeOf(hostileError, hostilePrototype);

    await expect(
      provisioned().withSecretLease(async () => {
        throw hostileError;
      })
    ).rejects.toThrow('Secret lease callback failed');
    expect(getterCalls).toBe(0);
  });

  it('rejects seeded secrets used as own property names without echoing them', async () => {
    const hiddenError = new Error('ordinary failure');
    let hiddenErrorGetterCalls = 0;
    Object.defineProperty(hiddenError, `${secret}-hidden`, {
      configurable: false,
      enumerable: false,
      get: () => {
        hiddenErrorGetterCalls += 1;
        return secret;
      },
    });
    const returnedValues: readonly unknown[] = [
      { [secret]: 'ordinary-value' },
      { nested: { [`prefix-${secret}-suffix`]: 'ordinary-value' } },
      new Map([[secret, 'ordinary-value']]),
    ];

    for (const value of returnedValues) {
      const fixture = provisioned();
      let error: unknown;
      try {
        await fixture.withSecretLease(async () => value);
      } catch (error_: unknown) {
        error = error_;
      }
      expect(String(error)).toBe('Error: Secret lease result is not redacted');
      expect(inspect(error)).not.toContain(secret);
      expect(JSON.stringify(error)).not.toContain(secret);
    }

    const fixture = provisioned();
    let rejection: unknown;
    try {
      await fixture.withSecretLease(async () => {
        throw hiddenError;
      });
    } catch (error_: unknown) {
      rejection = error_;
    }
    expect(String(rejection)).toBe('Error: Secret lease callback failed');
    expect(inspect(rejection)).not.toContain(secret);
    expect(JSON.stringify(rejection)).not.toContain(secret);
    expect(hiddenErrorGetterCalls).toBe(0);
  });

  it('permanently revokes future leases during fixture cleanup', async () => {
    const fixture = provisioned();
    revokeProvisionedPhase1Fixture(fixture);

    await expect(fixture.withSecretLease(async () => undefined)).rejects.toThrow(
      'Fixture secrets are revoked'
    );
  });

  it('rejects malformed, accessor-backed, proxied, and unknown secret seeds without reading them', () => {
    let getterCalls = 0;
    const accessor = {};
    Object.defineProperty(accessor, 'logicalId', {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return 'phase1-user';
      },
    });
    Object.defineProperty(accessor, 'value', { enumerable: true, value: secret });

    for (const passwords of [
      [accessor],
      [new Proxy({ logicalId: 'phase1-user', value: secret }, {})],
      [{ logicalId: 'missing-user', value: secret }],
      [{ logicalId: 'phase1-user', value: '' }],
    ]) {
      expect(() =>
        createProvisionedPhase1Fixture({
          public: map(),
          passwords: passwords as never,
          clientSecrets: [],
        })
      ).toThrow('Invalid Phase 1 fixture secret seeds');
    }
    expect(getterCalls).toBe(0);
  });

  it('rejects seeded secrets hidden in allowed public identifier fields', () => {
    const publicWithSecret = createPhase1FixtureMap({
      schemaVersion: 1,
      recipe: 'dataProtocol',
      allocations: [
        {
          ...map().allocations[0],
          entities: map().allocations[0]?.entities.map((entity) =>
            entity.kind === 'user' && entity.logicalId === 'phase1-user'
              ? { ...entity, runtimeId: secret }
              : entity
          ),
        },
      ],
    });

    expect(() =>
      createProvisionedPhase1Fixture({
        public: publicWithSecret,
        passwords: [{ logicalId: 'phase1-user', value: secret }],
        clientSecrets: [],
      })
    ).toThrow('Invalid Phase 1 fixture secret seeds');
  });

  it.each(credentialValues)(
    'rejects authority-locked runtime credential material in keys and values',
    (credential) => {
      for (const value of [{ runtimeId: credential }, { [credential]: 'ordinary-value' }]) {
        expect(() => assertPhase1RuntimeCredentialGraphIsSanitized(value)).toThrow(
          'Phase 1 runtime output contains forbidden credential material'
        );
      }
    }
  );

  it.each(['Cookie', 'Set-Cookie', 'accessToken', 'privateKey', 'clientSecret'])(
    'rejects credential wrapper key %s while preserving fixed diagnostics',
    (key) => {
      let caught: unknown;
      try {
        assertPhase1RuntimeCredentialGraphIsSanitized({ [key]: 'ordinary-value' });
      } catch (error: unknown) {
        caught = error;
      }
      expect(String(caught)).toBe(
        'Error: Phase 1 runtime output contains forbidden credential material'
      );
      expect(inspect(caught)).not.toContain(key);
      expect(JSON.stringify(caught)).not.toContain(key);
    }
  );

  it.each(['sid=opaque', '__Host-x=', 'sid=opaque; Path=/; Secure; HttpOnly'])(
    'rejects standalone cookie-pair value %s',
    (cookiePair) => {
      for (const value of [cookiePair, { nested: [cookiePair] }, { [cookiePair]: 'ordinary' }]) {
        expect(() => assertPhase1RuntimeCredentialGraphIsSanitized(value)).toThrow(
          'Phase 1 runtime output contains forbidden credential material'
        );
      }
    }
  );

  it('allows reviewed public metadata names through the runtime credential scanner', () => {
    expect(() =>
      assertPhase1RuntimeCredentialGraphIsSanitized({
        cookieKeyId: 'opaque-cookie-key-fingerprint',
        signingKeyId: 'opaque-signing-key-fingerprint',
      })
    ).not.toThrow();
  });
});

describe('runWithPhase1Fixture', () => {
  const createProvisioner = (
    cleanup: (fixture: ProvisionedPhase1Fixture) => Promise<void> = async () => undefined
  ) => {
    const events: string[] = [];
    const fixture = provisioned();
    const provisioner: Phase1FixtureProvisioner = {
      provision: async () => {
        events.push('provision');
        return fixture;
      },
      projectState: async () =>
        Object.freeze({ schemaVersion: 1 as const, recipe: 'none' as const, allocations: [] }),
      cleanup: async (provisionedFixture) => {
        events.push('cleanup');
        revokeProvisionedPhase1Fixture(provisionedFixture);
        await cleanup(provisionedFixture);
      },
    };

    return { events, fixture, provisioner };
  };

  it('cleans up after success and returns the scenario result', async () => {
    const { events, provisioner } = createProvisioner();

    await expect(
      runWithPhase1Fixture(provisioner, 'dataProtocol', async () => {
        events.push('scenario');
        return 'observed';
      })
    ).resolves.toBe('observed');
    expect(events).toEqual(['provision', 'scenario', 'cleanup']);
  });

  it('cleans up after assertion failure and preserves the primary error', async () => {
    const primary = new Error('assertion failed');
    const { events, provisioner } = createProvisioner();

    await expect(
      runWithPhase1Fixture(provisioner, 'dataProtocol', async () => {
        events.push('scenario');
        throw primary;
      })
    ).rejects.toBe(primary);
    expect(events).toEqual(['provision', 'scenario', 'cleanup']);
  });

  it('waits for a late timed-out mutation to settle, then cleans exactly once', async () => {
    const persisted = ['parent'];
    let cleanupCalls = 0;
    const { events, provisioner } = createProvisioner(async () => {
      cleanupCalls += 1;
      while (persisted.length > 0) {
        events.push(`delete:${persisted.pop()}`);
      }
    });

    await expect(
      runWithPhase1Fixture(
        provisioner,
        'dataProtocol',
        async (_fixture, signal) => {
          events.push('scenario');
          await new Promise<void>((resolve) => {
            signal.addEventListener(
              'abort',
              () => {
                events.push('abort');
                setTimeout(() => {
                  persisted.push('late-child');
                  events.push('late-write', 'settled');
                  resolve();
                }, 1);
              },
              { once: true }
            );
          });
        },
        { timeoutMs: 10 }
      )
    ).rejects.toThrow('Phase 1 fixture scenario timed out');
    expect(cleanupCalls).toBe(1);
    expect(persisted).toEqual([]);
    expect(events).toEqual([
      'provision',
      'scenario',
      'abort',
      'late-write',
      'settled',
      'cleanup',
      'delete:late-child',
      'delete:parent',
    ]);
    await new Promise((resolve) => {
      setTimeout(resolve, 20);
    });
    expect(cleanupCalls).toBe(1);
  });

  it('revokes an active secret lease before a timed-out callback can resume', async () => {
    const { provisioner } = createProvisioner();
    let markLeaseChecked: (() => void) | undefined;
    const leaseChecked = new Promise<void>((resolve) => {
      markLeaseChecked = resolve;
    });
    let lateRead = 'not-attempted';

    await expect(
      runWithPhase1Fixture(
        provisioner,
        'dataProtocol',
        async (fixture, signal) =>
          fixture.withSecretLease(async (lease) => {
            await new Promise<void>((resolve) => {
              signal.addEventListener(
                'abort',
                () => {
                  setTimeout(() => {
                    try {
                      lease.getPassword('phase1-user');
                      lateRead = 'escaped';
                    } catch {
                      lateRead = 'revoked';
                    }
                    markLeaseChecked?.();
                    resolve();
                  }, 1);
                },
                { once: true }
              );
            });
          }),
        { timeoutMs: 10 }
      )
    ).rejects.toThrow('Phase 1 fixture scenario timed out');
    await leaseChecked;
    expect(lateRead).toBe('revoked');
  });

  it('revokes before synchronously notifying abort listeners', async () => {
    const { provisioner } = createProvisioner();
    let synchronousRead = 'not-attempted';

    await expect(
      runWithPhase1Fixture(
        provisioner,
        'dataProtocol',
        async (fixture, signal) =>
          fixture.withSecretLease(
            async (lease) =>
              new Promise<void>((resolve) => {
                signal.addEventListener(
                  'abort',
                  () => {
                    try {
                      lease.getPassword('phase1-user');
                      synchronousRead = 'escaped';
                    } catch {
                      synchronousRead = 'revoked';
                    }
                    resolve();
                  },
                  { once: true }
                );
              })
          ),
        { timeoutMs: 10 }
      )
    ).rejects.toThrow('Phase 1 fixture scenario timed out');
    expect(synchronousRead).toBe('revoked');
  });

  it('revokes before awaiting delayed cleanup I/O', async () => {
    const fixture = provisioned();
    let markCleanupStarted: (() => void) | undefined;
    const cleanupStarted = new Promise<void>((resolve) => {
      markCleanupStarted = resolve;
    });
    let releaseCleanup: (() => void) | undefined;
    const cleanupReleased = new Promise<void>((resolve) => {
      releaseCleanup = resolve;
    });
    const provisioner: Phase1FixtureProvisioner = {
      provision: async () => fixture,
      projectState: async () =>
        Object.freeze({ schemaVersion: 1 as const, recipe: 'none' as const, allocations: [] }),
      cleanup: async () => {
        markCleanupStarted?.();
        await cleanupReleased;
      },
    };
    let readBeforeCleanup = 'not-attempted';
    const run = runWithPhase1Fixture(
      provisioner,
      'dataProtocol',
      async (activeFixture, signal) =>
        activeFixture.withSecretLease(
          async (lease) =>
            new Promise<void>((resolve) => {
              signal.addEventListener(
                'abort',
                () => {
                  try {
                    lease.getPassword('phase1-user');
                    readBeforeCleanup = 'escaped';
                  } catch {
                    readBeforeCleanup = 'revoked';
                  }
                  resolve();
                },
                { once: true }
              );
            })
        ),
      { timeoutMs: 10 }
    );

    await cleanupStarted;
    expect(readBeforeCleanup).toBe('revoked');
    releaseCleanup?.();
    await expect(run).rejects.toThrow('Phase 1 fixture scenario timed out');
  });

  it('does not swallow undefined thrown by the scenario or cleanup', async () => {
    const scenario = createProvisioner();
    await expect(
      runWithPhase1Fixture(scenario.provisioner, 'dataProtocol', async () => {
        throw undefined;
      })
    ).rejects.toBeUndefined();

    const cleanup = createProvisioner(async () => {
      throw undefined;
    });
    let caught: unknown;
    try {
      await runWithPhase1Fixture(cleanup.provisioner, 'dataProtocol', async () => 'observed');
    } catch (error: unknown) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(AggregateError);
    expect((caught as AggregateError).errors).toEqual([undefined]);
  });

  it('aggregates cleanup failure after the primary error without replacing it', async () => {
    const primary = new Error('assertion failed');
    const cleanup = new Error('cleanup failed');
    const { provisioner } = createProvisioner(async () => {
      throw cleanup;
    });

    let caught: unknown;
    try {
      await runWithPhase1Fixture(provisioner, 'dataProtocol', async () => {
        throw primary;
      });
    } catch (error: unknown) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(AggregateError);
    expect((caught as AggregateError).errors).toEqual([primary, cleanup]);
    expect((caught as Error & { cause?: unknown }).cause).toBe(primary);
  });
});

describe('fixture allocation isolation', () => {
  it('requires four canonical target origins to be pairwise disjoint', () => {
    const primary: TargetConfig = {
      label: 'oracle',
      coreUrl: 'http://localhost:3001/',
      adminUrl: 'http://localhost:3002/',
    };
    const isolated: TargetConfig = {
      label: 'oracle',
      coreUrl: 'http://localhost:3011/',
      adminUrl: 'http://localhost:3012/',
    };

    expect(phase1TargetOriginsArePairwiseDisjoint(primary, isolated)).toBe(true);
    expect(phase1TargetOriginsArePairwiseDisjoint(primary)).toBe(true);
    for (const foreign of [
      { ...isolated, coreUrl: primary.adminUrl },
      { ...isolated, adminUrl: primary.coreUrl },
      { ...isolated, adminUrl: isolated.coreUrl },
      { ...isolated, coreUrl: 'HTTP://LOCALHOST:3001' },
    ]) {
      expect(phase1TargetOriginsArePairwiseDisjoint(primary, foreign)).toBe(false);
    }
    expect(
      phase1TargetOriginsArePairwiseDisjoint(
        { ...primary, adminUrl: 'HTTP://LOCALHOST:3001' },
        isolated
      )
    ).toBe(false);
    expect(
      phase1TargetOriginsArePairwiseDisjoint({
        ...primary,
        adminUrl: 'HTTP://LOCALHOST:3001',
      })
    ).toBe(false);
    expect(
      phase1TargetOriginsArePairwiseDisjoint({
        ...primary,
        coreUrl: 'http://localhost:80/',
        adminUrl: 'HTTP://LOCALHOST',
      })
    ).toBe(false);
  });

  it('requires Experience and Console groups to use different allocations', () => {
    const experience = provisioned('experience-fixture');
    const consoleFixture = provisioned('console-fixture');

    expect(() =>
      assertPhase1FixtureAllocationsAreDistinct(experience, consoleFixture)
    ).not.toThrow();
    expect(() => assertPhase1FixtureAllocationsAreDistinct(experience, experience)).toThrow(
      'Phase 1 fixture allocations must be distinct'
    );
  });

  it('requires a separately keyed foreign target only for consentBoundary', () => {
    const primaryData = map('primary-data').allocations[0];
    const consentMap = createPhase1FixtureMap({
      schemaVersion: 1,
      recipe: 'consentBoundary',
      allocations: [
        {
          ...primaryData,
          entities: [
            ...(primaryData?.entities ?? []),
            { kind: 'user', logicalId: 'consent.primary.user-b', runtimeId: 'primary-peer-user' },
            {
              kind: 'application',
              logicalId: 'consent.primary.client-b',
              runtimeId: 'primary-peer-client',
            },
          ],
        },
        {
          allocationId: 'foreign-data',
          role: 'foreign',
          target: 'foreign',
          isolation: {
            persistenceId: 'foreign-persistence',
            cookieKeyId: 'foreign-cookie',
            signingKeyId: 'foreign-signing',
          },
          entities: [
            { kind: 'tenant', logicalId: 'default', runtimeId: 'foreign-tenant' },
            { kind: 'user', logicalId: 'consent.foreign.user-b', runtimeId: 'foreign-user' },
            {
              kind: 'application',
              logicalId: 'consent.foreign.client-b',
              runtimeId: 'foreign-client',
            },
          ],
        },
      ],
    });
    const fixture = createProvisionedPhase1Fixture({
      public: consentMap,
      foreignTarget: target(4011),
      passwords: [],
      clientSecrets: [],
    });

    expect(fixture.foreignTarget).toEqual(target(4011));
    expect(() =>
      createProvisionedPhase1Fixture({
        public: consentMap,
        passwords: [],
        clientSecrets: [],
      })
    ).toThrow('Invalid Phase 1 foreign target');
    expect(() =>
      createProvisionedPhase1Fixture({
        public: map(),
        foreignTarget: target(4011),
        passwords: [],
        clientSecrets: [],
      })
    ).toThrow('Invalid Phase 1 foreign target');
  });
});

/* eslint-enable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, unicorn/no-useless-undefined, unicorn/consistent-function-scoping, @typescript-eslint/no-confusing-void-expression, no-await-in-loop, @typescript-eslint/no-throw-literal */
