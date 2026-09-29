/* eslint-disable max-lines, @typescript-eslint/consistent-type-assertions, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unnecessary-condition, unicorn/consistent-function-scoping -- The mutation controls deliberately exercise hostile evidence shapes and ordered invocation counts. */
import path from 'node:path';

import type { DeviceAuthorizationProjection } from '../clients/device-authorization.js';
import { createDeviceAuthorizationTransportLease } from '../clients/device-authorization.js';
import type { Phase2ProfileRegistries } from '../profile.js';

import {
  createDeviceCandidateInvariantRegistry,
  createLiveDeviceCandidateInvariantExecutor,
  deviceDigestFailureStage,
  deviceEvidenceFailureStage,
  deviceCandidateInvariantExpectedProjection,
  deviceCandidateInvariantIds,
  observeConsumedReplayRevocation,
  projectDeviceConcurrencyInvariant,
  runDeviceCandidateInvariantControls,
  runDeviceCandidateInvariants,
} from './device-authorization.js';

describe('Phase 2 digest-only invariant diagnostics', () => {
  it.each([
    'private-code-extraction',
    'row-sql',
    'row-missing',
    'row-facts',
    'schema-query',
    'schema-clear-columns',
  ])('accepts the exact value-free %s driver signal', (substage) => {
    expect(
      deviceDigestFailureStage({
        exitCode: 41,
        signal: null,
        stdout: '',
        stderr: `Phase 2 client credentials invariant driver failed (device-1-${substage}).\n`,
        timedOut: false,
        killed: false,
        reaped: true,
      })
    ).toBe(substage);
  });

  it.each([
    'Phase 2 client credentials invariant driver failed (device-1-row-sql).\nsecret\n',
    'Phase 2 client credentials invariant driver failed (device-1-unknown).\n',
    'Phase 2 client credentials invariant driver failed (oracle-device-1-row-sql).\n',
  ])('rejects a non-exact or unclosed driver signal', (stderr) => {
    expect(
      deviceDigestFailureStage({
        exitCode: 41,
        signal: null,
        stdout: '',
        stderr,
        timedOut: false,
        killed: false,
        reaped: true,
      })
    ).toBeUndefined();
  });

  it.each([
    [
      'exact signal',
      'Phase 2 client credentials invariant driver failed (device-1-row-sql).\n',
      'Phase 2 stage failed: candidate-invariant-device-1-row-sql',
    ],
    [
      'signal with trailing child detail',
      'Phase 2 client credentials invariant driver failed (device-1-row-sql).\nprivate detail\n',
      'Phase 2 stage failed: candidate-invariant-device-1',
    ],
  ])('wires %s through the live executor', async (_name, stderr, expectedMessage) => {
    let clearCount = 0;
    const topology = Object.freeze({ projectName: 'test-topology' });
    const target = Object.freeze({
      label: 'candidate' as const,
      coreUrl: 'https://candidate.example/',
      adminUrl: 'https://candidate-admin.example/',
    });
    const foreignTarget = Object.freeze({
      label: 'candidate' as const,
      coreUrl: 'https://foreign.example/',
      adminUrl: 'https://foreign-admin.example/',
    });
    const success = (invariantId: string) => ({
      exitCode: 0,
      signal: null,
      stdout: JSON.stringify({
        schemaVersion: 1,
        kind: 'phase2-client-credentials-candidate-invariant',
        invariantId,
        projection: deviceCandidateInvariantExpectedProjection(
          'device-authorization.forced-rls-isolation'
        ),
        attestation: topology,
      }),
      stderr: '',
      timedOut: false,
      killed: false,
      reaped: true,
    });
    const executor = await createLiveDeviceCandidateInvariantExecutor({
      profile: profile(),
      target,
      foreignTarget,
      fixture: {
        public: { deviceClients: { firstParty: { id: 'device-client' } } },
      } as never,
      driverPath: path.resolve(
        process.cwd(),
        '../..',
        '.scripts/compatibility/phase2-client-credentials-invariant-driver.sh'
      ),
      controlSocket: '/var/tmp/henry-build/device-diagnostic-test.sock',
      topology: topology as never,
      state: {} as never,
      jwks: { keys: [] },
      createTransport: (() => ({
        requestAuthorization: async () => ({ status: 200, deviceCodeShape: 'opaque' }),
        requestVerification: async () => ({ status: 200 }),
        withAuthorizationSecretLease: async (use: (secrets: unknown) => Promise<unknown>) => {
          try {
            const outcome = await use({
              getDeviceCode: () => 'private-device-code',
              getUserCode: () => 'BCDF-GHJK',
              getXsrf: () => 'private-xsrf',
            });
            if (
              typeof outcome !== 'object' ||
              outcome === null ||
              !('kind' in outcome) ||
              (outcome.kind !== 'projection' && outcome.kind !== 'digest-failure')
            ) {
              throw new TypeError('invalid lease callback outcome');
            }
            return outcome;
          } catch {
            throw new TypeError('masked credential lease failure');
          }
        },
        clear: () => {
          clearCount += 1;
        },
      })) as never,
      runner: async (request) => {
        const descriptor = JSON.parse(request.stdin) as { invariantId: string };
        return descriptor.invariantId === 'device-authorization.forced-rls-isolation'
          ? success(descriptor.invariantId)
          : {
              exitCode: 41,
              signal: null,
              stdout: '',
              stderr,
              timedOut: false,
              killed: false,
              reaped: true,
            };
      },
    });

    await expect(runDeviceCandidateInvariants(profile(), executor)).rejects.toMatchObject({
      message: expectedMessage,
    });
    expect(clearCount).toBe(1);
  });
});

describe('Phase 2 secret-material invariant diagnostics', () => {
  const preDriverStages = [
    'prepare',
    'approval',
    'issuance',
    'evidence-open',
    'evidence-values',
    'evidence-validation',
    'evidence-lease',
    'driver-unclassified',
  ] as const;

  it.each([
    'private-extraction',
    'row-sql',
    'row-facts',
    'schema-query',
    'schema-clear-columns',
    'scan-input',
    'scan-query',
    'scan-match',
    'normalized-input',
    'normalized-query',
    'normalized-match',
  ])('accepts the exact value-free %s driver signal', (substage) => {
    expect(
      deviceEvidenceFailureStage({
        exitCode: 42,
        signal: null,
        stdout: '',
        stderr: `Phase 2 client credentials invariant driver failed (device-7-${substage}).\n`,
        timedOut: false,
        killed: false,
        reaped: true,
      })
    ).toBe(substage);
  });

  it.each([
    [41, 'Phase 2 client credentials invariant driver failed (device-7-row-sql).\n'],
    [42, 'Phase 2 client credentials invariant driver failed (device-7-unknown).\n'],
    [42, 'Phase 2 client credentials invariant driver failed (device-7-row-sql).\nsecret\n'],
    [42, 'Phase 2 client credentials invariant driver failed (device-1-row-sql).\n'],
  ])('rejects a forged or non-exact driver signal', (exitCode, stderr) => {
    expect(
      deviceEvidenceFailureStage({
        exitCode,
        signal: null,
        stdout: '',
        stderr,
        timedOut: false,
        killed: false,
        reaped: true,
      })
    ).toBeUndefined();
  });

  it.each([
    ['authentic', 'normalized-match'],
    ['generic', 'evidence-validation'],
    ['forged', 'evidence-validation'],
  ] as const)(
    'classifies combined %s driver and post-callback lease failures and clears the lease',
    async (driverFailure, expectedStage) => {
      let clearCount = 0;
      let leaseOutcome: unknown;
      const topology = Object.freeze({ projectName: 'test-topology' });
      const target = Object.freeze({
        label: 'candidate' as const,
        coreUrl: 'https://candidate.example/',
        adminUrl: 'https://candidate-admin.example/',
      });
      const executor = await createLiveDeviceCandidateInvariantExecutor({
        profile: profile(),
        target,
        foreignTarget: Object.freeze({
          label: 'candidate' as const,
          coreUrl: 'https://foreign.example/',
          adminUrl: 'https://foreign-admin.example/',
        }),
        fixture: {
          public: {
            deviceClients: { firstParty: { id: 'device-client' } },
          },
          status: { user: { id: 'subject-id', username: 'subject@example.test' } },
          withSecretLease: async (use: (secrets: unknown) => Promise<unknown>) =>
            use({
              getSubjectPassword: () => 'private-password',
              getClientSecret: () => 'private-client-secret',
              getStatusClientSecret: () => 'private-status-secret',
            }),
        } as never,
        driverPath: path.resolve(
          process.cwd(),
          '../..',
          '.scripts/compatibility/phase2-client-credentials-invariant-driver.sh'
        ),
        controlSocket: '/var/tmp/henry-build/device-evidence-diagnostic-test.sock',
        topology: topology as never,
        state: {} as never,
        jwks: { keys: [] },
        createTransport: (() => ({
          requestAuthorization: async () => ({ status: 200, deviceCodeShape: 'opaque' }),
          requestVerification: async () => ({ status: 200 }),
          requestLifecycle: async () => ({ status: 200 }),
          pollToken: async () => ({ status: 200 }),
          withEvidenceSecretLease: async (use: (secrets: unknown) => Promise<unknown>) => {
            try {
              leaseOutcome = await use({
                getDeviceCode: () => 'private-device-code',
                getUserCode: () => 'BCDF-GHJK',
                getAuditXsrf: () => 'private-xsrf',
                getAccessToken: () => 'private-access-token',
                getRefreshToken: () => 'private-refresh-token',
                getIdToken: () => 'private-id-token',
              });
              if (
                typeof leaseOutcome !== 'object' ||
                leaseOutcome === null ||
                !Object.isFrozen(leaseOutcome) ||
                JSON.stringify(leaseOutcome).includes('private-')
              ) {
                throw new TypeError('invalid evidence lease callback outcome');
              }
              throw new TypeError('private post-callback lease rejection');
            } catch {
              throw new TypeError('masked evidence lease failure');
            }
          },
          clear: () => {
            clearCount += 1;
          },
        })) as never,
        runner: async () => {
          if (driverFailure === 'generic') {
            throw new TypeError('private raw driver detail');
          }
          return {
            exitCode: 42,
            signal: null,
            stdout: '',
            stderr:
              driverFailure === 'authentic'
                ? 'Phase 2 client credentials invariant driver failed (device-7-normalized-match).\n'
                : 'Phase 2 client credentials invariant driver failed (device-7-normalized-match).\nprivate\n',
            timedOut: false,
            killed: false,
            reaped: true,
          };
        },
      });

      await expect(
        executor.execute('device-evidence.secret-material-absent')
      ).rejects.toMatchObject({
        message: `Phase 2 stage failed: candidate-invariant-device-7-${expectedStage}`,
      });
      expect(leaseOutcome).toEqual({
        kind: 'evidence-failure',
        stage: driverFailure === 'authentic' ? 'normalized-match' : 'driver-unclassified',
      });
      expect(clearCount).toBe(1);
    }
  );

  it.each(preDriverStages)(
    'classifies %s without exposing details and clears the lease',
    async (stage) => {
      let clearCount = 0;
      let fixtureLeaseCount = 0;
      let verificationCount = 0;
      const target = Object.freeze({
        label: 'candidate' as const,
        coreUrl: 'https://candidate.example/',
        adminUrl: 'https://candidate-admin.example/',
      });
      const executor = await createLiveDeviceCandidateInvariantExecutor({
        profile: profile(),
        target,
        foreignTarget: Object.freeze({
          label: 'candidate' as const,
          coreUrl: 'https://foreign.example/',
          adminUrl: 'https://foreign-admin.example/',
        }),
        fixture: {
          public: { deviceClients: { firstParty: { id: 'device-client' } } },
          status: { user: { id: 'subject-id', username: 'subject@example.test' } },
          withSecretLease: async (use: (secrets: unknown) => Promise<unknown>) => {
            fixtureLeaseCount += 1;
            if (stage === 'evidence-open' && fixtureLeaseCount > 1) {
              throw new TypeError('private fixture lease detail');
            }
            return use({
              getSubjectPassword: () => 'private-password',
              getClientSecret: () => 'private-client-secret',
              getStatusClientSecret: () => 'private-status-secret',
            });
          },
        } as never,
        driverPath: path.resolve(
          process.cwd(),
          '../..',
          '.scripts/compatibility/phase2-client-credentials-invariant-driver.sh'
        ),
        controlSocket: '/var/tmp/henry-build/device-evidence-pre-driver-test.sock',
        topology: Object.freeze({ projectName: 'test-topology' }) as never,
        state: {} as never,
        jwks: { keys: [] },
        createTransport: (() => ({
          requestAuthorization: async () => {
            if (stage === 'prepare') {
              throw new TypeError('private preparation detail');
            }
            return { status: 200, deviceCodeShape: 'opaque' };
          },
          requestVerification: async () => {
            verificationCount += 1;
            if (stage === 'approval' && verificationCount > 1) {
              throw new TypeError('private approval detail');
            }
            return { status: 200 };
          },
          requestLifecycle: async () => ({ status: 200 }),
          pollToken: async () => {
            if (stage === 'issuance') {
              throw new TypeError('private issuance detail');
            }
            return { status: 200 };
          },
          withEvidenceSecretLease: async (use: (secrets: unknown) => Promise<unknown>) => {
            const secrets = {
              getDeviceCode: () => {
                if (stage === 'evidence-values') {
                  throw new TypeError('private evidence value detail');
                }
                return 'private-device-code';
              },
              getUserCode: () => 'BCDF-GHJK',
              getAuditXsrf: () => 'private-xsrf',
              getAccessToken: () => 'private-access-token',
              getRefreshToken: () => 'private-refresh-token',
              getIdToken: () => 'private-id-token',
            };
            if (stage === 'evidence-lease') {
              void use(secrets);
              throw new TypeError('private evidence lease detail');
            }
            const result = await use(secrets);
            if (stage === 'evidence-validation') {
              throw new TypeError('private evidence validation detail');
            }
            return result;
          },
          clear: () => {
            clearCount += 1;
          },
        })) as never,
        runner: async () => {
          if (stage === 'evidence-lease') {
            return new Promise<never>(() => {
              expect(stage).toBe('evidence-lease');
            });
          }
          throw new TypeError('private raw driver detail');
        },
      });

      await expect(
        executor.execute('device-evidence.secret-material-absent')
      ).rejects.toMatchObject({
        message: `Phase 2 stage failed: candidate-invariant-device-7-${stage}`,
      });
      expect(clearCount).toBe(1);
    }
  );

  it('does not accept a forged secret-material substage from an executor', async () => {
    await expect(
      runDeviceCandidateInvariants(profile(), {
        execute: async (id) => {
          if (id === deviceCandidateInvariantIds[7]) {
            throw new Error('Phase 2 stage failed: candidate-invariant-device-7-normalized-match');
          }
          return deviceCandidateInvariantExpectedProjection(id);
        },
      })
    ).rejects.toMatchObject({
      message: 'Phase 2 stage failed: candidate-invariant-device-7',
    });
  });

  it.each(preDriverStages)('does not accept a forged %s stage from an executor', async (stage) => {
    await expect(
      runDeviceCandidateInvariants(profile(), {
        execute: async (id) => {
          if (id === deviceCandidateInvariantIds[7]) {
            throw new Error(`Phase 2 stage failed: candidate-invariant-device-7-${stage}`);
          }
          return deviceCandidateInvariantExpectedProjection(id);
        },
      })
    ).rejects.toMatchObject({ message: 'Phase 2 stage failed: candidate-invariant-device-7' });
  });
});

describe('Phase 2 cross-tenant invariant diagnostics', () => {
  it.each([
    ['foreign response', false, 'foreign-poll-invalid-client'],
    ['abort', true, 'abort'],
  ])(
    'carries the closed %s stage through a masking authorization lease',
    async (_name, abortFails, expectedStage) => {
      const topology = Object.freeze({ projectName: 'test-topology' });
      const target = Object.freeze({
        label: 'candidate' as const,
        coreUrl: 'https://candidate.example/',
        adminUrl: 'https://candidate-admin.example/',
      });
      const foreignTarget = Object.freeze({
        label: 'candidate' as const,
        coreUrl: 'https://foreign.example/',
        adminUrl: 'https://foreign-admin.example/',
      });
      const operations: string[] = [];
      let clearCount = 0;
      const executor = await createLiveDeviceCandidateInvariantExecutor({
        profile: profile(),
        target,
        foreignTarget,
        fixture: {
          public: { deviceClients: { firstParty: { id: 'device-client' } } },
        } as never,
        driverPath: path.resolve(
          process.cwd(),
          '../..',
          '.scripts/compatibility/phase2-client-credentials-invariant-driver.sh'
        ),
        controlSocket: '/var/tmp/henry-build/device-cross-tenant-diagnostic-test.sock',
        topology: topology as never,
        state: {} as never,
        jwks: { keys: [] },
        createTransport: (({ target: selectedTarget }: { target: { coreUrl: string } }) => ({
          requestAuthorization: async () => ({ status: 200, deviceCodeShape: 'opaque' }),
          requestVerification: async () => ({ status: 200 }),
          pollToken: async () => ({
            status: selectedTarget.coreUrl === foreignTarget.coreUrl ? 400 : 200,
            oauthError: {
              category:
                selectedTarget.coreUrl === foreignTarget.coreUrl ? 'invalid_client' : undefined,
            },
          }),
          withAuthorizationSecretLease: async (use: (secrets: unknown) => Promise<unknown>) => {
            try {
              const outcome = await use({
                getDeviceCode: () => 'private-device-code',
                getUserCode: () => 'BCDF-GHJK',
                getXsrf: () => 'private-xsrf',
              });
              if (
                typeof outcome !== 'object' ||
                outcome === null ||
                !Object.isFrozen(outcome) ||
                JSON.stringify(outcome).includes('private-')
              ) {
                throw new TypeError('invalid lease callback outcome');
              }
              return outcome;
            } catch {
              throw new TypeError('masked credential lease failure');
            }
          },
          clear: () => {
            clearCount += 1;
          },
        })) as never,
        runner: async (request) => {
          const descriptor = JSON.parse(request.stdin) as {
            invariantId: string;
            operation: string;
          };
          operations.push(descriptor.operation);
          const terminal =
            descriptor.operation === 'arm'
              ? {
                  schemaVersion: 1,
                  kind: 'phase2-device-candidate-invariant-control',
                  invariantId: descriptor.invariantId,
                  operation: 'arm',
                  handle: 'a'.repeat(32),
                  attestation: topology,
                }
              : {
                  schemaVersion: 1,
                  kind: 'phase2-device-candidate-invariant-control',
                  invariantId: descriptor.invariantId,
                  operation: 'abort',
                  ok: true,
                  attestation: topology,
                };
          return descriptor.operation === 'abort' && abortFails
            ? {
                exitCode: 1,
                signal: null,
                stdout: '',
                stderr: 'private abort failure',
                timedOut: false,
                killed: false,
                reaped: true,
              }
            : {
                exitCode: 0,
                signal: null,
                stdout: JSON.stringify(terminal),
                stderr: '',
                timedOut: false,
                killed: false,
                reaped: true,
              };
        },
      });

      await expect(
        executor.execute('device-authorization.cross-tenant-lookup-rejected')
      ).rejects.toMatchObject({
        message: `Phase 2 stage failed: candidate-invariant-device-2-${expectedStage}`,
      });
      expect(operations).toEqual(['arm', 'abort']);
      expect(clearCount).toBe(2);
    }
  );

  it('does not accept a forged cross-tenant substage from an executor', async () => {
    await expect(
      runDeviceCandidateInvariants(profile(), {
        execute: async (id) => {
          if (id === deviceCandidateInvariantIds[2]) {
            throw new Error(
              'Phase 2 stage failed: candidate-invariant-device-2-foreign-poll-invalid-client'
            );
          }
          return deviceCandidateInvariantExpectedProjection(id);
        },
      })
    ).rejects.toMatchObject({
      message: 'Phase 2 stage failed: candidate-invariant-device-2',
    });
  });
});

const legacyIds = [
  'client-credentials.cross-tenant-authority-rejected',
  'client-credentials.request-role-write-rejected',
  'client-credentials.signing-failure-rolls-back',
  'client-credentials.user-authority-unchanged',
  'logout-session.verification-storage-closed',
] as const;

const profile = (ids: readonly string[] = [...legacyIds, ...deviceCandidateInvariantIds]) =>
  ({ candidateInvariantScenarios: ids }) as unknown as Phase2ProfileRegistries;

describe('Phase 2 device candidate invariant registry', () => {
  it('closes the exact ordered eight-ID suffix of the thirteen-ID profile', () => {
    const registry = createDeviceCandidateInvariantRegistry(profile());
    expect(registry.map(({ id }) => id)).toEqual(deviceCandidateInvariantIds);
    expect(Object.isFrozen(registry)).toBe(true);

    for (const ids of [
      [...legacyIds, ...deviceCandidateInvariantIds.slice(1)],
      [
        ...legacyIds,
        deviceCandidateInvariantIds[1],
        deviceCandidateInvariantIds[0],
        ...deviceCandidateInvariantIds.slice(2),
      ],
      [...legacyIds, ...deviceCandidateInvariantIds, deviceCandidateInvariantIds[0]],
      [...deviceCandidateInvariantIds, ...legacyIds],
    ]) {
      expect(() => createDeviceCandidateInvariantRegistry(profile(ids))).toThrow(
        'Invalid Phase 2 device candidate invariant'
      );
    }
  });

  it('publishes one fixed candidate projection and mutation pointer per invariant', () => {
    expect(
      deviceCandidateInvariantIds.map((id) =>
        runDeviceCandidateInvariantControls(id, deviceCandidateInvariantExpectedProjection(id))
      )
    ).toEqual([
      expect.objectContaining({
        id: deviceCandidateInvariantIds[0],
        negativeControl: { detected: true, pointer: '/catalog/forcedRowSecurity' },
      }),
      expect.objectContaining({
        id: deviceCandidateInvariantIds[1],
        negativeControl: { detected: true, pointer: '/row/deviceDigestBytes' },
      }),
      expect.objectContaining({
        id: deviceCandidateInvariantIds[2],
        negativeControl: { detected: true, pointer: '/foreignPoll/error' },
      }),
      expect.objectContaining({
        id: deviceCandidateInvariantIds[3],
        negativeControl: { detected: true, pointer: '/rollback/deviceState' },
      }),
      expect.objectContaining({
        id: deviceCandidateInvariantIds[4],
        negativeControl: { detected: true, pointer: '/trials/0/winnerCount' },
      }),
      expect.objectContaining({
        id: deviceCandidateInvariantIds[5],
        negativeControl: { detected: true, pointer: '/authority/grant' },
      }),
      expect.objectContaining({
        id: deviceCandidateInvariantIds[6],
        negativeControl: { detected: true, pointer: '/cleanup/deletedExpired' },
      }),
      expect.objectContaining({
        id: deviceCandidateInvariantIds[7],
        negativeControl: { detected: true, pointer: '/evidence' },
      }),
    ]);
  });

  it('rejects a projection with an accessor, extra property, or wrong value', () => {
    const id = deviceCandidateInvariantIds[0];
    const expected = deviceCandidateInvariantExpectedProjection(id);
    if (expected.invariant !== 'forced-rls-isolation') {
      throw new TypeError('test fixture drift');
    }
    expect(() =>
      runDeviceCandidateInvariantControls(id, { ...expected, extra: true } as never)
    ).toThrow('Invalid Phase 2 device candidate invariant');
    expect(() =>
      runDeviceCandidateInvariantControls(
        id,
        Object.defineProperty({}, 'invariant', {
          enumerable: true,
          get: () => 'forced-rls-isolation',
        }) as never
      )
    ).toThrow('Invalid Phase 2 device candidate invariant');
    expect(() =>
      runDeviceCandidateInvariantControls(id, {
        ...expected,
        catalog: { ...expected.catalog, forcedRowSecurity: false },
      } as never)
    ).toThrow('Invalid Phase 2 device candidate invariant');
  });

  it('executes every device proof in exact profile order and attaches both controls', async () => {
    const calls: string[] = [];
    const evidence = await runDeviceCandidateInvariants(profile(), {
      execute: async (id) => {
        calls.push(id);
        return deviceCandidateInvariantExpectedProjection(id);
      },
    });
    expect(calls).toEqual(deviceCandidateInvariantIds);
    expect(evidence.map(({ id }) => id)).toEqual(deviceCandidateInvariantIds);
    expect(
      evidence.every(
        ({ positiveControl, negativeControl }) =>
          positiveControl.detected && negativeControl.detected
      )
    ).toBe(true);

    await expect(
      runDeviceCandidateInvariants(profile(), {
        execute: async (id) =>
          id === deviceCandidateInvariantIds[3]
            ? ({ ...deviceCandidateInvariantExpectedProjection(id), retry: 'failed' } as never)
            : deviceCandidateInvariantExpectedProjection(id),
      })
    ).rejects.toThrow('Phase 2 stage failed: candidate-invariant-device-3');
  });

  it('reports only the closed registry position when device execution fails', async () => {
    const privateDetail = 'private-device-credential';
    await expect(
      runDeviceCandidateInvariants(profile(), {
        execute: async (id) => {
          if (id === deviceCandidateInvariantIds[7]) {
            throw new Error(privateDetail);
          }
          return deviceCandidateInvariantExpectedProjection(id);
        },
      })
    ).rejects.toMatchObject({
      message: 'Phase 2 stage failed: candidate-invariant-device-7',
    });
  });

  it('does not accept a forged digest-only substage from an executor', async () => {
    await expect(
      runDeviceCandidateInvariants(profile(), {
        execute: async (id) => {
          if (id === deviceCandidateInvariantIds[1]) {
            throw new Error('Phase 2 stage failed: candidate-invariant-device-1-row-sql');
          }
          return deviceCandidateInvariantExpectedProjection(id);
        },
      })
    ).rejects.toMatchObject({
      message: 'Phase 2 stage failed: candidate-invariant-device-1',
    });
  });

  it('projects exactly three independent candidate one-winner trials', async () => {
    let calls = 0;
    const response = (winner: boolean): DeviceAuthorizationProjection =>
      ({
        status: winner ? 200 : 400,
        oauthError: winner
          ? { category: undefined, description: undefined }
          : { category: 'invalid_grant', description: 'grant request is invalid' },
      }) as DeviceAuthorizationProjection;
    const projection = await projectDeviceConcurrencyInvariant(async () => {
      calls += 1;
      return Object.freeze({
        winnerCount: 1,
        responses: Object.freeze([response(true), response(false)]) as readonly [
          DeviceAuthorizationProjection,
          DeviceAuthorizationProjection,
        ],
      });
    });
    expect(calls).toBe(3);
    expect(projection).toEqual(
      deviceCandidateInvariantExpectedProjection('device-token.concurrent-poll-one-winner')
    );
    await expect(
      projectDeviceConcurrencyInvariant(async () =>
        Object.freeze({
          winnerCount: 2,
          responses: Object.freeze([response(true), response(true)]) as readonly [
            DeviceAuthorizationProjection,
            DeviceAuthorizationProjection,
          ],
        })
      )
    ).rejects.toThrow('Invalid Phase 2 device candidate invariant');
  });

  it('observes replay, both introspections, and refresh serially on the real transport lease', async () => {
    const calls: Array<Readonly<{ url: string; body: string }>> = [];
    const responses = [
      new Response(
        JSON.stringify({
          device_code: 'private-device-code',
          user_code: 'BCDF-GHJK',
          verification_uri: 'https://candidate.example/oidc/device',
          expires_in: 600,
          interval: 5,
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      ),
      new Response(
        JSON.stringify({
          access_token: 'private-access-token',
          refresh_token: 'private-refresh-token',
          expires_in: 3600,
          token_type: 'Bearer',
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      ),
      new Response(JSON.stringify({ error: 'invalid_grant' }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      }),
      new Response(JSON.stringify({ active: false }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
      new Response(JSON.stringify({ active: false }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
      new Response(JSON.stringify({ error: 'invalid_grant' }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      }),
    ];
    const lease = createDeviceAuthorizationTransportLease({
      target: {
        label: 'candidate',
        coreUrl: 'https://candidate.example/',
        adminUrl: 'https://candidate-admin.example/',
      },
      fetch: (async (input, init) => {
        calls.push(
          Object.freeze({
            url: String(input),
            body: String(init?.body ?? ''),
          })
        );
        return responses.shift() ?? Promise.reject(new TypeError('unexpected fetch'));
      }) as typeof fetch,
    });
    await lease.requestAuthorization({
      encoding: 'form',
      fields: [['client_id', 'device-client']],
    });
    await lease.pollToken({ proof: { method: 'public', clientId: 'device-client' } });

    const observed = await observeConsumedReplayRevocation(
      lease,
      'device-client',
      'private-subject'
    );

    expect(observed).toEqual({
      replayStatus: 400,
      replayError: 'invalid_grant',
      accessActive: false,
      refreshActive: false,
      refreshStatus: 400,
      refreshError: 'invalid_grant',
    });
    expect(calls.slice(2).map(({ url }) => new URL(url).pathname)).toEqual([
      '/oidc/token',
      '/oidc/token/introspection',
      '/oidc/token/introspection',
      '/oidc/token',
    ]);
    expect(calls.slice(2).map(({ body }) => new URLSearchParams(body).get('grant_type'))).toEqual([
      'urn:ietf:params:oauth:grant-type:device_code',
      null,
      null,
      'refresh_token',
    ]);
    expect(JSON.stringify(observed)).not.toMatch(/private-(?:device|access|refresh)/u);
    lease.clear();
  });
});

/* eslint-enable max-lines, @typescript-eslint/consistent-type-assertions, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unnecessary-condition, unicorn/consistent-function-scoping */
