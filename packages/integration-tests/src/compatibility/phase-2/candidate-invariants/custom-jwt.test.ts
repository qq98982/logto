/* eslint-disable max-lines, prefer-destructuring, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unsafe-assignment -- The protocol lifecycle and its stage-by-stage cleanup matrix are intentionally kept together. */
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

import type { TargetConfig } from '../../model.js';
import type {
  CommandRunnerRequest,
  CommandRunnerResult,
} from '../../phase-1/clients/command-provisioner.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';

import {
  createCustomJwtCandidateInvariantExecutor,
  customJwtCandidateInvariantExpectedProjection,
  customJwtCandidateInvariantIds,
  runCustomJwtCandidateInvariantControls,
  type CustomJwtCandidateWorkflow,
} from './custom-jwt.js';

const rootPrefix = '/var/tmp/henry-build/phase2-custom-jwt-invariants-';
let root = '';
let driverPath = '';
const refreshCredential = 'PrivateRefreshCredential000000000001';
const storageCanary = 'AsterStorageCanary000000000000001';
const target: TargetConfig = Object.freeze({
  label: 'candidate',
  coreUrl: 'https://candidate.example/',
  adminUrl: 'https://candidate-admin.example/',
});
const foreignTarget: TargetConfig = Object.freeze({
  label: 'candidate',
  coreUrl: 'https://candidate-foreign.example/',
  adminUrl: 'https://candidate-foreign-admin.example/',
});
const topology = Object.freeze({
  projectName: 'aster-phase2-custom-jwt-2222222222222222',
  primary: Object.freeze({
    containerId: '2'.repeat(64),
    service: 'candidate-primary-core',
    imageDigest: `sha256:${'b'.repeat(64)}`,
  }),
  foreign: Object.freeze({
    containerId: '4'.repeat(64),
    service: 'candidate-foreign-core',
    imageDigest: `sha256:${'b'.repeat(64)}`,
  }),
});
const fixture = Object.freeze({
  public: Object.freeze({
    allocationId: 'custom-jwt-invariant-fixture',
    clients: Object.freeze({
      basic: Object.freeze({ id: 'phase2-m2m-basic', method: 'client_secret_basic' }),
      post: Object.freeze({ id: 'phase2-m2m-post', method: 'client_secret_post' }),
    }),
    deviceClients: Object.freeze({
      firstParty: Object.freeze({
        id: 'first',
        applicationType: 'Native',
        authenticationMethod: 'none',
        isThirdParty: false,
        deviceGrantEnabled: true,
      }),
      thirdParty: Object.freeze({
        id: 'third',
        applicationType: 'Native',
        authenticationMethod: 'none',
        isThirdParty: true,
        deviceGrantEnabled: true,
      }),
      missingGrant: Object.freeze({
        id: 'missing',
        applicationType: 'Native',
        authenticationMethod: 'none',
        isThirdParty: false,
        deviceGrantEnabled: false,
      }),
      ineligibleWeb: Object.freeze({
        id: 'web',
        applicationType: 'SPA',
        authenticationMethod: 'none',
        isThirdParty: false,
        deviceGrantEnabled: false,
      }),
    }),
    resources: Object.freeze({
      primary: Object.freeze({
        id: 'primary',
        indicator: 'https://phase2.example.invalid/api-primary',
      }),
      default: Object.freeze({
        id: 'default',
        indicator: 'https://phase2.example.invalid/api-default',
      }),
    }),
    organization: Object.freeze({ id: 'organization', scopeName: 'organization:read' }),
    scopes: Object.freeze({
      read: Object.freeze({ id: 'read', name: 'read' }),
      write: Object.freeze({ id: 'write', name: 'write' }),
      unassigned: Object.freeze({ id: 'unassigned', name: 'unassigned' }),
    }),
    boundary: Object.freeze({ primary: 'provisioned', foreign: 'unchanged' }),
  }),
  withSecretLease: async () => {
    throw new Error('unused');
  },
}) as unknown as ProvisionedPhase2Fixture;

const result = (stdout: string, stderr = ''): CommandRunnerResult => ({
  exitCode: 0,
  signal: null,
  stdout,
  stderr,
  timedOut: false,
  killed: false,
  reaped: true,
});

const terminal = (id: (typeof customJwtCandidateInvariantIds)[number]) =>
  JSON.stringify({
    schemaVersion: 1,
    kind: 'phase2-client-credentials-candidate-invariant',
    invariantId: id,
    projection: customJwtCandidateInvariantExpectedProjection(id),
    attestation: topology,
  });

beforeEach(async () => {
  root = await mkdtemp(rootPrefix);
  driverPath = path.join(root, 'driver');
  await writeFile(driverPath, '#!/bin/sh\nexit 0\n', { mode: 0o700 });
  await chmod(driverPath, 0o700);
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

describe('Phase 2 custom JWT candidate invariants', () => {
  it('accepts live canary-absent forced-RLS storage evidence and detects its negative control', async () => {
    const requests: CommandRunnerRequest[] = [];
    const runner = async (request: CommandRunnerRequest) => {
      requests.push(request);
      return result(terminal(customJwtCandidateInvariantIds[0]));
    };
    const workflow: CustomJwtCandidateWorkflow = Object.freeze({
      withStorageCanary: async <Result>(
        use: (canary: string, semanticRoundTrip: true) => Promise<Result>
      ) => use(storageCanary, true),
      withRefreshCredential: async () => {
        throw new Error('unused');
      },
      withBlockingCustomizer: async () => {
        throw new Error('unused');
      },
      installCorrectedCustomizer: async () => {
        throw new Error('unused');
      },
      exchangeRefresh: async () => {
        throw new Error('unused');
      },
    });
    const executor = await createCustomJwtCandidateInvariantExecutor({
      target,
      foreignTarget,
      fixture,
      driverPath,
      controlSocket: path.join(root, 'control.sock'),
      topology,
      workflow,
      runner,
    });
    const projection = await executor.execute(customJwtCandidateInvariantIds[0]);
    const evidence = runCustomJwtCandidateInvariantControls(
      customJwtCandidateInvariantIds[0],
      projection
    );
    expect(evidence.negativeControl).toEqual({
      detected: true,
      pointer: '/envelope/canaryBytes',
    });
    expect(requests).toHaveLength(1);
    expect(JSON.parse(requests[0]!.stdin)).toMatchObject({
      operation: 'probe',
      private: { canary: storageCanary },
      observation: { semanticRoundTrip: true },
    });
    expect(JSON.stringify(evidence)).not.toContain(storageCanary);
  });

  it('restores the prior storage configuration when the canary probe fails', async () => {
    const calls: string[] = [];
    const workflow: CustomJwtCandidateWorkflow = Object.freeze({
      withStorageCanary: async <Result>(
        use: (canary: string, semanticRoundTrip: true) => Promise<Result>
      ) => {
        calls.push('canary-installed');
        try {
          return await use(storageCanary, true);
        } finally {
          calls.push('prior-restored');
        }
      },
      withRefreshCredential: async () => {
        throw new Error('unused');
      },
      withBlockingCustomizer: async () => {
        throw new Error('unused');
      },
      installCorrectedCustomizer: async () => {
        throw new Error('unused');
      },
      exchangeRefresh: async () => {
        throw new Error('unused');
      },
    });
    const executor = await createCustomJwtCandidateInvariantExecutor({
      target,
      foreignTarget,
      fixture,
      driverPath,
      controlSocket: path.join(root, 'control.sock'),
      topology,
      workflow,
      runner: async () => {
        throw new Error('canary detected');
      },
    });
    await expect(executor.execute(customJwtCandidateInvariantIds[0])).rejects.toThrow(
      'canary detected'
    );
    expect(calls).toEqual(['canary-installed', 'prior-restored']);
  });

  it('proves blocked refresh rollback and retries the same credential after correction', async () => {
    const calls: string[] = [];
    const requests: CommandRunnerRequest[] = [];
    const workflow: CustomJwtCandidateWorkflow = Object.freeze({
      withStorageCanary: async () => {
        throw new Error('unused');
      },
      withRefreshCredential: async <Result>(use: (value: string) => Promise<Result>) =>
        use(refreshCredential),
      withBlockingCustomizer: async <Result>(use: () => Promise<Result>) => {
        calls.push('blocking-installed');
        try {
          return await use();
        } finally {
          calls.push('prior-restored');
        }
      },
      installCorrectedCustomizer: async () => {
        calls.push('corrected');
      },
      exchangeRefresh: async (value: string) => {
        expect(value).toBe(refreshCredential);
        const corrected = calls.includes('corrected');
        calls.push(corrected ? 'retry' : 'blocked');
        return corrected
          ? { status: 200, tokenPublished: true }
          : { status: 400, error: 'invalid_request', tokenPublished: false };
      },
    });
    const runner = async (request: CommandRunnerRequest) => {
      requests.push(request);
      const descriptor = JSON.parse(request.stdin);
      if (descriptor.operation === 'arm') {
        return result(
          JSON.stringify({
            schemaVersion: 1,
            kind: 'phase2-custom-jwt-candidate-invariant-control',
            invariantId: customJwtCandidateInvariantIds[1],
            operation: 'arm',
            handle: 'a'.repeat(32),
            attestation: topology,
          })
        );
      }
      if (descriptor.operation === 'restore') {
        return result(
          JSON.stringify({
            schemaVersion: 1,
            kind: 'phase2-custom-jwt-candidate-invariant-control',
            invariantId: customJwtCandidateInvariantIds[1],
            operation: 'restore',
            ok: true,
            attestation: topology,
          })
        );
      }
      return result(terminal(customJwtCandidateInvariantIds[1]));
    };
    const executor = await createCustomJwtCandidateInvariantExecutor({
      target,
      foreignTarget,
      fixture,
      driverPath,
      controlSocket: path.join(root, 'control.sock'),
      topology,
      workflow,
      runner,
    });
    const projection = await executor.execute(customJwtCandidateInvariantIds[1]);
    const evidence = runCustomJwtCandidateInvariantControls(
      customJwtCandidateInvariantIds[1],
      projection
    );
    expect(calls).toEqual([
      'blocking-installed',
      'blocked',
      'corrected',
      'retry',
      'prior-restored',
    ]);
    expect(evidence.negativeControl.pointer).toBe('/rollback/refreshAuthority');
    expect(requests.map(({ stdin }) => JSON.parse(stdin).operation)).toEqual([
      'arm',
      'restore',
      'finish',
    ]);
    expect(requests[0]!.stdin).toContain(refreshCredential);
    expect(requests.slice(1).every(({ stdin }) => !stdin.includes(refreshCredential))).toBe(true);
    expect(JSON.stringify(evidence)).not.toContain(refreshCredential);
  });

  it('rejects secret reflection, malformed terminal evidence, and incorrect candidates', async () => {
    const workflowCalls: string[] = [];
    const workflow: CustomJwtCandidateWorkflow = Object.freeze({
      withStorageCanary: async () => {
        throw new Error('unused');
      },
      withRefreshCredential: async <Result>(use: (value: string) => Promise<Result>) =>
        use(refreshCredential),
      withBlockingCustomizer: async <Result>(use: () => Promise<Result>) => {
        workflowCalls.push('blocking-installed');
        try {
          return await use();
        } finally {
          workflowCalls.push('prior-restored');
        }
      },
      installCorrectedCustomizer: async () => {
        workflowCalls.push('corrected');
      },
      exchangeRefresh: async () => ({
        status: 400,
        error: 'invalid_request',
        tokenPublished: false,
      }),
    });
    const executor = await createCustomJwtCandidateInvariantExecutor({
      target,
      foreignTarget,
      fixture,
      driverPath,
      controlSocket: path.join(root, 'control.sock'),
      topology,
      workflow,
      runner: async () => result('', `leaked ${refreshCredential}`),
    });
    await expect(executor.execute(customJwtCandidateInvariantIds[1])).rejects.toThrow(
      'Invalid Phase 2 custom JWT candidate invariant'
    );
    expect(workflowCalls).toEqual(['blocking-installed', 'prior-restored']);
    expect(() =>
      runCustomJwtCandidateInvariantControls(customJwtCandidateInvariantIds[0], {
        ...customJwtCandidateInvariantExpectedProjection(customJwtCandidateInvariantIds[0]),
        adminRole: 'accepted',
      } as never)
    ).toThrow('Invalid Phase 2 custom JWT candidate invariant');
  });

  it.each(['arm', 'exchange', 'restore', 'correct', 'finish'] as const)(
    'restores prior configuration and independently aborts an armed handle after %s failure',
    async (failureStage) => {
      const calls: string[] = [];
      let exchangeCount = 0;
      const workflow: CustomJwtCandidateWorkflow = Object.freeze({
        withStorageCanary: async () => {
          throw new Error('unused');
        },
        withRefreshCredential: async <Result>(use: (value: string) => Promise<Result>) =>
          use(refreshCredential),
        withBlockingCustomizer: async <Result>(use: () => Promise<Result>) => {
          calls.push('blocking-installed');
          try {
            return await use();
          } finally {
            calls.push('prior-restored');
          }
        },
        installCorrectedCustomizer: async () => {
          calls.push('correct');
          if (failureStage === 'correct') {
            throw new Error('correct failed');
          }
        },
        exchangeRefresh: async () => {
          exchangeCount += 1;
          calls.push(`exchange-${exchangeCount}`);
          if (failureStage === 'exchange' && exchangeCount === 1) {
            throw new Error('exchange failed');
          }
          return exchangeCount === 1
            ? { status: 400, error: 'invalid_request', tokenPublished: false }
            : { status: 200, tokenPublished: true };
        },
      });
      const runner = async (request: CommandRunnerRequest) => {
        const descriptor = JSON.parse(request.stdin);
        const operation: unknown = descriptor.operation;
        if (typeof operation !== 'string') {
          throw new TypeError('missing operation');
        }
        calls.push(operation);
        if (operation === failureStage) {
          throw new Error(
            failureStage === 'restore'
              ? 'sibling refresh mutation detected'
              : `${failureStage} failed`
          );
        }
        if (operation === 'arm') {
          return result(
            JSON.stringify({
              schemaVersion: 1,
              kind: 'phase2-custom-jwt-candidate-invariant-control',
              invariantId: customJwtCandidateInvariantIds[1],
              operation: 'arm',
              handle: 'b'.repeat(32),
              attestation: topology,
            })
          );
        }
        if (operation === 'restore' || operation === 'abort') {
          return result(
            JSON.stringify({
              schemaVersion: 1,
              kind: 'phase2-custom-jwt-candidate-invariant-control',
              invariantId: customJwtCandidateInvariantIds[1],
              operation,
              ok: true,
              attestation: topology,
            })
          );
        }
        return result(terminal(customJwtCandidateInvariantIds[1]));
      };
      const executor = await createCustomJwtCandidateInvariantExecutor({
        target,
        foreignTarget,
        fixture,
        driverPath,
        controlSocket: path.join(root, 'control.sock'),
        topology,
        workflow,
        runner,
      });
      await expect(executor.execute(customJwtCandidateInvariantIds[1])).rejects.toThrow();
      expect(calls.at(-1)).toBe('prior-restored');
      expect(calls.includes('abort')).toBe(failureStage !== 'arm');
    }
  );
});

/* eslint-enable max-lines, prefer-destructuring, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unsafe-assignment */
