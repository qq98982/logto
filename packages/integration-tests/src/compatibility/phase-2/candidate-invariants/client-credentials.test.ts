/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unsafe-assignment, unicorn/consistent-function-scoping -- Stateful temporary paths, captured runner calls, and hostile JSON mutations are intrinsic to these lifecycle and protocol tests. */
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

import type { TargetConfig } from '../../model.js';
import type {
  CommandRunnerRequest,
  CommandRunnerResult,
} from '../../phase-1/clients/command-provisioner.js';
import type { Phase2FixtureSecretLease, ProvisionedPhase2Fixture } from '../fixtures.js';
import { phase2ExpectedProfileAuthority, type Phase2ProfileRegistries } from '../profile.js';

import {
  clientCredentialsCandidateInvariantExpectedProjection,
  clientCredentialsCandidateInvariantIds,
  runClientCredentialsCandidateInvariantControls,
  runClientCredentialsCandidateInvariants,
} from './client-credentials.js';

const rootPrefix = '/var/tmp/henry-build/phase2-candidate-invariants-';
let root = '';
let driverPath = '';

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
const basicSecret = 'CandidateBasicSecret000000000001';
const postSecret = 'CandidatePostSecret0000000000002';
const topology = Object.freeze({
  projectName: 'aster-phase2-client-credentials-2222222222222222',
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
const fixture: ProvisionedPhase2Fixture = Object.freeze({
  public: Object.freeze({
    allocationId: 'candidate-invariant-fixture',
    clients: Object.freeze({
      basic: Object.freeze({ id: 'phase2-m2m-basic', method: 'client_secret_basic' }),
      post: Object.freeze({ id: 'phase2-m2m-post', method: 'client_secret_post' }),
    }),
    resources: Object.freeze({
      primary: Object.freeze({
        id: 'phase2-resource-primary',
        indicator: 'https://phase2.example.invalid/api-primary',
      }),
      default: Object.freeze({
        id: 'phase2-resource',
        indicator: 'https://phase2.example.invalid/api-default',
      }),
    }),
    organization: Object.freeze({ id: 'phase2-org', scopeName: 'organization:read' }),
    scopes: Object.freeze({
      read: Object.freeze({ id: 'read-scope', name: 'read' }),
      write: Object.freeze({ id: 'write-scope', name: 'write' }),
      unassigned: Object.freeze({ id: 'unassigned-scope', name: 'unassigned' }),
    }),
    boundary: Object.freeze({ primary: 'provisioned', foreign: 'unchanged' }),
  }),
  withSecretLease: async <Result>(
    use: (lease: Phase2FixtureSecretLease) => Promise<Result>
  ): Promise<Result> =>
    use(
      Object.freeze({
        getClientSecret: (client: 'basic' | 'post') =>
          client === 'basic' ? basicSecret : postSecret,
        getStatusClientSecret: () => 'CandidateStatusSecret00000000001',
        toJSON: (): never => {
          throw new Error('secret lease');
        },
      })
    ),
});
const profile: Phase2ProfileRegistries = Object.freeze({
  ...phase2ExpectedProfileAuthority,
  differentialScenarios: Object.freeze([
    'client-credentials.basic-explicit-resource',
    'client-credentials.post-explicit-resource',
    'client-credentials.default-resource',
    'client-credentials.resource-no-scope',
    'client-credentials.resource-partial-scope',
    'client-credentials.organization-empty-scope',
    'client-credentials.organization-scope',
    'client-credentials.organization-resource-scope',
    'client-credentials.unknown-client-basic',
    'client-credentials.unknown-client-post',
    'client-credentials.wrong-secret-basic',
    'client-credentials.wrong-secret-post',
    'client-credentials.mixed-authentication',
    'client-credentials.missing-target',
    'client-credentials.unknown-resource',
    'client-credentials.unassociated-organization',
    'client-credentials.duplicate-resource',
    'client-credentials.duplicate-scope-name',
    'client-credentials.malformed-scope-whitespace',
    'client-credentials.unsupported-parameter',
  ] as const),
  candidateInvariantScenarios: clientCredentialsCandidateInvariantIds,
  discovery: Object.freeze({
    grantTypesSupportedAppend: Object.freeze(['client_credentials'] as const),
    endpointFieldsAppend: Object.freeze(['introspection_endpoint', 'revocation_endpoint'] as const),
    stillAbsent: Object.freeze(['device_authorization_endpoint', 'registration_endpoint'] as const),
  }),
});

const result = (stdout: string, stderr = ''): CommandRunnerResult => ({
  exitCode: 0,
  signal: null,
  stdout,
  stderr,
  timedOut: false,
  killed: false,
  reaped: true,
});

beforeAll(async () => {
  root = await mkdtemp(rootPrefix);
  driverPath = path.join(root, 'phase2-driver');
  await writeFile(driverPath, '#!/bin/sh\nexit 1\n', { mode: 0o700 });
  await chmod(driverPath, 0o700);
});

afterAll(async () => {
  await rm(root, { force: true, recursive: true });
});

describe('Phase 2 candidate invariant driver', () => {
  it('runs the exact four real-driver contracts and emits sanitized positive/negative controls', async () => {
    const requests: CommandRunnerRequest[] = [];
    let fencedCalls = 0;
    const runner = async (request: CommandRunnerRequest): Promise<CommandRunnerResult> => {
      requests.push(request);
      const descriptor = JSON.parse(request.stdin) as {
        invariantId: (typeof clientCredentialsCandidateInvariantIds)[number];
      };
      return result(
        JSON.stringify({
          schemaVersion: 1,
          kind: 'phase2-client-credentials-candidate-invariant',
          invariantId: descriptor.invariantId,
          projection: clientCredentialsCandidateInvariantExpectedProjection(descriptor.invariantId),
          attestation: topology,
        })
      );
    };
    const evidence = await runClientCredentialsCandidateInvariants(profile, {
      target,
      foreignTarget,
      fixture,
      driverPath,
      controlSocket: path.join(root, 'control.sock'),
      topology,
      identityFence: {
        assertStable: async () => {
          // The fake identity remains stable during this driver contract test.
        },
        run: async <Result>(operation: () => Promise<Result>) => {
          fencedCalls += 1;
          return operation();
        },
      },
      environment: { PATH: '/usr/bin:/bin', HOME: '/forbidden' },
      runner,
    });

    expect(evidence.map(({ id }) => id)).toEqual(clientCredentialsCandidateInvariantIds);
    expect(fencedCalls).toBe(4);
    expect(evidence.map(({ negativeControl }) => negativeControl.pointer)).toEqual([
      '/foreignCredential',
      '/insert',
      '/tokenPublished',
      '/users',
    ]);
    expect(requests).toHaveLength(4);
    for (const request of requests) {
      expect(request.command).toBe(driverPath);
      expect(request.args).toEqual([]);
      expect(request.shell).toBe(false);
      expect(Object.keys(request.env).toSorted()).toEqual([
        'ASTER_ADMIN_URL',
        'ASTER_CORE_URL',
        'ASTER_FOREIGN_ADMIN_URL',
        'ASTER_FOREIGN_CORE_URL',
        'ASTER_PHASE2_CONTROL_SOCKET',
        'LC_ALL',
      ]);
      const descriptor = JSON.parse(request.stdin);
      expect(descriptor.credentials).toEqual({ basic: basicSecret, post: postSecret });
      expect(descriptor.target.primary).toEqual(target);
      expect(descriptor.target.foreign).toEqual(foreignTarget);
    }
    const serialized = JSON.stringify(evidence);
    expect(serialized).not.toContain(basicSecret);
    expect(serialized).not.toContain(postSecret);
    expect(serialized).not.toContain('access_token');
    expect(serialized).not.toMatch(/"authorization"\s*:/iu);
    expect(serialized).not.toMatch(/Authorization\s*:/u);
  });

  it('rejects profile drift, extra output, credential output, and unavailable drivers', async () => {
    await expect(
      runClientCredentialsCandidateInvariants(
        {
          ...profile,
          candidateInvariantScenarios: profile.candidateInvariantScenarios.slice(1),
        } as Phase2ProfileRegistries,
        {
          target,
          foreignTarget,
          fixture,
          driverPath,
          controlSocket: path.join(root, 'control.sock'),
        }
      )
    ).rejects.toThrow('Invalid Phase 2 candidate invariant');

    const extraRunner = async (request: CommandRunnerRequest): Promise<CommandRunnerResult> => {
      const descriptor = JSON.parse(request.stdin) as {
        invariantId: (typeof clientCredentialsCandidateInvariantIds)[number];
      };
      return result(
        JSON.stringify({
          schemaVersion: 1,
          kind: 'phase2-client-credentials-candidate-invariant',
          invariantId: descriptor.invariantId,
          projection: clientCredentialsCandidateInvariantExpectedProjection(descriptor.invariantId),
          attestation: topology,
          extra: true,
        })
      );
    };
    await expect(
      runClientCredentialsCandidateInvariants(profile, {
        target,
        foreignTarget,
        fixture,
        driverPath,
        controlSocket: path.join(root, 'control.sock'),
        topology,
        runner: extraRunner,
      })
    ).rejects.toThrow('Invalid Phase 2 candidate invariant');

    const leakingRunner = async (): Promise<CommandRunnerResult> =>
      result('', `driver leaked ${basicSecret}`);
    await expect(
      runClientCredentialsCandidateInvariants(profile, {
        target,
        foreignTarget,
        fixture,
        driverPath,
        controlSocket: path.join(root, 'control.sock'),
        topology,
        runner: leakingRunner,
      })
    ).rejects.toThrow('Invalid Phase 2 candidate invariant');

    await expect(
      runClientCredentialsCandidateInvariants(profile, {
        target,
        foreignTarget,
        fixture,
        driverPath: path.join(root, 'missing-driver'),
        controlSocket: path.join(root, 'control.sock'),
        topology,
      })
    ).rejects.toThrow('Invalid Phase 2 candidate invariant');
  });

  it('detects each invariant-specific negative mutation', () => {
    for (const id of clientCredentialsCandidateInvariantIds) {
      const evidence = runClientCredentialsCandidateInvariantControls(
        id,
        clientCredentialsCandidateInvariantExpectedProjection(id)
      );
      expect(evidence.positiveControl.detected).toBe(true);
      expect(evidence.negativeControl.detected).toBe(true);
    }
  });
});

/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unsafe-assignment, unicorn/consistent-function-scoping */
