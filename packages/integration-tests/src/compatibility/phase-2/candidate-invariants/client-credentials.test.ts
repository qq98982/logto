/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unsafe-assignment -- Stateful temporary paths, captured runner calls, and hostile JSON mutations are intrinsic to these lifecycle and protocol tests. */
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

import type { TargetConfig } from '../../model.js';
import type {
  CommandRunnerRequest,
  CommandRunnerResult,
} from '../../phase-1/clients/command-provisioner.js';
import type { Phase2FixtureSecretLease, ProvisionedPhase2Fixture } from '../fixtures.js';
import {
  loadPhase2Profile,
  phase2ExpectedProfileAuthority,
  type Phase2ProfileRegistries,
} from '../profile.js';

import {
  clientCredentialsCandidateInvariantExpectedProjection,
  clientCredentialsCandidateInvariantIds,
  runClientCredentialsCandidateInvariantControls,
  runClientCredentialsCandidateInvariants,
} from './client-credentials.js';

const rootPrefix = '/var/tmp/henry-build/phase2-candidate-invariants-';
let root = '';
let driverPath = '';
const canonicalProfilePaths = Object.freeze({
  profilePath: path.resolve(
    process.cwd(),
    'src/compatibility/phase-2/testing/phase-2-profile.json'
  ),
  schemaPath: path.resolve(
    process.cwd(),
    'src/compatibility/phase-2/testing/phase-2-profile.schema.json'
  ),
});

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
    deviceClients: Object.freeze({
      firstParty: Object.freeze({
        id: 'phase2-device-first',
        applicationType: 'Native',
        authenticationMethod: 'none',
        isThirdParty: false,
        deviceGrantEnabled: true,
      }),
      thirdParty: Object.freeze({
        id: 'phase2-device-third',
        applicationType: 'Native',
        authenticationMethod: 'none',
        isThirdParty: true,
        deviceGrantEnabled: true,
      }),
      missingGrant: Object.freeze({
        id: 'phase2-device-nogrant',
        applicationType: 'Native',
        authenticationMethod: 'none',
        isThirdParty: false,
        deviceGrantEnabled: false,
      }),
      ineligibleWeb: Object.freeze({
        id: 'phase2-device-web',
        applicationType: 'SPA',
        authenticationMethod: 'none',
        isThirdParty: false,
        deviceGrantEnabled: false,
      }),
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
  deviceOperations: Object.freeze([
    'device.authorize',
    'device.open-shortcut',
    'device.open-verification',
    'device.submit-verification',
    'device.submit-password',
    'device.read-consent',
    'device.submit-consent',
    'device.resume-consent',
    'device.open-success',
    'device.poll-token',
    'device.rotate-refresh',
    'device.introspect-token',
    'device.revoke-token',
    'device.request-userinfo',
    'device.open-logout',
    'device.confirm-logout',
    'device.discover-oidc',
    'device.discover-oauth',
  ] as const),
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
  candidateInvariantScenarios: Object.freeze([
    ...clientCredentialsCandidateInvariantIds,
    'device-authorization.forced-rls-isolation',
    'device-authorization.credentials-digest-only',
    'device-authorization.cross-tenant-lookup-rejected',
    'device-authorization.transition-failure-rolls-back',
    'device-token.concurrent-poll-one-winner',
    'device-token.consumed-replay-revokes-grant',
    'device-authorization.expired-cleanup-bounded',
    'device-evidence.secret-material-absent',
    'custom-jwt.storage-confidential-forced-rls',
    'custom-jwt.blocking-refresh-rolls-back',
    'custom-jwt.fetch-policy-boundary',
  ] as const),
  discovery: Object.freeze({
    grantTypesSupportedAppend: Object.freeze([
      'client_credentials',
      'urn:ietf:params:oauth:grant-type:device_code',
    ] as const),
    endpointFieldsAppend: Object.freeze([
      'introspection_endpoint',
      'revocation_endpoint',
      'end_session_endpoint',
      'device_authorization_endpoint',
    ] as const),
    scopesSupportedAppend: Object.freeze(['urn:aster:scope:sessions'] as const),
    stillAbsent: Object.freeze(['registration_endpoint'] as const),
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
  it('runs the exact legacy five-ID prefix for the closed sixteen-ID profile', async () => {
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
    expect(fencedCalls).toBe(5);
    expect(evidence.map(({ negativeControl }) => negativeControl.pointer)).toEqual([
      '/foreignCredential',
      '/insert',
      '/tokenPublished',
      '/users',
      '/clearMaterial',
    ]);
    expect(requests).toHaveLength(5);
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
    const canonicalProfile = await loadPhase2Profile(canonicalProfilePaths);
    const reordered = canonicalProfile.candidateInvariantScenarios.toSpliced(
      0,
      2,
      canonicalProfile.candidateInvariantScenarios[1]!,
      canonicalProfile.candidateInvariantScenarios[0]!
    );
    await Promise.all(
      [canonicalProfile.candidateInvariantScenarios.slice(1), reordered].map(
        async (candidateInvariantScenarios) =>
          expect(
            runClientCredentialsCandidateInvariants(
              { ...canonicalProfile, candidateInvariantScenarios } as Phase2ProfileRegistries,
              {
                target,
                foreignTarget,
                fixture,
                driverPath,
                controlSocket: path.join(root, 'control.sock'),
              }
            )
          ).rejects.toThrow('Invalid Phase 2 candidate invariant')
      )
    );

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

/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unsafe-assignment */
