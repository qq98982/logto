/* eslint-disable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, unicorn/no-object-as-default-parameter, no-bitwise, unicorn/no-await-expression-member, @typescript-eslint/consistent-type-assertions -- CLI tests intentionally capture ordered effects, mutate filesystem modes, and inspect awaited filesystem metadata. */
import {
  chmod,
  link,
  lstat,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';

import { writeSecureJsonArtifact } from '../phase-1/secure-evidence-sink.js';

import { commonEmailCodeRegistrationExpectedProjection } from './browser/common-email-code-registration-target-driver.js';
import { commonEmailCodeExpectedProjection } from './browser/common-email-code-sign-in.js';
import { commonEmailPasswordRegistrationExpectedProjection } from './browser/common-email-password-registration-target-driver.js';
import { commonEmailRecoveryExpectedProjection } from './browser/common-email-recovery-target-driver.js';
import {
  clientCredentialsCandidateInvariantExpectedProjection,
  clientCredentialsCandidateInvariantIds,
  runClientCredentialsCandidateInvariantControls,
} from './candidate-invariants/client-credentials.js';
import {
  customJwtFetchPolicyCandidateInvariantIds,
  customJwtFetchPolicyExpectedProjection,
  runCustomJwtFetchPolicyControls,
} from './candidate-invariants/custom-jwt-fetch-policy.js';
import {
  customJwtCandidateInvariantExpectedProjection,
  customJwtCandidateInvariantIds,
  runCustomJwtCandidateInvariantControls,
} from './candidate-invariants/custom-jwt.js';
import {
  deviceCandidateInvariantExpectedProjection,
  deviceCandidateInvariantIds,
  runDeviceCandidateInvariantControls,
} from './candidate-invariants/device-authorization.js';
import {
  runVerificationCodeCandidateInvariantControls,
  verificationCodeCandidateInvariantExpectedProjection,
  verificationCodeCandidateInvariantIds,
} from './candidate-invariants/verification-code.js';
import {
  closedDeviceFailureStage,
  commonEmailCodeRegistrationScenarioFailure,
  commonReadyScenarioFailure,
  commonGoogleProjectionScenarioFailure,
  commonAdditionProjectionScenarioFailure,
  commonEmailPasswordScenarioFailure,
  deviceIdClaimKeysDifferenceDiagnostic,
  deviceProjectionDifferenceField,
  deviceScenarioProjectionFailure,
  executeDifferential,
  observeDeviceResourceRefreshContext,
  parsePhase2Arguments,
  phase2FixtureRecipeForMode,
  projectDeviceResourceRefreshClaims,
  readPhase2OracleArtifact,
  readPhase2TargetDescriptor,
  runPhase2TargetFixture,
  runPhase2Cli,
  runPhase2CliMain,
  withCandidateAdminBearerDiagnostic,
  type Phase2CliDependencies,
} from './cli.js';
import type { Phase2FixtureSecretLease, ProvisionedPhase2Fixture } from './fixtures.js';
import { phase2ExpectedBaseAcceptance, type Phase2ProfileRegistries } from './profile.js';
import { validatePhase2TargetDescriptor } from './runtime.js';
import { commonEmailPasswordExpectedProjection } from './scenarios/common-email-password.js';
import { commonGoogleExistingOwnerExpectedProjection } from './scenarios/common-google-existing-owner.js';
import { commonWechatWebExpectedProjection } from './scenarios/common-wechat-web.js';
import { commonGoogleRegistrationTestProjection } from './testing/common-google-registration-projection.js';

describe('device projection diagnostic fields', () => {
  it('maps a nested cookie difference to its closed root field', () => {
    expect(deviceProjectionDifferenceField('/cookies/0/name')).toBe('cookies');
    expect(deviceProjectionDifferenceField('/sequence/completion/cookies/0/options/0')).toBe(
      'completion-cookies'
    );
    expect(deviceProjectionDifferenceField('/sequence/private/cookies/0/name')).toBe('other');
    expect(deviceProjectionDifferenceField('/sequence/completion/private-token/value')).toBe(
      'other'
    );
    expect(deviceProjectionDifferenceField('/sequence/siblingAfter/headers/cache-control')).toBe(
      'sequence-siblingAfter-headers'
    );
    expect(deviceProjectionDifferenceField('/sequence/private/headers/private-token')).toBe(
      'other'
    );
    expect(deviceProjectionDifferenceField('/private-token/value')).toBe('other');
    expect(deviceProjectionDifferenceField('/id/claims/claimKeys/0')).toBe('id-claimKeys');
    expect(deviceProjectionDifferenceField('/id/claims/claimTypes/email')).toBe(
      'id-claimTypes-email'
    );
    expect(deviceProjectionDifferenceField('/id/header/alg')).toBe('id-header');
    expect(deviceProjectionDifferenceField('/id/claims/issuer')).toBe('id-issuer');
    expect(deviceProjectionDifferenceField('/id/claims/lifetimeSeconds')).toBe(
      'id-lifetimeSeconds'
    );
    expect(deviceProjectionDifferenceField('/id/lifetimeSeconds')).toBe('id-other');
    expect(deviceProjectionDifferenceField('/id/claims/claimTypes/private-token')).toBe('id-other');
    expect(deviceProjectionDifferenceField('/id/private-token/value')).toBe('id-other');
  });

  it('reports sorted allowlisted ID claim-key differences without claim values', () => {
    expect(
      deviceIdClaimKeysDifferenceDiagnostic(
        {
          id: {
            claims: {
              claimKeys: [
                'sub',
                'iss',
                'email',
                'auth_time',
                'organizations',
                'organization_roles',
              ],
              claimTypes: { private: 'oracle-secret' },
            },
          },
        },
        {
          id: {
            claims: {
              claimKeys: ['iss', 'sub', 'jti', 'client_id'],
              claimTypes: { private: 'candidate-secret' },
            },
          },
        }
      )
    ).toBe(
      'Phase 2 device ID claimKeys differ (only on oracle: auth_time,email,organization_roles,organizations; only on candidate: client_id,jti).'
    );
  });

  it('refuses an ID claim-key diagnostic outside the closed claim-name allowlist', () => {
    expect(
      deviceIdClaimKeysDifferenceDiagnostic(
        { id: { claims: { claimKeys: ['iss', 'private-token'] } } },
        { id: { claims: { claimKeys: ['iss'] } } }
      )
    ).toBeUndefined();
  });
});

const wrapCandidateConsumer = async (
  use: (bearer: string, lease: Phase2FixtureSecretLease) => Promise<unknown>
) => {
  try {
    return await use('test-bearer', {} as Phase2FixtureSecretLease);
  } catch {
    throw new TypeError('Invalid Phase 2 Admin Management bearer flow (consumer)');
  }
};

// eslint-disable-next-line unicorn/no-useless-undefined -- The diagnostic port explicitly represents an absent device stage.
const noDeviceStage = () => undefined;

describe('candidate fixture diagnostics', () => {
  it('preserves only closed candidate admin stages for the Common email row', () => {
    expect(() =>
      commonEmailPasswordScenarioFailure(
        'candidate',
        new Error('Phase 2 stage failed: candidate-admin-bearer-jwks')
      )
    ).toThrow('Phase 2 stage failed: candidate-admin-bearer-jwks');
    expect(() =>
      commonEmailPasswordScenarioFailure(
        'candidate',
        new Error('Invalid Phase 2 Admin Management bearer flow (jwks)')
      )
    ).toThrow('Phase 2 stage failed: candidate-admin-bearer-jwks');
    expect(() =>
      commonEmailPasswordScenarioFailure('candidate', new Error('private fixture detail'))
    ).toThrow('Phase 2 scenario failed: candidate/common.email.password-sign-in');
    expect(() =>
      commonEmailPasswordScenarioFailure(
        'candidate',
        new Error('Invalid Phase 2 Admin Management bearer flow (consumer)')
      )
    ).toThrow('Phase 2 scenario failed: candidate/common.email.password-sign-in');
    expect(() =>
      commonEmailPasswordScenarioFailure(
        'candidate',
        new Error('Phase 2 stage failed: candidate-admin-bearer-jwks:private')
      )
    ).toThrow('Phase 2 scenario failed: candidate/common.email.password-sign-in');
  });
  it('classifies the raw consumer failure before the admin wrapper erases it', async () => {
    await Promise.all(
      ['http-500', 'issuance-token-http'].map(async (detail) =>
        expect(
          withCandidateAdminBearerDiagnostic(
            wrapCandidateConsumer,
            async () => {
              throw new Error(`Phase 2 custom JWT scenario failed (primary:19:${detail})`);
            },
            noDeviceStage
          )
        ).rejects.toThrow(`Phase 2 stage failed: candidate-custom-jwt-19:${detail}`)
      )
    );
    await expect(
      withCandidateAdminBearerDiagnostic(
        wrapCandidateConsumer,
        async () => {
          throw new Error('Phase 2 custom JWT scenario failed (primary:22)');
        },
        () => 'jwt-verify'
      )
    ).rejects.toThrow('Phase 2 stage failed: candidate-custom-jwt-22:jwt-verify');
    await expect(
      withCandidateAdminBearerDiagnostic(
        async () => {
          throw new TypeError('Invalid Phase 2 Admin Management bearer flow (jwks)');
        },
        async () => {
          throw new Error('unreachable consumer');
        },
        () => {
          throw new Error('unreachable device stage');
        }
      )
    ).rejects.toThrow('Phase 2 stage failed: candidate-admin-bearer-jwks');
    for (const index of [0, 1, 2, 3, 4, 5]) {
      // eslint-disable-next-line no-await-in-loop -- Each closed fetch index is checked independently in registry order.
      await expect(
        withCandidateAdminBearerDiagnostic(
          wrapCandidateConsumer,
          async () => {
            throw new Error(`Phase 2 custom JWT fetch scenario failed (primary:${index})`);
          },
          noDeviceStage
        )
      ).rejects.toThrow(`Phase 2 stage failed: candidate-custom-jwt-fetch-${index}`);
    }
    await expect(
      withCandidateAdminBearerDiagnostic(
        wrapCandidateConsumer,
        async () => {
          throw new Error('unknown consumer failure');
        },
        noDeviceStage
      )
    ).rejects.toThrow('Phase 2 stage failed: candidate-admin-consumer-unknown');
    await Promise.all(
      [
        new Error('Phase 2 custom JWT scenario failed (primary:22):private'),
        new Error('Phase 2 custom JWT scenario failed (primary:22)\nprivate'),
        new Error('Phase 2 custom JWT scenario failed (primary:19:private-secret)'),
        new Error('Phase 2 custom JWT scenario failed (primary:19:http-500)\nprivate-secret'),
      ].map(async (privateFailure) =>
        expect(
          withCandidateAdminBearerDiagnostic(
            wrapCandidateConsumer,
            async () => {
              throw privateFailure;
            },
            () => 'jwt-verify'
          )
        ).rejects.toThrow('Phase 2 stage failed: candidate-fixture')
      )
    );
    await expect(
      withCandidateAdminBearerDiagnostic(
        async () => {
          throw new TypeError('Invalid Phase 2 Admin Management bearer flow (jwks):private');
        },
        async () => {
          throw new Error('unreachable consumer');
        },
        () => {
          throw new Error('unreachable device stage');
        }
      )
    ).rejects.toThrow('Phase 2 stage failed: candidate-fixture');
  });

  it('classifies candidate fixture phases at their execution boundaries', async () => {
    const events: string[] = [];
    const fixture = {} as ProvisionedPhase2Fixture;
    const provisioner = {
      provision: async () => {
        events.push('provision');
        return fixture;
      },
      projectState: async () => ({}),
      cleanup: async () => {
        events.push('cleanup');
      },
    };
    await expect(
      runPhase2TargetFixture({
        kind: 'candidate',
        provisioner,
        waitUntilReady: async () => {
          events.push('readiness');
        },
        readPublicJwks: async () => {
          events.push('public-jwks');
          return 'jwks';
        },
        use: async (jwks) => {
          events.push(`body:${jwks}`);
          return 'result';
        },
      })
    ).resolves.toBe('result');
    expect(events).toEqual(['provision', 'readiness', 'public-jwks', 'body:jwks', 'cleanup']);

    for (const [phase, expected] of [
      ['provision', 'candidate-fixture-provision'],
      ['readiness', 'candidate-fixture-readiness'],
      ['public-jwks', 'candidate-fixture-public-jwks'],
    ] as const) {
      // eslint-disable-next-line no-await-in-loop -- Each fixture boundary must report its own fixed failure category.
      await expect(
        runPhase2TargetFixture({
          kind: 'candidate',
          provisioner: {
            ...provisioner,
            provision: async () => {
              if (phase === 'provision') {
                throw new Error('private');
              }
              return fixture;
            },
          },
          waitUntilReady: async () => {
            if (phase === 'readiness') {
              throw new Error('private');
            }
          },
          readPublicJwks: async () => {
            if (phase === 'public-jwks') {
              throw new Error('private');
            }
            return 'jwks';
          },
          use: async () => 'result',
        })
      ).rejects.toThrow(`Phase 2 stage failed: ${expected}`);
    }
  });

  it('distinguishes candidate fixture cleanup from body plus cleanup', async () => {
    const fixture = {} as ProvisionedPhase2Fixture;
    const provisioner = {
      provision: async () => fixture,
      projectState: async () => ({}),
      cleanup: async () => {
        throw new Error('private cleanup');
      },
    };
    const invoke = async (body: () => Promise<string>) =>
      runPhase2TargetFixture({
        kind: 'candidate',
        provisioner,
        waitUntilReady: async () => {
          Object.isFrozen(fixture);
        },
        readPublicJwks: async () => 'jwks',
        use: body,
      });
    await expect(invoke(async () => 'result')).rejects.toThrow(
      'Phase 2 stage failed: candidate-fixture-cleanup'
    );
    await expect(
      invoke(async () => {
        throw new Error('private body');
      })
    ).rejects.toThrow('Phase 2 stage failed: candidate-fixture-body-cleanup');
  });

  it('preserves a body aggregate when fixture cleanup succeeds', async () => {
    const fixture = {} as ProvisionedPhase2Fixture;
    const bodyFailure = new AggregateError([new Error('private body')], 'private aggregate');
    await expect(
      runPhase2TargetFixture({
        kind: 'candidate',
        provisioner: {
          provision: async () => fixture,
          projectState: async () => ({}),
          cleanup: async () => {
            Object.isFrozen(fixture);
          },
        },
        waitUntilReady: async () => {
          Object.isFrozen(fixture);
        },
        readPublicJwks: async () => 'jwks',
        use: async () => {
          throw bodyFailure;
        },
      })
    ).rejects.toBe(bodyFailure);
  });
});

describe('device resource refresh claim projection', () => {
  const expected = Object.freeze({
    issuer: 'https://issuer.example/oidc',
    audience: 'https://resource.example',
    subject: 'approved-user',
    clientId: 'approved-device-client',
  });
  const validClaims = Object.freeze({
    iss: expected.issuer,
    aud: expected.audience,
    sub: expected.subject,
    client_id: expected.clientId,
    probe_invoked: true,
    probe_user_context_present: true,
    probe_application_context_present: true,
    probe_user_matches_token: true,
    probe_application_matches_token: true,
    probe_user_id: expected.subject,
    probe_application_id: expected.clientId,
    probe_token_account_id: expected.subject,
    probe_token_client_id: expected.clientId,
    probe_token_kind: 'AccessToken',
    probe_grant_type: 'device_code refresh_token',
  });

  it('publishes only safe relationship and authority results for valid claims', () => {
    expect(projectDeviceResourceRefreshClaims(validClaims, expected)).toEqual({
      invoked: true,
      userContextPresent: true,
      applicationContextPresent: true,
      userMatchesToken: true,
      applicationMatchesToken: true,
      protectedClaimsMatch: true,
      tokenKind: 'access_token',
      grantType: 'device_code refresh_token',
    });
  });

  it.each(['iss', 'aud', 'sub', 'client_id'] as const)(
    'rejects a signed JWT with the wrong %s authority',
    (claim) => {
      expect(
        projectDeviceResourceRefreshClaims({ ...validClaims, [claim]: 'wrong-authority' }, expected)
          .protectedClaimsMatch
      ).toBe(false);
    }
  );

  it('preserves false customizer relationship checks', () => {
    expect(
      projectDeviceResourceRefreshClaims(
        {
          ...validClaims,
          probe_user_matches_token: false,
          probe_application_matches_token: false,
        },
        expected
      )
    ).toMatchObject({ userMatchesToken: false, applicationMatchesToken: false });
  });

  it('rejects internally matching context and token identities outside the approved fixture', () => {
    expect(
      projectDeviceResourceRefreshClaims(
        {
          ...validClaims,
          probe_user_id: 'wrong-user',
          probe_token_account_id: 'wrong-user',
          probe_application_id: 'wrong-client',
          probe_token_client_id: 'wrong-client',
        },
        expected
      )
    ).toMatchObject({
      userMatchesToken: false,
      applicationMatchesToken: false,
      protectedClaimsMatch: true,
    });
  });
});

describe('device resource refresh observation', () => {
  type ObservationInput = Parameters<typeof observeDeviceResourceRefreshContext>[0];
  type ObservationStage = Parameters<ObservationInput['recordStage']>[0];
  const expected = Object.freeze({
    issuer: 'https://issuer.example/oidc',
    audience: 'https://resource.example',
    subject: 'approved-user',
    clientId: 'approved-device-client',
  });
  const validClaims = Object.freeze({
    iss: expected.issuer,
    aud: expected.audience,
    sub: expected.subject,
    client_id: expected.clientId,
    probe_invoked: true,
    probe_user_context_present: true,
    probe_application_context_present: true,
    probe_user_matches_token: true,
    probe_application_matches_token: true,
    probe_user_id: expected.subject,
    probe_application_id: expected.clientId,
    probe_token_account_id: expected.subject,
    probe_token_client_id: expected.clientId,
    probe_token_kind: 'AccessToken',
    probe_grant_type: 'device_code refresh_token',
  });
  const createHarness = (overrides: Partial<ObservationInput['transport']> = {}) => {
    const stages: ObservationStage[] = [];
    let clearCalls = 0;
    let verifiedToken: string | undefined;
    const absentToken = new Map<string, string>().get('missing');
    const clear = () => {
      clearCalls += 1;
    };
    const verifyAccessToken = async (token: string) => {
      verifiedToken = token;
      return validClaims;
    };
    let credentialLeaseReads = 0;
    const transport = {
      withCredentialLease: async <Result>(
        use: (lease: {
          getAccessToken(): string | undefined;
          getRefreshToken(): string | undefined;
          getIdToken(): string | undefined;
          getPreviousRefreshToken(): string | undefined;
          toJSON(): never;
        }) => Result | Promise<Result>
      ) => {
        credentialLeaseReads += 1;
        return use({
          getAccessToken: () =>
            credentialLeaseReads === 1 ? 'opaque-access-token' : 'signed.access.token',
          getRefreshToken: () => 'opaque-refresh-token',
          getIdToken: () => absentToken,
          getPreviousRefreshToken: () => absentToken,
          toJSON: () => {
            throw new TypeError('credential lease is not serializable');
          },
        });
      },
      requestLifecycle: async () => ({ status: 200 }),
      clear,
      ...overrides,
    };
    return {
      stages,
      clear,
      verifyAccessToken,
      transport,
      credentialLeaseReads: () => credentialLeaseReads,
      clearCalls: () => clearCalls,
      verifiedToken: () => verifiedToken,
      input: {
        transport,
        approveAuthorization: async () => {
          await Promise.resolve();
        },
        pollToken: async () => {
          await Promise.resolve();
        },
        verifyAccessToken,
        refreshRequest: Object.freeze({
          kind: 'refresh' as const,
          method: 'POST' as const,
          proof: Object.freeze({ method: 'public' as const, clientId: expected.clientId }),
          resource: expected.audience,
          scope: 'read',
        }),
        expected,
        recordStage: (stage: ObservationStage) => {
          stages.push(stage);
        },
      } satisfies ObservationInput,
    };
  };

  it('observes a successful refresh in the closed lifecycle order and clears credentials', async () => {
    const harness = createHarness();
    await expect(observeDeviceResourceRefreshContext(harness.input)).resolves.toMatchObject({
      status: 200,
      initialAccessOpaque: true,
      invoked: true,
    });
    expect(harness.stages).toEqual([
      'authorize',
      'token-poll',
      'initial-lease',
      'refresh-request',
      'refresh-http',
      'jwt-verify',
      'projection',
    ]);
    expect(harness.verifiedToken()).toBe('signed.access.token');
    expect(harness.clearCalls()).toBe(1);
  });

  it('rejects a non-200 refresh before reading or verifying refreshed credentials', async () => {
    const harness = createHarness({ requestLifecycle: async () => ({ status: 503 }) });
    await expect(observeDeviceResourceRefreshContext(harness.input)).rejects.toEqual(
      new TypeError('Invalid Phase 2 custom JWT device resource refresh context')
    );
    expect(harness.stages).toEqual([
      'authorize',
      'token-poll',
      'initial-lease',
      'refresh-request',
      'refresh-http',
    ]);
    expect(harness.credentialLeaseReads()).toBe(1);
    expect(harness.verifiedToken()).toBeUndefined();
    expect(harness.clearCalls()).toBe(1);
  });

  const failureCases: ReadonlyArray<
    readonly [ObservationStage, (input: ObservationInput) => ObservationInput]
  > = [
    [
      'authorize',
      (input) => ({
        ...input,
        approveAuthorization: async () => {
          throw new Error('private user id');
        },
      }),
    ],
    [
      'approval-password',
      (input) => ({
        ...input,
        approveAuthorization: async () => {
          throw new TypeError('Invalid Phase 2 device already-used-code step (approval-password)');
        },
      }),
    ],
    [
      'token-poll',
      (input) => ({
        ...input,
        pollToken: async () => {
          throw new Error('private device code and user id');
        },
      }),
    ],
    [
      'initial-lease',
      (input) => ({
        ...input,
        transport: {
          ...input.transport,
          withCredentialLease: async () => {
            throw new Error('private initial token');
          },
        },
      }),
    ],
    [
      'refresh-request',
      (input) => ({
        ...input,
        transport: {
          ...input.transport,
          requestLifecycle: async () => {
            throw new Error('private response');
          },
        },
      }),
    ],
    [
      'jwt-verify',
      (input) => ({
        ...input,
        verifyAccessToken: async () => {
          throw new Error('private jwt');
        },
      }),
    ],
  ];

  it.each(failureCases)('reports fixed error text for a %s failure', async (stage, transform) => {
    const harness = createHarness();
    const input = transform(harness.input);
    await expect(observeDeviceResourceRefreshContext(input)).rejects.toEqual(
      new TypeError('Invalid Phase 2 custom JWT device resource refresh context')
    );
    expect(harness.stages.at(-1)).toBe(stage);
    expect(harness.clearCalls()).toBe(1);
  });
});

describe('Phase 2 fixture recipe routing', () => {
  it('selects the candidate invariant recipe only for candidate-invariants', () => {
    expect(phase2FixtureRecipeForMode('candidate-invariants')).toBe('phase2CandidateInvariants');
    expect(phase2FixtureRecipeForMode('oracle')).toBe('fullPhase1');
    expect(phase2FixtureRecipeForMode('differential')).toBe('fullPhase1');
  });
});

describe('Common email password differential comparison', () => {
  const oracle = Object.freeze({
    target: 'oracle' as const,
    discovery: Object.freeze({}),
    controls: Object.freeze([]),
    scenarios: Object.freeze([
      Object.freeze({
        id: 'common.email.password-sign-in',
        projection: commonEmailPasswordExpectedProjection,
      }),
    ]),
  });
  const candidateTarget = Object.freeze({
    descriptor: Object.freeze({ kind: 'candidate' as const }),
  });

  it('executes the email branch and accepts identical exact projections', async () => {
    const result = await executeDifferential(
      {
        profile,
        oracle: oracle as never,
        candidate: candidateTarget as never,
        sessionRoot: '/private/session',
      },
      async () =>
        ({
          target: 'candidate',
          discovery: {},
          controls: [],
          scenarios: [
            {
              id: 'common.email.password-sign-in',
              projection: commonEmailPasswordExpectedProjection,
            },
          ],
        }) as never
    );

    expect(result).toMatchObject({
      schemaVersion: 1,
      mode: 'differential',
      comparisons: [{ scenarioId: 'common.email.password-sign-in', differenceCount: 0 }],
    });
  });

  it('fails closed when one exact email projection field differs', async () => {
    await expect(
      executeDifferential(
        {
          profile,
          oracle: oracle as never,
          candidate: candidateTarget as never,
          sessionRoot: '/private/session',
        },
        async () =>
          ({
            target: 'candidate',
            discovery: {},
            controls: [],
            scenarios: [
              {
                id: 'common.email.password-sign-in',
                projection: { ...commonEmailPasswordExpectedProjection, emailVerified: false },
              },
            ],
          }) as never
      )
    ).rejects.toThrow('Phase 2 scenario failed: candidate/common.email.password-sign-in');
  });
});

describe('Common email Code differential comparison', () => {
  const oracle = Object.freeze({
    target: 'oracle' as const,
    discovery: Object.freeze({}),
    controls: Object.freeze([]),
    scenarios: Object.freeze([
      Object.freeze({
        id: 'common.email.code-sign-in',
        projection: commonEmailCodeExpectedProjection,
      }),
    ]),
  });
  const candidateTarget = Object.freeze({
    descriptor: Object.freeze({ kind: 'candidate' as const }),
  });

  it('executes the Code branch and accepts identical exact projections', async () => {
    const result = await executeDifferential(
      {
        profile,
        oracle: oracle as never,
        candidate: candidateTarget as never,
        sessionRoot: '/private/session',
      },
      async () =>
        ({
          target: 'candidate',
          discovery: {},
          controls: [],
          scenarios: [
            { id: 'common.email.code-sign-in', projection: commonEmailCodeExpectedProjection },
          ],
        }) as never
    );
    expect(result).toMatchObject({
      comparisons: [{ scenarioId: 'common.email.code-sign-in', differenceCount: 0 }],
    });
  });

  it('fails closed when one nested Code control differs', async () => {
    await expect(
      executeDifferential(
        {
          profile,
          oracle: oracle as never,
          candidate: candidateTarget as never,
          sessionRoot: '/private/session',
        },
        async () =>
          ({
            target: 'candidate',
            discovery: {},
            controls: [],
            scenarios: [
              {
                id: 'common.email.code-sign-in',
                projection: {
                  ...commonEmailCodeExpectedProjection,
                  controls: {
                    ...commonEmailCodeExpectedProjection.controls,
                    expiry: { status: 400, error: 'verification_code.not_found' },
                  },
                },
              },
            ],
          }) as never
      )
    ).rejects.toThrow('Phase 2 scenario failed: candidate/common.email.code-sign-in');
  });
});

describe('Common email Code registration differential comparison', () => {
  const oracle = Object.freeze({
    target: 'oracle' as const,
    discovery: Object.freeze({}),
    controls: Object.freeze([]),
    scenarios: Object.freeze([
      Object.freeze({
        id: 'common.email.code-registration',
        projection: commonEmailCodeRegistrationExpectedProjection,
      }),
    ]),
  });
  const candidateTarget = Object.freeze({
    descriptor: Object.freeze({ kind: 'candidate' as const }),
  });

  it('accepts identical exact registration projections', async () => {
    const result = await executeDifferential(
      {
        profile,
        oracle: oracle as never,
        candidate: candidateTarget as never,
        sessionRoot: '/private/session',
      },
      async () =>
        ({
          target: 'candidate',
          discovery: {},
          controls: [],
          scenarios: [
            {
              id: 'common.email.code-registration',
              projection: commonEmailCodeRegistrationExpectedProjection,
            },
          ],
        }) as never
    );
    expect(result).toMatchObject({
      comparisons: [{ scenarioId: 'common.email.code-registration', differenceCount: 0 }],
    });
  });

  it('fails closed when a registration control differs', async () => {
    await expect(
      executeDifferential(
        {
          profile,
          oracle: oracle as never,
          candidate: candidateTarget as never,
          sessionRoot: '/private/session',
        },
        async () =>
          ({
            target: 'candidate',
            discovery: {},
            controls: [],
            scenarios: [
              {
                id: 'common.email.code-registration',
                projection: {
                  ...commonEmailCodeRegistrationExpectedProjection,
                  occupiedRegistration: {
                    ...commonEmailCodeRegistrationExpectedProjection.occupiedRegistration,
                    ownerUnchanged: false,
                  },
                },
              },
            ],
          }) as never
      )
    ).rejects.toThrow('Phase 2 scenario failed: candidate/common.email.code-registration');
  });
});

describe('new Common browser registration and recovery comparisons', () => {
  const cases = [
    {
      id: 'common.email.password-registration',
      projection: commonEmailPasswordRegistrationExpectedProjection,
      changed: { ...commonEmailPasswordRegistrationExpectedProjection, sameOwner: false },
    },
    {
      id: 'common.password.recovery',
      projection: commonEmailRecoveryExpectedProjection,
      changed: { ...commonEmailRecoveryExpectedProjection, priorSessionUsable: false },
    },
  ];
  it.each(cases)('compares exact $id state and rejects a changed security outcome', async (row) => {
    const oracle = {
      target: 'oracle',
      discovery: {},
      controls: [],
      scenarios: [{ id: row.id, projection: row.projection }],
    };
    const input = {
      profile,
      oracle: oracle as never,
      candidate: { descriptor: { kind: 'candidate' } } as never,
      sessionRoot: '/private/session',
    };
    const run = async (projection: unknown) =>
      ({
        target: 'candidate',
        discovery: {},
        controls: [],
        scenarios: [{ id: row.id, projection }],
      }) as never;
    const compared = await executeDifferential(input, async () => run(row.projection));
    expect(compared).toMatchObject({ comparisons: [{ scenarioId: row.id, differenceCount: 0 }] });
    await expect(executeDifferential(input, async () => run(row.changed))).rejects.toThrow(
      `Phase 2 scenario failed: candidate/${row.id}`
    );
  });
});

const rootPrefix = '/var/tmp/henry-build/phase2-cli-';
let root = '';
let profilePath = '';
let schemaPath = '';
let oracleTargetPath = '';
let candidateTargetPath = '';

const profile: Phase2ProfileRegistries = Object.freeze({
  profileSha256: '1'.repeat(64),
  schemaSha256: '2'.repeat(64),
  baseAcceptance: phase2ExpectedBaseAcceptance,
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
    'client-credentials.cross-tenant-authority-rejected',
    'client-credentials.request-role-write-rejected',
    'client-credentials.signing-failure-rolls-back',
    'client-credentials.user-authority-unchanged',
    'logout-session.verification-storage-closed',
    ...verificationCodeCandidateInvariantIds,
    ...deviceCandidateInvariantIds,
    ...customJwtCandidateInvariantIds,
    ...customJwtFetchPolicyCandidateInvariantIds,
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

const targetDocument = (kind: 'oracle' | 'candidate') => ({
  schemaVersion: 1,
  kind,
  sourceCommit: kind === 'oracle' ? '6852a7b8c8984c5c12b2061e8c51faa310a36412' : 'a'.repeat(40),
  imageDigest:
    kind === 'oracle'
      ? 'sha256:76a9977bfc5ea3ed5b7623b879c27256670e377e27b987e8af99b53d55b30bbd'
      : `sha256:${'b'.repeat(64)}`,
  projectName: `aster-phase2-client-credentials-${(kind === 'oracle' ? '1' : '2').repeat(16)}`,
  primaryContainerId: (kind === 'oracle' ? '1' : '2').repeat(64),
  foreignContainerId: (kind === 'oracle' ? '3' : '4').repeat(64),
  target: {
    label: kind,
    coreUrl: kind === 'oracle' ? 'http://localhost:3311/' : 'http://localhost:3321/',
    adminUrl: kind === 'oracle' ? 'http://localhost:3411/' : 'http://localhost:3421/',
  },
  foreignTarget: {
    label: kind,
    coreUrl: kind === 'oracle' ? 'http://localhost:3312/' : 'http://localhost:3322/',
    adminUrl: kind === 'oracle' ? 'http://localhost:3412/' : 'http://localhost:3422/',
  },
  stateDriver: {
    path: '/usr/bin/true',
    sha256: 'c'.repeat(64),
    controlSocket: `/tmp/${kind}-state.sock`,
  },
  fetchObserverReceiptFile: `/tmp/${kind}-fetch-receipts.ndjson`,
  ...(kind === 'candidate'
    ? {
        fixtureSocket: '/tmp/candidate-fixture.sock',
        fixtureExecutable: { path: '/usr/bin/true', sha256: 'd'.repeat(64) },
        invariantDriver: {
          path: '/usr/bin/true',
          sha256: 'e'.repeat(64),
          controlSocket: '/tmp/candidate-invariant.sock',
        },
      }
    : {}),
});

beforeEach(async () => {
  root = await mkdtemp(rootPrefix);
  await chmod(root, 0o700);
  profilePath = path.join(root, 'profile.json');
  schemaPath = path.join(root, 'schema.json');
  oracleTargetPath = path.join(root, 'oracle-target.json');
  candidateTargetPath = path.join(root, 'candidate-target.json');
  await Promise.all([
    writeFile(profilePath, '{}', { mode: 0o600 }),
    writeFile(schemaPath, '{}', { mode: 0o600 }),
    writeFile(oracleTargetPath, JSON.stringify(targetDocument('oracle')), { mode: 0o600 }),
    writeFile(candidateTargetPath, JSON.stringify(targetDocument('candidate')), { mode: 0o600 }),
  ]);
});

afterEach(async () => {
  await rm(root, { force: true, recursive: true });
});

const dependencies = (
  calls: string[],
  evidence: unknown = { schemaVersion: 1, mode: 'test', sanitized: true }
): Phase2CliDependencies => ({
  loadProfile: async () => profile,
  readTarget: readPhase2TargetDescriptor,
  readOracleArtifact: async () =>
    ({
      schemaVersion: 1,
      mode: 'oracle',
      sanitizerSuccess: true,
      provenance: {
        profileSha256: profile.profileSha256,
        schemaSha256: profile.schemaSha256,
        baseAcceptance: profile.baseAcceptance,
        harness: {
          repositoryUrl: 'https://github.com/qq98982/logto.git',
          headCommit: 'f'.repeat(40),
          headTree: 'a'.repeat(40),
          runtimeBundleSha256: 'b'.repeat(64),
        },
        oracle: {
          sourceCommit: '6852a7b8c8984c5c12b2061e8c51faa310a36412',
          imageDigest: 'sha256:76a9977bfc5ea3ed5b7623b879c27256670e377e27b987e8af99b53d55b30bbd',
          topology: { primaryRole: 'oracle-primary-core', foreignRole: 'oracle-foreign-core' },
          drivers: { state: { role: 'state-driver', sha256: 'c'.repeat(64) } },
        },
      },
      payload: { schemaVersion: 1, mode: 'oracle', target: { target: 'oracle' } },
    }) as never,
  executeOracle: async () => {
    calls.push('oracle');
    return evidence;
  },
  executeDifferential: async () => {
    calls.push('differential');
    return evidence;
  },
  executeCandidateInvariants: async () => {
    calls.push('candidate-invariants');
    return Object.freeze({
      schemaVersion: 1,
      mode: 'candidate-invariants',
      invariants: Object.freeze([
        ...clientCredentialsCandidateInvariantIds.map((id) =>
          runClientCredentialsCandidateInvariantControls(
            id,
            clientCredentialsCandidateInvariantExpectedProjection(id)
          )
        ),
        ...verificationCodeCandidateInvariantIds.map((id) =>
          runVerificationCodeCandidateInvariantControls(
            id,
            verificationCodeCandidateInvariantExpectedProjection(id)
          )
        ),
        ...deviceCandidateInvariantIds.map((id) =>
          runDeviceCandidateInvariantControls(id, deviceCandidateInvariantExpectedProjection(id))
        ),
        ...customJwtCandidateInvariantIds.map((id) =>
          runCustomJwtCandidateInvariantControls(
            id,
            customJwtCandidateInvariantExpectedProjection(id)
          )
        ),
        ...customJwtFetchPolicyCandidateInvariantIds.map((id) =>
          runCustomJwtFetchPolicyControls(id, customJwtFetchPolicyExpectedProjection(id))
        ),
      ]),
    });
  },
  publish: async (outputPath, value) => {
    calls.push(`publish:${path.basename(outputPath)}`);
    await writeSecureJsonArtifact(outputPath, value);
  },
  removeSessionRoot: async (sessionRoot) => {
    await rm(sessionRoot, { force: true, recursive: true });
  },
  stdout: (message) => {
    calls.push(`stdout:${message.trim()}`);
  },
  stderr: (message) => {
    calls.push(`stderr:${message.trim()}`);
  },
  inspectHarness: async () => ({
    repositoryRoot: '/private',
    repositoryDev: '1',
    repositoryIno: '2',
    clean: true,
    public: {
      repositoryUrl: 'https://github.com/qq98982/logto.git',
      headCommit: 'f'.repeat(40),
      headTree: 'a'.repeat(40),
      runtimeBundleSha256: 'b'.repeat(64),
    },
    runtimeEntryPath: '/private/lib/compatibility/phase-2/cli.js',
  }),
  recheckHarness: async () => {
    // The fake capability remains stable for this CLI unit test.
  },
  verifyTarget: async (target) => ({
    descriptor: target,
    topology: {
      projectName: target.projectName,
      primary: {
        containerId: target.primaryContainerId,
        service: `${target.kind}-primary-core`,
        imageDigest: target.imageDigest,
      },
      foreign: {
        containerId: target.foreignContainerId,
        service: `${target.kind}-foreign-core`,
        imageDigest: target.imageDigest,
      },
    },
    stateDriver: {
      path: '/private/state',
      sha256: target.stateDriver.sha256,
      dev: '1',
      ino: '2',
      uid: 1,
      mode: 0o700,
      nlink: 1,
    },
    stateControlSocket: {
      path: '/private/state.sock',
      dev: '1',
      ino: '3',
      uid: 1,
      mode: 0o600,
      nlink: 1,
      type: 'unix-socket',
    },
    ...(target.fixtureExecutable && {
      fixtureExecutable: {
        path: '/private/fixture',
        sha256: target.fixtureExecutable.sha256,
        dev: '1',
        ino: '4',
        uid: 1,
        mode: 0o700,
        nlink: 1,
      },
    }),
    ...(target.fixtureSocket && {
      fixtureSocket: {
        path: '/private/fixture.sock',
        dev: '1',
        ino: '5',
        uid: 1,
        mode: 0o600,
        nlink: 1,
        type: 'unix-socket',
      },
    }),
    ...(target.invariantDriver && {
      invariantDriver: {
        path: '/private/invariant',
        sha256: target.invariantDriver.sha256,
        dev: '1',
        ino: '6',
        uid: 1,
        mode: 0o700,
        nlink: 1,
      },
      invariantControlSocket: {
        path: '/private/invariant.sock',
        dev: '1',
        ino: '7',
        uid: 1,
        mode: 0o600,
        nlink: 1,
        type: 'unix-socket',
      },
    }),
    fetchObserverReceiptFile: {
      path: target.fetchObserverReceiptFile,
      dev: '1',
      ino: '8',
      uid: 1,
      mode: 0o600,
      nlink: 1,
    },
  }),
  prepareTarget: async (verified) => ({
    descriptor: verified.descriptor,
    topology: verified.topology,
    fence: {
      run: async <Result>(operation: () => Promise<Result>) => operation(),
      assertStable: async () => {
        // The fake target identity remains stable for this CLI unit test.
      },
    },
    fetchObserverReceiptFile: verified.fetchObserverReceiptFile,
  }),
});

const oracleArguments = (output = path.join(root, 'phase-2-client-credentials-oracle.json')) => [
  'oracle',
  '--profile',
  profilePath,
  '--schema',
  schemaPath,
  '--target',
  oracleTargetPath,
  '--output',
  output,
  '--temp-root',
  root,
];

describe('Phase 2 CLI', () => {
  it('classifies only exact closed device failure stages', () => {
    for (const stage of [
      'lifecycle-request',
      'lifecycle-response',
      'token-response',
      'credential-lease',
    ] as const) {
      expect(
        closedDeviceFailureStage(
          new TypeError(`Invalid Phase 2 device authorization transport (${stage})`)
        )
      ).toBe(stage);
    }
    expect(
      closedDeviceFailureStage(new TypeError('Invalid Phase 2 device authorization projection'))
    ).toBe('projection');
    expect(
      closedDeviceFailureStage(new TypeError('Invalid Phase 2 device authorization scenario'))
    ).toBe('scenario');
    for (const stage of [
      'approval',
      'approval-authorize',
      'approval-capture',
      'approval-verify',
      'approval-experience-open',
      'approval-password',
      'approval-identification',
      'approval-experience-submit',
      'approval-resume-initial',
      'approval-consent-read',
      'approval-consent-write',
      'approval-resume-final',
      'transition',
      'verification-get',
      'verification-post',
    ] as const) {
      expect(
        closedDeviceFailureStage(
          new TypeError(`Invalid Phase 2 device already-used-code step (${stage})`)
        )
      ).toBe(stage);
    }
    expect(
      closedDeviceFailureStage(
        new TypeError('Invalid Phase 2 device authorization transport (unknown-marker)')
      )
    ).toBeUndefined();
    expect(
      closedDeviceFailureStage(
        new TypeError(
          'Invalid Phase 2 device authorization transport (credential-lease):private-marker'
        )
      )
    ).toBeUndefined();
    expect(closedDeviceFailureStage('lifecycle-request')).toBeUndefined();
    expect(
      closedDeviceFailureStage(
        new TypeError('Invalid Phase 2 device already-used-code step (approval):private-marker')
      )
    ).toBeUndefined();
  });

  it('parses only the three exact command grammars', () => {
    expect(parsePhase2Arguments(oracleArguments())).toMatchObject({ mode: 'oracle' });
    expect(
      parsePhase2Arguments([
        'differential',
        '--profile',
        profilePath,
        '--schema',
        schemaPath,
        '--oracle-evidence',
        oracleTargetPath,
        '--candidate-target',
        candidateTargetPath,
        '--output',
        path.join(root, 'phase-2-client-credentials-differential.json'),
        '--temp-root',
        root,
      ])
    ).toMatchObject({ mode: 'differential' });
    expect(
      parsePhase2Arguments([
        'candidate-invariants',
        '--profile',
        profilePath,
        '--schema',
        schemaPath,
        '--target',
        candidateTargetPath,
        '--output',
        path.join(root, 'phase-2-client-credentials-candidate-invariants.json'),
        '--temp-root',
        root,
      ])
    ).toMatchObject({ mode: 'candidate-invariants' });
    for (const invalid of [
      [],
      ['run'],
      [...oracleArguments(), '--extra', 'x'],
      oracleArguments().with(1, '--profile=x'),
      oracleArguments().with(3, '--profile'),
    ]) {
      expect(() => parsePhase2Arguments(invalid)).toThrow('Invalid Phase 2 arguments.');
    }

    expect(() =>
      commonReadyScenarioFailure(
        'oracle',
        'common.google.registration',
        new TypeError(
          'Common Google registration target failed: unverified-email-control-rejected-resume-303-session.interaction_not_found'
        )
      )
    ).toThrow(
      'Phase 2 stage failed: oracle-common-ready-google-registration-unverified-email-control-rejected-resume-303-session.interaction_not_found'
    );
    expect(() =>
      commonReadyScenarioFailure(
        'oracle',
        'common.google.registration',
        new TypeError(
          'Common Google registration target failed: occupied-email-control-invalid-status-social-verify-200-none'
        )
      )
    ).toThrow(
      'Phase 2 stage failed: oracle-common-ready-google-registration-occupied-email-control-invalid-status-social-verify-200-none'
    );
    expect(() =>
      commonReadyScenarioFailure(
        'oracle',
        'common.google.registration',
        new TypeError(
          'Common Google registration target failed: unverified-email-control-disallowed-error-identification-404-session.identity_conflict'
        )
      )
    ).toThrow(
      'Phase 2 stage failed: oracle-common-ready-google-registration-unverified-email-control-disallowed-error-identification-404-session.identity_conflict'
    );
  });

  it('publishes one exclusive mode-0600 fixed artifact and removes owned session roots', async () => {
    const calls: string[] = [];
    const output = path.join(root, 'phase-2-client-credentials-oracle.json');
    await runPhase2Cli(oracleArguments(output), dependencies(calls));
    expect(calls).toEqual([
      'oracle',
      'publish:phase-2-client-credentials-oracle.json',
      'stdout:Phase 2 client credentials oracle complete.',
    ]);
    expect(JSON.parse(await readFile(output, 'utf8'))).toMatchObject({
      schemaVersion: 1,
      mode: 'oracle',
      sanitizerSuccess: true,
      provenance: {
        profileSha256: '1'.repeat(64),
        schemaSha256: '2'.repeat(64),
        harness: {
          repositoryUrl: 'https://github.com/qq98982/logto.git',
          runtimeBundleSha256: 'b'.repeat(64),
        },
      },
      payload: { schemaVersion: 1, mode: 'test', sanitized: true },
    });
    expect((await lstat(output)).mode & 0o777).toBe(0o600);
    expect(
      (await readdir(root)).filter((name) => name.startsWith('phase2-client-credentials-run-'))
    ).toEqual([]);
    await expect(runPhase2Cli(oracleArguments(output), dependencies([]))).rejects.toThrow(
      'Invalid Phase 2 arguments.'
    );
  });

  it('routes differential and candidate-invariants without aliases', async () => {
    const differentialCalls: string[] = [];
    await runPhase2Cli(
      [
        'differential',
        '--profile',
        profilePath,
        '--schema',
        schemaPath,
        '--oracle-evidence',
        oracleTargetPath,
        '--candidate-target',
        candidateTargetPath,
        '--output',
        path.join(root, 'phase-2-client-credentials-differential.json'),
        '--temp-root',
        root,
      ],
      dependencies(differentialCalls)
    );
    expect(differentialCalls[0]).toBe('differential');

    const invariantCalls: string[] = [];
    await runPhase2Cli(
      [
        'candidate-invariants',
        '--profile',
        profilePath,
        '--schema',
        schemaPath,
        '--target',
        candidateTargetPath,
        '--output',
        path.join(root, 'phase-2-client-credentials-candidate-invariants.json'),
        '--temp-root',
        root,
      ],
      dependencies(invariantCalls)
    );
    expect(invariantCalls[0]).toBe('candidate-invariants');
  });

  it('reads immutable oracle evidence and freshly prepares only the candidate', async () => {
    const calls: string[] = [];
    const base = dependencies(calls);
    const observed: string[] = [];
    await runPhase2Cli(
      [
        'differential',
        '--profile',
        profilePath,
        '--schema',
        schemaPath,
        '--oracle-evidence',
        oracleTargetPath,
        '--candidate-target',
        candidateTargetPath,
        '--output',
        path.join(root, 'phase-2-client-credentials-differential.json'),
        '--temp-root',
        root,
      ],
      {
        ...base,
        readOracleArtifact: async (...arguments_) => {
          observed.push('oracle-artifact');
          return base.readOracleArtifact(...arguments_);
        },
        readTarget: async (filePath) => {
          observed.push(`target:${path.basename(filePath)}`);
          return base.readTarget(filePath);
        },
        verifyTarget: async (value) => {
          observed.push(`verify:${value.kind}`);
          return base.verifyTarget(value);
        },
        prepareTarget: async (value, sessionRoot, namespace) => {
          observed.push(`prepare:${namespace}`);
          return base.prepareTarget(value, sessionRoot, namespace);
        },
        executeOracle: async () => {
          throw new Error('oracle must not execute');
        },
      }
    );
    expect(observed).toEqual([
      'oracle-artifact',
      'target:candidate-target.json',
      'verify:candidate',
      'prepare:candidate',
    ]);
  });

  it('rejects wrong filenames, non-0700 roots, symlinks, duplicate target keys, and aliased targets', async () => {
    await expect(
      runPhase2Cli(oracleArguments(path.join(root, 'wrong.json')), dependencies([]))
    ).rejects.toThrow('Invalid Phase 2 arguments.');

    await chmod(root, 0o755);
    await expect(runPhase2Cli(oracleArguments(), dependencies([]))).rejects.toThrow(
      'Invalid Phase 2 arguments.'
    );
    await chmod(root, 0o700);

    const linkPath = path.join(root, 'target-link.json');
    await symlink(oracleTargetPath, linkPath);
    await expect(
      runPhase2Cli(
        oracleArguments().map((value) => (value === oracleTargetPath ? linkPath : value)),
        dependencies([])
      )
    ).rejects.toThrow('Phase 2 command stage failed: oracle-target-path');

    const duplicate = path.join(root, 'duplicate.json');
    await writeFile(duplicate, '{"schemaVersion":1,"schemaVersion":1}', { mode: 0o600 });
    await expect(readPhase2TargetDescriptor(duplicate)).rejects.toThrow(
      'Invalid Phase 2 arguments.'
    );

    expect(() =>
      validatePhase2TargetDescriptor({
        ...targetDocument('candidate'),
        foreignTarget: targetDocument('candidate').target,
      })
    ).toThrow('Invalid Phase 2 runtime');

    const artifactLink = path.join(root, 'oracle-artifact-link.json');
    await symlink(oracleTargetPath, artifactLink);
    const differential = (artifactPath: string) => [
      'differential',
      '--profile',
      profilePath,
      '--schema',
      schemaPath,
      '--oracle-evidence',
      artifactPath,
      '--candidate-target',
      candidateTargetPath,
      '--output',
      path.join(root, 'phase-2-client-credentials-differential.json'),
      '--temp-root',
      root,
    ];
    await expect(runPhase2Cli(differential(artifactLink), dependencies([]))).rejects.toThrow(
      'Phase 2 command stage failed: differential-target-path'
    );
    const oversized = path.join(root, 'oversized-oracle.json');
    await writeFile(oversized, Buffer.alloc(1024 * 1024 + 1, 0x20), { mode: 0o600 });
    await expect(runPhase2Cli(differential(oversized), dependencies([]))).rejects.toThrow(
      'Phase 2 command stage failed: differential-target-path'
    );
    const hardlinkPath = path.join(root, 'oracle-artifact-hardlink.json');
    await link(oracleTargetPath, hardlinkPath);
    await expect(
      readPhase2OracleArtifact(oracleTargetPath, profile, await dependencies([]).inspectHarness())
    ).rejects.toThrow('Invalid Phase 2 arguments.');
    await rm(hardlinkPath);
    await chmod(oracleTargetPath, 0o644);
    await expect(
      readPhase2OracleArtifact(oracleTargetPath, profile, await dependencies([]).inspectHarness())
    ).rejects.toThrow('Invalid Phase 2 arguments.');
  });

  it('publishes nothing on execution or sanitizer failure and emits fixed diagnostics', async () => {
    const output = path.join(root, 'phase-2-client-credentials-oracle.json');
    const calls: string[] = [];
    const failing = dependencies(calls);
    const code = await runPhase2CliMain(oracleArguments(output), undefined, {
      ...failing,
      executeOracle: async () => {
        throw new Error('private detail');
      },
    });
    expect(code).toBe(1);
    expect(calls).toContain('stderr:Phase 2 client credentials command failed (oracle-execution).');
    await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
    expect(
      (await readdir(root)).filter((name) => name.startsWith('phase2-client-credentials-run-'))
    ).toEqual([]);

    const sanitizerCalls: string[] = [];
    expect(
      await runPhase2CliMain(
        oracleArguments(output),
        undefined,
        dependencies(sanitizerCalls, { Authorization: 'Basic planted-secret' })
      )
    ).toBe(1);
    expect(sanitizerCalls).toContain(
      'stderr:Phase 2 client credentials command failed (oracle-evidence).'
    );
    await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it.each([
    ['common.email.code-sign-in', 'oracle/common.email.code-sign-in'],
    ['common.email.code-sign-in:credential-lease', null],
    ['common.email.code-sign-in:projection-status', null],
    ['common.email.code-sign-in:private', null],
  ] as const)(
    'forwards only the exact Code scenario diagnostic for %s',
    async (detail, expected) => {
      const calls: string[] = [];
      const base = dependencies(calls);
      expect(
        await runPhase2CliMain(oracleArguments(), undefined, {
          ...base,
          executeOracle: async () => {
            throw new Error(`Phase 2 scenario failed: oracle/${detail}`);
          },
        })
      ).toBe(1);
      expect(calls).toContain(
        expected
          ? `stderr:Phase 2 client credentials command failed (${expected}).`
          : 'stderr:Phase 2 client credentials command failed (oracle-execution).'
      );
    }
  );

  it.each([
    [
      'common.email.password-registration',
      'password-registration',
      'Common email password registration target failed: controls-duplicate-identification',
      'controls-duplicate-identification',
    ],
    [
      'common.password.recovery',
      'recovery',
      'Common email recovery target failed: flow-new-password-reset',
      'flow-new-password-reset',
    ],
    [
      'common.google.existing-owner',
      'google',
      'Common Google existing-owner target failed: wrong-state-provider',
      'wrong-state-provider',
    ],
    [
      'common.email.password-registration',
      'password-registration',
      'Common email password registration target failed: private-token',
      'other',
    ],
    [
      'common.google.existing-owner',
      'google',
      'Common Google existing-owner failed: provider-click',
      'flow-provider-click',
    ],
    [
      'common.google.existing-owner',
      'google',
      'Common Google existing-owner failed: profile',
      'flow-profile',
    ],
    [
      'common.google.existing-owner',
      'google',
      'Common Google existing-owner failed: callback-callback-route',
      'flow-callback-callback-route',
    ],
    [
      'common.google.existing-owner',
      'google',
      'Common Google existing-owner failed: private-token',
      'other',
    ],
    [
      'common.google.existing-owner',
      'google',
      'Common Google existing-owner target failed: fixture-prepare-connector-health',
      'fixture-prepare-connector-health',
    ],
    [
      'common.google.existing-owner',
      'google',
      'Invalid Common Google existing-owner fixture runtime',
      'fixture-input',
    ],
    [
      'common.google.existing-owner',
      'google',
      'Invalid Common Google existing-owner scenario fixture',
      'scenario-fixture',
    ],
    [
      'common.google.existing-owner',
      'google',
      'Invalid Common Google existing-owner scenario projection',
      'scenario-projection',
    ],
    [
      'common.google.existing-owner',
      'google',
      'Common Google existing-owner target failed: fixture-private-token',
      'other',
    ],
    [
      'common.google.existing-owner',
      'google',
      'Common Google existing-owner target failed: wrong-state-authorization-state-round-trip',
      'wrong-state-authorization-state-round-trip',
    ],
    [
      'common.google.existing-owner',
      'google',
      'Common Google existing-owner target failed: wrong-state-callback-external-callback-query',
      'wrong-state-callback-external-callback-query',
    ],
    [
      'common.google.existing-owner',
      'google',
      'Common Google existing-owner target failed: wrong-state-callback-private-token',
      'other',
    ],
    [
      'common.wechat.web',
      'wechat-web',
      'Common Wechat existing-owner target failed: context-after-flow',
      'context-after-flow',
    ],
    [
      'common.wechat.web',
      'wechat-web',
      'Common Wechat existing-owner target failed: context-control-response',
      'context-control-response',
    ],
    [
      'common.wechat.web',
      'wechat-web',
      'Common Wechat existing-owner target failed: context-positive-provider',
      'context-positive-provider',
    ],
    ['common.google.existing-owner', 'google', 'private provider response', 'other'],
  ] as const)(
    'forwards only the closed new Common stage for %s',
    async (id, label, message, stage) => {
      const calls: string[] = [];
      const base = dependencies(calls);
      expect(
        await runPhase2CliMain(oracleArguments(), undefined, {
          ...base,
          executeOracle: async () => commonReadyScenarioFailure('oracle', id, new Error(message)),
        })
      ).toBe(1);
      expect(calls).toContain(
        `stderr:Phase 2 client credentials command failed (oracle-common-ready-${label}-${stage}).`
      );
      expect(calls.join(' ')).not.toContain('private-token');
      expect(calls.join(' ')).not.toContain('private provider response');
      expect(() => commonReadyScenarioFailure('candidate', id, new Error(message))).toThrow(
        `Phase 2 stage failed: candidate-common-ready-${label}-${stage}`
      );
    }
  );

  it.each([
    'unverified-email-control',
    'unverified-email-owner',
    'occupied-email-control',
    'occupied-email-owner',
    'control-publication',
  ] as const)('retains the closed registration control stage %s', (stage) => {
    expect(() =>
      commonReadyScenarioFailure(
        'oracle',
        'common.google.registration',
        new TypeError(`Common Google registration target failed: ${stage}`)
      )
    ).toThrow(`Phase 2 stage failed: oracle-common-ready-google-registration-${stage}`);
  });

  it('keeps registration public errors exact and rejects unrecognized diagnostic values', () => {
    const projection = commonGoogleRegistrationTestProjection;
    expect(() =>
      commonAdditionProjectionScenarioFailure('google-registration', projection, {
        ...projection,
        occupiedEmail: { ...projection.occupiedEmail, error: 'guard.invalid_input' },
      })
    ).toThrow(
      'candidate-google-registration-projection-occupied-email-error-ouser.email_already_in_use-cguard.invalid_input'
    );
    expect(() =>
      commonAdditionProjectionScenarioFailure('google-registration', projection, {
        ...projection,
        occupiedEmail: { ...projection.occupiedEmail, error: 'private-token' },
      })
    ).toThrow('candidate-google-registration-projection-contract-otrue-cfalse');
    expect(() =>
      commonAdditionProjectionScenarioFailure('wechat-web', commonWechatWebExpectedProjection, {
        ...commonWechatWebExpectedProjection,
        wrongCallback: {
          ...commonWechatWebExpectedProjection.wrongCallback,
          correctRetryAccepted: false,
        },
      })
    ).toThrow('candidate-wechat-web-projection-contract-otrue-cfalse');
  });

  it('formats only validated public Google comparison values', () => {
    const projection = {
      ...commonGoogleExistingOwnerExpectedProjection,
      wrongState: {
        ...commonGoogleExistingOwnerExpectedProjection.wrongState,
        status: 200,
        error: 'unknown',
      },
      replay: {
        ...commonGoogleExistingOwnerExpectedProjection.replay,
        secondStatus: 400,
        secondError: 'connector.general',
      },
    };
    expect(() =>
      commonGoogleProjectionScenarioFailure(projection, {
        ...projection,
        replay: { ...projection.replay, secondError: 'guard.invalid_input' },
      })
    ).toThrow(
      'Phase 2 stage failed: candidate-google-projection-replay-second-error-oconnector.general-cguard.invalid_input'
    );
    expect(() =>
      commonGoogleProjectionScenarioFailure(projection, {
        ...projection,
        replay: { ...projection.replay, secondError: 'private-token' },
      })
    ).toThrow('Phase 2 stage failed: candidate-google-projection-contract-otrue-cfalse');
  });

  it.each([
    ['wrong-state-status-o200-c400', true],
    ['replay-second-error-oconnector.general-cguard.invalid_input', true],
    ['contract-otrue-cfalse', true],
    ['replay-second-status-o400-c999', false],
    ['replay-second-error-oconnector.general-cprivate-token', false],
  ] as const)('forwards only closed Google comparison diagnostic %s', async (detail, accepted) => {
    const calls: string[] = [];
    const base = dependencies(calls);
    const code = await runPhase2CliMain(oracleArguments(), undefined, {
      ...base,
      executeOracle: async () => {
        throw new Error(`Phase 2 stage failed: candidate-google-projection-${detail}`);
      },
    });
    expect(code).toBe(1);
    expect(calls).toContain(
      accepted
        ? `stderr:Phase 2 client credentials command failed (candidate-google-projection-${detail}).`
        : 'stderr:Phase 2 client credentials command failed (oracle-execution).'
    );
    expect(calls.join(' ')).not.toContain('private-token');
  });

  it('preserves the closed diagnostic produced by the registration row failure wrapper', async () => {
    const calls: string[] = [];
    const base = dependencies(calls);
    expect(
      await runPhase2CliMain(oracleArguments(), undefined, {
        ...base,
        executeOracle: async () =>
          commonEmailCodeRegistrationScenarioFailure('oracle', new Error('private driver detail')),
      })
    ).toBe(1);
    expect(calls).toContain(
      'stderr:Phase 2 client credentials command failed (oracle/common.email.code-registration).'
    );
    expect(calls.join(' ')).not.toContain('private driver detail');
  });

  it.each([
    ['common.email.code-registration', 'oracle/common.email.code-registration'],
    ['common.email.code-registration:private', null],
    ['common.email.code-registration-unknown', null],
  ] as const)(
    'forwards only the exact registration scenario diagnostic for %s',
    async (detail, expected) => {
      const calls: string[] = [];
      const base = dependencies(calls);
      expect(
        await runPhase2CliMain(oracleArguments(), undefined, {
          ...base,
          executeOracle: async () => {
            throw new Error(`Phase 2 scenario failed: oracle/${detail}`);
          },
        })
      ).toBe(1);
      expect(calls).toContain(
        expected
          ? `stderr:Phase 2 client credentials command failed (${expected}).`
          : 'stderr:Phase 2 client credentials command failed (oracle-execution).'
      );
    }
  );

  it.each([
    ['code-178', 'oracle-sanitizer-code-178'],
    ['code-177', null],
    ['code-178-private', null],
  ] as const)('forwards only the exact Code sanitizer stage for %s', async (stage, expected) => {
    const calls: string[] = [];
    const base = dependencies(calls);
    expect(
      await runPhase2CliMain(oracleArguments(), undefined, {
        ...base,
        executeOracle: async () => {
          throw new Error(`Phase 2 stage failed: oracle-sanitizer-${stage}`);
        },
      })
    ).toBe(1);
    expect(calls).toContain(
      expected
        ? `stderr:Phase 2 client credentials command failed (${expected}).`
        : 'stderr:Phase 2 client credentials command failed (oracle-execution).'
    );
  });

  it('identifies generic oracle and candidate-invariant stage failures', async () => {
    const oracleCalls: string[] = [];
    const oracleBase = dependencies(oracleCalls);
    expect(
      await runPhase2CliMain(oracleArguments(), undefined, {
        ...oracleBase,
        verifyTarget: async () => {
          throw new Error('private oracle verification detail');
        },
      })
    ).toBe(1);
    expect(oracleCalls).toContain(
      'stderr:Phase 2 client credentials command failed (oracle-target-verify).'
    );

    const candidateCalls: string[] = [];
    const candidateBase = dependencies(candidateCalls);
    const candidateArguments = [
      'candidate-invariants',
      '--profile',
      profilePath,
      '--schema',
      schemaPath,
      '--target',
      candidateTargetPath,
      '--output',
      path.join(root, 'phase-2-client-credentials-candidate-invariants.json'),
      '--temp-root',
      root,
    ];
    expect(
      await runPhase2CliMain(candidateArguments, undefined, {
        ...candidateBase,
        executeCandidateInvariants: async () => {
          throw new Error('private candidate execution detail');
        },
      })
    ).toBe(1);
    expect(candidateCalls).toContain(
      'stderr:Phase 2 client credentials command failed (candidate-execution).'
    );
    expect(candidateCalls.join(' ')).not.toContain('private candidate execution detail');
  });

  it('forwards only closed device candidate-invariant stages', async () => {
    const candidateArguments = [
      'candidate-invariants',
      '--profile',
      profilePath,
      '--schema',
      schemaPath,
      '--target',
      candidateTargetPath,
      '--output',
      path.join(root, 'phase-2-client-credentials-candidate-invariants.json'),
      '--temp-root',
      root,
    ];
    await Promise.all(
      [
        'candidate-invariant-device-0',
        'candidate-invariant-device-1-row-sql',
        'candidate-invariant-device-1-schema-clear-columns',
        'candidate-invariant-device-2-foreign-poll-invalid-client',
        'candidate-invariant-device-2-abort',
        'candidate-invariant-device-2-finish',
        'candidate-invariant-device-7',
        'candidate-invariant-device-7-private-extraction',
        'candidate-invariant-device-7-normalized-match',
        'candidate-invariant-device-7-prepare',
        'candidate-invariant-device-7-approval',
        'candidate-invariant-device-7-issuance',
        'candidate-invariant-device-7-evidence-open',
        'candidate-invariant-device-7-evidence-values',
        'candidate-invariant-device-7-evidence-validation',
        'candidate-invariant-device-7-evidence-lease',
        'candidate-invariant-device-7-driver-unclassified',
      ].map(async (stage) => {
        const calls: string[] = [];
        const base = dependencies(calls);
        expect(
          await runPhase2CliMain(candidateArguments, undefined, {
            ...base,
            executeCandidateInvariants: async () => {
              throw new Error(`Phase 2 stage failed: ${stage}`);
            },
          })
        ).toBe(1);
        expect(calls).toContain(`stderr:Phase 2 client credentials command failed (${stage}).`);
      })
    );

    const rejectedCalls: string[] = [];
    const rejectedBase = dependencies(rejectedCalls);
    expect(
      await runPhase2CliMain(candidateArguments, undefined, {
        ...rejectedBase,
        executeCandidateInvariants: async () => {
          throw new Error('Phase 2 stage failed: oracle-invariant-device-0');
        },
      })
    ).toBe(1);
    expect(rejectedCalls).toContain(
      'stderr:Phase 2 client credentials command failed (candidate-execution).'
    );
    expect(rejectedCalls.join(' ')).not.toContain('oracle-invariant-device-0');

    for (const stage of [
      'candidate-invariant-device-1-unknown',
      'oracle-invariant-device-1-row-sql',
      'candidate-invariant-device-1-row-sql: private credential',
      'candidate-invariant-device-2-unknown',
      'candidate-invariant-device-2-finish: private credential',
      'candidate-invariant-device-7-unknown',
      'candidate-invariant-device-7-normalized-match: private credential',
      'candidate-invariant-device-7-driver-unclassified: private credential',
    ]) {
      const calls: string[] = [];
      const base = dependencies(calls);
      // eslint-disable-next-line no-await-in-loop -- CLI fixtures share one output path.
      const status = await runPhase2CliMain(candidateArguments, undefined, {
        ...base,
        executeCandidateInvariants: async () => {
          throw new Error(`Phase 2 stage failed: ${stage}`);
        },
      });
      expect(status).toBe(1);
      expect(calls).toContain(
        'stderr:Phase 2 client credentials command failed (candidate-execution).'
      );
      expect(calls.join(' ')).not.toContain(stage);
    }

    const oracleCalls: string[] = [];
    const oracleBase = dependencies(oracleCalls);
    expect(
      await runPhase2CliMain(oracleArguments(), undefined, {
        ...oracleBase,
        executeOracle: async () => {
          throw new Error('Phase 2 stage failed: candidate-invariant-device-0');
        },
      })
    ).toBe(1);
    expect(oracleCalls).toContain(
      'stderr:Phase 2 client credentials command failed (oracle-execution).'
    );
    expect(oracleCalls.join(' ')).not.toContain('candidate-invariant-device-0');
  });

  it('identifies the failed closed scenario without printing a credential-bearing exception', async () => {
    const output = path.join(root, 'phase-2-client-credentials-differential.json');
    const calls: string[] = [];
    const code = await runPhase2CliMain(
      [
        'differential',
        '--profile',
        profilePath,
        '--schema',
        schemaPath,
        '--oracle-evidence',
        oracleTargetPath,
        '--candidate-target',
        candidateTargetPath,
        '--output',
        output,
        '--temp-root',
        root,
      ],
      undefined,
      {
        ...dependencies(calls),
        executeDifferential: async () => {
          throw new Error(
            'Phase 2 scenario failed: candidate/client-credentials.basic-explicit-resource'
          );
        },
      }
    );
    expect(code).toBe(1);
    expect(calls).toContain(
      'stderr:Phase 2 client credentials command failed (candidate/client-credentials.basic-explicit-resource).'
    );
    expect(calls.join(' ')).not.toContain('private');
    await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('preserves an exact registration comparator failure for the launcher', async () => {
    const output = path.join(root, 'phase-2-client-credentials-differential.json');
    const calls: string[] = [];
    const code = await runPhase2CliMain(
      [
        'differential',
        '--profile',
        profilePath,
        '--schema',
        schemaPath,
        '--oracle-evidence',
        oracleTargetPath,
        '--candidate-target',
        candidateTargetPath,
        '--output',
        output,
        '--temp-root',
        root,
      ],
      undefined,
      {
        ...dependencies(calls),
        readOracleArtifact: async () =>
          ({
            schemaVersion: 1,
            mode: 'oracle',
            sanitizerSuccess: true,
            provenance: {
              oracle: {
                sourceCommit: '6852a7b8c8984c5c12b2061e8c51faa310a36412',
                imageDigest:
                  'sha256:76a9977bfc5ea3ed5b7623b879c27256670e377e27b987e8af99b53d55b30bbd',
              },
            },
            payload: {
              target: {
                target: 'oracle',
                discovery: {},
                controls: [],
                scenarios: [
                  {
                    id: 'common.email.code-registration',
                    projection: commonEmailCodeRegistrationExpectedProjection,
                  },
                ],
              },
            },
          }) as never,
        executeDifferential: async (input) =>
          executeDifferential(
            input,
            async () =>
              ({
                target: 'candidate',
                discovery: {},
                controls: [],
                scenarios: [
                  {
                    id: 'common.email.code-registration',
                    projection: {
                      ...commonEmailCodeRegistrationExpectedProjection,
                      occupiedRegistration: {
                        ...commonEmailCodeRegistrationExpectedProjection.occupiedRegistration,
                        ownerUnchanged: false,
                      },
                    },
                  },
                ],
              }) as never
          ),
      }
    );
    expect(code).toBe(1);
    expect(calls).toContain(
      'stderr:Phase 2 client credentials command failed (candidate/common.email.code-registration).'
    );
    await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('preserves an exact closed verification-code scenario failure for the launcher', async () => {
    const output = path.join(root, 'phase-2-client-credentials-differential.json');
    const calls: string[] = [];
    const code = await runPhase2CliMain(
      [
        'differential',
        '--profile',
        profilePath,
        '--schema',
        schemaPath,
        '--oracle-evidence',
        oracleTargetPath,
        '--candidate-target',
        candidateTargetPath,
        '--output',
        output,
        '--temp-root',
        root,
      ],
      undefined,
      {
        ...dependencies(calls),
        executeDifferential: async () => {
          throw new TypeError(
            'Phase 2 scenario failed: candidate/verification-code.failed-delivery-preserves-current'
          );
        },
      }
    );
    expect(code).toBe(1);
    expect(calls).toContain(
      'stderr:Phase 2 client credentials command failed (candidate/verification-code.failed-delivery-preserves-current).'
    );
    expect(calls.join(' ')).not.toContain('private');
    await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('preserves an exact closed device scenario failure for the launcher', async () => {
    const output = path.join(root, 'phase-2-client-credentials-differential.json');
    const calls: string[] = [];
    const code = await runPhase2CliMain(
      [
        'differential',
        '--profile',
        profilePath,
        '--schema',
        schemaPath,
        '--oracle-evidence',
        oracleTargetPath,
        '--candidate-target',
        candidateTargetPath,
        '--output',
        output,
        '--temp-root',
        root,
      ],
      undefined,
      {
        ...dependencies(calls),
        executeDifferential: async () => {
          throw new Error(
            'Phase 2 scenario failed: candidate/device-token.concurrent-reference-multi-winner'
          );
        },
      }
    );
    expect(code).toBe(1);
    const exact =
      'Phase 2 client credentials command failed (candidate/device-token.concurrent-reference-multi-winner).';
    expect(calls).toContain(`stderr:${exact}`);
    expect(calls.join(' ')).not.toContain('private');
    await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('reports only closed ID claim-key structure beside the fixed scenario failure', async () => {
    const output = path.join(root, 'phase-2-client-credentials-differential.json');
    const calls: string[] = [];
    const code = await runPhase2CliMain(
      [
        'differential',
        '--profile',
        profilePath,
        '--schema',
        schemaPath,
        '--oracle-evidence',
        oracleTargetPath,
        '--candidate-target',
        candidateTargetPath,
        '--output',
        output,
        '--temp-root',
        root,
      ],
      undefined,
      {
        ...dependencies(calls),
        executeDifferential: async () => {
          throw deviceScenarioProjectionFailure(
            'device-token.refresh-organization-selection',
            '/id/claims/claimKeys/0',
            {
              id: {
                claims: {
                  claimKeys: [
                    'iss',
                    'sub',
                    'email',
                    'auth_time',
                    'organizations',
                    'organization_roles',
                  ],
                },
              },
            },
            { id: { claims: { claimKeys: ['iss', 'sub', 'client_id', 'jti'] } } }
          );
        },
      }
    );
    expect(code).toBe(1);
    expect(calls).toContain(
      'stderr:Phase 2 client credentials command failed (candidate/device-token.refresh-organization-selection:projection-id-claimKeys).\n' +
        'Phase 2 device ID claimKeys differ (only on oracle: auth_time,email,organization_roles,organizations; only on candidate: client_id,jti).'
    );
    expect(calls.join(' ')).not.toContain('token-value');
    await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('reports only a closed device failure stage suffix', async () => {
    const output = path.join(root, 'phase-2-client-credentials-differential.json');
    const arguments_ = [
      'differential',
      '--profile',
      profilePath,
      '--schema',
      schemaPath,
      '--oracle-evidence',
      oracleTargetPath,
      '--candidate-target',
      candidateTargetPath,
      '--output',
      output,
      '--temp-root',
      root,
    ];
    const stageCalls: string[] = [];
    expect(
      await runPhase2CliMain(arguments_, undefined, {
        ...dependencies(stageCalls),
        executeDifferential: async () => {
          throw new Error(
            'Phase 2 scenario failed: oracle/device-token.refresh-resource-selection:credential-lease'
          );
        },
      })
    ).toBe(1);
    expect(stageCalls).toContain(
      'stderr:Phase 2 client credentials command failed (oracle/device-token.refresh-resource-selection:credential-lease).'
    );

    const hostileCalls: string[] = [];
    expect(
      await runPhase2CliMain(arguments_, undefined, {
        ...dependencies(hostileCalls),
        executeDifferential: async () => {
          throw new Error(
            'Phase 2 scenario failed: oracle/device-token.refresh-resource-selection:private credential value'
          );
        },
      })
    ).toBe(1);
    expect(hostileCalls).toContain(
      'stderr:Phase 2 client credentials command failed (differential-execution).'
    );
    expect(hostileCalls.join(' ')).not.toContain('private credential value');
  });

  it('reports only a closed device projection field suffix', async () => {
    const output = path.join(root, 'phase-2-client-credentials-differential.json');
    const arguments_ = [
      'differential',
      '--profile',
      profilePath,
      '--schema',
      schemaPath,
      '--oracle-evidence',
      oracleTargetPath,
      '--candidate-target',
      candidateTargetPath,
      '--output',
      output,
      '--temp-root',
      root,
    ];
    const runSuffix = async (suffix: string, expected: string) => {
      const calls: string[] = [];
      expect(
        await runPhase2CliMain(arguments_, undefined, {
          ...dependencies(calls),
          executeDifferential: async () => {
            throw new Error(
              `Phase 2 scenario failed: candidate/device-verification.already-used-code:${suffix}`
            );
          },
        })
      ).toBe(1);
      expect(calls).toContain(`stderr:Phase 2 client credentials command failed (${expected}).`);
      expect(calls.join(' ')).not.toContain('private-token');
    };
    await runSuffix(
      'projection-cookies',
      'candidate/device-verification.already-used-code:projection-cookies'
    );
    await runSuffix(
      'projection-completion-cookies',
      'candidate/device-verification.already-used-code:projection-completion-cookies'
    );
    await runSuffix(
      'projection-sequence-siblingAfter-headers',
      'candidate/device-verification.already-used-code:projection-sequence-siblingAfter-headers'
    );
    await runSuffix(
      'projection-id-claimKeys',
      'candidate/device-verification.already-used-code:projection-id-claimKeys'
    );
    await runSuffix(
      'projection-id-claimTypes-email_verified',
      'candidate/device-verification.already-used-code:projection-id-claimTypes-email_verified'
    );
    await runSuffix(
      'projection-id-signature',
      'candidate/device-verification.already-used-code:projection-id-signature'
    );
    await runSuffix(
      'projection-id-other',
      'candidate/device-verification.already-used-code:projection-id-other'
    );
    await Promise.all(
      [
        'approval',
        'approval-authorize',
        'approval-capture',
        'approval-verify',
        'approval-experience-open',
        'approval-password',
        'approval-identification',
        'approval-experience-submit',
        'approval-resume-initial',
        'approval-consent-read',
        'approval-consent-write',
        'approval-resume-final',
        'transition',
        'verification-get',
        'verification-post',
      ].map(async (stage) =>
        runSuffix(stage, `candidate/device-verification.already-used-code:${stage}`)
      )
    );
    await runSuffix('projection-private', 'differential-execution');
    await runSuffix('approval:private', 'differential-execution');
    await runSuffix('approval-password:private', 'differential-execution');
    await runSuffix('projection-cookies:private', 'differential-execution');
    await runSuffix('projection-completion-private', 'differential-execution');
    await runSuffix('projection-sequence-private-headers', 'differential-execution');
    await runSuffix('projection-sequence-siblingAfter-private', 'differential-execution');
    await runSuffix('projection-sequence-siblingAfter-headers:private', 'differential-execution');
    await runSuffix('projection-id-claimTypes-private-token', 'differential-execution');
    await runSuffix('projection-id-signature:private', 'differential-execution');
  });

  it('reports a bounded public status stage without printing its private exception', async () => {
    const calls: string[] = [];
    const output = path.join(root, 'phase-2-client-credentials-oracle.json');
    const code = await runPhase2CliMain(oracleArguments(output), undefined, {
      ...dependencies(calls),
      executeOracle: async () => {
        throw new Error('Phase 2 stage failed: oracle-status-verification: private credential');
      },
    });
    expect(code).toBe(1);
    expect(calls).toContain(
      'stderr:Phase 2 client credentials command failed (oracle-status-verification).'
    );
    expect(calls.join(' ')).not.toContain('private credential');
    await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('reports only a closed custom JWT failure index', async () => {
    for (const index of ['0', '23']) {
      const calls: string[] = [];
      // eslint-disable-next-line no-await-in-loop -- CLI fixtures share one output path.
      const code = await runPhase2CliMain(oracleArguments(), undefined, {
        ...dependencies(calls),
        executeOracle: async () => {
          throw new Error(`Phase 2 stage failed: oracle-custom-jwt-${index}`);
        },
      });
      expect(code).toBe(1);
      expect(calls).toContain(
        `stderr:Phase 2 client credentials command failed (oracle-custom-jwt-${index}).`
      );
    }
    for (const suffix of [
      '24',
      '01',
      '0-private',
      '0:private credential',
      '23:private credential',
    ]) {
      const calls: string[] = [];
      // eslint-disable-next-line no-await-in-loop -- CLI fixtures share one output path.
      const code = await runPhase2CliMain(oracleArguments(), undefined, {
        ...dependencies(calls),
        executeOracle: async () => {
          throw new Error(`Phase 2 stage failed: oracle-custom-jwt-${suffix}`);
        },
      });
      expect(code).toBe(1);
      expect(calls).toContain(
        'stderr:Phase 2 client credentials command failed (oracle-execution).'
      );
      expect(calls.join(' ')).not.toContain(`custom-jwt-${suffix}`);
    }
  });

  it('reports only a closed device refresh stage for custom JWT scenario 22', async () => {
    const candidateStageArguments = [
      'candidate-invariants',
      '--profile',
      profilePath,
      '--schema',
      schemaPath,
      '--target',
      candidateTargetPath,
      '--output',
      path.join(root, 'phase-2-client-credentials-candidate-invariants.json'),
      '--temp-root',
      root,
    ];
    for (const target of ['oracle', 'candidate'] as const) {
      for (const stage of [
        'authorize',
        'approval-authorize',
        'approval-capture',
        'approval-verify',
        'approval-experience-open',
        'approval-password',
        'approval-identification',
        'approval-experience-submit',
        'approval-resume-initial',
        'approval-consent-read',
        'approval-consent-write',
        'approval-resume-final',
        'token-poll',
        'initial-lease',
        'refresh-request',
        'refresh-http',
        'jwt-verify',
        'projection',
      ]) {
        const calls: string[] = [];
        const base = dependencies(calls);
        // eslint-disable-next-line no-await-in-loop -- CLI fixtures share one output path.
        const code = await runPhase2CliMain(
          target === 'oracle' ? oracleArguments() : candidateStageArguments,
          undefined,
          {
            ...base,
            ...(target === 'oracle'
              ? {
                  executeOracle: async () => {
                    throw new Error(`Phase 2 stage failed: oracle-custom-jwt-22:${stage}`);
                  },
                }
              : {
                  executeCandidateInvariants: async () => {
                    throw new Error(`Phase 2 stage failed: candidate-custom-jwt-22:${stage}`);
                  },
                }),
          }
        );
        expect(code).toBe(1);
        expect(calls).toContain(
          `stderr:Phase 2 client credentials command failed (${target}-custom-jwt-22:${stage}).`
        );
      }
    }

    for (const diagnostic of [
      'oracle-custom-jwt-21:authorize',
      'oracle-custom-jwt-23:projection',
      'oracle-custom-jwt-22:unknown',
      'oracle-custom-jwt-22:approval-unknown',
      'oracle-custom-jwt-22:approval-password:private credential',
      'oracle-custom-jwt-22:jwt-verify:private credential',
    ]) {
      const calls: string[] = [];
      // eslint-disable-next-line no-await-in-loop -- CLI fixtures share one output path.
      const code = await runPhase2CliMain(oracleArguments(), undefined, {
        ...dependencies(calls),
        executeOracle: async () => {
          throw new Error(`Phase 2 stage failed: ${diagnostic}`);
        },
      });
      expect(code).toBe(1);
      expect(calls).toContain(
        'stderr:Phase 2 client credentials command failed (oracle-execution).'
      );
      expect(calls.join(' ')).not.toContain(diagnostic);
    }
  });

  it('reports only a closed sanitizer partition and bounded scenario index', async () => {
    const calls: string[] = [];
    const output = path.join(root, 'phase-2-client-credentials-oracle.json');
    const code = await runPhase2CliMain(oracleArguments(output), undefined, {
      ...dependencies(calls),
      executeOracle: async () => {
        throw new Error('Phase 2 stage failed: oracle-sanitizer-device-138: private credential');
      },
    });
    expect(code).toBe(1);
    expect(calls).toContain(
      'stderr:Phase 2 client credentials command failed (oracle-sanitizer-device-138).'
    );
    expect(calls.join(' ')).not.toContain('private credential');
    await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('identifies a fixed fixture failure stage without printing its private exception', async () => {
    const output = path.join(root, 'phase-2-client-credentials-differential.json');
    const calls: string[] = [];
    const code = await runPhase2CliMain(
      [
        'differential',
        '--profile',
        profilePath,
        '--schema',
        schemaPath,
        '--oracle-evidence',
        oracleTargetPath,
        '--candidate-target',
        candidateTargetPath,
        '--output',
        output,
        '--temp-root',
        root,
      ],
      undefined,
      {
        ...dependencies(calls),
        executeDifferential: async () => {
          throw new Error('Phase 2 stage failed: candidate-fixture: private credential value');
        },
      }
    );
    expect(code).toBe(1);
    expect(calls).toContain(
      'stderr:Phase 2 client credentials command failed (candidate-fixture).'
    );
    expect(calls.join(' ')).not.toContain('private credential value');
    await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it.each([
    'candidate-admin-consumer-unknown',
    'candidate-custom-jwt-19:http-500',
    'candidate-custom-jwt-19:issuance-token-http',
  ])('preserves the closed %s stage through both command paths', async (stage) => {
    for (const mode of ['differential', 'candidate-invariants'] as const) {
      const calls: string[] = [];
      const output = path.join(root, `phase-2-client-credentials-${mode}.json`);
      const targetArguments =
        mode === 'differential'
          ? ['--oracle-evidence', oracleTargetPath, '--candidate-target', candidateTargetPath]
          : ['--target', candidateTargetPath];
      // eslint-disable-next-line no-await-in-loop -- Both commands share one private fixture directory and must clean it independently.
      const code = await runPhase2CliMain(
        [
          mode,
          '--profile',
          profilePath,
          '--schema',
          schemaPath,
          ...targetArguments,
          '--output',
          output,
          '--temp-root',
          root,
        ],
        undefined,
        {
          ...dependencies(calls),
          executeDifferential: async () => {
            throw new Error(`Phase 2 stage failed: ${stage}`);
          },
          executeCandidateInvariants: async () => {
            throw new Error(`Phase 2 stage failed: ${stage}`);
          },
        }
      );
      expect(code).toBe(1);
      expect(calls).toContain(`stderr:Phase 2 client credentials command failed (${stage}).`);
      // eslint-disable-next-line no-await-in-loop -- Failed commands must not publish an artifact before the next invocation.
      await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
    }
  });

  it.each([0, 4])(
    'preserves failed legacy invariant %i through the command boundary',
    async (index) => {
      const calls: string[] = [];
      const output = path.join(root, 'phase-2-client-credentials-candidate-invariants.json');
      const code = await runPhase2CliMain(
        [
          'candidate-invariants',
          '--profile',
          profilePath,
          '--schema',
          schemaPath,
          '--target',
          candidateTargetPath,
          '--output',
          output,
          '--temp-root',
          root,
        ],
        undefined,
        {
          ...dependencies(calls),
          executeCandidateInvariants: async () => {
            throw new Error(`Phase 2 stage failed: candidate-invariant-legacy-${index}`);
          },
        }
      );
      expect(code).toBe(1);
      expect(calls).toContain(
        `stderr:Phase 2 client credentials command failed (candidate-invariant-legacy-${index}).`
      );
      await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
    }
  );

  it('preserves the execution stage when differential cleanup also fails', async () => {
    const calls: string[] = [];
    const output = path.join(root, 'phase-2-client-credentials-differential.json');
    const code = await runPhase2CliMain(
      [
        'differential',
        '--profile',
        profilePath,
        '--schema',
        schemaPath,
        '--oracle-evidence',
        oracleTargetPath,
        '--candidate-target',
        candidateTargetPath,
        '--output',
        output,
        '--temp-root',
        root,
      ],
      undefined,
      {
        ...dependencies(calls),
        executeDifferential: async () => {
          throw new Error('private execution credential');
        },
        removeSessionRoot: async () => {
          throw new Error('private cleanup credential');
        },
      }
    );
    expect(code).toBe(1);
    expect(calls).toContain(
      'stderr:Phase 2 client credentials command failed (differential-execution).'
    );
    expect(calls.join(' ')).not.toContain('private execution credential');
    expect(calls.join(' ')).not.toContain('private cleanup credential');
    await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('reports differential target verification without exposing the failure', async () => {
    const calls: string[] = [];
    const output = path.join(root, 'phase-2-client-credentials-differential.json');
    const code = await runPhase2CliMain(
      [
        'differential',
        '--profile',
        profilePath,
        '--schema',
        schemaPath,
        '--oracle-evidence',
        oracleTargetPath,
        '--candidate-target',
        candidateTargetPath,
        '--output',
        output,
        '--temp-root',
        root,
      ],
      undefined,
      {
        ...dependencies(calls),
        verifyTarget: async () => {
          throw new Error('private verification detail');
        },
      }
    );
    expect(code).toBe(1);
    expect(calls).toContain(
      'stderr:Phase 2 client credentials command failed (differential-target-verify).'
    );
    expect(calls.join(' ')).not.toContain('private verification detail');
    await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('does not publish when owned session-root removal fails', async () => {
    const output = path.join(root, 'phase-2-client-credentials-oracle.json');
    const calls: string[] = [];
    await expect(
      runPhase2Cli(oracleArguments(output), {
        ...dependencies(calls),
        removeSessionRoot: async () => {
          throw new Error('planted rm failure');
        },
      })
    ).rejects.toThrow('Phase 2 command stage failed: oracle-cleanup');
    expect(calls.some((call) => call.startsWith('publish:'))).toBe(false);
    await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('uses the mode-specific cleanup stage when no earlier fixed diagnostic exists', async () => {
    const calls: string[] = [];
    const base = dependencies(calls);
    const code = await runPhase2CliMain(oracleArguments(), undefined, {
      ...base,
      loadProfile: async () => {
        throw new Error('private unclassified failure');
      },
      removeSessionRoot: async () => {
        throw new Error('private cleanup failure');
      },
    });
    expect(code).toBe(1);
    expect(calls).toContain('stderr:Phase 2 client credentials command failed (oracle-cleanup).');
    expect(calls.join(' ')).not.toContain('private');
  });
});

/* eslint-enable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, unicorn/no-object-as-default-parameter, no-bitwise, unicorn/no-await-expression-member, @typescript-eslint/consistent-type-assertions */
