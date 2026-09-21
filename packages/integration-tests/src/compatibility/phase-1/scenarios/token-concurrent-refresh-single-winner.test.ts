import { protocolHeaderPairs } from '../clients/oidc.js';
import type { Phase1ScenarioStateProjectionInput } from '../scenario-runtime.js';
import { validateExactPhase1ScenarioSteps } from '../scenario-runtime.js';

import { phase1DifferentialScenarios } from './index.js';
import { revokePositiveTokenGrant, type PositiveOidcTokenGrant } from './positive-oidc-token.js';
import {
  createTokenScenarioHarness,
  createTokenTestSigner,
  requireConcurrentTokenTransport,
  tokenGrantBody,
  tokenTestCredentials,
  tokenTestRuntimeValues,
  tokenTestTarget,
} from './positive-oidc-token.test-helpers.js';
import { runTokenConcurrentRefreshSingleWinner } from './token-concurrent-refresh-single-winner.js';

const scenarioState = (stepId: string): Phase1ScenarioStateProjectionInput => ({
  body: {},
  semanticState: { unrelatedMutation: false },
  persistedState: {
    presentationSuccessCount: 2,
    predecessorConsumed: true,
    replacementRefreshCount: 2,
    distinctReplacementCount: 2,
    activeDescendantCount: 2,
    replacementRotationOrdinals: [1, 1],
    familyCount: 1,
    unrelatedMutation: false,
  },
  generatedIds: stepId === 'state' ? { tokenFamily: '<token-family.1>' } : {},
  sideEffects: {
    sameGrantFamily: true,
    siblingDescendantsCreated: true,
    unrelatedMutation: false,
  },
});

describe('token.concurrent-refresh-single-winner', () => {
  it('preserves two successful presentations as distinct active siblings in one grant family', async () => {
    const signer = await createTokenTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const signIdToken = async (offset: number) =>
      signer.sign({
        iss: `${tokenTestTarget.coreUrl}oidc`,
        sub: 'runtime-subject',
        aud: tokenTestCredentials.clientId,
        iat: now + offset,
        exp: now + offset + 3600,
      });
    const [initialIdToken, firstIdToken, secondIdToken] = await Promise.all([
      signIdToken(0),
      signIdToken(1),
      signIdToken(2),
    ]);
    const harness = createTokenScenarioHarness({
      jwk: signer.jwk,
      userInfoBody: {
        sub: 'runtime-subject',
        name: 'Observed User',
        email: tokenTestRuntimeValues.email,
        email_verified: true,
      },
      tokenBodies: [
        tokenGrantBody({
          accessToken: 'opaque-private-initial-access-token',
          idToken: initialIdToken,
          refreshToken: 'opaque-private-initial-refresh-token',
        }),
        tokenGrantBody({
          accessToken: 'opaque-private-first-access-token',
          idToken: firstIdToken,
          refreshToken: 'opaque-private-first-refresh-token',
        }),
        tokenGrantBody({
          accessToken: 'opaque-private-second-access-token',
          idToken: secondIdToken,
          refreshToken: 'opaque-private-second-refresh-token',
        }),
      ],
      projectScenarioState: async ({ stepId }) => scenarioState(stepId),
    });
    const witness = requireConcurrentTokenTransport(harness.context, [
      'token-concurrent-refresh-attempt-a',
      'token-concurrent-refresh-attempt-b',
    ]);
    const revoke = import.meta.jest.fn((grant: PositiveOidcTokenGrant) => {
      const userInfoRequests = harness.requests.filter(
        ({ operation }) => operation === 'userinfo-openid'
      );
      expect(userInfoRequests).toHaveLength(2);
      revokePositiveTokenGrant(grant);
    });
    const steps = await runTokenConcurrentRefreshSingleWinner(witness.context, {
      withPositiveOidcFlow: harness.flow,
      revokePositiveTokenGrant: revoke,
    });
    const scenario = phase1DifferentialScenarios.find(
      ({ id }) => id === 'token.concurrent-refresh-single-winner'
    );

    if (!scenario) {
      throw new Error('Phase 1 concurrent refresh scenario is unavailable');
    }
    expect(validateExactPhase1ScenarioSteps(scenario, steps)).toHaveLength(4);

    witness.assertWitness();
    expect(revoke).toHaveBeenCalledTimes(3);
    expect(steps.map(({ stepId }) => stepId)).toEqual(['attempt-a', 'attempt-b', 'race', 'state']);
    expect(harness.requests).toHaveLength(5);
    expect(harness.requests.slice(1).map(({ operation }) => operation)).toEqual([
      'token-concurrent-refresh-attempt-a',
      'token-concurrent-refresh-attempt-b',
      'userinfo-openid',
      'userinfo-openid',
    ]);
    expect(
      harness.requests
        .slice(3)
        .map(
          ({ options }) =>
            protocolHeaderPairs(options?.headers).find(
              ([name]) => name.toLowerCase() === 'authorization'
            )?.[1]
        )
    ).toEqual(
      expect.arrayContaining([
        'Bearer opaque-private-first-access-token',
        'Bearer opaque-private-second-access-token',
      ])
    );
    expect(harness.requests[1]?.path).toBe('oidc/token');
    expect(harness.requests[1]?.options).toEqual(harness.requests[2]?.options);
    expect(new URLSearchParams(harness.requests[1]?.options?.body).get('grant_type')).toBe(
      'refresh_token'
    );
    expect(steps[0]?.value.status).toBe(200);
    expect(steps[1]?.value.status).toBe(200);
    for (const index of [0, 1]) {
      expect(steps[index]?.value).toMatchObject({
        outcomes: [
          {
            kind: 'userinfo-email',
            response: {
              status: 200,
              body: {
                sub: '<user.phase1-user>',
                name: 'Observed User',
                email: '<fixture.data.email>',
                email_verified: true,
              },
            },
          },
        ],
      });
    }
    expect(steps[2]?.value.outcomes).toEqual([
      { kind: 'success', status: 200 },
      { kind: 'success', status: 200 },
    ]);
    expect(steps[3]?.value).toMatchObject({
      generatedIds: { tokenFamily: '<token-family.1>' },
      persistedState: {
        presentationSuccessCount: 2,
        predecessorConsumed: true,
        replacementRefreshCount: 2,
        distinctReplacementCount: 2,
        activeDescendantCount: 2,
        replacementRotationOrdinals: [1, 1],
        familyCount: 1,
      },
      sideEffects: { sameGrantFamily: true, siblingDescendantsCreated: true },
    });
    expect(JSON.stringify(steps)).not.toMatch(/private|refresh_token/u);
  });

  it('rejects the legacy one-winner persisted state', async () => {
    const signer = await createTokenTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const idToken = await signer.sign({
      iss: `${tokenTestTarget.coreUrl}oidc`,
      sub: 'runtime-subject',
      aud: tokenTestCredentials.clientId,
      iat: now,
      exp: now + 3600,
    });
    const grantBody = (suffix: string) =>
      tokenGrantBody({
        accessToken: `opaque-private-${suffix}-access-token`,
        idToken,
        refreshToken: `opaque-private-${suffix}-refresh-token`,
      });
    const harness = createTokenScenarioHarness({
      jwk: signer.jwk,
      tokenBodies: [grantBody('initial'), grantBody('first'), grantBody('second')],
      projectScenarioState: async ({ stepId }) => ({
        ...scenarioState(stepId),
        persistedState: {
          presentationSuccessCount: 2,
          rotationWinnerCount: 1,
          familyCount: 1,
          unrelatedMutation: false,
        },
        sideEffects: { sameFamily: true, unrelatedMutation: false },
      }),
    });

    await expect(
      runTokenConcurrentRefreshSingleWinner(harness.context, {
        withPositiveOidcFlow: harness.flow,
      })
    ).rejects.toThrow('Phase 1 concurrent refresh attempt state is invalid');
    expect(harness.requests).toHaveLength(3);
    expect(harness.requests[1]?.options).toEqual(harness.requests[2]?.options);
  });

  it('rejects replacement rows that do not represent two distinct descendants', async () => {
    const signer = await createTokenTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const idToken = await signer.sign({
      iss: `${tokenTestTarget.coreUrl}oidc`,
      sub: 'runtime-subject',
      aud: tokenTestCredentials.clientId,
      iat: now,
      exp: now + 3600,
    });
    const grantBody = (suffix: string) =>
      tokenGrantBody({
        accessToken: `opaque-private-${suffix}-access-token`,
        idToken,
        refreshToken: `opaque-private-${suffix}-refresh-token`,
      });
    const harness = createTokenScenarioHarness({
      jwk: signer.jwk,
      tokenBodies: [grantBody('initial'), grantBody('first'), grantBody('second')],
      projectScenarioState: async ({ stepId }) => ({
        ...scenarioState(stepId),
        persistedState: {
          presentationSuccessCount: 2,
          predecessorConsumed: true,
          replacementRefreshCount: 2,
          distinctReplacementCount: 1,
          activeDescendantCount: 2,
          replacementRotationOrdinals: [1, 1],
          familyCount: 1,
          unrelatedMutation: false,
        },
      }),
    });

    await expect(
      runTokenConcurrentRefreshSingleWinner(harness.context, {
        withPositiveOidcFlow: harness.flow,
      })
    ).rejects.toThrow('Phase 1 concurrent refresh attempt state is invalid');
    expect(harness.requests).toHaveLength(3);
    expect(harness.requests[1]?.options).toEqual(harness.requests[2]?.options);
  });

  it('drains a partial refresh failure and revokes every fulfilled grant', async () => {
    const signer = await createTokenTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const idToken = await signer.sign({
      iss: `${tokenTestTarget.coreUrl}oidc`,
      sub: 'runtime-subject',
      aud: tokenTestCredentials.clientId,
      iat: now,
      exp: now + 3600,
    });
    const grantBody = (suffix: string) =>
      tokenGrantBody({
        accessToken: `opaque-private-${suffix}-access-token`,
        idToken,
        refreshToken: `opaque-private-${suffix}-refresh-token`,
      });
    const harness = createTokenScenarioHarness({
      jwk: signer.jwk,
      tokenBodies: [grantBody('initial'), grantBody('fulfilled')],
      projectScenarioState: async ({ stepId }) => scenarioState(stepId),
    });
    const revoke = import.meta.jest.fn((grant: PositiveOidcTokenGrant) => {
      revokePositiveTokenGrant(grant);
    });

    await expect(
      runTokenConcurrentRefreshSingleWinner(harness.context, {
        withPositiveOidcFlow: harness.flow,
        revokePositiveTokenGrant: revoke,
      })
    ).rejects.toThrow('Phase 1 concurrent refresh outcomes are invalid');
    expect(harness.requests).toHaveLength(3);
    expect(harness.requests[1]?.options).toEqual(harness.requests[2]?.options);
    expect(revoke).toHaveBeenCalledTimes(2);
    expect(new Set(revoke.mock.calls.map(([grant]) => grant))).toHaveProperty('size', 2);
  });
});
