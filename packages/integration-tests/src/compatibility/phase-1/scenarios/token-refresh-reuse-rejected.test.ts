import type { JsonObject } from '../../normalize.js';
import type { Phase1ScenarioStateProjectionInput } from '../scenario-runtime.js';

import {
  createTokenScenarioHarness,
  createTokenTestSigner,
  tokenGrantBody,
  tokenTestCredentials,
  tokenTestTarget,
} from './positive-oidc-token.test-helpers.js';
import { runTokenRefreshReuseRejected } from './token-refresh-reuse-rejected.js';

const invalidGrantBody = {
  code: 'oidc.invalid_grant',
  message: 'Grant request is invalid.',
  error_uri: 'https://openid.sh/debug/invalid_grant',
  error: 'invalid_grant',
  error_description: 'grant request is invalid',
};

const rawResponse = (status: number, body: unknown) => {
  const text = JSON.stringify(body);

  return Object.freeze({
    status,
    headers: Object.freeze([
      Object.freeze(['content-type', 'application/json; charset=utf-8'] as const),
      Object.freeze(['cache-control', 'no-store'] as const),
      Object.freeze(['content-length', String(Buffer.byteLength(text))] as const),
    ]),
    body: text,
  });
};

const scenarioState = (
  stepId: string,
  familyRevoked = true
): Phase1ScenarioStateProjectionInput => {
  const generatedIds: JsonObject = stepId === 'state' ? { tokenFamily: '<token-family.1>' } : {};
  const common = {
    body: {},
    semanticState: { unrelatedMutation: false },
    generatedIds,
  };

  if (stepId === 'code-token') {
    return {
      ...common,
      persistedState: {
        rotationCount: 0,
        predecessorConsumed: false,
        reuseDetected: false,
        familyRevoked: false,
        activeDescendantCount: 1,
        unrelatedMutation: false,
      },
      sideEffects: { unrelatedMutation: false },
    };
  }
  if (stepId === 'rotate') {
    return {
      ...common,
      persistedState: {
        rotationCount: 1,
        predecessorConsumed: true,
        reuseDetected: false,
        familyRevoked: false,
        activeDescendantCount: 1,
        unrelatedMutation: false,
      },
      sideEffects: { unrelatedMutation: false },
    };
  }
  if (stepId === 'replay-old') {
    return {
      ...common,
      persistedState: {
        rotationCount: 1,
        predecessorConsumed: true,
        reuseDetected: true,
        familyRevoked,
        activeDescendantCount: familyRevoked ? 0 : 1,
        unrelatedMutation: false,
      },
      sideEffects: { grantRevoked: familyRevoked, unrelatedMutation: false },
    };
  }

  return {
    ...common,
    persistedState: {
      rotationCount: 1,
      predecessorConsumed: true,
      reuseDetected: true,
      descendantProbeRejected: true,
      familyRevoked,
      activeDescendantCount: familyRevoked ? 0 : 1,
      unrelatedMutation: false,
    },
    sideEffects: { grantRevoked: familyRevoked, unrelatedMutation: false },
  };
};

describe('token.refresh-reuse-rejected', () => {
  it('waits past leeway then rejects the old token and newest descendant', async () => {
    const signer = await createTokenTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const initialIdToken = await signer.sign({
      iss: `${tokenTestTarget.coreUrl}oidc`,
      sub: 'runtime-subject',
      aud: tokenTestCredentials.clientId,
      iat: now,
      exp: now + 3600,
    });
    const rotatedIdToken = await signer.sign({
      iss: `${tokenTestTarget.coreUrl}oidc`,
      sub: 'runtime-subject',
      aud: tokenTestCredentials.clientId,
      iat: now + 1,
      exp: now + 3601,
    });
    const initialRefreshToken = 'private-initial-refresh-token';
    const rotatedRefreshToken = 'private-rotated-refresh-token';
    const harness = createTokenScenarioHarness({
      jwk: signer.jwk,
      tokenBodies: [],
      tokenResponses: [
        rawResponse(
          200,
          tokenGrantBody({
            accessToken: 'private-initial-access-token',
            idToken: initialIdToken,
            refreshToken: initialRefreshToken,
          })
        ),
        rawResponse(
          200,
          tokenGrantBody({
            accessToken: 'private-rotated-access-token',
            idToken: rotatedIdToken,
            refreshToken: rotatedRefreshToken,
          })
        ),
        rawResponse(400, invalidGrantBody),
        rawResponse(400, invalidGrantBody),
      ],
      projectScenarioState: async ({ stepId }: { stepId: string }) => scenarioState(stepId),
    });
    const wait = import.meta.jest.fn(async (milliseconds: number) => {
      expect(milliseconds).toBe(4000);
      expect(harness.requests.map(({ operation }) => operation)).toEqual([
        'token-authorization-code',
        'token-refresh',
      ]);
    });
    const steps = await runTokenRefreshReuseRejected(harness.context, {
      withPositiveOidcFlow: harness.flow,
      wait,
    });

    expect(wait).toHaveBeenCalledTimes(1);
    expect(steps.map(({ stepId }) => stepId)).toEqual([
      'code-token',
      'rotate',
      'replay-old',
      'probe-descendant',
      'state',
    ]);
    expect(harness.requests.map(({ operation }) => operation)).toEqual([
      'token-authorization-code',
      'token-refresh',
      'token-refresh-replay-old',
      'token-refresh-probe-descendant',
    ]);
    const forms = harness.requests.map(({ options }) =>
      Object.fromEntries(new URLSearchParams(options?.body))
    );
    expect(forms[1]).toEqual({
      grant_type: 'refresh_token',
      client_id: tokenTestCredentials.clientId,
      refresh_token: initialRefreshToken,
    });
    expect(forms[2]).toEqual(forms[1]);
    expect(forms[3]).toEqual({
      grant_type: 'refresh_token',
      client_id: tokenTestCredentials.clientId,
      refresh_token: rotatedRefreshToken,
    });
    expect(steps[0]?.value).toMatchObject({
      status: 200,
      body: { refresh: { format: 'opaque', present: true } },
      tokens: [],
    });
    expect(steps[1]?.value).toMatchObject({
      status: 200,
      tokens: [
        { kind: 'access', format: 'opaque' },
        { kind: 'id', format: 'jwt', signatureVerified: true },
        { kind: 'refresh', format: 'opaque', present: true },
      ],
      persistedState: { rotationCount: 1, predecessorConsumed: true, familyRevoked: false },
    });
    for (const index of [2, 3]) {
      expect(steps[index]?.value).toMatchObject({
        status: 400,
        body: { error: 'invalid_grant', errorCode: 'oidc.invalid_grant' },
        persistedState: { familyRevoked: true, activeDescendantCount: 0 },
        sideEffects: { grantRevoked: true },
        redirect: null,
        cookies: [],
      });
    }
    expect(steps[4]?.value).toMatchObject({
      generatedIds: { tokenFamily: '<token-family.1>' },
      persistedState: {
        reuseDetected: true,
        descendantProbeRejected: true,
        familyRevoked: true,
        activeDescendantCount: 0,
      },
      sideEffects: { grantRevoked: true },
    });
    expect(JSON.stringify(steps)).not.toMatch(
      /private-initial|private-rotated|private-authorization-code|vvvvvvvv/u
    );
  });

  it('rejects reuse handling that leaves the family active', async () => {
    const signer = await createTokenTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const idToken = await signer.sign({
      iss: `${tokenTestTarget.coreUrl}oidc`,
      sub: 'runtime-subject',
      aud: tokenTestCredentials.clientId,
      iat: now,
      exp: now + 3600,
    });
    const harness = createTokenScenarioHarness({
      jwk: signer.jwk,
      tokenBodies: [],
      tokenResponses: [
        rawResponse(
          200,
          tokenGrantBody({
            accessToken: 'private-initial-access-token',
            idToken,
            refreshToken: 'private-initial-refresh-token',
          })
        ),
        rawResponse(
          200,
          tokenGrantBody({
            accessToken: 'private-rotated-access-token',
            idToken,
            refreshToken: 'private-rotated-refresh-token',
          })
        ),
        rawResponse(400, invalidGrantBody),
      ],
      projectScenarioState: async ({ stepId }) => scenarioState(stepId, false),
    });

    await expect(
      runTokenRefreshReuseRejected(harness.context, {
        withPositiveOidcFlow: harness.flow,
        wait: async () => {
          // The state mutation control does not need wall-clock delay.
        },
      })
    ).rejects.toThrow('Phase 1 refresh token reuse state is invalid');
    expect(harness.requests).toHaveLength(3);
  });
});
