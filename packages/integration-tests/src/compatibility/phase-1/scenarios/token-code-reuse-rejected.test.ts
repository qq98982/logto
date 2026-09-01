import type { Phase1ScenarioStateProjectionInput } from '../scenario-runtime.js';

import {
  createTokenScenarioHarness,
  createTokenTestSigner,
  tokenGrantBody,
  tokenTestCredentials,
  tokenTestTarget,
} from './positive-oidc-token.test-helpers.js';
import { runTokenCodeReuseRejected } from './token-code-reuse-rejected.js';

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

const scenarioState = (stepId: string, keepFamily = false): Phase1ScenarioStateProjectionInput => {
  const common = {
    body: {},
    semanticState: { unrelatedMutation: false },
  };

  if (stepId === 'first-exchange') {
    return {
      ...common,
      persistedState: {
        firstExchangeSucceeded: true,
        grantConsumed: true,
        familyCount: 1,
        unrelatedMutation: false,
      },
      generatedIds: {},
      sideEffects: { unrelatedMutation: false },
    };
  }

  return {
    ...common,
    persistedState: {
      firstExchangeSucceeded: true,
      replayRejected: true,
      grantPresent: keepFamily,
      familyCount: keepFamily ? 1 : 0,
      unrelatedMutation: false,
    },
    generatedIds: stepId === 'state' ? { tokenFamily: '<token-family.1>' } : {},
    sideEffects: { grantRevoked: !keepFamily, unrelatedMutation: false },
  };
};

describe('token.code-reuse-rejected', () => {
  it('rejects byte-identical replay and removes the original grant and token family', async () => {
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
            accessToken: 'opaque-private-access-token',
            idToken,
            refreshToken: 'opaque-private-refresh-token',
          })
        ),
        rawResponse(400, invalidGrantBody),
      ],
      projectScenarioState: async ({ stepId }) => scenarioState(stepId),
    });
    const steps = await runTokenCodeReuseRejected(harness.context, {
      withPositiveOidcFlow: harness.flow,
    });

    expect(steps.map(({ stepId }) => stepId)).toEqual(['first-exchange', 'replay', 'state']);
    expect(harness.requests).toHaveLength(2);
    expect(harness.requests.map(({ operation }) => operation)).toEqual([
      'token-code-first-exchange',
      'token-code-replay',
    ]);
    expect(harness.requests[0]?.options?.body).toBe(harness.requests[1]?.options?.body);
    const replayForm = Object.fromEntries(new URLSearchParams(harness.requests[0]?.options?.body));
    expect(replayForm).toMatchObject({
      grant_type: 'authorization_code',
      client_id: tokenTestCredentials.clientId,
      redirect_uri: tokenTestCredentials.redirectUri,
    });
    expect(replayForm.code).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(replayForm.code_verifier).toMatch(/^[A-Za-z0-9_-]{64}$/u);
    expect(steps[0]?.value).toMatchObject({
      status: 200,
      tokens: [
        { kind: 'access', format: 'opaque' },
        { kind: 'id', format: 'jwt', signatureVerified: true },
        { kind: 'refresh', format: 'opaque' },
      ],
      persistedState: { familyCount: 1 },
    });
    expect(steps[1]?.value).toMatchObject({
      status: 400,
      body: { error: 'invalid_grant', errorCode: 'oidc.invalid_grant' },
      persistedState: { grantPresent: false, familyCount: 0 },
      sideEffects: { grantRevoked: true },
      redirect: null,
      cookies: [],
    });
    expect(steps[2]?.value).toMatchObject({
      generatedIds: { tokenFamily: '<token-family.1>' },
      persistedState: { grantPresent: false, familyCount: 0 },
      sideEffects: { grantRevoked: true },
    });
    expect(JSON.stringify(steps)).not.toMatch(
      /private-authorization-code|private-refresh|private-access|vvvv/u
    );
  });

  it('detects replay handling that leaves the original family active', async () => {
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
            accessToken: 'opaque-private-access-token',
            idToken,
            refreshToken: 'opaque-private-refresh-token',
          })
        ),
        rawResponse(400, invalidGrantBody),
      ],
      projectScenarioState: async ({ stepId }) =>
        scenarioState(stepId, stepId !== 'first-exchange'),
    });

    await expect(
      runTokenCodeReuseRejected(harness.context, {
        withPositiveOidcFlow: harness.flow,
      })
    ).rejects.toThrow('Phase 1 authorization code replay state is invalid');
    expect(harness.requests).toHaveLength(2);
  });
});
