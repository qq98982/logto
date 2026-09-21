import type { Phase1ScenarioStateProjectionInput } from '../scenario-runtime.js';
import { validateExactPhase1ScenarioSteps } from '../scenario-runtime.js';

import { phase1DifferentialScenarios } from './index.js';
import {
  createTokenScenarioHarness,
  createTokenTestSigner,
  tokenGrantBody,
  tokenTestCredentials,
  tokenTestRuntimeValues,
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
      userInfoBody: {
        sub: 'runtime-subject',
        name: 'Observed User',
        email: tokenTestRuntimeValues.email,
        email_verified: true,
      },
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
    const scenario = phase1DifferentialScenarios.find(
      ({ id }) => id === 'token.code-reuse-rejected'
    );

    if (!scenario) {
      throw new Error('Phase 1 code-reuse scenario is unavailable');
    }
    expect(validateExactPhase1ScenarioSteps(scenario, steps)).toHaveLength(3);

    expect(steps.map(({ stepId }) => stepId)).toEqual(['first-exchange', 'replay', 'state']);
    expect(harness.requests).toHaveLength(3);
    expect(harness.requests.map(({ operation }) => operation)).toEqual([
      'token-code-first-exchange',
      'userinfo-openid',
      'token-code-replay',
    ]);
    expect(harness.requests[1]?.options?.headers).toMatchObject({
      authorization: 'Bearer opaque-private-access-token',
    });
    expect(harness.requests[0]?.options?.body).toBe(harness.requests[2]?.options?.body);
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
      outcomes: [
        {
          kind: 'userinfo-email',
          response: {
            status: 200,
            mediaType: { type: 'application', subtype: 'json', parameters: {} },
            headers: { 'content-type': ['application/json'] },
            semanticState: null,
            sideEffects: null,
            body: {
              sub: '<user.phase1-user>',
              name: 'Observed User',
              email: '<fixture.data.email>',
              email_verified: true,
            },
          },
        },
      ],
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
      userInfoBody: {
        sub: 'runtime-subject',
        email: tokenTestRuntimeValues.email,
        email_verified: true,
      },
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
    expect(harness.requests).toHaveLength(3);
  });
});
