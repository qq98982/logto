import {
  createTokenScenarioHarness,
  createTokenTestSigner,
  tokenGrantBody,
  tokenTestCredentials,
  tokenTestTarget,
} from './positive-oidc-token.test-helpers.js';
import { runTokenRefreshRotation } from './token-refresh-rotation.js';

describe('token.refresh-rotation', () => {
  it('rotates a public-client refresh token without unrelated mutation', async () => {
    const signer = await createTokenTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const createdAt = (now - 120) * 1000;
    const updatedAt = (now - 60) * 1000;
    const initialIdToken = await signer.sign({
      iss: `${tokenTestTarget.coreUrl}oidc`,
      sub: 'runtime-subject',
      aud: tokenTestCredentials.clientId,
      iat: now,
      exp: now + 3600,
      auth_time: now - 50,
      created_at: createdAt,
      updated_at: updatedAt,
    });
    const rotatedIdToken = await signer.sign({
      iss: `${tokenTestTarget.coreUrl}oidc`,
      sub: 'runtime-subject',
      aud: tokenTestCredentials.clientId,
      iat: now + 1,
      exp: now + 3601,
      auth_time: now - 50,
      created_at: createdAt,
      updated_at: updatedAt,
    });
    const initialRefreshToken = 'private-initial-refresh-token';
    const rotatedRefreshToken = 'private-rotated-refresh-token';
    const harness = createTokenScenarioHarness({
      jwk: signer.jwk,
      tokenBodies: [
        tokenGrantBody({
          accessToken: 'private-initial-opaque-access',
          idToken: initialIdToken,
          refreshToken: initialRefreshToken,
        }),
        tokenGrantBody({
          accessToken: 'private-rotated-opaque-access',
          idToken: rotatedIdToken,
          refreshToken: rotatedRefreshToken,
        }),
      ],
    });
    const steps = await runTokenRefreshRotation(harness.context, {
      withPositiveOidcFlow: harness.flow,
    });

    expect(steps.map(({ stepId }) => stepId)).toEqual([
      'code-token',
      'refresh-token',
      'family-state',
    ]);
    expect(harness.requests.map(({ operation }) => operation)).toEqual([
      'token-authorization-code',
      'token-refresh',
    ]);
    const refreshForm = new URLSearchParams(harness.requests[1]?.options?.body);
    expect(Object.fromEntries(refreshForm)).toEqual({
      grant_type: 'refresh_token',
      client_id: tokenTestCredentials.clientId,
      refresh_token: initialRefreshToken,
    });
    expect(steps[0]?.value).toMatchObject({
      body: {
        tokenType: 'Bearer',
        access: { format: 'opaque' },
        id: { format: 'jwt' },
        refresh: { format: 'opaque', present: true },
      },
      tokens: [],
    });
    expect(steps[1]?.value).toMatchObject({
      tokens: [
        { kind: 'access', format: 'opaque' },
        { kind: 'id', format: 'jwt', signatureVerified: true },
        { kind: 'refresh', format: 'opaque', present: true },
      ],
      sideEffects: { unrelatedMutation: false },
    });
    expect(steps[2]?.value).toMatchObject({
      generatedIds: { tokenFamily: '<token-family.1>' },
      persistedState: {
        unrelatedMutation: false,
        rotation: { replaced: true, sameFamily: true },
      },
    });
    expect(harness.stateReads).toEqual(['code-token', 'refresh-token', 'family-state']);
    expect(JSON.stringify(steps)).not.toMatch(
      /private-initial|private-rotated|private-authorization-code|vvvvvvvv/u
    );

    const incomplete = createTokenScenarioHarness({
      jwk: signer.jwk,
      tokenBodies: [
        tokenGrantBody({
          accessToken: 'private-incomplete-initial-access',
          idToken: initialIdToken,
          refreshToken: 'private-incomplete-initial-refresh',
        }),
        tokenGrantBody({
          accessToken: 'private-incomplete-rotated-access',
          idToken: rotatedIdToken,
          refreshToken: 'private-incomplete-rotated-refresh',
        }),
      ],
    });
    const incompleteContext = {
      ...incomplete.context,
      projectScenarioState: async (
        input: Parameters<typeof incomplete.context.projectScenarioState>[0]
      ) =>
        input.stepId === 'family-state'
          ? {
              body: {},
              semanticState: {},
              persistedState: {
                rotation: { replaced: true, sameFamily: false },
                unrelatedMutation: false,
              },
              generatedIds: { tokenFamily: '<token-family.1>' },
              sideEffects: { unrelatedMutation: false },
            }
          : incomplete.context.projectScenarioState(input),
    };
    await expect(
      runTokenRefreshRotation(incompleteContext, {
        withPositiveOidcFlow: incomplete.flow,
      })
    ).rejects.toThrow('Phase 1 refresh family state is invalid');
  });
});
