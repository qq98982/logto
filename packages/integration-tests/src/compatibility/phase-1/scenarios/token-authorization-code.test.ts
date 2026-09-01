/* eslint-disable no-await-in-loop -- Each invalid signed-token case owns a fresh key, fixture, and protocol exchange. */
import {
  createTokenScenarioHarness,
  createTokenTestSigner,
  tokenGrantBody,
  tokenTestCredentials,
  tokenTestRuntimeValues,
  tokenTestTarget,
} from './positive-oidc-token.test-helpers.js';
import { runTokenAuthorizationCode } from './token-authorization-code.js';

describe('token.authorization-code', () => {
  it('exchanges one S256 code and consumes it atomically', async () => {
    const signer = await createTokenTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const createdAt = (now - 120) * 1000;
    const updatedAt = (now - 60) * 1000;
    const accessToken = await signer.sign({
      iss: `${tokenTestTarget.coreUrl}oidc`,
      sub: 'runtime-subject',
      aud: tokenTestRuntimeValues.resourceIndicator,
      client_id: tokenTestCredentials.clientId,
      scope: tokenTestRuntimeValues.scopeName,
      iat: now,
      exp: now + 3600,
      auth_time: now - 50,
    });
    const idToken = await signer.sign({
      iss: `${tokenTestTarget.coreUrl}oidc`,
      sub: 'runtime-subject',
      aud: tokenTestCredentials.clientId,
      iat: now,
      exp: now + 3600,
      auth_time: now - 50,
      created_at: createdAt,
      updated_at: updatedAt,
    });
    const harness = createTokenScenarioHarness({
      jwk: signer.jwk,
      tokenBodies: [
        tokenGrantBody({
          accessToken,
          idToken,
          refreshToken: 'private-initial-refresh-token',
        }),
      ],
    });
    const steps = await runTokenAuthorizationCode(harness.context, {
      withPositiveOidcFlow: harness.flow,
    });

    expect(steps.map(({ stepId }) => stepId)).toEqual(['token', 'state']);
    expect(harness.requests).toHaveLength(1);
    const request = harness.requests[0];
    expect(request).toMatchObject({
      operation: 'token-authorization-code',
      path: 'oidc/token',
      options: {
        method: 'POST',
        includeCookies: false,
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
      },
    });
    expect(Object.fromEntries(new URLSearchParams(request?.options?.body))).toEqual({
      grant_type: 'authorization_code',
      client_id: tokenTestCredentials.clientId,
      code: tokenTestCredentials.code,
      code_verifier: tokenTestCredentials.codeVerifier,
      redirect_uri: tokenTestCredentials.redirectUri,
    });
    expect(steps[0]?.value).toMatchObject({
      status: 200,
      tokens: [
        {
          kind: 'access',
          format: 'jwt',
          signatureVerified: true,
          claims: {
            sub: '<user.phase1-user>',
            aud: '<fixture.data.resource-indicator>',
            scope: '<fixture.data.scope-name>',
          },
        },
        { kind: 'id', format: 'jwt', signatureVerified: true },
        { kind: 'refresh', format: 'opaque', present: true },
      ],
    });
    expect(steps[1]?.value).toMatchObject({
      generatedIds: { tokenFamily: '<token-family.1>' },
      persistedState: { grantConsumed: true, familyCount: 1 },
      semanticState: { unrelatedMutation: false },
    });
    expect(steps[0]?.value.tokens[1]).toMatchObject({
      kind: 'id',
      claims: {
        created_at: { $timestamp: Math.floor(createdAt / 1000), $toleranceSeconds: 30 },
        updated_at: { $timestamp: Math.floor(updatedAt / 1000), $toleranceSeconds: 30 },
      },
    });
    expect(harness.stateReads).toEqual(['token', 'state']);
    expect(JSON.stringify(steps)).not.toMatch(
      /private-authorization-code|private-initial-refresh-token|vvvvvvvv/u
    );

    const incomplete = createTokenScenarioHarness({
      jwk: signer.jwk,
      tokenBodies: [
        tokenGrantBody({
          accessToken,
          idToken,
          refreshToken: 'private-incomplete-refresh-token',
        }),
      ],
    });
    const incompleteContext = {
      ...incomplete.context,
      projectScenarioState: async (
        input: Parameters<typeof incomplete.context.projectScenarioState>[0]
      ) =>
        input.stepId === 'state'
          ? {
              body: {},
              semanticState: {},
              persistedState: { grantConsumed: false },
              generatedIds: { tokenFamily: '<token-family.1>' },
              sideEffects: { unrelatedMutation: false },
            }
          : incomplete.context.projectScenarioState(input),
    };
    await expect(
      runTokenAuthorizationCode(incompleteContext, {
        withPositiveOidcFlow: incomplete.flow,
      })
    ).rejects.toThrow('Phase 1 authorization code state is invalid');
  });

  it('rejects signed tokens with invalid algorithm issuer audience subject lifetime or scope', async () => {
    const now = Math.floor(Date.now() / 1000);
    const cases: ReadonlyArray<
      Readonly<{
        algorithm?: 'ES384' | 'RS256';
        id?: Readonly<Record<string, unknown>>;
        access?: Readonly<Record<string, unknown>>;
      }>
    > = [
      { algorithm: 'RS256' },
      { id: { iss: 'https://wrong-issuer.example/oidc' } },
      { id: { aud: 'wrong-client' } },
      { id: { sub: 'wrong-subject' } },
      { id: { iat: now - 7200, exp: now - 3600 } },
      { access: { aud: 'https://wrong-resource.example' } },
      { access: { scope: 'write:profile' } },
    ];

    for (const invalid of cases) {
      const signer = await createTokenTestSigner(invalid.algorithm);
      const accessToken = await signer.sign({
        iss: `${tokenTestTarget.coreUrl}oidc`,
        sub: 'runtime-subject',
        aud: tokenTestRuntimeValues.resourceIndicator,
        client_id: tokenTestCredentials.clientId,
        scope: tokenTestRuntimeValues.scopeName,
        iat: now,
        exp: now + 3600,
        ...invalid.access,
      });
      const idToken = await signer.sign({
        iss: `${tokenTestTarget.coreUrl}oidc`,
        sub: 'runtime-subject',
        aud: tokenTestCredentials.clientId,
        iat: now,
        exp: now + 3600,
        ...invalid.id,
      });
      const harness = createTokenScenarioHarness({
        jwk: signer.jwk,
        tokenBodies: [
          tokenGrantBody({
            accessToken,
            idToken,
            refreshToken: 'private-invalid-refresh-token',
          }),
        ],
      });

      await expect(
        runTokenAuthorizationCode(harness.context, {
          withPositiveOidcFlow: harness.flow,
        })
      ).rejects.toThrow('Phase 1 token claims are invalid');
    }
  });

  it('rejects valid profile claims signed by a key outside the observed JWKS', async () => {
    const signer = await createTokenTestSigner();
    const unrelatedSigner = await createTokenTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const accessToken = await signer.sign({
      iss: `${tokenTestTarget.coreUrl}oidc`,
      sub: 'runtime-subject',
      aud: tokenTestRuntimeValues.resourceIndicator,
      client_id: tokenTestCredentials.clientId,
      scope: tokenTestRuntimeValues.scopeName,
      iat: now,
      exp: now + 3600,
    });
    const idToken = await signer.sign({
      iss: `${tokenTestTarget.coreUrl}oidc`,
      sub: 'runtime-subject',
      aud: tokenTestCredentials.clientId,
      iat: now,
      exp: now + 3600,
    });
    const harness = createTokenScenarioHarness({
      jwk: unrelatedSigner.jwk,
      tokenBodies: [
        tokenGrantBody({
          accessToken,
          idToken,
          refreshToken: 'private-signature-refresh-token',
        }),
      ],
    });

    await expect(
      runTokenAuthorizationCode(harness.context, {
        withPositiveOidcFlow: harness.flow,
      })
    ).rejects.toThrow('Invalid phase 1 observed JWT signature');
  });
});

/* eslint-enable no-await-in-loop */
