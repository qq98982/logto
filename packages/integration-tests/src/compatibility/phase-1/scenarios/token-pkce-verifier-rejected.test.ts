import type { Phase1ScenarioStateProjectionInput } from '../scenario-runtime.js';

import { exchangePositiveAuthorizationCode } from './positive-oidc-flow.js';
import * as positiveOidcFlow from './positive-oidc-flow.js';
import {
  assertPositiveOidcAuthorizationCodeRequestActive,
  assertPositiveOidcTokenGrantIncludesScope,
  assertPositiveOidcTokenGrantActive,
  exchangePositiveAuthorizationCodeRequest,
  revokePositiveTokenGrant,
  type PositiveOidcAuthorizationCodeRequest,
  type PositiveOidcTokenGrant,
  withPositiveOidcAuthorizationCodeRequest,
} from './positive-oidc-token.js';
import * as positiveOidcToken from './positive-oidc-token.js';
import {
  createTokenScenarioHarness,
  createTokenTestSigner,
  tokenGrantBody,
  tokenTestCredentials,
  tokenTestTarget,
} from './positive-oidc-token.test-helpers.js';
import { runTokenPkceVerifierRejected } from './token-pkce-verifier-rejected.js';

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

describe('token.pkce-verifier-rejected', () => {
  it('rejects a mismatched verifier without consuming the grant then accepts the correct probe', async () => {
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
        rawResponse(400, invalidGrantBody),
        rawResponse(
          200,
          tokenGrantBody({
            accessToken: 'opaque-private-access-token',
            idToken,
            refreshToken: 'opaque-private-refresh-token',
          })
        ),
      ],
      projectScenarioState: async ({ stepId }): Promise<Phase1ScenarioStateProjectionInput> => {
        const common = {
          body: {},
          semanticState: { unrelatedMutation: false },
          sideEffects: { unrelatedMutation: false },
        };

        if (stepId === 'bad-verifier') {
          return {
            ...common,
            persistedState: {
              firstAttemptConsumed: false,
              grantConsumed: false,
              familyCount: 0,
              unrelatedMutation: false,
            },
            generatedIds: {},
          };
        }
        if (stepId === 'valid-verifier-probe') {
          return {
            ...common,
            persistedState: {
              firstAttemptConsumed: false,
              grantConsumed: true,
              familyCount: 1,
              unrelatedMutation: false,
            },
            generatedIds: {},
          };
        }

        return {
          ...common,
          persistedState: {
            firstAttemptConsumed: false,
            validProbeSucceeded: true,
            grantConsumed: true,
            familyCount: 1,
            unrelatedMutation: false,
          },
          generatedIds: { tokenFamily: '<token-family.1>' },
        };
      },
    });
    const steps = await runTokenPkceVerifierRejected(harness.context, {
      withPositiveOidcFlow: harness.flow,
    });

    expect(steps.map(({ stepId }) => stepId)).toEqual([
      'bad-verifier',
      'valid-verifier-probe',
      'state',
    ]);
    expect(harness.requests).toHaveLength(2);
    const badForm = new URLSearchParams(harness.requests[0]?.options?.body);
    const validForm = new URLSearchParams(harness.requests[1]?.options?.body);
    expect(harness.requests.map(({ operation }) => operation)).toEqual([
      'token-pkce-bad-verifier',
      'token-pkce-valid-verifier-probe',
    ]);
    const badFields = Object.fromEntries(badForm);
    const validFields = Object.fromEntries(validForm);
    expect(badFields).toMatchObject({
      grant_type: 'authorization_code',
      client_id: tokenTestCredentials.clientId,
      redirect_uri: tokenTestCredentials.redirectUri,
    });
    expect(validFields).toMatchObject({
      grant_type: 'authorization_code',
      client_id: tokenTestCredentials.clientId,
      redirect_uri: tokenTestCredentials.redirectUri,
    });
    expect(badFields.code).toBe(validFields.code);
    expect(badFields.code).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(validFields.code_verifier).toMatch(/^[A-Za-z0-9_-]{64}$/u);
    expect(badFields.code_verifier).toBe(
      `${validFields.code_verifier?.startsWith('x') ? 'y' : 'x'}${validFields.code_verifier?.slice(1)}`
    );
    expect(badFields.code_verifier).not.toBe(validFields.code_verifier);
    expect(harness.requests.map(({ options }) => options)).toEqual([
      {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: badForm.toString(),
        includeCookies: false,
      },
      {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: validForm.toString(),
        includeCookies: false,
      },
    ]);
    expect(steps[0]?.value).toMatchObject({
      status: 400,
      body: {
        error: 'invalid_grant',
        errorCode: 'oidc.invalid_grant',
        error_uri: { $url: 0 },
      },
      urls: [
        {
          scheme: 'https',
          origin: 'https://openid.sh',
          path: '/debug/invalid_grant',
        },
      ],
      redirect: null,
      cookies: [],
    });
    expect(Object.keys(steps[0]?.value.headers ?? {})).toEqual([
      'cache-control',
      'content-length',
      'content-type',
    ]);
    expect(steps[0]?.value.headers['cache-control']).toEqual(['no-store']);
    expect(steps[0]?.value.headers['content-length']).toHaveLength(1);
    expect(steps[0]?.value.headers['content-type']).toEqual(['application/json; charset=utf-8']);
    expect(steps[0]?.value.redirect).toBeNull();
    expect(steps[0]?.value.cookies).toEqual([]);
    expect(steps[1]?.value).toMatchObject({
      status: 200,
      body: {
        tokenType: 'Bearer',
        access: { format: 'opaque' },
        id: { format: 'jwt' },
        refresh: { format: 'opaque' },
      },
      tokens: [],
    });
    expect(steps[2]?.value).toMatchObject({
      generatedIds: { tokenFamily: '<token-family.1>' },
      persistedState: { firstAttemptConsumed: false, familyCount: 1 },
    });
    expect(JSON.stringify(steps)).not.toMatch(
      /private-authorization-code|private-refresh|private-access|vvvv/u
    );
  });

  it('detects an implementation that consumes the grant on a bad verifier', async () => {
    const signer = await createTokenTestSigner();
    const harness = createTokenScenarioHarness({
      jwk: signer.jwk,
      tokenBodies: [],
      tokenResponses: [rawResponse(400, invalidGrantBody)],
      projectScenarioState: async () => ({
        body: {},
        semanticState: { unrelatedMutation: false },
        persistedState: {
          firstAttemptConsumed: true,
          grantConsumed: true,
          familyCount: 0,
          unrelatedMutation: false,
        },
        generatedIds: {},
        sideEffects: { unrelatedMutation: false },
      }),
    });

    await expect(
      runTokenPkceVerifierRejected(harness.context, {
        withPositiveOidcFlow: harness.flow,
      })
    ).rejects.toThrow('Phase 1 rejected PKCE verifier state is invalid');
    expect(harness.requests).toHaveLength(1);
  });

  it('does not export raw authorization-code transport or expose a serializable success response', async () => {
    expect(Object.keys(positiveOidcFlow)).not.toEqual(
      expect.arrayContaining([
        'requestPositiveOidcAuthorization',
        'requestPositiveAuthorizationCode',
        'withPositiveOidcAuthorizationCodeResponse',
        'withPositiveOidcAuthorizationGrantCredentials',
      ])
    );
    expect(Object.keys(positiveOidcToken)).not.toEqual(
      expect.arrayContaining([
        'PositiveOidcTokenGrant',
        'acceptPositiveAuthorizationCodeResponse',
        'projectPositiveOidcInvalidGrant',
        'requestPositiveAuthorizationCode',
        'requestPositiveUserInfo',
      ])
    );
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
      tokenBodies: [
        tokenGrantBody({
          accessToken: 'opaque-private-access-token',
          idToken,
          refreshToken: 'opaque-private-refresh-token',
        }),
        tokenGrantBody({
          accessToken: 'second-opaque-private-access-token',
          idToken,
          refreshToken: 'second-opaque-private-refresh-token',
        }),
      ],
    });

    await harness.flow(harness.context, { captureSteps: false }, async (authorizationGrant) => {
      const tokenGrant = await exchangePositiveAuthorizationCode(
        harness.context,
        authorizationGrant
      );
      try {
        expect(() => {
          assertPositiveOidcTokenGrantActive(tokenGrant);
        }).not.toThrow();
        expect(() => {
          assertPositiveOidcTokenGrantIncludesScope(tokenGrant, 'openid');
        }).not.toThrow();
        expect(() => JSON.stringify(tokenGrant)).toThrow('Phase 1 token grant is not serializable');
      } finally {
        revokePositiveTokenGrant(tokenGrant);
      }
      expect(() => {
        assertPositiveOidcTokenGrantActive(tokenGrant);
      }).toThrow('Invalid Phase 1 token grant');

      return null;
    });

    const forged = Object.freeze({
      toJSON: () => {
        throw new TypeError('forged');
      },
    }) as PositiveOidcTokenGrant;
    expect(() => {
      assertPositiveOidcTokenGrantActive(forged);
    }).toThrow('Invalid Phase 1 token grant');

    const forgedRequest = Object.freeze({
      toJSON: () => {
        throw new TypeError('forged');
      },
    }) as PositiveOidcAuthorizationCodeRequest;
    expect(() => {
      assertPositiveOidcAuthorizationCodeRequestActive(forgedRequest);
    }).toThrow('Invalid Phase 1 authorization code request');
    await expect(
      exchangePositiveAuthorizationCodeRequest(harness.context, forgedRequest)
    ).rejects.toThrow('Invalid Phase 1 authorization code request');

    await withPositiveOidcAuthorizationCodeRequest(
      harness.context,
      {
        operation: 'token-authority-capability',
        clientId: tokenTestCredentials.clientId,
        code: tokenTestCredentials.code,
        verifier: tokenTestCredentials.codeVerifier,
        redirectUri: tokenTestCredentials.redirectUri,
      },
      async (request) => {
        expect(() => {
          assertPositiveOidcAuthorizationCodeRequestActive(request);
        }).not.toThrow();
        expect(() => JSON.stringify(request)).toThrow(
          'Phase 1 authorization code request is not serializable'
        );
        const tokenGrant = await exchangePositiveAuthorizationCodeRequest(harness.context, request);
        revokePositiveTokenGrant(tokenGrant);
        expect(() => {
          assertPositiveOidcAuthorizationCodeRequestActive(request);
        }).toThrow('Invalid Phase 1 authorization code request');
        await expect(
          exchangePositiveAuthorizationCodeRequest(harness.context, request)
        ).rejects.toThrow('Invalid Phase 1 authorization code request');

        return null;
      }
    );
    const retained = await withPositiveOidcAuthorizationCodeRequest(
      harness.context,
      {
        operation: 'token-authority-retained',
        clientId: tokenTestCredentials.clientId,
        code: tokenTestCredentials.code,
        verifier: tokenTestCredentials.codeVerifier,
        redirectUri: tokenTestCredentials.redirectUri,
      },
      async (request) => request
    );
    expect(() => {
      assertPositiveOidcAuthorizationCodeRequestActive(retained);
    }).toThrow('Invalid Phase 1 authorization code request');
    expect(harness.requests).toHaveLength(2);
    const request = harness.requests[1];
    const form = new URLSearchParams(request?.options?.body);
    expect(request).toMatchObject({
      operation: 'token-authority-capability',
      path: 'oidc/token',
      options: {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        includeCookies: false,
      },
    });
    expect(form.get('client_id')).toBe(tokenTestCredentials.clientId);
    expect(form.get('code')).toBe(tokenTestCredentials.code);
    expect(form.get('code_verifier')).toBe(tokenTestCredentials.codeVerifier);
    expect(form.get('redirect_uri')).toBe(tokenTestCredentials.redirectUri);
  });
});
