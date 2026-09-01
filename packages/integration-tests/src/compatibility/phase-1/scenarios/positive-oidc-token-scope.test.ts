import { exchangePositiveAuthorizationCode } from './positive-oidc-flow.js';
import {
  assertPositiveOidcTokenGrantIncludesScope,
  revokePositiveTokenGrant,
} from './positive-oidc-token.js';
import {
  createTokenScenarioHarness,
  createTokenTestSigner,
  tokenGrantBody,
  tokenTestCredentials,
  tokenTestTarget,
} from './positive-oidc-token.test-helpers.js';

describe('positive OIDC token scope authority', () => {
  it('rejects an opaque token grant response missing a required scope', async () => {
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
          accessToken: 'opaque-private-profile-access-token',
          idToken,
          refreshToken: 'opaque-private-profile-refresh-token',
          scope: 'profile',
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
          assertPositiveOidcTokenGrantIncludesScope(tokenGrant, 'openid');
        }).toThrow('Phase 1 token grant scope is invalid');
      } finally {
        revokePositiveTokenGrant(tokenGrant);
      }

      return null;
    });
  });
});
