import {
  createTokenScenarioHarness,
  createTokenTestSigner,
  tokenGrantBody,
  tokenTestCredentials,
  tokenTestRuntimeValues,
  tokenTestTarget,
} from './positive-oidc-token.test-helpers.js';
import { runUserInfoOpenId } from './userinfo-openid.js';

describe('userinfo.openid', () => {
  it('returns the seeded subject and requested profile claims', async () => {
    const signer = await createTokenTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const createdAt = (now - 120) * 1000;
    const updatedAt = (now - 60) * 1000;
    const idToken = await signer.sign({
      iss: `${tokenTestTarget.coreUrl}oidc`,
      sub: 'runtime-subject',
      aud: tokenTestCredentials.clientId,
      iat: now,
      exp: now + 3600,
      auth_time: now - 50,
    });
    const accessToken = 'private-userinfo-opaque-access';
    const userInfo = {
      sub: 'runtime-subject',
      name: 'Phase 1 User',
      preferred_username: tokenTestRuntimeValues.username,
      username: tokenTestRuntimeValues.username,
      email: tokenTestRuntimeValues.email,
      email_verified: true,
      phone_number: tokenTestRuntimeValues.phone,
      phone_number_verified: true,
      address: { formatted: '1 Aster Way', country: 'US' },
      created_at: createdAt,
      updated_at: updatedAt,
    };
    const harness = createTokenScenarioHarness({
      jwk: signer.jwk,
      tokenBodies: [
        tokenGrantBody({
          accessToken,
          idToken,
          refreshToken: 'private-userinfo-refresh-token',
        }),
      ],
      userInfoBody: userInfo,
    });
    const steps = await runUserInfoOpenId(harness.context, {
      withPositiveOidcFlow: harness.flow,
    });

    expect(steps.map(({ stepId }) => stepId)).toEqual(['userinfo', 'state']);
    expect(harness.requests.map(({ operation, path }) => `${operation}:${path}`)).toEqual([
      'token-authorization-code:oidc/token',
      'userinfo-openid:oidc/me',
    ]);
    expect(harness.requests[1]?.options).toMatchObject({
      includeCookies: false,
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(steps[0]?.value).toMatchObject({
      status: 200,
      body: {
        sub: '<user.phase1-user>',
        name: 'Phase 1 User',
        preferred_username: '<fixture.data.username>',
        username: '<fixture.data.username>',
        email: '<fixture.data.email>',
        email_verified: true,
        phone_number: '<fixture.data.phone>',
        phone_number_verified: true,
        address: { formatted: '1 Aster Way', country: 'US' },
        created_at: { $timestamp: Math.floor(createdAt / 1000), $toleranceSeconds: 30 },
        updated_at: { $timestamp: Math.floor(updatedAt / 1000), $toleranceSeconds: 30 },
      },
    });
    expect(steps[1]?.value).toMatchObject({
      semanticState: { unrelatedMutation: false },
      persistedState: { unrelatedMutation: false },
    });
    expect(harness.stateReads).toEqual(['userinfo', 'state']);
    expect(JSON.stringify(steps)).not.toMatch(
      /private-userinfo|private-authorization-code|vvvvvvvv/u
    );
  });
});
