/* eslint-disable @silverhand/fp/no-mutating-methods -- Ordered calls are the public behavior under test. */
import { createWebSocialIdentityDriver } from './web-social-identity.js';

test.each([
  ['google', 'https://accounts.google.test/auth'],
  ['wechat', 'https://open.weixin.test/connect/qrconnect'],
] as const)(
  'binds the %s provider authorization to the issued state and verification',
  async (provider, base) => {
    const calls: string[] = [];
    const driver = createWebSocialIdentityDriver({
      connectorId: `${provider}-connector`,
      redirectUri: `https://core.test/callback/${provider}-connector`,
      provider,
      takeProviderCode: async (authorizationUri, state) => {
        expect(new URL(authorizationUri).searchParams.get('state')).toBe(state);
        return 'owned-provider-code';
      },
    });
    await driver({
      request: async (path, method, body) => {
        calls.push(`${method} ${path}`);
        if (path === '/api/experience') {
          return new Response(null, { status: 204 });
        }
        if (path.endsWith('/authorization-uri')) {
          const state = String((body as { state: unknown }).state);
          return Response.json({
            verificationId: 'verification-id',
            authorizationUri: `${base}?state=${encodeURIComponent(state)}`,
          });
        }
        if (path.endsWith('/verify')) {
          expect(body).toEqual({
            verificationId: 'verification-id',
            connectorData: {
              code: 'owned-provider-code',
              redirectUri: `https://core.test/callback/${provider}-connector`,
            },
          });
          return Response.json({ verificationId: 'verification-id' });
        }
        return new Response(null, { status: 204 });
      },
    });
    expect(calls).toEqual([
      'PUT /api/experience',
      `POST /api/experience/verification/social/${provider}-connector/authorization-uri`,
      `POST /api/experience/verification/social/${provider}-connector/verify`,
      'POST /api/experience/identification',
    ]);
  }
);

test('rejects a provider authorization whose state is not bound to the interaction', async () => {
  const driver = createWebSocialIdentityDriver({
    connectorId: 'google-connector',
    redirectUri: 'https://core.test/callback/google-connector',
    provider: 'google',
    takeProviderCode: async () => 'must-not-run',
  });
  await expect(
    driver({
      request: async (path) =>
        path === '/api/experience'
          ? new Response(null, { status: 204 })
          : Response.json({
              verificationId: 'verification-id',
              authorizationUri: 'https://accounts.google.test/auth?state=foreign',
            }),
    })
  ).rejects.toThrow('Invalid Common web social identity flow');
});
/* eslint-enable @silverhand/fp/no-mutating-methods */
