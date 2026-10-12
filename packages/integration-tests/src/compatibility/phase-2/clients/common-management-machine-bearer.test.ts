/* eslint-disable @silverhand/fp/no-mutating-methods, @silverhand/fp/no-mutation -- The request journal proves Admin issuer selection and absence of public Candidate setup. */
import { exportJWK, generateKeyPair, SignJWT } from 'jose';

import { withCommonManagementMachineBearer } from './common-management-machine-bearer.js';

const response = (value: unknown) =>
  new Response(JSON.stringify(value), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });

test('verifies the real Admin machine token without public Candidate provisioning', async () => {
  const target = {
    label: 'candidate' as const,
    coreUrl: 'https://data.test/',
    adminUrl: 'https://admin.test/',
  };
  const { publicKey, privateKey } = await generateKeyPair('ES384');
  const jwk = {
    ...(await exportJWK(publicKey)),
    kid: 'owned-signing-key',
    alg: 'ES384',
    use: 'sig',
  };
  const urls: string[] = [];
  const state = { cleaned: false };

  await expect(
    withCommonManagementMachineBearer(
      {
        target,
        fixture: {
          withCandidateManagementMachineClient: async (_seed, use) => {
            try {
              return await use({
                clientId: 'aster-mgmt-m2m',
                resource: 'urn:aster:resource:management',
                scope: 'all',
                tokenEndpointAuthMethod: 'client_secret_basic',
                grantType: 'client_credentials',
                accessTokenAlg: 'ES384',
                accessTokenType: 'at+jwt',
                accessTokenTtlSeconds: 3600,
              });
            } finally {
              state.cleaned = true;
            }
          },
        },
        fetch: async (url) => {
          const parsed = new URL(String(url));
          urls.push(parsed.href);
          if (parsed.pathname.endsWith('openid-configuration')) {
            return response({ issuer: 'https://admin.test/oidc' });
          }
          if (parsed.pathname === '/oidc/jwks') {
            return response({ keys: [jwk] });
          }
          const now = Math.floor(Date.now() / 1000);
          const token = await new SignJWT({ client_id: 'aster-mgmt-m2m', scope: 'all' })
            .setProtectedHeader({ alg: 'ES384', typ: 'at+jwt', kid: jwk.kid })
            .setIssuer('https://admin.test/oidc')
            .setAudience('urn:aster:resource:management')
            .setSubject('aster-mgmt-m2m')
            .setIssuedAt(now)
            .setExpirationTime(now + 3600)
            .sign(privateKey);
          return response({
            access_token: token,
            token_type: 'Bearer',
            expires_in: 3600,
            scope: 'all',
          });
        },
      },
      async (bearer) => bearer.split('.').length === 3
    )
  ).resolves.toBe(true);
  expect(urls).toEqual([
    'https://admin.test/oidc/.well-known/openid-configuration',
    'https://admin.test/oidc/jwks',
    'https://admin.test/oidc/token',
  ]);
  expect(state.cleaned).toBe(true);
});
/* eslint-enable @silverhand/fp/no-mutating-methods, @silverhand/fp/no-mutation */
