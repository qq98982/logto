/* eslint-disable @silverhand/fp/no-mutating-methods -- The fake records owned IDs and request order. */
import type { Phase2AdminRequest, Phase2AdminRequestFunction } from '../fixtures.js';

import {
  createManagementApplication,
  createManagementApplicationSecret,
  observeClientSecretAuthentication,
} from './management-applications-family.js';

const credentialBearingApplicationRequest: Phase2AdminRequestFunction = async () => ({
  id: 'app',
  name: 'owned',
  description: 'Owned application',
  type: 'Traditional',
  isThirdParty: false,
  clientSecret: 'must-not-enter-the-projection',
  oidcClientMetadata: {
    redirectUris: ['https://owned.example/callback'],
    postLogoutRedirectUris: ['https://owned.example/logout'],
    backchannelLogoutUri: 'https://owned.example/backchannel',
    backchannelLogoutSessionRequired: true,
  },
});
test('captures an owned application and leases a newly revealed secret', async () => {
  const calls: Phase2AdminRequest[] = [];
  const request: Phase2AdminRequestFunction = async (input) => {
    calls.push(input);
    return input.path === 'applications'
      ? {
          id: 'app',
          name: 'owned',
          description: 'Owned application',
          type: 'Traditional',
          isThirdParty: false,
          oidcClientMetadata: {
            redirectUris: ['https://owned.example/callback'],
            postLogoutRedirectUris: ['https://owned.example/logout'],
            backchannelLogoutUri: 'https://owned.example/backchannel',
            backchannelLogoutSessionRequired: true,
          },
        }
      : { id: 'secret', name: 'secondary', value: 'private-secret', createdAt: 1, expiresAt: null };
  };
  const owned: string[] = [];
  await expect(
    createManagementApplication(
      request,
      {
        name: 'owned',
        description: 'Owned application',
        redirectUri: 'https://owned.example/callback',
        postLogoutRedirectUri: 'https://owned.example/logout',
        backchannelLogoutUri: 'https://owned.example/backchannel',
      },
      (id) => owned.push(id)
    )
  ).resolves.toMatchObject({ id: 'app' });
  await expect(
    createManagementApplicationSecret(
      request,
      'app',
      'secondary',
      async ({ getSecret }) => getSecret() === 'private-secret'
    )
  ).resolves.toBe(true);
  expect(owned).toEqual(['app']);
  expect(calls.map(({ method, path }) => `${method} ${path}`)).toEqual([
    'POST applications',
    'POST applications/app/secrets',
  ]);
});

test('rejects credential material in an ordinary application response', async () => {
  const captured: string[] = [];
  await expect(
    createManagementApplication(
      credentialBearingApplicationRequest,
      {
        name: 'owned',
        description: 'Owned application',
        redirectUri: 'https://owned.example/callback',
        postLogoutRedirectUri: 'https://owned.example/logout',
        backchannelLogoutUri: 'https://owned.example/backchannel',
      },
      (id) => captured.push(id)
    )
  ).rejects.toThrow('Invalid Common Management applications family transport');
  expect(captured).toEqual(['app']);
});
test('accepts a secret only when it reaches target validation and a wrong secret is rejected', async () => {
  const authorizations: string[] = [];
  const bodies: string[] = [];
  const fetcher: typeof fetch = async (_input, init) => {
    const authorization = new Headers(init?.headers).get('authorization') ?? '';
    authorizations.push(authorization);
    bodies.push(String(init?.body));
    const decoded = Buffer.from(authorization.slice('Basic '.length), 'base64').toString();
    return decoded.endsWith(':private-secret')
      ? new Response(JSON.stringify({ error: 'invalid_grant' }), { status: 400 })
      : new Response(JSON.stringify({ error: 'invalid_client' }), { status: 401 });
  };
  await expect(
    observeClientSecretAuthentication(
      { label: 'oracle', coreUrl: 'https://core.example/', adminUrl: 'https://admin.example/' },
      'app',
      'private-secret',
      { redirectUri: 'https://owned.example/callback', fetch: fetcher }
    )
  ).resolves.toEqual({ accepted: true });
  expect(authorizations).toHaveLength(2);
  expect(bodies).toEqual([
    'grant_type=authorization_code&code=common-management-nonexistent-code&redirect_uri=https%3A%2F%2Fowned.example%2Fcallback',
    'grant_type=authorization_code&code=common-management-nonexistent-code&redirect_uri=https%3A%2F%2Fowned.example%2Fcallback',
  ]);
});
test('rejects a revealed secret when the endpoint reports invalid client authentication', async () => {
  await expect(
    observeClientSecretAuthentication(
      { label: 'oracle', coreUrl: 'https://core.example/', adminUrl: 'https://admin.example/' },
      'app',
      'rejected-secret',
      {
        redirectUri: 'https://owned.example/callback',
        fetch: async () =>
          new Response(JSON.stringify({ error: 'invalid_client' }), { status: 401 }),
      }
    )
  ).resolves.toEqual({ accepted: false });
});
/* eslint-enable @silverhand/fp/no-mutating-methods */
