/* eslint-disable @silverhand/fp/no-mutating-methods -- The fake callback transport records the private authorization sequence. */
import type { TargetConfig } from '../model.js';

import type { Phase2FixtureSecretLease, ProvisionedPhase2Fixture } from './fixtures.js';
import { stopSelectedNativeAtCallback } from './selected-native-callback.js';
import type { Phase2FixturePublicWithSelectedNative } from './selected-native-fixture.js';

const target: TargetConfig = {
  label: 'candidate',
  coreUrl: 'https://candidate.example/',
  adminUrl: 'https://candidate-admin.example/',
};
const expectedIssuer = 'https://candidate.example/oidc';

const response = (
  status: number,
  body?: unknown,
  headers: Readonly<Record<string, string>> = {}
): Response =>
  new Response(body === undefined ? undefined : JSON.stringify(body), {
    status,
    headers: { ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...headers },
  });

const selectedFixture = (): ProvisionedPhase2Fixture & {
  public: Phase2FixturePublicWithSelectedNative;
} => {
  const publicFixture = {
    allocationId: 'selected-native-callback',
    clients: {
      basic: { id: 'generic-client', method: 'client_secret_basic' as const },
      post: { id: 'post-client', method: 'client_secret_post' as const },
    },
    deviceClients: {
      firstParty: {
        id: 'device-client',
        applicationType: 'Native' as const,
        authenticationMethod: 'none' as const,
        isThirdParty: false,
        deviceGrantEnabled: true,
      },
      thirdParty: {
        id: 'device-third',
        applicationType: 'Native' as const,
        authenticationMethod: 'none' as const,
        isThirdParty: true,
        deviceGrantEnabled: true,
      },
      missingGrant: {
        id: 'device-no-grant',
        applicationType: 'Native' as const,
        authenticationMethod: 'none' as const,
        isThirdParty: false,
        deviceGrantEnabled: false,
      },
      ineligibleWeb: {
        id: 'device-web',
        applicationType: 'SPA' as const,
        authenticationMethod: 'none' as const,
        isThirdParty: false,
        deviceGrantEnabled: false,
      },
    },
    resources: {
      primary: { id: 'generic-resource', indicator: 'https://generic.example/api' },
      default: { id: 'default-resource', indicator: 'https://default.example/api' },
    },
    organization: { id: 'organization', scopeName: 'organization:read' as const },
    scopes: {
      read: { id: 'read', name: 'read' as const },
      write: { id: 'write', name: 'write' as const },
      unassigned: { id: 'unassigned', name: 'unassigned' as const },
    },
    boundary: { primary: 'provisioned' as const, foreign: 'unchanged' as const },
    selectedNative: {
      clientId: 'actual-native-client',
      applicationType: 'Native' as const,
      redirectUri: 'https://native.example/logto-callback',
      resource: {
        id: 'native-resource',
        indicator: 'https://native.example/api',
        accessTokenTtl: 300 as const,
        scope: { id: 'native-scope', name: 'session:exchange' as const },
      },
      defaultUserRoleId: 'native-role',
      identity: { id: 'actual-native-user', primaryEmail: 'native@example.invalid' },
    },
  };
  return Object.freeze({
    public: Object.freeze(publicFixture),
    status: {
      user: { id: 'generic-user', username: 'generic-user' },
      client: { id: 'generic-client', redirectUri: 'https://generic.example/callback' },
      confidentialClient: {
        id: 'confidential-client',
        redirectUri: 'https://generic.example/callback',
      },
      resource: {
        id: 'generic-resource',
        indicator: 'https://generic.example/api',
        scopeName: 'read',
      },
    },
    withSecretLease: async <Result>(
      use: (lease: Phase2FixtureSecretLease) => Promise<Result>
    ): Promise<Result> =>
      use({
        getClientSecret: () => 'unused',
        getStatusClientSecret: () => 'unused',
        getSelectedNativePassword: () => 'private-native-password',
        toJSON: (): never => {
          throw new Error('private');
        },
      }),
  });
};

test('selected Native caller binds actual metadata and returned user before token exchange', async () => {
  const requests: Array<{ url: URL; init: RequestInit }> = [];
  const replies = [
    response(303, undefined, { 'set-cookie': 'interaction=private; Path=/' }),
    response(204),
    response(200, { verificationId: 'verification' }),
    response(204),
    response(200, { redirectTo: 'https://candidate.example/oidc/bridge' }),
    response(303),
    response(200, {}),
    response(200, { redirectTo: 'https://candidate.example/oidc/resume' }),
  ];
  const requestFetch = (async (input: URL | RequestInfo, init?: RequestInit) => {
    const url = new URL(String(input));
    requests.push({ url, init: init ?? {} });
    if (requests.length === 9) {
      const state = requests[0]?.url.searchParams.get('state');
      return response(303, undefined, {
        location: `https://native.example/logto-callback?code=private-code&state=${state}&iss=${encodeURIComponent(expectedIssuer)}`,
      });
    }
    return replies[requests.length - 1] ?? response(500, { private: 'unexpected' });
  }) as typeof fetch;
  const handoff = await stopSelectedNativeAtCallback(
    target,
    selectedFixture(),
    expectedIssuer,
    requestFetch
  );

  expect(requests).toHaveLength(9);
  expect(requests.some(({ url }) => url.pathname === '/oidc/token')).toBe(false);
  expect(requests[0]?.url.searchParams.get('client_id')).toBe('actual-native-client');
  expect(requests[0]?.url.searchParams.get('resource')).toBe('https://native.example/api');
  expect(requests[0]?.url.searchParams.get('scope')).toBe(
    'openid offline_access profile session:exchange'
  );
  expect(JSON.parse(String(requests[2]?.init.body))).toEqual({
    identifier: { type: 'email', value: 'native@example.invalid' },
    password: 'private-native-password',
  });
  expect(handoff.getExpectedSubject()).toBe('actual-native-user');
  expect(handoff.getCallbackUrl()).toContain(`iss=${encodeURIComponent(expectedIssuer)}`);
});

/* eslint-enable @silverhand/fp/no-mutating-methods */
