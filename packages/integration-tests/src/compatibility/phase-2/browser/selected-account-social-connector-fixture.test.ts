/* eslint-disable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions -- The fixture fakes record compensated Management state. */
import {
  getPhase2FixtureFailureOperation,
  withPhase2FixtureOperationDiagnostic,
} from '../fixture-operation-diagnostic.js';
import type {
  Phase2AdminRequest,
  Phase2AdminRequestFunction,
  ProvisionedPhase2Fixture,
} from '../fixtures.js';

import { withSelectedAccountSocialConnector } from './selected-account-social-connector-fixture.js';

test('removes the owned connector and restores social targets when provider preparation fails', async () => {
  const calls: string[] = [];
  const request: Phase2AdminRequestFunction = async (input) => {
    calls.push(`${input.method} ${input.path}`);
    if (input.method === 'GET') {
      return { socialSignInConnectorTargets: ['github'] };
    }
    if (input.method === 'POST') {
      return { id: 'connector', connectorId: 'google-universal' };
    }
    return input.responseKind === 'status' ? 204 : { socialSignInConnectorTargets: ['github'] };
  };
  await expect(
    withSelectedAccountSocialConnector({
      fixture: { public: { allocationId: 'fixture' } } as ProvisionedPhase2Fixture,
      request,
      browser: { clientId: 'client', redirectUri: 'https://app.example/callback' },
      callbackOrigin: 'https://core.example/',
      provider: 'google',
      connectorConfig: { clientId: 'owned', clientSecret: 'private' },
      getPassword: () => 'private',
      prepareProvider: async () => {
        throw new TypeError('provider unavailable');
      },
      use: async () => true,
    })
  ).rejects.toThrow('Selected Account social connector fixture failed');
  expect(calls).toEqual([
    'GET sign-in-exp',
    'POST connectors',
    'PATCH sign-in-exp',
    'DELETE connectors/connector',
  ]);
});

test('retains a real provider preparation operation through connector cleanup replacement', async () => {
  // eslint-disable-next-line unicorn/consistent-function-scoping -- This request belongs only to the diagnostic fixture below.
  const request: Phase2AdminRequestFunction = async (input) => {
    if (input.method === 'GET') {
      return { socialSignInConnectorTargets: ['github'] };
    }
    if (input.method === 'POST') {
      return { id: 'connector' };
    }
    return input.responseKind === 'status' ? 204 : { socialSignInConnectorTargets: ['github'] };
  };
  const failure = withPhase2FixtureOperationDiagnostic(async (diagnostic) =>
    withSelectedAccountSocialConnector({
      fixture: { public: { allocationId: 'fixture' } } as ProvisionedPhase2Fixture,
      request,
      browser: { clientId: 'client', redirectUri: 'https://app.example/callback' },
      callbackOrigin: 'https://core.example/',
      provider: 'google',
      connectorConfig: {},
      getPassword: () => 'private',
      operationDiagnostic: diagnostic,
      prepareProvider: async () => {
        throw new Error('private provider failure');
      },
      use: async () => true,
    })
  );
  let error: unknown;
  try {
    await failure;
  } catch (error_: unknown) {
    error = error_;
  }
  expect(error).toBeInstanceOf(AggregateError);
  expect(getPhase2FixtureFailureOperation(error)).toBe('connector-provider-prepare');
});

test('registers the core social callback with the browser application and restores metadata', async () => {
  const applicationPatches: Phase2AdminRequest[] = [];
  let methods: unknown = [
    { identifier: 'username', password: true, verificationCode: false, isPasswordPrimary: true },
  ];
  let branding: unknown = {};
  let targets: unknown = ['github'];
  let accountCenter = { enabled: false, fields: { social: 'ReadOnly' } };
  let metadata = {
    redirectUris: ['https://app.example/demo-app'],
    postLogoutRedirectUris: ['https://app.example/logout'],
  };
  const request: Phase2AdminRequestFunction = async (input) => {
    if (input.path === 'sign-in-exp' && input.method === 'GET') {
      return { signIn: { methods }, branding, socialSignInConnectorTargets: targets };
    }
    if (input.path === 'sign-in-exp') {
      const body = input.body as Record<string, unknown>;
      if ('socialSignInConnectorTargets' in body) {
        targets = body.socialSignInConnectorTargets;
      }
      if ('signIn' in body) {
        methods = (body.signIn as { methods: unknown }).methods;
        branding = body.branding;
      }
      return { signIn: { methods }, branding, socialSignInConnectorTargets: targets };
    }
    if (input.path === 'account-center' && input.method === 'GET') {
      return accountCenter;
    }
    if (input.path === 'account-center') {
      accountCenter = input.body as typeof accountCenter;
      return accountCenter;
    }
    if (input.path === 'connectors' && input.method === 'POST') {
      return { id: 'connector', connectorId: 'google-universal' };
    }
    if (input.path === 'connectors/connector') {
      return 204;
    }
    if (input.path === 'applications/client' && input.method === 'GET') {
      return { id: 'client', type: 'SPA', oidcClientMetadata: metadata };
    }
    if (input.path === 'applications/client') {
      applicationPatches.push(input);
      metadata = (input.body as { oidcClientMetadata: typeof metadata }).oidcClientMetadata;
      return { id: 'client', type: 'SPA', oidcClientMetadata: metadata };
    }
    throw new TypeError('unexpected fixture request');
  };
  let stopped = false;
  await expect(
    withSelectedAccountSocialConnector({
      fixture: { public: { allocationId: 'fixture' } } as ProvisionedPhase2Fixture,
      request,
      browser: { clientId: 'client', redirectUri: 'https://app.example/demo-app' },
      callbackOrigin: 'https://core.example/',
      provider: 'google',
      connectorConfig: { clientId: 'owned', clientSecret: 'private' },
      getPassword: () => 'private',
      prepareProvider: async () => ({
        associationData: {},
        takeAccountCode: async () => 'private',
        takeForeignAccountCode: async () => 'private',
        assertAccountProviderCase: async () => {
          await Promise.resolve();
        },
        stop: async () => {
          stopped = true;
        },
      }),
      use: async () => true,
    })
  ).rejects.toThrow('Selected Account social connector fixture failed');
  expect(applicationPatches.map(({ body }) => body)).toEqual([
    {
      oidcClientMetadata: {
        redirectUris: ['https://app.example/demo-app', 'https://core.example/callback/connector'],
        postLogoutRedirectUris: ['https://app.example/logout'],
      },
    },
    {
      oidcClientMetadata: {
        redirectUris: ['https://app.example/demo-app'],
        postLogoutRedirectUris: ['https://app.example/logout'],
      },
    },
  ]);
  expect(metadata).toEqual({
    redirectUris: ['https://app.example/demo-app'],
    postLogoutRedirectUris: ['https://app.example/logout'],
  });
  expect(stopped).toBe(true);
});
/* eslint-enable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions */
