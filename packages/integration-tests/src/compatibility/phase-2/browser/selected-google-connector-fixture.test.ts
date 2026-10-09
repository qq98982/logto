/* eslint-disable complexity, curly, @typescript-eslint/consistent-type-assertions, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Stateful request fake and hostile descriptors prove connector/SIE/owner lifecycle. */
import { isDeepStrictEqual } from 'node:util';

import { createReferencePhase2AdminRequest, type Phase2AdminRequest } from '../fixtures.js';

import {
  googleSignInButtonSelectorCandidate,
  selectedGoogleOwnerFixtureStageForTesting,
  withSelectedGoogleConnectorFixture,
} from './selected-google-connector-fixture.js';

const fixtureTarget = {
  label: 'oracle' as const,
  coreUrl: 'https://core.example/',
  adminUrl: 'https://admin.example/',
};
const createdMembershipRequest = () =>
  createReferencePhase2AdminRequest(
    fixtureTarget,
    async () => new Response('Created', { status: 201 })
  );

test('pins the source-derived Google button selector candidate pending actual DOM capture', () => {
  expect(googleSignInButtonSelectorCandidate).toBe('role=button[name=/Continue with Google$/]');
});

test('bounds owner-stage aggregate depth and rejects cyclic or accessor-backed errors', () => {
  const known = new TypeError('Selected Google fixture failed: associate');
  let withinBound: unknown = known;
  for (let index = 0; index < 3; index += 1)
    withinBound = new AggregateError([withinBound], 'bounded owner fixture error');
  expect(selectedGoogleOwnerFixtureStageForTesting(withinBound)).toBe('existing-owner-associate');
  const overDeep = new AggregateError([withinBound], 'over-deep owner fixture error');
  expect(selectedGoogleOwnerFixtureStageForTesting(overDeep)).toBeUndefined();
  const cyclic = new AggregateError([], 'cyclic owner fixture error');
  cyclic.errors[0] = cyclic;
  expect(selectedGoogleOwnerFixtureStageForTesting(cyclic)).toBeUndefined();
  let getterCalls = 0;
  const hostile = Object.defineProperty(
    new AggregateError([], 'hostile owner fixture error'),
    'errors',
    {
      get: () => {
        getterCalls += 1;
        throw new Error('private owner value');
      },
    }
  );
  expect(selectedGoogleOwnerFixtureStageForTesting(hostile)).toBeUndefined();
  expect(getterCalls).toBe(0);
});

test('uses the real Created classifier for the role membership response', async () => {
  const target = fixtureTarget;
  const descriptor = {
    method: 'POST' as const,
    path: 'roles/role/users',
    body: { userIds: ['owner'] },
    expectedStatuses: [201],
    responseKind: 'created' as const,
  };
  await expect(
    createReferencePhase2AdminRequest(
      target,
      async () => new Response('Created', { status: 201 })
    )(descriptor)
  ).resolves.toBeUndefined();
  await expect(
    createReferencePhase2AdminRequest(
      target,
      async () => new Response('', { status: 201 })
    )(descriptor)
  ).rejects.toThrow('Phase 2 fixture operation failed');
});

test('binds Google connector and SIE to the immutable existing owner then restores both', async () => {
  let targets = ['github'];
  const previousBranding = { logoUrl: 'https://legacy.invalid/logo.svg' };
  let branding: unknown = previousBranding;
  let selectedBrandingObserved = false;
  let connector = false;
  let user: Record<string, unknown> | undefined;
  let appMetadata: Record<string, unknown> = {
    redirectUris: ['https://old.example/callback'],
    postLogoutRedirectUris: [],
  };
  let roleCreated = false;
  let providerStopped = false;
  let providerProofCalls = 0;
  const membershipRequest = createdMembershipRequest();
  const request = async (input: Phase2AdminRequest): Promise<unknown> => {
    if (input.method === 'GET' && input.path === 'applications/browser')
      return { id: 'browser', type: 'SPA', oidcClientMetadata: appMetadata };
    if (input.method === 'PATCH' && input.path === 'applications/browser') {
      appMetadata = (input.body as { oidcClientMetadata: Record<string, unknown> })
        .oidcClientMetadata;
      return { oidcClientMetadata: appMetadata };
    }
    if (input.method === 'GET' && input.path === 'resources')
      return [{ id: 'resource', scopes: [{ id: 'scope', name: 'read:profile' }] }];
    if (input.method === 'POST' && input.path === 'roles') {
      roleCreated = true;
      return { id: 'role', type: 'User', isDefault: false };
    }
    if (input.method === 'POST' && input.path === 'roles/role/users')
      return membershipRequest(input);
    if (input.method === 'GET' && input.path === 'users/owner/roles') return [{ id: 'role' }];
    if (input.method === 'DELETE' && input.path === 'roles/role') {
      roleCreated = false;
      return undefined;
    }
    if (input.method === 'GET' && input.path === 'sign-in-exp')
      return { branding, socialSignInConnectorTargets: targets };
    if (input.method === 'POST' && input.path === 'connectors') {
      connector = true;
      return { id: 'google-instance', connectorId: 'google-universal' };
    }
    if (input.method === 'PATCH' && input.path === 'sign-in-exp') {
      branding = (input.body as { branding: unknown }).branding;
      targets = [
        ...(input.body as { socialSignInConnectorTargets: string[] }).socialSignInConnectorTargets,
      ];
      if (targets.length === 1 && targets[0] === 'google') {
        selectedBrandingObserved = isDeepStrictEqual(branding, {});
      }
      return { branding, socialSignInConnectorTargets: targets };
    }
    if (input.method === 'POST' && input.path === 'users') {
      user = { id: 'owner', identities: {} };
      return user;
    }
    if (input.method === 'POST' && input.path === 'users/owner/identities') {
      user = { ...user, identities: { google: { userId: 'google-subject' } } };
      return (user as { identities: unknown }).identities;
    }
    if (input.method === 'GET' && input.path === 'users/owner') return user;
    if (input.method === 'DELETE' && input.path === 'users/owner') {
      user = undefined;
      return undefined;
    }
    if (input.method === 'DELETE' && input.path === 'connectors/google-instance') {
      expect(providerStopped).toBe(true);
      connector = false;
      return undefined;
    }
    throw new Error('unexpected request');
  };
  const result = await withSelectedGoogleConnectorFixture({
    fixture: {
      public: { allocationId: 'a' },
      status: { resource: { id: 'resource', scopeName: 'read:profile' } },
    } as never,
    request,
    targetOrigin: 'https://core.example',
    browser: { clientId: 'browser', redirectUri: 'https://core.example/demo-app' },
    clientId: 'client',
    clientSecret: 'private',
    googleSubject: 'google-subject',
    originalEmail: 'owner@example.invalid',
    prepareConnector: async (connectorId) => {
      expect(connectorId).toBe('google-instance');
      return {
        associationData: { code: 'stable-code' },
        assertChangedEmailProviderCase: async () => {
          providerProofCalls += 1;
        },
        stop: async () => {
          providerStopped = true;
        },
      };
    },
    takeBrowserCode: async () => 'changed-code',
    use: async (value) => {
      expect(value.ownerId).toBe('owner');
      await value.assertChangedEmailProviderCase();
      return value.observation().fulfilledOnce;
    },
  });
  expect(result).toBe(false);
  expect(targets).toEqual(['github']);
  expect(branding).toEqual(previousBranding);
  expect(selectedBrandingObserved).toBe(true);
  expect(connector).toBe(false);
  expect(roleCreated).toBe(false);
  expect(appMetadata).toEqual({
    redirectUris: ['https://old.example/callback'],
    postLogoutRedirectUris: [],
  });
  expect(user).toBeUndefined();
  expect(providerProofCalls).toBe(1);
  expect(providerStopped).toBe(true);
});

test.each(['bad-ack', 'transport', 'combined', 'membership-empty', 'provider-stop'] as const)(
  'reports closed SIE cleanup for %s and still deletes the connector',
  async (failure) => {
    let targets = ['github'];
    const previousBranding = { logoUrl: 'https://legacy.invalid/logo.svg' };
    let branding: unknown = previousBranding;
    let connectorDeleted = false;
    let user: Record<string, unknown> | undefined;
    let patchCount = 0;
    const membershipRequest = createReferencePhase2AdminRequest(
      fixtureTarget,
      async () => new Response(failure === 'membership-empty' ? '' : 'Created', { status: 201 })
    );
    let useCalled = false;
    let appMetadata: Record<string, unknown> = {
      redirectUris: ['https://old.example/callback'],
      postLogoutRedirectUris: [],
    };
    const request = async (input: Phase2AdminRequest): Promise<unknown> => {
      if (input.method === 'GET' && input.path === 'applications/browser')
        return { id: 'browser', type: 'SPA', oidcClientMetadata: appMetadata };
      if (input.method === 'PATCH' && input.path === 'applications/browser') {
        appMetadata = (input.body as { oidcClientMetadata: Record<string, unknown> })
          .oidcClientMetadata;
        return { oidcClientMetadata: appMetadata };
      }
      if (input.method === 'GET' && input.path === 'resources')
        return [{ id: 'resource', scopes: [{ id: 'scope', name: 'read:profile' }] }];
      if (input.method === 'POST' && input.path === 'roles')
        return { id: 'role', type: 'User', isDefault: false };
      if (input.method === 'POST' && input.path === 'roles/role/users')
        return membershipRequest(input);
      if (input.method === 'GET' && input.path === 'users/owner/roles') return [{ id: 'role' }];
      if (input.method === 'DELETE' && input.path === 'roles/role') return undefined;
      if (input.method === 'GET' && input.path === 'sign-in-exp')
        return { branding, socialSignInConnectorTargets: targets };
      if (input.method === 'POST' && input.path === 'connectors')
        return { id: 'google-instance', connectorId: 'google-universal' };
      if (input.method === 'PATCH' && input.path === 'sign-in-exp') {
        patchCount += 1;
        if (patchCount === 2 && failure === 'transport') throw new Error('private-restore-token');
        branding = (input.body as { branding: unknown }).branding;
        targets = [
          ...(input.body as { socialSignInConnectorTargets: string[] })
            .socialSignInConnectorTargets,
        ];
        return {
          branding,
          socialSignInConnectorTargets:
            patchCount === 2 && failure !== 'transport' && failure !== 'provider-stop'
              ? ['wrong']
              : targets,
        };
      }
      if (input.method === 'POST' && input.path === 'users') {
        user = { id: 'owner', identities: {} };
        return user;
      }
      if (input.method === 'POST' && input.path === 'users/owner/identities') {
        user = { ...user, identities: { google: { userId: 'google-subject' } } };
        return (user as { identities: unknown }).identities;
      }
      if (input.method === 'GET' && input.path === 'users/owner') return user;
      if (input.method === 'DELETE' && input.path === 'users/owner') {
        user = undefined;
        return undefined;
      }
      if (input.method === 'DELETE' && input.path === 'connectors/google-instance') {
        connectorDeleted = true;
        return undefined;
      }
      throw new Error('private-unexpected');
    };
    const operation = withSelectedGoogleConnectorFixture({
      fixture: {
        public: { allocationId: 'a' },
        status: { resource: { id: 'resource', scopeName: 'read:profile' } },
      } as never,
      request,
      targetOrigin: 'https://core.example',
      browser: { clientId: 'browser', redirectUri: 'https://core.example/demo-app' },
      clientId: 'client',
      clientSecret: 'private',
      googleSubject: 'google-subject',
      originalEmail: 'owner@example.invalid',
      prepareConnector: async () => ({
        associationData: { code: 'stable' },
        assertChangedEmailProviderCase: async () => {
          expect(connectorDeleted).toBe(false);
        },
        stop: async () => {
          if (failure === 'provider-stop') throw new Error('private-provider-stop-token');
        },
      }),
      takeBrowserCode: async () => 'changed',
      use: async (value) => {
        useCalled = true;
        await value.assertChangedEmailProviderCase();
        if (failure === 'combined') throw new Error('private-use-token');
        return null;
      },
    });
    await expect(operation).rejects.toMatchObject({
      message: 'Selected Google connector cleanup failed',
      errors: [
        {
          message: `Selected Google connector fixture failed: ${failure === 'provider-stop' ? 'stop-provider' : 'restore-sie'}`,
        },
        ...(failure === 'combined' || failure === 'membership-empty'
          ? [{ message: 'Selected Google connector fixture failed: existing-owner-use' }]
          : []),
      ],
    });
    await expect(operation).rejects.not.toThrow(
      /private-restore|private-unexpected|private-use|private-provider/u
    );
    expect(connectorDeleted).toBe(true);
    if (failure === 'membership-empty') expect(useCalled).toBe(false);
  }
);
/* eslint-enable complexity, curly, @typescript-eslint/consistent-type-assertions, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
