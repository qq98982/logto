/* eslint-disable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-empty-function -- Closed fake ports prove orchestration and lease lifetime. */
import type {
  Phase1BrowserNetworkFacts,
  Phase1BrowserSession,
} from '../../phase-1/browser/contracts.js';
import type { Phase2AdminRequest, ProvisionedPhase2Fixture } from '../fixtures.js';

import { runCommonEmailPasswordScenario } from './common-email-password-runner.js';

test('keeps credentials inside one lease and executes real control requests in order', async () => {
  const actions: string[] = [];
  const suspensionRequests: Phase2AdminRequest[] = [];
  let active = false;
  let methods: unknown = [{ identifier: 'username' }];
  let branding: unknown = {};
  let applicationMetadata = {
    redirectUris: ['http://localhost:3001/demo-app'],
    postLogoutRedirectUris: [] as string[],
  };
  const managementRequest = async (request: Phase2AdminRequest) => {
    actions.push(`management:${request.method}:${request.path}`);
    if (request.path === 'applications/app' && request.method === 'GET') {
      return { id: 'app', type: 'SPA', oidcClientMetadata: applicationMetadata };
    }
    if (request.path === 'applications/app') {
      applicationMetadata = (request.body as { oidcClientMetadata: typeof applicationMetadata })
        .oidcClientMetadata;
      return { id: 'app', type: 'SPA', oidcClientMetadata: applicationMetadata };
    }
    if (request.path === 'resources' && request.query?.includeScopes === 'true') {
      return [{ id: 'resource', scopes: [{ id: 'scope', name: 'read:profile' }] }];
    }
    if (request.path === 'roles' && request.method === 'POST') {
      return { id: 'email-role', name: 'common-email-allocation', type: 'User', isDefault: false };
    }
    if (request.path === 'roles/email-role/scopes') {
      return [{ id: 'scope', name: 'read:profile', resourceId: 'resource' }];
    }
    if (request.path === 'roles/email-role/users') {
      return 201;
    }
    if (request.path === 'users/email-user/roles') {
      return [{ id: 'email-role', type: 'User' }];
    }
    if (request.method === 'GET') {
      return { signIn: { methods }, branding };
    }
    if (request.path === 'sign-in-exp') {
      methods = (request.body as { signIn: { methods: unknown } }).signIn.methods;
      branding = (request.body as { branding: unknown }).branding;
      return { signIn: { methods }, branding };
    }
    if (request.method === 'POST') {
      return {
        id: 'email-user',
        primaryEmail: 'common-email-allocation@example.invalid',
        hasPassword: true,
        isSuspended: false,
      };
    }
    if (request.path === 'users/email-user/is-suspended') {
      suspensionRequests.push(request);
      return {
        id: 'email-user',
        isSuspended: (request.body as { isSuspended: boolean }).isSuspended,
      };
    }
    return 204;
  };
  const facts: Phase1BrowserNetworkFacts = {
    signIns: [
      {
        authority: 'core',
        status: 303,
        queryShapeExact: true,
        clientId: 'app',
        redirectUri: 'https://core.example/demo-app',
        responseType: 'code',
        prompt: 'consent',
        scope: 'openid profile offline_access',
        resources: ['https://api.example'],
        pkceMethod: 'S256',
        stateFormatValid: true,
        challengeFormatValid: true,
      },
    ],
    callbacks: [
      {
        authority: 'core',
        path: '/demo-app',
        status: 200,
        queryShapeExact: true,
        stateMatches: true,
        issuer: 'https://core.example/oidc',
        codePresent: true,
        fragmentEmpty: true,
      },
    ],
    exchanges: [
      {
        kind: 'initial',
        authority: 'core',
        status: 200,
        requestShapeExact: true,
        requestCorrelationValid: true,
        clientId: 'app',
        redirectUri: 'https://core.example/demo-app',
        initialRefreshPresent: true,
        replacementFresh: true,
        resource: null,
        organizationId: null,
        responseScope: 'openid profile offline_access',
        accessKind: 'opaque',
      },
    ],
    endpointDiscoveries: [],
    accountReads: [],
    applicationReads: [],
    userReads: [],
  };
  const refreshed: Phase1BrowserNetworkFacts = {
    ...facts,
    exchanges: [
      ...facts.exchanges,
      {
        kind: 'management',
        authority: 'core',
        status: 200,
        requestShapeExact: true,
        requestCorrelationValid: true,
        clientId: 'app',
        redirectUri: null,
        initialRefreshPresent: false,
        replacementFresh: true,
        resource: 'https://api.example',
        organizationId: null,
        responseScope: 'read:profile',
        accessKind: 'compact',
        compactAccess: {
          issuer: 'https://core.example/oidc',
          subject: 'email-user',
          audience: 'https://api.example',
          clientId: 'app',
          scope: 'read:profile',
          organizationIdPresent: false,
        },
      },
    ],
  };
  let factReads = 0;
  const session = {
    preloadDemoConfiguration: async () => {},
    navigate: async () => {},
    waitForRoute: async () => {},
    waitForExactRoute: async () => {},
    assertRoute: async () => {},
    assertExactRoute: async () => {},
    fill: async () => {},
    click: async () => {},
    expectText: async () => {},
    expectCount: async () => {},
    waitForNetworkFacts: async () => (factReads++ < 2 ? facts : refreshed),
    clickAndObserveObject: async (
      _step: string,
      _selector: string,
      project: (body: Record<string, unknown>) => Record<string, unknown>
    ) =>
      project({
        sub: 'email-user',
        email: 'common-email-allocation@example.invalid',
        email_verified: true,
      }),
  } as Phase1BrowserSession;
  const result = await runCommonEmailPasswordScenario({
    fixture: {
      public: { allocationId: 'allocation' },
      status: {
        user: { id: 'existing-subject', username: 'existing-user' },
        client: { id: 'app', redirectUri: 'https://core.example/demo-app' },
        confidentialClient: { id: 'confidential', redirectUri: 'https://core.example/demo-app' },
        resource: {
          id: 'resource',
          indicator: 'https://api.example',
          scopeName: 'read:profile',
        },
      },
    } as ProvisionedPhase2Fixture,
    managementRequest,
    session,
    configuration: {
      storageKey: 'config',
      demo: {
        appId: 'app',
        prompt: 'consent',
        scope: 'openid profile offline_access',
        resource: 'https://api.example',
      },
      expectedIssuer: 'https://core.example/oidc',
      redirectUri: 'https://core.example/demo-app',
      initialResponseScope: 'openid profile offline_access',
      resourceScope: 'read:profile',
    },
    preservedUsername: { identifier: 'existing-user', subject: 'existing-subject' },
    withCredentialLease: async (use) => {
      active = true;
      try {
        return await use({
          getSelectedEmailPassword: () => (active ? 'selected-secret' : ''),
          getInvalidEmailPassword: () => (active ? 'wrong-secret' : ''),
          getPreservedUsernamePassword: () => (active ? 'existing-secret' : ''),
        });
      } finally {
        active = false;
      }
    },
    createControlDriver: (identity) => {
      expect(identity.id).toBe('email-user');
      return {
        assertInvalidPassword: async (identifier) => {
          actions.push(`invalid:${identifier}`);
        },
        assertSuspended: async (identifier) => {
          actions.push(`suspended:${identifier}`);
        },
        authenticateUsername: async (identifier) => {
          actions.push(`username:${identifier}`);
          return 'existing-subject';
        },
      };
    },
  });
  expect(result.usernamePreserved).toBe(true);
  expect(actions).toContain('management:PATCH:users/email-user/is-suspended');
  expect(suspensionRequests).toHaveLength(2);
  expect(suspensionRequests.every(({ expectedStatuses }) => expectedStatuses[0] === 200)).toBe(
    true
  );
  expect(suspensionRequests.every(({ responseKind }) => responseKind === 'object')).toBe(true);
  expect(actions).toContain('management:DELETE:users/email-user');
  expect(applicationMetadata.redirectUris).toEqual(['http://localhost:3001/demo-app']);
  expect(active).toBe(false);
});
/* eslint-enable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-empty-function */
