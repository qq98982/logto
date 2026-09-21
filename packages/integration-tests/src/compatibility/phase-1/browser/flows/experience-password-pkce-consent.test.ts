/* eslint-disable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The focused fake browser records the complete Experience action order and supplies hostile console/state controls. */
import type { JsonObject } from '../../../normalize.js';
import {
  getPhase1FixtureRuntimeEmail,
  getPhase1FixtureRuntimeResourceIndicator,
  getPhase1FixtureRuntimeText,
  getPhase1FixtureRuntimeUsername,
} from '../../fixture-map.js';
import type {
  Phase1BrowserFlowContext,
  Phase1BrowserNetworkFacts,
  Phase1BrowserSession,
  Phase1ProfiledDemoConfiguration,
} from '../contracts.js';

import {
  experiencePasswordPkceConsentFlow,
  experiencePasswordPkceConsentSourcePaths,
} from './experience-password-pkce-consent.js';

const allocationId = 'experience-allocation';
const logical = Object.freeze({
  applicationId: 'phase1-browser',
  resourceId: 'phase1-api',
  scopeId: 'phase1-read-profile',
  subjectId: 'phase1-user',
  username: 'phase1-user',
  email: 'phase1-user@example.com',
  resourceIndicator: 'https://api.example.com',
  resourceName: 'Phase 1 API',
  scopeName: 'read:profile',
});
const runtime = Object.freeze({
  applicationId: 'runtime-browser-client',
  subjectId: 'runtime-subject',
  username: getPhase1FixtureRuntimeUsername(logical.username, allocationId),
  email: getPhase1FixtureRuntimeEmail(logical.email, allocationId),
  resourceIndicator: getPhase1FixtureRuntimeResourceIndicator(
    logical.resourceIndicator,
    allocationId
  ),
  resourceName: getPhase1FixtureRuntimeText(logical.resourceName, allocationId),
  scopeName: getPhase1FixtureRuntimeText(logical.scopeName, allocationId),
});
const password = 'private-experience-password';
const runtimeEffectiveScopes = Object.freeze([
  'openid',
  'offline_access',
  'profile',
  'email',
  'address',
  'phone',
  runtime.scopeName,
]);
const sourcePaths = [
  'packages/demo-app/src/App.tsx',
  'packages/demo-app/src/DevPanel.tsx',
  'packages/demo-app/src/utils.ts',
  'packages/experience/src/apis/consent.ts',
  'packages/experience/src/pages/Consent/index.tsx',
  'packages/integration-tests/src/client/experience/index.ts',
  'packages/integration-tests/src/helpers/experience/index.ts',
  'packages/experience/src/apis/settings.ts',
] as const;

type SessionOptions = Readonly<{
  resourceResult?: unknown;
  userResult?: unknown;
  networkFacts?: Phase1BrowserNetworkFacts;
  offRouteBeforeCredential?: boolean;
  signal?: AbortSignal;
  profileRoute?: string;
}>;

const initialFacts = Object.freeze({
  signIns: Object.freeze([
    Object.freeze({
      authority: 'core' as const,
      status: 303,
      queryShapeExact: true,
      clientId: runtime.applicationId,
      redirectUri: 'https://data.example/demo-app',
      responseType: 'code',
      prompt: 'login consent',
      scope: runtimeEffectiveScopes.join(' '),
      resources: Object.freeze([runtime.resourceIndicator]),
      pkceMethod: 'S256',
      stateFormatValid: true,
      challengeFormatValid: true,
    }),
  ]),
  callbacks: Object.freeze([
    Object.freeze({
      authority: 'core' as const,
      path: '/demo-app' as const,
      status: 200,
      queryShapeExact: true,
      stateMatches: true,
      issuer: 'https://data.example/oidc',
      codePresent: true,
      fragmentEmpty: true,
    }),
  ]),
  endpointDiscoveries: Object.freeze([]),
  exchanges: Object.freeze([
    Object.freeze({
      kind: 'initial' as const,
      authority: 'core' as const,
      status: 200,
      requestShapeExact: true,
      requestCorrelationValid: true,
      clientId: runtime.applicationId,
      redirectUri: 'https://data.example/demo-app',
      initialRefreshPresent: true,
      replacementFresh: true,
      resource: null,
      organizationId: null,
      responseScope: runtimeEffectiveScopes
        .filter((scope) => scope !== runtime.scopeName)
        .join(' '),
      accessKind: 'opaque' as const,
    }),
  ]),
  accountReads: Object.freeze([]),
  applicationReads: Object.freeze([]),
  userReads: Object.freeze([]),
});

class FakeSession implements Phase1BrowserSession {
  readonly records: string[] = [];
  readonly configurations: Phase1ProfiledDemoConfiguration[] = [];
  #route = '/';
  readonly #options: SessionOptions;

  constructor(options: SessionOptions = {}) {
    this.#options = options;
  }

  async preloadDemoConfiguration(
    stepId: string,
    storageKey: string,
    value: Phase1ProfiledDemoConfiguration
  ): Promise<void> {
    this.records.push(`preload:${stepId}:${storageKey}`);
    this.configurations.push(value);
  }

  async navigate(stepId: string, endpoint: 'core' | 'admin', path: string): Promise<void> {
    this.#route = new URL(path, 'https://browser.invalid').pathname;
    this.records.push(`navigate:${stepId}:${endpoint}:${path}`);
  }

  async waitForRoute(
    stepId: string,
    endpoint: 'core' | 'admin',
    paths: readonly string[]
  ): Promise<void> {
    this.#route =
      stepId === 'wait-sign-in'
        ? this.#options.offRouteBeforeCredential
          ? '/foreign'
          : '/sign-in'
        : stepId === 'wait-consent'
          ? '/consent'
          : '/demo-app';
    this.records.push(`wait:${stepId}:${endpoint}:${paths.join('|')}`);
  }

  async waitForExactRoute(stepId: string, endpoint: 'core' | 'admin', path: string): Promise<void> {
    this.#route = path;
    this.records.push(`wait-exact:${stepId}:${endpoint}:${path}`);
  }

  async assertRoute(
    stepId: string,
    endpoint: 'core' | 'admin',
    paths: readonly string[]
  ): Promise<void> {
    this.records.push(`assert:${stepId}:${endpoint}:${paths.join('|')}`);
    if (!paths.includes(this.#route)) {
      throw new Error('Phase 1 browser route is invalid');
    }
  }

  async assertExactRoute(): Promise<void> {
    throw new Error('Unexpected exact route assertion');
  }

  async fill(
    stepId: string,
    selector: string,
    value: string,
    route: Readonly<{ endpoint: 'core' | 'admin'; paths: readonly string[] }>
  ): Promise<void> {
    await this.assertRoute(`${stepId}-route`, route.endpoint, route.paths);
    this.records.push(
      `fill:${stepId}:${selector}:${selector.includes('password') ? '<secret>' : value}`
    );
  }

  async click(
    stepId: string,
    selector: string,
    route?: Readonly<{ endpoint: 'core' | 'admin'; paths: readonly string[] }>
  ): Promise<void> {
    if (route) {
      await this.assertRoute(`${stepId}-route`, route.endpoint, route.paths);
    }
    this.records.push(`click:${stepId}:${selector}`);
  }

  async expectText(stepId: string, selector: string, expected: string): Promise<void> {
    this.records.push(`text:${stepId}:${selector}:${expected}`);
  }

  async expectCount(stepId: string, selector: string, expected: number): Promise<void> {
    this.records.push(`count:${stepId}:${selector}:${expected}`);
  }

  async clickAndObserveObject<Projection extends JsonObject>(
    stepId: string,
    selector: string,
    project: (value: JsonObject) => Projection
  ): Promise<Readonly<Projection>> {
    this.records.push(`observe:${stepId}:${selector}`);
    const value =
      stepId === 'request-resource'
        ? (this.#options.resourceResult ?? resourceResult())
        : (this.#options.userResult ?? userResult());

    return project(value as JsonObject);
  }

  async waitForNetworkFacts(
    stepId: string,
    accept: (facts: Phase1BrowserNetworkFacts) => boolean
  ): Promise<Phase1BrowserNetworkFacts> {
    this.records.push(`network:${stepId}`);
    const facts = this.#options.networkFacts ?? initialFacts;

    if (!accept(facts)) {
      throw new Error('Phase 1 browser network facts are invalid');
    }

    return facts;
  }
}

const resourceResult = (overrides: Readonly<Record<string, unknown>> = {}): JsonObject => ({
  iss: 'https://data.example/oidc',
  sub: runtime.subjectId,
  aud: runtime.resourceIndicator,
  client_id: runtime.applicationId,
  scope: runtime.scopeName,
  iat: 1,
  exp: 2,
  private_raw_claim: 'must-not-escape',
  ...overrides,
});

const userResult = (overrides: Readonly<Record<string, unknown>> = {}): JsonObject => ({
  iss: 'https://data.example/oidc',
  sub: runtime.subjectId,
  aud: runtime.applicationId,
  exp: 2,
  iat: 1,
  username: runtime.username,
  email: runtime.email,
  phone_number: '+15550000000',
  private_raw_profile: 'must-not-escape',
  ...overrides,
});

const profile = Object.freeze({
  fixtures: {
    dataTenant: {
      subject: {
        id: logical.subjectId,
        username: logical.username,
        name: logical.username,
        primaryEmail: logical.email,
      },
      applications: [
        {
          id: logical.applicationId,
          name: 'Phase 1 Consent Client',
          isThirdParty: true,
          oidcClientMetadata: { redirectUris: ['https://data.example/demo-app'] },
        },
      ],
      resource: {
        id: logical.resourceId,
        name: logical.resourceName,
        indicator: logical.resourceIndicator,
        scopes: [
          {
            id: logical.scopeId,
            name: logical.scopeName,
            description: "Read the signed-in user's profile",
          },
        ],
      },
      browserClientConfiguration: {
        route: '/demo-app?app_id=phase1-browser',
        localStorageKey: 'logto:demo-app:dev:config',
        localStorageValue: {
          appId: logical.applicationId,
          prompt: 'login consent',
          scope: 'profile email address phone read:profile',
          resource: logical.resourceIndicator,
        },
        effectiveScopes: [
          'openid',
          'offline_access',
          'profile',
          'email',
          'address',
          'phone',
          logical.scopeName,
        ],
      },
    },
  },
  browserFlows: [
    {
      id: 'experience.password-pkce-consent',
      executionGroup: 'experience',
      sourceEvidence: sourcePaths,
      routes: [
        '/demo-app?app_id=phase1-browser',
        '/oidc/auth',
        '/sign-in',
        '/sign-in/password',
        '/consent',
      ],
      assertions: [],
    },
  ],
});

const fixture = Object.freeze({
  public: {
    schemaVersion: 1,
    recipe: 'fullPhase1',
    allocations: [
      {
        allocationId,
        role: 'data',
        target: 'primary',
        isolation: {
          persistenceId: 'persistence-data',
          cookieKeyId: 'cookie-data',
          signingKeyId: 'signing-data',
        },
        entities: [
          { kind: 'user', logicalId: logical.subjectId, runtimeId: runtime.subjectId },
          {
            kind: 'application',
            logicalId: logical.applicationId,
            runtimeId: runtime.applicationId,
          },
          { kind: 'resource', logicalId: logical.resourceId, runtimeId: 'runtime-resource' },
          { kind: 'scope', logicalId: logical.scopeId, runtimeId: 'runtime-scope' },
        ],
      },
    ],
  },
  withSecretLease: async () => {
    throw new Error('unused');
  },
});

const createHarness = (options: SessionOptions = {}) => {
  const session = new FakeSession(options);
  const activity = ['never', 'never', 'present'] as const;
  let activityIndex = 0;
  const state = Object.freeze({ schemaVersion: 1, recipe: 'fullPhase1', allocations: [] });
  const missingClientSecret: string | undefined = undefined;
  const effectiveProfile =
    options.profileRoute === undefined
      ? profile
      : {
          ...profile,
          fixtures: {
            ...profile.fixtures,
            dataTenant: {
              ...profile.fixtures.dataTenant,
              browserClientConfiguration: {
                ...profile.fixtures.dataTenant.browserClientConfiguration,
                route: options.profileRoute,
              },
            },
          },
        };
  const context: Phase1BrowserFlowContext = {
    profile: effectiveProfile as never,
    target: {
      label: 'candidate',
      coreUrl: 'https://data.example/',
      adminUrl: 'https://admin.example/',
    },
    fixture: fixture as never,
    lease: {
      getPassword: (logicalId: string) => {
        expect(logicalId).toBe(logical.subjectId);
        return password;
      },
      getClientSecret: () => missingClientSecret,
      toJSON: () => {
        throw new TypeError('secret');
      },
    },
    session,
    readActivityState: async (logicalId: string) => {
      expect(logicalId).toBe(logical.subjectId);
      const lastSignInState = activity[Math.min(activityIndex, activity.length - 1)]!;
      activityIndex += 1;
      return { lastSignInState };
    },
    projectState: async () => state as never,
    signal: options.signal ?? new AbortController().signal,
  };

  return { context, session };
};

describe('experience.password-pkce-consent browser flow', () => {
  it('resolves runtime values, follows the fixed browser order, and emits closed evidence', async () => {
    const { context, session } = createHarness();
    const result = await experiencePasswordPkceConsentFlow.run(context);

    expect(session.configurations).toEqual([
      {
        appId: runtime.applicationId,
        prompt: 'login consent',
        scope: `profile email address phone ${runtime.scopeName}`,
        resource: runtime.resourceIndicator,
      },
    ]);
    expect(session.records).toEqual([
      'preload:preload-demo:logto:demo-app:dev:config',
      'navigate:open-demo:core:/demo-app',
      'wait:wait-sign-in:core:/sign-in|/sign-in/password',
      'assert:fill-username-route:core:/sign-in|/sign-in/password',
      `fill:fill-username:input[name="identifier"]:${runtime.username}`,
      'assert:fill-password-route:core:/sign-in|/sign-in/password',
      'fill:fill-password:input[name="password"]:<secret>',
      'assert:submit-sign-in-route:core:/sign-in|/sign-in/password',
      'click:submit-sign-in:button[name="submit"]',
      'wait:wait-consent:core:/consent',
      `text:consent-user:text=${JSON.stringify(logical.username)}:${logical.username}`,
      `text:consent-email:text=${JSON.stringify(runtime.email)}:${runtime.email}`,
      'text:consent-user-group:text="User Scopes":User Scopes',
      `text:consent-resource-group:text=${JSON.stringify(runtime.resourceName)}:${runtime.resourceName}`,
      'assert:expand-user-scopes-route:core:/consent',
      'click:expand-user-scopes:role=button[name="User Scopes"]',
      'assert:expand-resource-scopes-route:core:/consent',
      `click:expand-resource-scopes:role=button[name=${JSON.stringify(runtime.resourceName)}]`,
      'count:consent-user-scope-count:role=button[name="User Scopes"] >> xpath=following-sibling::ul/li:4',
      `count:consent-resource-scope-count:role=button[name=${JSON.stringify(runtime.resourceName)}] >> xpath=following-sibling::ul/li:1`,
      'text:consent-profile-scope:text="Your name, username, avatar, and other profile info":Your name, username, avatar, and other profile info',
      'text:consent-email-scope:text="Your email address":Your email address',
      'text:consent-address-scope:text="Your address":Your address',
      'text:consent-phone-scope:text="Your phone number":Your phone number',
      'text:consent-resource-scope:text="Read the signed-in user\'s profile":Read the signed-in user\'s profile',
      'assert:authorize-consent-route:core:/consent',
      'click:authorize-consent:role=button[name="Authorize"]',
      'wait-exact:wait-demo-callback:core:/demo-app',
      'network:callback-exchange',
      'assert:open-dev-panel-route:core:/demo-app',
      'click:open-dev-panel:role=button[name="Open dev panel"]',
      'assert:fill-resource-route:core:/demo-app',
      `fill:fill-resource:form:has-text("Refresh token grant") input[name="resource"]:${runtime.resourceIndicator}`,
      'assert:request-resource:core:/demo-app',
      'observe:request-resource:role=button[name="Request token"]',
      'assert:fetch-user:core:/demo-app',
      'observe:fetch-user:role=button[name="Fetch user info"]',
    ]);
    expect(result).toEqual({
      activity: { lastSignInState: 'present' },
      callback: { completed: true, path: '/demo-app' },
      consent: {
        application: logical.applicationId,
        permissions: ['profile', 'email', 'address', 'phone'],
        resource: {
          indicator: logical.resourceIndicator,
          permissions: [logical.scopeName],
        },
        subject: logical.subjectId,
      },
      fixture: { stable: true },
      resourceGrant: {
        client: logical.applicationId,
        format: 'decoded-compact',
        issuer: 'data',
        permission: logical.scopeName,
        resource: logical.resourceIndicator,
        subject: logical.subjectId,
      },
      userProfile: {
        email: logical.email,
        subject: logical.subjectId,
        username: logical.username,
      },
    });
    const serialized = JSON.stringify(result);
    for (const forbidden of [
      password,
      runtime.applicationId,
      runtime.subjectId,
      runtime.username,
      runtime.email,
      runtime.resourceIndicator,
      runtime.scopeName,
      'must-not-escape',
    ]) {
      expect(serialized).not.toContain(forbidden);
    }
    expect(Object.keys(result).join(' ')).not.toMatch(/token|jwt|auth|password|cookie/iu);
  });

  it.each([
    ['wrong audience', resourceResult({ aud: 'https://wrong.example' })],
    ['wrong scope', resourceResult({ scope: 'wrong:scope' })],
    ['wrong subject', resourceResult({ sub: 'wrong-subject' })],
    ['string result', 'private-raw-token'],
  ] as const)('rejects a resource console object with %s', async (_name, resourceResult) => {
    const { context } = createHarness({ resourceResult });

    await expect(experiencePasswordPkceConsentFlow.run(context)).rejects.toThrow(
      'Phase 1 Experience resource result is invalid'
    );
  });

  it('rejects the wrong UserInfo subject', async () => {
    const { context } = createHarness({ userResult: userResult({ sub: 'wrong-subject' }) });

    await expect(experiencePasswordPkceConsentFlow.run(context)).rejects.toThrow(
      'Phase 1 Experience user result is invalid'
    );
  });

  it.each([
    [
      'a non-canonical sign-in query',
      { ...initialFacts, signIns: [{ ...initialFacts.signIns[0]!, queryShapeExact: false }] },
    ],
    [
      'a callback state mismatch',
      { ...initialFacts, callbacks: [{ ...initialFacts.callbacks[0]!, stateMatches: false }] },
    ],
    [
      'an uncorrelated code exchange',
      {
        ...initialFacts,
        exchanges: [{ ...initialFacts.exchanges[0]!, requestCorrelationValid: false }],
      },
    ],
    [
      'an initial response containing the resource-only scope',
      {
        ...initialFacts,
        exchanges: [
          {
            ...initialFacts.exchanges[0]!,
            responseScope: runtimeEffectiveScopes.join(' '),
          },
        ],
      },
    ],
  ] as const)('rejects %s in the browser authorization chain', async (_name, networkFacts) => {
    const { context } = createHarness({ networkFacts });

    await expect(experiencePasswordPkceConsentFlow.run(context)).rejects.toThrow(
      'Phase 1 Experience browser authorization chain is invalid'
    );
  });

  it('fails before entering a fixture credential on an off-route page', async () => {
    const { context, session } = createHarness({ offRouteBeforeCredential: true });

    await expect(experiencePasswordPkceConsentFlow.run(context)).rejects.toThrow(
      'Phase 1 browser route is invalid'
    );
    expect(session.records.some((record) => record.includes('<secret>'))).toBe(false);
    expect(session.records.some((record) => record.startsWith('click:'))).toBe(false);
  });

  it.each([
    ['a mismatched app ID', '/demo-app?app_id=another-application'],
    ['an extra forwarded parameter', '/demo-app?app_id=phase1-browser&unexpected=value'],
    ['an empty app ID query', '/demo-app?app_id='],
  ])('rejects %s in the profiled demo route', async (_name, profileRoute) => {
    const { context, session } = createHarness({ profileRoute });

    await expect(experiencePasswordPkceConsentFlow.run(context)).rejects.toThrow(
      'Phase 1 Experience browser profile is invalid'
    );
    expect(session.records).toEqual([]);
  });

  it('stops activity convergence when the group signal is aborted', async () => {
    const controller = new AbortController();
    controller.abort();
    const { context } = createHarness({ signal: controller.signal });

    await expect(experiencePasswordPkceConsentFlow.run(context)).rejects.toThrow(
      'Phase 1 Experience activity state is invalid'
    );
  });

  it('exports the exact profile source paths', () => {
    expect(experiencePasswordPkceConsentSourcePaths).toEqual(sourcePaths);
    expect(experiencePasswordPkceConsentFlow).toMatchObject({
      id: 'experience.password-pkce-consent',
      executionGroup: 'experience',
      sourcePaths,
    });
  });
});

/* eslint-enable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
