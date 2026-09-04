/* eslint-disable @typescript-eslint/consistent-type-assertions, @typescript-eslint/array-type, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, import/order, max-lines, unicorn/no-useless-undefined -- Focused browser-flow fakes retain ordered calls and apply isolated fact/state mutations. */
import type { TargetConfig } from '../../../model.js';
import type { JsonObject } from '../../../normalize.js';
import type {
  Phase1FixtureSecretLease,
  ProvisionedPhase1Fixture,
  SemanticStateProjection,
} from '../../fixtures.js';
import {
  getPhase1FixtureRuntimeEmail,
  getPhase1FixtureRuntimeText,
  getPhase1FixtureRuntimeUsername,
} from '../../fixture-map.js';
import type { Phase1Profile } from '../../profile-types.js';
import type {
  Phase1BrowserFlowContext,
  Phase1BrowserNetworkFacts,
  Phase1BrowserSession,
} from '../contracts.js';

import {
  consoleApplicationReadFlow,
  consoleApplicationReadSourcePaths,
} from './console-application-read.js';
import {
  consoleCleanAuthenticationFlow,
  consoleCleanAuthenticationSourcePaths,
} from './console-clean-authentication.js';
import { consoleUserReadFlow, consoleUserReadSourcePaths } from './console-user-read.js';

const target = Object.freeze({
  label: 'oracle',
  coreUrl: 'http://localhost:3001/',
  adminUrl: 'http://localhost:3002/',
}) satisfies TargetConfig;
const adminAllocationId = 'admin-allocation';
const dataAllocationId = 'data-allocation';
const runtime = Object.freeze({
  adminId: 'runtime-admin-id',
  adminUsername: getPhase1FixtureRuntimeUsername('phase1-admin', adminAllocationId),
  adminEmail: getPhase1FixtureRuntimeEmail('phase1-admin@example.com', adminAllocationId),
  firstPartyId: 'runtime-first-party-id',
  firstPartyName: getPhase1FixtureRuntimeText('Phase 1 Application', dataAllocationId),
  thirdPartyId: 'runtime-third-party-id',
  thirdPartyName: getPhase1FixtureRuntimeText('Phase 1 Consent Client', dataAllocationId),
  userId: 'runtime-user-id',
  userUsername: getPhase1FixtureRuntimeUsername('phase1-user', dataAllocationId),
  userEmail: getPhase1FixtureRuntimeEmail('phase1-user@example.com', dataAllocationId),
});
const requestedScope =
  'openid offline_access profile email phone identities custom_data urn:logto:scope:organizations urn:logto:scope:organization_roles all';
const initialResponseScope =
  'openid offline_access profile email phone identities custom_data urn:logto:scope:organizations urn:logto:scope:organization_roles';

const profile = {
  fixtures: {
    adminTenant: {
      operator: {
        id: 'phase1-admin',
        username: 'phase1-admin',
        primaryEmail: 'phase1-admin@example.com',
      },
      tenantOrganization: { id: 't-default' },
    },
    dataTenant: {
      subject: {
        id: 'phase1-user',
        username: 'phase1-user',
        name: 'phase1-user',
        primaryEmail: 'phase1-user@example.com',
      },
      applications: [
        {
          id: 'phase1-app',
          name: 'Phase 1 Application',
          isThirdParty: false,
        },
        {
          id: 'phase1-browser',
          name: 'Phase 1 Consent Client',
          isThirdParty: true,
        },
      ],
    },
  },
  consoleAuthentication: {
    applicationId: 'admin-console',
    prompt: ['login', 'consent'],
    configuredResources: ['https://default.logto.app/api', 'https://admin.logto.app/me'],
    effectiveResources: [
      'https://default.logto.app/api',
      'https://admin.logto.app/me',
      'urn:logto:resource:organizations',
    ],
    effectiveScopes: requestedScope.split(' '),
  },
  browserFlows: [
    {
      id: 'console.clean-authentication',
      executionGroup: 'console',
      startRoute: '/console/applications',
      postAuthenticationRoute: '/console/applications',
      sourceEvidence: consoleCleanAuthenticationSourcePaths,
      routes: [],
      assertions: [],
    },
    {
      id: 'console.application-read',
      executionGroup: 'console',
      sourceEvidence: consoleApplicationReadSourcePaths,
      routes: ['/console/applications', '/console/applications/third-party-applications'],
      assertions: [],
    },
    {
      id: 'console.user-read',
      executionGroup: 'console',
      sourceEvidence: consoleUserReadSourcePaths,
      routes: ['/console/users'],
      assertions: [],
    },
  ],
} as unknown as Phase1Profile;

const fixture = {
  public: {
    recipe: 'fullPhase1',
    allocations: [
      {
        allocationId: adminAllocationId,
        role: 'admin',
        target: 'primary',
        isolation: {},
        entities: [{ kind: 'user', logicalId: 'phase1-admin', runtimeId: runtime.adminId }],
      },
      {
        allocationId: dataAllocationId,
        role: 'data',
        target: 'primary',
        isolation: {},
        entities: [
          { kind: 'user', logicalId: 'phase1-user', runtimeId: runtime.userId },
          { kind: 'application', logicalId: 'phase1-app', runtimeId: runtime.firstPartyId },
          {
            kind: 'application',
            logicalId: 'phase1-browser',
            runtimeId: runtime.thirdPartyId,
          },
        ],
      },
    ],
  },
} as unknown as ProvisionedPhase1Fixture;

const initialFact = Object.freeze({
  kind: 'initial' as const,
  authority: 'admin' as const,
  status: 200,
  requestShapeExact: true,
  requestCorrelationValid: true,
  clientId: 'admin-console',
  redirectUri: 'http://localhost:3002/console/callback',
  initialRefreshPresent: true,
  replacementFresh: true,
  resource: null,
  organizationId: null,
  responseScope: initialResponseScope,
  accessKind: 'opaque' as const,
});
const managementFact = Object.freeze({
  kind: 'management' as const,
  authority: 'admin' as const,
  status: 200,
  requestShapeExact: true,
  requestCorrelationValid: true,
  clientId: 'admin-console',
  redirectUri: null,
  initialRefreshPresent: false,
  replacementFresh: true,
  resource: profile.consoleAuthentication.configuredResources[0]!,
  organizationId: null,
  responseScope: 'all',
  accessKind: 'compact' as const,
  compactAccess: Object.freeze({
    issuer: 'http://localhost:3002/oidc',
    subject: runtime.adminId,
    audience: profile.consoleAuthentication.configuredResources[0]!,
    clientId: 'admin-console',
    scope: 'all',
    organizationIdPresent: false,
  }),
});
const organizationFact = Object.freeze({
  kind: 'organization' as const,
  authority: 'admin' as const,
  status: 200,
  requestShapeExact: true,
  requestCorrelationValid: true,
  clientId: 'admin-console',
  redirectUri: null,
  initialRefreshPresent: false,
  replacementFresh: true,
  resource: null,
  organizationId: 't-default',
  responseScope: '',
  accessKind: 'compact' as const,
  compactAccess: Object.freeze({
    issuer: 'http://localhost:3002/oidc',
    subject: runtime.adminId,
    audience: 'urn:logto:organization:t-default',
    clientId: 'admin-console',
    scope: '',
    organizationIdPresent: false,
  }),
});
const accountFact = Object.freeze({
  authority: 'admin' as const,
  status: 200,
  queryShapeExact: true,
  accessMatchesInitial: true,
  id: runtime.adminId,
  username: runtime.adminUsername,
  primaryEmail: runtime.adminEmail,
});
const signInFact = Object.freeze({
  authority: 'admin' as const,
  status: 303,
  queryShapeExact: true,
  clientId: 'admin-console',
  redirectUri: 'http://localhost:3002/console/callback',
  responseType: 'code',
  prompt: 'login consent',
  scope: profile.consoleAuthentication.effectiveScopes.join(' '),
  resources: Object.freeze([...profile.consoleAuthentication.effectiveResources]),
  pkceMethod: 'S256',
  stateFormatValid: true,
  challengeFormatValid: true,
});
const callbackFact = Object.freeze({
  authority: 'admin' as const,
  path: '/console/callback' as const,
  status: 200,
  queryShapeExact: true,
  stateMatches: true,
  issuer: 'http://localhost:3002/oidc',
  codePresent: true,
  fragmentEmpty: true,
});
const endpointDiscoveryFact = Object.freeze({
  authority: 'admin' as const,
  status: 200,
  queryShapeExact: true,
  accessAbsent: true,
  userOriginMatchesCore: true,
});
const applicationFacts = Object.freeze([
  Object.freeze({
    authority: 'core' as const,
    status: 200,
    queryShapeExact: true,
    originMatches: true,
    languageMatches: true,
    accessMatchesManagement: true,
    isThirdParty: false,
    isSamlProbe: false,
    total: 1,
    rows: Object.freeze([{ id: runtime.firstPartyId, name: runtime.firstPartyName }]),
  }),
  Object.freeze({
    authority: 'core' as const,
    status: 200,
    queryShapeExact: true,
    originMatches: true,
    languageMatches: true,
    accessMatchesManagement: true,
    isThirdParty: true,
    isSamlProbe: false,
    total: 1,
    rows: Object.freeze([{ id: runtime.thirdPartyId, name: runtime.thirdPartyName }]),
  }),
  Object.freeze({
    authority: 'core' as const,
    status: 200,
    queryShapeExact: true,
    originMatches: true,
    languageMatches: true,
    accessMatchesManagement: true,
    isThirdParty: false,
    isSamlProbe: true,
    total: 0,
    rows: Object.freeze([]),
  }),
]);
const userFact = Object.freeze({
  authority: 'core' as const,
  status: 200,
  queryShapeExact: true,
  originMatches: true,
  languageMatches: true,
  accessMatchesManagement: true,
  total: 1,
  rows: Object.freeze([
    Object.freeze({
      id: runtime.userId,
      name: 'phase1-user',
      username: runtime.userUsername,
      primaryEmail: runtime.userEmail,
      lastSignInState: 'never' as const,
    }),
  ]),
});

const emptyFacts = (): Phase1BrowserNetworkFacts => ({
  signIns: [],
  callbacks: [],
  endpointDiscoveries: [],
  exchanges: [],
  accountReads: [],
  applicationReads: [],
  userReads: [],
});
const authorizationFacts = Object.freeze({
  signIns: Object.freeze([signInFact]),
  callbacks: Object.freeze([callbackFact]),
  endpointDiscoveries: Object.freeze([endpointDiscoveryFact]),
});

class FakeSession implements Phase1BrowserSession {
  readonly calls: string[] = [];
  readonly #textSets: readonly ReadonlyMap<string, string>[];
  #textSetIndex = 0;
  #route: string;
  readonly #postAuthenticationRoute: string;

  constructor(
    readonly facts: Phase1BrowserNetworkFacts,
    input: Readonly<{
      route?: string;
      postAuthenticationRoute?: string;
      textSets?: readonly Readonly<Record<string, string>>[];
    }> = {}
  ) {
    this.#route = input.route ?? '/sign-in';
    this.#postAuthenticationRoute = input.postAuthenticationRoute ?? '/console/applications';
    this.#textSets = (input.textSets ?? []).map((texts) => new Map(Object.entries(texts)));
  }

  async preloadDemoConfiguration(): Promise<void> {
    throw new Error('Unexpected demo configuration');
  }

  async navigate(stepId: string, endpoint: 'core' | 'admin', path: string): Promise<void> {
    this.calls.push(`navigate:${stepId}:${endpoint}:${path}`);
    this.#route = path === '/console/applications' ? '/sign-in' : path;
  }

  async waitForRoute(
    stepId: string,
    endpoint: 'core' | 'admin',
    paths: readonly string[]
  ): Promise<void> {
    this.calls.push(`wait:${stepId}:${endpoint}:${paths.join('|')}`);
    if (!paths.includes(this.#route)) {
      throw new Error('Unexpected route');
    }
  }

  async waitForExactRoute(stepId: string, endpoint: 'core' | 'admin', path: string): Promise<void> {
    this.calls.push(`wait-exact:${stepId}:${endpoint}:${path}`);
    if (this.#route !== path) {
      throw new Error('Unexpected exact route');
    }
  }

  async assertRoute(
    stepId: string,
    endpoint: 'core' | 'admin',
    paths: readonly string[]
  ): Promise<void> {
    this.calls.push(`assert:${stepId}:${endpoint}:${paths.join('|')}`);
    if (!paths.includes(this.#route)) {
      throw new Error('Unexpected route');
    }
  }

  async assertExactRoute(stepId: string, endpoint: 'core' | 'admin', path: string): Promise<void> {
    this.calls.push(`assert-exact:${stepId}:${endpoint}:${path}`);
    if (this.#route !== path) {
      throw new Error('Unexpected exact route');
    }
  }

  async fill(
    stepId: string,
    selector: string,
    _value: string,
    route: Readonly<{ endpoint: 'core' | 'admin'; paths: readonly string[] }>
  ): Promise<void> {
    this.calls.push(`fill:${stepId}:${selector}`);
    if (!route.paths.includes(this.#route)) {
      throw new Error('Unexpected form route');
    }
  }

  async click(
    stepId: string,
    selector: string,
    route?: Readonly<{ endpoint: 'core' | 'admin'; paths: readonly string[] }>
  ): Promise<void> {
    this.calls.push(`click:${stepId}:${selector}`);
    if (route && !route.paths.includes(this.#route)) {
      throw new Error('Unexpected click route');
    }
    if (selector === 'form button[name="submit"]') {
      this.#route = this.#postAuthenticationRoute;
    } else if (selector.includes('third-party-applications')) {
      this.#route = '/console/applications/third-party-applications';
    }
  }

  async expectText(stepId: string, selector: string, expected: string): Promise<void> {
    this.calls.push(`text:${stepId}:${selector}`);
    if (this.#textSets[this.#textSetIndex]?.get(selector) !== expected) {
      throw new Error('Unexpected text');
    }
    if (selector.includes('nth-child(2)')) {
      this.#textSetIndex += 1;
    }
  }

  async expectCount(stepId: string, selector: string, expected: number): Promise<void> {
    this.calls.push(`count:${stepId}:${selector}`);
    if (selector !== 'table tbody tr' || expected !== 1) {
      throw new Error('Unexpected count');
    }
  }

  async clickAndObserveObject<Projection extends JsonObject>(): Promise<Readonly<Projection>> {
    throw new Error('Unexpected object observation');
  }

  async waitForNetworkFacts(
    stepId: string,
    accept: (facts: Phase1BrowserNetworkFacts) => boolean
  ): Promise<Phase1BrowserNetworkFacts> {
    this.calls.push(`facts:${stepId}`);
    if (!accept(this.facts)) {
      throw new Error('Facts were not accepted');
    }
    return this.facts;
  }
}

type ContextOptions = Readonly<{
  session: Phase1BrowserSession;
  activities?: readonly ('never' | 'present')[];
  projectedStates?: readonly SemanticStateProjection[];
  leasePassword?: string;
}>;

const createContext = ({
  session,
  activities = ['never', 'never'],
  projectedStates = [
    { allocations: [{ marker: 'same' }] } as unknown as SemanticStateProjection,
    { allocations: [{ marker: 'same' }] } as unknown as SemanticStateProjection,
  ],
  leasePassword = 'private-password-value',
}: ContextOptions): Phase1BrowserFlowContext => {
  let activityIndex = 0;
  let projectionIndex = 0;
  const lease = {
    getPassword: (logicalId: string) => {
      if (logicalId !== 'phase1-admin') {
        throw new Error('Unexpected password identity');
      }
      return leasePassword;
    },
    getClientSecret: () => undefined,
    toJSON: () => {
      throw new TypeError('Secret lease serialization is forbidden');
    },
  } as Phase1FixtureSecretLease;

  return {
    profile,
    target,
    fixture,
    lease,
    session,
    readActivityState: async () => ({
      lastSignInState: activities[activityIndex++] ?? 'present',
    }),
    projectState: async () =>
      projectedStates[projectionIndex++] ??
      ({ allocations: [{ marker: 'different' }] } as unknown as SemanticStateProjection),
    signal: new AbortController().signal,
  };
};

const applicationTexts = Object.freeze({
  'table tbody tr td:first-child a': runtime.firstPartyName,
  'table tbody tr td:nth-child(2) div[class*="content"]': runtime.firstPartyId,
});
const thirdPartyTexts = Object.freeze({
  'table tbody tr td:first-child a': runtime.thirdPartyName,
  'table tbody tr td:nth-child(2) div[class*="content"]': runtime.thirdPartyId,
});
const userTexts = Object.freeze({
  'table tbody tr td:first-child a': 'phase1-user',
  'table tbody tr td:first-child div[class*="subtitle"]': runtime.userEmail,
  'table tbody tr td:nth-child(3) span': '-',
});

describe('Phase 1 ordered Console browser flows', () => {
  it('exports the exact independent source arrays', () => {
    expect(consoleCleanAuthenticationFlow.sourcePaths).toEqual([
      'packages/console/src/App.tsx',
      'packages/console/src/contexts/AppDataProvider.tsx',
      'packages/console/src/containers/ConsoleContent/hooks.ts',
      'packages/console/src/hooks/use-account-api.ts',
      'packages/console/src/hooks/use-current-user.ts',
      'packages/console/src/hooks/use-oss-onboarding-data.ts',
      'packages/integration-tests/src/helpers/admin-tenant.ts',
      'packages/console/src/containers/ProtectedRoutes/index.tsx',
      'packages/console/src/pages/Callback/index.tsx',
      'packages/console/src/utils/storage.ts',
      'packages/console/src/hooks/use-redirect-uri.ts',
    ]);
    expect(consoleApplicationReadFlow.sourcePaths).toEqual([
      'packages/console/src/App.tsx',
      'packages/console/src/contexts/AppDataProvider.tsx',
      'packages/console/src/hooks/use-api.ts',
      'packages/console/src/hooks/use-current-user.ts',
      'packages/console/src/pages/Applications/hooks/use-application-data.ts',
      'packages/console/src/pages/Applications/index.tsx',
      'packages/integration-tests/src/tests/console/applications/index.test.ts',
    ]);
    expect(consoleUserReadFlow.sourcePaths).toEqual([
      'packages/console/src/App.tsx',
      'packages/console/src/contexts/AppDataProvider.tsx',
      'packages/console/src/hooks/use-api.ts',
      'packages/console/src/hooks/use-current-user.ts',
      'packages/console/src/pages/Users/index.tsx',
      'packages/integration-tests/src/tests/console/user-management.test.ts',
    ]);
    expect(consoleCleanAuthenticationFlow.sourcePaths).not.toBe(
      consoleApplicationReadFlow.sourcePaths
    );
    expect(consoleApplicationReadFlow.sourcePaths).not.toBe(consoleUserReadFlow.sourcePaths);
  });

  it('authenticates from the exact form and accepts canonical refresh facts in any order', async () => {
    const facts = {
      ...emptyFacts(),
      ...authorizationFacts,
      exchanges: [
        { ...organizationFact, transportDetail: 'raw-private-response' },
        { ...initialFact, transportDetail: 'raw-private-response' },
        { ...managementFact, transportDetail: 'raw-private-response' },
      ],
      accountReads: [{ ...accountFact, transportDetail: 'raw-private-account' }],
    };
    const session = new FakeSession(facts);
    const result = await consoleCleanAuthenticationFlow.run(createContext({ session }));

    expect(signInFact.scope).toBe(requestedScope);
    expect(signInFact.scope.split(' ')).toContain('all');
    expect(initialFact.responseScope).toBe(initialResponseScope);
    expect(initialFact.responseScope.split(' ')).not.toContain('all');
    expect(result).toEqual({
      route: '/console/applications',
      initialExchange: {
        status: 200,
        accessKind: 'opaque',
        requestCorrelationValid: true,
      },
      managementExchange: {
        status: 200,
        resource: 'https://default.logto.app/api',
        responseScope: 'all',
        decodedClaimsMatch: true,
        requestCorrelationValid: true,
      },
      organizationExchange: {
        status: 200,
        organizationId: 't-default',
        responseScope: '',
        decodedClaimsMatch: true,
        requestCorrelationValid: true,
      },
      accountRead: {
        status: 200,
        accessMatchesInitial: true,
        id: 'phase1-admin',
        username: 'phase1-admin',
        primaryEmail: 'phase1-admin@example.com',
      },
      routeRestored: true,
      browserChainMatches: true,
      dataSubjectActivity: 'never',
    });
    expect(session.calls).toEqual([
      'navigate:console-auth-start:admin:/console/applications',
      'wait:console-auth-form:admin:/sign-in',
      'fill:console-auth-identifier:form input[name="identifier"]',
      'fill:console-auth-password:form input[name="password"]',
      'click:console-auth-submit:form button[name="submit"]',
      'wait-exact:console-auth-return:admin:/console/applications',
      'facts:console-auth-facts',
      'assert-exact:console-auth-final-route:admin:/console/applications',
    ]);
    expect(JSON.stringify(result)).not.toMatch(/private-password|raw-private/u);
  });

  it.each([
    {
      name: 'a missing organization exchange',
      facts: {
        ...emptyFacts(),
        ...authorizationFacts,
        exchanges: [initialFact, managementFact],
        accountReads: [accountFact],
      },
    },
    {
      name: 'a wrong Management resource',
      facts: {
        ...emptyFacts(),
        ...authorizationFacts,
        exchanges: [
          initialFact,
          { ...managementFact, resource: 'https://wrong.example/api' },
          organizationFact,
        ],
        accountReads: [accountFact],
      },
    },
    {
      name: 'an Account read not bound to the initial access value',
      facts: {
        ...emptyFacts(),
        ...authorizationFacts,
        exchanges: [initialFact, managementFact, organizationFact],
        accountReads: [{ ...accountFact, accessMatchesInitial: false }],
      },
    },
    {
      name: 'a non-canonical sign-in query',
      facts: {
        ...emptyFacts(),
        ...authorizationFacts,
        signIns: [{ ...signInFact, queryShapeExact: false }],
        exchanges: [initialFact, managementFact, organizationFact],
        accountReads: [accountFact],
      },
    },
    {
      name: 'a callback state mismatch',
      facts: {
        ...emptyFacts(),
        ...authorizationFacts,
        callbacks: [{ ...callbackFact, stateMatches: false }],
        exchanges: [initialFact, managementFact, organizationFact],
        accountReads: [accountFact],
      },
    },
    {
      name: 'a wrong tenant endpoint discovery',
      facts: {
        ...emptyFacts(),
        ...authorizationFacts,
        endpointDiscoveries: [{ ...endpointDiscoveryFact, userOriginMatchesCore: false }],
        exchanges: [initialFact, managementFact, organizationFact],
        accountReads: [accountFact],
      },
    },
    {
      name: 'an authenticated tenant endpoint discovery',
      facts: {
        ...emptyFacts(),
        ...authorizationFacts,
        endpointDiscoveries: [{ ...endpointDiscoveryFact, accessAbsent: false }],
        exchanges: [initialFact, managementFact, organizationFact],
        accountReads: [accountFact],
      },
    },
    {
      name: 'a missing initial refresh replacement',
      facts: {
        ...emptyFacts(),
        ...authorizationFacts,
        exchanges: [
          { ...initialFact, initialRefreshPresent: false, replacementFresh: false },
          managementFact,
          organizationFact,
        ],
        accountReads: [accountFact],
      },
    },
    {
      name: 'an initial response missing the organizations user scope',
      facts: {
        ...emptyFacts(),
        ...authorizationFacts,
        exchanges: [
          {
            ...initialFact,
            responseScope: initialResponseScope
              .split(' ')
              .filter((scope) => scope !== 'urn:logto:scope:organizations')
              .join(' '),
          },
          managementFact,
          organizationFact,
        ],
        accountReads: [accountFact],
      },
    },
    {
      name: 'an initial response missing the organization roles user scope',
      facts: {
        ...emptyFacts(),
        ...authorizationFacts,
        exchanges: [
          {
            ...initialFact,
            responseScope: initialResponseScope
              .split(' ')
              .filter((scope) => scope !== 'urn:logto:scope:organization_roles')
              .join(' '),
          },
          managementFact,
          organizationFact,
        ],
        accountReads: [accountFact],
      },
    },
    {
      name: 'an initial response containing the resource-only all scope',
      facts: {
        ...emptyFacts(),
        ...authorizationFacts,
        exchanges: [
          { ...initialFact, responseScope: `${initialResponseScope} all` },
          managementFact,
          organizationFact,
        ],
        accountReads: [accountFact],
      },
    },
    {
      name: 'an uncorrelated authorization code exchange',
      facts: {
        ...emptyFacts(),
        ...authorizationFacts,
        exchanges: [
          { ...initialFact, requestCorrelationValid: false },
          managementFact,
          organizationFact,
        ],
        accountReads: [accountFact],
      },
    },
    {
      name: 'a malformed Management refresh form',
      facts: {
        ...emptyFacts(),
        ...authorizationFacts,
        exchanges: [initialFact, { ...managementFact, requestShapeExact: false }, organizationFact],
        accountReads: [accountFact],
      },
    },
    {
      name: 'a duplicate Management refresh replacement',
      facts: {
        ...emptyFacts(),
        ...authorizationFacts,
        exchanges: [initialFact, { ...managementFact, replacementFresh: false }, organizationFact],
        accountReads: [accountFact],
      },
    },
    {
      name: 'an access-equal organization refresh replacement',
      facts: {
        ...emptyFacts(),
        ...authorizationFacts,
        exchanges: [initialFact, managementFact, { ...organizationFact, replacementFresh: false }],
        accountReads: [accountFact],
      },
    },
  ])('rejects $name', async ({ facts }) => {
    await expect(
      consoleCleanAuthenticationFlow.run(createContext({ session: new FakeSession(facts) }))
    ).rejects.toThrow();
  });

  it('rejects a restored Console route with unexpected search or fragment state', async () => {
    const facts = {
      ...emptyFacts(),
      ...authorizationFacts,
      exchanges: [initialFact, managementFact, organizationFact],
      accountReads: [accountFact],
    };

    await expect(
      consoleCleanAuthenticationFlow.run(
        createContext({
          session: new FakeSession(facts, {
            postAuthenticationRoute: '/console/applications?unexpected=1#fragment',
          }),
        })
      )
    ).rejects.toThrow('Unexpected exact route');
  });

  it('rejects Console authentication when the data subject becomes active', async () => {
    const facts = {
      ...emptyFacts(),
      ...authorizationFacts,
      exchanges: [initialFact, managementFact, organizationFact],
      accountReads: [accountFact],
    };

    await expect(
      consoleCleanAuthenticationFlow.run(
        createContext({ session: new FakeSession(facts), activities: ['never', 'present'] })
      )
    ).rejects.toThrow('Phase 1 Console data subject activity is invalid');
  });

  it('reads both application tabs from exact API facts and runtime DOM values', async () => {
    const session = new FakeSession(
      { ...emptyFacts(), applicationReads: applicationFacts },
      { route: '/console/applications', textSets: [applicationTexts, thirdPartyTexts] }
    );
    const result = await consoleApplicationReadFlow.run(createContext({ session }));

    expect(result).toEqual({
      routes: ['/console/applications', '/console/applications/third-party-applications'],
      applicationReads: [
        {
          kind: 'first-party',
          status: 200,
          total: 1,
          rows: [{ id: 'phase1-app', name: 'Phase 1 Application' }],
        },
        {
          kind: 'third-party',
          status: 200,
          total: 1,
          rows: [{ id: 'phase1-browser', name: 'Phase 1 Consent Client' }],
        },
        { kind: 'saml-probe', status: 200, total: 0, rows: [] },
      ],
      unchanged: true,
    });
  });

  it('rejects duplicate application facts and persisted application mutation', async () => {
    const duplicateFacts = {
      ...emptyFacts(),
      applicationReads: [...applicationFacts, applicationFacts[0]!],
    };
    const session = new FakeSession(duplicateFacts, {
      route: '/console/applications',
      textSets: [applicationTexts, thirdPartyTexts],
    });

    await expect(consoleApplicationReadFlow.run(createContext({ session }))).rejects.toThrow();

    const mutatedStates = [
      { allocations: [{ marker: 'before' }] } as unknown as SemanticStateProjection,
      { allocations: [{ marker: 'after' }] } as unknown as SemanticStateProjection,
    ];
    const validSession = new FakeSession(
      { ...emptyFacts(), applicationReads: applicationFacts },
      { route: '/console/applications', textSets: [applicationTexts, thirdPartyTexts] }
    );
    await expect(
      consoleApplicationReadFlow.run(
        createContext({ session: validSession, projectedStates: mutatedStates })
      )
    ).rejects.toThrow('Phase 1 Console application state changed');
  });

  it('rejects a wrong application API row even when the visible table matches', async () => {
    const session = new FakeSession(
      {
        ...emptyFacts(),
        applicationReads: [
          {
            ...applicationFacts[0]!,
            rows: [{ ...applicationFacts[0]!.rows[0]!, id: 'wrong-runtime-application' }],
          },
          applicationFacts[1]!,
          applicationFacts[2]!,
        ],
      },
      { route: '/console/applications', textSets: [applicationTexts, thirdPartyTexts] }
    );

    await expect(consoleApplicationReadFlow.run(createContext({ session }))).rejects.toThrow(
      'Phase 1 Console application API fact is invalid'
    );
  });

  it.each([
    ['a non-canonical query', { queryShapeExact: false }],
    ['a wrong origin', { authority: 'admin' as const, originMatches: false }],
    ['a missing language header', { languageMatches: false }],
    ['a different bearer value', { accessMatchesManagement: false }],
  ])('rejects an application read with $name', async (_name, mutation) => {
    const session = new FakeSession(
      {
        ...emptyFacts(),
        applicationReads: [{ ...applicationFacts[0]!, ...mutation }, ...applicationFacts.slice(1)],
      },
      { route: '/console/applications', textSets: [applicationTexts, thirdPartyTexts] }
    );

    await expect(consoleApplicationReadFlow.run(createContext({ session }))).rejects.toThrow(
      'Phase 1 Console application API fact is invalid'
    );
  });

  it('proves username through the API fact while the row displays name and email', async () => {
    const session = new FakeSession(
      { ...emptyFacts(), userReads: [userFact] },
      { route: '/console/applications/third-party-applications', textSets: [userTexts] }
    );
    const result = await consoleUserReadFlow.run(createContext({ session }));

    expect(result).toEqual({
      route: '/console/users',
      userRead: {
        status: 200,
        total: 1,
        row: {
          id: 'phase1-user',
          username: 'phase1-user',
          primaryEmail: 'phase1-user@example.com',
          lastSignInState: 'never',
        },
      },
      display: {
        name: 'phase1-user',
        primaryEmail: 'phase1-user@example.com',
        latestSignIn: 'never',
      },
      unchanged: true,
    });
  });

  it('rejects a wrong API username even when the visible row still matches', async () => {
    const session = new FakeSession(
      {
        ...emptyFacts(),
        userReads: [
          {
            ...userFact,
            rows: [{ ...userFact.rows[0]!, username: 'wrong-runtime-username' }],
          },
        ],
      },
      { route: '/console/applications', textSets: [userTexts] }
    );

    await expect(consoleUserReadFlow.run(createContext({ session }))).rejects.toThrow(
      'Phase 1 Console user API fact is invalid'
    );
  });

  it.each([
    ['a non-canonical query', { queryShapeExact: false }],
    ['a wrong origin', { authority: 'admin' as const, originMatches: false }],
    ['a missing language header', { languageMatches: false }],
    ['a different bearer value', { accessMatchesManagement: false }],
  ])('rejects a user read with $name', async (_name, mutation) => {
    const session = new FakeSession(
      { ...emptyFacts(), userReads: [{ ...userFact, ...mutation }] },
      { route: '/console/applications', textSets: [userTexts] }
    );

    await expect(consoleUserReadFlow.run(createContext({ session }))).rejects.toThrow(
      'Phase 1 Console user API fact is invalid'
    );
  });

  it('rejects user mutation independently of API and DOM success', async () => {
    const session = new FakeSession(
      { ...emptyFacts(), userReads: [userFact] },
      { route: '/console/applications', textSets: [userTexts] }
    );
    const projectedStates = [
      { allocations: [{ marker: 'before' }] } as unknown as SemanticStateProjection,
      { allocations: [{ marker: 'after' }] } as unknown as SemanticStateProjection,
    ];

    await expect(
      consoleUserReadFlow.run(createContext({ session, projectedStates }))
    ).rejects.toThrow('Phase 1 Console user state changed');
  });

  it('rejects user activity independently of API, DOM, and persisted-state success', async () => {
    const session = new FakeSession(
      { ...emptyFacts(), userReads: [userFact] },
      { route: '/console/applications', textSets: [userTexts] }
    );

    await expect(
      consoleUserReadFlow.run(createContext({ session, activities: ['never', 'present'] }))
    ).rejects.toThrow('Phase 1 Console data subject activity is invalid');
  });
});

/* eslint-enable @typescript-eslint/consistent-type-assertions, @typescript-eslint/array-type, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, import/order, max-lines, unicorn/no-useless-undefined */
