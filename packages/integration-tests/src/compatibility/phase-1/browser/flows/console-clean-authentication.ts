/* eslint-disable complexity, max-lines -- The flow validates one closed profile, fixture, browser action sequence, and three independent network fact classes. */
import { isDeepStrictEqual } from 'node:util';

import { ReservedScope, userClaims } from '@logto/core-kit';

import { assertEvidenceIsSanitized } from '../../../evidence.js';
import type { JsonObject } from '../../../normalize.js';
import {
  getPhase1FixtureRuntimeEmail,
  getPhase1FixtureRuntimeId,
  getPhase1FixtureRuntimeUsername,
  type Phase1FixtureAllocation,
} from '../../fixture-map.js';
import type { Phase1BrowserExchangeFact, Phase1BrowserFlowModule } from '../contracts.js';

export const consoleCleanAuthenticationSourcePaths = Object.freeze([
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
] as const);

const signInPaths = Object.freeze(['/sign-in'] as const);
const identifierSelector = 'form input[name="identifier"]';
const passwordSelector = 'form input[name="password"]';
const submitSelector = 'form button[name="submit"]';
const userClaimScopeNames = new Set(Object.keys(userClaims));

const initialResponseScope = (effectiveScopes: readonly string[]): string =>
  effectiveScopes
    .filter(
      (scope) =>
        scope === ReservedScope.OpenId ||
        scope === ReservedScope.OfflineAccess ||
        userClaimScopeNames.has(scope)
    )
    .join(' ');

const requireAllocation = (
  allocations: readonly Phase1FixtureAllocation[],
  role: 'admin' | 'data'
): Phase1FixtureAllocation => {
  const matches = allocations.filter((allocation) => allocation.role === role);

  if (matches.length !== 1 || !matches[0]) {
    throw new Error('Phase 1 Console fixture allocation is invalid');
  }

  return matches[0];
};

const requireSingleExchange = (
  exchanges: readonly Phase1BrowserExchangeFact[],
  kind: Phase1BrowserExchangeFact['kind']
): Phase1BrowserExchangeFact => {
  const matches = exchanges.filter((exchange) => exchange.kind === kind);

  if (matches.length !== 1 || !matches[0]) {
    throw new Error('Phase 1 Console exchange facts are invalid');
  }

  return matches[0];
};

const audienceEquals = (actual: string | readonly string[], expected: string): boolean =>
  actual === expected || (Array.isArray(actual) && actual.length === 1 && actual[0] === expected);

const assertCompactExchange = (
  exchange: Phase1BrowserExchangeFact,
  expected: Readonly<{
    issuer: string;
    subject: string;
    audience: string;
    clientId: string;
    scope: string;
  }>
): void => {
  const compact = exchange.compactAccess;

  if (
    exchange.authority !== 'admin' ||
    exchange.status !== 200 ||
    !exchange.requestShapeExact ||
    !exchange.requestCorrelationValid ||
    !exchange.replacementFresh ||
    exchange.clientId !== expected.clientId ||
    exchange.redirectUri !== null ||
    exchange.accessKind !== 'compact' ||
    !compact ||
    compact.issuer !== expected.issuer ||
    compact.subject !== expected.subject ||
    !audienceEquals(compact.audience, expected.audience) ||
    compact.clientId !== expected.clientId ||
    compact.scope !== expected.scope ||
    compact.organizationIdPresent
  ) {
    throw new Error('Phase 1 Console compact exchange fact is invalid');
  }
};

export const consoleCleanAuthentication: Phase1BrowserFlowModule = Object.freeze({
  id: 'console.clean-authentication',
  executionGroup: 'console',
  sourcePaths: consoleCleanAuthenticationSourcePaths,
  run: async (context): Promise<JsonObject> => {
    const flow = context.profile.browserFlows.find(
      (candidate) => candidate.id === 'console.clean-authentication'
    );

    if (
      !flow ||
      flow.executionGroup !== 'console' ||
      !isDeepStrictEqual(flow.sourceEvidence, consoleCleanAuthenticationSourcePaths)
    ) {
      throw new Error('Phase 1 Console authentication profile is invalid');
    }
    const { allocations } = context.fixture.public;
    const adminAllocation = requireAllocation(allocations, 'admin');
    requireAllocation(allocations, 'data');
    const { operator, tenantOrganization } = context.profile.fixtures.adminTenant;
    const runtimeAdminId = getPhase1FixtureRuntimeId(
      context.fixture.public,
      adminAllocation.allocationId,
      'user',
      operator.id
    );
    const runtimeUsername = getPhase1FixtureRuntimeUsername(
      operator.username,
      adminAllocation.allocationId
    );
    const runtimeEmail = getPhase1FixtureRuntimeEmail(
      operator.primaryEmail,
      adminAllocation.allocationId
    );
    const beforeActivity = await context.readActivityState(
      context.profile.fixtures.dataTenant.subject.id
    );

    if (beforeActivity.lastSignInState !== 'never') {
      throw new Error('Phase 1 Console data subject activity is invalid');
    }

    await context.session.navigate('console-auth-start', 'admin', flow.startRoute);
    await context.session.waitForRoute('console-auth-form', 'admin', signInPaths);
    const formRoute = Object.freeze({ endpoint: 'admin' as const, paths: signInPaths });
    await context.session.fill(
      'console-auth-identifier',
      identifierSelector,
      runtimeUsername,
      formRoute
    );
    await context.session.fill(
      'console-auth-password',
      passwordSelector,
      context.lease.getPassword(operator.id),
      formRoute
    );
    await context.session.click('console-auth-submit', submitSelector, formRoute);
    await context.session.waitForExactRoute(
      'console-auth-return',
      'admin',
      flow.postAuthenticationRoute
    );
    const facts = await context.session.waitForNetworkFacts(
      'console-auth-facts',
      (candidate) =>
        candidate.signIns.length > 0 &&
        candidate.callbacks.length > 0 &&
        candidate.endpointDiscoveries.length > 0 &&
        candidate.exchanges.some(({ kind }) => kind === 'initial') &&
        candidate.exchanges.some(({ kind }) => kind === 'management') &&
        candidate.exchanges.some(({ kind }) => kind === 'organization') &&
        candidate.accountReads.length > 0
    );

    if (
      facts.signIns.length !== 1 ||
      facts.callbacks.length !== 1 ||
      facts.endpointDiscoveries.length !== 1 ||
      facts.exchanges.length !== 3 ||
      facts.accountReads.length !== 1
    ) {
      throw new Error('Phase 1 Console authentication facts are invalid');
    }
    const [signIn] = facts.signIns;
    const [callback] = facts.callbacks;
    const [endpointDiscovery] = facts.endpointDiscoveries;
    const initial = requireSingleExchange(facts.exchanges, 'initial');
    const management = requireSingleExchange(facts.exchanges, 'management');
    const organization = requireSingleExchange(facts.exchanges, 'organization');
    const [managementResource] = context.profile.consoleAuthentication.configuredResources;
    const clientId = context.profile.consoleAuthentication.applicationId;
    const issuer = new URL('/oidc', context.target.adminUrl).href;
    const redirectUri = new URL('/console/callback', context.target.adminUrl).href;

    if (
      !signIn ||
      signIn.authority !== 'admin' ||
      signIn.status !== 303 ||
      !signIn.queryShapeExact ||
      signIn.clientId !== clientId ||
      signIn.redirectUri !== redirectUri ||
      signIn.responseType !== 'code' ||
      signIn.prompt !== context.profile.consoleAuthentication.prompt.join(' ') ||
      signIn.scope !== context.profile.consoleAuthentication.effectiveScopes.join(' ') ||
      !isDeepStrictEqual(
        signIn.resources,
        context.profile.consoleAuthentication.effectiveResources
      ) ||
      signIn.pkceMethod !== 'S256' ||
      !signIn.stateFormatValid ||
      !signIn.challengeFormatValid ||
      !callback ||
      callback.authority !== 'admin' ||
      callback.path !== '/console/callback' ||
      callback.status !== 200 ||
      !callback.queryShapeExact ||
      !callback.stateMatches ||
      callback.issuer !== issuer ||
      !callback.codePresent ||
      !callback.fragmentEmpty ||
      !endpointDiscovery ||
      endpointDiscovery.authority !== 'admin' ||
      endpointDiscovery.status !== 200 ||
      !endpointDiscovery.queryShapeExact ||
      !endpointDiscovery.accessAbsent ||
      !endpointDiscovery.userOriginMatchesCore
    ) {
      throw new Error('Phase 1 Console browser authorization chain is invalid');
    }

    if (
      !managementResource ||
      initial.authority !== 'admin' ||
      initial.status !== 200 ||
      !initial.requestShapeExact ||
      !initial.requestCorrelationValid ||
      !initial.replacementFresh ||
      initial.clientId !== clientId ||
      initial.redirectUri !== redirectUri ||
      !initial.initialRefreshPresent ||
      initial.resource !== null ||
      initial.organizationId !== null ||
      initial.responseScope !==
        initialResponseScope(context.profile.consoleAuthentication.effectiveScopes) ||
      initial.accessKind !== 'opaque' ||
      initial.compactAccess !== undefined ||
      management.resource !== managementResource ||
      management.organizationId !== null ||
      management.responseScope !== 'all'
    ) {
      throw new Error('Phase 1 Console authentication facts are invalid');
    }
    assertCompactExchange(management, {
      issuer,
      subject: runtimeAdminId,
      audience: managementResource,
      clientId,
      scope: 'all',
    });

    if (
      organization.resource !== null ||
      organization.organizationId !== tenantOrganization.id ||
      organization.responseScope !== ''
    ) {
      throw new Error('Phase 1 Console organization exchange fact is invalid');
    }
    assertCompactExchange(organization, {
      issuer,
      subject: runtimeAdminId,
      audience: `urn:logto:organization:${tenantOrganization.id}`,
      clientId,
      scope: '',
    });
    const [account] = facts.accountReads;

    if (
      !account ||
      account.authority !== 'admin' ||
      account.status !== 200 ||
      !account.queryShapeExact ||
      !account.accessMatchesInitial ||
      account.id !== runtimeAdminId ||
      account.username !== runtimeUsername ||
      account.primaryEmail !== runtimeEmail
    ) {
      throw new Error('Phase 1 Console Account read fact is invalid');
    }
    await context.session.assertExactRoute(
      'console-auth-final-route',
      'admin',
      flow.postAuthenticationRoute
    );
    const afterActivity = await context.readActivityState(
      context.profile.fixtures.dataTenant.subject.id
    );

    if (afterActivity.lastSignInState !== 'never') {
      throw new Error('Phase 1 Console data subject activity is invalid');
    }

    const observation = Object.freeze({
      route: flow.postAuthenticationRoute,
      initialExchange: Object.freeze({
        status: initial.status,
        accessKind: initial.accessKind,
        requestCorrelationValid: true,
      }),
      managementExchange: Object.freeze({
        status: management.status,
        resource: managementResource,
        responseScope: management.responseScope,
        decodedClaimsMatch: true,
        requestCorrelationValid: true,
      }),
      organizationExchange: Object.freeze({
        status: organization.status,
        organizationId: tenantOrganization.id,
        responseScope: organization.responseScope,
        decodedClaimsMatch: true,
        requestCorrelationValid: true,
      }),
      accountRead: Object.freeze({
        status: account.status,
        accessMatchesInitial: true,
        id: operator.id,
        username: operator.username,
        primaryEmail: operator.primaryEmail,
      }),
      routeRestored: true,
      browserChainMatches: true,
      dataSubjectActivity: 'never',
    });

    assertEvidenceIsSanitized(observation);
    return observation;
  },
});

export const consoleCleanAuthenticationFlow = consoleCleanAuthentication;

export default consoleCleanAuthentication;

/* eslint-enable complexity, max-lines */
