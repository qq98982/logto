/* eslint-disable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- These assertions intentionally keep ordered protocol facts and bounded wait counters together. */
import type {
  Phase1BrowserSession,
  Phase1ProfiledDemoConfiguration,
} from '../../phase-1/browser/contracts.js';

import type { CommonEmailPasswordBrowserSession } from './common-email-password-sign-in.js';

const callbackFail = (field: string): never => {
  throw new TypeError(`Common email password callback failed: ${field}`);
};
const refreshFail = (field: string): never => {
  throw new TypeError(`Common email password refresh failed: ${field}`);
};
const requireFact = <Value>(value: Value | undefined, field: string): Value =>
  value ?? callbackFail(field);
const exactResourceAudience = (audience: string | readonly string[], resource: string): boolean =>
  typeof audience === 'string'
    ? audience === resource
    : audience.length === 1 && audience[0] === resource;
export type RefreshScopeClass = 'api-only' | 'oidc-plus-api' | 'oidc-only' | 'missing' | 'other';
const oidcScopes = new Set(['openid', 'offline_access', 'profile', 'email']);
export const classifyRefreshScope = (value: unknown, resourceScope: string): RefreshScopeClass => {
  const tokens = (typeof value === 'string' ? value : '').split(' ').filter(Boolean);
  if (tokens.length === 0) {
    return 'missing';
  }
  if (
    new Set(tokens).size !== tokens.length ||
    tokens.some((token) => token !== resourceScope && !oidcScopes.has(token))
  ) {
    return 'other';
  }
  const hasApi = tokens.includes(resourceScope);
  const hasOidc = tokens.some((token) => oidcScopes.has(token));
  return hasApi ? (hasOidc ? 'oidc-plus-api' : 'api-only') : hasOidc ? 'oidc-only' : 'other';
};

export const adaptPhase1SessionForEmailPassword = (
  session: Phase1BrowserSession,
  configuration: Readonly<{
    storageKey: string;
    demo: Phase1ProfiledDemoConfiguration;
    expectedSubject: string;
    expectedIssuer: string;
    canonicalEmail: string;
    resource: string;
    redirectUri: string;
    initialResponseScope: string;
    resourceScope: string;
  }>
): CommonEmailPasswordBrowserSession => ({
  navigate: async (step, path) => {
    await session.preloadDemoConfiguration(
      'preload-email-password',
      configuration.storageKey,
      configuration.demo
    );
    await session.navigate(step, 'core', path);
  },
  waitForRoute: async (step, paths) => session.waitForRoute(step, 'core', paths),
  fill: async (step, selector, value) =>
    session.fill(step, selector, value, {
      endpoint: 'core',
      paths: ['/sign-in', '/sign-in/password'],
    }),
  click: async (step, selector) => session.click(step, selector),
  assertInitialCallback: async () => {
    try {
      await session.waitForExactRoute('wait-email-callback', 'core', '/demo-app');
    } catch {
      callbackFail('callback-route');
    }
    let facts: Awaited<ReturnType<Phase1BrowserSession['waitForNetworkFacts']>>;
    let signInCount = '0';
    let callbackCount = '0';
    let initialCount = '0';
    try {
      facts = await session.waitForNetworkFacts('email-callback-facts', (value) => {
        signInCount = value.signIns.length === 0 ? '0' : value.signIns.length === 1 ? '1' : 'many';
        callbackCount =
          value.callbacks.length === 0 ? '0' : value.callbacks.length === 1 ? '1' : 'many';
        const count = value.exchanges.filter(({ kind }) => kind === 'initial').length;
        initialCount = count === 0 ? '0' : count === 1 ? '1' : 'many';
        return callbackCount === '1' && initialCount === '1';
      });
    } catch {
      return callbackFail(`callback-facts-s${signInCount}-c${callbackCount}-i${initialCount}`);
    }
    const [callback] = facts.callbacks;
    const [signIn] = facts.signIns;
    const initial = facts.exchanges.filter(({ kind }) => kind === 'initial');
    const [exchange] = initial;
    if (facts.signIns.length !== 1 || facts.callbacks.length !== 1 || initial.length !== 1) {
      callbackFail('cardinality');
    }
    const signInFact = requireFact(signIn, 'signin-authority');
    const callbackFact = requireFact(callback, 'callback-authority');
    const exchangeFact = requireFact(exchange, 'exchange-authority');
    if (signInFact.authority !== 'core') {
      callbackFail('signin-authority');
    }
    if (signInFact.status !== 303 || !signInFact.queryShapeExact) {
      callbackFail('signin-response');
    }
    if (signInFact.clientId !== configuration.demo.appId) {
      callbackFail('signin-client');
    }
    if (signInFact.redirectUri !== configuration.redirectUri) {
      callbackFail('signin-redirect');
    }
    if (signInFact.responseType !== 'code' || signInFact.prompt !== configuration.demo.prompt) {
      callbackFail('signin-mode');
    }
    if (signInFact.scope !== configuration.demo.scope) {
      callbackFail('signin-scope');
    }
    if (
      signInFact.resources.length !== 1 ||
      signInFact.resources[0] !== configuration.demo.resource
    ) {
      callbackFail('signin-resource');
    }
    if (
      signInFact.pkceMethod !== 'S256' ||
      !signInFact.stateFormatValid ||
      !signInFact.challengeFormatValid
    ) {
      callbackFail('signin-pkce');
    }
    if (!callback) {
      callbackFail('callback-authority');
    }
    if (callbackFact.authority !== 'core' || callbackFact.path !== '/demo-app') {
      callbackFail('callback-authority');
    }
    if (callbackFact.status !== 200 || !callbackFact.queryShapeExact) {
      callbackFail('callback-response');
    }
    if (!callbackFact.stateMatches) {
      callbackFail('callback-state');
    }
    if (callbackFact.issuer !== configuration.expectedIssuer) {
      callbackFail('callback-issuer');
    }
    if (!callbackFact.codePresent || !callbackFact.fragmentEmpty) {
      callbackFail('callback-code');
    }
    if (!exchange) {
      callbackFail('exchange-authority');
    }
    if (exchangeFact.authority !== 'core') {
      callbackFail('exchange-authority');
    }
    if (exchangeFact.status !== 200 || !exchangeFact.requestShapeExact) {
      callbackFail('exchange-response');
    }
    if (!exchangeFact.requestCorrelationValid) {
      callbackFail('exchange-correlation');
    }
    if (
      exchangeFact.clientId !== configuration.demo.appId ||
      exchangeFact.redirectUri !== configuration.redirectUri
    ) {
      callbackFail('exchange-client');
    }
    if (!exchangeFact.initialRefreshPresent || !exchangeFact.replacementFresh) {
      callbackFail('exchange-refresh');
    }
    if (exchangeFact.resource !== null || exchangeFact.organizationId !== null) {
      callbackFail('exchange-target');
    }
    if (exchangeFact.responseScope !== configuration.initialResponseScope) {
      callbackFail('exchange-scope');
    }
    if (exchangeFact.accessKind !== 'opaque' || exchangeFact.compactAccess !== undefined) {
      callbackFail('exchange-access');
    }
  },
  readProfile: async () => {
    await session.click('open-email-dev-panel', 'role=button[name="Open dev panel"]');
    const value = await session.clickAndObserveObject(
      'email-userinfo',
      'role=button[name="Fetch user info"]',
      (body) => ({
        sub: body.sub ?? null,
        email: body.email ?? null,
        emailVerified: body.email_verified ?? null,
      })
    );
    return { sub: value.sub, email: value.email, emailVerified: value.emailVerified };
  },
  refresh: async () => {
    const before = await session.waitForNetworkFacts('email-refresh-before', () => true);
    const beforeCount = before.exchanges.length;
    await session.fill(
      'email-refresh-resource',
      'form:has-text("Refresh token grant") input[name="resource"]',
      configuration.resource,
      { endpoint: 'core', paths: ['/demo-app'] }
    );
    await session.clickAndObserveObject(
      'email-refresh',
      'role=button[name="Request token"]',
      () => ({ observed: true })
    );
    const facts = await session.waitForNetworkFacts(
      'email-refresh-facts',
      ({ exchanges }) => exchanges.length === beforeCount + 1
    );
    const exchange = facts.exchanges[beforeCount];
    if (!exchange) {
      return refreshFail('exchange-kind');
    }
    if (exchange.kind !== 'management') {
      refreshFail('exchange-kind');
    }
    if (exchange.authority !== 'core') {
      refreshFail('authority');
    }
    if (exchange.status !== 200) {
      refreshFail('status');
    }
    if (!exchange.requestShapeExact) {
      refreshFail('request-shape');
    }
    if (!exchange.requestCorrelationValid) {
      refreshFail('correlation');
    }
    if (exchange.clientId !== configuration.demo.appId) {
      refreshFail('client');
    }
    if (exchange.redirectUri !== null) {
      refreshFail('redirect');
    }
    if (exchange.initialRefreshPresent) {
      refreshFail('initial-refresh-flag');
    }
    if (!exchange.replacementFresh) {
      refreshFail('replacement-fresh');
    }
    if (exchange.resource !== configuration.resource) {
      refreshFail('resource');
    }
    if (exchange.organizationId !== null) {
      refreshFail('organization');
    }
    if (exchange.responseScope !== configuration.resourceScope) {
      const responseClass = classifyRefreshScope(
        exchange.responseScope,
        configuration.resourceScope
      );
      const claimsClass = classifyRefreshScope(
        exchange.compactAccess?.scope ?? '',
        configuration.resourceScope
      );
      refreshFail(`response-scope-${responseClass}-claims-${claimsClass}`);
    }
    if (exchange.accessKind !== 'compact') {
      refreshFail('access-kind');
    }
    const compactAccess = exchange.compactAccess ?? refreshFail('access-kind');
    if (compactAccess.issuer !== configuration.expectedIssuer) {
      refreshFail('compact-issuer');
    }
    if (compactAccess.subject !== configuration.expectedSubject) {
      refreshFail('subject');
    }
    if (!exactResourceAudience(compactAccess.audience, configuration.resource)) {
      refreshFail('audience');
    }
    if (compactAccess.clientId !== configuration.demo.appId) {
      refreshFail('compact-client');
    }
    if (compactAccess.scope !== configuration.resourceScope) {
      refreshFail('scope');
    }
    if (compactAccess.organizationIdPresent) {
      refreshFail('organization-present');
    }
    return { subject: compactAccess.subject, rotated: true };
  },
});
/* eslint-enable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
