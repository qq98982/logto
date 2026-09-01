/* eslint-disable complexity, max-lines -- The profiled browser actions, runtime fixture resolution, exact authorization chain, closed console projections, and activity convergence form one auditable use case. */
import { isDeepStrictEqual } from 'node:util';

import { assertEvidenceIsSanitized } from '../../../evidence.js';
import type { JsonObject, JsonValue } from '../../../normalize.js';
import {
  getPhase1FixtureRuntimeEmail,
  getPhase1FixtureRuntimeId,
  getPhase1FixtureRuntimeResourceIndicator,
  getPhase1FixtureRuntimeText,
  getPhase1FixtureRuntimeUsername,
} from '../../fixture-map.js';
import type { Phase1BrowserFlowContext, Phase1BrowserFlowModule } from '../contracts.js';

const flowId = 'experience.password-pkce-consent';
const invalidProfile = 'Phase 1 Experience browser profile is invalid';
const invalidFixture = 'Phase 1 Experience browser fixture is invalid';
const invalidResourceResult = 'Phase 1 Experience resource result is invalid';
const invalidUserResult = 'Phase 1 Experience user result is invalid';
const invalidActivityState = 'Phase 1 Experience activity state is invalid';
const invalidFixtureState = 'Phase 1 Experience fixture state is invalid';
const activityAttempts = 20;
const activityIntervalMilliseconds = 25;

export const experiencePasswordPkceConsentSourcePaths = Object.freeze([
  'packages/demo-app/src/App.tsx',
  'packages/demo-app/src/DevPanel.tsx',
  'packages/demo-app/src/utils.ts',
  'packages/experience/src/apis/consent.ts',
  'packages/experience/src/pages/Consent/index.tsx',
  'packages/integration-tests/src/client/experience/index.ts',
  'packages/integration-tests/src/helpers/experience/index.ts',
  'packages/experience/src/apis/settings.ts',
] as const);

const signInRoutes = Object.freeze(['/sign-in', '/sign-in/password']);
const consentRoute = Object.freeze(['/consent']);
const demoPath = '/demo-app';
const demoRoute = Object.freeze([demoPath]);
const roleButton = (name: string): string => `role=button[name=${JSON.stringify(name)}]`;
const exactText = (value: string): string => `text=${JSON.stringify(value)}`;
const scopeItems = (groupName: string): string =>
  `${roleButton(groupName)} >> xpath=following-sibling::ul/li`;

const exactAudience = (value: JsonValue | undefined, expected: string): boolean =>
  value === expected || (Array.isArray(value) && value.length === 1 && value[0] === expected);

const delay = async (signal: AbortSignal): Promise<void> => {
  if (signal.aborted) {
    throw new Error(invalidActivityState);
  }

  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort);
      resolve();
    }, activityIntervalMilliseconds);
    const onAbort = () => {
      clearTimeout(timer);
      signal.removeEventListener('abort', onAbort);
      reject(new Error(invalidActivityState));
    };

    signal.addEventListener('abort', onAbort, { once: true });
    if (signal.aborted) {
      onAbort();
    }
  });
};

const waitForActivityAttempt = async (
  context: Phase1BrowserFlowContext,
  logicalUserId: string,
  remainingAttempts: number
): Promise<void> => {
  if (remainingAttempts <= 0 || context.signal.aborted) {
    throw new Error(invalidActivityState);
  }
  const { lastSignInState } = await context.readActivityState(logicalUserId);

  if (lastSignInState === 'present') {
    return;
  }
  await delay(context.signal);
  return waitForActivityAttempt(context, logicalUserId, remainingAttempts - 1);
};

const waitForActivity = async (
  context: Phase1BrowserFlowContext,
  logicalUserId: string
): Promise<void> => waitForActivityAttempt(context, logicalUserId, activityAttempts);

const requireProfile = (context: Phase1BrowserFlowContext) => {
  const flow = context.profile.browserFlows.find(({ id }) => id === flowId);
  const { dataTenant } = context.profile.fixtures;
  const configuration = dataTenant.browserClientConfiguration;
  const application = dataTenant.applications.find(
    ({ id }) => id === configuration.localStorageValue.appId
  );
  const [scope] = dataTenant.resource.scopes;

  if (
    !flow ||
    flow.executionGroup !== 'experience' ||
    !isDeepStrictEqual(flow.sourceEvidence, experiencePasswordPkceConsentSourcePaths) ||
    !application?.isThirdParty ||
    !scope ||
    configuration.localStorageValue.resource !== dataTenant.resource.indicator ||
    !configuration.route.startsWith('/demo-app?')
  ) {
    throw new Error(invalidProfile);
  }

  return Object.freeze({ application, configuration, dataTenant, scope });
};

const resolveFixture = (context: Phase1BrowserFlowContext) => {
  const { application, configuration, dataTenant, scope } = requireProfile(context);
  const dataAllocations = context.fixture.public.allocations.filter(({ role }) => role === 'data');
  const [allocation] = dataAllocations;

  if (!allocation || dataAllocations.length !== 1) {
    throw new Error(invalidFixture);
  }
  try {
    const applicationId = getPhase1FixtureRuntimeId(
      context.fixture.public,
      allocation.allocationId,
      'application',
      application.id
    );
    const subjectId = getPhase1FixtureRuntimeId(
      context.fixture.public,
      allocation.allocationId,
      'user',
      dataTenant.subject.id
    );
    const resourceIndicator = getPhase1FixtureRuntimeResourceIndicator(
      dataTenant.resource.indicator,
      allocation.allocationId
    );
    const resourceName = getPhase1FixtureRuntimeText(
      dataTenant.resource.name,
      allocation.allocationId
    );
    const scopeName = getPhase1FixtureRuntimeText(scope.name, allocation.allocationId);
    const username = getPhase1FixtureRuntimeUsername(
      dataTenant.subject.username,
      allocation.allocationId
    );
    const email = getPhase1FixtureRuntimeEmail(
      dataTenant.subject.primaryEmail,
      allocation.allocationId
    );
    const configuredScopes = configuration.localStorageValue.scope.split(/\s+/u).filter(Boolean);
    const logicalResourceScopeNames = new Set(dataTenant.resource.scopes.map(({ name }) => name));
    const resolveScope = (candidate: string) =>
      candidate === scope.name
        ? scopeName
        : logicalResourceScopeNames.has(candidate)
          ? (() => {
              throw new Error(invalidProfile);
            })()
          : candidate;
    const resolvedScopes = configuredScopes.map((candidate) => resolveScope(candidate));
    const effectiveScopes = configuration.effectiveScopes
      .map((candidate) => resolveScope(candidate))
      .join(' ');
    const route = new URL(configuration.route, 'https://browser.invalid');
    route.searchParams.set('app_id', applicationId);

    return Object.freeze({
      applicationId,
      configuredScopes: resolvedScopes.join(' '),
      dataTenant,
      email,
      effectiveScopes,
      issuer: new URL('/oidc', context.target.coreUrl).href.replace(/\/$/u, ''),
      prompt: configuration.localStorageValue.prompt,
      redirectUri: new URL(demoPath, context.target.coreUrl).href,
      resourceIndicator,
      resourceName,
      scope,
      scopeName,
      startPath: `${route.pathname}?${route.searchParams.toString()}`,
      subjectId,
      username,
    });
  } catch (error: unknown) {
    if (error instanceof Error && error.message === invalidProfile) {
      throw error;
    }
    throw new Error(invalidFixture);
  }
};

const projectResourceResult = (
  value: JsonObject,
  expected: ReturnType<typeof resolveFixture>
): JsonObject => {
  if (
    !exactAudience(value.aud, expected.resourceIndicator) ||
    value.iss !== expected.issuer ||
    value.sub !== expected.subjectId ||
    value.client_id !== expected.applicationId ||
    value.scope !== expected.scopeName ||
    Object.hasOwn(value, 'organization_id')
  ) {
    throw new Error(invalidResourceResult);
  }

  return Object.freeze({
    client: expected.dataTenant.browserClientConfiguration.localStorageValue.appId,
    format: 'decoded-compact',
    issuer: 'data',
    permission: expected.scope.name,
    resource: expected.dataTenant.resource.indicator,
    subject: expected.dataTenant.subject.id,
  });
};

const projectUserResult = (
  value: JsonObject,
  expected: ReturnType<typeof resolveFixture>
): JsonObject => {
  if (
    value.sub !== expected.subjectId ||
    value.username !== expected.username ||
    value.email !== expected.email
  ) {
    throw new Error(invalidUserResult);
  }

  return Object.freeze({
    email: expected.dataTenant.subject.primaryEmail,
    subject: expected.dataTenant.subject.id,
    username: expected.dataTenant.subject.username,
  });
};

const hasInitialBrowserChain = (
  facts: Awaited<ReturnType<Phase1BrowserFlowContext['session']['waitForNetworkFacts']>>
): boolean => {
  const initial = facts.exchanges.filter(({ kind }) => kind === 'initial');

  return facts.signIns.length > 0 && facts.callbacks.length > 0 && initial.length > 0;
};

const assertInitialBrowserChain = (
  facts: Awaited<ReturnType<Phase1BrowserFlowContext['session']['waitForNetworkFacts']>>,
  expected: ReturnType<typeof resolveFixture>
): void => {
  const [signIn] = facts.signIns;
  const [callback] = facts.callbacks;
  const initial = facts.exchanges.filter(({ kind }) => kind === 'initial');
  const [exchange] = initial;
  const { redirectUri } = expected;

  if (
    facts.signIns.length !== 1 ||
    facts.callbacks.length !== 1 ||
    initial.length !== 1 ||
    !signIn ||
    signIn.authority !== 'core' ||
    signIn.status !== 303 ||
    !signIn.queryShapeExact ||
    signIn.clientId !== expected.applicationId ||
    signIn.redirectUri !== redirectUri ||
    signIn.responseType !== 'code' ||
    signIn.prompt !== expected.prompt ||
    signIn.scope !== expected.effectiveScopes ||
    !isDeepStrictEqual(signIn.resources, [expected.resourceIndicator]) ||
    signIn.pkceMethod !== 'S256' ||
    !signIn.stateFormatValid ||
    !signIn.challengeFormatValid ||
    !callback ||
    callback.authority !== 'core' ||
    callback.path !== demoPath ||
    callback.status !== 200 ||
    !callback.queryShapeExact ||
    !callback.stateMatches ||
    callback.issuer !== expected.issuer ||
    !callback.codePresent ||
    !callback.fragmentEmpty ||
    !exchange ||
    exchange.authority !== 'core' ||
    exchange.status !== 200 ||
    !exchange.requestShapeExact ||
    !exchange.requestCorrelationValid ||
    exchange.clientId !== expected.applicationId ||
    exchange.redirectUri !== redirectUri ||
    !exchange.initialRefreshPresent ||
    !exchange.replacementFresh ||
    exchange.resource !== null ||
    exchange.organizationId !== null ||
    exchange.responseScope !== expected.effectiveScopes ||
    exchange.accessKind !== 'opaque' ||
    exchange.compactAccess !== undefined
  ) {
    throw new Error('Phase 1 Experience browser authorization chain is invalid');
  }
};

const run = async (context: Phase1BrowserFlowContext): Promise<JsonObject> => {
  const resolved = resolveFixture(context);
  const beforeState = await context.projectState();
  const beforeActivity = await context.readActivityState(resolved.dataTenant.subject.id);

  if (beforeActivity.lastSignInState !== 'never') {
    throw new Error(invalidActivityState);
  }
  const password = context.lease.getPassword(resolved.dataTenant.subject.id);
  const configuration = context.profile.fixtures.dataTenant.browserClientConfiguration;
  const { session } = context;

  await session.preloadDemoConfiguration('preload-demo', configuration.localStorageKey, {
    appId: resolved.applicationId,
    prompt: configuration.localStorageValue.prompt,
    scope: resolved.configuredScopes,
    resource: resolved.resourceIndicator,
  });
  await session.navigate('open-demo', 'core', resolved.startPath);
  await session.waitForRoute('wait-sign-in', 'core', signInRoutes);
  await session.fill('fill-username', 'input[name="identifier"]', resolved.username, {
    endpoint: 'core',
    paths: signInRoutes,
  });
  await session.fill('fill-password', 'input[name="password"]', password, {
    endpoint: 'core',
    paths: signInRoutes,
  });
  await session.click('submit-sign-in', 'button[name="submit"]', {
    endpoint: 'core',
    paths: signInRoutes,
  });
  await session.waitForRoute('wait-consent', 'core', consentRoute);
  await session.expectText(
    'consent-user',
    exactText(resolved.dataTenant.subject.name),
    resolved.dataTenant.subject.name
  );
  await session.expectText('consent-email', exactText(resolved.email), resolved.email);
  await session.expectText('consent-user-group', exactText('User Scopes'), 'User Scopes');
  await session.expectText(
    'consent-resource-group',
    exactText(resolved.resourceName),
    resolved.resourceName
  );
  await session.click('expand-user-scopes', roleButton('User Scopes'), {
    endpoint: 'core',
    paths: consentRoute,
  });
  await session.click('expand-resource-scopes', roleButton(resolved.resourceName), {
    endpoint: 'core',
    paths: consentRoute,
  });
  await session.expectCount('consent-user-scope-count', scopeItems('User Scopes'), 4);
  await session.expectCount('consent-resource-scope-count', scopeItems(resolved.resourceName), 1);
  await session.expectText(
    'consent-profile-scope',
    exactText('Your name, username, avatar, and other profile info'),
    'Your name, username, avatar, and other profile info'
  );
  await session.expectText(
    'consent-email-scope',
    exactText('Your email address'),
    'Your email address'
  );
  await session.expectText('consent-address-scope', exactText('Your address'), 'Your address');
  await session.expectText(
    'consent-phone-scope',
    exactText('Your phone number'),
    'Your phone number'
  );
  await session.expectText(
    'consent-resource-scope',
    exactText(resolved.scope.description),
    resolved.scope.description
  );
  await session.click('authorize-consent', roleButton('Authorize'), {
    endpoint: 'core',
    paths: consentRoute,
  });
  await session.waitForExactRoute('wait-demo-callback', 'core', demoPath);
  const browserFacts = await session.waitForNetworkFacts(
    'callback-exchange',
    hasInitialBrowserChain
  );
  assertInitialBrowserChain(browserFacts, resolved);
  await session.click('open-dev-panel', roleButton('Open dev panel'), {
    endpoint: 'core',
    paths: demoRoute,
  });
  await session.fill(
    'fill-resource',
    'form:has-text("Refresh token grant") input[name="resource"]',
    resolved.resourceIndicator,
    { endpoint: 'core', paths: demoRoute }
  );
  await session.assertRoute('request-resource', 'core', demoRoute);
  const resourceGrant = await session.clickAndObserveObject(
    'request-resource',
    roleButton('Request token'),
    (value) => projectResourceResult(value, resolved)
  );
  await session.assertRoute('fetch-user', 'core', demoRoute);
  const userProfile = await session.clickAndObserveObject(
    'fetch-user',
    roleButton('Fetch user info'),
    (value) => projectUserResult(value, resolved)
  );
  await waitForActivity(context, resolved.dataTenant.subject.id);
  const afterState = await context.projectState();

  if (!isDeepStrictEqual(afterState, beforeState)) {
    throw new Error(invalidFixtureState);
  }
  const observation = Object.freeze({
    activity: Object.freeze({ lastSignInState: 'present' }),
    callback: Object.freeze({ completed: true, path: '/demo-app' }),
    consent: Object.freeze({
      application: resolved.dataTenant.browserClientConfiguration.localStorageValue.appId,
      permissions: ['profile', 'email', 'address', 'phone'],
      resource: Object.freeze({
        indicator: resolved.dataTenant.resource.indicator,
        permissions: [resolved.scope.name],
      }),
      subject: resolved.dataTenant.subject.id,
    }),
    fixture: Object.freeze({ stable: true }),
    resourceGrant,
    userProfile,
  });

  assertEvidenceIsSanitized(observation);
  return observation;
};

export const experiencePasswordPkceConsent = Object.freeze({
  id: flowId,
  executionGroup: 'experience',
  sourcePaths: experiencePasswordPkceConsentSourcePaths,
  run,
} satisfies Phase1BrowserFlowModule);

export const experiencePasswordPkceConsentFlow = experiencePasswordPkceConsent;

export default experiencePasswordPkceConsent;

/* eslint-enable complexity, max-lines */
