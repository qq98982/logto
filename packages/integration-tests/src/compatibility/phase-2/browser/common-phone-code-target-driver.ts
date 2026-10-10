/* eslint-disable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/no-unsafe-assignment -- JSON and Management payloads are narrowed immediately at the boundary. */
import type { TargetConfig } from '../../model.js';
import type {
  Phase1BrowserGroupObserver,
  Phase1BrowserSession,
} from '../../phase-1/browser/contracts.js';
import { isPlaywrightBrowserGroupObserver } from '../../phase-1/browser/playwright-session.js';
import { withPhase2AdminManagementBearer } from '../clients/admin-management-bearer.js';
import {
  createBearerPhase2AdminRequest,
  createReferencePhase2AdminRequest,
  type Phase2AdminRequestFunction,
  type ProvisionedPhase2Fixture,
} from '../fixtures.js';

import { runCommonPhoneCodeHttpControls } from './common-phone-code-controls.js';
import {
  assertCommonPhoneCodeControls,
  runCommonPhoneCodeRegistration,
  runCommonPhoneCodeSignIn,
  type CommonPhoneCodeControls,
  type CommonPhoneCodeProjection,
} from './common-phone-code.js';
import {
  adaptPhase1SessionForPhoneCode,
  type PhoneCodeBrowserConfiguration,
} from './phone-code-phase1-session-adapter.js';
import {
  type CommonPhoneCodeProviderLease,
  withSelectedPhoneCodeFixture,
} from './selected-phone-code-fixture.js';

const fail = (stage: string): never => {
  throw new TypeError(`Common phone code target failed: ${stage}`);
};

const closedPhoneConsumerStage = (error: unknown): string | undefined => {
  if (!(error instanceof Error)) {
    return undefined;
  }
  const descriptor = Object.getOwnPropertyDescriptor(error, 'message');
  const message: unknown = descriptor?.value;
  if (typeof message !== 'string') {
    return undefined;
  }
  const fixture =
    /^Selected phone code fixture failed: (read-sie|get-app|patch-app|read-resource|create-role|create-connector|patch-sie|create-owner|create-control-owner|create-collision-owner|create-suspended|assign-role|registration-owner-before|use(?:-(?:sign-in|registration)-(?:input|initialization|identifier|delivery|code-format|code-fill|consent|callback|profile|refresh|subject))?|cleanup-(?:discover-registered-ambiguous|discover-registered|delete-registered|delete-suspended|delete-collision-owner|delete-control-owner|delete-owner|delete-role|delete-connector|restore-sie|restore-app|registered-owner-remains|read-registered-owner-after)(?:\+(?:discover-registered-ambiguous|discover-registered|delete-registered|delete-suspended|delete-collision-owner|delete-control-owner|delete-owner|delete-role|delete-connector|restore-sie|restore-app|registered-owner-remains|read-registered-owner-after))*)$/u.exec(
      message
    )?.[1];
  if (fixture) {
    return fixture.startsWith('use-') ? `flow-${fixture.slice(4)}` : `fixture-${fixture}`;
  }
  return /^Common phone code target failed: (admission|capability|discovery|subject)$/u.exec(
    message
  )?.[1];
};

const phoneAdminStage = (error: unknown): string | undefined => {
  if (!(error instanceof Error)) {
    return undefined;
  }
  const descriptor = Object.getOwnPropertyDescriptor(error, 'message');
  const message: unknown = descriptor?.value;
  return typeof message === 'string'
    ? /^Invalid Phase 2 Admin Management bearer flow \((admission|authorization|bootstrap|password|identification|submit|bridge|consent|resume|code-token|management-refresh|jwks|consumer)\)$/u.exec(
        message
      )?.[1]
    : undefined;
};

export const runCommonPhoneCodeAdminBoundary = async <Result>(
  runAdmin: (capture: (operation: () => Promise<Result>) => Promise<Result>) => Promise<Result>
): Promise<Result> => {
  let consumerStage: string | undefined;
  try {
    return await runAdmin(async (operation) => {
      try {
        return await operation();
      } catch (error: unknown) {
        consumerStage = closedPhoneConsumerStage(error);
        throw error;
      }
    });
  } catch (error: unknown) {
    if (consumerStage) {
      return fail(`admin-consumer-${consumerStage}`);
    }
    const stage = phoneAdminStage(error);
    return fail(stage && stage !== 'consumer' ? `admin-${stage}` : 'other');
  }
};

export const runCommonPhoneCodeInFreshContext = async <Result>(
  observer: Phase1BrowserGroupObserver,
  signal: AbortSignal,
  target: TargetConfig,
  use: (session: Phase1BrowserSession) => Promise<Result>
): Promise<Result> => {
  let closedStage: string | undefined;
  try {
    return await observer.runInFreshContext('experience', signal, target, async (session) => {
      try {
        return await use(session);
      } catch (error: unknown) {
        closedStage = closedPhoneConsumerStage(error);
        throw error;
      }
    });
  } catch {
    return fail(closedStage ?? 'browser');
  }
};

export type CommonPhoneCodeScenario = 'registration' | 'sign-in';
export type CommonPhoneCodeScenarioProjection = Readonly<{
  flow: CommonPhoneCodeProjection['registration'] | CommonPhoneCodeProjection['signIn'];
  controls: CommonPhoneCodeControls;
}>;

export type CommonPhoneCodeTargetInput = Readonly<{
  scenario: CommonPhoneCodeScenario;
  target: TargetConfig;
  fixture: ProvisionedPhase2Fixture;
  observer: Phase1BrowserGroupObserver;
  signal: AbortSignal;
  browser: Omit<PhoneCodeBrowserConfiguration, 'expectedIssuer' | 'resource'>;
  fetch?: typeof fetch;
  withProviderLease<Result>(
    use: (lease: CommonPhoneCodeProviderLease) => Promise<Result>
  ): Promise<Result>;
  runControls?(
    input: Readonly<{
      request: Phase2AdminRequestFunction;
      lease: CommonPhoneCodeProviderLease;
      owner: Readonly<{ id: string; primaryPhone: string }>;
      collisionOwner: Readonly<{ id: string; primaryPhone: string }>;
      suspended: Readonly<{ id: string; primaryPhone: string }>;
    }>
  ): Promise<CommonPhoneCodeControls>;
}>;

const discoverIssuer = async (
  target: TargetConfig,
  requestFetch: typeof fetch
): Promise<string> => {
  const response = await requestFetch(
    new URL('/oidc/.well-known/openid-configuration', target.coreUrl),
    {
      redirect: 'manual',
      signal: AbortSignal.timeout(10_000),
    }
  );
  if (response.status !== 200 || response.redirected) {
    await response.body?.cancel().catch(() => false);
    return fail('discovery');
  }
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > 16 * 1024)) {
    await response.body?.cancel().catch(() => false);
    return fail('discovery');
  }
  const text = await response.text();
  if (Buffer.byteLength(text) > 16 * 1024) {
    return fail('discovery');
  }
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return fail('discovery');
  }
  const value = typeof body === 'object' && body !== null ? Reflect.get(body, 'issuer') : undefined;
  if (typeof value !== 'string') {
    return fail('discovery');
  }
  const issuer = new URL(value);
  const core = new URL(target.coreUrl);
  if (
    issuer.origin !== core.origin ||
    issuer.pathname !== '/oidc' ||
    issuer.search ||
    issuer.hash
  ) {
    return fail('discovery');
  }
  return issuer.href.replace(/\/$/u, '');
};

export const readRegisteredUserByPhone = async (
  request: Phase2AdminRequestFunction,
  phone: string
): Promise<Readonly<{ id: string; primaryPhone: string }>> => {
  const users = await request({
    method: 'GET',
    path: 'users',
    query: { page: '1', page_size: '100' },
    expectedStatuses: [200],
    responseKind: 'array',
  });
  if (!Array.isArray(users) || users.length >= 100) {
    return fail('subject');
  }
  const matches = users.filter(
    (user) =>
      typeof user === 'object' && user !== null && Reflect.get(user, 'primaryPhone') === phone
  );
  const match: unknown = matches[0];
  const id =
    matches.length === 1 && typeof match === 'object' && match !== null
      ? Reflect.get(match, 'id')
      : undefined;
  if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/u.test(id)) {
    return fail('subject');
  }
  return Object.freeze({ id, primaryPhone: phone });
};

const execute = async (
  input: CommonPhoneCodeTargetInput
): Promise<CommonPhoneCodeScenarioProjection> => {
  const status = input.fixture.status ?? fail('admission');
  const redirectUri = new URL('/demo-app', input.target.coreUrl).href;
  const requested = input.browser.demo.scope.split(' ').filter(Boolean);
  const initial = input.browser.initialResponseScope.split(' ').filter(Boolean);
  const expected = ['openid', 'offline_access', 'profile', 'phone', status.resource.scopeName];
  if (
    input.browser.demo.appId !== status.client.id ||
    input.browser.redirectUri !== redirectUri ||
    input.browser.demo.resource !== status.resource.indicator ||
    input.browser.resourceScope !== status.resource.scopeName ||
    input.browser.demo.prompt !== 'consent' ||
    requested.length !== expected.length ||
    !expected.every((scope) => requested.includes(scope)) ||
    !isDeepScope(initial, ['openid', 'offline_access', 'profile', 'phone'])
  ) {
    return fail('admission');
  }
  const requestFetch = input.fetch ?? fetch;
  const issuer = await discoverIssuer(input.target, requestFetch);
  const run = async (request: Phase2AdminRequestFunction, lease: CommonPhoneCodeProviderLease) =>
    withSelectedPhoneCodeFixture({
      fixture: input.fixture,
      request,
      lease,
      browser: { clientId: status.client.id, redirectUri },
      use: async (selected) => {
        const runInContext = async <Result>(
          operation: (session: Phase1BrowserSession) => Promise<Result>
        ) =>
          runCommonPhoneCodeInFreshContext(input.observer, input.signal, input.target, operation);
        const configuration = {
          ...input.browser,
          expectedIssuer: issuer,
          resource: status.resource.indicator,
        };
        const projection =
          input.scenario === 'sign-in'
            ? await runInContext(async (phase1) =>
                runCommonPhoneCodeSignIn({
                  session: adaptPhase1SessionForPhoneCode(phase1, configuration, selected.owner.id),
                  phone: selected.owner.primaryPhone,
                  nationalPhone: selected.owner.primaryPhone.slice(2),
                  expectedSubject: selected.owner.id,
                  arm: lease.arm,
                  takeCode: lease.takeCode,
                })
              )
            : await runInContext(async (phase1) => {
                let subject = '';
                return runCommonPhoneCodeRegistration({
                  session: adaptPhase1SessionForPhoneCode(phase1, configuration, () => subject),
                  phone: selected.registrationPhone,
                  nationalPhone: selected.registrationNationalPhone,
                  arm: lease.arm,
                  takeCode: lease.takeCode,
                  readSubject: async (phone) => readRegisteredUserByPhone(request, phone),
                  captureSubject: async (id) => {
                    await selected.captureRegisteredUser(id);
                    subject = id;
                  },
                });
              });
        const controlInput = {
          request,
          lease,
          owner: selected.controlOwner,
          collisionOwner: selected.collisionOwner,
          suspended: selected.suspended,
        };
        const controls = assertCommonPhoneCodeControls(
          input.runControls
            ? await input.runControls(controlInput)
            : await runCommonPhoneCodeHttpControls({
                ...controlInput,
                target: input.target,
                fixture: input.fixture,
                redirectUri,
                fetch: requestFetch,
              })
        );
        return Object.freeze({ flow: projection, controls });
      },
    });
  return input.withProviderLease(async (lease) => {
    if (input.target.label === 'candidate') {
      return runCommonPhoneCodeAdminBoundary(async (capture) =>
        withPhase2AdminManagementBearer(
          input.target,
          input.fixture,
          async (bearer) =>
            capture(async () =>
              run(createBearerPhase2AdminRequest(input.target, bearer, requestFetch), lease)
            ),
          { fetch: requestFetch }
        )
      );
    }
    return run(createReferencePhase2AdminRequest(input.target, requestFetch), lease);
  });
};

const isDeepScope = (actual: readonly string[], expected: readonly string[]): boolean =>
  actual.length === expected.length &&
  new Set(actual).size === actual.length &&
  expected.every((scope) => actual.includes(scope));

export const runCommonPhoneCodeForTarget = async (
  input: CommonPhoneCodeTargetInput
): Promise<CommonPhoneCodeScenarioProjection> => {
  if (!isPlaywrightBrowserGroupObserver(input.observer)) {
    return fail('capability');
  }
  return execute(input);
};

export const runCommonPhoneCodeForTargetTesting = async (
  input: CommonPhoneCodeTargetInput
): Promise<CommonPhoneCodeScenarioProjection> => {
  if (process.env.NODE_ENV !== 'test') {
    return fail('capability');
  }
  return execute(input);
};
/* eslint-enable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/no-unsafe-assignment */
