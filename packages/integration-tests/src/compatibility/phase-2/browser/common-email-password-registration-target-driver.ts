/* eslint-disable complexity, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/no-unsafe-assignment -- Parsed discovery values are validated before use. */
import { randomBytes } from 'node:crypto';

import type { TargetConfig } from '../../model.js';
import type { Phase1BrowserGroupObserver } from '../../phase-1/browser/contracts.js';
import { isPlaywrightBrowserGroupObserver } from '../../phase-1/browser/playwright-session.js';
import { withPhase2AdminManagementBearer } from '../clients/admin-management-bearer.js';
import {
  createBearerPhase2AdminRequest,
  createReferencePhase2AdminRequest,
  type Phase2AdminRequestFunction,
  type Phase2FixtureSecretLease,
  type ProvisionedPhase2Fixture,
} from '../fixtures.js';

import { createEmailPasswordRegistrationControlRuntime } from './common-email-password-registration-control-runtime.js';
import {
  commonEmailPasswordRegistrationExpectedControls,
  runCommonEmailPasswordRegistrationControls,
  type CommonEmailPasswordRegistrationControls,
} from './common-email-password-registration-controls.js';
import {
  commonEmailPasswordRegistrationPositiveProjection,
  runCommonEmailPasswordRegistration,
  type CommonEmailPasswordRegistrationPositiveProjection,
} from './common-email-password-registration.js';
import { adaptPhase1SessionForEmailPasswordRegistration } from './email-password-registration-phase1-session-adapter.js';
import type { CommonEmailPasswordBrowserConfiguration } from './fresh-context-password-controls.js';
import { withSelectedEmailPasswordRegistrationFixture } from './selected-email-password-registration-fixture.js';

const fail = (stage: string): never => {
  throw new TypeError(`Common email password registration target failed: ${stage}`);
};
export type CommonEmailPasswordRegistrationTargetProjection =
  CommonEmailPasswordRegistrationPositiveProjection & CommonEmailPasswordRegistrationControls;
export const commonEmailPasswordRegistrationExpectedProjection = Object.freeze({
  ...commonEmailPasswordRegistrationPositiveProjection,
  ...commonEmailPasswordRegistrationExpectedControls,
}) satisfies CommonEmailPasswordRegistrationTargetProjection;

export type CommonEmailPasswordRegistrationTargetInput = Readonly<{
  target: TargetConfig;
  fixture: ProvisionedPhase2Fixture;
  observer: Phase1BrowserGroupObserver;
  signal: AbortSignal;
  browser: Omit<CommonEmailPasswordBrowserConfiguration, 'expectedIssuer'>;
  fetch?: typeof fetch;
}>;

const boundedIssuer = async (target: TargetConfig, requestFetch: typeof fetch): Promise<string> => {
  const response = await requestFetch(
    new URL('/oidc/.well-known/openid-configuration', target.coreUrl),
    { redirect: 'manual', signal: AbortSignal.timeout(10_000) }
  );
  const declared = response.headers.get('content-length');
  if (
    response.status !== 200 ||
    response.redirected ||
    (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > 65_536))
  ) {
    return fail('discovery');
  }
  const text = await response.text();
  if (Buffer.byteLength(text) > 65_536) {
    return fail('discovery');
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return fail('discovery');
  }
  const raw =
    typeof value === 'object' && value !== null ? Reflect.get(value, 'issuer') : undefined;
  if (typeof raw !== 'string') {
    return fail('discovery');
  }
  const issuer = new URL(raw);
  const core = new URL(target.coreUrl);
  if (
    issuer.origin !== core.origin ||
    issuer.pathname !== '/oidc' ||
    issuer.username ||
    issuer.password ||
    issuer.search ||
    issuer.hash
  ) {
    return fail('discovery');
  }
  return issuer.href.replace(/\/$/u, '');
};

export const readEmailPasswordRegisteredUser = async (
  request: Phase2AdminRequestFunction,
  email: string
): Promise<Readonly<{ id: string; hasPassword: true }>> => {
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
      typeof user === 'object' && user !== null && Reflect.get(user, 'primaryEmail') === email
  );
  if (matches.length !== 1) {
    return fail('subject');
  }
  const id = Reflect.get(matches[0] as Record<string, unknown>, 'id');
  const hasPassword = Reflect.get(matches[0] as Record<string, unknown>, 'hasPassword');
  if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/u.test(id) || hasPassword !== true) {
    return fail('subject');
  }
  return Object.freeze({ id, hasPassword: true });
};

const execute = async (
  input: CommonEmailPasswordRegistrationTargetInput
): Promise<CommonEmailPasswordRegistrationTargetProjection> => {
  const status = input.fixture.status ?? fail('admission');
  const redirectUri = new URL('/demo-app', input.target.coreUrl).href;
  const scopes = input.browser.demo.scope.split(' ').filter(Boolean);
  if (
    input.signal.aborted ||
    input.browser.demo.appId !== status.client.id ||
    input.browser.redirectUri !== redirectUri ||
    input.browser.demo.resource !== status.resource.indicator ||
    input.browser.resourceScope !== status.resource.scopeName ||
    input.browser.demo.prompt !== 'consent' ||
    new Set(scopes).size !== scopes.length ||
    !['openid', 'offline_access', 'profile', 'email', status.resource.scopeName].every((scope) =>
      scopes.includes(scope)
    )
  ) {
    return fail('admission');
  }
  const requestFetch = input.fetch ?? fetch;
  const expectedIssuer = await boundedIssuer(input.target, requestFetch);

  const run = async (
    request: Phase2AdminRequestFunction,
    lease: Phase2FixtureSecretLease
  ): Promise<CommonEmailPasswordRegistrationTargetProjection> => {
    const { takeVerificationCode } = lease;
    if (typeof takeVerificationCode !== 'function') {
      return fail('lease');
    }
    let latched: TypeError | undefined;
    try {
      return await withSelectedEmailPasswordRegistrationFixture({
        fixture: input.fixture,
        request,
        browser: { clientId: status.client.id, redirectUri },
        use: async ({
          primaryEmail,
          incompleteEmail,
          rejectedPolicyEmail,
          captureRegisteredUser,
        }) => {
          let subject: string | undefined;
          let bindActiveSubject: ((id: string) => void) | undefined;
          try {
            const positive = await runCommonEmailPasswordRegistration({
              email: primaryEmail,
              getPassword: () => `Aa1!${randomBytes(24).toString('base64url')}`,
              takePasscode: takeVerificationCode,
              readCreatedUser: async () => readEmailPasswordRegisteredUser(request, primaryEmail),
              captureCreatedUser: async (id) => {
                await captureRegisteredUser(id);
                subject = id;
                bindActiveSubject?.(id);
              },
              withFreshSession: async (use) =>
                input.observer.runInFreshContext(
                  'experience',
                  input.signal,
                  input.target,
                  async (phase1) => {
                    const adapted = adaptPhase1SessionForEmailPasswordRegistration(phase1, {
                      ...input.browser,
                      expectedIssuer,
                      canonicalEmail: primaryEmail,
                      resource: status.resource.indicator,
                    });
                    bindActiveSubject = adapted.bindRegisteredSubject;
                    if (subject) {
                      adapted.bindRegisteredSubject(subject);
                    }
                    try {
                      return await use(adapted.session);
                    } finally {
                      bindActiveSubject = undefined;
                    }
                  }
                ),
            });
            const controls = await runCommonEmailPasswordRegistrationControls(
              createEmailPasswordRegistrationControlRuntime({
                target: input.target,
                request,
                clientId: status.client.id,
                redirectUri,
                takePasscode: takeVerificationCode,
                fetch: requestFetch,
              }),
              { incompleteEmail, duplicateEmail: primaryEmail, rejectedPolicyEmail }
            );
            return Object.freeze({ ...positive, ...controls });
          } catch (error: unknown) {
            const message = error instanceof Error ? error.message : '';
            const flow = /^Common email password registration failed: ([a-z-]+)$/u.exec(
              message
            )?.[1];
            const controls =
              /^Common email password registration controls failed: ([a-z-]+)$/u.exec(message)?.[1];
            latched = new TypeError(
              `Common email password registration target failed: ${flow ? `flow-${flow}` : controls ? `controls-${controls}` : 'browser'}`
            );
            throw error;
          }
        },
      });
    } catch (error: unknown) {
      if (
        error instanceof Error &&
        error.message.startsWith('Email password registration fixture failed: cleanup-')
      ) {
        return fail('cleanup');
      }
      if (latched) {
        throw latched;
      }
      return fail('fixture');
    }
  };

  if (input.target.label === 'oracle') {
    return input.fixture.withSecretLease(async (lease) =>
      run(createReferencePhase2AdminRequest(input.target, requestFetch), lease)
    );
  }
  let consumer: TypeError | undefined;
  try {
    return await withPhase2AdminManagementBearer(
      input.target,
      input.fixture,
      async (bearer, lease) => {
        try {
          return await run(
            createBearerPhase2AdminRequest(input.target, bearer, requestFetch),
            lease
          );
        } catch (error: unknown) {
          if (
            error instanceof TypeError &&
            error.message.startsWith('Common email password registration target failed:')
          ) {
            consumer = error;
          }
          throw error;
        }
      },
      { fetch: requestFetch }
    );
  } catch {
    if (consumer) {
      throw consumer;
    }
    return fail('admin');
  }
};

export const runCommonEmailPasswordRegistrationForTarget = async (
  input: CommonEmailPasswordRegistrationTargetInput
): Promise<CommonEmailPasswordRegistrationTargetProjection> => {
  if (!isPlaywrightBrowserGroupObserver(input.observer)) {
    return fail('capability');
  }
  return execute(input);
};

export const runCommonEmailPasswordRegistrationForTargetTesting = async (
  input: CommonEmailPasswordRegistrationTargetInput
): Promise<CommonEmailPasswordRegistrationTargetProjection> => {
  if (process.env.NODE_ENV !== 'test') {
    return fail('capability');
  }
  return execute(input);
};
/* eslint-enable complexity, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/no-unsafe-assignment */
