/* eslint-disable complexity, max-lines, no-await-in-loop, no-constant-condition, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unnecessary-condition, @typescript-eslint/no-unsafe-assignment -- Discovery, authenticated lookup, browser context, and fixture compensation form one target boundary. */
import { types as nodeTypes } from 'node:util';

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

import {
  runEmailCodeRegistrationControls,
  type EmailCodeRegistrationControls,
} from './common-email-code-registration-controls.js';
import {
  commonEmailCodeRegistrationExpectedProjection as commonEmailCodeRegistrationPositiveProjection,
  runCommonEmailCodeRegistration,
  type CommonEmailCodeRegistrationProjection,
} from './common-email-code-registration.js';
import { createEmailCodeRegistrationControlRuntime } from './email-code-registration-control-runtime.js';
import { adaptPhase1SessionForEmailCodeRegistration } from './email-code-registration-phase1-session-adapter.js';
import {
  observeRegisterVerificationReplay,
  type RegistrationReplayObservation,
} from './email-code-registration-replay-probe.js';
import type { CommonEmailPasswordBrowserConfiguration } from './fresh-context-password-controls.js';
import {
  registrationEmailForAllocation,
  withSelectedEmailCodeRegistrationFixture,
} from './selected-email-code-registration-fixture.js';

const fail = (stage: string): never => {
  throw new TypeError(`Common email code registration target failed: ${stage}`);
};

export type CommonEmailCodeRegistrationTargetProjection = CommonEmailCodeRegistrationProjection &
  EmailCodeRegistrationControls &
  Readonly<{ verificationReplay: RegistrationReplayObservation }>;

export const commonEmailCodeRegistrationExpectedProjection = Object.freeze({
  ...commonEmailCodeRegistrationPositiveProjection,
  noImplicitRegistration: Object.freeze({
    requestStatus: 200,
    verifyStatus: 200,
    identificationStatus: 404,
    error: 'user.user_not_exist',
    beforeCount: 0,
    afterCount: 0,
  }),
  occupiedRegistration: Object.freeze({
    requestStatus: 200,
    verifyStatus: 200,
    identificationStatus: 422,
    error: 'user.email_already_in_use',
    beforeCount: 1,
    afterCount: 1,
    ownerUnchanged: true,
  }),
  verificationReplay: Object.freeze({
    first: Object.freeze({ status: 's200', outcome: 'verified', error: 'none' }),
    second: Object.freeze({
      status: 's400',
      outcome: 'error',
      error: 'verification_code.not_found',
    }),
  }),
}) satisfies CommonEmailCodeRegistrationTargetProjection;
const ownErrorMessage = (error: unknown): string | undefined => {
  if (nodeTypes.isProxy(error) || !(error instanceof Error)) {
    return undefined;
  }
  const descriptor = Object.getOwnPropertyDescriptor(error, 'message');
  const value: unknown =
    descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
  return typeof value === 'string' ? value : undefined;
};
const flowStage = (error: unknown): string | undefined =>
  /^Common email code registration stage failed: (initialization|register-route|identifier-submit|verification-route(?:-(?:init|send)-s[1-5][0-9]{2}-(?:none|guard-invalid-input|session-interaction-not-found|request-message-rate-limited|connector-not-found|connector-invalid-config|connector-general|other))?|passcode-retrieval(?:-(?:env-missing|socket-shape|recipient|connect|timeout|not-found|response))?|passcode-format|passcode-fill|registration-subject|registration-capture|consent|callback(?:-(?:callback-route|callback-facts-s(?:0|1|many)-c(?:0|1|many)-i(?:0|1|many)|cardinality|signin-(?:authority|response|client|redirect|mode|scope|resource|pkce)|callback-(?:authority|response|state|issuer|code)|exchange-(?:authority|response|correlation|client|refresh|target|scope|access)))?|profile|refresh)$/u.exec(
    ownErrorMessage(error) ?? ''
  )?.[1];
const controlStage = (error: unknown): string | undefined =>
  /^Common email code registration controls failed: (admission|signin-before|signin-proof(?:-(?:auth|init|request|verify)-(?:s[1-5][0-9]{2}|unavailable)-(?:none|guard-invalid-input|session-interaction-not-found|request-message-rate-limited|connector-not-found|connector-invalid-config|connector-general|other))?|signin-identification(?:-identify-(?:s[1-5][0-9]{2}|unavailable)-(?:none|guard-invalid-input|session-interaction-not-found|request-message-rate-limited|connector-not-found|connector-invalid-config|connector-general|user-user-not-exist|user-email-already-in-use|other))?|signin-after|register-before|register-proof(?:-(?:auth|init|request|verify)-(?:s[1-5][0-9]{2}|unavailable)-(?:none|guard-invalid-input|session-interaction-not-found|request-message-rate-limited|connector-not-found|connector-invalid-config|connector-general|other))?|register-identification(?:-identify-(?:s[1-5][0-9]{2}|unavailable)-(?:none|guard-invalid-input|session-interaction-not-found|request-message-rate-limited|connector-not-found|connector-invalid-config|connector-general|user-user-not-exist|user-email-already-in-use|other))?|register-after)$/u.exec(
    ownErrorMessage(error) ?? ''
  )?.[1];
const fixtureFailure = (error: unknown) => {
  if (!(error instanceof Error)) {
    return;
  }
  const primary =
    /^Email code registration fixture failed: primary-(read-sie|read-app|patch-app|read-resource|create-role|patch-sie|use|read-user-roles);cleanup-(none|restore-sie|restore-app|delete-user|delete-role)(?:\+(?:restore-sie|restore-app|delete-user|delete-role))*$/u.exec(
      error.message
    );
  if (primary?.[1] && primary[2]) {
    return { primary: primary[1], cleanup: primary[2] };
  }
  return /^Email code registration fixture failed: cleanup-(restore-sie|restore-app|delete-user|delete-role)(?:\+(?:restore-sie|restore-app|delete-user|delete-role))*$/u.test(
    error.message
  )
    ? { primary: 'cleanup', cleanup: 'cleanup' }
    : undefined;
};
const closedTargetMessage = (error: unknown): string | undefined => {
  const message = ownErrorMessage(error) ?? '';
  return /^Common email code registration target failed: (admission|capability|discovery|subject|lease|browser|cleanup|admin|fixture-(?:read-sie|read-app|patch-app|read-resource|create-role|patch-sie|use|read-user-roles|cleanup)|controls-(?:admission|signin-before|signin-proof(?:-(?:auth|init|request|verify)-(?:s[1-5][0-9]{2}|unavailable)-(?:none|guard-invalid-input|session-interaction-not-found|request-message-rate-limited|connector-not-found|connector-invalid-config|connector-general|other))?|signin-identification(?:-identify-(?:s[1-5][0-9]{2}|unavailable)-(?:none|guard-invalid-input|session-interaction-not-found|request-message-rate-limited|connector-not-found|connector-invalid-config|connector-general|user-user-not-exist|user-email-already-in-use|other))?|signin-after|register-before|register-proof(?:-(?:auth|init|request|verify)-(?:s[1-5][0-9]{2}|unavailable)-(?:none|guard-invalid-input|session-interaction-not-found|request-message-rate-limited|connector-not-found|connector-invalid-config|connector-general|other))?|register-identification(?:-identify-(?:s[1-5][0-9]{2}|unavailable)-(?:none|guard-invalid-input|session-interaction-not-found|request-message-rate-limited|connector-not-found|connector-invalid-config|connector-general|user-user-not-exist|user-email-already-in-use|other))?|register-after)|flow-(?:initialization|register-route|identifier-submit|verification-route(?:-(?:init|send)-s[1-5][0-9]{2}-(?:none|guard-invalid-input|session-interaction-not-found|request-message-rate-limited|connector-not-found|connector-invalid-config|connector-general|other))?|passcode-retrieval(?:-(?:env-missing|socket-shape|recipient|connect|timeout|not-found|response))?|passcode-format|passcode-fill|registration-subject|registration-capture|consent|callback(?:-(?:callback-route|callback-facts-s(?:0|1|many)-c(?:0|1|many)-i(?:0|1|many)|cardinality|signin-(?:authority|response|client|redirect|mode|scope|resource|pkce)|callback-(?:authority|response|state|issuer|code)|exchange-(?:authority|response|correlation|client|refresh|target|scope|access)))?|profile|refresh))$/u.test(
    message
  )
    ? message
    : undefined;
};
const boundedBody = async (response: Response): Promise<Uint8Array> => {
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > 65_536)) {
    return fail('discovery');
  }
  const reader = response.body?.getReader() ?? fail('discovery');
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) {
        break;
      }
      size += chunk.value.byteLength;
      if (size > 65_536) {
        return fail('discovery');
      }
      chunks.push(chunk.value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
};

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
    return fail('discovery');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(
      new TextDecoder('utf8', { fatal: true }).decode(await boundedBody(response))
    );
  } catch {
    return fail('discovery');
  }
  const raw = typeof parsed === 'object' && parsed !== null ? Reflect.get(parsed, 'issuer') : null;
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

export const readRegisteredUserByEmail = async (
  request: Phase2AdminRequestFunction,
  email: string
): Promise<Readonly<{ id: string; primaryEmail: string }>> => {
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
  const match = matches[0];
  if (typeof match !== 'object' || match === null) {
    return fail('subject');
  }
  const id = Reflect.get(match, 'id');
  if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/u.test(id)) {
    return fail('subject');
  }
  return Object.freeze({ id, primaryEmail: email });
};

export type CommonEmailCodeRegistrationTargetInput = Readonly<{
  target: TargetConfig;
  fixture: ProvisionedPhase2Fixture;
  observer: Phase1BrowserGroupObserver;
  signal: AbortSignal;
  browser: Omit<CommonEmailPasswordBrowserConfiguration, 'expectedIssuer'>;
  fetch?: typeof fetch;
  captureReferenceReplay?(observation: RegistrationReplayObservation): Promise<void>;
}>;

const execute = async (
  input: CommonEmailCodeRegistrationTargetInput
): Promise<CommonEmailCodeRegistrationTargetProjection> => {
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
  const expectedIssuer = await discoverIssuer(input.target, requestFetch);
  const canonicalEmail = registrationEmailForAllocation(input.fixture.public.allocationId);
  const run = async (request: Phase2AdminRequestFunction, lease: Phase2FixtureSecretLease) => {
    let latched: TypeError | undefined;
    let latchedFlow: string | undefined;
    let latchedControl: string | undefined;
    try {
      return await input.observer.runInFreshContext(
        'experience',
        input.signal,
        input.target,
        async (phase1) => {
          try {
            const adapted = adaptPhase1SessionForEmailCodeRegistration(phase1, {
              ...input.browser,
              expectedIssuer,
              canonicalEmail,
              resource: status.resource.indicator,
            });
            return await withSelectedEmailCodeRegistrationFixture({
              fixture: input.fixture,
              request,
              browser: { clientId: status.client.id, redirectUri },
              use: async ({ primaryEmail, captureRegisteredUser }) => {
                try {
                  const projection = await runCommonEmailCodeRegistration({
                    session: adapted.session,
                    email: primaryEmail,
                    takePasscode: async (recipient) => {
                      if (typeof lease.takeVerificationCode !== 'function') {
                        return fail('lease');
                      }
                      return lease.takeVerificationCode(recipient);
                    },
                    readRegistrationSubject: async (email) =>
                      readRegisteredUserByEmail(request, email),
                    captureRegisteredUser: async (id) => {
                      await captureRegisteredUser(id);
                      adapted.bindRegisteredSubject(id);
                    },
                  });
                  const controls = await runEmailCodeRegistrationControls(
                    createEmailCodeRegistrationControlRuntime({
                      target: input.target,
                      request,
                      clientId: status.client.id,
                      redirectUri,
                      takePasscode: async (recipient) => {
                        if (typeof lease.takeVerificationCode !== 'function') {
                          return fail('lease');
                        }
                        return lease.takeVerificationCode(recipient);
                      },
                      fetch: requestFetch,
                    }),
                    {
                      missingEmail: registrationEmailForAllocation(
                        `${input.fixture.public.allocationId}-missing`
                      ),
                      occupiedEmail: primaryEmail,
                    }
                  );
                  const verificationReplay = await observeRegisterVerificationReplay({
                    target: input.target,
                    clientId: status.client.id,
                    redirectUri,
                    email: registrationEmailForAllocation(
                      `${input.fixture.public.allocationId}-replay`
                    ),
                    takePasscode: async (recipient) => {
                      if (typeof lease.takeVerificationCode !== 'function') {
                        return fail('lease');
                      }
                      return lease.takeVerificationCode(recipient);
                    },
                    fetch: requestFetch,
                  });
                  if (input.captureReferenceReplay) {
                    await input.captureReferenceReplay(verificationReplay);
                  }
                  return Object.freeze({ ...projection, ...controls, verificationReplay });
                } catch (error: unknown) {
                  latchedFlow = flowStage(error);
                  latchedControl = controlStage(error);
                  throw error;
                }
              },
            });
          } catch (error: unknown) {
            const fixture = fixtureFailure(error);
            if (fixture?.cleanup !== undefined && fixture.cleanup !== 'none') {
              latched = new TypeError(
                'Common email code registration target failed: fixture-cleanup'
              );
            } else if (fixture?.primary === 'use' && latchedControl) {
              latched = new TypeError(
                `Common email code registration target failed: controls-${latchedControl}`
              );
            } else if (fixture?.primary === 'use' && latchedFlow) {
              latched = new TypeError(
                `Common email code registration target failed: flow-${latchedFlow}`
              );
            } else if (fixture) {
              latched = new TypeError(
                `Common email code registration target failed: fixture-${fixture.primary}`
              );
            }
            throw error;
          }
        }
      );
    } catch (error: unknown) {
      if (error instanceof AggregateError) {
        return fail('cleanup');
      }
      if (latched) {
        throw latched;
      }
      return fail('browser');
    }
  };
  if (input.target.label === 'candidate') {
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
            const message = closedTargetMessage(error);
            if (message) {
              consumer = new TypeError(message);
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
  }
  return input.fixture.withSecretLease(async (lease) =>
    run(createReferencePhase2AdminRequest(input.target, requestFetch), lease)
  );
};

export const runCommonEmailCodeRegistrationForTarget = async (
  input: CommonEmailCodeRegistrationTargetInput
): Promise<CommonEmailCodeRegistrationTargetProjection> => {
  if (!isPlaywrightBrowserGroupObserver(input.observer)) {
    return fail('capability');
  }
  return execute(input);
};

export const runCommonEmailCodeRegistrationForTargetTesting = async (
  input: CommonEmailCodeRegistrationTargetInput
): Promise<CommonEmailCodeRegistrationTargetProjection> => {
  if (process.env.NODE_ENV !== 'test') {
    return fail('capability');
  }
  return execute(input);
};
/* eslint-enable complexity, max-lines, no-await-in-loop, no-constant-condition, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unnecessary-condition, @typescript-eslint/no-unsafe-assignment */
