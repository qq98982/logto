/* eslint-disable complexity, no-await-in-loop, no-constant-condition, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unnecessary-condition, @typescript-eslint/no-unsafe-assignment -- One target composition owns bounded discovery, admin authority, fixture secrets, browser contexts, and closed HTTP controls. */
import { randomBytes } from 'node:crypto';

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
  type Phase2FixtureSecretLease,
  type ProvisionedPhase2Fixture,
} from '../fixtures.js';

import {
  commonEmailRecoveryExpectedControls,
  createEmailRecoveryControlRuntime,
  runCommonEmailRecoveryControls,
  type EmailRecoveryControlsProjection,
} from './common-email-recovery-controls.js';
import {
  commonEmailRecoveryExpectedFlowProjection,
  runCommonEmailRecovery,
  type CommonEmailRecoveryProjection,
} from './common-email-recovery.js';
import { adaptPhase1SessionForEmailRecovery } from './email-recovery-phase1-session-adapter.js';
import type { CommonEmailPasswordBrowserConfiguration } from './fresh-context-password-controls.js';
import { withSelectedEmailRecoveryFixture } from './selected-email-recovery-fixture.js';

const fail = (stage: string): never => {
  throw new TypeError(`Common email recovery target failed: ${stage}`);
};

export type CommonEmailRecoveryTargetProjection = CommonEmailRecoveryProjection &
  EmailRecoveryControlsProjection;

export const commonEmailRecoveryExpectedProjection = Object.freeze({
  ...commonEmailRecoveryExpectedFlowProjection,
  ...commonEmailRecoveryExpectedControls,
}) satisfies CommonEmailRecoveryTargetProjection;

export const commonEmailRecoveryTargetFailureStage = (error: unknown): string => {
  if (error instanceof AggregateError) {
    const descriptor = Object.getOwnPropertyDescriptor(error, 'errors');
    const members: unknown =
      descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
    const first = Array.isArray(members) ? members[0] : undefined;
    const inner = first === undefined ? 'cleanup' : commonEmailRecoveryTargetFailureStage(first);
    return inner === 'cleanup' || inner === 'fixture'
      ? 'cleanup'
      : inner.endsWith('-cleanup')
        ? inner
        : `${inner}-cleanup`;
  }
  const message = error instanceof Error ? error.message : '';
  const context = /^Common email recovery context failed: ([a-z0-9-]+)$/u.exec(message)?.[1];
  if (context) {
    return context;
  }
  const recovery = /^Common email recovery failed: ([a-z0-9-]+)$/u.exec(message)?.[1];
  if (recovery) {
    return `flow-${recovery}`;
  }
  const controls = /^Common email recovery controls failed: (replay|wrong-purpose)$/u.exec(
    message
  )?.[1];
  if (controls) {
    return `controls-${controls}`;
  }
  const selected = /^Selected email recovery fixture failed: ([a-z0-9-]+)$/u.exec(message)?.[1];
  if (selected) {
    return `fixture-${selected}`;
  }
  const password =
    /^Common email password fixture failed: primary-([a-z0-9-]+);cleanup-([a-z0-9+-]+);flow-([a-z0-9-]+)$/u.exec(
      message
    );
  if (password) {
    const [, primary, cleanup, flow] = password;
    if (flow !== 'none') {
      const stage = `flow-${flow}`;
      return cleanup !== 'none' && !stage.endsWith('-cleanup') ? `${stage}-cleanup` : stage;
    }
    return cleanup === 'none' ? `fixture-password-${primary}` : 'cleanup';
  }
  if (message === 'Invalid selected email password fixture') {
    return 'fixture-password';
  }
  if (message.startsWith('Invalid Phase 2 Admin Management')) {
    return 'admin';
  }
  return 'fixture';
};

export const combineEmailRecoveryContextFailure = (
  callbackError: unknown,
  contextError: unknown
): unknown => {
  if (callbackError === undefined || callbackError === contextError) {
    return contextError;
  }
  if (!(contextError instanceof AggregateError)) {
    return callbackError;
  }
  return new TypeError(
    `Common email recovery context failed: ${commonEmailRecoveryTargetFailureStage(callbackError)}-cleanup`
  );
};

const discoverIssuer = async (
  target: TargetConfig,
  requestFetch: typeof fetch
): Promise<string> => {
  const response = await requestFetch(
    new URL('/oidc/.well-known/openid-configuration', target.coreUrl),
    { redirect: 'manual', signal: AbortSignal.timeout(10_000) }
  );
  if (response.status !== 200 || response.redirected) {
    return fail('discovery');
  }
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > 65_536)) {
    await response.body?.cancel().catch(() => false);
    return fail('discovery');
  }
  const reader = response.body?.getReader() ?? fail('discovery');
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) {
        break;
      }
      length += chunk.value.byteLength;
      if (length > 65_536) {
        await reader.cancel().catch(() => false);
        return fail('discovery');
      }
      chunks.push(chunk.value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let body: unknown;
  try {
    body = JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes));
  } catch {
    return fail('discovery');
  }
  const raw = typeof body === 'object' && body !== null ? Reflect.get(body, 'issuer') : undefined;
  const issuer = typeof raw === 'string' ? new URL(raw) : fail('discovery');
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

export type CommonEmailRecoveryTargetInput = Readonly<{
  target: TargetConfig;
  fixture: ProvisionedPhase2Fixture;
  signal: AbortSignal;
  browser: Omit<CommonEmailPasswordBrowserConfiguration, 'expectedIssuer'>;
  fetch?: typeof fetch;
  observer: Phase1BrowserGroupObserver;
}>;

export const runCommonEmailRecoveryForTarget = async (
  input: CommonEmailRecoveryTargetInput
): Promise<CommonEmailRecoveryTargetProjection> => {
  const status = input.fixture.status ?? fail('admission');
  const redirectUri = new URL('/demo-app', input.target.coreUrl).href;
  const requestedScopes = input.browser.demo.scope.split(' ').filter(Boolean);
  if (
    input.signal.aborted ||
    input.browser.demo.appId !== status.client.id ||
    input.browser.redirectUri !== redirectUri ||
    input.browser.demo.resource !== status.resource.indicator ||
    input.browser.resourceScope !== status.resource.scopeName ||
    input.browser.demo.prompt !== 'consent' ||
    new Set(requestedScopes).size !== requestedScopes.length ||
    !['openid', 'offline_access', 'profile', 'email', status.resource.scopeName].every((scope) =>
      requestedScopes.includes(scope)
    )
  ) {
    return fail('admission');
  }
  if (!isPlaywrightBrowserGroupObserver(input.observer)) {
    return fail('observer');
  }
  const requestFetch = input.fetch ?? fetch;
  const expectedIssuer = await discoverIssuer(input.target, requestFetch);

  const execute = async (request: Phase2AdminRequestFunction, lease: Phase2FixtureSecretLease) => {
    const getOldPassword = lease.getSelectedEmailPassword ?? fail('lease');
    const takeVerificationCode = lease.takeVerificationCode ?? fail('lease');
    const newPassword = `Aa1!${randomBytes(24).toString('base64url')}`;
    return withSelectedEmailRecoveryFixture({
      fixture: input.fixture,
      request,
      browser: { clientId: status.client.id, redirectUri },
      getOldPassword,
      use: async (identity) => {
        const configuration = Object.freeze({
          ...input.browser,
          expectedIssuer,
          expectedSubject: identity.id,
          canonicalEmail: identity.primaryEmail,
          resource: status.resource.indicator,
        });
        const adapt = (raw: Phase1BrowserSession) =>
          adaptPhase1SessionForEmailRecovery(raw, configuration);
        const runFresh = async <Result>(
          use: (session: ReturnType<typeof adapt>) => Promise<Result>
        ): Promise<Result> => {
          let callbackError: unknown;
          try {
            return await input.observer.runInFreshContext(
              'experience',
              input.signal,
              input.target,
              async (raw) => {
                try {
                  return await use(adapt(raw));
                } catch (error: unknown) {
                  callbackError = error;
                  throw error;
                }
              }
            );
          } catch (error: unknown) {
            throw combineEmailRecoveryContextFailure(callbackError, error);
          }
        };
        const flow = await runCommonEmailRecovery({
          mixedCaseEmail: identity.primaryEmail.replace(/^common/u, 'Common'),
          canonicalEmail: identity.primaryEmail,
          oldPassword: getOldPassword,
          newPassword: () => newPassword,
          takeVerificationCode,
          withInitialSession: runFresh,
          withFreshSession: async (_name, use) => runFresh(use),
        });
        const controls = await runCommonEmailRecoveryControls(
          createEmailRecoveryControlRuntime({
            target: input.target,
            clientId: status.client.id,
            redirectUri,
            recipient: identity.primaryEmail,
            takeVerificationCode,
            fetch: requestFetch,
          })
        );
        return Object.freeze({ ...flow, ...controls });
      },
    });
  };

  if (input.target.label === 'candidate') {
    let consumerError: unknown;
    try {
      return await withPhase2AdminManagementBearer(
        input.target,
        input.fixture,
        async (bearer, lease) => {
          try {
            return await execute(
              createBearerPhase2AdminRequest(input.target, bearer, requestFetch),
              lease
            );
          } catch (error: unknown) {
            consumerError = error;
            throw error;
          }
        },
        { fetch: requestFetch }
      );
    } catch (error: unknown) {
      return fail(commonEmailRecoveryTargetFailureStage(consumerError ?? error));
    }
  }
  let consumerError: unknown;
  try {
    return await input.fixture.withSecretLease(async (lease) => {
      try {
        return await execute(createReferencePhase2AdminRequest(input.target, requestFetch), lease);
      } catch (error: unknown) {
        consumerError = error;
        throw error;
      }
    });
  } catch (error: unknown) {
    return fail(commonEmailRecoveryTargetFailureStage(consumerError ?? error));
  }
};
/* eslint-enable complexity, no-await-in-loop, no-constant-condition, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unnecessary-condition, @typescript-eslint/no-unsafe-assignment */
