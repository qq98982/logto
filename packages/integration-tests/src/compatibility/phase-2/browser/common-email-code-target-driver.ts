/* eslint-disable complexity, max-lines, no-await-in-loop, no-constant-condition, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unnecessary-condition, @typescript-eslint/no-unsafe-assignment -- Admission, bounded discovery, one browser context, and fixture cleanup form one boundary. */
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
  type Phase2FixtureSecretLease,
  type ProvisionedPhase2Fixture,
} from '../fixtures.js';

import { runCommonEmailCodeHttpControls } from './common-email-code-controls.js';
import { runCommonEmailCodeScenario } from './common-email-code-runner.js';
import type { CommonEmailCodeProjection } from './common-email-code-sign-in.js';
import type { CommonEmailPasswordBrowserConfiguration } from './fresh-context-password-controls.js';

const fail = (stage: string): never => {
  throw new TypeError(`Common email code target failed: ${stage}`);
};
const fixtureStage = (error: unknown): string | undefined => {
  if (!(error instanceof Error)) {
    return undefined;
  }
  const match =
    /^Common email code fixture failed: primary-(get-sie|get-app|patch-app|read-app|read-resource-scopes|patch-sie-request|patch-sie-response|create-role|read-role-scopes|read-sie|create-user|assign-role|read-user-roles|use);cleanup-(none|restore-sie|restore-app|read-restored-sie|delete-user|delete-role)(?:\+(?:restore-sie|restore-app|read-restored-sie|delete-user|delete-role))*(?:;flow-(initialization|identifier-submit|verification-route|passcode-retrieval(?:-(?:env-missing|socket-shape|recipient|connect|timeout|not-found|response))?|passcode-format|passcode-fill|consent|callback|profile|refresh|controls(?:-(?:basic|foreign-account|secondary-client))?))?$/u.exec(
      error.message
    );
  if (!match) {
    return undefined;
  }
  const [, primary, cleanup, flow] = match;
  if (cleanup !== 'none') {
    return 'fixture-cleanup';
  }
  if (primary === 'use' && flow) {
    return `flow-${flow}`;
  }
  return primary ? `fixture-${primary}` : undefined;
};
const closedTargetStage = (error: unknown): string | undefined =>
  error instanceof Error
    ? /^Common email code target failed: (lease|browser|fixture-(?:get-sie|get-app|patch-app|read-app|read-resource-scopes|patch-sie-request|patch-sie-response|create-role|read-role-scopes|read-sie|create-user|assign-role|read-user-roles|use|cleanup)|flow-(?:initialization|identifier-submit|verification-route|passcode-retrieval(?:-(?:env-missing|socket-shape|recipient|connect|timeout|not-found|response))?|passcode-format|passcode-fill|consent|callback|profile|refresh|controls(?:-(?:basic|foreign-account|secondary-client))?))$/u.exec(
        error.message
      )?.[1]
    : undefined;
const adminStage = (error: unknown): string | undefined =>
  error instanceof Error
    ? /^Invalid Phase 2 Admin Management bearer flow \((admission|authorization|bootstrap|password|identification|submit|bridge|consent|resume|code-token|management-refresh|jwks|consumer)\)$/u.exec(
        error.message
      )?.[1]
    : undefined;

export const runCommonEmailCodeAdminBoundary = async <Result>(
  runAdmin: (capture: (operation: () => Promise<Result>) => Promise<Result>) => Promise<Result>
): Promise<Result> => {
  let consumerStage: string | undefined;
  try {
    return await runAdmin(async (operation) => {
      try {
        return await operation();
      } catch (error: unknown) {
        consumerStage = closedTargetStage(error);
        throw error;
      }
    });
  } catch (error: unknown) {
    if (consumerStage) {
      return fail(`admin-consumer-${consumerStage}`);
    }
    const stage = adminStage(error);
    return fail(stage ? `admin-${stage}` : 'admin');
  }
};

export const runCommonEmailCodeInFreshContext = async <Result>(
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
        closedStage = fixtureStage(error);
        throw error;
      }
    });
  } catch {
    if (closedStage) {
      return fail(closedStage);
    }
    return fail('browser');
  }
};

const readIssuer = async (target: TargetConfig, requestFetch: typeof fetch): Promise<string> => {
  const response = await requestFetch(
    new URL('/oidc/.well-known/openid-configuration', target.coreUrl),
    { redirect: 'manual', signal: AbortSignal.timeout(10_000) }
  );
  const length = response.headers.get('content-length');
  if (
    response.status !== 200 ||
    response.redirected ||
    (length !== null && (!/^(?:0|[1-9]\d*)$/u.test(length) || Number(length) > 65_536))
  ) {
    await response.body?.cancel().catch(() => false);
    return fail('discovery');
  }
  const reader = response.body?.getReader();
  if (!reader) {
    return fail('discovery');
  }
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
        await reader.cancel().catch(() => false);
        return fail('discovery');
      }
      chunks.push(chunk.value);
    }
  } catch {
    await reader.cancel().catch(() => false);
    return fail('discovery');
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes)) as unknown;
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

export type CommonEmailCodeTargetInput = Readonly<{
  target: TargetConfig;
  fixture: ProvisionedPhase2Fixture;
  observer: Phase1BrowserGroupObserver;
  signal: AbortSignal;
  browser: Omit<CommonEmailPasswordBrowserConfiguration, 'expectedIssuer'>;
  fetch?: typeof fetch;
}>;

export const createScopedEmailCodeFixture = (
  fixture: ProvisionedPhase2Fixture,
  lease: Phase2FixtureSecretLease,
  redirectUri: string
) => {
  let active = true;
  let delegated = false;
  return Object.freeze({
    fixture: Object.freeze({
      ...fixture,
      ...(fixture.status && {
        status: Object.freeze({
          ...fixture.status,
          client: Object.freeze({ ...fixture.status.client, redirectUri }),
        }),
      }),
      withSecretLease: async <Result>(
        use: (value: Phase2FixtureSecretLease) => Promise<Result>
      ) => {
        if (!active || delegated) {
          return fail('lease');
        }
        delegated = true;
        try {
          return await use(lease);
        } finally {
          delegated = false;
        }
      },
    }),
    revoke: () => {
      active = false;
    },
  });
};

const execute = async (input: CommonEmailCodeTargetInput): Promise<CommonEmailCodeProjection> => {
  const status = input.fixture.status ?? fail('admission');
  const redirectUri = new URL('/demo-app', input.target.coreUrl).href;
  const requestedScopes = input.browser.demo.scope.split(' ').filter(Boolean);
  const initialScopes = input.browser.initialResponseScope.split(' ').filter(Boolean);
  const expectedOidcScopes = ['openid', 'offline_access', 'profile', 'email'];
  const expectedScopes = [...expectedOidcScopes, status.resource.scopeName];
  if (
    input.browser.demo.appId !== status.client.id ||
    input.browser.redirectUri !== redirectUri ||
    input.browser.demo.resource !== status.resource.indicator ||
    input.browser.resourceScope !== status.resource.scopeName ||
    input.browser.demo.prompt !== 'consent' ||
    requestedScopes.length !== expectedScopes.length ||
    new Set(requestedScopes).size !== requestedScopes.length ||
    !expectedScopes.every((scope) => requestedScopes.includes(scope)) ||
    initialScopes.length !== expectedOidcScopes.length ||
    new Set(initialScopes).size !== initialScopes.length ||
    !expectedOidcScopes.every((scope) => initialScopes.includes(scope))
  ) {
    return fail('admission');
  }
  const requestFetch = input.fetch ?? fetch;
  let expectedIssuer: string;
  try {
    expectedIssuer = await readIssuer(input.target, requestFetch);
  } catch {
    return fail('discovery');
  }
  const run = async (
    managementRequest: ReturnType<typeof createReferencePhase2AdminRequest>,
    lease: Phase2FixtureSecretLease
  ) => {
    const scope = createScopedEmailCodeFixture(input.fixture, lease, redirectUri);
    try {
      return await runCommonEmailCodeInFreshContext(
        input.observer,
        input.signal,
        input.target,
        async (session) =>
          runCommonEmailCodeScenario({
            fixture: scope.fixture,
            managementRequest,
            session,
            configuration: { ...input.browser, expectedIssuer },
            takePasscode: async (recipient) => {
              if (typeof lease.takeVerificationCode !== 'function') {
                return fail('lease');
              }
              return lease.takeVerificationCode(recipient);
            },
            runControls: async (identity) =>
              runCommonEmailCodeHttpControls(
                input.target,
                scope.fixture,
                identity.primaryEmail,
                requestFetch
              ),
          })
      );
    } finally {
      scope.revoke();
    }
  };
  if (input.target.label === 'candidate') {
    return runCommonEmailCodeAdminBoundary(async (capture) =>
      withPhase2AdminManagementBearer(
        input.target,
        input.fixture,
        async (bearer, lease) =>
          capture(async () =>
            run(createBearerPhase2AdminRequest(input.target, bearer, requestFetch), lease)
          ),
        { fetch: requestFetch }
      )
    );
  }
  return input.fixture.withSecretLease(async (lease) =>
    run(createReferencePhase2AdminRequest(input.target, requestFetch), lease)
  );
};

export const runCommonEmailCodeForTarget = async (
  input: CommonEmailCodeTargetInput
): Promise<CommonEmailCodeProjection> => {
  if (!isPlaywrightBrowserGroupObserver(input.observer)) {
    return fail('capability');
  }
  return execute(input);
};

export const runCommonEmailCodeForTargetTesting = async (
  input: CommonEmailCodeTargetInput
): Promise<CommonEmailCodeProjection> => {
  if (process.env.NODE_ENV !== 'test') {
    return fail('capability');
  }
  return execute(input);
};
/* eslint-enable complexity, max-lines, no-await-in-loop, no-constant-condition, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unnecessary-condition, @typescript-eslint/no-unsafe-assignment */
