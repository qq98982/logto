/* eslint-disable complexity, no-await-in-loop, no-constant-condition, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unnecessary-condition -- Target admission, bounded streaming, discovery, one credential lease, and one browser scope are one closed composition boundary. */
import type { TargetConfig } from '../../model.js';
import type { Phase1BrowserGroupObserver } from '../../phase-1/browser/contracts.js';
import { isPlaywrightBrowserGroupObserver } from '../../phase-1/browser/playwright-session.js';
import { withPhase2AdminManagementBearer } from '../clients/admin-management-bearer.js';
import {
  createBearerPhase2AdminRequest,
  createReferencePhase2AdminRequest,
  type Phase2FixtureSecretLease,
  type ProvisionedPhase2Fixture,
} from '../fixtures.js';

import {
  runCommonEmailPasswordScenario,
  type CommonEmailPasswordCredentialLease,
} from './common-email-password-runner.js';
import type { CommonEmailPasswordProjection } from './common-email-password-sign-in.js';
import {
  createFreshContextPasswordControls,
  type CommonEmailPasswordBrowserConfiguration,
} from './fresh-context-password-controls.js';

type EmailPasswordFixtureLease = Phase2FixtureSecretLease;

const fail = (): never => {
  throw new TypeError('Invalid Common email password target composition');
};
const targetFail = (stage: string): never => {
  throw new TypeError(`Common email password target failed: ${stage}`);
};
const preservesKnownStage = (error: unknown): boolean =>
  error instanceof Error &&
  /^(?:Common email password stage failed: (?:initialization|credentials|consent|callback(?:-(?:cardinality|signin-authority|signin-response|signin-client|signin-redirect|signin-mode|signin-scope|signin-resource|signin-pkce|callback-authority|callback-response|callback-state|callback-issuer|callback-code|callback-route|callback-facts-s(?:0|1|many)-c(?:0|1|many)-i(?:0|1|many)|exchange-authority|exchange-response|exchange-correlation|exchange-client|exchange-refresh|exchange-target|exchange-scope|exchange-access))?|profile|profile-sub|profile-email|refresh|refresh-sub|refresh-rotation|refresh-exchange-kind|refresh-authority|refresh-status|refresh-request-shape|refresh-correlation|refresh-client|refresh-redirect|refresh-initial-refresh-flag|refresh-replacement-fresh|refresh-resource|refresh-organization|refresh-response-scope(?:-(?:api-only|oidc-plus-api|oidc-only|missing|other)-claims-(?:api-only|oidc-plus-api|oidc-only|missing|other))?|refresh-access-kind|refresh-compact-issuer|refresh-subject|refresh-audience|refresh-compact-client|refresh-scope|refresh-organization-present|controls-invalid|controls-suspended(?:-set|-attempt|-restore|-attempt-restore|-set-restore)?|controls-username|username-sub)|Common email password target failed: (?:network-(?:parser-(?:auth|callback|token|other)|guard-(?:external-request(?:-(?:get|post|other)-(?:loopback-wrong-port|logto-branding|github-assets|google-fonts|numbers-logto|external)-(?:well-known|token|demo-app|api|avatar|pull-json|captcha-cloudflare|captcha-google|one-tap-google|google-font|branding-static|other-static|other))?|extra-page|websocket|page-boundary)|observation-(?:aborted|parser|guard|timeout))|capability|admission|discovery|lease|context-launch|context-open|context-use|context-cleanup)|Common email password fixture failed: primary-(?:setup-config|patch-sie|read-sie|get-app|patch-app|read-app|post-user|read-resource-scopes|post-resource-role|read-resource-role-scopes|assign-resource-role|read-user-roles|use|none);cleanup-(?:none|(?:restore-sie|delete-user|restore-app-patch|restore-app-read|delete-role)(?:\+(?:restore-sie|delete-user|restore-app-patch|restore-app-read|delete-role))*);flow-(?:none|initialization|credentials|consent|callback(?:-(?:cardinality|signin-authority|signin-response|signin-client|signin-redirect|signin-mode|signin-scope|signin-resource|signin-pkce|callback-authority|callback-response|callback-state|callback-issuer|callback-code|callback-route|callback-facts-s(?:0|1|many)-c(?:0|1|many)-i(?:0|1|many)|exchange-authority|exchange-response|exchange-correlation|exchange-client|exchange-refresh|exchange-target|exchange-scope|exchange-access))?|profile|profile-sub|profile-email|refresh|refresh-sub|refresh-rotation|refresh-exchange-kind|refresh-authority|refresh-status|refresh-request-shape|refresh-correlation|refresh-client|refresh-redirect|refresh-initial-refresh-flag|refresh-replacement-fresh|refresh-resource|refresh-organization|refresh-response-scope(?:-(?:api-only|oidc-plus-api|oidc-only|missing|other)-claims-(?:api-only|oidc-plus-api|oidc-only|missing|other))?|refresh-access-kind|refresh-compact-issuer|refresh-subject|refresh-audience|refresh-compact-client|refresh-scope|refresh-organization-present|controls-invalid|controls-suspended(?:-set|-attempt|-restore|-attempt-restore|-set-restore)?|controls-username|username-sub))$/u.test(
    error.message
  );

export const preserveCommonEmailPasswordContextStage = (
  latchedError: TypeError | undefined,
  observerError: unknown
): never => {
  if (observerError instanceof AggregateError) {
    return targetFail('context-cleanup');
  }
  if (latchedError) {
    throw latchedError;
  }
  return targetFail('context-use');
};

export const withCandidateEmailPasswordStageLatch = async <Result>(
  authenticate: (
    use: (bearer: string, lease: Phase2FixtureSecretLease) => Promise<Result>
  ) => Promise<Result>,
  use: (bearer: string, lease: Phase2FixtureSecretLease) => Promise<Result>
): Promise<Result> => {
  let consumerStage: TypeError | undefined;
  try {
    return await authenticate(async (bearer, lease) => {
      try {
        return await use(bearer, lease);
      } catch (error: unknown) {
        if (preservesKnownStage(error)) {
          consumerStage = new TypeError(error instanceof Error ? error.message : '');
        }
        throw error;
      }
    });
  } catch (error: unknown) {
    if (consumerStage) {
      throw consumerStage;
    }
    throw error;
  }
};

const parseJson = (text: string): unknown => {
  try {
    return JSON.parse(text);
  } catch {
    return fail();
  }
};

const readBoundedBody = async (response: Response): Promise<Uint8Array> => {
  const maximumBytes = 64 * 1024;
  const declared = response.headers.get('content-length');
  if (
    declared !== null &&
    (!/^(?:0|[1-9]\d*)$/u.test(declared) || Number(declared) > maximumBytes)
  ) {
    await response.body?.cancel().catch(() => false);
    return fail();
  }
  if (!response.body) {
    return new Uint8Array();
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) {
        break;
      }
      length += chunk.value.byteLength;
      if (length > maximumBytes) {
        await reader.cancel().catch(() => false);
        return fail();
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
  return bytes;
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
    return fail();
  }
  const text = new TextDecoder('utf8', { fatal: true }).decode(await readBoundedBody(response));
  const body = parseJson(text);
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    return fail();
  }
  const issuerValue: unknown = Reflect.get(body, 'issuer');
  if (typeof issuerValue !== 'string') {
    return fail();
  }
  const issuer = new URL(issuerValue);
  const core = new URL(target.coreUrl);
  if (
    issuer.origin !== core.origin ||
    issuer.pathname !== '/oidc' ||
    issuer.username ||
    issuer.password ||
    issuer.search ||
    issuer.hash
  ) {
    return fail();
  }
  return issuer.href.replace(/\/$/u, '');
};

const credentialLease = (lease: EmailPasswordFixtureLease): CommonEmailPasswordCredentialLease => {
  const selected = lease.getSelectedEmailPassword;
  const invalid = lease.getInvalidEmailPassword;
  const preserved = lease.getSubjectPassword;
  if (
    typeof selected !== 'function' ||
    typeof invalid !== 'function' ||
    typeof preserved !== 'function'
  ) {
    return fail();
  }
  return Object.freeze({
    getSelectedEmailPassword: selected,
    getInvalidEmailPassword: invalid,
    getPreservedUsernamePassword: preserved,
  });
};

export type CommonEmailPasswordTargetDriverInput = Readonly<{
  target: TargetConfig;
  fixture: ProvisionedPhase2Fixture;
  observer: Phase1BrowserGroupObserver;
  signal: AbortSignal;
  browser: Omit<CommonEmailPasswordBrowserConfiguration, 'expectedIssuer'>;
  fetch?: typeof fetch;
}>;

const executeCommonEmailPasswordForTarget = async (
  input: CommonEmailPasswordTargetDriverInput
): Promise<CommonEmailPasswordProjection> => {
  const status = input.fixture.status ?? targetFail('admission');
  const requestedScopes = input.browser.demo.scope.split(' ');
  const expectedRedirectUri = new URL('/demo-app', input.target.coreUrl).href;
  if (
    input.browser.demo.appId !== status.client.id ||
    input.browser.redirectUri !== expectedRedirectUri ||
    input.browser.demo.resource !== status.resource.indicator ||
    input.browser.resourceScope !== status.resource.scopeName ||
    input.browser.demo.prompt !== 'consent' ||
    new Set(requestedScopes).size !== requestedScopes.length ||
    !['openid', 'offline_access', 'profile', 'email', status.resource.scopeName].every((scope) =>
      requestedScopes.includes(scope)
    )
  ) {
    return targetFail('admission');
  }
  const requestFetch = input.fetch ?? fetch;
  let expectedIssuer: string;
  try {
    expectedIssuer = await discoverIssuer(input.target, requestFetch);
  } catch {
    return targetFail('discovery');
  }
  const configuration = Object.freeze({ ...input.browser, expectedIssuer });
  const execute = async (
    managementRequest: Parameters<typeof runCommonEmailPasswordScenario>[0]['managementRequest'],
    fixtureLease: EmailPasswordFixtureLease
  ): Promise<CommonEmailPasswordProjection> => {
    let latchedError: TypeError | undefined;
    try {
      return await input.observer.runInFreshContext(
        'experience',
        input.signal,
        input.target,
        async (session) => {
          try {
            return await runCommonEmailPasswordScenario({
              fixture: input.fixture,
              managementRequest,
              session,
              configuration,
              preservedUsername: { identifier: status.user.username, subject: status.user.id },
              withCredentialLease: async (use) => {
                try {
                  return await use(credentialLease(fixtureLease));
                } catch (error: unknown) {
                  if (preservesKnownStage(error)) {
                    throw error;
                  }
                  return targetFail('lease');
                }
              },
              createControlDriver: (identity) =>
                createFreshContextPasswordControls({
                  observer: input.observer,
                  target: input.target,
                  signal: input.signal,
                  configuration,
                  canonicalEmail: identity.primaryEmail,
                  emailSubject: identity.id,
                  usernameSubject: status.user.id,
                }),
            });
          } catch (error: unknown) {
            if (preservesKnownStage(error)) {
              latchedError = new TypeError(error instanceof Error ? error.message : '');
            }
            throw error;
          }
        }
      );
    } catch (error: unknown) {
      return preserveCommonEmailPasswordContextStage(latchedError, error);
    }
  };
  if (input.target.label === 'candidate') {
    return withCandidateEmailPasswordStageLatch(
      async (use) =>
        withPhase2AdminManagementBearer(input.target, input.fixture, use, {
          fetch: requestFetch,
        }),
      async (bearer, lease) =>
        execute(createBearerPhase2AdminRequest(input.target, bearer, requestFetch), lease)
    );
  }
  return input.fixture.withSecretLease(async (lease) =>
    execute(createReferencePhase2AdminRequest(input.target, requestFetch), lease)
  );
};

export const runCommonEmailPasswordForTarget = async (
  input: CommonEmailPasswordTargetDriverInput
): Promise<CommonEmailPasswordProjection> => {
  if (!isPlaywrightBrowserGroupObserver(input.observer)) {
    return targetFail('capability');
  }
  return executeCommonEmailPasswordForTarget(input);
};

/** Test-only lifecycle executor. Production code must use the capability-checked entrypoint. */
export const runCommonEmailPasswordForTargetTesting = async (
  input: CommonEmailPasswordTargetDriverInput
): Promise<CommonEmailPasswordProjection> => {
  if (process.env.NODE_ENV !== 'test') {
    return fail();
  }
  return executeCommonEmailPasswordForTarget(input);
};
/* eslint-enable complexity, no-await-in-loop, no-constant-condition, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unnecessary-condition */
