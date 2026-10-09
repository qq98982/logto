/* eslint-disable complexity, max-lines, no-await-in-loop, no-constant-condition, no-return-await, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unnecessary-condition, @typescript-eslint/return-await -- Target admission, bounded discovery, credential scopes, provider fixture, browser context, and cleanup-stage preservation form one composition boundary. Explicit return-await keeps both target promises inside the outer stage-latch boundary. */
import { isDeepStrictEqual, types as nodeTypes } from 'node:util';

import { validateTargetConfig } from '../../config.js';
import type { TargetConfig } from '../../model.js';
import type { Phase1BrowserGroupObserver } from '../../phase-1/browser/contracts.js';
import {
  type PlaywrightExternalAuthorizationCapability,
  type PlaywrightExternalCallbackFailureReason,
  withPlaywrightExternalAuthorizationCapability,
} from '../../phase-1/browser/playwright-session.js';
import { withPhase2AdminManagementBearer } from '../clients/admin-management-bearer.js';
import {
  createBearerPhase2AdminRequest,
  createReferencePhase2AdminRequest,
  type Phase2AdminRequestFunction,
  type ProvisionedPhase2Fixture,
} from '../fixtures.js';

import {
  runCommonGoogleExistingOwnerSignIn,
  type CommonGoogleExistingOwnerProjection,
} from './common-google-existing-owner-sign-in.js';
import type { CommonEmailPasswordBrowserConfiguration } from './fresh-context-password-controls.js';
import type { GoogleAuthorizationObservation } from './google-authorization-observer.js';
import {
  createGoogleBrowserReplayTestControl,
  type GoogleBrowserReplayObservation,
} from './google-browser-replay-control.js';
import {
  type GoogleProviderControl,
  type GoogleProviderHealthTiming,
  type GoogleProviderLease,
  prepareGoogleProviderLease,
} from './google-provider-lease.js';
import { adaptPhase1SessionForEmailPassword } from './phase1-session-adapter.js';
import {
  googleSignInButtonSelectorCandidate,
  withSelectedGoogleConnectorFixture,
} from './selected-google-connector-fixture.js';

const maximumDiscoveryBytes = 64 * 1024;
const connectorFixtureStages = new Set([
  'read-sie',
  'get-app',
  'patch-app',
  'read-app',
  'read-resource',
  'create-role',
  'create-connector',
  'prepare-connector',
  'prepare-connector-docker-environment',
  'prepare-connector-admission',
  'prepare-connector-configuration-file',
  'prepare-connector-receipt-file',
  'prepare-connector-container-admission',
  'prepare-connector-configuration-write',
  'prepare-connector-start',
  'prepare-connector-health',
  'prepare-connector-compensation',
  'prepare-connector-unknown',
  'patch-sie',
  'read-sie-updated',
  'existing-owner-create-user',
  'existing-owner-associate',
  'existing-owner-read-before',
  'existing-owner-use',
  'existing-owner-read-after',
  'existing-owner-cleanup-user',
  'stop-provider',
  'restore-app',
  'delete-role',
  'restore-sie',
  'delete-connector',
]);
type FixtureStage = `fixture-${string}`;
type Stage =
  | 'admission'
  | 'capability'
  | 'cleanup'
  | 'context'
  | 'credentials'
  | 'discovery'
  | 'fixture'
  | 'management'
  | 'wrong-state-owner-before'
  | 'wrong-state-open'
  | 'wrong-state-sign-in'
  | 'wrong-state-provider-count'
  | 'wrong-state-provider-click'
  | 'wrong-state-callback-outcome'
  | `wrong-state-callback-${PlaywrightExternalCallbackFailureReason}`
  | 'wrong-state-owner-after'
  | 'wrong-state-authorization'
  | `wrong-state-authorization-${string}`
  | 'wrong-state-provider'
  | FixtureStage;
const fail = (): never => {
  throw new TypeError('Invalid Common Google existing-owner target composition');
};
const targetFail = (stage: Stage): never => {
  throw new TypeError(`Common Google existing-owner target failed: ${stage}`);
};
const isBounded = (value: unknown, maximum = 1024): value is string =>
  typeof value === 'string' &&
  value.length > 0 &&
  Buffer.byteLength(value) <= maximum &&
  ![...value].some((character) => {
    const code = character.codePointAt(0) ?? 0;
    return code < 0x20 || code === 0x7f;
  });
const bounded = (value: unknown, maximum = 1024): string => {
  if (!isBounded(value, maximum)) {
    return fail();
  }
  return value;
};
const preservesFlowStage = (error: unknown): error is TypeError =>
  !nodeTypes.isProxy(error) &&
  error instanceof TypeError &&
  /^Common Google existing-owner failed: (?:admission|initialization|provider|provider-count|provider-click|consent|callback(?:-(?:callback-route|callback-facts-s(?:0|1|many)-c(?:0|1|many)-i(?:0|1|many)|cardinality|signin-(?:authority|response|client|redirect|mode|scope|resource|pkce)|callback-(?:authority|response|state|issuer|code)|exchange-(?:authority|response|correlation|client|refresh|target|scope|access)))?|profile|refresh|provider-case|authorization)$/u.test(
    ownMessage(error) ?? ''
  );

const ownMessage = (error: unknown): string | undefined => {
  const descriptor =
    !nodeTypes.isProxy(error) && error instanceof Error
      ? Object.getOwnPropertyDescriptor(error, 'message')
      : undefined;
  return descriptor && Object.hasOwn(descriptor, 'value') && typeof descriptor.value === 'string'
    ? descriptor.value
    : undefined;
};
const externalCallbackFailureReason = (error: unknown): PlaywrightExternalCallbackFailureReason => {
  const reason =
    /^Browser external callback outcome failed: (signal|guard|observation-other|external-callback-method|external-callback-query|external-callback-fragment|cardinality)$/u.exec(
      ownMessage(error) ?? ''
    )?.[1];
  switch (reason) {
    case 'signal':
    case 'guard':
    case 'observation-other':
    case 'external-callback-method':
    case 'external-callback-query':
    case 'external-callback-fragment':
    case 'cardinality': {
      return reason;
    }
    default: {
      return 'observation-other';
    }
  }
};
const isDuplicateExternalCallbackCleanup = (error: unknown, stage: Stage | undefined): boolean => {
  if (
    !stage?.startsWith('wrong-state-callback-') ||
    nodeTypes.isProxy(error) ||
    !(error instanceof AggregateError)
  ) {
    return false;
  }
  const descriptor = Object.getOwnPropertyDescriptor(error, 'errors');
  const members: unknown =
    descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
  if (!Array.isArray(members) || nodeTypes.isProxy(members) || members.length !== 2) {
    return false;
  }
  const entries = Object.getOwnPropertyDescriptors(members);
  const first = entries['0'];
  const second = entries['1'];
  if (
    !first ||
    !second ||
    !Object.hasOwn(first, 'value') ||
    !Object.hasOwn(second, 'value') ||
    !first.enumerable ||
    !second.enumerable
  ) {
    return false;
  }
  const reason = stage.slice('wrong-state-callback-'.length);
  return (
    ownMessage(first.value) === `Browser external callback outcome failed: ${reason}` &&
    ownMessage(second.value) === 'Browser network observation failed'
  );
};
const fixtureStage = (error: unknown, depth = 0): FixtureStage | undefined => {
  if (depth >= 4) {
    return undefined;
  }
  const direct = /^Selected Google connector fixture failed: ([a-z]+(?:-[a-z]+)*)$/u.exec(
    ownMessage(error) ?? ''
  )?.[1];
  if (direct && connectorFixtureStages.has(direct)) {
    return `fixture-${direct}`;
  }
  if (!(error instanceof AggregateError)) {
    return undefined;
  }
  const descriptor = Object.getOwnPropertyDescriptor(error, 'errors');
  const members: unknown =
    descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
  if (!Array.isArray(members) || members.length === 0 || members.length > 8) {
    return undefined;
  }
  const entries = Object.getOwnPropertyDescriptors(members);
  const stages: FixtureStage[] = [];
  for (let index = 0; index < members.length; index += 1) {
    const entry = entries[String(index)];
    if (!entry || !Object.hasOwn(entry, 'value') || !entry.enumerable) {
      return undefined;
    }
    const entryValue: unknown = entry.value;
    const stage = fixtureStage(entryValue, depth + 1);
    if (stage) {
      stages.push(stage);
    }
  }
  return (
    stages.find((stage) =>
      /^fixture-(?:stop-provider|restore-app|delete-role|restore-sie|delete-connector|existing-owner-cleanup-user)$/u.test(
        stage
      )
    ) ?? stages[0]
  );
};
export const commonGoogleTargetFixtureStageForTesting = (
  error: unknown
): FixtureStage | undefined => {
  if (process.env.NODE_ENV !== 'test') {
    return undefined;
  }
  return fixtureStage(error);
};
const fixtureCleanupStage = (stage: FixtureStage): boolean =>
  /^fixture-(?:stop-provider|restore-app|delete-role|restore-sie|delete-connector|existing-owner-cleanup-user|prepare-connector-compensation)$/u.test(
    stage
  );

const boundedDiscoveryBody = async (response: Response): Promise<Uint8Array> => {
  const declared = response.headers.get('content-length');
  if (
    declared !== null &&
    (!/^(?:0|[1-9]\d*)$/u.test(declared) || Number(declared) > maximumDiscoveryBytes)
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
      if (length > maximumDiscoveryBytes) {
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
  const text = new TextDecoder('utf8', { fatal: true }).decode(
    await boundedDiscoveryBody(response)
  );
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return fail();
  }
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

export type GoogleProviderCredentialLease = Readonly<{
  getClientId(): string;
  getClientSecret(): string;
  toJSON(): never;
}>;

export type GoogleProviderTargetConfiguration = Readonly<{
  control: GoogleProviderControl;
  container: string;
  project: string;
  service: string;
  image: string;
  configFile: string;
  receiptFile: string;
  healthDiagnosticFile: string;
  googleSubject: string;
  originalOwnerEmail: string;
  changedProviderEmail: string;
  expectedUserinfoMethod: 'GET' | 'POST';
  resetPrivateFilesOnStop?: true;
  healthTiming?: GoogleProviderHealthTiming;
}>;

export type CommonGoogleExistingOwnerTargetDriverInput = Readonly<{
  target: TargetConfig;
  fixture: ProvisionedPhase2Fixture;
  signal: AbortSignal;
  browser: Omit<CommonEmailPasswordBrowserConfiguration, 'expectedIssuer'>;
  provider: GoogleProviderTargetConfiguration;
  fetch?: typeof fetch;
  observer: Phase1BrowserGroupObserver;
  /** Test-only fake observer factory. Production always uses the branded observer bridge. */
  createObserverForTesting?(
    capability: PlaywrightExternalAuthorizationCapability
  ): Phase1BrowserGroupObserver;
  withProviderCredentialLease<Result>(
    use: (lease: GoogleProviderCredentialLease) => Promise<Result>
  ): Promise<Result>;
}>;

export type CommonGoogleExistingOwnerWrongStateObservation = Readonly<{
  callbackAccepted: boolean | 'unknown';
  status: number | 'unavailable';
  error: 'unknown';
  ownerPreserved: true;
  authorization: GoogleAuthorizationObservation;
}>;
export type CommonGoogleExistingOwnerReplayObservation = GoogleBrowserReplayObservation;

const admit = (
  input: CommonGoogleExistingOwnerTargetDriverInput,
  target: TargetConfig
): NonNullable<ProvisionedPhase2Fixture['status']> => {
  const status = input.fixture.status ?? targetFail('admission');
  const expectedRedirectUri = new URL('/demo-app', target.coreUrl).href;
  const scopes = input.browser.demo.scope.split(' ');
  if (
    input.signal.aborted ||
    typeof input.observer?.runInFreshContext !== 'function' ||
    typeof input.withProviderCredentialLease !== 'function' ||
    input.browser.demo.appId !== status.client.id ||
    input.browser.redirectUri !== expectedRedirectUri ||
    input.browser.demo.resource !== status.resource.indicator ||
    input.browser.resourceScope !== status.resource.scopeName ||
    input.browser.demo.prompt !== 'consent' ||
    new Set(scopes).size !== scopes.length ||
    !['openid', 'offline_access', 'profile', 'email', status.resource.scopeName].every((scope) =>
      scopes.includes(scope)
    ) ||
    !isBounded(input.provider.googleSubject) ||
    !isBounded(input.provider.originalOwnerEmail) ||
    !isBounded(input.provider.changedProviderEmail) ||
    input.provider.originalOwnerEmail === input.provider.changedProviderEmail
  ) {
    return targetFail('admission');
  }
  return status;
};

function executeCommonGoogleExistingOwnerForTarget(
  input: CommonGoogleExistingOwnerTargetDriverInput,
  requirePlaywrightBrand: boolean,
  mode: 'normal'
): Promise<CommonGoogleExistingOwnerProjection>;
function executeCommonGoogleExistingOwnerForTarget(
  input: CommonGoogleExistingOwnerTargetDriverInput,
  requirePlaywrightBrand: boolean,
  mode: 'wrong-state'
): Promise<CommonGoogleExistingOwnerWrongStateObservation>;
function executeCommonGoogleExistingOwnerForTarget(
  input: CommonGoogleExistingOwnerTargetDriverInput,
  requirePlaywrightBrand: boolean,
  mode: 'replay'
): Promise<CommonGoogleExistingOwnerReplayObservation>;
async function executeCommonGoogleExistingOwnerForTarget(
  input: CommonGoogleExistingOwnerTargetDriverInput,
  requirePlaywrightBrand: boolean,
  mode: 'normal' | 'wrong-state' | 'replay'
): Promise<
  | CommonGoogleExistingOwnerProjection
  | CommonGoogleExistingOwnerWrongStateObservation
  | CommonGoogleExistingOwnerReplayObservation
> {
  let target: TargetConfig;
  try {
    target = validateTargetConfig(input.target);
  } catch {
    return targetFail('admission');
  }
  const status = admit(input, target);
  const requestFetch = input.fetch ?? fetch;
  let expectedIssuer: string;
  try {
    expectedIssuer = await discoverIssuer(target, requestFetch);
  } catch {
    return targetFail('discovery');
  }
  let flowError: TypeError | undefined;
  let selectedFixtureStage: FixtureStage | undefined;
  let wrongStateCallbackStage: Stage | undefined;
  let cleanupFailed = false;
  let stage: Stage = 'credentials';
  try {
    return await input.withProviderCredentialLease(async (credentials) => {
      if (
        typeof credentials.getClientId !== 'function' ||
        typeof credentials.getClientSecret !== 'function' ||
        typeof credentials.toJSON !== 'function'
      ) {
        return fail();
      }
      const clientId = bounded(credentials.getClientId());
      const clientSecret = bounded(credentials.getClientSecret());
      const executeFixture = async (request: Phase2AdminRequestFunction) => {
        stage = 'fixture';
        let providerLease: GoogleProviderLease | undefined;
        try {
          return await withSelectedGoogleConnectorFixture({
            fixture: input.fixture,
            request,
            targetOrigin: target.coreUrl,
            browser: {
              clientId: input.browser.demo.appId,
              redirectUri: input.browser.redirectUri,
            },
            clientId,
            clientSecret,
            googleSubject: input.provider.googleSubject,
            originalEmail: input.provider.originalOwnerEmail,
            prepareConnector: async (connectorId) => {
              const prepared = await prepareGoogleProviderLease({
                control: input.provider.control,
                container: input.provider.container,
                project: input.provider.project,
                service: input.provider.service,
                image: input.provider.image,
                configFile: input.provider.configFile,
                receiptFile: input.provider.receiptFile,
                healthDiagnosticFile: input.provider.healthDiagnosticFile,
                role: target.label,
                googleSubject: input.provider.googleSubject,
                originalEmail: input.provider.originalOwnerEmail,
                changedEmail: input.provider.changedProviderEmail,
                expectedUserinfoMethod: input.provider.expectedUserinfoMethod,
                ...(input.provider.resetPrivateFilesOnStop && { resetPrivateFilesOnStop: true }),
                ...(input.provider.healthTiming && {
                  healthTiming: input.provider.healthTiming,
                }),
                clientId,
                clientSecret,
                connectorId,
                targetOrigin: target.coreUrl,
              });
              providerLease = prepared;
              return prepared;
            },
            takeBrowserCode: async () => providerLease?.takeBrowserCode() ?? fail(),
            ...(mode === 'wrong-state' && {
              authorizationMode: 'wrong-state' as const,
              takeWrongStateControlCode: async () =>
                providerLease?.takeWrongStateControlCode() ?? fail(),
            }),
            use: async (value) => {
              stage = 'capability';
              const replay =
                mode === 'replay'
                  ? createGoogleBrowserReplayTestControl({
                      authorization: value.capability,
                      targetOrigin: target.coreUrl,
                      connectorId: value.connectorId,
                      ownerSnapshot: value.ownerSnapshot,
                    })
                  : undefined;
              const capability = replay?.capability ?? value.capability;
              const observer = requirePlaywrightBrand
                ? withPlaywrightExternalAuthorizationCapability(input.observer, capability)
                : (input.createObserverForTesting?.(capability) ?? input.observer);
              stage = 'context';
              try {
                return await observer.runInFreshContext(
                  'experience',
                  input.signal,
                  target,
                  async (session) => {
                    const adaptedSession = adaptPhase1SessionForEmailPassword(session, {
                      ...input.browser,
                      expectedIssuer,
                      expectedSubject: value.ownerId,
                      canonicalEmail: input.provider.originalOwnerEmail,
                      resource: status.resource.indicator,
                    });
                    if (mode === 'wrong-state') {
                      const readOutcome = session.readExternalCallbackOutcome;
                      if (typeof readOutcome !== 'function') {
                        return targetFail('capability');
                      }
                      stage = 'wrong-state-owner-before';
                      const before = structuredClone(await value.ownerSnapshot());
                      stage = 'wrong-state-open';
                      await adaptedSession.navigate('google-wrong-state-open', '/demo-app');
                      stage = 'wrong-state-sign-in';
                      await adaptedSession.waitForRoute('google-wrong-state-sign-in', [
                        '/sign-in',
                        '/sign-in/identifier',
                        '/sign-in/password',
                      ]);
                      stage = 'wrong-state-provider-count';
                      await session.expectCount(
                        'google-wrong-state-provider-count',
                        googleSignInButtonSelectorCandidate,
                        1
                      );
                      stage = 'wrong-state-provider-click';
                      await session.click(
                        'google-wrong-state-provider',
                        googleSignInButtonSelectorCandidate
                      );
                      stage = 'wrong-state-callback-outcome';
                      const outcome = await readOutcome
                        .call(
                          session,
                          'google-wrong-state-callback',
                          `/callback/${encodeURIComponent(value.connectorId)}`
                        )
                        .catch((error: unknown) => {
                          stage = `wrong-state-callback-${externalCallbackFailureReason(error)}`;
                          wrongStateCallbackStage = stage;
                          throw error;
                        });
                      stage = 'wrong-state-owner-after';
                      const after = structuredClone(await value.ownerSnapshot());
                      if (!isDeepStrictEqual(before, after)) {
                        return fail();
                      }
                      stage = 'wrong-state-authorization';
                      const authorization = value.observation();
                      const invalidAuthorizationField = [
                        authorization.requestCount === 1 || 'request-count',
                        authorization.queryShapeExact || 'query-shape',
                        authorization.clientMatched || 'client',
                        authorization.callbackMatched || 'callback',
                        authorization.responseTypeCode || 'response-type',
                        authorization.scopeExact || 'scope',
                        authorization.stateFormatValid || 'state-format',
                        !authorization.stateRoundTrip || 'state-round-trip',
                        authorization.fulfilledOnce || 'fulfilled',
                      ].find((value): value is string => typeof value === 'string');
                      if (invalidAuthorizationField) {
                        stage = `wrong-state-authorization-${invalidAuthorizationField}`;
                        return targetFail(stage);
                      }
                      stage = 'wrong-state-provider';
                      await value.assertWrongStateProviderCase();
                      return Object.freeze({
                        ...outcome,
                        ownerPreserved: true as const,
                        authorization,
                      });
                    }
                    try {
                      const normal = await runCommonGoogleExistingOwnerSignIn({
                        session: {
                          ...adaptedSession,
                          expectCount: async (step, selector, expected) =>
                            session.expectCount(step, selector, expected),
                        },
                        expectedSubject: value.ownerId,
                        originalOwnerEmail: input.provider.originalOwnerEmail,
                        changedProviderEmail: input.provider.changedProviderEmail,
                        assertChangedEmailProviderCase: async () =>
                          value.assertChangedEmailProviderCase(
                            mode === 'replay' ? 'replay' : 'positive'
                          ),
                        authorizationObservation: value.observation,
                      });
                      if (mode !== 'replay') {
                        return normal;
                      }
                      const replayObservation = replay?.observation();
                      if (!replayObservation) {
                        return fail();
                      }
                      return replayObservation;
                    } catch (error: unknown) {
                      if (preservesFlowStage(error)) {
                        flowError = new TypeError(error.message);
                      }
                      throw error;
                    }
                  }
                );
              } catch (error: unknown) {
                if (
                  error instanceof AggregateError &&
                  !isDuplicateExternalCallbackCleanup(error, wrongStateCallbackStage)
                ) {
                  cleanupFailed = true;
                }
                throw error;
              }
            },
          });
        } catch (error: unknown) {
          const observedFixtureStage = fixtureStage(error);
          if (
            observedFixtureStage &&
            (stage === 'fixture' || fixtureCleanupStage(observedFixtureStage))
          ) {
            selectedFixtureStage = observedFixtureStage;
          }
          if (error instanceof AggregateError && !selectedFixtureStage) {
            cleanupFailed = true;
          }
          throw error;
        }
      };
      if (target.label === 'candidate') {
        stage = 'management';
        return await withPhase2AdminManagementBearer(
          target,
          input.fixture,
          async (bearer) =>
            executeFixture(createBearerPhase2AdminRequest(target, bearer, requestFetch)),
          { fetch: requestFetch }
        );
      }
      stage = 'fixture';
      return await input.fixture.withSecretLease(async () =>
        executeFixture(createReferencePhase2AdminRequest(target, requestFetch))
      );
    });
  } catch {
    if (cleanupFailed) {
      return targetFail('cleanup');
    }
    if (selectedFixtureStage && fixtureCleanupStage(selectedFixtureStage)) {
      return targetFail(selectedFixtureStage);
    }
    if (flowError) {
      throw flowError;
    }
    if (selectedFixtureStage) {
      return targetFail(selectedFixtureStage);
    }
    return targetFail(stage);
  }
}

export const runCommonGoogleExistingOwnerForTarget = async (
  input: CommonGoogleExistingOwnerTargetDriverInput
): Promise<CommonGoogleExistingOwnerProjection> =>
  executeCommonGoogleExistingOwnerForTarget(input, true, 'normal');

export const runCommonGoogleExistingOwnerWrongStateForTarget = async (
  input: CommonGoogleExistingOwnerTargetDriverInput
): Promise<CommonGoogleExistingOwnerWrongStateObservation> =>
  executeCommonGoogleExistingOwnerForTarget(input, true, 'wrong-state');

export const runCommonGoogleExistingOwnerReplayForTarget = async (
  input: CommonGoogleExistingOwnerTargetDriverInput
): Promise<CommonGoogleExistingOwnerReplayObservation> =>
  executeCommonGoogleExistingOwnerForTarget(input, true, 'replay');

/** Test-only composition executor. Production always requires a branded Playwright observer. */
export const runCommonGoogleExistingOwnerForTargetTesting = async (
  input: CommonGoogleExistingOwnerTargetDriverInput
): Promise<CommonGoogleExistingOwnerProjection> => {
  if (process.env.NODE_ENV !== 'test') {
    return fail();
  }
  return executeCommonGoogleExistingOwnerForTarget(input, false, 'normal');
};

/** Test-only wrong-state composition executor. Production always requires a branded Playwright observer. */
export const runCommonGoogleExistingOwnerWrongStateForTargetTesting = async (
  input: CommonGoogleExistingOwnerTargetDriverInput
): Promise<CommonGoogleExistingOwnerWrongStateObservation> => {
  if (process.env.NODE_ENV !== 'test') {
    return fail();
  }
  return executeCommonGoogleExistingOwnerForTarget(input, false, 'wrong-state');
};

/** Test-only replay composition executor. Production always requires a branded Playwright observer. */
export const runCommonGoogleExistingOwnerReplayForTargetTesting = async (
  input: CommonGoogleExistingOwnerTargetDriverInput
): Promise<CommonGoogleExistingOwnerReplayObservation> => {
  if (process.env.NODE_ENV !== 'test') {
    return fail();
  }
  return executeCommonGoogleExistingOwnerForTarget(input, false, 'replay');
};
/* eslint-enable complexity, max-lines, no-await-in-loop, no-constant-condition, no-return-await, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unnecessary-condition, @typescript-eslint/return-await */
