/* eslint-disable complexity, max-lines, no-await-in-loop, no-constant-condition, no-return-await, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unnecessary-condition, @typescript-eslint/return-await -- Target admission, bounded discovery, credential scopes, provider fixture, browser context, and cleanup-stage preservation form one composition boundary. Explicit return-await keeps both target promises inside the outer stage-latch boundary. */
import { isDeepStrictEqual, types as nodeTypes } from 'node:util';

import { validateTargetConfig } from '../../config.js';
import type { TargetConfig } from '../../model.js';
import type {
  Phase1BrowserExperienceFailure,
  Phase1BrowserGroupObserver,
} from '../../phase-1/browser/contracts.js';
import {
  isPlaywrightBrowserGroupObserver,
  type PlaywrightExternalAuthorizationCapability,
} from '../../phase-1/browser/playwright-session.js';
import { withPhase2AdminManagementBearer } from '../clients/admin-management-bearer.js';
import {
  createBearerPhase2AdminRequest,
  createReferencePhase2AdminRequest,
  type Phase2AdminRequestFunction,
  type ProvisionedPhase2Fixture,
} from '../fixtures.js';

import { runCommonWechatWebExistingOwner, type CommonWechatWebStage } from './common-wechat-web.js';
import type { CommonEmailPasswordBrowserConfiguration } from './fresh-context-password-controls.js';
import { adaptPhase1SessionForEmailPassword } from './phase1-session-adapter.js';
import {
  type SelectedWechatWebProviderLease,
  wechatWebSignInButtonSelectorCandidate,
  withSelectedWechatWebConnectorFixture,
} from './selected-wechat-web-connector-fixture.js';
import {
  createWechatWebCrossInteractionTestControl,
  type WechatWebCrossInteractionFailureStage,
  type WechatWebCrossInteractionObservation,
} from './wechat-web-cross-interaction-control.js';
import { runWechatWebProviderDenialControl } from './wechat-web-provider-denial-control.js';
import type { WechatWebProviderDenialStage } from './wechat-web-provider-denial-control.js';
import {
  admitsWechatWebStateControlFailure,
  completeWechatWebStateControlRetry,
} from './wechat-web-state-control-retry.js';

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
  'stop-provider-state',
  'stop-provider-config-identity',
  'stop-provider-receipt-identity',
  'restore-app',
  'delete-role',
  'restore-sie',
  'delete-connector',
]);
type FixtureStage = `fixture-${string}`;
type ConsentStage = `consent-route-${string}`;
type Stage =
  | 'admission'
  | 'capability'
  | 'cleanup'
  | 'context'
  | `consent-field-invalid-${'route' | 'operation' | 'status' | 'binding' | 'code' | 'authorization' | 'state' | 'tuple'}`
  | 'context-adapter'
  | 'context-flow'
  | 'context-after-flow'
  | `context-control-${WechatWebProviderDenialStage}`
  | `context-positive-${CommonWechatWebStage}`
  | `context-positive-consent-${'response' | 'authorization' | 'state' | 'route' | 'complete'}`
  | 'credentials'
  | 'discovery'
  | 'fixture'
  | 'management'
  | `cleanup-${string}`
  | FixtureStage
  | ConsentStage;
const fail = (): never => {
  throw new TypeError('Invalid Common Wechat existing-owner target composition');
};
const targetReceipt = (stage: Stage): string => `ASTER_WECHAT_TARGET_STAGE=${stage}\n`;
const targetFail = (stage: Stage): never => {
  process.stderr.write(targetReceipt(stage));
  throw new TypeError(`Common Wechat existing-owner target failed: ${stage}`);
};
export const commonWechatWebTargetFailForTesting = (): never =>
  process.env.NODE_ENV === 'test' ? targetFail('cleanup') : fail();
export const commonWechatWebTargetReceiptForTesting = (): string | undefined =>
  process.env.NODE_ENV === 'test' ? targetReceipt('cleanup') : undefined;
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
const consentStagePattern =
  /^consent-route-(?:sign-in|register|continue|demo|error|callback|other)-(?:social-verify|identification|submit|resume|none)-(?:200|201|204|302|303|400|401|403|404|409|422|500|503|0)-(?:complete|missing-resume-(?:not-issued|path-mismatch|expired|secure-mismatch|other)|missing-mapping|missing-shared|missing-session|not-applicable)-(?:user-identity_not_exist|user-missing_profile|session-verification_session_not_found|session-interaction_not_found|session-invalid_credentials|user-suspended|user-sign_in_method_not_enabled|session-identity_conflict|user-email_already_in_use|verification_record-permission_denied|guard-invalid_input|connector-general|connector-wechat_unionid_required|connector-social_auth_code_invalid|connector-invalid_response|unknown|none)-auth-[01]{9}-state-(?:stored|cleared|unavailable)$/u;
const closedConsentRoutes = new Set([
  'sign-in',
  'register',
  'continue',
  'demo',
  'error',
  'callback',
  'other',
]);
const closedConsentOperations = new Set([
  'social-verify',
  'identification',
  'submit',
  'resume',
  'none',
]);
const closedConsentStatuses = new Set([
  200, 201, 204, 302, 303, 400, 401, 403, 404, 409, 422, 500, 503, 0,
]);
const closedConsentBindings = new Set([
  'complete',
  'missing-resume-not-issued',
  'missing-resume-path-mismatch',
  'missing-resume-expired',
  'missing-resume-secure-mismatch',
  'missing-resume-other',
  'missing-mapping',
  'missing-shared',
  'missing-session',
  'not-applicable',
]);
const closedConsentCodes = new Set([
  'user.identity_not_exist',
  'user.missing_profile',
  'session.verification_session_not_found',
  'session.interaction_not_found',
  'session.invalid_credentials',
  'user.suspended',
  'user.sign_in_method_not_enabled',
  'session.identity_conflict',
  'user.email_already_in_use',
  'verification_record.permission_denied',
  'guard.invalid_input',
  'connector.general',
  'connector.wechat_unionid_required',
  'connector.social_auth_code_invalid',
  'connector.invalid_response',
  'unknown',
  'none',
]);
const closedConsentStates = new Set(['state-stored', 'state-cleared', 'state-unavailable']);
type InvalidConsentStage = `consent-field-invalid-${
  | 'route'
  | 'operation'
  | 'status'
  | 'binding'
  | 'code'
  | 'authorization'
  | 'state'
  | 'tuple'}`;
const closedConsentStage = (
  input: Readonly<{
    route: string;
    response: Phase1BrowserExperienceFailure;
    authorizationBits: string;
    state: string;
  }>,
  onInvalid?: (stage: InvalidConsentStage) => void
): Readonly<{ stage: ConsentStage; detail: string }> => {
  const invalid = (stage: InvalidConsentStage): never => {
    onInvalid?.(stage);
    return targetFail(stage);
  };
  if (!closedConsentRoutes.has(input.route)) {
    return invalid('consent-field-invalid-route');
  }
  if (!closedConsentOperations.has(input.response.operation)) {
    return invalid('consent-field-invalid-operation');
  }
  if (!closedConsentStatuses.has(input.response.status)) {
    return invalid('consent-field-invalid-status');
  }
  if (!closedConsentBindings.has(input.response.binding)) {
    return invalid('consent-field-invalid-binding');
  }
  if (!closedConsentCodes.has(input.response.code)) {
    return invalid('consent-field-invalid-code');
  }
  if (!/^[01]{9}$/u.test(input.authorizationBits)) {
    return invalid('consent-field-invalid-authorization');
  }
  if (!closedConsentStates.has(input.state)) {
    return invalid('consent-field-invalid-state');
  }
  const detail = `${input.route}-${input.response.operation}-${input.response.status}-${input.response.binding}-${input.response.code.replaceAll('.', '-')}-auth-${input.authorizationBits}-${input.state}`;
  const value = `consent-route-${detail}`;
  if (!consentStagePattern.test(value)) {
    return invalid('consent-field-invalid-tuple');
  }
  // The exact closed grammar above is the runtime constructor for this template type.
  // eslint-disable-next-line no-restricted-syntax
  return Object.freeze({ stage: value as ConsentStage, detail });
};
export const closedConsentStageForTesting = (
  input: Parameters<typeof closedConsentStage>[0],
  onInvalid?: (stage: InvalidConsentStage) => void
) => (process.env.NODE_ENV === 'test' ? closedConsentStage(input, onInvalid) : fail());
const preservesFlowStage = (error: unknown): error is TypeError =>
  !nodeTypes.isProxy(error) &&
  error instanceof TypeError &&
  /^Common WeChat Web failed: (?:admission|initialization|provider-count|provider-click|consent-click|consent-route(?:-(?:sign-in|register|continue|demo|error|callback|other)-(?:social-verify|identification|submit|resume|none)-(?:200|201|204|302|303|400|401|403|404|409|422|500|503|0)-(?:complete|missing-resume-(?:not-issued|path-mismatch|expired|secure-mismatch|other)|missing-mapping|missing-shared|missing-session|not-applicable)-(?:user-identity_not_exist|user-missing_profile|session-verification_session_not_found|session-interaction_not_found|session-invalid_credentials|user-suspended|user-sign_in_method_not_enabled|session-identity_conflict|user-email_already_in_use|verification_record-permission_denied|guard-invalid_input|connector-general|connector-wechat_unionid_required|connector-social_auth_code_invalid|connector-invalid_response|unknown|none)-auth-[01]{9}-state-(?:stored|cleared|unavailable))?|callback(?:-[a-z0-9-]+)?|profile|refresh|provider)$/u.test(
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
const fixtureStage = (error: unknown, depth = 0): FixtureStage | undefined => {
  if (depth >= 4) {
    return undefined;
  }
  const direct = /^Selected Wechat connector fixture failed: ([a-z0-9]+(?:-[a-z0-9]+)*)$/u.exec(
    ownMessage(error) ?? ''
  )?.[1];
  if (
    direct &&
    (connectorFixtureStages.has(direct) ||
      /^delete-connector-status-(?:400|401|403|404|409|422|500|503)$/u.test(direct))
  ) {
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
      /^fixture-(?:stop-provider(?:-(?:state|config-identity|receipt-identity))?|restore-app|delete-role|restore-sie|delete-connector(?:-status-(?:400|401|403|404|409|422|500|503))?|existing-owner-cleanup-user)$/u.test(
        stage
      )
    ) ?? stages[0]
  );
};
export const commonWechatWebTargetFixtureStageForTesting = (
  error: unknown
): FixtureStage | undefined => {
  if (process.env.NODE_ENV !== 'test') {
    return undefined;
  }
  return fixtureStage(error);
};
const fixtureCleanupStage = (stage: FixtureStage): boolean =>
  /^fixture-(?:stop-provider(?:-(?:state|config-identity|receipt-identity))?|restore-app|delete-role|restore-sie|delete-connector(?:-status-(?:400|401|403|404|409|422|500|503))?|existing-owner-cleanup-user|prepare-connector-compensation)$/u.test(
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

export type WechatProviderCredentialLease = Readonly<{
  getClientId(): string;
  getClientSecret(): string;
  getSmsAccessSecret?(): string;
  toJSON(): never;
}>;

export type WechatProviderTargetConfiguration = Readonly<{
  wechatSubject: string;
  originalOwnerEmail: string;
}>;

export type CommonWechatWebProviderControlKind =
  | 'noUnionId'
  | 'invalidCode'
  | 'replay'
  | 'malformedProvider';
export type CommonWechatWebProviderControlObservation = Readonly<{
  accepted: false;
  status: number;
  error: string;
  ownerPreserved: true;
}>;
export type CommonWechatWebStateControlKind = 'missingState' | 'wrongState' | 'wrongCallback';
export type CommonWechatWebStateControlObservation = Readonly<{
  accepted: false;
  status: number;
  error: string;
  ownerPreserved: true;
  statePreserved: true;
  proofPreserved: true;
  correctRetryAccepted: boolean;
}>;
type CommonWechatWebExecutionKind =
  | 'positive'
  | CommonWechatWebProviderControlKind
  | CommonWechatWebStateControlKind
  | 'crossInteraction';
const isProviderControlKind = (
  value: CommonWechatWebExecutionKind
): value is CommonWechatWebProviderControlKind =>
  value === 'noUnionId' ||
  value === 'invalidCode' ||
  value === 'replay' ||
  value === 'malformedProvider';

type CommonWechatWebExistingOwnerProjection = Awaited<
  ReturnType<typeof runCommonWechatWebExistingOwner>
>;

export type CommonWechatWebExistingOwnerTargetDriverInput = Readonly<{
  target: TargetConfig;
  fixture: ProvisionedPhase2Fixture;
  signal: AbortSignal;
  browser: Omit<CommonEmailPasswordBrowserConfiguration, 'expectedIssuer'>;
  provider: WechatProviderTargetConfiguration;
  fetch?: typeof fetch;
  createObserver(capability: PlaywrightExternalAuthorizationCapability): Phase1BrowserGroupObserver;
  withProviderCredentialLease<Result>(
    use: (lease: WechatProviderCredentialLease) => Promise<Result>
  ): Promise<Result>;
  prepareProvider(
    input: Readonly<{
      connectorId: string;
      clientId: string;
      clientSecret: string;
      targetOrigin: string;
      role: 'oracle' | 'candidate';
      subject: string;
      providerCase?: 'positive' | CommonWechatWebProviderControlKind;
    }>
  ): Promise<SelectedWechatWebProviderLease & Readonly<{ takeBrowserCode(): Promise<string> }>>;
}>;

const admit = (
  input: CommonWechatWebExistingOwnerTargetDriverInput,
  target: TargetConfig
): NonNullable<ProvisionedPhase2Fixture['status']> => {
  const status = input.fixture.status ?? targetFail('admission');
  const expectedRedirectUri = new URL('/demo-app', target.coreUrl).href;
  const scopes = input.browser.demo.scope.split(' ');
  if (
    input.signal.aborted ||
    typeof input.createObserver !== 'function' ||
    typeof input.withProviderCredentialLease !== 'function' ||
    typeof input.prepareProvider !== 'function' ||
    input.browser.demo.appId !== status.client.id ||
    input.browser.redirectUri !== expectedRedirectUri ||
    input.browser.demo.resource !== status.resource.indicator ||
    input.browser.resourceScope !== status.resource.scopeName ||
    input.browser.demo.prompt !== 'consent' ||
    new Set(scopes).size !== scopes.length ||
    !['openid', 'offline_access', 'profile', 'email', status.resource.scopeName].every((scope) =>
      scopes.includes(scope)
    ) ||
    !isBounded(input.provider.wechatSubject) ||
    !isBounded(input.provider.originalOwnerEmail)
  ) {
    return targetFail('admission');
  }
  return status;
};

const executeCommonWechatWebExistingOwnerForTarget = async (
  input: CommonWechatWebExistingOwnerTargetDriverInput,
  requirePlaywrightBrand: boolean,
  providerCase: CommonWechatWebExecutionKind = 'positive'
): Promise<
  | CommonWechatWebExistingOwnerProjection
  | CommonWechatWebProviderControlObservation
  | CommonWechatWebStateControlObservation
  | WechatWebCrossInteractionObservation
> => {
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
  let cleanupFailed = false;
  let readCrossFailure: (() => WechatWebCrossInteractionFailureStage | undefined) | undefined;
  let readCrossObservation: (() => WechatWebCrossInteractionObservation | undefined) | undefined;
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
        let providerLease:
          | (SelectedWechatWebProviderLease & Readonly<{ takeBrowserCode(): Promise<string> }>)
          | undefined;
        let providerControlFailure: Readonly<{ status: number; error: string }> | undefined;
        let storedSocialState = false;
        try {
          return await withSelectedWechatWebConnectorFixture({
            fixture: input.fixture,
            request,
            targetOrigin: target.coreUrl,
            browser: {
              clientId: input.browser.demo.appId,
              redirectUri: input.browser.redirectUri,
            },
            clientId,
            clientSecret,
            channel: 'web',
            wechatSubject: input.provider.wechatSubject,
            ownerEmail: input.provider.originalOwnerEmail,
            prepareConnector: async (connectorId) => {
              const prepared = await input.prepareProvider({
                role: target.label,
                subject: input.provider.wechatSubject,
                clientId,
                clientSecret,
                connectorId,
                targetOrigin: target.coreUrl,
                providerCase: isProviderControlKind(providerCase) ? providerCase : 'positive',
              });
              providerLease = prepared;
              return prepared;
            },
            takeBrowserCode: async () =>
              isProviderControlKind(providerCase)
                ? (providerLease?.takeControlCode?.(providerCase) ?? fail())
                : (providerLease?.takeBrowserCode() ?? fail()),
            callbackMode:
              providerCase === 'missingState'
                ? 'missing-state'
                : providerCase === 'wrongState'
                  ? 'wrong-state'
                  : providerCase === 'wrongCallback'
                    ? 'wrong-callback'
                    : 'normal',
            use: async (value) => {
              const ownerBefore = await value.ownerSnapshot();
              let contextProgress:
                | 'adapter'
                | 'flow'
                | `positive-${CommonWechatWebStage}`
                | `positive-consent-${
                    | 'response'
                    | 'authorization'
                    | 'state'
                    | 'route'
                    | 'complete'}`
                | `control-${WechatWebProviderDenialStage}`
                | 'after-flow' = 'adapter';
              let observedConsentStage: ConsentStage | undefined;
              stage = 'capability';
              const crossControl =
                providerCase === 'crossInteraction'
                  ? createWechatWebCrossInteractionTestControl({
                      authorization: value.capability,
                      clientId: input.browser.demo.appId,
                      targetOrigin: target.coreUrl,
                      connectorId: value.connectorId,
                      ownerSnapshot: value.ownerSnapshot,
                      redirectUri: input.browser.redirectUri,
                      resource: input.browser.demo.resource,
                      scope: input.browser.demo.scope,
                    })
                  : undefined;
              readCrossFailure = crossControl?.failureStage;
              readCrossObservation = crossControl?.observation;
              const observer = input.createObserver(crossControl?.capability ?? value.capability);
              if (requirePlaywrightBrand && !isPlaywrightBrowserGroupObserver(observer)) {
                return targetFail('capability');
              }
              stage = 'context';
              try {
                return await observer.runInFreshContext(
                  'experience',
                  input.signal,
                  target,
                  async (session) => {
                    const adapted = adaptPhase1SessionForEmailPassword(session, {
                      ...input.browser,
                      expectedIssuer,
                      expectedSubject: value.ownerId ?? fail(),
                      canonicalEmail: input.provider.originalOwnerEmail,
                      resource: status.resource.indicator,
                    });
                    contextProgress = 'flow';
                    if (isProviderControlKind(providerCase)) {
                      const readFailure = session.readExperienceFailure;
                      const beginObservation = session.beginExperienceObservation;
                      if (
                        typeof readFailure !== 'function' ||
                        typeof beginObservation !== 'function'
                      ) {
                        return targetFail('capability');
                      }
                      const expected =
                        providerCase === 'noUnionId'
                          ? {
                              status: 400 as const,
                              error: 'connector.wechat_unionid_required' as const,
                            }
                          : providerCase === 'malformedProvider'
                            ? {
                                status: 400 as const,
                                error: 'connector.invalid_response' as const,
                              }
                            : {
                                status: 401 as const,
                                error: 'connector.social_auth_code_invalid' as const,
                              };
                      const denial = await runWechatWebProviderDenialControl({
                        selector: wechatWebSignInButtonSelectorCandidate,
                        expectedStatus: expected.status,
                        expectedError: expected.error,
                        ownerBefore,
                        ownerSnapshot: value.ownerSnapshot,
                        reportStage: (controlStage) => {
                          contextProgress = `control-${controlStage}`;
                        },
                        session: {
                          navigate: adapted.navigate,
                          waitForRoute: adapted.waitForRoute,
                          expectCount: async (step, selector, expectedCount) =>
                            session.expectCount(step, selector, expectedCount),
                          click: adapted.click,
                          beginExperienceObservation: async () => beginObservation.call(session),
                          readExperienceFailure: async () => readFailure.call(session),
                        },
                      });
                      contextProgress = 'after-flow';
                      return denial;
                    }
                    if (providerCase === 'missingState') {
                      const expectWithoutState = session.expectExternalCallbackWithoutState;
                      if (typeof expectWithoutState !== 'function') {
                        return targetFail('capability');
                      }
                      expectWithoutState.call(session);
                    }
                    try {
                      const positive = await runCommonWechatWebExistingOwner({
                        session: {
                          ...adapted,
                          expectCount: async (step, selector, expected) =>
                            session.expectCount(step, selector, expected),
                          consentFailureRoute: async () => {
                            contextProgress = 'positive-consent-response';
                            const response = (await session.readExperienceFailure?.()) ?? {
                              operation: 'none' as const,
                              status: 0 as const,
                              binding: 'not-applicable' as const,
                              code: 'none' as const,
                            };
                            if (
                              response.status >= 400 &&
                              response.status <= 599 &&
                              response.code !== 'none'
                            ) {
                              providerControlFailure = Object.freeze({
                                status: response.status,
                                error: response.code,
                              });
                            }
                            contextProgress = 'positive-consent-authorization';
                            const authorization = value.observation();
                            const authorizationBits = [
                              authorization.requestCount === 1,
                              authorization.queryShapeExact,
                              authorization.clientMatched,
                              authorization.callbackMatched,
                              authorization.responseTypeCode,
                              authorization.scopeExact,
                              authorization.stateFormatValid,
                              authorization.stateRoundTrip,
                              authorization.fulfilledOnce,
                            ]
                              .map((value) => (value ? '1' : '0'))
                              .join('');
                            contextProgress = 'positive-consent-state';
                            let storedState = 'state-unavailable';
                            try {
                              storedSocialState =
                                (await session.hasStoredSocialState?.(value.connectorId)) ?? false;
                              storedState = storedSocialState ? 'state-stored' : 'state-cleared';
                            } catch {
                              storedSocialState = false;
                            }
                            const consentDetail = (kind: string) => {
                              const projection = closedConsentStage(
                                { route: kind, response, authorizationBits, state: storedState },
                                (invalidStage) => {
                                  stage = invalidStage;
                                }
                              );
                              observedConsentStage = projection.stage;
                              return projection.detail;
                            };
                            contextProgress = 'positive-consent-route';
                            for (const [kind, paths] of [
                              ['sign-in', ['/sign-in', '/sign-in/identifier', '/sign-in/password']],
                              ['register', ['/register']],
                              ['continue', ['/continue']],
                              ['demo', ['/demo-app']],
                              ['error', ['/error']],
                              ['callback', ['/callback']],
                            ] as const) {
                              let routeMatched = false;
                              try {
                                await session.assertRoute(
                                  `wechat-web-consent-failure-${kind}`,
                                  'core',
                                  paths
                                );
                                routeMatched = true;
                              } catch {
                                // Try the next closed route class.
                              }
                              if (routeMatched) {
                                contextProgress = 'positive-consent-complete';
                                return consentDetail(kind);
                              }
                            }
                            contextProgress = 'positive-consent-complete';
                            return consentDetail('other');
                          },
                        },
                        selector: wechatWebSignInButtonSelectorCandidate,
                        expectedSubject: value.ownerId ?? fail(),
                        reportStage: (positiveStage) => {
                          contextProgress = `positive-${positiveStage}`;
                        },
                        providerObservation: async () => {
                          const authorization = value.observation();
                          const provider = await providerLease?.observation();
                          if (
                            authorization.requestCount !== 1 ||
                            !authorization.queryShapeExact ||
                            !authorization.clientMatched ||
                            !authorization.callbackMatched ||
                            !authorization.responseTypeCode ||
                            !authorization.scopeExact ||
                            !authorization.stateFormatValid ||
                            !authorization.stateRoundTrip ||
                            !authorization.fulfilledOnce ||
                            !provider
                          ) {
                            return fail();
                          }
                          return Object.freeze({ ...provider, authorizationExact: true as const });
                        },
                      });
                      contextProgress = 'after-flow';
                      if (providerCase === 'crossInteraction') {
                        if (crossControl?.observation()) {
                          throw new TypeError('Invalid WeChat Web cross-interaction after-control');
                        }
                        const crossFailure = crossControl?.failureStage();
                        if (crossFailure) {
                          throw new TypeError(
                            `Invalid WeChat Web cross-interaction ${crossFailure}`
                          );
                        }
                        return crossControl?.observation() ?? fail();
                      }
                      return positive;
                    } catch (error: unknown) {
                      if (providerCase === 'crossInteraction') {
                        const crossFailure = crossControl?.failureStage();
                        if (crossFailure) {
                          throw new TypeError(
                            `Invalid WeChat Web cross-interaction ${crossFailure}`
                          );
                        }
                      }
                      if (
                        ['missingState', 'wrongState', 'wrongCallback'].includes(providerCase) &&
                        admitsWechatWebStateControlFailure({
                          errorMessage: ownMessage(error),
                          storedSocialState,
                          expectedStoredSocialState: providerCase !== 'wrongState',
                          providerFailureObserved: providerControlFailure !== undefined,
                          authorization: value.observation(),
                        })
                      ) {
                        const retryPath = value.retryPath();
                        if (!retryPath) {
                          return fail();
                        }
                        await completeWechatWebStateControlRetry({
                          retryPath,
                          expectedOwnerId: value.ownerId ?? fail(),
                          ownerBefore,
                          ownerSnapshot: value.ownerSnapshot,
                          session: adapted,
                        });
                        return Object.freeze({
                          accepted: false as const,
                          status: 0,
                          error: 'none',
                          ownerPreserved: true as const,
                          statePreserved: true as const,
                          proofPreserved: true as const,
                          correctRetryAccepted: true as const,
                        });
                      }
                      if (providerCase !== 'positive' && providerControlFailure) {
                        const ownerAfter = await value.ownerSnapshot();
                        if (!isDeepStrictEqual(ownerBefore, ownerAfter)) {
                          return fail();
                        }
                        return Object.freeze({
                          accepted: false as const,
                          status: providerControlFailure.status,
                          error: providerControlFailure.error,
                          ownerPreserved: true as const,
                        });
                      }
                      if (observedConsentStage) {
                        stage = observedConsentStage;
                        throw error;
                      }
                      if (preservesFlowStage(error)) {
                        flowError = new TypeError(error.message);
                      }
                      throw error;
                    }
                  }
                );
              } catch (error: unknown) {
                if (stage === 'context') {
                  stage = `context-${contextProgress}`;
                }
                if (error instanceof AggregateError) {
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
    if (providerCase === 'crossInteraction') {
      if (readCrossObservation?.()) {
        throw new TypeError('Invalid WeChat Web cross-interaction after-control');
      }
      const crossFailure = readCrossFailure?.();
      if (crossFailure) {
        throw new TypeError(`Invalid WeChat Web cross-interaction ${crossFailure}`);
      }
    }
    if (cleanupFailed && flowError) {
      const flowStage = /^Common WeChat Web failed: ([a-z0-9-]+)$/u.exec(
        ownMessage(flowError) ?? ''
      )?.[1];
      return targetFail(flowStage ? `cleanup-${flowStage}` : 'cleanup');
    }
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
};

type CommonWechatWebExecutionResult = Awaited<
  ReturnType<typeof executeCommonWechatWebExistingOwnerForTarget>
>;
const isPositiveResult = (
  value: CommonWechatWebExecutionResult
): value is CommonWechatWebExistingOwnerProjection => 'channel' in value;
const isProviderControlResult = (
  value: CommonWechatWebExecutionResult
): value is CommonWechatWebProviderControlObservation =>
  'accepted' in value && !('statePreserved' in value) && !('requestCount' in value);
const isStateControlResult = (
  value: CommonWechatWebExecutionResult
): value is CommonWechatWebStateControlObservation => 'statePreserved' in value;
const isCrossInteractionResult = (
  value: CommonWechatWebExecutionResult
): value is WechatWebCrossInteractionObservation => 'requestCount' in value;

export const runCommonWechatWebExistingOwnerForTarget = async (
  input: CommonWechatWebExistingOwnerTargetDriverInput
): Promise<CommonWechatWebExistingOwnerProjection> => {
  const result = await executeCommonWechatWebExistingOwnerForTarget(input, true, 'positive');
  return isPositiveResult(result) ? result : fail();
};

export const runCommonWechatWebProviderControlForTarget = async (
  input: CommonWechatWebExistingOwnerTargetDriverInput,
  kind: CommonWechatWebProviderControlKind
): Promise<CommonWechatWebProviderControlObservation> => {
  const result = await executeCommonWechatWebExistingOwnerForTarget(input, true, kind);
  return isProviderControlResult(result) ? result : fail();
};

export const runCommonWechatWebStateControlForTarget = async (
  input: CommonWechatWebExistingOwnerTargetDriverInput,
  kind: CommonWechatWebStateControlKind
): Promise<CommonWechatWebStateControlObservation> => {
  const result = await executeCommonWechatWebExistingOwnerForTarget(input, true, kind);
  return isStateControlResult(result) ? result : fail();
};

export const runCommonWechatWebCrossInteractionForTarget = async (
  input: CommonWechatWebExistingOwnerTargetDriverInput
): Promise<WechatWebCrossInteractionObservation> => {
  let result: CommonWechatWebExecutionResult;
  try {
    result = await executeCommonWechatWebExistingOwnerForTarget(input, true, 'crossInteraction');
  } catch (error: unknown) {
    const message = ownMessage(error);
    if (error instanceof Error && message?.startsWith('Invalid WeChat Web cross-interaction ')) {
      throw error;
    }
    throw new TypeError('Invalid WeChat Web cross-interaction target');
  }
  if (!isCrossInteractionResult(result)) {
    throw new TypeError('Invalid WeChat Web cross-interaction result');
  }
  return result;
};

/** Test-only composition executor. Production always requires a branded Playwright observer. */
export const runCommonWechatWebExistingOwnerForTargetTesting = async (
  input: CommonWechatWebExistingOwnerTargetDriverInput
): Promise<CommonWechatWebExistingOwnerProjection> => {
  if (process.env.NODE_ENV !== 'test') {
    return fail();
  }
  const result = await executeCommonWechatWebExistingOwnerForTarget(input, false, 'positive');
  return isPositiveResult(result) ? result : fail();
};
/* eslint-enable complexity, max-lines, no-await-in-loop, no-constant-condition, no-return-await, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unnecessary-condition, @typescript-eslint/return-await */
