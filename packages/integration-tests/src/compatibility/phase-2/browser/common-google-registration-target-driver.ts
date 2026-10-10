/* eslint-disable complexity, max-lines, max-params, no-await-in-loop, no-constant-condition, no-return-await, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unnecessary-condition, @typescript-eslint/return-await -- Target admission, bounded discovery, credential scopes, provider fixture, browser context, and cleanup-stage preservation form one composition boundary. The denied-control executor carries the complete target/browser authority explicitly. */
import { types as nodeTypes } from 'node:util';

import { validateTargetConfig } from '../../config.js';
import type { TargetConfig } from '../../model.js';
import type {
  Phase1BrowserExperienceFailure,
  Phase1BrowserGroupObserver,
} from '../../phase-1/browser/contracts.js';
import {
  isPlaywrightBrowserGroupObserver,
  type PlaywrightExternalAuthorizationCapability,
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
  runCommonGoogleRegistration,
  type CommonGoogleRegistrationProjection,
} from './common-google-registration.js';
import type { CommonEmailPasswordBrowserConfiguration } from './fresh-context-password-controls.js';
import {
  type GoogleProviderControl,
  type GoogleProviderHealthTiming,
  type GoogleProviderLease,
  prepareGoogleProviderLease,
} from './google-provider-lease.js';
import { adaptPhase1SessionForEmailPassword } from './phase1-session-adapter.js';
import { googleSignInButtonSelectorCandidate } from './selected-google-connector-fixture.js';
import { withSelectedGoogleRegistrationFixture } from './selected-google-registration-fixture.js';

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
  'registration-owner-before',
  'registration-owner-use',
  'registration-owner-after',
  'registration-owner-cleanup',
  'registration-owner-discovery',
  'stop-provider',
  'restore-app',
  'delete-role',
  'restore-sie',
  'delete-connector',
]);
type FixtureStage = `fixture-${string}`;
type RegistrationControlStage = `${'unverified-email' | 'occupied-email'}-control-${
  | 'response'
  | 'consent'
  | 'profile-route'
  | 'profile-input'
  | 'outcome'
  | 'outcome-code'
  | 'outcome-status'
  | 'outcome-error'
  | 'outcome-accepted'
  | 'link-count'
  | 'link-click'
  | 'link-complete'}`;
type RegistrationControlResponseStage = `${
  | 'unverified-email'
  | 'occupied-email'}-control-observed-${Phase1BrowserExperienceFailure['operation']}-${Phase1BrowserExperienceFailure['status']}-${
  | 'known'
  | 'unknown'}-${'incomplete' | 'other'}`;
type RegistrationControlUnknownStage = `${
  | 'unverified-email'
  | 'occupied-email'}-control-unknown-${Phase1BrowserExperienceFailure['operation']}-${Phase1BrowserExperienceFailure['status']}`;
type RegistrationControlRejectedStage = `${
  | 'unverified-email'
  | 'occupied-email'}-control-rejected-${Phase1BrowserExperienceFailure['operation']}-${Phase1BrowserExperienceFailure['status']}-${Exclude<
  Phase1BrowserExperienceFailure['code'],
  CommonGoogleRegistrationControlError | 'unknown'
>}`;
type RegistrationControlValidationStage = `${
  | 'unverified-email'
  | 'occupied-email'}-control-${'invalid-status' | 'disallowed-error'}-${Phase1BrowserExperienceFailure['operation']}-${Phase1BrowserExperienceFailure['status']}-${CommonGoogleRegistrationControlError}`;
type Stage =
  | 'admission'
  | 'capability'
  | 'cleanup'
  | 'context'
  | 'credentials'
  | 'discovery'
  | 'fixture'
  | 'management'
  | 'unverified-email-control'
  | 'unverified-email-owner'
  | 'occupied-email-control'
  | 'occupied-email-owner'
  | 'control-publication'
  | RegistrationControlStage
  | RegistrationControlResponseStage
  | RegistrationControlUnknownStage
  | RegistrationControlRejectedStage
  | RegistrationControlValidationStage
  | FixtureStage;
const fail = (): never => {
  throw new TypeError('Invalid Common Google registration target composition');
};
const targetFail = (stage: Stage): never => {
  throw new TypeError(`Common Google registration target failed: ${stage}`);
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
const ownMessage = (error: unknown): string | undefined => {
  const descriptor =
    !nodeTypes.isProxy(error) && error instanceof Error
      ? Object.getOwnPropertyDescriptor(error, 'message')
      : undefined;
  return descriptor && Object.hasOwn(descriptor, 'value') && typeof descriptor.value === 'string'
    ? descriptor.value
    : undefined;
};
const simpleFlowStages = new Set([
  'admission',
  'initialization',
  'registration-transition',
  'registration-route',
  'provider-count',
  'provider-click',
  'consent-route',
  'consent-click',
  'callback',
  'profile',
  'refresh',
  'owner-lookup',
  'authorization',
]);
const closedFlowStage = (error: unknown): string | undefined => {
  if (nodeTypes.isProxy(error) || !(error instanceof TypeError)) {
    return undefined;
  }
  const stage = /^Common Google registration failed: ([a-z0-9-]+)$/u.exec(
    ownMessage(error) ?? ''
  )?.[1];
  if (!stage) {
    return undefined;
  }
  if (simpleFlowStages.has(stage)) {
    return stage;
  }
  if (
    /^callback-(?:callback-route|callback-facts-s(?:0|1|many)-c(?:0|1|many)-i(?:0|1|many)|cardinality|signin-(?:authority|response|client|redirect|mode|scope|resource|pkce)|callback-(?:authority|response|state|issuer|code)|exchange-(?:authority|response|correlation|client|refresh|target|scope|access))$/u.test(
      stage
    )
  ) {
    return stage;
  }
  return /^consent-route-(?:sign-in|register|continue|demo|error|other)-(?:social-verify|identification|submit|none)-(?:400|401|403|404|409|422|500|503|0)-(?:new-password-required|missing-profile|permission-denied|invalid-verification|interaction-not-found|invalid-credentials|suspended|method-disabled|identity-conflict|email-in-use|proof-absent|interaction-client-expiry|config-absent|event-invalid|owner-missing-signin|attested-email-absent|interaction-rejected|unknown|none)$/u.test(
    stage
  )
    ? stage
    : undefined;
};
const preservesFlowStage = (error: unknown): error is TypeError =>
  closedFlowStage(error) !== undefined;
export const commonGoogleRegistrationFlowStageForTesting = (error: unknown): string | undefined =>
  process.env.NODE_ENV === 'test' ? closedFlowStage(error) : undefined;
const fixtureStage = (error: unknown, depth = 0): FixtureStage | undefined => {
  if (depth >= 4) {
    return undefined;
  }
  const direct = /^Selected Google connector fixture failed: ([a-z0-9]+(?:-[a-z0-9]+)*)$/u.exec(
    ownMessage(error) ?? ''
  )?.[1];
  if (
    direct &&
    (connectorFixtureStages.has(direct) || /^delete-connector-status-[1-5][0-9]{2}$/u.test(direct))
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
      /^fixture-(?:stop-provider|restore-app|delete-role|restore-sie|delete-connector|registration-owner-cleanup|registration-owner-discovery)$/u.test(
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
  /^fixture-(?:stop-provider|restore-app|delete-role|restore-sie|delete-connector|registration-owner-cleanup|registration-owner-discovery|prepare-connector-compensation)$/u.test(
    stage
  ) || /^fixture-delete-connector-status-[1-5][0-9]{2}$/u.test(stage);
export const commonGoogleCleanupStageForTesting = (error: unknown): string | undefined => {
  if (process.env.NODE_ENV !== 'test') {
    return undefined;
  }
  const stage = fixtureStage(error);
  return stage && fixtureCleanupStage(stage) ? stage : undefined;
};

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

export type CommonGoogleRegistrationTargetDriverInput = Readonly<{
  target: TargetConfig;
  fixture: ProvisionedPhase2Fixture;
  signal: AbortSignal;
  browser: Omit<CommonEmailPasswordBrowserConfiguration, 'expectedIssuer'>;
  provider: GoogleProviderTargetConfiguration;
  observer: Phase1BrowserGroupObserver;
  fetch?: typeof fetch;
  onDeleteConnectorFailure?(status: number | undefined): Promise<void>;
  onControls?(controls: CommonGoogleRegistrationControlsObservation): Promise<void>;
  withProviderCredentialLease<Result>(
    use: (lease: GoogleProviderCredentialLease) => Promise<Result>
  ): Promise<Result>;
}>;

export type CommonGoogleRegistrationControlError =
  | 'connector.general'
  | 'guard.invalid_input'
  | 'user.missing_profile'
  | 'verification_record.permission_denied'
  | 'session.identity_conflict'
  | 'user.email_already_in_use'
  | 'none';
export type CommonGoogleRegistrationControlsObservation = Readonly<{
  unverifiedEmail: Readonly<{ status: number; error: CommonGoogleRegistrationControlError }>;
  occupiedEmail: Readonly<{ status: number; error: CommonGoogleRegistrationControlError }>;
}>;
export const waitForCommonGoogleRegistrationControlOutcome = async (
  input: Readonly<{
    initial?: Phase1BrowserExperienceFailure;
    signal: AbortSignal;
    onIdentityNotExist?(): Promise<void>;
    read(): Promise<Phase1BrowserExperienceFailure>;
    wait?(milliseconds: number): Promise<void>;
  }>
): Promise<Phase1BrowserExperienceFailure> => {
  const wait =
    input.wait ??
    (async (milliseconds: number) =>
      new Promise<void>((resolve) => {
        setTimeout(resolve, milliseconds);
      }));
  let identityNotExistHandled = false;
  for (let attempt = 0; attempt < 1200; attempt += 1) {
    if (input.signal.aborted) {
      return targetFail('capability');
    }
    const outcome = await input.read();
    if (input.initial && JSON.stringify(outcome) === JSON.stringify(input.initial)) {
      await wait(25);
      continue;
    }
    if (
      input.onIdentityNotExist &&
      outcome.operation === 'identification' &&
      outcome.status === 404 &&
      outcome.code === 'user.identity_not_exist'
    ) {
      if (!identityNotExistHandled) {
        identityNotExistHandled = true;
        await input.onIdentityNotExist();
      }
      await wait(25);
      continue;
    }
    if (
      outcome.operation !== 'none' &&
      !(outcome.operation === 'social-verify' && outcome.status >= 200 && outcome.status < 300)
    ) {
      return outcome;
    }
    await wait(25);
  }
  return targetFail('capability');
};
const controlError = (value: unknown): CommonGoogleRegistrationControlError => {
  switch (value) {
    case 'connector.general':
    case 'guard.invalid_input':
    case 'user.missing_profile':
    case 'verification_record.permission_denied':
    case 'session.identity_conflict':
    case 'user.email_already_in_use':
    case 'none': {
      return value;
    }
    default: {
      return targetFail('capability');
    }
  }
};
const rejectedControlError = (
  value: Phase1BrowserExperienceFailure['code']
):
  | Exclude<
      Phase1BrowserExperienceFailure['code'],
      CommonGoogleRegistrationControlError | 'unknown'
    >
  | undefined => {
  switch (value) {
    case 'user.identity_not_exist':
    case 'session.verification_session_not_found':
    case 'session.interaction_not_found':
    case 'session.invalid_credentials':
    case 'user.suspended':
    case 'user.sign_in_method_not_enabled':
    case 'connector.wechat_unionid_required':
    case 'connector.social_auth_code_invalid':
    case 'connector.invalid_response': {
      return value;
    }
    default: {
      return undefined;
    }
  }
};

const admit = (
  input: CommonGoogleRegistrationTargetDriverInput,
  target: TargetConfig
): NonNullable<ProvisionedPhase2Fixture['status']> => {
  const status = input.fixture.status ?? targetFail('admission');
  const expectedRedirectUri = new URL('/demo-app', target.coreUrl).href;
  const scopes = input.browser.demo.scope.split(' ');
  if (
    input.signal.aborted ||
    typeof input.observer.runInFreshContext !== 'function' ||
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

const runDeniedRegistrationControl = async (
  input: CommonGoogleRegistrationTargetDriverInput,
  target: TargetConfig,
  expectedIssuer: string,
  status: NonNullable<ProvisionedPhase2Fixture['status']>,
  capability: PlaywrightExternalAuthorizationCapability,
  label: 'unverified-email' | 'occupied-email',
  requirePlaywrightBrand: boolean,
  onStage: (
    stage:
      | RegistrationControlStage
      | RegistrationControlResponseStage
      | RegistrationControlUnknownStage
      | RegistrationControlRejectedStage
      | RegistrationControlValidationStage
  ) => void
): Promise<Readonly<{ status: number; error: CommonGoogleRegistrationControlError }>> => {
  const observer = requirePlaywrightBrand
    ? withPlaywrightExternalAuthorizationCapability(input.observer, capability)
    : input.observer;
  return observer.runInFreshContext('experience', input.signal, target, async (session) => {
    if (!session.beginExperienceObservation || !session.readExperienceFailure) {
      return targetFail('capability');
    }
    const adapted = adaptPhase1SessionForEmailPassword(session, {
      ...input.browser,
      expectedIssuer,
      expectedSubject: 'denied-control',
      canonicalEmail: input.provider.originalOwnerEmail,
      resource: status.resource.indicator,
    });
    await adapted.navigate(`google-${label}-open`, '/demo-app');
    await adapted.waitForRoute(`google-${label}-sign-in`, [
      '/sign-in',
      '/sign-in/identifier',
      '/sign-in/password',
    ]);
    await session.expectCount(
      `google-${label}-register-count`,
      'role=link[name="Create account"]',
      1
    );
    await session.click(`google-${label}-register`, 'role=link[name="Create account"]');
    await adapted.waitForRoute(`google-${label}-register-route`, ['/register']);
    await session.expectCount(
      `google-${label}-provider-count`,
      googleSignInButtonSelectorCandidate,
      1
    );
    await session.beginExperienceObservation();
    await session.click(`google-${label}-provider`, googleSignInButtonSelectorCandidate);
    onStage(`${label}-control-response`);
    const failure = await waitForCommonGoogleRegistrationControlOutcome({
      onIdentityNotExist: async () => {
        if (label === 'occupied-email') {
          onStage('occupied-email-control-link-count');
          await session.expectCount(
            'google-occupied-email-create-without-linking-count',
            'a:text-is("Link another email")',
            1
          );
          onStage('occupied-email-control-link-click');
          await session.click(
            'google-occupied-email-create-without-linking',
            'a:text-is("Link another email")'
          );
          onStage('occupied-email-control-link-complete');
        }
      },
      read: async () => session.readExperienceFailure?.() ?? targetFail('capability'),
      signal: input.signal,
    });
    let reachedConsent = true;
    onStage(`${label}-control-consent`);
    try {
      await session.assertRoute(`google-${label}-consent-check`, 'core', ['/consent']);
    } catch {
      reachedConsent = false;
    }
    if (reachedConsent) {
      return targetFail('capability');
    }
    const incompleteEmailProfile =
      failure.operation === 'identification' &&
      failure.status === 422 &&
      failure.code === 'user.missing_profile';
    onStage(
      `${label}-control-observed-${failure.operation}-${failure.status}-${
        failure.code === 'unknown' ? 'unknown' : 'known'
      }-${incompleteEmailProfile ? 'incomplete' : 'other'}`
    );
    if (incompleteEmailProfile) {
      try {
        onStage(`${label}-control-profile-route`);
        await adapted.waitForRoute(`google-${label}-incomplete-profile-route`, ['/continue/email']);
        onStage(`${label}-control-profile-input`);
        await session.expectCount(
          `google-${label}-incomplete-profile-email-count`,
          'input[name="identifier"]',
          1
        );
      } catch {
        return targetFail('capability');
      }
    }
    onStage(`${label}-control-outcome`);
    const errors = new Set<CommonGoogleRegistrationControlError>(
      label === 'unverified-email'
        ? [
            'connector.general',
            'guard.invalid_input',
            'user.missing_profile',
            'verification_record.permission_denied',
          ]
        : [
            'connector.general',
            'guard.invalid_input',
            'session.identity_conflict',
            'user.missing_profile',
            'user.email_already_in_use',
          ]
    );
    const validStatus =
      failure.code === 'user.missing_profile'
        ? failure.operation === 'identification' && failure.status === 422
        : failure.status >= 400 && failure.status <= 499;
    onStage(`${label}-control-outcome-code`);
    if (failure.code === 'unknown') {
      const classified = `${label}-control-unknown-${failure.operation}-${failure.status}` as const;
      onStage(classified);
      return targetFail(classified);
    }
    const rejected = rejectedControlError(failure.code);
    if (rejected) {
      const classified =
        `${label}-control-rejected-${failure.operation}-${failure.status}-${rejected}` as const;
      onStage(classified);
      return targetFail(classified);
    }
    const error = controlError(failure.code);
    if (!validStatus) {
      onStage(`${label}-control-invalid-status-${failure.operation}-${failure.status}-${error}`);
      return targetFail('capability');
    }
    if (!errors.has(error)) {
      onStage(`${label}-control-disallowed-error-${failure.operation}-${failure.status}-${error}`);
      return targetFail('capability');
    }
    onStage(`${label}-control-outcome-accepted`);
    return Object.freeze({
      status: failure.status,
      error,
    });
  });
};

const executeCommonGoogleRegistrationForTarget = async (
  input: CommonGoogleRegistrationTargetDriverInput,
  requirePlaywrightBrand: boolean
): Promise<CommonGoogleRegistrationProjection> => {
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
          return await withSelectedGoogleRegistrationFixture({
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
            controlEmail: input.provider.changedProviderEmail,
            onDeleteConnectorFailure: input.onDeleteConnectorFailure,
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
                resetPrivateFilesOnStop: true,
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
            takeBrowserCode: async () => providerLease?.takePrimaryRegistrationCode() ?? fail(),
            takeUnverifiedEmailControlCode: async () =>
              providerLease?.takeUnverifiedEmailControlCode() ?? fail(),
            takeOccupiedEmailControlCode: async () =>
              providerLease?.takeOccupiedEmailControlCode() ?? fail(),
            use: async (value) => {
              stage = 'capability';
              const observer = requirePlaywrightBrand
                ? withPlaywrightExternalAuthorizationCapability(input.observer, value.capability)
                : input.observer;
              if (requirePlaywrightBrand && !isPlaywrightBrowserGroupObserver(observer)) {
                return targetFail('capability');
              }
              stage = 'context';
              try {
                const positive = await observer.runInFreshContext(
                  'experience',
                  input.signal,
                  target,
                  async (session) => {
                    try {
                      let registeredSubject: string | undefined;
                      const adapted = adaptPhase1SessionForEmailPassword(session, {
                        ...input.browser,
                        expectedIssuer,
                        expectedSubject: () => registeredSubject ?? '',
                        canonicalEmail: input.provider.originalOwnerEmail,
                        resource: status.resource.indicator,
                      });
                      return await runCommonGoogleRegistration({
                        session: {
                          ...adapted,
                          readProfile: async () => {
                            const profile = await adapted.readProfile();
                            if (typeof profile.sub === 'string') {
                              registeredSubject = profile.sub;
                            }
                            return profile;
                          },
                          expectCount: async (step, selector, expected) =>
                            session.expectCount(step, selector, expected),
                          consentFailureRoute: async () => 'other-none-0-unknown',
                        },
                        expectedEmail: input.provider.originalOwnerEmail,
                        assertRegisteredOwner: value.assertRegisteredOwner,
                        authorizationObservation: value.observation,
                      });
                    } catch (error: unknown) {
                      if (preservesFlowStage(error)) {
                        flowError = new TypeError(error.message);
                      }
                      throw error;
                    }
                  }
                );
                if (input.onControls) {
                  stage = 'unverified-email-control';
                  const unverifiedEmail = await runDeniedRegistrationControl(
                    input,
                    target,
                    expectedIssuer,
                    status,
                    value.unverifiedEmailCapability,
                    'unverified-email',
                    requirePlaywrightBrand,
                    (controlStage) => {
                      stage = controlStage;
                    }
                  );
                  stage = 'unverified-email-owner';
                  await value.assertControlsPreservedOwner();
                  stage = 'occupied-email-control';
                  const occupiedEmail = await runDeniedRegistrationControl(
                    input,
                    target,
                    expectedIssuer,
                    status,
                    value.occupiedEmailCapability,
                    'occupied-email',
                    requirePlaywrightBrand,
                    (controlStage) => {
                      stage = controlStage;
                    }
                  );
                  stage = 'occupied-email-owner';
                  await value.assertControlsPreservedOwner();
                  stage = 'control-publication';
                  await input.onControls(Object.freeze({ unverifiedEmail, occupiedEmail }));
                }
                return positive;
              } catch (error: unknown) {
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
    if (selectedFixtureStage && fixtureCleanupStage(selectedFixtureStage)) {
      return targetFail(selectedFixtureStage);
    }
    if (cleanupFailed) {
      return targetFail('cleanup');
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

export const runCommonGoogleRegistrationForTarget = async (
  input: CommonGoogleRegistrationTargetDriverInput
): Promise<CommonGoogleRegistrationProjection> =>
  executeCommonGoogleRegistrationForTarget(input, true);

/** Test-only composition executor. Production always requires a branded Playwright observer. */
export const runCommonGoogleRegistrationForTargetTesting = async (
  input: CommonGoogleRegistrationTargetDriverInput
): Promise<CommonGoogleRegistrationProjection> => {
  if (process.env.NODE_ENV !== 'test') {
    return fail();
  }
  return executeCommonGoogleRegistrationForTarget(input, false);
};
/* eslint-enable complexity, max-lines, max-params, no-await-in-loop, no-constant-condition, no-return-await, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unnecessary-condition, @typescript-eslint/return-await */
