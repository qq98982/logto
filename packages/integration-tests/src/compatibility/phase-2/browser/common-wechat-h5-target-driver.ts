/* eslint-disable complexity, max-lines, no-await-in-loop, no-constant-condition, no-return-await, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unnecessary-condition, @typescript-eslint/return-await -- Target admission, bounded discovery, credential scopes, provider fixture, browser context, and cleanup-stage preservation form one composition boundary. Explicit return-await keeps both target promises inside the outer stage-latch boundary. */
import { types as nodeTypes } from 'node:util';

import { validateTargetConfig } from '../../config.js';
import type { TargetConfig } from '../../model.js';
import type { Phase1BrowserGroupObserver } from '../../phase-1/browser/contracts.js';
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

import { runCommonWechatH5Registration } from './common-wechat-web-h5.js';
import type { CommonEmailPasswordBrowserConfiguration } from './fresh-context-password-controls.js';
import { adaptPhase1SessionForEmailPassword } from './phase1-session-adapter.js';
import {
  type SelectedWechatProviderLease,
  type SelectedWechatSmsConfiguration,
  wechatH5SignInButtonSelectorCandidate,
  withSelectedWechatConnectorFixture,
} from './selected-wechat-connector-fixture.js';

const maximumDiscoveryBytes = 64 * 1024;
const connectorFixtureStages = new Set([
  'read-sie',
  'get-app',
  'patch-app',
  'read-app',
  'read-resource',
  'create-role',
  'create-connector',
  'create-sms-connector',
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
type Stage =
  | 'admission'
  | 'capability'
  | 'cleanup'
  | 'context'
  | 'credentials'
  | 'discovery'
  | 'fixture'
  | 'management'
  | `cleanup-${string}`
  | FixtureStage;
const fail = (): never => {
  throw new TypeError('Invalid Common Wechat H5 registration target composition');
};
const targetFail = (stage: Stage): never => {
  process.stderr.write(`ASTER_WECHAT_TARGET_STAGE=${stage}\n`);
  throw new TypeError(`Common Wechat H5 registration target failed: ${stage}`);
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
  /^Common WeChat H5 failed: (?:admission|initialization|registration-transition|registration-route|provider-count|provider-click|phone-route|phone-submit|passcode-route|passcode-retrieval(?:-(?:env-missing|socket-shape|recipient|connect|timeout|not-found|response))?|passcode-format|passcode-fill|consent-click|consent-route(?:-(?:sign-in|register|continue|demo|error|callback|other)-(?:social-verify|identification|submit|resume|none)-(?:200|201|204|302|303|400|401|403|404|409|422|500|503|0)-(?:complete|missing-resume-(?:not-issued|path-mismatch|expired|secure-mismatch|other)|missing-mapping|missing-shared|missing-session|not-applicable)-(?:user-identity-not-exist|user-missing-profile|session-verification-session-not-found|session-interaction-not-found|session-invalid-credentials|user-suspended|user-sign-in-method-not-enabled|session-identity-conflict|unknown|none)-(?:callback-complete|callback-incomplete)-(?:state-stored|state-cleared))?|callback(?:-[a-z0-9-]+)?|profile|refresh|provider)$/u.test(
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
export const commonWechatH5TargetFixtureStageForTesting = (
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
  getSmsConfiguration?(): SelectedWechatSmsConfiguration;
  armSmsRegistration?(recipient: string): Promise<void>;
  takeSmsRegistrationCode?(recipient: string): Promise<string>;
  toJSON(): never;
}>;

export type WechatProviderTargetConfiguration = Readonly<{
  wechatSubject: string;
  registrationPhone: string;
}>;

type CommonWechatH5RegistrationProjection = Awaited<
  ReturnType<typeof runCommonWechatH5Registration>
>;

export type CommonWechatH5RegistrationTargetDriverInput = Readonly<{
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
    }>
  ): Promise<SelectedWechatProviderLease & Readonly<{ takeBrowserCode(): Promise<string> }>>;
}>;

const admit = (
  input: CommonWechatH5RegistrationTargetDriverInput,
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
    !/^\d{8,15}$/u.test(input.provider.registrationPhone)
  ) {
    return targetFail('admission');
  }
  return status;
};

const executeCommonWechatH5RegistrationForTarget = async (
  input: CommonWechatH5RegistrationTargetDriverInput,
  requirePlaywrightBrand: boolean
): Promise<CommonWechatH5RegistrationProjection> => {
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
      const smsConfiguration = credentials.getSmsConfiguration?.() ?? fail();
      const armSmsRegistration = credentials.armSmsRegistration ?? fail();
      const takeSmsRegistrationCode = credentials.takeSmsRegistrationCode ?? fail();
      const executeFixture = async (request: Phase2AdminRequestFunction) => {
        stage = 'fixture';
        let providerLease:
          | (SelectedWechatProviderLease & Readonly<{ takeBrowserCode(): Promise<string> }>)
          | undefined;
        try {
          return await withSelectedWechatConnectorFixture({
            ownerMode: 'registration',
            fixture: input.fixture,
            request,
            targetOrigin: target.coreUrl,
            browser: {
              clientId: input.browser.demo.appId,
              redirectUri: input.browser.redirectUri,
            },
            clientId,
            clientSecret,
            channel: 'h5',
            wechatSubject: input.provider.wechatSubject,
            registrationPhone: input.provider.registrationPhone,
            smsConfiguration,
            prepareConnector: async (connectorId) => {
              const prepared = await input.prepareProvider({
                role: target.label,
                subject: input.provider.wechatSubject,
                clientId,
                clientSecret,
                connectorId,
                targetOrigin: target.coreUrl,
              });
              providerLease = prepared;
              return prepared;
            },
            takeBrowserCode: async () => providerLease?.takeBrowserCode() ?? fail(),
            use: async (value) => {
              stage = 'capability';
              const observer = input.createObserver(value.capability);
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
                    try {
                      let registeredSubject: string | undefined;
                      const adapted = adaptPhase1SessionForEmailPassword(session, {
                        ...input.browser,
                        expectedIssuer,
                        expectedSubject: () => registeredSubject ?? '',
                        canonicalEmail: '',
                        resource: status.resource.indicator,
                      });
                      return await runCommonWechatH5Registration({
                        session: {
                          ...adapted,
                          readProfile: async () => {
                            const profile = await adapted.readProfile();
                            if (typeof profile.sub === 'string') {
                              registeredSubject = profile.sub;
                            }
                            return {
                              sub: profile.sub,
                              phone: Reflect.get(profile, 'phone'),
                              phoneVerified: Reflect.get(profile, 'phoneVerified'),
                            };
                          },
                          expectCount: async (step, selector, expected) =>
                            session.expectCount(step, selector, expected),
                          consentFailureRoute: async () => {
                            const response = (await session.readExperienceFailure?.()) ?? {
                              operation: 'none' as const,
                              status: 0 as const,
                              binding: 'not-applicable' as const,
                              code: 'none' as const,
                            };
                            const code = response.code.replaceAll('.', '-');
                            const authorization = value.observation();
                            const callback =
                              authorization.requestCount === 1 &&
                              authorization.stateFormatValid &&
                              authorization.stateRoundTrip &&
                              authorization.fulfilledOnce
                                ? 'callback-complete'
                                : 'callback-incomplete';
                            const storedState = (await session.hasStoredSocialState?.(
                              value.connectorId
                            ))
                              ? 'state-stored'
                              : 'state-cleared';
                            for (const [kind, paths] of [
                              ['sign-in', ['/sign-in', '/sign-in/identifier', '/sign-in/password']],
                              ['register', ['/register']],
                              [
                                'continue',
                                ['/continue', '/continue/phone', '/continue/verification-code'],
                              ],
                              ['demo', ['/demo-app']],
                              ['error', ['/error']],
                              ['callback', ['/callback']],
                            ] as const) {
                              try {
                                await session.assertRoute(
                                  `wechat-h5-consent-failure-${kind}`,
                                  'core',
                                  paths
                                );
                                return `${kind}-${response.operation}-${response.status}-${response.binding}-${code}-${callback}-${storedState}`;
                              } catch {
                                // Try the next closed route class.
                              }
                            }
                            return `other-${response.operation}-${response.status}-${response.binding}-${code}-${callback}-${storedState}`;
                          },
                        },
                        selector: wechatH5SignInButtonSelectorCandidate,
                        phone: input.provider.registrationPhone,
                        armPasscode: armSmsRegistration,
                        takePasscode: async (recipient) => takeSmsRegistrationCode(recipient),
                        providerObservation: () => {
                          const authorization = value.observation();
                          const provider = providerLease?.observation();
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
                          return provider;
                        },
                      });
                    } catch (error: unknown) {
                      if (preservesFlowStage(error)) {
                        flowError = new TypeError(error.message);
                      }
                      throw error;
                    }
                  }
                );
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
    if (cleanupFailed && flowError) {
      const flowStage = /^Common WeChat H5 failed: ([a-z0-9-]+)$/u.exec(
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

export const runCommonWechatH5RegistrationForTarget = async (
  input: CommonWechatH5RegistrationTargetDriverInput
): Promise<CommonWechatH5RegistrationProjection> =>
  executeCommonWechatH5RegistrationForTarget(input, true);

/** Test-only composition executor. Production always requires a branded Playwright observer. */
export const runCommonWechatH5RegistrationForTargetTesting = async (
  input: CommonWechatH5RegistrationTargetDriverInput
): Promise<CommonWechatH5RegistrationProjection> => {
  if (process.env.NODE_ENV !== 'test') {
    return fail();
  }
  return executeCommonWechatH5RegistrationForTarget(input, false);
};
/* eslint-enable complexity, max-lines, no-await-in-loop, no-constant-condition, no-return-await, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unnecessary-condition, @typescript-eslint/return-await */
