/* eslint-disable no-await-in-loop, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- Ordered passcode actions and the closed consumer stage are one browser boundary. */
import type { TargetConfig } from '../../model.js';
import type { Phase1BrowserGroupObserver } from '../../phase-1/browser/contracts.js';
import { asterNativeSurfaceContract } from '../../phase-1/native-surface.js';
import { withPhase2AdminManagementBearer } from '../clients/admin-management-bearer.js';
import {
  createBearerPhase2AdminRequest,
  createReferencePhase2AdminRequest,
  type Phase2AdminRequestFunction,
  type Phase2FixtureSecretLease,
  type ProvisionedPhase2Fixture,
} from '../fixtures.js';

import {
  runCommonAccountPhoneChange,
  type CommonAccountPhoneChangeProjection,
} from './common-account-phone-change.js';
import { runCommonPhoneCodeInFreshContext } from './common-phone-code-target-driver.js';
import { adaptPhase1SessionForPhoneCode } from './phone-code-phase1-session-adapter.js';
import type { CommonPhoneCodeProviderLease } from './selected-phone-code-fixture.js';

type PhoneChangeTargetStage =
  | 'admission'
  | 'discovery'
  | 'account-transport'
  | 'fixture'
  | 'token-issuance'
  | 'browser-login'
  | 'provider-lease'
  | 'flow';
const fail = (stage: PhoneChangeTargetStage = 'flow'): never => {
  throw new TypeError(`Invalid Common Account phone change target (${stage})`);
};

const closedStage = (error: unknown): PhoneChangeTargetStage => {
  const descriptor =
    error instanceof Error ? Object.getOwnPropertyDescriptor(error, 'message') : undefined;
  const message: unknown = descriptor?.value;
  if (message === 'Invalid Common Account settings transport') {
    return 'account-transport';
  }
  if (
    typeof message === 'string' &&
    (message.startsWith('Invalid selected Account settings fixture') ||
      message.startsWith('Common email password fixture failed:'))
  ) {
    return 'fixture';
  }
  if (
    typeof message === 'string' &&
    message.startsWith('Invalid Phase 2 public user token issuance')
  ) {
    return 'token-issuance';
  }
  if (
    typeof message === 'string' &&
    (message.startsWith('Common phone code target failed:') ||
      message.startsWith('Invalid Common phone code browser adapter'))
  ) {
    return 'browser-login';
  }
  return 'flow';
};

const discoverIssuer = async (
  target: TargetConfig,
  requestFetch: typeof fetch
): Promise<string> => {
  const response = await requestFetch(
    new URL('/oidc/.well-known/openid-configuration', target.coreUrl),
    { redirect: 'manual', signal: AbortSignal.timeout(10_000) }
  );
  const text =
    response.status === 200 && !response.redirected ? await response.text() : fail('discovery');
  if (Buffer.byteLength(text) > 16 * 1024) {
    return fail('discovery');
  }
  const parsed: unknown = JSON.parse(text);
  const value: unknown =
    typeof parsed === 'object' && parsed !== null ? Reflect.get(parsed, 'issuer') : null;
  const issuer = typeof value === 'string' ? new URL(value) : fail('discovery');
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

const enterCode = async (
  session: ReturnType<typeof adaptPhase1SessionForPhoneCode>,
  code: string
): Promise<void> => {
  if (!/^\d{6}$/u.test(code)) {
    return fail();
  }
  for (const [index, digit] of [...code].entries()) {
    await session.fill(`account-phone-code-${index}`, `input[name="passcode_${index}"]`, digit);
  }
};

export const runCommonAccountPhoneLogin = async (
  input: Readonly<{
    session: ReturnType<typeof adaptPhase1SessionForPhoneCode>;
    provider: CommonPhoneCodeProviderLease;
    phone: string;
    ownerId: string;
  }>
): Promise<Readonly<{ refreshRotated: boolean }>> => {
  const { session, provider, phone, ownerId } = input;
  await session.navigate('open-account-phone-sign-in', '/demo-app');
  await session.waitForRoute('wait-account-phone-sign-in', ['/sign-in', '/sign-in/password']);
  await session.selectChinaCountryCode('select-account-phone-china', '/sign-in');
  await session.fill('fill-account-phone', 'input[name="identifier"]', phone.slice(2));
  await provider.arm(phone, 'SignIn');
  await session.click('submit-account-phone', 'button[name="submit"]');
  await session.waitForRoute('wait-account-phone-code', ['/sign-in/verification-code']);
  await enterCode(session, await provider.takeCode(phone, 'SignIn'));
  await session.waitForRoute('wait-account-phone-consent', ['/consent']);
  await session.click('authorize-account-phone', 'role=button[name="Authorize"]');
  await session.assertInitialCallback();
  const profile = await session.readProfile();
  const refreshed = await session.refresh();
  if (
    profile.sub !== ownerId ||
    profile.phoneNumber !== phone ||
    profile.phoneNumberVerified !== true ||
    profile.emailAbsent !== false ||
    refreshed.subject !== ownerId ||
    refreshed.phoneNumber !== phone ||
    !refreshed.rotated
  ) {
    return fail();
  }
  return Object.freeze({ refreshRotated: true });
};

export const runCommonAccountPhoneChangeForTarget = async (
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    observer: Phase1BrowserGroupObserver;
    signal: AbortSignal;
    fetch?: typeof fetch;
    withProviderLease<Result>(
      use: (lease: CommonPhoneCodeProviderLease) => Promise<Result>
    ): Promise<Result>;
  }>
): Promise<CommonAccountPhoneChangeProjection> => {
  const status = input.fixture.status ?? fail('admission');
  if (input.signal.aborted) {
    return fail('admission');
  }
  const requestFetch = input.fetch ?? fetch;
  const issuer = await discoverIssuer(input.target, requestFetch);
  const redirectUri = new URL('/demo-app', input.target.coreUrl).href;
  const execute = async (
    managementRequest: Phase2AdminRequestFunction,
    secrets: Phase2FixtureSecretLease,
    provider: CommonPhoneCodeProviderLease
  ) => {
    const getPassword = () => secrets.getSubjectPassword?.() ?? fail();
    return runCommonAccountPhoneChange({
      target: input.target,
      fixture: input.fixture,
      managementRequest,
      provider,
      signal: input.signal,
      fetch: requestFetch,
      getSelectedPassword: getPassword,
      getStatusSubjectPassword: getPassword,
      runPhoneLogin: async (phone, ownerId) =>
        runCommonPhoneCodeInFreshContext(
          input.observer,
          input.signal,
          input.target,
          async (phase1) => {
            const session = adaptPhase1SessionForPhoneCode(
              phase1,
              {
                storageKey:
                  input.target.label === 'oracle'
                    ? asterNativeSurfaceContract.markers.demoConfigStorageKey.reference
                    : asterNativeSurfaceContract.markers.demoConfigStorageKey.candidate,
                demo: {
                  appId: status.client.id,
                  prompt: 'consent',
                  scope: `openid offline_access profile email phone ${status.resource.scopeName}`,
                  resource: status.resource.indicator,
                },
                expectedIssuer: issuer,
                resource: status.resource.indicator,
                redirectUri,
                initialResponseScope: 'openid offline_access profile email phone',
                resourceScope: status.resource.scopeName,
              },
              ownerId
            );
            return runCommonAccountPhoneLogin({ session, provider, phone, ownerId });
          }
        ),
    });
  };
  let consumerStage: PhoneChangeTargetStage | undefined;
  try {
    return await input.withProviderLease(async (provider) => {
      const run = async (
        managementRequest: Phase2AdminRequestFunction,
        secrets: Phase2FixtureSecretLease
      ) => {
        try {
          return await execute(managementRequest, secrets, provider);
        } catch (error: unknown) {
          consumerStage = closedStage(error);
          throw error;
        }
      };
      if (input.target.label === 'candidate') {
        return withPhase2AdminManagementBearer(
          input.target,
          input.fixture,
          async (bearer, secrets) =>
            run(createBearerPhase2AdminRequest(input.target, bearer, requestFetch), secrets),
          { fetch: requestFetch }
        );
      }
      return input.fixture.withSecretLease(async (secrets) =>
        run(createReferencePhase2AdminRequest(input.target, requestFetch), secrets)
      );
    });
  } catch (error: unknown) {
    return fail(
      consumerStage ?? (closedStage(error) === 'flow' ? 'provider-lease' : closedStage(error))
    );
  }
};
/* eslint-enable no-await-in-loop, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
