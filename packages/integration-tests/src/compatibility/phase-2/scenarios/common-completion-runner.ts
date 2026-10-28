/* eslint-disable complexity, no-await-in-loop, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The approved append order executes each actual family before publishing its closed projection. */
import type { JSONWebKeySet } from 'jose';

import type { TargetConfig } from '../../model.js';
import type { Phase1BrowserGroupObserver } from '../../phase-1/browser/contracts.js';
import {
  getCommonGoogleConfiguredCollisionCheckpoint,
  type CommonGoogleConfiguredCollisionCheckpoint,
} from '../browser/common-google-configured-collision.js';
import {
  getCommonPasswordPolicyFailurePhase,
  runCommonPasswordPolicyForTarget,
  type CommonPasswordPolicyFailurePhase,
  type PasswordCompromiseFixture,
} from '../browser/common-password-policy.js';
import {
  getCommonSessionLogoutFailurePhase,
  runCommonSessionLogoutForTarget,
  type CommonSessionLogoutFailurePhase,
  type CommonSessionLogoutFixtureRuntime,
} from '../browser/common-session-logout-target-driver.js';
import { runCommonSocialAccountForTarget } from '../browser/common-social-account-target-driver.js';
import { withSelectedPasswordCoreApplication } from '../browser/selected-password-core-application-fixture.js';
import { withPhase2AdminManagementBearer } from '../clients/admin-management-bearer.js';
import {
  createBearerPhase2AdminRequest,
  createReferencePhase2AdminRequest,
  createScopedPhase2Fixture,
  type Phase2AdminRequestFunction,
  type Phase2FixtureSecretLease,
  type ProvisionedPhase2Fixture,
} from '../fixtures.js';

import {
  assertCommonCompletionProjection,
  commonCompletionScenarioIds,
  type CommonCompletionScenarioResult,
  type CommonCompletionScenarioId,
} from './common-completion.js';
import type { CommonGoogleExistingOwnerFixtureRuntime } from './common-google-existing-owner.js';
import { commonSocialAccountScenarioIds } from './common-social-account.js';
import {
  commonWechatFamilyScenarioIds,
  runCommonWechatFamilyScenarioRow,
  type CommonWechatFamilyRuntime,
} from './common-wechat-family.js';
import type { CommonWechatWebFixtureRuntime } from './common-wechat-web.js';
import {
  managementCompletionFamilyIds,
  runManagementCompletionFamilyScenarioRow,
} from './management-completion-family.js';

export type CommonCompletionFixtureRuntime = Readonly<{
  google: CommonGoogleExistingOwnerFixtureRuntime;
  web: CommonWechatWebFixtureRuntime;
  password: PasswordCompromiseFixture;
  passwordTarget: TargetConfig;
  logout: CommonSessionLogoutFixtureRuntime;
  wechat: CommonWechatFamilyRuntime;
  h5Target: TargetConfig;
  h5Observer: Phase1BrowserGroupObserver;
  management: Pick<
    Parameters<typeof runManagementCompletionFamilyScenarioRow>[0],
    | 'withManagementBearer'
    | 'captureOwnedApplication'
    | 'observeForeignApplicationPreserved'
    | 'observeForeignUserPreserved'
    | 'observeForeignConnectorPreserved'
    | 'withProvisioningFixture'
  >;
  takePasswordRecoveryCode(recipient: string): Promise<string>;
}>;
export class CommonCompletionScenarioFailure extends Error {
  constructor(
    readonly scenarioId: CommonCompletionScenarioId,
    readonly passwordPolicyPhase?: CommonPasswordPolicyFailurePhase,
    readonly logoutPhase?: CommonSessionLogoutFailurePhase,
    readonly googleCollisionCheckpoint?: CommonGoogleConfiguredCollisionCheckpoint
  ) {
    super(`Common completion scenario failed: ${scenarioId}`);
    this.name = 'CommonCompletionScenarioFailure';
  }
}

const fail = (): never => {
  throw new TypeError('Invalid Common completion execution');
};
const socialIds = new Set<string>(commonSocialAccountScenarioIds);
const wechatIds = new Set<string>(commonWechatFamilyScenarioIds);
const managementIds = new Set<string>(managementCompletionFamilyIds);
const isSocialId = (id: string): id is (typeof commonSocialAccountScenarioIds)[number] =>
  socialIds.has(id);
const isWechatId = (id: string): id is (typeof commonWechatFamilyScenarioIds)[number] =>
  wechatIds.has(id);
const isManagementId = (id: string): id is (typeof managementCompletionFamilyIds)[number] =>
  managementIds.has(id);

export const runCommonCompletionScenariosForTarget = async (
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    runtime: CommonCompletionFixtureRuntime;
    jwks: Readonly<JSONWebKeySet>;
    observer: Phase1BrowserGroupObserver;
    signal: AbortSignal;
    fetch?: typeof fetch;
  }>
): Promise<readonly CommonCompletionScenarioResult[]> => {
  const requestFetch = input.fetch ?? fetch;
  const results: CommonCompletionScenarioResult[] = [];
  const providerFixture = Object.freeze({
    ...input.fixture,
    commonGoogleExistingOwner: input.runtime.google,
    commonWechatWeb: input.runtime.web,
  });
  for (const id of commonCompletionScenarioIds) {
    if (input.signal.aborted) {
      return fail();
    }
    try {
      let projection: unknown;
      if (id === 'common.password.policy') {
        const execute = async (
          request: Phase2AdminRequestFunction,
          lease: Phase2FixtureSecretLease
        ) => {
          const delegated = createScopedPhase2Fixture(input.fixture, lease);
          try {
            const redirectUri = new URL('/demo-app', input.runtime.passwordTarget.coreUrl).href;
            return await withSelectedPasswordCoreApplication({
              fixture: delegated.fixture,
              request,
              redirectUri,
              use: async (fixture) =>
                runCommonPasswordPolicyForTarget({
                  ...input,
                  target: input.runtime.passwordTarget,
                  fixture,
                  request,
                  compromiseFixture: input.runtime.password,
                  getPassword: lease.getSelectedEmailPassword ?? fail,
                  takeRecoveryCode: input.runtime.takePasswordRecoveryCode,
                }),
            });
          } finally {
            delegated.revoke();
          }
        };
        projection =
          input.target.label === 'candidate'
            ? await withPhase2AdminManagementBearer(
                input.target,
                input.fixture,
                async (bearer, lease) =>
                  execute(
                    createBearerPhase2AdminRequest(input.target, bearer, requestFetch),
                    lease
                  ),
                { fetch: requestFetch }
              )
            : await input.fixture.withSecretLease(async (lease) =>
                execute(createReferencePhase2AdminRequest(input.target, requestFetch), lease)
              );
      } else if (id === 'common.session.logout-preservation') {
        projection = await runCommonSessionLogoutForTarget({
          ...input,
          runtime: input.runtime.logout,
        });
      } else if (isSocialId(id)) {
        projection = await runCommonSocialAccountForTarget({
          ...input,
          id,
          fixture: providerFixture,
        });
      } else if (isWechatId(id)) {
        const row = await runCommonWechatFamilyScenarioRow({
          ...input,
          id,
          target: id === 'common.wechat.h5' ? input.runtime.h5Target : input.target,
          observer: id === 'common.wechat.h5' ? input.runtime.h5Observer : input.observer,
          runtime: input.runtime.wechat,
        });
        projection = row.projection;
      } else if (isManagementId(id)) {
        const row = await runManagementCompletionFamilyScenarioRow({
          ...input,
          id,
          ...input.runtime.management,
        });
        projection = row.projection;
      } else {
        return fail();
      }
      assertCommonCompletionProjection(id, projection);
      results.push(Object.freeze({ id, projection }));
    } catch (error: unknown) {
      throw new CommonCompletionScenarioFailure(
        id,
        id === 'common.password.policy'
          ? (getCommonPasswordPolicyFailurePhase(error) ?? 'initialization')
          : undefined,
        id === 'common.session.logout-preservation'
          ? (getCommonSessionLogoutFailurePhase(error) ?? 'authority')
          : undefined,
        id === 'common.google.configured-collision'
          ? (getCommonGoogleConfiguredCollisionCheckpoint(error) ?? 'composition')
          : undefined
      );
    }
  }
  return Object.freeze(results);
};
/* eslint-enable complexity, no-await-in-loop, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
