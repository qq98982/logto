import { isDeepStrictEqual } from 'node:util';

import { z } from 'zod';

import type { ManagementCompletionFamilyId } from '../browser/management-completion-family-target-driver.js';

import {
  commonAccountSocialExpectedProjection,
  commonGoogleConfiguredCollisionExpectedProjection,
} from './common-social-account.js';
import {
  assertCommonWechatFamilyProjection,
  commonWechatFamilyScenarioIds,
  type CommonWechatFamilyScenarioId,
} from './common-wechat-family.js';
import {
  compareManagementCompletionFamilyProjections,
  managementCompletionFamilyIds,
} from './management-completion-family.js';

export const commonCompletionScenarioIds = Object.freeze([
  'common.password.policy',
  'common.google.configured-collision',
  'common.account.google-link',
  'common.wechat.h5',
  'common.wechat.mini',
  'common.wechat.mini-phone-registration',
  'common.wechat.native',
  'common.account.wechat-link',
  'common.management.applications-secrets',
  'common.management.native-resource-role',
  'common.management.connectors-experience',
  'common.management.user-suspend-delete',
  'common.management.provisioning-convergence',
  'common.session.logout-preservation',
] as const);
export type CommonCompletionScenarioId = (typeof commonCompletionScenarioIds)[number];
export type CommonCompletionScenarioResult = Readonly<{
  id: CommonCompletionScenarioId;
  projection: unknown;
}>;
const managementIds = new Set<string>(managementCompletionFamilyIds);
const wechatIds = new Set<string>(commonWechatFamilyScenarioIds);
const isManagementId = (id: string): id is ManagementCompletionFamilyId => managementIds.has(id);
const isWechatId = (id: string): id is CommonWechatFamilyScenarioId => wechatIds.has(id);
const fail = (): never => {
  throw new TypeError('Invalid Common completion projection');
};
const success = z
  .object({ status: z.literal(204), error: z.literal('none'), issues: z.tuple([]) })
  .strict();
const rejected = <Issue extends z.ZodTypeAny>(issue: Issue) =>
  z
    .object({
      status: z.literal(422),
      error: z.literal('password.rejected'),
      issues: z.tuple([issue]),
    })
    .strict();
const issue = (code: string) => z.object({ code: z.literal(code) }).strict();
const passwordPolicy = z
  .object({
    localMinimum: rejected(
      z.object({ code: z.literal('password_rejected.too_short'), minimum: z.literal(12) }).strict()
    ),
    localWord: rejected(issue('password_rejected.restricted.words')),
    registrationValid: success,
    compromised: rejected(issue('password_rejected.pwned')),
    compromiseClear: success,
    lookupUnavailable: z
      .object({
        status: z.literal(503),
        error: z.literal('temporarily_unavailable'),
        issues: z.tuple([]),
      })
      .strict(),
    recoverySamePassword: z
      .object({
        status: z.literal(422),
        error: z.literal('user.same_password'),
        issues: z.tuple([]),
      })
      .strict(),
    recoveryUserInfo: rejected(issue('password_rejected.restricted.user_info')),
    failuresPreservedOwner: z.literal(true),
    noRegistrationOwnerCreated: z.literal(true),
    oldPasswordAccepted: z.literal(true),
    policyRestored: z.literal(true),
  })
  .strict();
const signedNotification = z
  .object({
    algorithm: z.literal('ES384'),
    tokenType: z.literal('logout+jwt'),
    issuerBound: z.literal(true),
    audienceBound: z.literal(true),
    subjectBound: z.literal(true),
    sessionBound: z.literal(true),
    eventBound: z.literal(true),
    nonceAbsent: z.literal(true),
    uniqueIdentifierPresent: z.literal(true),
    lifetimeSeconds: z.literal(120),
  })
  .strict();
const logoutMethod = (method: 'google' | 'email-code' | 'wechat-native') =>
  z
    .object({
      method: z.literal(method),
      rpLogoutStatus: z.literal(303),
      signedNotification,
      sessionRemoved: z.literal(true),
      offlineRefreshRotated: z.literal(true),
      offlineProfilePreserved: z.literal(true),
      receiverConsumedOnce: z.literal(true),
      deliveryFailureStatus: z.literal(503),
      failureSessionRemoved: z.literal(true),
      failureOfflineRefreshRotated: z.literal(true),
      failureProfilePreserved: z.literal(true),
      accountDeleteStatus: z.literal(204),
      accountSessionRemoved: z.literal(true),
      accountOfflineRefreshRotated: z.literal(true),
      accountProfilePreserved: z.literal(true),
    })
    .strict();
const logout = z
  .object({
    methods: z.tuple([
      logoutMethod('google'),
      logoutMethod('email-code'),
      logoutMethod('wechat-native'),
    ]),
  })
  .strict();

export const assertCommonCompletionProjection = (
  id: CommonCompletionScenarioId,
  value: unknown
): void => {
  if (id === 'common.password.policy') {
    if (!passwordPolicy.safeParse(value).success) {
      fail();
    }
    return;
  }
  if (id === 'common.session.logout-preservation') {
    if (!logout.safeParse(value).success) {
      fail();
    }
    return;
  }
  if (isManagementId(id)) {
    if (compareManagementCompletionFamilyProjections(id, value, value).length > 0) {
      fail();
    }
    return;
  }
  if (isWechatId(id)) {
    assertCommonWechatFamilyProjection(id, value);
    return;
  }
  const expected =
    id === 'common.google.configured-collision'
      ? commonGoogleConfiguredCollisionExpectedProjection
      : commonAccountSocialExpectedProjection(
          id === 'common.account.google-link' ? 'google' : 'wechat'
        );
  if (!isDeepStrictEqual(value, expected)) {
    fail();
  }
};
export const compareCommonCompletionProjections = (
  id: CommonCompletionScenarioId,
  oracle: unknown,
  candidate: unknown
): readonly string[] => {
  try {
    assertCommonCompletionProjection(id, oracle);
    assertCommonCompletionProjection(id, candidate);
    return isDeepStrictEqual(oracle, candidate) ? [] : ['/projection'];
  } catch {
    return ['/projection'];
  }
};
