import { isDeepStrictEqual } from 'node:util';

import type { TargetConfig } from '../../model.js';
import type { Phase1BrowserGroupObserver } from '../../phase-1/browser/contracts.js';
import { runCommonAccountPhoneChangeForTarget } from '../browser/common-account-phone-change-target-driver.js';
import {
  commonAccountPhoneChangePendingReferenceProjection,
  type CommonAccountPhoneChangeProjection,
} from '../browser/common-account-phone-change.js';
import type { CommonPhoneCodeProviderLease } from '../browser/selected-phone-code-fixture.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';

export const commonAccountPhoneChangeScenarioIds = Object.freeze([
  'common.account.phone-change',
] as const);
export type CommonAccountPhoneChangeScenarioResult = Readonly<{
  id: (typeof commonAccountPhoneChangeScenarioIds)[number];
  projection: CommonAccountPhoneChangeProjection;
}>;
export const compareCommonAccountPhoneChangeProjections = (
  oracle: CommonAccountPhoneChangeProjection,
  candidate: CommonAccountPhoneChangeProjection
): readonly string[] =>
  isDeepStrictEqual(oracle, commonAccountPhoneChangePendingReferenceProjection) &&
  isDeepStrictEqual(candidate, commonAccountPhoneChangePendingReferenceProjection) &&
  isDeepStrictEqual(oracle, candidate)
    ? []
    : ['/projection'];
export const runCommonAccountPhoneChangeScenarioRow = async (
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    observer: Phase1BrowserGroupObserver;
    signal: AbortSignal;
    withProviderLease<Result>(
      use: (lease: CommonPhoneCodeProviderLease) => Promise<Result>
    ): Promise<Result>;
  }>
): Promise<CommonAccountPhoneChangeScenarioResult> =>
  Object.freeze({
    id: commonAccountPhoneChangeScenarioIds[0],
    projection: await runCommonAccountPhoneChangeForTarget(input),
  });
