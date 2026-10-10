import { isDeepStrictEqual } from 'node:util';

import type { TargetConfig } from '../../model.js';
import { runCommonAccountEmailChangeForTarget } from '../browser/common-account-email-change-target-driver.js';
import type { CommonAccountEmailChangeProjection } from '../browser/common-account-email-change.js';
import { commonAccountEmailChangeExpectedProjection } from '../browser/common-account-email-change.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';

export const commonAccountEmailChangeScenarioIds = Object.freeze([
  'common.account.email-change',
] as const);

export type CommonAccountEmailChangeScenarioResult = Readonly<{
  id: (typeof commonAccountEmailChangeScenarioIds)[number];
  projection: CommonAccountEmailChangeProjection;
}>;

export const compareCommonAccountEmailChangeProjections = (
  oracle: CommonAccountEmailChangeProjection,
  candidate: CommonAccountEmailChangeProjection
): readonly string[] =>
  isDeepStrictEqual(oracle, commonAccountEmailChangeExpectedProjection) &&
  isDeepStrictEqual(candidate, commonAccountEmailChangeExpectedProjection) &&
  isDeepStrictEqual(oracle, candidate)
    ? []
    : ['/projection'];

export const runCommonAccountEmailChangeScenarioRow = async (
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    signal: AbortSignal;
    fetch?: typeof fetch;
  }>
): Promise<CommonAccountEmailChangeScenarioResult> =>
  Object.freeze({
    id: commonAccountEmailChangeScenarioIds[0],
    projection: await runCommonAccountEmailChangeForTarget(input),
  });
