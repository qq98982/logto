import { isDeepStrictEqual } from 'node:util';

import type { TargetConfig } from '../../model.js';
import { runCommonAccountPasswordUpdateForTarget } from '../browser/common-account-password-update-target-driver.js';
import type { CommonAccountPasswordUpdateProjection } from '../browser/common-account-password-update.js';
import { commonAccountPasswordUpdateExpectedProjection } from '../browser/common-account-password-update.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';

export const commonAccountPasswordUpdateScenarioIds = Object.freeze([
  'common.account.password-update',
] as const);

export type CommonAccountPasswordUpdateScenarioResult = Readonly<{
  id: (typeof commonAccountPasswordUpdateScenarioIds)[number];
  projection: CommonAccountPasswordUpdateProjection;
}>;

export const compareCommonAccountPasswordUpdateProjections = (
  oracle: CommonAccountPasswordUpdateProjection,
  candidate: CommonAccountPasswordUpdateProjection
): readonly string[] =>
  isDeepStrictEqual(oracle, commonAccountPasswordUpdateExpectedProjection) &&
  isDeepStrictEqual(candidate, commonAccountPasswordUpdateExpectedProjection) &&
  isDeepStrictEqual(oracle, candidate)
    ? []
    : ['/projection'];

export const runCommonAccountPasswordUpdateScenarioRow = async (
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    signal: AbortSignal;
    fetch?: typeof fetch;
  }>
): Promise<CommonAccountPasswordUpdateScenarioResult> =>
  Object.freeze({
    id: commonAccountPasswordUpdateScenarioIds[0],
    projection: await runCommonAccountPasswordUpdateForTarget(input),
  });
