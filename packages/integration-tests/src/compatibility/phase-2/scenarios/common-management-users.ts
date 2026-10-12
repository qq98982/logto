import { isDeepStrictEqual } from 'node:util';

import type { JSONWebKeySet } from 'jose';

import type { TargetConfig } from '../../model.js';
import { runCommonManagementUserForTarget } from '../browser/common-management-users-target-driver.js';
import {
  commonManagementUserContactUpdatePendingProjection,
  commonManagementUserCreatePendingProjection,
  type CommonManagementUserContactUpdateProjection,
  type CommonManagementUserCreateProjection,
} from '../browser/common-management-users.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';

export const commonManagementUserScenarioIds = Object.freeze([
  'common.management.user-create',
  'common.management.user-contact-update',
] as const);
export type CommonManagementUserScenarioResult = Readonly<{
  id: (typeof commonManagementUserScenarioIds)[number];
  projection: CommonManagementUserCreateProjection | CommonManagementUserContactUpdateProjection;
}>;
export const compareCommonManagementUserProjections = (
  id: CommonManagementUserScenarioResult['id'],
  oracle: unknown,
  candidate: unknown
): readonly string[] => {
  const expected =
    id === commonManagementUserScenarioIds[0]
      ? commonManagementUserCreatePendingProjection
      : commonManagementUserContactUpdatePendingProjection;
  return isDeepStrictEqual(oracle, expected) && isDeepStrictEqual(candidate, expected)
    ? []
    : ['/projection'];
};
export const runCommonManagementUserScenarioRow = async (
  input: Readonly<{
    id: CommonManagementUserScenarioResult['id'];
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    signal: AbortSignal;
    jwks: Readonly<JSONWebKeySet>;
    fetch?: typeof fetch;
  }>
): Promise<CommonManagementUserScenarioResult> =>
  Object.freeze({
    id: input.id,
    projection: await runCommonManagementUserForTarget({
      ...input,
      kind: input.id === commonManagementUserScenarioIds[0] ? 'user-create' : 'user-contact-update',
    }),
  });
