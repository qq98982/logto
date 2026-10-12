import type { JSONWebKeySet } from 'jose';

import type { TargetConfig } from '../../model.js';
import { managementApplicationsSecretsExpectedProjection } from '../browser/management-applications-secrets-family.js';
import {
  runManagementCompletionFamilyForTarget,
  type ManagementCompletionFamilyId,
  type ManagementCompletionFamilyProjection,
  type ManagementProvisioningFixture,
} from '../browser/management-completion-family-target-driver.js';
import { managementConnectorsExperienceExpectedProjection } from '../browser/management-connectors-experience-family.js';
import { managementNativeResourceRoleExpectedProjection } from '../browser/management-native-resource-role-family.js';
import { managementProvisioningConvergenceExpectedProjection } from '../browser/management-provisioning-convergence-family.js';
import { managementUserSuspendDeleteExpectedProjection } from '../browser/management-user-suspend-delete-family.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';

export type ManagementCompletionFamilyScenarioResult = Readonly<{
  id: ManagementCompletionFamilyId;
  projection: ManagementCompletionFamilyProjection;
}>;
const expected = Object.freeze({
  'common.management.applications-secrets': managementApplicationsSecretsExpectedProjection,
  'common.management.native-resource-role': managementNativeResourceRoleExpectedProjection,
  'common.management.connectors-experience': managementConnectorsExperienceExpectedProjection,
  'common.management.user-suspend-delete': managementUserSuspendDeleteExpectedProjection,
  'common.management.provisioning-convergence': managementProvisioningConvergenceExpectedProjection,
});
const exactClosedProjection = (
  value: unknown,
  contract: Readonly<Record<string, true>>
): boolean => {
  try {
    if (
      typeof value !== 'object' ||
      value === null ||
      Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype
    ) {
      return false;
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    const expectedKeys = Object.keys(contract);
    return (
      keys.length === expectedKeys.length &&
      keys.every(
        (key) =>
          typeof key === 'string' &&
          Object.hasOwn(contract, key) &&
          Object.hasOwn(descriptors[key] ?? {}, 'value') &&
          descriptors[key]?.value === true
      )
    );
  } catch {
    return false;
  }
};

export const compareManagementCompletionFamilyProjections = (
  id: ManagementCompletionFamilyId,
  oracle: unknown,
  candidate: unknown
): readonly string[] => {
  const contract = expected[id];
  return exactClosedProjection(oracle, contract) && exactClosedProjection(candidate, contract)
    ? []
    : ['/projection'];
};

export const runManagementCompletionFamilyScenarioRow = async (
  input: Readonly<{
    id: ManagementCompletionFamilyId;
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    signal: AbortSignal;
    jwks: Readonly<JSONWebKeySet>;
    fetch?: typeof fetch;
    withManagementBearer<Result>(use: (bearer: string) => Promise<Result>): Promise<Result>;
    captureOwnedApplication(id: string): void;
    observeForeignUserPreserved(use: (foreignId: string) => Promise<void>): Promise<boolean>;
    observeForeignConnectorPreserved(use: (foreignId: string) => Promise<void>): Promise<boolean>;
    observeForeignApplicationPreserved(use: (foreignId: string) => Promise<void>): Promise<boolean>;
    withProvisioningFixture<Result>(
      bearer: string,
      use: (fixture: ManagementProvisioningFixture) => Promise<Result>
    ): Promise<Result>;
  }>
): Promise<ManagementCompletionFamilyScenarioResult> =>
  Object.freeze({
    id: input.id,
    projection: await runManagementCompletionFamilyForTarget(input),
  });

export { managementCompletionFamilyIds } from '../browser/management-completion-family-target-driver.js';
