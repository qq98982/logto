import { managementApplicationsSecretsExpectedProjection } from '../browser/management-applications-secrets-family.js';

import {
  compareManagementCompletionFamilyProjections,
  managementCompletionFamilyIds,
} from './management-completion-family.js';

const accessorProjection: unknown = Object.create(Object.prototype, {
  applicationStable: { get: () => true, enumerable: true },
});

describe('Common Management completion scenario', () => {
  it('keeps exactly the five locally owned family identifiers in append order', () => {
    expect(managementCompletionFamilyIds).toEqual([
      'common.management.applications-secrets',
      'common.management.native-resource-role',
      'common.management.connectors-experience',
      'common.management.user-suspend-delete',
      'common.management.provisioning-convergence',
    ]);
  });

  it('requires both targets to equal the closed row projection', () => {
    expect(
      compareManagementCompletionFamilyProjections(
        'common.management.applications-secrets',
        managementApplicationsSecretsExpectedProjection,
        managementApplicationsSecretsExpectedProjection
      )
    ).toEqual([]);
    expect(
      compareManagementCompletionFamilyProjections(
        'common.management.applications-secrets',
        { ...managementApplicationsSecretsExpectedProjection, initialSecretAuthenticated: false },
        managementApplicationsSecretsExpectedProjection
      )
    ).toEqual(['/projection']);
    expect(
      compareManagementCompletionFamilyProjections(
        'common.management.applications-secrets',
        { ...managementApplicationsSecretsExpectedProjection, extra: true },
        managementApplicationsSecretsExpectedProjection
      )
    ).toEqual(['/projection']);
    expect(
      compareManagementCompletionFamilyProjections(
        'common.management.applications-secrets',
        accessorProjection,
        managementApplicationsSecretsExpectedProjection
      )
    ).toEqual(['/projection']);
  });
});
