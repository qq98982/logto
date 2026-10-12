import {
  commonManagementUserContactUpdatePendingProjection,
  commonManagementUserCreatePendingProjection,
} from '../browser/common-management-users.js';

import {
  commonManagementUserScenarioIds,
  compareCommonManagementUserProjections,
} from './common-management-users.js';

test('appends two closed Management user rows with exact projections', () => {
  expect(commonManagementUserScenarioIds).toEqual([
    'common.management.user-create',
    'common.management.user-contact-update',
  ]);
  expect(
    compareCommonManagementUserProjections(
      commonManagementUserScenarioIds[0],
      commonManagementUserCreatePendingProjection,
      commonManagementUserCreatePendingProjection
    )
  ).toEqual([]);
  expect(
    compareCommonManagementUserProjections(
      commonManagementUserScenarioIds[1],
      commonManagementUserContactUpdatePendingProjection,
      commonManagementUserContactUpdatePendingProjection
    )
  ).toEqual([]);
  expect(
    compareCommonManagementUserProjections(
      commonManagementUserScenarioIds[0],
      { ...commonManagementUserCreatePendingProjection, everyDefaultRoleAssigned: false },
      commonManagementUserCreatePendingProjection
    )
  ).toEqual(['/projection']);
});
