import type { CommonNativeCodePkceProjection } from '../scenarios/common-native.js';

import { managementNativeResourceRoleExpectedProjection } from './management-native-resource-role-family.js';

test('publishes only the closed Native resource-role guarantees', () => {
  expect(managementNativeResourceRoleExpectedProjection).toEqual({
    nativeStable: true,
    provisioningOrdersAccepted: true,
    resourceTtl300: true,
    sessionExchangeBound: true,
    everyDefaultRoleAssigned: true,
    duplicateResourceRejected: true,
    duplicateScopeRejected: true,
    duplicateRoleScopeRejected: true,
    codeS256Accepted: true,
    resourceClaimsVerified: true,
    resourceRefreshRotated: true,
    ordinaryAccessOpaque: true,
    ordinaryProfilePreserved: true,
    deviceFlowRejected: true,
    targetOwnedCleanup: true,
  });
  expect(managementNativeResourceRoleExpectedProjection).not.toHaveProperty('accessToken');
  expect({} as CommonNativeCodePkceProjection).not.toHaveProperty('refreshToken');
});
