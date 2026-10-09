import { commonEmailRecoveryExpectedProjection } from '../browser/common-email-recovery-target-driver.js';

import {
  commonPasswordRecoveryScenarioIds,
  compareCommonPasswordRecoveryProjections,
} from './common-password-recovery.js';

test('registers the canonical Common password recovery row', () => {
  expect(commonPasswordRecoveryScenarioIds).toEqual(['common.password.recovery']);
  expect(Object.isFrozen(commonPasswordRecoveryScenarioIds)).toBe(true);
});

test('accepts only the exact expected recovery projection on both targets', () => {
  expect(
    compareCommonPasswordRecoveryProjections(
      commonEmailRecoveryExpectedProjection,
      commonEmailRecoveryExpectedProjection
    )
  ).toEqual([]);
  expect(
    compareCommonPasswordRecoveryProjections(commonEmailRecoveryExpectedProjection, {
      ...commonEmailRecoveryExpectedProjection,
      priorAccessUsable: false,
    } as never)
  ).toEqual(['/projection']);
  expect(
    compareCommonPasswordRecoveryProjections(commonEmailRecoveryExpectedProjection, {
      ...commonEmailRecoveryExpectedProjection,
      wrongPurpose: {
        ...commonEmailRecoveryExpectedProjection.wrongPurpose,
        ownerAfterRecovery: {
          ...commonEmailRecoveryExpectedProjection.wrongPurpose.ownerAfterRecovery,
          status: 's400',
        },
      },
    } as never)
  ).toEqual(['/projection']);
});
