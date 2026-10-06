import {
  commonEmailCodeExpectedProjection,
  commonEmailCodeScenarioId,
} from '../browser/common-email-code-sign-in.js';

import {
  commonEmailCodeScenarioIds,
  compareCommonEmailCodeProjections,
} from './common-email-code.js';

test('registers one Common email Code row after the password row', () => {
  expect(commonEmailCodeScenarioIds).toEqual([commonEmailCodeScenarioId]);
  expect(Object.isFrozen(commonEmailCodeScenarioIds)).toBe(true);
});

test('compares only two identical exact Code projections', () => {
  expect(
    compareCommonEmailCodeProjections(
      commonEmailCodeExpectedProjection,
      commonEmailCodeExpectedProjection
    )
  ).toEqual([]);
  expect(
    compareCommonEmailCodeProjections(commonEmailCodeExpectedProjection, {
      ...commonEmailCodeExpectedProjection,
      controls: {
        ...commonEmailCodeExpectedProjection.controls,
        expiry: { status: 400, error: 'verification_code.not_found' },
      },
    } as never)
  ).toEqual(['/projection']);
});
