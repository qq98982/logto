import { commonEmailPasswordScenarioIds } from './common-email-password.js';

test('registers one Common email password row after the accepted Native row', () => {
  expect(commonEmailPasswordScenarioIds).toEqual(['common.email.password-sign-in']);
  expect(Object.isFrozen(commonEmailPasswordScenarioIds)).toBe(true);
});
