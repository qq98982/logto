import {
  compareCommonPhoneCodeProjections,
  commonPhoneCodeScenarioIds,
} from './common-phone-code.js';

const controls = {
  occupiedRegistration: {
    status: 422 as const,
    code: 'user.phone_already_in_use' as const,
    ownerUnchanged: true as const,
  },
  consumedReplay: { status: 400 as const, code: 'verification_code.not_found' as const },
  recipientMismatch: {
    status: 400 as const,
    code: 'verification_code.phone_mismatch' as const,
    ownerRetained: true as const,
  },
  suspendedOwner: { status: 401 as const, code: 'user.suspended' as const },
};
const signInFlow = {
  identifier: 'phone' as const,
  outcome: 'accepted' as const,
  consent: true as const,
  callback: 'state-issuer-code-bound' as const,
  pkce: 'S256' as const,
  profileSubject: true as const,
  phoneVerified: true as const,
  refreshRotated: true as const,
};
const signIn = { flow: signInFlow, controls };
const registration = { flow: { ...signInFlow, outcome: 'created' as const }, controls };
it('keeps registration and existing-owner sign-in as distinct observable contracts', () => {
  expect(commonPhoneCodeScenarioIds).toEqual([
    'common.phone.code-registration',
    'common.phone.code-sign-in',
  ]);
  expect(
    compareCommonPhoneCodeProjections(commonPhoneCodeScenarioIds[0], registration, registration)
  ).toEqual([]);
  expect(compareCommonPhoneCodeProjections(commonPhoneCodeScenarioIds[1], signIn, signIn)).toEqual(
    []
  );
  expect(compareCommonPhoneCodeProjections(commonPhoneCodeScenarioIds[0], signIn, signIn)).toEqual([
    '/projection',
  ]);
});
it('rejects matching incorrect security outcomes on both targets', () => {
  const invalid = {
    ...signIn,
    controls: {
      ...controls,
      recipientMismatch: { ...controls.recipientMismatch, ownerRetained: false },
    },
  };
  expect(
    // @ts-expect-error -- Malformed wire facts must fail even when both targets agree.
    compareCommonPhoneCodeProjections(commonPhoneCodeScenarioIds[1], invalid, invalid)
  ).toEqual(['/projection']);
  const unverified = { ...registration, flow: { ...registration.flow, phoneVerified: false } };
  expect(
    // @ts-expect-error -- Unverified wire facts cannot establish phone-only registration.
    compareCommonPhoneCodeProjections(commonPhoneCodeScenarioIds[0], unverified, unverified)
  ).toEqual(['/projection']);
});
