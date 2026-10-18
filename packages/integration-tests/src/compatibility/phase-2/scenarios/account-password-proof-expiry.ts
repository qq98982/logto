import { randomBytes } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

import type { TargetConfig } from '../../model.js';
import { withSelectedAccountSettingsFixture } from '../browser/selected-account-settings-fixture.js';
import {
  createAccountPasswordProof,
  observeAccountPasswordProof,
  readAccountProfile,
  updateAccountPassword,
  type AccountSettingsObservation,
} from '../clients/account-settings.js';
import { issuePublicAccountTokensForSubject } from '../clients/user-token-issuance.js';
import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

export const accountPasswordProofExpiryScenarioId = 'supplemental.account.password-proof-expiry';
export type AccountPasswordProofScenarioId = typeof accountPasswordProofExpiryScenarioId;

export type AccountPasswordProofStateHandle = Readonly<{
  capture(): Promise<void>;
  expire(): Promise<void>;
}>;

export type AccountPasswordProofStateDriver = Readonly<{
  withAccountPasswordProofHandle<Result>(
    scenarioId: AccountPasswordProofScenarioId,
    fixture: ProvisionedPhase2Fixture,
    userId: string,
    use: (handle: AccountPasswordProofStateHandle) => Result | Promise<Result>
  ): Promise<Result>;
}>;

export type AccountPasswordProofExpiryProjection = Readonly<{
  mutation: AccountSettingsObservation;
  ownerPreserved: true;
  emailPreserved: true;
  currentPasswordAccepted: true;
  attemptedPasswordRejected: true;
}>;

export const accountPasswordProofExpiryExpectedProjection = Object.freeze({
  mutation: Object.freeze({
    status: 401,
    error: 'verification_record.permission_denied' as const,
  }),
  ownerPreserved: true as const,
  emailPreserved: true as const,
  currentPasswordAccepted: true as const,
  attemptedPasswordRejected: true as const,
});

const fail = (): never => {
  throw new TypeError('Invalid Account password-proof expiry comparison');
};

export const assertAccountPasswordProofExpiryProjection = (
  value: AccountPasswordProofExpiryProjection
): AccountPasswordProofExpiryProjection =>
  isDeepStrictEqual(value, accountPasswordProofExpiryExpectedProjection) ? value : fail();

export const compareAccountPasswordProofExpiryProjections = (
  oracle: AccountPasswordProofExpiryProjection,
  candidate: AccountPasswordProofExpiryProjection
): readonly string[] =>
  isDeepStrictEqual(oracle, accountPasswordProofExpiryExpectedProjection) &&
  isDeepStrictEqual(candidate, accountPasswordProofExpiryExpectedProjection) &&
  isDeepStrictEqual(oracle, candidate)
    ? []
    : ['/projection'];

export const runAccountPasswordProofExpiry = async (
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    state: AccountPasswordProofStateDriver;
    managementRequest: Phase2AdminRequestFunction;
    signal: AbortSignal;
    fetch?: typeof fetch;
    getPassword(): string;
  }>
): Promise<AccountPasswordProofExpiryProjection> => {
  const status = input.fixture.status ?? fail();
  const requestFetch = input.fetch ?? fetch;
  const attemptedPassword = `A9!${randomBytes(18).toString('hex')}`;
  return withSelectedAccountSettingsFixture({
    fixture: input.fixture,
    request: input.managementRequest,
    browser: { clientId: status.client.id, redirectUri: status.client.redirectUri },
    field: 'password',
    getPassword: input.getPassword,
    use: async ({ identity }) => {
      const tokens = await issuePublicAccountTokensForSubject(
        input.target,
        input.fixture,
        { email: identity.primaryEmail, password: input.getPassword() },
        requestFetch
      );
      return input.state.withAccountPasswordProofHandle(
        accountPasswordProofExpiryScenarioId,
        input.fixture,
        identity.id,
        async (stateHandle) =>
          createAccountPasswordProof(
            { target: input.target, bearer: tokens.access, password: input.getPassword() },
            async (proof) => {
              await stateHandle.capture();
              await stateHandle.expire();
              const mutation = await updateAccountPassword(
                {
                  target: input.target,
                  bearer: tokens.access,
                  password: attemptedPassword,
                  verificationRecordId: proof.getVerificationRecordId(),
                },
                requestFetch
              );
              const [profile, currentPassword, attemptedPasswordProof] = await Promise.all([
                readAccountProfile(
                  {
                    target: input.target,
                    bearer: tokens.access,
                    expectedOwnerId: identity.id,
                    expectedEmail: identity.primaryEmail,
                  },
                  requestFetch
                ),
                observeAccountPasswordProof(
                  { target: input.target, bearer: tokens.access, password: input.getPassword() },
                  requestFetch
                ),
                observeAccountPasswordProof(
                  { target: input.target, bearer: tokens.access, password: attemptedPassword },
                  requestFetch
                ),
              ]);
              if (
                input.signal.aborted ||
                mutation.status !== 401 ||
                mutation.error !== 'verification_record.permission_denied' ||
                profile.status !== 200 ||
                !profile.ownerMatches ||
                !profile.emailMatches ||
                currentPassword.status !== 201 ||
                currentPassword.error !== 'none' ||
                attemptedPasswordProof.status !== 422 ||
                attemptedPasswordProof.error !== 'session.invalid_credentials'
              ) {
                return fail();
              }
              return accountPasswordProofExpiryExpectedProjection;
            },
            requestFetch
          )
      );
    },
  });
};
