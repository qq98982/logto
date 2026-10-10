/* eslint-disable max-lines -- The password update flow and its closed public projection stay in one auditable module. */
import { randomBytes } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

import type { TargetConfig } from '../../model.js';
import {
  createAccountPasswordProof,
  observeAccountPasswordProof,
  readAccountProfile,
  updateAccountPassword,
  type AccountSettingsObservation,
} from '../clients/account-settings.js';
import {
  exchangePublicRefresh,
  issuePublicAccountTokensForSubject,
  observePublicAccountPasswordSignIn,
} from '../clients/user-token-issuance.js';
import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

import { withSelectedAccountSettingsFixture } from './selected-account-settings-fixture.js';

export type CommonAccountPasswordUpdateProjection = Readonly<{
  opaqueAccess: true;
  proof: 'current';
  mutation: AccountSettingsObservation;
  missingProof: AccountSettingsObservation;
  foreignProof: AccountSettingsObservation;
  samePassword: AccountSettingsObservation;
  readOnly: AccountSettingsObservation;
  disabled: AccountSettingsObservation;
  denialStatePreserved: true;
  oldAccessRetained: true;
  oldRefreshRotated: true;
  oldPasswordLoginRejected: true;
  newPasswordAccepted: true;
  newRefreshRotated: true;
  ownerPreserved: true;
}>;

export const commonAccountPasswordUpdateExpectedProjection = Object.freeze({
  opaqueAccess: true as const,
  proof: 'current' as const,
  mutation: Object.freeze({ status: 204, error: 'none' as const }),
  missingProof: Object.freeze({
    status: 401,
    error: 'verification_record.permission_denied' as const,
  }),
  foreignProof: Object.freeze({
    status: 401,
    error: 'verification_record.permission_denied' as const,
  }),
  samePassword: Object.freeze({ status: 422, error: 'user.same_password' as const }),
  readOnly: Object.freeze({
    status: 400,
    error: 'account_center.field_not_editable' as const,
  }),
  disabled: Object.freeze({ status: 400, error: 'account_center.not_enabled' as const }),
  denialStatePreserved: true as const,
  oldAccessRetained: true as const,
  oldRefreshRotated: true as const,
  oldPasswordLoginRejected: true as const,
  newPasswordAccepted: true as const,
  newRefreshRotated: true as const,
  ownerPreserved: true as const,
});

const fail = (): never => {
  throw new TypeError('Invalid Common Account password update flow');
};
export const assertCommonAccountPasswordUpdateProjection = (
  value: CommonAccountPasswordUpdateProjection
): CommonAccountPasswordUpdateProjection =>
  isDeepStrictEqual(value, commonAccountPasswordUpdateExpectedProjection) ? value : fail();

export const runCommonAccountPasswordUpdate = async (
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    managementRequest: Phase2AdminRequestFunction;
    signal: AbortSignal;
    fetch?: typeof fetch;
    getSelectedPassword(): string;
    getStatusSubjectPassword(): string;
  }>
): Promise<CommonAccountPasswordUpdateProjection> => {
  const status = input.fixture.status ?? fail();
  const requestFetch = input.fetch ?? fetch;
  const newPassword = `A9!${randomBytes(18).toString('hex')}`;
  return withSelectedAccountSettingsFixture({
    fixture: input.fixture,
    request: input.managementRequest,
    browser: { clientId: status.client.id, redirectUri: status.client.redirectUri },
    field: 'password',
    getPassword: input.getSelectedPassword,
    use: async ({ identity, setControl }) => {
      const ownerTokens = await issuePublicAccountTokensForSubject(
        input.target,
        input.fixture,
        { email: identity.primaryEmail, password: input.getSelectedPassword() },
        requestFetch
      );
      if (ownerTokens.access.includes('.')) {
        return fail();
      }
      return createAccountPasswordProof(
        {
          target: input.target,
          bearer: ownerTokens.access,
          password: input.getSelectedPassword(),
        },
        // eslint-disable-next-line complexity -- One callback validates the closed control sequence.
        async (proof) => {
          const proofId = proof.getVerificationRecordId();
          const missingProof = await updateAccountPassword(
            { target: input.target, bearer: ownerTokens.access, password: newPassword },
            requestFetch
          );
          const foreignTokens = await issuePublicAccountTokensForSubject(
            input.target,
            input.fixture,
            {
              username: status.user.username,
              password: input.getStatusSubjectPassword(),
            },
            requestFetch
          );
          const foreignProof = await createAccountPasswordProof(
            {
              target: input.target,
              bearer: foreignTokens.access,
              password: input.getStatusSubjectPassword(),
            },
            async (foreign) =>
              updateAccountPassword(
                {
                  target: input.target,
                  bearer: ownerTokens.access,
                  password: newPassword,
                  verificationRecordId: foreign.getVerificationRecordId(),
                },
                requestFetch
              ),
            requestFetch
          );
          await setControl({ enabled: true, field: 'ReadOnly' });
          const readOnly = await updateAccountPassword(
            {
              target: input.target,
              bearer: ownerTokens.access,
              password: newPassword,
              verificationRecordId: proofId,
            },
            requestFetch
          );
          await setControl({ enabled: false, field: 'Edit' });
          const disabled = await updateAccountPassword(
            {
              target: input.target,
              bearer: ownerTokens.access,
              password: newPassword,
              verificationRecordId: proofId,
            },
            requestFetch
          );
          await setControl({ enabled: true, field: 'Edit' });
          const currentProofAfterDenials = await observeAccountPasswordProof(
            {
              target: input.target,
              bearer: ownerTokens.access,
              password: input.getSelectedPassword(),
            },
            requestFetch
          );
          const ownerAfterDenials = await readAccountProfile(
            {
              target: input.target,
              bearer: ownerTokens.access,
              expectedOwnerId: identity.id,
              expectedEmail: identity.primaryEmail,
            },
            requestFetch
          );
          const foreignAfterDenials = await readAccountProfile(
            {
              target: input.target,
              bearer: foreignTokens.access,
              expectedOwnerId: status.user.id,
            },
            requestFetch
          );
          const mutation = await updateAccountPassword(
            {
              target: input.target,
              bearer: ownerTokens.access,
              password: newPassword,
              verificationRecordId: proofId,
            },
            requestFetch
          );
          const samePassword = await updateAccountPassword(
            {
              target: input.target,
              bearer: ownerTokens.access,
              password: newPassword,
              verificationRecordId: proofId,
            },
            requestFetch
          );
          const oldProfile = await readAccountProfile(
            {
              target: input.target,
              bearer: ownerTokens.access,
              expectedOwnerId: identity.id,
              expectedEmail: identity.primaryEmail,
            },
            requestFetch
          );
          const refreshed = await exchangePublicRefresh(
            input.target,
            input.fixture,
            ownerTokens.refresh,
            { resource: false, fetch: requestFetch }
          );
          const oldPassword = await observeAccountPasswordProof(
            {
              target: input.target,
              bearer: ownerTokens.access,
              password: input.getSelectedPassword(),
            },
            requestFetch
          );
          const oldPasswordSignIn = await observePublicAccountPasswordSignIn(
            input.target,
            input.fixture,
            { email: identity.primaryEmail, password: input.getSelectedPassword() },
            requestFetch
          );
          const newTokens = await issuePublicAccountTokensForSubject(
            input.target,
            input.fixture,
            { email: identity.primaryEmail, password: newPassword },
            requestFetch
          );
          const newProfile = await readAccountProfile(
            {
              target: input.target,
              bearer: newTokens.access,
              expectedOwnerId: identity.id,
              expectedEmail: identity.primaryEmail,
            },
            requestFetch
          );
          const newRefreshed = await exchangePublicRefresh(
            input.target,
            input.fixture,
            newTokens.refresh,
            { resource: false, fetch: requestFetch }
          );
          const refreshedNewProfile = await readAccountProfile(
            {
              target: input.target,
              bearer: newRefreshed.access,
              expectedOwnerId: identity.id,
              expectedEmail: identity.primaryEmail,
            },
            requestFetch
          );
          if (
            input.signal.aborted ||
            currentProofAfterDenials.status !== 201 ||
            currentProofAfterDenials.error !== 'none' ||
            !ownerAfterDenials.ownerMatches ||
            !ownerAfterDenials.emailMatches ||
            !foreignAfterDenials.ownerMatches ||
            mutation.status !== 204 ||
            mutation.error !== 'none' ||
            oldProfile.status !== 200 ||
            !oldProfile.ownerMatches ||
            refreshed.refresh === ownerTokens.refresh ||
            oldPassword.status !== 422 ||
            oldPassword.error !== 'session.invalid_credentials' ||
            oldPasswordSignIn.accepted ||
            newProfile.status !== 200 ||
            !newProfile.ownerMatches ||
            newRefreshed.refresh === newTokens.refresh ||
            refreshedNewProfile.status !== 200 ||
            !refreshedNewProfile.ownerMatches ||
            !refreshedNewProfile.emailMatches
          ) {
            return fail();
          }
          return assertCommonAccountPasswordUpdateProjection(
            Object.freeze({
              opaqueAccess: true,
              proof: 'current',
              mutation,
              missingProof,
              foreignProof,
              samePassword,
              readOnly,
              disabled,
              denialStatePreserved: true,
              oldAccessRetained: true,
              oldRefreshRotated: true,
              oldPasswordLoginRejected: true,
              newPasswordAccepted: true,
              newRefreshRotated: true,
              ownerPreserved: true,
            })
          );
        },
        requestFetch
      );
    },
  });
};
/* eslint-enable max-lines */
