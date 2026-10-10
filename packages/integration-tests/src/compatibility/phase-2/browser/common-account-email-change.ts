/* eslint-disable complexity, max-lines -- The Account email main flow keeps destination, collision, mutation and login evidence in one compensated callback. */
import { randomBytes } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

import type { TargetConfig } from '../../model.js';
import {
  createAccountPasswordProof,
  readAccountProfile,
  readAccountUserInfo,
  requestAccountEmailProof,
  updateAccountEmail,
  verifyAccountEmailProof,
  type AccountSettingsObservation,
} from '../clients/account-settings.js';
import {
  exchangePublicRefresh,
  issuePublicAccountTokensForSubject,
} from '../clients/user-token-issuance.js';
import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

import { withSelectedAccountSettingsFixture } from './selected-account-settings-fixture.js';

export type CommonAccountEmailChangeProjection = Readonly<{
  opaqueAccess: true;
  proof: 'current+destination-email';
  mutation: AccountSettingsObservation;
  missingCurrentProof: AccountSettingsObservation;
  wrongAccountProof: AccountSettingsObservation;
  destinationReplay: AccountSettingsObservation;
  collision: AccountSettingsObservation;
  denialStatePreserved: true;
  ownerPreserved: true;
  newEmailVerified: true;
  newEmailLoginAccepted: true;
  refreshRotated: true;
}>;

export const commonAccountEmailChangeExpectedProjection = Object.freeze({
  opaqueAccess: true as const,
  proof: 'current+destination-email' as const,
  mutation: Object.freeze({ status: 204, error: 'none' as const }),
  missingCurrentProof: Object.freeze({
    status: 401,
    error: 'verification_record.permission_denied' as const,
  }),
  wrongAccountProof: Object.freeze({
    status: 401,
    error: 'verification_record.permission_denied' as const,
  }),
  destinationReplay: Object.freeze({ status: 204, error: 'none' as const }),
  collision: Object.freeze({ status: 422, error: 'user.email_already_in_use' as const }),
  denialStatePreserved: true as const,
  ownerPreserved: true as const,
  newEmailVerified: true as const,
  newEmailLoginAccepted: true as const,
  refreshRotated: true as const,
});

const fail = (): never => {
  throw new TypeError('Invalid Common Account email change flow');
};
export const assertCommonAccountEmailChangeProjection = (
  value: CommonAccountEmailChangeProjection
): CommonAccountEmailChangeProjection =>
  isDeepStrictEqual(value, commonAccountEmailChangeExpectedProjection) ? value : fail();
const record = (value: unknown): Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? Object.fromEntries(Object.entries(value))
    : fail();

export const runCommonAccountEmailChange = async (
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    managementRequest: Phase2AdminRequestFunction;
    signal: AbortSignal;
    fetch?: typeof fetch;
    getSelectedPassword(): string;
    getStatusSubjectPassword(): string;
    takeVerificationCode(recipient: string): Promise<string>;
  }>
): Promise<CommonAccountEmailChangeProjection> => {
  const status = input.fixture.status ?? fail();
  const requestFetch = input.fetch ?? fetch;
  const destinationEmail = `account-${randomBytes(12).toString('hex')}@example.invalid`;
  return withSelectedAccountSettingsFixture({
    fixture: input.fixture,
    request: input.managementRequest,
    browser: { clientId: status.client.id, redirectUri: status.client.redirectUri },
    field: 'email',
    getPassword: input.getSelectedPassword,
    use: async ({ identity }) => {
      const ownerTokens = await issuePublicAccountTokensForSubject(
        input.target,
        input.fixture,
        { email: identity.primaryEmail, password: input.getSelectedPassword() },
        requestFetch
      );
      if (ownerTokens.access.includes('.')) {
        return fail();
      }
      const destination = await requestAccountEmailProof(
        { target: input.target, bearer: ownerTokens.access, email: destinationEmail },
        requestFetch
      );
      if (destination.observation.status !== 201 || destination.observation.error !== 'none') {
        return fail();
      }
      const code = await input.takeVerificationCode(destinationEmail);
      const destinationId = destination.lease.getVerificationRecordId();
      const verified = await verifyAccountEmailProof(
        {
          target: input.target,
          bearer: ownerTokens.access,
          email: destinationEmail,
          code,
          verificationRecordId: destinationId,
        },
        requestFetch
      );
      if (verified.status !== 200 || verified.error !== 'none') {
        return fail();
      }
      return createAccountPasswordProof(
        {
          target: input.target,
          bearer: ownerTokens.access,
          password: input.getSelectedPassword(),
        },
        async (current) => {
          const collisionEmail = `collision-${randomBytes(12).toString('hex')}@example.invalid`;
          const collisionUser: unknown = await input.managementRequest({
            method: 'POST',
            path: 'users',
            body: {
              primaryEmail: collisionEmail,
              password: `C9!${randomBytes(18).toString('hex')}`,
            },
            expectedStatuses: [200],
            responseKind: 'object',
          });
          const collisionUserId: unknown = record(collisionUser).id;
          if (typeof collisionUserId !== 'string' || collisionUserId.length === 0) {
            return fail();
          }
          const collision = await (async () => {
            try {
              const collisionDestination = await requestAccountEmailProof(
                { target: input.target, bearer: ownerTokens.access, email: collisionEmail },
                requestFetch
              );
              const collisionId = collisionDestination.lease.getVerificationRecordId();
              const collisionCode = await input.takeVerificationCode(collisionEmail);
              const collisionVerified = await verifyAccountEmailProof(
                {
                  target: input.target,
                  bearer: ownerTokens.access,
                  email: collisionEmail,
                  code: collisionCode,
                  verificationRecordId: collisionId,
                },
                requestFetch
              );
              if (collisionVerified.status !== 200 || collisionVerified.error !== 'none') {
                return fail();
              }
              return await updateAccountEmail(
                {
                  target: input.target,
                  bearer: ownerTokens.access,
                  email: collisionEmail,
                  currentVerificationRecordId: current.getVerificationRecordId(),
                  destinationVerificationRecordId: collisionId,
                },
                requestFetch
              );
            } finally {
              await input.managementRequest({
                method: 'DELETE',
                path: `users/${encodeURIComponent(collisionUserId)}`,
                expectedStatuses: [204],
                responseKind: 'empty',
              });
            }
          })();
          const missingCurrentProof = await updateAccountEmail(
            {
              target: input.target,
              bearer: ownerTokens.access,
              email: destinationEmail,
              destinationVerificationRecordId: destinationId,
            },
            requestFetch
          );
          const foreignTokens = await issuePublicAccountTokensForSubject(
            input.target,
            input.fixture,
            { username: status.user.username, password: input.getStatusSubjectPassword() },
            requestFetch
          );
          const wrongAccountProof = await createAccountPasswordProof(
            {
              target: input.target,
              bearer: foreignTokens.access,
              password: input.getStatusSubjectPassword(),
            },
            async (foreign) =>
              updateAccountEmail(
                {
                  target: input.target,
                  bearer: ownerTokens.access,
                  email: destinationEmail,
                  currentVerificationRecordId: foreign.getVerificationRecordId(),
                  destinationVerificationRecordId: destinationId,
                },
                requestFetch
              ),
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
          const mutation = await updateAccountEmail(
            {
              target: input.target,
              bearer: ownerTokens.access,
              email: destinationEmail,
              currentVerificationRecordId: current.getVerificationRecordId(),
              destinationVerificationRecordId: destinationId,
            },
            requestFetch
          );
          const destinationReplay = await updateAccountEmail(
            {
              target: input.target,
              bearer: ownerTokens.access,
              email: destinationEmail,
              currentVerificationRecordId: current.getVerificationRecordId(),
              destinationVerificationRecordId: destinationId,
            },
            requestFetch
          );
          const profile = await readAccountProfile(
            {
              target: input.target,
              bearer: ownerTokens.access,
              expectedOwnerId: identity.id,
              expectedEmail: destinationEmail,
            },
            requestFetch
          );
          const newTokens = await issuePublicAccountTokensForSubject(
            input.target,
            input.fixture,
            { email: destinationEmail, password: input.getSelectedPassword() },
            requestFetch
          );
          if (newTokens.access.includes('.')) {
            return fail();
          }
          const newProfile = await readAccountProfile(
            {
              target: input.target,
              bearer: newTokens.access,
              expectedOwnerId: identity.id,
              expectedEmail: destinationEmail,
            },
            requestFetch
          );
          const userInfo = await readAccountUserInfo(
            {
              target: input.target,
              bearer: newTokens.access,
              expectedOwnerId: identity.id,
              expectedEmail: destinationEmail,
            },
            requestFetch
          );
          const refreshed = await exchangePublicRefresh(
            input.target,
            input.fixture,
            newTokens.refresh,
            { resource: false, fetch: requestFetch }
          );
          const refreshedProfile = await readAccountProfile(
            {
              target: input.target,
              bearer: refreshed.access,
              expectedOwnerId: identity.id,
              expectedEmail: destinationEmail,
            },
            requestFetch
          );
          if (
            input.signal.aborted ||
            ownerAfterDenials.status !== 200 ||
            !ownerAfterDenials.ownerMatches ||
            !ownerAfterDenials.emailMatches ||
            foreignAfterDenials.status !== 200 ||
            !foreignAfterDenials.ownerMatches ||
            mutation.status !== 204 ||
            mutation.error !== 'none' ||
            profile.status !== 200 ||
            !profile.ownerMatches ||
            !profile.emailMatches ||
            newProfile.status !== 200 ||
            !newProfile.ownerMatches ||
            !newProfile.emailMatches ||
            userInfo.status !== 200 ||
            !userInfo.ownerMatches ||
            !userInfo.emailMatches ||
            !userInfo.emailVerified ||
            refreshed.refresh === newTokens.refresh ||
            refreshedProfile.status !== 200 ||
            !refreshedProfile.ownerMatches ||
            !refreshedProfile.emailMatches
          ) {
            return fail();
          }
          return assertCommonAccountEmailChangeProjection(
            Object.freeze({
              opaqueAccess: true,
              proof: 'current+destination-email',
              mutation,
              missingCurrentProof,
              wrongAccountProof,
              destinationReplay,
              collision,
              denialStatePreserved: true,
              ownerPreserved: true,
              newEmailVerified: true,
              newEmailLoginAccepted: true,
              refreshRotated: true,
            })
          );
        },
        requestFetch
      );
    },
  });
};
/* eslint-enable complexity, max-lines */
