/* eslint-disable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- The Account phone flow keeps proof, denial, mutation and login evidence in one compensated callback. */
import { isDeepStrictEqual } from 'node:util';

import type { TargetConfig } from '../../model.js';
import {
  createAccountPasswordProof,
  readAccountProfile,
  readAccountUserInfo,
  requestAccountPhoneProof,
  updateAccountPhone,
  verifyAccountPhoneProof,
  type AccountSettingsObservation,
} from '../clients/account-settings.js';
import { issuePublicAccountTokensForSubject } from '../clients/user-token-issuance.js';
import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

import { withSelectedAccountSettingsFixture } from './selected-account-settings-fixture.js';
import type { CommonPhoneCodeProviderLease } from './selected-phone-code-fixture.js';

export type CommonAccountPhoneChangeProjection = Readonly<{
  opaqueAccess: true;
  proof: 'current+destination-phone';
  mutation: AccountSettingsObservation;
  missingCurrentProof: AccountSettingsObservation;
  wrongAccountProof: AccountSettingsObservation;
  destinationReplay: AccountSettingsObservation;
  collision: AccountSettingsObservation;
  denialStatePreserved: true;
  collisionOwnerPreserved: true;
  ownerPreserved: true;
  emailPreserved: true;
  oldPhoneReleased: true;
  newPhoneVerified: true;
  newPhoneLoginAccepted: true;
  refreshRotated: true;
}>;

// Pending confirmation by the pinned Reference/Aster pair; publication remains exact-only.
export const commonAccountPhoneChangePendingReferenceProjection = Object.freeze({
  opaqueAccess: true as const,
  proof: 'current+destination-phone' as const,
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
  collision: Object.freeze({ status: 422, error: 'user.phone_already_in_use' as const }),
  denialStatePreserved: true as const,
  collisionOwnerPreserved: true as const,
  ownerPreserved: true as const,
  emailPreserved: true as const,
  oldPhoneReleased: true as const,
  newPhoneVerified: true as const,
  newPhoneLoginAccepted: true as const,
  refreshRotated: true as const,
});

const fail = (): never => {
  throw new TypeError('Invalid Common Account phone change flow');
};
const record = (value: unknown): Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? Object.fromEntries(Object.entries(value))
    : fail();

export const assertCommonAccountPhoneChangeProjection = (
  value: CommonAccountPhoneChangeProjection
): CommonAccountPhoneChangeProjection =>
  isDeepStrictEqual(value, commonAccountPhoneChangePendingReferenceProjection) ? value : fail();

const phoneSuffix = (allocationId: string): string =>
  [...allocationId]
    .map((value) => String(value.codePointAt(0) ?? 0))
    .join('')
    .padEnd(9, '0')
    .slice(0, 9);

export const runCommonAccountPhoneChange = async (
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    managementRequest: Phase2AdminRequestFunction;
    provider: CommonPhoneCodeProviderLease;
    signal: AbortSignal;
    fetch?: typeof fetch;
    getSelectedPassword(): string;
    getStatusSubjectPassword(): string;
    runPhoneLogin(phone: string, ownerId: string): Promise<Readonly<{ refreshRotated: boolean }>>;
  }>
): Promise<CommonAccountPhoneChangeProjection> => {
  const status = input.fixture.status ?? fail();
  const requestFetch = input.fetch ?? fetch;
  const suffix = phoneSuffix(input.fixture.public.allocationId);
  const destinationPhone = `8616${suffix}`;
  const collisionPhone = `8619${suffix}`;
  return withSelectedAccountSettingsFixture({
    fixture: input.fixture,
    request: input.managementRequest,
    browser: {
      clientId: status.client.id,
      redirectUri: new URL('/demo-app', input.target.coreUrl).href,
    },
    field: 'phone',
    phoneProvider: input.provider,
    getPassword: input.getSelectedPassword,
    use: async ({ identity, initialPhone, setPhoneSignIn }) => {
      if (!initialPhone) {
        return fail();
      }
      const ownerTokens = await issuePublicAccountTokensForSubject(
        input.target,
        input.fixture,
        { email: identity.primaryEmail, password: input.getSelectedPassword() },
        requestFetch,
        { includePhone: true }
      );
      if (ownerTokens.access.includes('.')) {
        return fail();
      }
      await input.provider.arm(destinationPhone, 'Generic');
      const destination = await requestAccountPhoneProof(
        { target: input.target, bearer: ownerTokens.access, phone: destinationPhone },
        requestFetch
      );
      if (destination.observation.status !== 201 || destination.observation.error !== 'none') {
        return fail();
      }
      const destinationId = destination.lease.getVerificationRecordId();
      const verified = await verifyAccountPhoneProof(
        {
          target: input.target,
          bearer: ownerTokens.access,
          phone: destinationPhone,
          code: await input.provider.takeCode(destinationPhone, 'Generic'),
          verificationRecordId: destinationId,
        },
        requestFetch
      );
      if (verified.status !== 200 || verified.error !== 'none') {
        return fail();
      }
      return createAccountPasswordProof(
        { target: input.target, bearer: ownerTokens.access, password: input.getSelectedPassword() },
        async (current) => {
          const collisionUser = record(
            await input.managementRequest({
              method: 'POST',
              path: 'users',
              body: { primaryPhone: collisionPhone },
              expectedStatuses: [200, 201],
              responseKind: 'object',
            })
          );
          const collisionUserId =
            typeof collisionUser.id === 'string' && collisionUser.id ? collisionUser.id : fail();
          try {
            await input.provider.arm(collisionPhone, 'Generic');
            const collisionDestination = await requestAccountPhoneProof(
              { target: input.target, bearer: ownerTokens.access, phone: collisionPhone },
              requestFetch
            );
            const collisionId = collisionDestination.lease.getVerificationRecordId();
            const collisionVerified = await verifyAccountPhoneProof(
              {
                target: input.target,
                bearer: ownerTokens.access,
                phone: collisionPhone,
                code: await input.provider.takeCode(collisionPhone, 'Generic'),
                verificationRecordId: collisionId,
              },
              requestFetch
            );
            if (collisionVerified.status !== 200 || collisionVerified.error !== 'none') {
              return fail();
            }
            const collision = await updateAccountPhone(
              {
                target: input.target,
                bearer: ownerTokens.access,
                phone: collisionPhone,
                currentVerificationRecordId: current.getVerificationRecordId(),
                destinationVerificationRecordId: collisionId,
              },
              requestFetch
            );
            const missingCurrentProof = await updateAccountPhone(
              {
                target: input.target,
                bearer: ownerTokens.access,
                phone: destinationPhone,
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
                updateAccountPhone(
                  {
                    target: input.target,
                    bearer: ownerTokens.access,
                    phone: destinationPhone,
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
                expectedPhone: initialPhone,
              },
              requestFetch
            );
            const collisionAfterDenials = record(
              await input.managementRequest({
                method: 'GET',
                path: `users/${encodeURIComponent(collisionUserId)}`,
                expectedStatuses: [200],
                responseKind: 'object',
              })
            );
            const mutation = await updateAccountPhone(
              {
                target: input.target,
                bearer: ownerTokens.access,
                phone: destinationPhone,
                currentVerificationRecordId: current.getVerificationRecordId(),
                destinationVerificationRecordId: destinationId,
              },
              requestFetch
            );
            const destinationReplay = await updateAccountPhone(
              {
                target: input.target,
                bearer: ownerTokens.access,
                phone: destinationPhone,
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
                expectedEmail: identity.primaryEmail,
                expectedPhone: destinationPhone,
              },
              requestFetch
            );
            const userInfo = await readAccountUserInfo(
              {
                target: input.target,
                bearer: ownerTokens.access,
                expectedOwnerId: identity.id,
                expectedEmail: identity.primaryEmail,
                expectedPhone: destinationPhone,
              },
              requestFetch
            );
            const oldPhoneReleased = await (async () => {
              let releasedOwnerId: string | undefined;
              try {
                const releasedOwner = record(
                  await input.managementRequest({
                    method: 'POST',
                    path: 'users',
                    body: { primaryPhone: initialPhone },
                    expectedStatuses: [200, 201],
                    responseKind: 'object',
                  })
                );
                releasedOwnerId =
                  typeof releasedOwner.id === 'string' && releasedOwner.id
                    ? releasedOwner.id
                    : fail();
                return releasedOwner.primaryPhone === initialPhone;
              } finally {
                if (releasedOwnerId) {
                  await input.managementRequest({
                    method: 'DELETE',
                    path: `users/${encodeURIComponent(releasedOwnerId)}`,
                    expectedStatuses: [204, 404],
                    responseKind: 'status',
                  });
                }
              }
            })();
            await setPhoneSignIn();
            const login = await input.runPhoneLogin(destinationPhone, identity.id);
            if (
              input.signal.aborted ||
              ownerAfterDenials.status !== 200 ||
              !ownerAfterDenials.ownerMatches ||
              !ownerAfterDenials.emailMatches ||
              !ownerAfterDenials.phoneMatches ||
              collisionAfterDenials.id !== collisionUserId ||
              collisionAfterDenials.primaryPhone !== collisionPhone ||
              mutation.status !== 204 ||
              mutation.error !== 'none' ||
              profile.status !== 200 ||
              !profile.ownerMatches ||
              !profile.emailMatches ||
              !profile.phoneMatches ||
              userInfo.status !== 200 ||
              !userInfo.ownerMatches ||
              !userInfo.emailMatches ||
              !userInfo.emailVerified ||
              !userInfo.phoneMatches ||
              !userInfo.phoneVerified ||
              !oldPhoneReleased ||
              !login.refreshRotated
            ) {
              return fail();
            }
            return assertCommonAccountPhoneChangeProjection(
              Object.freeze({
                opaqueAccess: true,
                proof: 'current+destination-phone',
                mutation,
                missingCurrentProof,
                wrongAccountProof,
                destinationReplay,
                collision,
                denialStatePreserved: true,
                collisionOwnerPreserved: true,
                ownerPreserved: true,
                emailPreserved: true,
                oldPhoneReleased: true,
                newPhoneVerified: true,
                newPhoneLoginAccepted: true,
                refreshRotated: true,
              })
            );
          } finally {
            await input.managementRequest({
              method: 'DELETE',
              path: `users/${encodeURIComponent(collisionUserId)}`,
              expectedStatuses: [204, 404],
              responseKind: 'status',
            });
          }
        },
        requestFetch
      );
    },
  });
};
/* eslint-enable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
