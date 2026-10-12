import type { TargetConfig } from '../../model.js';
import {
  createAccountPasswordProof,
  type AccountVerificationLease,
} from '../clients/account-settings.js';
import {
  observeAccountSocialMutation,
  readAccountSocialProfile,
  type AccountSocialProvider,
} from '../clients/account-social.js';
import type { IssuedPublicUserTokens } from '../clients/user-token-issuance.js';
import {
  assertCommonAccountSocialProjection,
  type CommonAccountSocialProjection,
  type SocialMutation,
} from '../scenarios/common-social-account.js';

const fail = (): never => {
  throw new TypeError('Invalid Common Account social flow');
};
type ProofUse = <Result>(
  use: (proof: AccountVerificationLease) => Promise<Result>
) => Promise<Result>;

export type CommonAccountSocialFixture = Readonly<{
  provider: AccountSocialProvider;
  ownerId: string;
  socialSubject: string;
  ownerPassword: string;
  ownerTokens: IssuedPublicUserTokens;
  foreignTokens: IssuedPublicUserTokens;
  foreignPassword: string;
  withDestinationProof: ProofUse;
  withForeignOwnedDestinationProof: ProofUse;
  observeLastMethod(): Promise<SocialMutation>;
  providerRequestExact(): boolean;
}>;

const mutation = async (
  input: Readonly<{
    target: TargetConfig;
    bearer: string;
    provider: AccountSocialProvider;
    operation: 'link' | 'unlink';
    permissionId?: string;
    destinationProofId?: string;
  }>,
  requestFetch: typeof fetch
): Promise<SocialMutation> => observeAccountSocialMutation(input, requestFetch);

export const runCommonAccountSocial = async (
  target: TargetConfig,
  fixture: CommonAccountSocialFixture,
  requestFetch: typeof fetch = fetch
): Promise<CommonAccountSocialProjection> => {
  const { ownerTokens, provider } = fixture;
  if (ownerTokens.access.includes('.') || fixture.foreignTokens.access.includes('.')) {
    return fail();
  }
  return createAccountPasswordProof(
    { target, bearer: ownerTokens.access, password: fixture.ownerPassword },
    async (current) =>
      fixture.withDestinationProof(async (destination) => {
        const destinationProofId = destination.getVerificationRecordId();
        const missingCurrentProof = await mutation(
          {
            target,
            bearer: ownerTokens.access,
            provider,
            operation: 'link',
            destinationProofId,
          },
          requestFetch
        );
        const wrongAccountProof = await createAccountPasswordProof(
          {
            target,
            bearer: fixture.foreignTokens.access,
            password: fixture.foreignPassword,
          },
          async (wrong) =>
            mutation(
              {
                target,
                bearer: ownerTokens.access,
                provider,
                operation: 'link',
                permissionId: wrong.getVerificationRecordId(),
                destinationProofId,
              },
              requestFetch
            ),
          requestFetch
        );
        const link = await mutation(
          {
            target,
            bearer: ownerTokens.access,
            provider,
            operation: 'link',
            permissionId: current.getVerificationRecordId(),
            destinationProofId,
          },
          requestFetch
        );
        const linked = await readAccountSocialProfile(
          {
            target,
            bearer: ownerTokens.access,
            provider,
            expectedOwner: fixture.ownerId,
            expectedSocialSubject: fixture.socialSubject,
          },
          requestFetch
        );
        const destinationReplay = await mutation(
          {
            target,
            bearer: ownerTokens.access,
            provider,
            operation: 'link',
            permissionId: current.getVerificationRecordId(),
            destinationProofId,
          },
          requestFetch
        );
        const unlink = await mutation(
          {
            target,
            bearer: ownerTokens.access,
            provider,
            operation: 'unlink',
            permissionId: current.getVerificationRecordId(),
          },
          requestFetch
        );
        const unlinked = await readAccountSocialProfile(
          {
            target,
            bearer: ownerTokens.access,
            provider,
            expectedOwner: fixture.ownerId,
          },
          requestFetch
        );
        const foreignOwner = await fixture.withForeignOwnedDestinationProof(async (foreignProof) =>
          mutation(
            {
              target,
              bearer: ownerTokens.access,
              provider,
              operation: 'link',
              permissionId: current.getVerificationRecordId(),
              destinationProofId: foreignProof.getVerificationRecordId(),
            },
            requestFetch
          )
        );
        const lastMethod = await fixture.observeLastMethod();
        return assertCommonAccountSocialProjection({
          provider,
          opaqueAccess: true,
          proof: 'current+provider',
          link,
          profileLinked: linked.status === 200 && linked.ownerMatches && linked.identityMatches,
          unlink,
          profileUnlinked:
            unlinked.status === 200 && unlinked.ownerMatches && unlinked.identityMatches,
          missingCurrentProof,
          wrongAccountProof,
          foreignOwner,
          destinationReplay,
          lastMethod,
          denialStatePreserved:
            linked.ownerMatches && unlinked.ownerMatches && unlinked.identityMatches,
          credentialsAbsent: linked.credentialsAbsent && unlinked.credentialsAbsent,
          providerRequestExact: fixture.providerRequestExact(),
        });
      }),
    requestFetch
  );
};
