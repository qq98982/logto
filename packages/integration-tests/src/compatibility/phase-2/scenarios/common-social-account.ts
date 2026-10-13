import { isDeepStrictEqual } from 'node:util';

export const commonSocialAccountScenarioIds = Object.freeze([
  'common.google.configured-collision',
  'common.account.google-link',
  'common.account.wechat-link',
] as const);

export type SocialMutation = Readonly<{ status: number; error: string }>;

export type CommonGoogleConfiguredCollisionProjection = Readonly<{
  configured: boolean;
  signInStatus: number;
  implicitAssociationAbsent: boolean;
  originalOwnerPreserved: boolean;
  providerRequestExact: boolean;
}>;

export type CommonAccountSocialProjection = Readonly<{
  provider: 'google' | 'wechat';
  opaqueAccess: boolean;
  proof: 'current+provider';
  link: SocialMutation;
  profileLinked: boolean;
  unlink: SocialMutation;
  profileUnlinked: boolean;
  missingCurrentProof: SocialMutation;
  wrongAccountProof: SocialMutation;
  foreignOwner: SocialMutation;
  destinationReplay: SocialMutation;
  lastMethod: SocialMutation;
  denialStatePreserved: boolean;
  credentialsAbsent: boolean;
  providerRequestExact: boolean;
}>;

export const commonGoogleConfiguredCollisionExpectedProjection = Object.freeze({
  configured: true as const,
  signInStatus: 404 as const,
  implicitAssociationAbsent: true as const,
  originalOwnerPreserved: true as const,
  providerRequestExact: true as const,
});

const permissionDenied = Object.freeze({
  status: 401,
  error: 'verification_record.permission_denied',
});
const identityInUse = Object.freeze({ status: 422, error: 'user.identity_already_in_use' });
const sameOwnerLinked = Object.freeze({ status: 204, error: 'none' });
const lastMethod = Object.freeze({ status: 400, error: 'user.last_sign_in_method_required' });

export const commonAccountSocialExpectedProjection = (
  provider: 'google' | 'wechat'
): CommonAccountSocialProjection =>
  Object.freeze({
    provider,
    opaqueAccess: true,
    proof: 'current+provider',
    link: Object.freeze({ status: 204, error: 'none' }),
    profileLinked: true,
    unlink: Object.freeze({ status: 204, error: 'none' }),
    profileUnlinked: true,
    missingCurrentProof: permissionDenied,
    wrongAccountProof: permissionDenied,
    foreignOwner: identityInUse,
    destinationReplay: sameOwnerLinked,
    lastMethod,
    denialStatePreserved: true,
    credentialsAbsent: true,
    providerRequestExact: true,
  });

const fail = (): never => {
  throw new TypeError('Invalid Common social Account projection');
};

export const assertCommonGoogleConfiguredCollisionProjection = (
  value: CommonGoogleConfiguredCollisionProjection
): CommonGoogleConfiguredCollisionProjection =>
  isDeepStrictEqual(value, commonGoogleConfiguredCollisionExpectedProjection) ? value : fail();

export const assertCommonAccountSocialProjection = (
  value: CommonAccountSocialProjection
): CommonAccountSocialProjection =>
  isDeepStrictEqual(value, commonAccountSocialExpectedProjection(value.provider)) ? value : fail();

export const compareCommonGoogleConfiguredCollisionProjections = (
  oracle: CommonGoogleConfiguredCollisionProjection,
  candidate: CommonGoogleConfiguredCollisionProjection
): readonly string[] =>
  isDeepStrictEqual(oracle, commonGoogleConfiguredCollisionExpectedProjection) &&
  isDeepStrictEqual(candidate, commonGoogleConfiguredCollisionExpectedProjection) &&
  isDeepStrictEqual(oracle, candidate)
    ? []
    : ['/projection'];

export const compareCommonAccountSocialProjections = (
  oracle: CommonAccountSocialProjection,
  candidate: CommonAccountSocialProjection
): readonly string[] =>
  isDeepStrictEqual(oracle, commonAccountSocialExpectedProjection(oracle.provider)) &&
  isDeepStrictEqual(candidate, commonAccountSocialExpectedProjection(candidate.provider)) &&
  isDeepStrictEqual(oracle, candidate)
    ? []
    : ['/projection'];
