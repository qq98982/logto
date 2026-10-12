/* eslint-disable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- Each workflow owns Management mutation, public credentials and reverse compensation. */
import { randomBytes } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

import type { JSONWebKeySet } from 'jose';

import type { TargetConfig } from '../../model.js';
import {
  readAccountProfile,
  readAccountUserInfo,
  type AccountProfileObservation,
  type AccountUserInfoObservation,
} from '../clients/account-settings.js';
import {
  createManagementUser,
  deleteManagementUser,
  readDefaultManagementUserRoleIds,
  readManagementUser,
  readManagementUserRoles,
  updateManagementUser,
  verifyManagementResourceAccess,
  type ManagementUserMutationObserver,
} from '../clients/management-users.js';
import {
  exchangePublicRefresh,
  issuePublicAccountTokensForSubject,
  observePublicAccountPasswordSignIn,
} from '../clients/user-token-issuance.js';
import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

export type CommonManagementUserCreateProjection = Readonly<{
  managementCreated: true;
  credentialFreeProjection: true;
  everyDefaultRoleAssigned: true;
  duplicateRejected: true;
  duplicateStatePreserved: true;
  opaqueAccountAccess: true;
  ownerPreserved: true;
  emailVerified: true;
  resourceAccessSigned: true;
  refreshRotated: true;
}>;
export type CommonManagementUserContactUpdateProjection = Readonly<{
  atomicContactUpdate: true;
  updatedAtMonotonic: true;
  newEmailLoginAccepted: true;
  oldEmailRejected: true;
  claimsVerified: true;
  ordinaryProfilePreserved: true;
  collisionRolledBack: true;
  malformedRejected: true;
  authFirstDenied: true;
  priorAccessAccepted: true;
  priorRefreshAccepted: true;
  rolesPreserved: true;
  foreignUserPreserved: true;
}>;
export const commonManagementUserCreatePendingProjection = Object.freeze({
  managementCreated: true as const,
  credentialFreeProjection: true as const,
  everyDefaultRoleAssigned: true as const,
  duplicateRejected: true as const,
  duplicateStatePreserved: true as const,
  opaqueAccountAccess: true as const,
  ownerPreserved: true as const,
  emailVerified: true as const,
  resourceAccessSigned: true as const,
  refreshRotated: true as const,
});
export const commonManagementUserContactUpdatePendingProjection = Object.freeze({
  atomicContactUpdate: true as const,
  updatedAtMonotonic: true as const,
  newEmailLoginAccepted: true as const,
  oldEmailRejected: true as const,
  claimsVerified: true as const,
  ordinaryProfilePreserved: true as const,
  collisionRolledBack: true as const,
  malformedRejected: true as const,
  authFirstDenied: true as const,
  priorAccessAccepted: true as const,
  priorRefreshAccepted: true as const,
  rolesPreserved: true as const,
  foreignUserPreserved: true as const,
});
const fail = (stage = 'contract'): never => {
  throw new TypeError(`Invalid Common Management user flow (${stage})`);
};
const suffix = () => randomBytes(12).toString('hex');
const exact = <Value>(value: Value, expected: Value): Value =>
  isDeepStrictEqual(value, expected) ? value : fail();
export const assertManagementMutation = (
  value: Readonly<{ status: number; error: string }>,
  expected: Readonly<{ status: number; error: string }>,
  stage: string
): void => {
  if (value.status !== expected.status || value.error !== expected.error) {
    return fail(`${stage}-s${value.status}-${value.error.replaceAll('.', '-')}`);
  }
};
export const assertManagementUserCreateReads = (
  profile: AccountProfileObservation,
  userInfo: AccountUserInfoObservation
): void => {
  if (
    profile.status !== 200 ||
    profile.error !== 'none' ||
    !profile.ownerMatches ||
    !profile.emailMatches ||
    userInfo.status !== 200 ||
    !userInfo.ownerMatches ||
    !userInfo.emailMatches ||
    !userInfo.emailVerified
  ) {
    return fail('create-account-reads');
  }
};
export const assertManagementUserContactReads = (
  profile: AccountProfileObservation,
  userInfo: AccountUserInfoObservation,
  priorProfile: AccountProfileObservation,
  ordinaryAccess: string
): void => {
  if (
    profile.status !== 200 ||
    profile.error !== 'none' ||
    !profile.ownerMatches ||
    !profile.emailMatches ||
    !profile.phoneMatches ||
    userInfo.status !== 200 ||
    !userInfo.ownerMatches ||
    !userInfo.emailMatches ||
    !userInfo.emailVerified ||
    !userInfo.phoneMatches ||
    !userInfo.phoneVerified ||
    priorProfile.status !== 200 ||
    priorProfile.error !== 'none' ||
    !priorProfile.ownerMatches ||
    ordinaryAccess.includes('.')
  ) {
    return fail('contact-account-reads');
  }
};

export const deleteOwnedManagementUsers = async (
  request: Phase2AdminRequestFunction,
  ids: ReadonlyArray<string | undefined>
): Promise<void> => {
  const results = await Promise.allSettled(
    ids
      .filter((id): id is string => id !== undefined)
      .map(async (id) => deleteManagementUser(request, id))
  );
  const failures = results.filter((result) => result.status === 'rejected');
  if (failures.length > 0) {
    throw new AggregateError(
      Array.from(
        { length: failures.length },
        () => new TypeError('Management user cleanup failed')
      ),
      'Common Management user cleanup failed'
    );
  }
};

export const runCommonManagementUserCreate = async (
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    request: Phase2AdminRequestFunction;
    observeMutation: ManagementUserMutationObserver;
    observeUnauthorizedMutation: ManagementUserMutationObserver;
    password: string;
    jwks: Readonly<JSONWebKeySet>;
    fetch?: typeof fetch;
  }>
): Promise<CommonManagementUserCreateProjection> => {
  const requestFetch = input.fetch ?? fetch;
  const email = `management-create-${suffix()}@example.invalid`;
  let ownerId: string | undefined;
  try {
    const defaultIds = await readDefaultManagementUserRoleIds(input.request);
    const owner = await createManagementUser(
      input.request,
      { email, password: input.password },
      (id) => {
        ownerId = id;
      }
    );
    const roles = await readManagementUserRoles(input.request, owner.id);
    if (
      !isDeepStrictEqual(
        roles
          .filter(({ isDefault }) => isDefault)
          .map(({ id }) => id)
          .slice()
          .sort(),
        defaultIds
      )
    ) {
      return fail('default-role-membership');
    }
    const duplicate = await input.observeMutation({
      method: 'POST',
      path: 'users',
      body: { primaryEmail: email, password: input.password },
    });
    const afterDuplicate = await readManagementUser(input.request, owner.id);
    const rolesAfterDuplicate = await readManagementUserRoles(input.request, owner.id);
    const tokens = await issuePublicAccountTokensForSubject(
      input.target,
      input.fixture,
      { email, password: input.password },
      requestFetch,
      { includePhone: false }
    );
    const profile = await readAccountProfile(
      {
        target: input.target,
        bearer: tokens.access,
        expectedOwnerId: owner.id,
        expectedEmail: email,
      },
      requestFetch
    );
    const userInfo = await readAccountUserInfo(
      {
        target: input.target,
        bearer: tokens.access,
        expectedOwnerId: owner.id,
        expectedEmail: email,
      },
      requestFetch
    );
    const resource = await issuePublicAccountTokensForSubject(
      input.target,
      input.fixture,
      { email, password: input.password },
      requestFetch,
      { resource: true }
    );
    const refreshed = await exchangePublicRefresh(input.target, input.fixture, resource.refresh, {
      resource: true,
      fetch: requestFetch,
    });
    await verifyManagementResourceAccess(resource.access, input.jwks, {
      issuer: new URL('/oidc', input.target.coreUrl).href,
      audience: input.fixture.status?.resource.indicator ?? fail(),
      subject: owner.id,
      clientId: input.fixture.status?.client.id ?? fail(),
      scope: input.fixture.status?.resource.scopeName ?? fail(),
    }).catch(() => fail('resource-token'));
    await verifyManagementResourceAccess(refreshed.access, input.jwks, {
      issuer: new URL('/oidc', input.target.coreUrl).href,
      audience: input.fixture.status?.resource.indicator ?? fail(),
      subject: owner.id,
      clientId: input.fixture.status?.client.id ?? fail(),
      scope: input.fixture.status?.resource.scopeName ?? fail(),
    }).catch(() => fail('refreshed-resource-token'));
    assertManagementMutation(
      duplicate,
      { status: 422, error: 'user.email_already_in_use' },
      'duplicate'
    );
    assertManagementUserCreateReads(profile, userInfo);
    if (
      !isDeepStrictEqual(afterDuplicate, owner) ||
      !isDeepStrictEqual(rolesAfterDuplicate, roles) ||
      tokens.access.includes('.') ||
      refreshed.refresh === resource.refresh
    ) {
      return fail('create-predicates');
    }
    return exact(
      Object.freeze({
        managementCreated: true,
        credentialFreeProjection: true,
        everyDefaultRoleAssigned: true,
        duplicateRejected: true,
        duplicateStatePreserved: true,
        opaqueAccountAccess: true,
        ownerPreserved: true,
        emailVerified: true,
        resourceAccessSigned: true,
        refreshRotated: true,
      }),
      commonManagementUserCreatePendingProjection
    );
  } finally {
    if (ownerId) {
      await deleteOwnedManagementUsers(input.request, [ownerId]);
    }
  }
};

export const runCommonManagementUserContactUpdate = async (
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    request: Phase2AdminRequestFunction;
    observeMutation: ManagementUserMutationObserver;
    observeUnauthorizedMutation: ManagementUserMutationObserver;
    password: string;
    jwks: Readonly<JSONWebKeySet>;
    fetch?: typeof fetch;
  }>
): Promise<CommonManagementUserContactUpdateProjection> => {
  const requestFetch = input.fetch ?? fetch;
  const oldEmail = `management-old-${suffix()}@example.invalid`;
  const newEmail = `management-new-${suffix()}@example.invalid`;
  const collisionEmail = `management-collision-${suffix()}@example.invalid`;
  const updatedName = 'After';
  const updatedPhone = `8618${Date.now().toString().slice(-9)}`;
  let ownerId: string | undefined;
  let collisionId: string | undefined;
  try {
    const owner = await createManagementUser(
      input.request,
      {
        email: oldEmail,
        password: input.password,
        name: 'Before',
        phone: `8613${Date.now().toString().slice(-9)}`,
      },
      (id) => {
        ownerId = id;
      }
    );
    const rolesBefore = await readManagementUserRoles(input.request, owner.id);
    const prior = await issuePublicAccountTokensForSubject(
      input.target,
      input.fixture,
      { email: oldEmail, password: input.password },
      requestFetch
    );
    const priorResource = await issuePublicAccountTokensForSubject(
      input.target,
      input.fixture,
      { email: oldEmail, password: input.password },
      requestFetch,
      { resource: true }
    );
    const updated = await updateManagementUser(input.request, {
      id: owner.id,
      name: updatedName,
      email: newEmail,
      phone: updatedPhone,
    });
    const readback = await readManagementUser(input.request, owner.id);
    const collision = await createManagementUser(
      input.request,
      { email: collisionEmail, password: input.password },
      (id) => {
        collisionId = id;
      }
    );
    const foreignBefore = await readManagementUser(input.request, collision.id);
    const beforeCollision = await readManagementUser(input.request, owner.id);
    const collisionAttempt = await input.observeMutation({
      method: 'PATCH',
      path: `users/${encodeURIComponent(owner.id)}`,
      body: { name: 'Bad', primaryEmail: collisionEmail },
    });
    const afterCollision = await readManagementUser(input.request, owner.id);
    const malformed = await input.observeMutation({
      method: 'PATCH',
      path: `users/${encodeURIComponent(owner.id)}`,
      body: { primaryEmail: 'invalid' },
    });
    const authFirst = await input.observeUnauthorizedMutation({
      method: 'PATCH',
      path: `users/${encodeURIComponent(owner.id)}`,
      body: { primaryEmail: 'invalid' },
    });
    const afterControls = await readManagementUser(input.request, owner.id);
    const foreignAfter = await readManagementUser(input.request, collision.id);
    const oldSignIn = await observePublicAccountPasswordSignIn(
      input.target,
      input.fixture,
      { email: oldEmail, password: input.password },
      requestFetch
    );
    const current = await issuePublicAccountTokensForSubject(
      input.target,
      input.fixture,
      { email: newEmail, password: input.password },
      requestFetch,
      { includePhone: true, resource: true }
    );
    const ordinary = await issuePublicAccountTokensForSubject(
      input.target,
      input.fixture,
      { email: newEmail, password: input.password },
      requestFetch,
      { includePhone: true }
    );
    const profile = await readAccountProfile(
      {
        target: input.target,
        bearer: ordinary.access,
        expectedOwnerId: owner.id,
        expectedEmail: newEmail,
        expectedPhone: updated.primaryPhone ?? undefined,
      },
      requestFetch
    );
    const info = await readAccountUserInfo(
      {
        target: input.target,
        bearer: ordinary.access,
        expectedOwnerId: owner.id,
        expectedEmail: newEmail,
        expectedPhone: updated.primaryPhone ?? undefined,
      },
      requestFetch
    );
    const priorProfile = await readAccountProfile(
      { target: input.target, bearer: prior.access, expectedOwnerId: owner.id },
      requestFetch
    );
    const priorRefresh = await exchangePublicRefresh(
      input.target,
      input.fixture,
      priorResource.refresh,
      {
        resource: true,
        fetch: requestFetch,
      }
    );
    await Promise.all(
      [current.access, priorRefresh.access].map(async (access) =>
        verifyManagementResourceAccess(access, input.jwks, {
          issuer: new URL('/oidc', input.target.coreUrl).href,
          audience: input.fixture.status?.resource.indicator ?? fail(),
          subject: owner.id,
          clientId: input.fixture.status?.client.id ?? fail(),
          scope: input.fixture.status?.resource.scopeName ?? fail(),
        }).catch(() => fail('retained-resource-token'))
      )
    );
    assertManagementMutation(
      collisionAttempt,
      { status: 422, error: 'user.email_already_in_use' },
      'collision'
    );
    assertManagementMutation(malformed, { status: 400, error: 'guard.invalid_input' }, 'malformed');
    assertManagementMutation(authFirst, { status: 401, error: 'auth.unauthorized' }, 'auth-first');
    assertManagementUserContactReads(profile, info, priorProfile, ordinary.access);
    const rolesAfter = await readManagementUserRoles(input.request, owner.id);
    if (
      updated.name !== updatedName ||
      updated.primaryEmail !== newEmail ||
      updated.primaryPhone !== updatedPhone ||
      !isDeepStrictEqual(readback, updated) ||
      updated.updatedAt < owner.updatedAt ||
      !isDeepStrictEqual(beforeCollision, afterCollision) ||
      !isDeepStrictEqual(afterControls, updated) ||
      !isDeepStrictEqual(foreignBefore, foreignAfter) ||
      oldSignIn.accepted ||
      priorRefresh.refresh === priorResource.refresh ||
      !isDeepStrictEqual(rolesBefore, rolesAfter)
    ) {
      return fail('contact-predicates');
    }
    return exact(
      Object.freeze({
        atomicContactUpdate: true,
        updatedAtMonotonic: true,
        newEmailLoginAccepted: true,
        oldEmailRejected: true,
        claimsVerified: true,
        ordinaryProfilePreserved: true,
        collisionRolledBack: true,
        malformedRejected: true,
        authFirstDenied: true,
        priorAccessAccepted: true,
        priorRefreshAccepted: true,
        rolesPreserved: true,
        foreignUserPreserved: true,
      }),
      commonManagementUserContactUpdatePendingProjection
    );
  } finally {
    await deleteOwnedManagementUsers(input.request, [collisionId, ownerId]);
  }
};
/* eslint-enable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
