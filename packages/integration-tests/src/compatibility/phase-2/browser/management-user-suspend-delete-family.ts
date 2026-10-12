/* eslint-disable complexity, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- The flow retains owned IDs for independent cleanup after lifecycle mutations. */
import { randomBytes } from 'node:crypto';

import type { TargetConfig } from '../../model.js';
import { observeManagementCompletionRequest } from '../clients/management-completion-observer.js';
import {
  observeActiveUserInfo,
  observeRevokedRefresh,
  observeRevokedUserInfo,
} from '../clients/management-user-lifecycle-family.js';
import {
  createManagementUser,
  deleteManagementUser,
  readManagementUser,
} from '../clients/management-users.js';
import { issuePublicAccountTokensForSubject } from '../clients/user-token-issuance.js';
import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

export const managementUserSuspendDeleteFamilyId = 'common.management.user-suspend-delete';
export type ManagementUserSuspendDeleteProjection = Readonly<{
  suspended: true;
  oldAccessDenied: true;
  oldRefreshDenied: true;
  unsuspended: true;
  freshLoginAccepted: true;
  oldGrantNotRevived: true;
  deleted: true;
  deletedAccessDenied: true;
  deletedRefreshDenied: true;
  repeatDeleteNotFound: true;
  foreignUserPreserved: true;
  authFirstDenied: true;
  missingUserRejected: true;
}>;
export const managementUserSuspendDeleteExpectedProjection: ManagementUserSuspendDeleteProjection =
  Object.freeze({
    suspended: true,
    oldAccessDenied: true,
    oldRefreshDenied: true,
    unsuspended: true,
    freshLoginAccepted: true,
    oldGrantNotRevived: true,
    deleted: true,
    deletedAccessDenied: true,
    deletedRefreshDenied: true,
    repeatDeleteNotFound: true,
    foreignUserPreserved: true,
    authFirstDenied: true,
    missingUserRejected: true,
  });
const fail = (stage: string): never => {
  throw new TypeError(`Invalid Common Management lifecycle family (${stage})`);
};

export const runManagementUserSuspendDeleteFamily = async (
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    request: Phase2AdminRequestFunction;
    password: string;
    fetch?: typeof fetch;
    observeForeignPreserved(use: (foreignId: string) => Promise<void>): Promise<boolean>;
  }>
): Promise<ManagementUserSuspendDeleteProjection> => {
  const email = `management-lifecycle-${randomBytes(12).toString('hex')}@example.invalid`;
  let ownerId: string | undefined;
  let deleted = false;
  try {
    const owner = await createManagementUser(
      input.request,
      { email, password: input.password },
      (id) => {
        ownerId = id;
      }
    );
    const tokens = await issuePublicAccountTokensForSubject(
      input.target,
      input.fixture,
      { email, password: input.password },
      input.fetch
    );
    const suspended = await input.request({
      method: 'PATCH',
      path: `users/${encodeURIComponent(owner.id)}/is-suspended`,
      body: { isSuspended: true },
      expectedStatuses: [200],
      responseKind: 'object',
    });
    if (Reflect.get(suspended as Record<string, unknown>, 'isSuspended') !== true) {
      return fail('suspend');
    }
    const suspendedAccess = await observeRevokedUserInfo(input.target, tokens.access, input.fetch);
    const suspendedRefresh = await observeRevokedRefresh(
      input.target,
      input.fixture,
      tokens.refresh,
      input.fetch
    );
    const restored = await input.request({
      method: 'PATCH',
      path: `users/${encodeURIComponent(owner.id)}/is-suspended`,
      body: { isSuspended: false },
      expectedStatuses: [200],
      responseKind: 'object',
    });
    if (Reflect.get(restored as Record<string, unknown>, 'isSuspended') !== false) {
      return fail('unsuspend');
    }
    const fresh = await issuePublicAccountTokensForSubject(
      input.target,
      input.fixture,
      { email, password: input.password },
      input.fetch
    );
    const freshInfo = await observeActiveUserInfo(input.target, fresh.access, input.fetch);
    const oldAfterRestore = await observeRevokedRefresh(
      input.target,
      input.fixture,
      tokens.refresh,
      input.fetch
    );
    const unauthorized = await observeManagementCompletionRequest({
      target: input.target,
      createHeaders: () =>
        new Headers({ authorization: 'Bearer invalid.phase2.management.bearer' }),
      method: 'PATCH',
      path: `users/${encodeURIComponent(owner.id)}/is-suspended`,
      body: 'not-json',
      ...(input.fetch ? { fetch: input.fetch } : {}),
    });
    const missingId = `missing-${randomBytes(12).toString('hex')}`;
    const missingSuspend = await input.request({
      method: 'PATCH',
      path: `users/${missingId}/is-suspended`,
      body: { isSuspended: true },
      expectedStatuses: [404],
      responseKind: 'object',
    });
    const missingDelete = await input.request({
      method: 'DELETE',
      path: `users/${missingId}`,
      expectedStatuses: [404],
      responseKind: 'object',
    });
    let foreignSuspendCode: unknown;
    let foreignDeleteCode: unknown;
    const foreignPreserved = await input.observeForeignPreserved(async (foreignId) => {
      const foreignSuspend = await input.request({
        method: 'PATCH',
        path: `users/${encodeURIComponent(foreignId)}/is-suspended`,
        body: { isSuspended: true },
        expectedStatuses: [404],
        responseKind: 'object',
      });
      const foreignDelete = await input.request({
        method: 'DELETE',
        path: `users/${encodeURIComponent(foreignId)}`,
        expectedStatuses: [404],
        responseKind: 'object',
      });
      foreignSuspendCode = Reflect.get(foreignSuspend as Record<string, unknown>, 'code');
      foreignDeleteCode = Reflect.get(foreignDelete as Record<string, unknown>, 'code');
    });
    await readManagementUser(input.request, owner.id);
    await deleteManagementUser(input.request, owner.id);
    deleted = true;
    const deletedAccess = await observeRevokedUserInfo(input.target, fresh.access, input.fetch);
    const deletedRefresh = await observeRevokedRefresh(
      input.target,
      input.fixture,
      fresh.refresh,
      input.fetch
    );
    const repeated = await input.request({
      method: 'DELETE',
      path: `users/${encodeURIComponent(owner.id)}`,
      expectedStatuses: [404],
      responseKind: 'object',
    });
    if (
      suspendedAccess.status !== 401 ||
      suspendedAccess.code !== 'invalid_token' ||
      suspendedRefresh.status !== 400 ||
      suspendedRefresh.code !== 'invalid_grant' ||
      deletedAccess.status !== 401 ||
      deletedAccess.code !== 'invalid_token' ||
      deletedRefresh.status !== 400 ||
      deletedRefresh.code !== 'invalid_grant' ||
      oldAfterRestore.status !== 400 ||
      oldAfterRestore.code !== 'invalid_grant' ||
      freshInfo.subject !== owner.id ||
      unauthorized.status !== 401 ||
      unauthorized.code !== 'auth.unauthorized' ||
      Reflect.get(missingSuspend as Record<string, unknown>, 'code') !== 'entity.not_found' ||
      Reflect.get(missingDelete as Record<string, unknown>, 'code') !== 'entity.not_found' ||
      Reflect.get(repeated as Record<string, unknown>, 'code') !== 'entity.not_found' ||
      foreignSuspendCode !== 'entity.not_found' ||
      foreignDeleteCode !== 'entity.not_found' ||
      !foreignPreserved
    ) {
      return fail('projection');
    }
    return managementUserSuspendDeleteExpectedProjection;
  } finally {
    if (ownerId && !deleted) {
      await deleteManagementUser(input.request, ownerId);
    }
  }
};
/* eslint-enable complexity, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
