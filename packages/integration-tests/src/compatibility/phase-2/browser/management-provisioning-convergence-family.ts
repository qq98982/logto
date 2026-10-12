/* eslint-disable no-restricted-syntax, no-await-in-loop, @silverhand/fp/no-mutating-methods, @typescript-eslint/member-ordering, @typescript-eslint/require-array-sort-compare -- The bounded convergence runner serializes external provisioner passes and canonicalizes response snapshots. */
import { isDeepStrictEqual } from 'node:util';

import type { TargetConfig } from '../../model.js';
import { observeClientSecretAuthentication } from '../clients/management-applications-family.js';
import { withManagementProvisioningFamily } from '../clients/management-provisioning-family.js';
import type { Phase2AdminRequestFunction } from '../fixtures.js';

export const managementProvisioningConvergenceFamilyId =
  'common.management.provisioning-convergence';
export type ManagementProvisioningConvergenceProjection = Readonly<{
  repeatedConverged: true;
  identitiesStable: true;
  relationshipsStable: true;
  secretStableAndAuthenticated: true;
  associationRepaired: true;
  globalAndChinaNativeConverged: true;
  ownershipRefused: true;
  credentialOutputPrivate: true;
}>;
export const managementProvisioningConvergenceExpectedProjection: ManagementProvisioningConvergenceProjection =
  Object.freeze({
    repeatedConverged: true,
    identitiesStable: true,
    relationshipsStable: true,
    secretStableAndAuthenticated: true,
    associationRepaired: true,
    globalAndChinaNativeConverged: true,
    ownershipRefused: true,
    credentialOutputPrivate: true,
  });
const fail = (stage: string): never => {
  throw new TypeError(`Invalid Common Management convergence family (${stage})`);
};
const array = (value: unknown): readonly unknown[] =>
  Array.isArray(value) && value.length < 100 ? value : fail('array');
const snapshot = async (request: Phase2AdminRequestFunction) => {
  const roles = array(
    await request({
      method: 'GET',
      path: 'roles',
      query: { page: '1', page_size: '100' },
      expectedStatuses: [200],
      responseKind: 'array',
    })
  );
  const roleScopes = await Promise.all(
    roles.map(async (value) => {
      const id = Reflect.get(value as Record<string, unknown>, 'id');
      if (typeof id !== 'string' || id.length === 0 || id.length > 128) {
        return fail('role-id');
      }
      const scopes = array(
        await request({
          method: 'GET',
          path: `roles/${encodeURIComponent(id)}/scopes`,
          expectedStatuses: [200],
          responseKind: 'array',
        })
      );
      return [
        id,
        scopes.map((scope) => Reflect.get(scope as Record<string, unknown>, 'id')).sort(),
      ] as const;
    })
  );
  return Object.freeze({
    users: array(
      await request({
        method: 'GET',
        path: 'users',
        query: { page: '1', page_size: '100' },
        expectedStatuses: [200],
        responseKind: 'array',
      })
    )
      .map((value) => [
        Reflect.get(value as Record<string, unknown>, 'id'),
        Reflect.get(value as Record<string, unknown>, 'username'),
        Reflect.get(value as Record<string, unknown>, 'primaryEmail'),
        Reflect.get(value as Record<string, unknown>, 'primaryPhone'),
      ])
      .sort(),
    applications: array(
      await request({
        method: 'GET',
        path: 'applications',
        expectedStatuses: [200],
        responseKind: 'array',
      })
    )
      .map((value) => [
        Reflect.get(value as Record<string, unknown>, 'id'),
        Reflect.get(value as Record<string, unknown>, 'name'),
        Reflect.get(value as Record<string, unknown>, 'type'),
      ])
      .sort(),
    resources: array(
      await request({
        method: 'GET',
        path: 'resources',
        query: { includeScopes: 'true' },
        expectedStatuses: [200],
        responseKind: 'array',
      })
    )
      .map((value) => [
        Reflect.get(value as Record<string, unknown>, 'id'),
        Reflect.get(value as Record<string, unknown>, 'name'),
      ])
      .sort(),
    roles: roles
      .map((value) => [
        Reflect.get(value as Record<string, unknown>, 'id'),
        Reflect.get(value as Record<string, unknown>, 'name'),
      ])
      .sort(),
    roleScopes: roleScopes.sort(),
    connectors: array(
      await request({
        method: 'GET',
        path: 'connectors',
        expectedStatuses: [200],
        responseKind: 'array',
      })
    )
      .map((value) => [
        Reflect.get(value as Record<string, unknown>, 'id'),
        Reflect.get(value as Record<string, unknown>, 'connectorId'),
      ])
      .sort(),
    experience: await request({
      method: 'GET',
      path: 'sign-in-exp',
      expectedStatuses: [200],
      responseKind: 'object',
    }),
  });
};

export const runManagementProvisioningConvergenceFamily = async (
  input: Readonly<{
    target: TargetConfig;
    request: Phase2AdminRequestFunction;
    environments: readonly [Readonly<Record<string, string>>, Readonly<Record<string, string>>];
    removeOwnedRoleScope(environment: Readonly<Record<string, string>>): Promise<void>;
    observeOwnershipRefusals(): Promise<boolean>;
    fetch?: typeof fetch;
  }>
): Promise<ManagementProvisioningConvergenceProjection> => {
  for (const environment of input.environments) {
    const first = await withManagementProvisioningFamily({
      environment,
      use: async ({ getClientId, getClientSecret }) => ({
        snapshot: await snapshot(input.request),
        id: getClientId(),
        secret: getClientSecret(),
        accepted: await observeClientSecretAuthentication(
          input.target,
          getClientId(),
          getClientSecret(),
          {
            redirectUri: new URL('/api/v1/hosted-auth/callback', input.target.coreUrl).href,
            ...(input.fetch ? { fetch: input.fetch } : {}),
          }
        ),
      }),
    });
    const second = await withManagementProvisioningFamily({
      environment,
      use: async ({ getClientId, getClientSecret }) => ({
        snapshot: await snapshot(input.request),
        id: getClientId(),
        secret: getClientSecret(),
        accepted: await observeClientSecretAuthentication(
          input.target,
          getClientId(),
          getClientSecret(),
          {
            redirectUri: new URL('/api/v1/hosted-auth/callback', input.target.coreUrl).href,
            ...(input.fetch ? { fetch: input.fetch } : {}),
          }
        ),
      }),
    });
    await input.removeOwnedRoleScope(environment);
    const repaired = await withManagementProvisioningFamily({
      environment,
      use: async ({ getClientId, getClientSecret }) => ({
        snapshot: await snapshot(input.request),
        id: getClientId(),
        secret: getClientSecret(),
      }),
    });
    if (
      !first.accepted.accepted ||
      !second.accepted.accepted ||
      first.id !== second.id ||
      first.secret !== second.secret ||
      repaired.id !== first.id ||
      repaired.secret !== first.secret ||
      !isDeepStrictEqual(first.snapshot, second.snapshot) ||
      !isDeepStrictEqual(first.snapshot, repaired.snapshot)
    ) {
      return fail('projection');
    }
  }
  if (!(await input.observeOwnershipRefusals())) {
    return fail('ownership');
  }
  return managementProvisioningConvergenceExpectedProjection;
};
/* eslint-enable no-restricted-syntax, no-await-in-loop, @silverhand/fp/no-mutating-methods, @typescript-eslint/member-ordering, @typescript-eslint/require-array-sort-compare */
