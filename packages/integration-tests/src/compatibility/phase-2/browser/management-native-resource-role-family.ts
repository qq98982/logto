/* eslint-disable complexity, no-await-in-loop, @typescript-eslint/member-ordering, @typescript-eslint/no-unnecessary-condition -- Closed projection checks intentionally restate the selected fixture and public-flow contracts. */
import { isDeepStrictEqual } from 'node:util';

import type { JSONWebKeySet } from 'jose';

import type { TargetConfig } from '../../model.js';
import type { ManagementCompletionObservation } from '../clients/management-completion-observer.js';
import {
  readDefaultManagementUserRoleIds,
  readManagementUserRoles,
} from '../clients/management-users.js';
import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';
import { observeCommonNativeCodePkce } from '../scenarios/common-native.js';
import { withSelectedNativeFixture } from '../selected-native-fixture.js';

export const managementNativeResourceRoleFamilyId = 'common.management.native-resource-role';
export type ManagementNativeResourceRoleProjection = Readonly<{
  nativeStable: true;
  provisioningOrdersAccepted: true;
  resourceTtl300: true;
  sessionExchangeBound: true;
  everyDefaultRoleAssigned: true;
  duplicateResourceRejected: true;
  duplicateScopeRejected: true;
  duplicateRoleScopeRejected: true;
  codeS256Accepted: true;
  resourceClaimsVerified: true;
  resourceRefreshRotated: true;
  ordinaryAccessOpaque: true;
  ordinaryProfilePreserved: true;
  deviceFlowRejected: true;
  targetOwnedCleanup: true;
}>;
export const managementNativeResourceRoleExpectedProjection: ManagementNativeResourceRoleProjection =
  Object.freeze({
    nativeStable: true,
    provisioningOrdersAccepted: true,
    resourceTtl300: true,
    sessionExchangeBound: true,
    everyDefaultRoleAssigned: true,
    duplicateResourceRejected: true,
    duplicateScopeRejected: true,
    duplicateRoleScopeRejected: true,
    codeS256Accepted: true,
    resourceClaimsVerified: true,
    resourceRefreshRotated: true,
    ordinaryAccessOpaque: true,
    ordinaryProfilePreserved: true,
    deviceFlowRejected: true,
    targetOwnedCleanup: true,
  });
const fail = (stage: string): never => {
  throw new TypeError(`Invalid Common Management native resource family (${stage})`);
};
export type ManagementNativeProvisioningOrder = 'application-first' | 'resource-first';
const exactObservation = (
  value: ManagementCompletionObservation,
  status: number,
  code: string
): boolean => value.status === status && value.code === code;
const observeDeviceIneligible = async (
  target: TargetConfig,
  clientId: string,
  requestFetch: typeof fetch
): Promise<boolean> => {
  const response = await requestFetch(new URL('/oidc/device/auth', target.coreUrl), {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: clientId, scope: 'openid' }),
    redirect: 'manual',
    signal: AbortSignal.timeout(10_000),
  });
  const text = await response.text();
  if (response.status !== 400 || Buffer.byteLength(text) > 4096) {
    return false;
  }
  try {
    const value: unknown = JSON.parse(text);
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      return false;
    }
    const keys = Reflect.ownKeys(value);
    const description: unknown = Reflect.get(value, 'error_description');
    return (
      keys.every(
        (key) =>
          typeof key === 'string' && ['code', 'error', 'error_description', 'message'].includes(key)
      ) &&
      Reflect.get(value, 'error') === 'invalid_request' &&
      typeof description === 'string' &&
      description.length > 0 &&
      Buffer.byteLength(description) <= 256
    );
  } catch {
    return false;
  }
};

export const runManagementNativeResourceRoleFamily = async (
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    request: Phase2AdminRequestFunction;
    jwks: Readonly<JSONWebKeySet>;
    getPassword(): string;
    observeMutation(
      input: Readonly<{ method: 'POST'; path: string; body: unknown }>
    ): Promise<ManagementCompletionObservation>;
    fetch?: typeof fetch;
  }>
): Promise<ManagementNativeResourceRoleProjection> => {
  for (const order of ['application-first', 'resource-first'] as const) {
    await withSelectedNativeFixture(
      input.fixture,
      {
        request: input.request,
        target: input.target,
        provisioningOrder: order,
        namespace: `management-${order}`,
        getSelectedNativePassword: input.getPassword,
      },
      async (fixture) => {
        const selected = fixture.public.selectedNative;
        const defaults = await readDefaultManagementUserRoleIds(input.request);
        const roles = await readManagementUserRoles(input.request, selected.identity.id);
        if (
          selected.applicationType !== 'Native' ||
          selected.resource.accessTokenTtl !== 300 ||
          selected.resource.scope.name !== 'session:exchange' ||
          !isDeepStrictEqual(
            roles
              .filter(({ isDefault }) => isDefault)
              .map(({ id }) => id)
              .slice()
              .sort(),
            defaults
          )
        ) {
          return fail('setup');
        }
        const duplicateResource = await input.observeMutation({
          method: 'POST',
          path: 'resources',
          body: {
            name: `Duplicate ${order}`,
            indicator: selected.resource.indicator,
            accessTokenTtl: 300,
          },
        });
        const duplicateScope = await input.observeMutation({
          method: 'POST',
          path: `resources/${encodeURIComponent(selected.resource.id)}/scopes`,
          body: { name: selected.resource.scope.name, description: `Duplicate ${order}` },
        });
        const duplicateRoleScope = await input.observeMutation({
          method: 'POST',
          path: `roles/${encodeURIComponent(selected.defaultUserRoleId)}/scopes`,
          body: { scopeIds: [selected.resource.scope.id] },
        });
        if (
          !exactObservation(duplicateResource, 422, 'resource.resource_identifier_in_use') ||
          !exactObservation(duplicateScope, 422, 'scope.name_exists') ||
          !exactObservation(duplicateRoleScope, 422, 'role.scope_exists')
        ) {
          return fail('duplicate-controls');
        }
        const native = await observeCommonNativeCodePkce({
          target: input.target,
          fixture,
          jwks: input.jwks,
          getSelectedNativePassword: input.getPassword,
          ...(input.fetch ? { requestFetch: input.fetch } : {}),
        });
        if (
          native.pkce !== 'S256' ||
          native.resourceToken !== 'jwt' ||
          native.resourceRefresh !== 'jwt' ||
          native.profileToken !== 'opaque' ||
          native.resourceTtlSeconds !== 300 ||
          native.resourceRefreshTtlSeconds !== 300 ||
          !native.profileSubject ||
          !native.expectedSubject
        ) {
          return fail('public-flow');
        }
        if (
          !(await observeDeviceIneligible(input.target, selected.clientId, input.fetch ?? fetch))
        ) {
          return fail('device-ineligible');
        }
      }
    );
  }
  return managementNativeResourceRoleExpectedProjection;
};
/* eslint-enable complexity, no-await-in-loop, @typescript-eslint/member-ordering, @typescript-eslint/no-unnecessary-condition */
