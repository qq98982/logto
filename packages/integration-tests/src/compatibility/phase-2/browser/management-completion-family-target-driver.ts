import type { JSONWebKeySet } from 'jose';

import type { TargetConfig } from '../../model.js';
import { observeManagementCompletionRequest } from '../clients/management-completion-observer.js';
import {
  createBearerPhase2AdminRequest,
  createScopedPhase2Fixture,
  type Phase2AdminRequestFunction,
  type ProvisionedPhase2Fixture,
} from '../fixtures.js';

import {
  runManagementApplicationsSecretsFamily,
  type ManagementApplicationsSecretsProjection,
} from './management-applications-secrets-family.js';
import {
  runManagementConnectorsExperienceFamily,
  type ManagementConnectorsExperienceProjection,
} from './management-connectors-experience-family.js';
import {
  runManagementNativeResourceRoleFamily,
  type ManagementNativeResourceRoleProjection,
} from './management-native-resource-role-family.js';
import {
  runManagementProvisioningConvergenceFamily,
  type ManagementProvisioningConvergenceProjection,
} from './management-provisioning-convergence-family.js';
import {
  runManagementUserSuspendDeleteFamily,
  type ManagementUserSuspendDeleteProjection,
} from './management-user-suspend-delete-family.js';

export const managementCompletionFamilyIds = Object.freeze([
  'common.management.applications-secrets',
  'common.management.native-resource-role',
  'common.management.connectors-experience',
  'common.management.user-suspend-delete',
  'common.management.provisioning-convergence',
] as const);
export type ManagementCompletionFamilyId = (typeof managementCompletionFamilyIds)[number];
export type ManagementCompletionFamilyProjection =
  | ManagementApplicationsSecretsProjection
  | ManagementNativeResourceRoleProjection
  | ManagementConnectorsExperienceProjection
  | ManagementUserSuspendDeleteProjection
  | ManagementProvisioningConvergenceProjection;
export type ManagementProvisioningFixture = Readonly<{
  environments: readonly [Readonly<Record<string, string>>, Readonly<Record<string, string>>];
  removeOwnedRoleScope(environment: Readonly<Record<string, string>>): Promise<void>;
  observeOwnershipRefusals(): Promise<boolean>;
}>;

const fail = (stage: string): never => {
  throw new TypeError(`Invalid Common Management completion target (${stage})`);
};

const runWithRequest = async (
  input: Readonly<{
    id: ManagementCompletionFamilyId;
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    request: Phase2AdminRequestFunction;
    jwks: Readonly<JSONWebKeySet>;
    password: string;
    fetch?: typeof fetch;
    createManagementHeaders(): Headers;
    captureOwnedApplication(id: string): void;
    observeForeignUserPreserved(use: (foreignId: string) => Promise<void>): Promise<boolean>;
    observeForeignConnectorPreserved(use: (foreignId: string) => Promise<void>): Promise<boolean>;
    observeForeignApplicationPreserved(use: (foreignId: string) => Promise<void>): Promise<boolean>;
    withProvisioningFixture<Result>(
      use: (fixture: ManagementProvisioningFixture) => Promise<Result>
    ): Promise<Result>;
  }>
): Promise<ManagementCompletionFamilyProjection> => {
  switch (input.id) {
    case 'common.management.applications-secrets': {
      return runManagementApplicationsSecretsFamily({
        target: input.target,
        request: input.request,
        captureOwnedApplication: input.captureOwnedApplication,
        observeForeignApplicationPreserved: input.observeForeignApplicationPreserved,
        observeMutation: async ({ method, path, body, validAuthorization = true }) =>
          observeManagementCompletionRequest({
            target: input.target,
            createHeaders: validAuthorization
              ? input.createManagementHeaders
              : () => new Headers({ authorization: 'Bearer invalid.phase2.management.bearer' }),
            method,
            path,
            body,
            ...(input.fetch ? { fetch: input.fetch } : {}),
          }),
        ...(input.fetch ? { fetch: input.fetch } : {}),
      });
    }
    case 'common.management.native-resource-role': {
      return runManagementNativeResourceRoleFamily({
        target: input.target,
        fixture: input.fixture,
        request: input.request,
        jwks: input.jwks,
        getPassword: () => input.password,
        observeMutation: async ({ method, path, body }) =>
          observeManagementCompletionRequest({
            target: input.target,
            createHeaders: input.createManagementHeaders,
            method,
            path,
            body,
            ...(input.fetch ? { fetch: input.fetch } : {}),
          }),
        ...(input.fetch ? { fetch: input.fetch } : {}),
      });
    }
    case 'common.management.connectors-experience': {
      return runManagementConnectorsExperienceFamily({
        target: input.target,
        request: input.request,
        observeForeignConnectorPreserved: input.observeForeignConnectorPreserved,
        createManagementHeaders: input.createManagementHeaders,
        observeMutation: async ({ method, path, body, validAuthorization = true }) =>
          observeManagementCompletionRequest({
            target: input.target,
            createHeaders: validAuthorization ? input.createManagementHeaders : () => new Headers(),
            method,
            path,
            body,
            ...(input.fetch ? { fetch: input.fetch } : {}),
          }),
        ...(input.fetch ? { fetch: input.fetch } : {}),
      });
    }
    case 'common.management.user-suspend-delete': {
      return runManagementUserSuspendDeleteFamily({
        target: input.target,
        fixture: input.fixture,
        request: input.request,
        password: input.password,
        observeForeignPreserved: input.observeForeignUserPreserved,
        ...(input.fetch ? { fetch: input.fetch } : {}),
      });
    }
    case 'common.management.provisioning-convergence': {
      return input.withProvisioningFixture(async (provisioning: ManagementProvisioningFixture) =>
        runManagementProvisioningConvergenceFamily({
          target: input.target,
          request: input.request,
          environments: provisioning.environments,
          removeOwnedRoleScope: provisioning.removeOwnedRoleScope,
          observeOwnershipRefusals: provisioning.observeOwnershipRefusals,
          ...(input.fetch ? { fetch: input.fetch } : {}),
        })
      );
    }
  }
};

export const runManagementCompletionFamilyForTarget = async (
  input: Readonly<{
    id: ManagementCompletionFamilyId;
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    signal: AbortSignal;
    jwks: Readonly<JSONWebKeySet>;
    fetch?: typeof fetch;
    withManagementBearer<Result>(use: (bearer: string) => Promise<Result>): Promise<Result>;
    captureOwnedApplication(id: string): void;
    observeForeignUserPreserved(use: (foreignId: string) => Promise<void>): Promise<boolean>;
    observeForeignConnectorPreserved(use: (foreignId: string) => Promise<void>): Promise<boolean>;
    observeForeignApplicationPreserved(use: (foreignId: string) => Promise<void>): Promise<boolean>;
    withProvisioningFixture<Result>(
      bearer: string,
      use: (fixture: ManagementProvisioningFixture) => Promise<Result>
    ): Promise<Result>;
  }>
): Promise<ManagementCompletionFamilyProjection> => {
  if (!input.fixture.status || input.signal.aborted) {
    return fail('admission');
  }
  const requestFetch = input.fetch ?? fetch;
  return input.fixture.withSecretLease<ManagementCompletionFamilyProjection>(async (lease) => {
    const scope = createScopedPhase2Fixture(input.fixture, lease);
    try {
      return await input.withManagementBearer<ManagementCompletionFamilyProjection>(
        async (bearer: string) =>
          runWithRequest({
            ...input,
            fixture: scope.fixture,
            request: createBearerPhase2AdminRequest(input.target, bearer, requestFetch),
            password: lease.getSubjectPassword?.() ?? fail('password'),
            createManagementHeaders: () => new Headers({ authorization: `Bearer ${bearer}` }),
            fetch: requestFetch,
            withProvisioningFixture: async (use) => input.withProvisioningFixture(bearer, use),
          })
      );
    } finally {
      scope.revoke();
    }
  });
};
