import type { JSONWebKeySet } from 'jose';

import type { TargetConfig } from '../../model.js';
import { withPhase2AdminManagementBearer } from '../clients/admin-management-bearer.js';
import { createManagementUserMutationObserver } from '../clients/management-users.js';
import {
  createBearerPhase2AdminRequest,
  createReferencePhase2AdminRequest,
  type ProvisionedPhase2Fixture,
} from '../fixtures.js';

import {
  runCommonManagementUserContactUpdate,
  runCommonManagementUserCreate,
  type CommonManagementUserContactUpdateProjection,
  type CommonManagementUserCreateProjection,
} from './common-management-users.js';
import { withSelectedAccountSettingsFixture } from './selected-account-settings-fixture.js';

const fail = (stage: string): never => {
  throw new TypeError(`Invalid Common Management user target (${stage})`);
};
const flowStagePattern = /^Invalid Common Management user flow \(([a-z0-9_-]+)\)$/u;
export const closedCommonManagementUserFlowStage = (error: unknown): string | undefined =>
  error instanceof Error ? flowStagePattern.exec(error.message)?.[1] : undefined;
export type CommonManagementUserKind = 'user-create' | 'user-contact-update';
export const withAdditionalDefaultManagementRole = async <Result>(
  request: ReturnType<typeof createReferencePhase2AdminRequest>,
  allocationId: string,
  use: () => Promise<Result>
): Promise<Result> => {
  const role: unknown = await request({
    method: 'POST',
    path: 'roles',
    body: {
      name: `common-management-default-${allocationId}`,
      description: 'Common Management default user membership',
      type: 'User',
      isDefault: true,
    },
    expectedStatuses: [200],
    responseKind: 'object',
  });
  if (typeof role !== 'object' || role === null || Array.isArray(role)) {
    return fail('default-role');
  }
  const id: unknown = Reflect.get(role, 'id');
  const roleId = typeof id === 'string' && id.length > 0 ? id : fail('default-role');
  if (Reflect.get(role, 'name') !== `common-management-default-${allocationId}`) {
    return fail('default-role');
  }
  try {
    if (Reflect.get(role, 'type') !== 'User' || Reflect.get(role, 'isDefault') !== true) {
      return fail('default-role');
    }
    return await use();
  } finally {
    await request({
      method: 'DELETE',
      path: `roles/${encodeURIComponent(roleId)}`,
      expectedStatuses: [204, 404],
      responseKind: 'status',
    });
  }
};
export const runCommonManagementUserForTarget = async (
  input: Readonly<{
    kind: CommonManagementUserKind;
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    signal: AbortSignal;
    jwks: Readonly<JSONWebKeySet>;
    fetch?: typeof fetch;
  }>
): Promise<CommonManagementUserCreateProjection | CommonManagementUserContactUpdateProjection> => {
  if (!input.fixture.status || input.signal.aborted) {
    return fail('admission');
  }
  const requestFetch = input.fetch ?? fetch;
  const execute = async (
    request: ReturnType<typeof createReferencePhase2AdminRequest>,
    createHeaders: () => Headers,
    password: string
  ) =>
    withAdditionalDefaultManagementRole(request, input.fixture.public.allocationId, async () =>
      withSelectedAccountSettingsFixture({
        fixture: input.fixture,
        request,
        browser: {
          clientId: input.fixture.status?.client.id ?? fail('client'),
          redirectUri: input.fixture.status?.client.redirectUri ?? fail('redirect'),
        },
        field: 'email',
        additionalReadOnlyFields: ['phone'],
        resourceRoleIsDefault: true,
        getPassword: () => password,
        use: async () => {
          const observeMutation = createManagementUserMutationObserver(
            input.target,
            createHeaders,
            requestFetch
          );
          const observeUnauthorizedMutation = createManagementUserMutationObserver(
            input.target,
            () => new Headers({ authorization: 'Bearer invalid.phase2.management.bearer' }),
            requestFetch
          );
          try {
            return input.kind === 'user-create'
              ? await runCommonManagementUserCreate({
                  target: input.target,
                  fixture: input.fixture,
                  request,
                  observeMutation,
                  observeUnauthorizedMutation,
                  password,
                  jwks: input.jwks,
                  fetch: requestFetch,
                })
              : await runCommonManagementUserContactUpdate({
                  target: input.target,
                  fixture: input.fixture,
                  request,
                  observeMutation,
                  observeUnauthorizedMutation,
                  password,
                  jwks: input.jwks,
                  fetch: requestFetch,
                });
          } catch (error: unknown) {
            const stage = closedCommonManagementUserFlowStage(error);
            return fail(
              stage ??
                (input.kind === 'user-create' ? 'user-create-flow' : 'user-contact-update-flow')
            );
          }
        },
      })
    );
  if (input.target.label === 'candidate') {
    return withPhase2AdminManagementBearer(
      input.target,
      input.fixture,
      async (bearer, lease) =>
        execute(
          createBearerPhase2AdminRequest(input.target, bearer, requestFetch),
          () => new Headers({ authorization: `Bearer ${bearer}` }),
          lease.getSubjectPassword?.() ?? fail('password')
        ),
      { fetch: requestFetch }
    );
  }
  return input.fixture.withSecretLease(async (lease) =>
    execute(
      createReferencePhase2AdminRequest(input.target, requestFetch),
      () => new Headers({ 'development-user-id': 'integration-test-admin-user' }),
      lease.getSubjectPassword?.() ?? fail('password')
    )
  );
};
