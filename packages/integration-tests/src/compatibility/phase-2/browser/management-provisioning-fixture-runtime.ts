/* eslint-disable complexity, max-lines, no-await-in-loop, no-restricted-syntax, unicorn/no-array-callback-reference, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- The bounded lease serializes dependency cleanup and retains a body error until restoration completes. */
import { isDeepStrictEqual } from 'node:util';

import type { TargetConfig } from '../../model.js';
import { observeManagementProvisioningClientRefusal } from '../clients/management-provisioning-family.js';
import type { ForeignManagementControls, Phase2AdminRequestFunction } from '../fixtures.js';

import type { ManagementProvisioningFixture } from './management-completion-family-target-driver.js';

const fail = (): never => {
  throw new TypeError('Invalid Management provisioning fixture runtime');
};
const array = (value: unknown): unknown[] =>
  Array.isArray(value) && value.length < 100 ? value.map((entry: unknown) => entry) : fail();
const field = (value: unknown, key: string): unknown =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? Object.getOwnPropertyDescriptor(value, key)?.value
    : fail();

export type ManagementProvisioningRuntimeInput = Readonly<{
  target: TargetConfig;
  bearer: string;
  request: Phase2AdminRequestFunction;
  globalEnvironment: Readonly<Record<string, string>>;
  chinaNativeEnvironment: Readonly<Record<string, string>>;
  withForeignManagementControls<Result>(
    use: (controls: ForeignManagementControls) => Promise<Result>
  ): Promise<Result>;
  cleanupProvisioningRows(
    rows: Readonly<{
      resourceId: string;
      applicationIds: readonly [string, string];
    }>
  ): Promise<void>;
  cleanupOwnershipControlApplication?(applicationId: string): Promise<void>;
  removeProvisioningRoleScope?(ids: Readonly<{ roleId: string; scopeId: string }>): Promise<void>;
}>;
const environment = (
  input: ManagementProvisioningRuntimeInput,
  market: 'global' | 'cn',
  values: Readonly<Record<string, string>>
) =>
  Object.freeze({
    ...values,
    PATH: '/usr/bin:/bin',
    BOX_AI_MARKET: market,
    BOX_AI_LOGTO_BOOTSTRAP_ENDPOINT: input.target.coreUrl,
    BOX_AI_LOGTO_ENDPOINT: input.target.coreUrl,
    BOX_AI_PUBLIC_BASE_URL: input.target.coreUrl,
    BOX_AI_LOGTO_MANAGEMENT_TOKEN: input.bearer,
  });
const removeNativeRelation = async (input: ManagementProvisioningRuntimeInput): Promise<void> => {
  const { request } = input;
  const roles = array(
    await request({
      method: 'GET',
      path: 'roles',
      query: { page: '1', page_size: '100' },
      expectedStatuses: [200],
      responseKind: 'array',
    })
  ).filter((role) => field(role, 'name') === 'Box-AI Native Session User');
  const roleId = roles.length === 1 ? field(roles[0], 'id') : undefined;
  if (typeof roleId !== 'string') {
    return fail();
  }
  const scopes = array(
    await request({
      method: 'GET',
      path: `roles/${encodeURIComponent(roleId)}/scopes`,
      expectedStatuses: [200],
      responseKind: 'array',
    })
  ).filter((scope) => field(scope, 'name') === 'session:exchange');
  const scopeId = scopes.length === 1 ? field(scopes[0], 'id') : undefined;
  if (typeof scopeId !== 'string') {
    return fail();
  }
  await (input.removeProvisioningRoleScope ?? fail())({ roleId, scopeId });
};
const exactNotFound = (value: unknown): boolean =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  Object.keys(value).length > 0 &&
  Object.keys(value).length <= 8 &&
  field(value, 'code') === 'entity.not_found';

export const createManagementOwnershipRefusalObserver =
  (
    request: Phase2AdminRequestFunction,
    refusalEnvironment: Readonly<Record<string, string>>,
    withForeignManagementControls: ManagementProvisioningRuntimeInput['withForeignManagementControls'],
    observeClientRefusal: (
      environment: Readonly<Record<string, string>>
    ) => Promise<boolean> = observeManagementProvisioningClientRefusal,
    cleanupOwnershipControlApplication?: ManagementProvisioningRuntimeInput['cleanupOwnershipControlApplication']
  ): (() => Promise<boolean>) =>
  async () => {
    const previousExperience = record(
      await request({
        method: 'GET',
        path: 'sign-in-exp',
        expectedStatuses: [200],
        responseKind: 'object',
      })
    );
    const created = record(
      await request({
        method: 'POST',
        path: 'applications',
        body: {
          name: 'Box-AI',
          description: 'Foreign owner retained by compatibility fixture',
          type: 'Traditional',
          isThirdParty: false,
          oidcClientMetadata: { redirectUris: [], postLogoutRedirectUris: [] },
        },
        expectedStatuses: [200],
        responseKind: 'object',
      })
    );
    const applicationId = rowId(created);
    let rejected = false;
    let preserved = false;
    let bodyError: unknown;
    try {
      rejected = await observeClientRefusal(refusalEnvironment);
      const [application, experience] = await Promise.all([
        request({
          method: 'GET',
          path: `applications/${encodeURIComponent(applicationId)}`,
          expectedStatuses: [200],
          responseKind: 'object',
        }),
        request({
          method: 'GET',
          path: 'sign-in-exp',
          expectedStatuses: [200],
          responseKind: 'object',
        }),
      ]);
      const retained = record(application);
      preserved =
        field(retained, 'id') === applicationId &&
        field(retained, 'name') === 'Box-AI' &&
        field(retained, 'description') === 'Foreign owner retained by compatibility fixture' &&
        isDeepStrictEqual(record(experience), previousExperience);
    } catch (error: unknown) {
      bodyError = error;
    }
    try {
      await (cleanupOwnershipControlApplication ?? fail())(applicationId);
    } catch {
      return fail();
    }
    if (bodyError !== undefined) {
      return fail();
    }
    let tenantDenied = false;
    await withForeignManagementControls(async ({ userId, connectorId }) => {
      const [user, connector] = await Promise.all([
        request({
          method: 'DELETE',
          path: `users/${encodeURIComponent(userId)}`,
          expectedStatuses: [404],
          responseKind: 'object',
        }),
        request({
          method: 'DELETE',
          path: `connectors/${encodeURIComponent(connectorId)}`,
          expectedStatuses: [404],
          responseKind: 'object',
        }),
      ]);
      tenantDenied = exactNotFound(user) && exactNotFound(connector);
    });
    return rejected && preserved && tenantDenied;
  };

const catalogPaths = Object.freeze(['roles', 'resources', 'applications', 'connectors'] as const);
type ProvisioningCatalog = Readonly<{
  rows: Readonly<Record<(typeof catalogPaths)[number], ReadonlyArray<Record<string, unknown>>>>;
  experience: Readonly<Record<string, unknown>>;
}>;
const record = (value: unknown): Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? Object.fromEntries(Object.keys(value).map((key) => [key, field(value, key)]))
    : fail();
const readCatalog = async (request: Phase2AdminRequestFunction): Promise<ProvisioningCatalog> => {
  const entries = await Promise.all(
    catalogPaths.map(async (path) => {
      const listed = array(
        await request({
          method: 'GET',
          path,
          ...(path === 'roles' && { query: { page: '1', page_size: '100' } }),
          ...(path === 'resources' && { query: { includeScopes: 'true' } }),
          expectedStatuses: [200],
          responseKind: 'array',
        })
      ).map(record);
      const rows =
        path === 'connectors'
          ? await Promise.all(
              listed.map(async (connector) =>
                record(
                  await request({
                    method: 'GET',
                    path: `connectors/${encodeURIComponent(rowId(connector))}`,
                    expectedStatuses: [200],
                    responseKind: 'object',
                  })
                )
              )
            )
          : listed;
      return [path, rows] as const;
    })
  );
  const rows = Object.fromEntries(entries);
  return Object.freeze({
    rows: Object.freeze({
      roles: rows.roles ?? fail(),
      resources: rows.resources ?? fail(),
      applications: rows.applications ?? fail(),
      connectors: rows.connectors ?? fail(),
    }),
    experience: Object.freeze(
      record(
        await request({
          method: 'GET',
          path: 'sign-in-exp',
          expectedStatuses: [200],
          responseKind: 'object',
        })
      )
    ),
  });
};
const assertEmptyManagedNamespace = (
  catalog: ProvisioningCatalog,
  input: ManagementProvisioningRuntimeInput
): void => {
  const managedNames = new Set([
    'Box-AI',
    'Box-AI Native',
    'Box-AI Native Session API',
    'Box-AI Native Session User',
  ]);
  const managedDescriptions = new Set([
    'Managed by the Box-AI deployment',
    'Managed by the Box-AI deployment as a native public client',
    'Managed by the Box-AI deployment for native session exchange',
  ]);
  const nativeResourceIndicator = new URL('/api', input.target.coreUrl).href;
  const provisionsNativeResource = (input.chinaNativeEnvironment.BOX_AI_WECHAT_CHANNELS ?? '')
    .split(',')
    .map((channel) => channel.trim())
    .includes('native');
  const managedFactories = new Set([
    ...(input.globalEnvironment.BOX_AI_GOOGLE_CLIENT_ID ? ['google-universal'] : []),
    ...(input.globalEnvironment.BOX_AI_SMTP_HOST ? ['simple-mail-transfer-protocol'] : []),
    ...(input.chinaNativeEnvironment.BOX_AI_SMS_ACCESS_KEY_ID
      ? [
          input.chinaNativeEnvironment.BOX_AI_SMS_CONNECTOR_FACTORY_ID ??
            'aliyun-short-message-service',
        ]
      : []),
    ...(input.chinaNativeEnvironment.BOX_AI_WECHAT_CHANNELS ?? '')
      .split(',')
      .map((channel) => channel.trim())
      .filter(Boolean)
      .map((channel) => `wechat-${channel}`),
  ]);
  const occupied = catalogPaths.some((path) =>
    catalog.rows[path].some((row) => {
      const name = field(row, 'name');
      const description = field(row, 'description');
      const indicator = field(row, 'indicator');
      const connectorId = field(row, 'connectorId');
      const scopes = field(row, 'scopes');
      return (
        (typeof name === 'string' && managedNames.has(name)) ||
        (typeof description === 'string' && managedDescriptions.has(description)) ||
        (provisionsNativeResource && indicator === nativeResourceIndicator) ||
        (typeof connectorId === 'string' && managedFactories.has(connectorId)) ||
        (Array.isArray(scopes) &&
          scopes.some((scope) => field(scope, 'name') === 'session:exchange'))
      );
    })
  );
  if (occupied) {
    return fail();
  }
};
const rowId = (value: Record<string, unknown>): string => {
  const id = field(value, 'id');
  return typeof id === 'string' && id.length > 0 && id.length <= 128 ? id : fail();
};
const restoreProvisioningCatalog = async (
  input: ManagementProvisioningRuntimeInput,
  request: Phase2AdminRequestFunction,
  before: ProvisioningCatalog
): Promise<void> => {
  const after = await readCatalog(request);
  let failures: unknown[] = [];
  const attempt = async (operation: () => Promise<unknown>): Promise<void> => {
    try {
      await operation();
    } catch (error: unknown) {
      failures = [...failures, error];
    }
  };
  for (const path of ['roles', 'connectors'] as const) {
    const beforeIds = new Set(before.rows[path].map(rowId));
    for (const id of after.rows[path].map(rowId).filter((id) => !beforeIds.has(id))) {
      await attempt(async () =>
        request({
          method: 'DELETE',
          path: `${path}/${encodeURIComponent(id)}`,
          expectedStatuses: [204, 404],
          responseKind: 'status',
        })
      );
    }
  }
  const applicationBeforeIds = new Set(before.rows.applications.map(rowId));
  const applications = after.rows.applications.filter(
    (row) => !applicationBeforeIds.has(rowId(row))
  );
  const resourceBeforeIds = new Set(before.rows.resources.map(rowId));
  const resources = after.rows.resources.filter((row) => !resourceBeforeIds.has(rowId(row)));
  const applicationsMatch =
    applications.length === 2 &&
    new Set(applications.map((row) => field(row, 'name'))).size === 2 &&
    applications.every(
      (row) =>
        (field(row, 'name') === 'Box-AI' &&
          field(row, 'description') === 'Managed by the Box-AI deployment' &&
          field(row, 'type') === 'Traditional') ||
        (field(row, 'name') === 'Box-AI Native' &&
          field(row, 'description') ===
            'Managed by the Box-AI deployment as a native public client' &&
          field(row, 'type') === 'Native')
    );
  const resource = resources.length === 1 ? resources[0] : undefined;
  const scopes = resource === undefined ? undefined : field(resource, 'scopes');
  const resourceMatches =
    resource !== undefined &&
    field(resource, 'name') === 'Box-AI Native Session API' &&
    field(resource, 'indicator') === new URL('/api', input.target.coreUrl).href &&
    field(resource, 'accessTokenTtl') === 300 &&
    Array.isArray(scopes) &&
    scopes.length === 1 &&
    field(scopes[0], 'name') === 'session:exchange' &&
    field(scopes[0], 'description') ===
      'Managed by the Box-AI deployment for native session exchange';
  if (!applicationsMatch || !resourceMatches) {
    failures = [...failures, new TypeError('Invalid Management provisioning owned rows')];
  } else {
    await attempt(async () =>
      input.cleanupProvisioningRows({
        resourceId: rowId(resource),
        applicationIds: applications.map(rowId).toSorted() as [string, string],
      })
    );
  }
  const experienceKeys = [
    'branding',
    'color',
    'customContent',
    'languageInfo',
    'passwordPolicy',
    'signIn',
    'signUp',
    'socialSignIn',
    'socialSignInConnectorTargets',
    'forgotPasswordMethods',
  ];
  const body = Object.fromEntries(
    experienceKeys.flatMap((key) =>
      Object.hasOwn(before.experience, key) ? [[key, field(before.experience, key)]] : []
    )
  );
  await attempt(async () =>
    request({
      method: 'PATCH',
      path: 'sign-in-exp',
      body,
      expectedStatuses: [200],
      responseKind: 'object',
    })
  );
  let restored: ProvisioningCatalog | undefined;
  await attempt(async () => {
    restored = await readCatalog(request);
  });
  const idsMatch = restored
    ? catalogPaths.every((path) =>
        isDeepStrictEqual(
          restored?.rows[path].map((row) => rowId(row)),
          before.rows[path].map((row) => rowId(row))
        )
      )
    : false;
  const connectorConfigsMatch = restored
    ? before.rows.connectors.every((connector) => {
        const current = restored?.rows.connectors.find((row) => rowId(row) === rowId(connector));
        return current && isDeepStrictEqual(field(current, 'config'), field(connector, 'config'));
      })
    : false;
  if (
    failures.length > 0 ||
    !idsMatch ||
    !connectorConfigsMatch ||
    !restored ||
    !isDeepStrictEqual(restored.experience, before.experience)
  ) {
    throw new AggregateError(failures, 'Invalid Management provisioning fixture cleanup');
  }
};
export const createManagementProvisioningFixtureRuntime = (
  input: ManagementProvisioningRuntimeInput
): ManagementProvisioningFixture => {
  const global = environment(input, 'global', input.globalEnvironment);
  const china = environment(input, 'cn', input.chinaNativeEnvironment);
  const environments: ManagementProvisioningFixture['environments'] = [global, china];
  return Object.freeze({
    environments,
    removeOwnedRoleScope: async (selected: Readonly<Record<string, string>>) => {
      if (selected.BOX_AI_MARKET === 'global') {
        return;
      }
      if (selected !== china) {
        return fail();
      }
      await removeNativeRelation(input);
    },
    observeOwnershipRefusals: createManagementOwnershipRefusalObserver(
      input.request,
      global,
      input.withForeignManagementControls,
      observeManagementProvisioningClientRefusal,
      input.cleanupOwnershipControlApplication
    ),
  });
};

export const withManagementProvisioningFixtureRuntime = async <Result>(
  input: ManagementProvisioningRuntimeInput,
  use: (fixture: ManagementProvisioningFixture) => Promise<Result>
): Promise<Result> => {
  const before = await readCatalog(input.request);
  assertEmptyManagedNamespace(before, input);
  let bodyError: unknown;
  let value: Result | undefined;
  try {
    value = await use(createManagementProvisioningFixtureRuntime(input));
  } catch (error: unknown) {
    bodyError = error;
  }
  try {
    await restoreProvisioningCatalog(input, input.request, before);
  } catch (cleanupError: unknown) {
    throw new AggregateError(
      [...(bodyError === undefined ? [] : [bodyError]), cleanupError],
      'Invalid Management provisioning fixture cleanup'
    );
  }
  if (bodyError !== undefined) {
    throw bodyError instanceof Error
      ? bodyError
      : new TypeError('Invalid Management provisioning fixture body', { cause: bodyError });
  }
  return value as Result;
};
/* eslint-enable complexity, max-lines, no-await-in-loop, no-restricted-syntax, unicorn/no-array-callback-reference, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
