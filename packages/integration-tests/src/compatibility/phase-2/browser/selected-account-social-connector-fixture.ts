/* eslint-disable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The fixture restores each Management surface and provider lease after owned use. */
import { isDeepStrictEqual } from 'node:util';

import type {
  Phase2FixtureFailureOperation,
  Phase2FixtureOperationDiagnostic,
} from '../fixture-operation-diagnostic.js';
import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

import { withSelectedAccountSettingsFixture } from './selected-account-settings-fixture.js';

export type AccountSocialProviderLease = Readonly<{
  associationData: Readonly<Record<string, unknown>>;
  takeAccountCode(): Promise<string>;
  takeForeignAccountCode(): Promise<string>;
  assertAccountProviderCase(): Promise<void>;
  assertSessionProviderCase?(): Promise<void>;
  stop(): Promise<void>;
}>;
const fail = (): never => {
  throw new TypeError('Invalid selected Account social connector fixture');
};
const record = (value: unknown): Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? Object.fromEntries(Object.entries(value))
    : fail();

export const withSelectedAccountSocialConnector = async <Result>(
  input: Readonly<{
    fixture: ProvisionedPhase2Fixture;
    request: Phase2AdminRequestFunction;
    browser: Readonly<{ clientId: string; redirectUri: string }>;
    callbackOrigin: string;
    provider: 'google' | 'wechat';
    connectorConfig: Readonly<Record<string, unknown>>;
    operationDiagnostic?: Phase2FixtureOperationDiagnostic;
    getPassword(): string;
    prepareProvider(connectorId: string): Promise<AccountSocialProviderLease>;
    use(
      value: Readonly<{
        owner: Readonly<{ id: string; primaryEmail: string }>;
        connectorId: string;
        redirectUri: string;
        provider: AccountSocialProviderLease;
      }>
    ): Promise<Result>;
  }>
): Promise<Result> => {
  const runOperation = async <Value>(
    operation: Phase2FixtureFailureOperation,
    use: () => Promise<Value>
  ) => input.operationDiagnostic?.run(operation, use) ?? use();
  const previous = await runOperation('connector-target-select', async () =>
    record(
      await input.request({
        method: 'GET',
        path: 'sign-in-exp',
        expectedStatuses: [200],
        responseKind: 'object',
      })
    )
  );
  const previousTargets = previous.socialSignInConnectorTargets;
  if (
    !Array.isArray(previousTargets) ||
    !previousTargets.every((value) => typeof value === 'string')
  ) {
    input.operationDiagnostic?.record('connector-target-select');
    return fail();
  }
  let connectorId: string | undefined;
  let providerLease: AccountSocialProviderLease | undefined;
  let result: Result | undefined;
  let primary: unknown;
  const cleanup: unknown[] = [];
  try {
    const connector = await runOperation('connector-create', async () =>
      record(
        await input.request({
          method: 'POST',
          path: 'connectors',
          body: {
            connectorId: input.provider === 'google' ? 'google-universal' : 'wechat-web',
            config: input.connectorConfig,
          },
          expectedStatuses: [200, 201],
          responseKind: 'object',
        })
      )
    );
    connectorId = typeof connector.id === 'string' ? connector.id : undefined;
    if (!connectorId) {
      input.operationDiagnostic?.record('connector-create');
      return fail();
    }
    const redirectUri = new URL(
      `/callback/${encodeURIComponent(connectorId)}`,
      input.callbackOrigin
    ).href;
    const activeConnectorId = connectorId;
    providerLease = await runOperation('connector-provider-prepare', async () =>
      input.prepareProvider(activeConnectorId)
    );
    const patched = await runOperation('connector-target-select', async () =>
      record(
        await input.request({
          method: 'PATCH',
          path: 'sign-in-exp',
          body: { socialSignInConnectorTargets: [input.provider] },
          expectedStatuses: [200],
          responseKind: 'object',
        })
      )
    );
    if (!isDeepStrictEqual(patched.socialSignInConnectorTargets, [input.provider])) {
      input.operationDiagnostic?.record('connector-target-select');
      return fail();
    }
    const activeProvider = providerLease;
    result = await runOperation('connector-account-settings', async () =>
      withSelectedAccountSettingsFixture({
        fixture: input.fixture,
        request: input.request,
        browser: { ...input.browser, additionalRedirectUris: [redirectUri] },
        field: 'social',
        getPassword: input.getPassword,
        operationDiagnostic: input.operationDiagnostic,
        use: async ({ identity }) =>
          input.use({
            owner: identity,
            connectorId: activeConnectorId,
            redirectUri,
            provider: activeProvider,
          }),
      })
    );
  } catch (error: unknown) {
    primary = error;
  } finally {
    if (providerLease) {
      try {
        const activeLease = providerLease;
        await runOperation('connector-provider-stop', async () => activeLease.stop());
      } catch (error: unknown) {
        cleanup.push(error);
      }
    }
    try {
      await runOperation('connector-target-restore', async () =>
        input.request({
          method: 'PATCH',
          path: 'sign-in-exp',
          body: {
            socialSignInConnectorTargets: previousTargets,
          },
          expectedStatuses: [200],
          responseKind: 'object',
        })
      );
    } catch (error: unknown) {
      cleanup.push(error);
    }
    if (connectorId) {
      const cleanupConnectorId = connectorId;
      try {
        await runOperation('connector-delete', async () =>
          input.request({
            method: 'DELETE',
            path: `connectors/${encodeURIComponent(cleanupConnectorId)}`,
            expectedStatuses: [204, 404],
            responseKind: 'status',
          })
        );
      } catch (error: unknown) {
        cleanup.push(error);
      }
    }
  }
  if (primary !== undefined || cleanup.length > 0 || result === undefined) {
    throw new AggregateError(
      [...(primary === undefined ? [] : [primary]), ...cleanup],
      'Selected Account social connector fixture failed'
    );
  }
  return result;
};
/* eslint-enable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
