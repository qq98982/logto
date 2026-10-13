/* eslint-disable complexity, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- Exact application metadata is compensated around one password-core row. */
import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

const fail = (stage: string): never => {
  throw new TypeError(`Selected password core application fixture failed: ${stage}`);
};
const record = (value: unknown): Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? Object.fromEntries(Object.entries(value))
    : fail('application');
const jsonValue = (value: unknown): unknown => {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((entry) => jsonValue(entry));
  }
  if (typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value)
        .slice()
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, entry]) => [key, jsonValue(entry)])
    );
  }
  return fail('metadata-json');
};
const sameJson = (left: unknown, right: unknown): boolean =>
  JSON.stringify(jsonValue(left)) === JSON.stringify(jsonValue(right));

export const withSelectedPasswordCoreApplication = async <Result>(
  input: Readonly<{
    fixture: ProvisionedPhase2Fixture;
    request: Phase2AdminRequestFunction;
    redirectUri: string;
    use(fixture: ProvisionedPhase2Fixture): Promise<Result>;
  }>
): Promise<Result> => {
  const status = input.fixture.status ?? fail('status');
  const clientId = status.client.id;
  if (!/^https:\/\/localhost:\d+\/demo-app$/u.test(input.redirectUri)) {
    return fail('redirect');
  }
  const path = `applications/${encodeURIComponent(clientId)}`;
  const application = record(
    await input.request({ method: 'GET', path, expectedStatuses: [200], responseKind: 'object' })
  );
  const metadata = record(application.oidcClientMetadata);
  const redirects = metadata.redirectUris;
  if (
    application.id !== clientId ||
    application.type !== 'SPA' ||
    !Array.isArray(redirects) ||
    !redirects.every((value) => typeof value === 'string')
  ) {
    return fail('read');
  }
  const previous = structuredClone(metadata);
  const selected = {
    ...previous,
    redirectUris: [...new Set([input.redirectUri, ...redirects])],
  };
  let result: Result | undefined;
  let bodyError: unknown;
  let cleanupError: unknown;
  try {
    const patched = record(
      await input.request({
        method: 'PATCH',
        path,
        body: { oidcClientMetadata: selected },
        expectedStatuses: [200],
        responseKind: 'object',
      })
    );
    const read = record(
      await input.request({
        method: 'GET',
        path,
        expectedStatuses: [200],
        responseKind: 'object',
      })
    );
    if (
      !sameJson(patched.oidcClientMetadata, selected) ||
      !sameJson(read.oidcClientMetadata, selected)
    ) {
      return fail('selection-readback');
    }
    result = await input.use(
      Object.freeze({
        ...input.fixture,
        status: Object.freeze({
          ...status,
          client: Object.freeze({ ...status.client, redirectUri: input.redirectUri }),
        }),
      })
    );
  } catch (error: unknown) {
    bodyError = error;
  } finally {
    try {
      const restored = record(
        await input.request({
          method: 'PATCH',
          path,
          body: { oidcClientMetadata: previous },
          expectedStatuses: [200],
          responseKind: 'object',
        })
      );
      const read = record(
        await input.request({
          method: 'GET',
          path,
          expectedStatuses: [200],
          responseKind: 'object',
        })
      );
      if (
        !sameJson(restored.oidcClientMetadata, previous) ||
        !sameJson(read.oidcClientMetadata, previous)
      ) {
        fail('restore-readback');
      }
    } catch (error: unknown) {
      cleanupError = error;
    }
  }
  if (bodyError && cleanupError) {
    throw new AggregateError(
      [bodyError, cleanupError],
      'Selected password core application cleanup failed'
    );
  }
  if (cleanupError) {
    throw cleanupError instanceof Error
      ? cleanupError
      : new TypeError('Selected password core application cleanup failed');
  }
  if (bodyError) {
    throw bodyError instanceof Error
      ? bodyError
      : new TypeError('Selected password core application body failed');
  }
  return result as Result;
};
/* eslint-enable complexity, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
