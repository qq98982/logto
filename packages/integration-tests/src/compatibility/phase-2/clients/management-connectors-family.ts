/* eslint-disable no-restricted-syntax -- The parser narrows external JSON records at the transport boundary. */
import type { TargetConfig } from '../../model.js';
import type { Phase2AdminRequestFunction } from '../fixtures.js';

const fail = (): never => {
  throw new TypeError('Invalid Common Management connectors family transport');
};
const record = (value: unknown): Readonly<Record<string, unknown>> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : fail();
const text = (value: unknown, maximum = 256): string =>
  typeof value === 'string' && value.length > 0 && Buffer.byteLength(value) <= maximum
    ? value
    : fail();
const readBoundedText = async (response: Response): Promise<string> => {
  const maximum = 1024 * 1024;
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > maximum)) {
    return fail();
  }
  const value = await response.text();
  return Buffer.byteLength(value) <= maximum ? value : fail();
};
export type ManagementConnectorSnapshot = Readonly<{
  id: string;
  connectorId: string;
  target: string | undefined;
}>;
const connector = (value: unknown): ManagementConnectorSnapshot => {
  const item = record(value);
  if (
    ['clientSecret', 'client_secret', 'secret', 'password', 'privateKey'].some((key) =>
      Object.hasOwn(item, key)
    )
  ) {
    return fail();
  }
  return Object.freeze({
    id: text(item.id),
    connectorId: text(item.connectorId),
    target: item.target === undefined ? undefined : text(item.target),
  });
};

export const readManagementExperience = async (
  request: Phase2AdminRequestFunction
): Promise<Readonly<Record<string, unknown>>> =>
  record(
    await request({
      method: 'GET',
      path: 'sign-in-exp',
      expectedStatuses: [200],
      responseKind: 'object',
    })
  );

export const readManagementConnectorFactoryIds = async (
  target: TargetConfig,
  createHeaders: () => Headers,
  requestFetch: typeof fetch = fetch
): Promise<readonly string[]> => {
  const response = await requestFetch(new URL('/api/connector-factories', target.coreUrl), {
    headers: createHeaders(),
    redirect: 'manual',
    signal: AbortSignal.timeout(10_000),
  });
  const body: unknown = JSON.parse(await readBoundedText(response));
  if (response.status !== 200 || !Array.isArray(body) || body.length === 0 || body.length >= 100) {
    return fail();
  }
  return Object.freeze(
    body.map((value) => {
      const item = record(value);
      return text(item.id ?? item.connectorId);
    })
  );
};

export const readManagementPublicExperience = async (
  target: TargetConfig,
  requestFetch: typeof fetch = fetch
): Promise<Readonly<Record<string, unknown>>> => {
  const response = await requestFetch(new URL('/api/.well-known/sign-in-exp', target.coreUrl), {
    redirect: 'manual',
    signal: AbortSignal.timeout(10_000),
  });
  return response.status === 200 ? record(JSON.parse(await readBoundedText(response))) : fail();
};

export const patchManagementExperience = async (
  request: Phase2AdminRequestFunction,
  body: unknown
): Promise<Readonly<Record<string, unknown>>> =>
  record(
    await request({
      method: 'PATCH',
      path: 'sign-in-exp',
      body,
      expectedStatuses: [200],
      responseKind: 'object',
    })
  );

export const createManagementConnector = async (
  request: Phase2AdminRequestFunction,
  input: Readonly<{ factoryId: string; config: Readonly<Record<string, unknown>> }>,
  captureOwnedId: (id: string) => void
): Promise<ManagementConnectorSnapshot> => {
  const value = await request({
    method: 'POST',
    path: 'connectors',
    body: { connectorId: text(input.factoryId), config: input.config },
    expectedStatuses: [200],
    responseKind: 'object',
  });
  const ownership = record(value);
  const ownedId = text(ownership.id);
  captureOwnedId(ownedId);
  if (ownership.connectorId !== input.factoryId) {
    return fail();
  }
  return connector(value);
};

export const patchManagementConnector = async (
  request: Phase2AdminRequestFunction,
  id: string,
  config: Readonly<Record<string, unknown>>
): Promise<ManagementConnectorSnapshot> =>
  connector(
    await request({
      method: 'PATCH',
      path: `connectors/${encodeURIComponent(text(id))}`,
      body: { config },
      expectedStatuses: [200],
      responseKind: 'object',
    })
  );

export const readManagementConnectors = async (
  request: Phase2AdminRequestFunction
): Promise<readonly ManagementConnectorSnapshot[]> => {
  const value = await request({
    method: 'GET',
    path: 'connectors',
    expectedStatuses: [200],
    responseKind: 'array',
  });
  return Array.isArray(value) && value.length < 100
    ? Object.freeze(value.map((entry) => connector(entry)))
    : fail();
};

export const deleteManagementConnector = async (
  request: Phase2AdminRequestFunction,
  id: string
): Promise<void> => {
  await request({
    method: 'DELETE',
    path: `connectors/${encodeURIComponent(text(id))}`,
    expectedStatuses: [204, 404],
    responseKind: 'status',
  });
};
/* eslint-enable no-restricted-syntax */
