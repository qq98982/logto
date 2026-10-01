/* eslint-disable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, no-restricted-syntax, @typescript-eslint/member-ordering -- Bounded response and receipt validation are confined to this capability adapter. */
import { types as nodeTypes } from 'node:util';

import type {
  CustomJwtFetchReceipt,
  CustomJwtFetchTargetPort,
  CustomJwtHttpResponse,
  CustomJwtScenarioId,
  CustomJwtTargetPort,
} from '../scenarios/custom-jwt.js';

type M2MCaseId = Extract<CustomJwtScenarioId, `custom-jwt.m2m-${string}`>;

export type CustomJwtHttpCapabilities = Readonly<{
  assertInvocationFence(): Promise<void>;
  managementRequest(
    input: Readonly<{
      method: 'GET' | 'PUT' | 'PATCH' | 'POST' | 'DELETE';
      path: string;
      body?: unknown;
      signal: AbortSignal;
    }>
  ): Promise<CustomJwtHttpResponse>;
  withM2MSecret<Result>(use: (secret: string) => Promise<Result>): Promise<Result>;
  issueClientCredentials(
    input: Readonly<{
      caseId: M2MCaseId;
      clientSecret: string;
      signal: AbortSignal;
    }>
  ): Promise<Readonly<{ status: number; body: unknown }>>;
  verifyAccessToken(token: string): Promise<Readonly<Record<string, unknown>>>;
  issueUserTokens(
    input: Readonly<{ signal: AbortSignal }>
  ): Promise<Readonly<{ access: string; refresh: string }>>;
  exchangeUserRefresh(
    input: Readonly<{ refreshToken: string; signal: AbortSignal }>
  ): Promise<Readonly<{ status: number; body: unknown }>>;
  readAndResetFetchReceipts?(
    input: Readonly<{ signal: AbortSignal; accept(value: unknown): void }>
  ): Promise<void>;
  timeoutMs?: number;
}>;

const maximumBodyBytes = 64 * 1024;
const maximumHeaderBytes = 16 * 1024;
const maximumFetchReceiptBytes = 16 * 1024;
const maximumFetchReceipts = 64;
const fetchReceiptPaths = new Set([
  '/text',
  '/json',
  '/post',
  '/not-found',
  '/redirect',
  '/final',
  '/reset-connection',
]);
const fail = (): never => {
  throw new TypeError('Invalid Phase 2 custom JWT HTTP observation');
};

const boundedClone = <Value>(value: Value): Value => {
  let encoded: string;
  try {
    encoded = JSON.stringify(value);
  } catch {
    return fail();
  }
  if (Buffer.byteLength(encoded) > maximumBodyBytes) {
    return fail();
  }
  return JSON.parse(encoded) as Value;
};

const boundedHeaders = (headers: Readonly<Record<string, string>>) => {
  if (nodeTypes.isProxy(headers) || Object.getPrototypeOf(headers) !== Object.prototype) {
    return fail();
  }
  let bytes = 0;
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    bytes += Buffer.byteLength(key) + Buffer.byteLength(value);
    if (bytes > maximumHeaderBytes || /^(?:authorization|set-cookie)$/iu.test(key)) {
      return fail();
    }
    result[key] = value;
  }
  return Object.freeze(result);
};

const ownData = (
  value: Readonly<Record<string, unknown>> | readonly unknown[],
  key: string
): unknown => {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) {
    return fail();
  }
  return descriptor.value as unknown;
};

const boundedFetchReceipt = (item: unknown): CustomJwtFetchReceipt => {
  if (typeof item !== 'object' || item === null || Array.isArray(item) || nodeTypes.isProxy(item)) {
    return fail();
  }
  if (Object.getPrototypeOf(item) !== Object.prototype) {
    return fail();
  }
  const ownKeys = Reflect.ownKeys(item);
  if (
    ownKeys.some((key) => typeof key !== 'string') ||
    JSON.stringify(ownKeys.toSorted((left, right) => String(left).localeCompare(String(right)))) !==
      JSON.stringify(['bodyMatches', 'headerMatches', 'method', 'path'])
  ) {
    return fail();
  }
  const record = item as Readonly<Record<string, unknown>>;
  const method = ownData(record, 'method');
  const path = ownData(record, 'path');
  const headerMatches = ownData(record, 'headerMatches');
  const bodyMatches = ownData(record, 'bodyMatches');
  if (
    (method !== 'GET' && method !== 'POST') ||
    typeof path !== 'string' ||
    !fetchReceiptPaths.has(path) ||
    (path === '/reset-connection' && method !== 'GET') ||
    typeof headerMatches !== 'boolean' ||
    typeof bodyMatches !== 'boolean'
  ) {
    return fail();
  }
  return Object.freeze({
    method,
    path: path as CustomJwtFetchReceipt['path'],
    headerMatches,
    bodyMatches,
  });
};

const boundedFetchReceipts = (value: unknown): readonly CustomJwtFetchReceipt[] => {
  if (
    !Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Array.prototype
  ) {
    return fail();
  }
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
  if (!lengthDescriptor || !('value' in lengthDescriptor)) {
    return fail();
  }
  const lengthValue: unknown = lengthDescriptor.value as unknown;
  if (
    typeof lengthValue !== 'number' ||
    !Number.isInteger(lengthValue) ||
    lengthValue < 0 ||
    lengthValue > maximumFetchReceipts
  ) {
    return fail();
  }
  const expectedKeys = [
    ...Array.from({ length: lengthValue }, (_, index) => String(index)),
    'length',
  ];
  if (JSON.stringify(Reflect.ownKeys(value)) !== JSON.stringify(expectedKeys)) {
    return fail();
  }
  const result = expectedKeys.slice(0, -1).map((key) => boundedFetchReceipt(ownData(value, key)));
  const frozen = Object.freeze(result);
  if (Buffer.byteLength(JSON.stringify(frozen)) > maximumFetchReceiptBytes) {
    return fail();
  }
  return frozen;
};

export const createCustomJwtHttpPort = (
  capabilities: CustomJwtHttpCapabilities
): CustomJwtTargetPort & CustomJwtFetchTargetPort => {
  const timeoutMs = capabilities.timeoutMs ?? 10_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000) {
    return fail();
  }
  const fenced = async <Value>(invoke: (signal: AbortSignal) => Promise<Value>): Promise<Value> => {
    await capabilities.assertInvocationFence();
    const value = await invoke(AbortSignal.timeout(timeoutMs));
    await capabilities.assertInvocationFence();
    return value;
  };
  return Object.freeze({
    request: async (input) => {
      const response = await fenced(async (signal) =>
        capabilities.managementRequest({ ...input, signal })
      );
      if (!Number.isInteger(response.status) || response.status < 100 || response.status > 599) {
        return fail();
      }
      return Object.freeze({
        status: response.status,
        headers: boundedHeaders(response.headers),
        body: boundedClone(response.body),
      });
    },
    issueClientCredentials: async ({ caseId }) =>
      capabilities.withM2MSecret(async (clientSecret) => {
        if (typeof clientSecret !== 'string' || clientSecret.length === 0) {
          return fail();
        }
        const response = await fenced(async (signal) =>
          capabilities.issueClientCredentials({ caseId, clientSecret, signal })
        );
        if (!Number.isInteger(response.status) || response.status < 100 || response.status > 599) {
          return fail();
        }
        return Object.freeze({ status: response.status, body: boundedClone(response.body) });
      }),
    verifyAccessToken: async (token) => {
      if (typeof token !== 'string' || token.length === 0 || Buffer.byteLength(token) > 16 * 1024) {
        return fail();
      }
      return Object.freeze(boundedClone(await capabilities.verifyAccessToken(token)));
    },
    issueUserTokens: async () => {
      const issued = await fenced(async (signal) => capabilities.issueUserTokens({ signal }));
      if (
        typeof issued.access !== 'string' ||
        issued.access.length === 0 ||
        Buffer.byteLength(issued.access) > 16 * 1024 ||
        typeof issued.refresh !== 'string' ||
        issued.refresh.length === 0 ||
        Buffer.byteLength(issued.refresh) > 16 * 1024 ||
        issued.access === issued.refresh
      ) {
        return fail();
      }
      return Object.freeze({
        access: issued.access,
        refresh: issued.refresh,
        toJSON: (): never => fail(),
      });
    },
    exchangeUserRefresh: async ({ refreshToken }) => {
      if (
        typeof refreshToken !== 'string' ||
        refreshToken.length === 0 ||
        Buffer.byteLength(refreshToken) > 16 * 1024
      ) {
        return fail();
      }
      const response = await fenced(async (signal) =>
        capabilities.exchangeUserRefresh({ refreshToken, signal })
      );
      if (!Number.isInteger(response.status) || response.status < 100 || response.status > 599) {
        return fail();
      }
      return Object.freeze({
        status: response.status,
        body: boundedClone(response.body),
        toJSON: (): never => fail(),
      });
    },
    readAndResetFetchReceipts: async () => {
      const takeReceipts = capabilities.readAndResetFetchReceipts;
      if (!takeReceipts) {
        return fail();
      }
      let accepted: readonly CustomJwtFetchReceipt[] | undefined;
      await fenced(async (signal) =>
        takeReceipts({
          signal,
          accept: (value) => {
            if (accepted) {
              fail();
            }
            accepted = boundedFetchReceipts(value);
          },
        })
      );
      return accepted ?? fail();
    },
  });
};

/* eslint-enable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, no-restricted-syntax, @typescript-eslint/member-ordering */
