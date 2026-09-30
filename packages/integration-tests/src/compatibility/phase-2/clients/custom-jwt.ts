/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, no-restricted-syntax, @typescript-eslint/member-ordering -- Bounded response accounting and JSON cloning are confined to this capability adapter. */
import { types as nodeTypes } from 'node:util';

import type {
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
  timeoutMs?: number;
}>;

const maximumBodyBytes = 64 * 1024;
const maximumHeaderBytes = 16 * 1024;
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

export const createCustomJwtHttpPort = (
  capabilities: CustomJwtHttpCapabilities
): CustomJwtTargetPort => {
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
  });
};

/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, no-restricted-syntax, @typescript-eslint/member-ordering */
