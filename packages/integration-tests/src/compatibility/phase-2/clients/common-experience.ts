/* eslint-disable complexity, no-await-in-loop, no-control-regex, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Bounded cookie and response leases belong to one isolated Experience interaction. */
import { inspect } from 'node:util';

import { CookieJar } from 'tough-cookie';

import type { TargetConfig } from '../../model.js';

export type CommonExperienceResponse = Readonly<{
  getStatus(): number;
  getRecord(): Readonly<Record<string, unknown>>;
  getLocation(): string | undefined;
  toJSON(): never;
}>;
type ExperienceMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
type ExperienceBody = Readonly<Record<string, unknown>> | URLSearchParams | string;
export type CommonExperienceSession = Readonly<{
  request(
    path: string,
    method: ExperienceMethod,
    body?: ExperienceBody
  ): Promise<CommonExperienceResponse>;
  getCookieHeader(): Promise<string>;
  close(): void;
  toJSON(): never;
}>;

const maximumBodyBytes = 64 * 1024;
const fail = (): never => {
  throw new TypeError('Invalid Common Experience transport');
};
const text = (value: unknown, maximum = 8192): string =>
  typeof value === 'string' &&
  value.length > 0 &&
  Buffer.byteLength(value) <= maximum &&
  !/[\u0000-\u001F\u007F]/u.test(value)
    ? value
    : fail();

export const readCommonExperienceRecord = async (
  response: Response
): Promise<Readonly<Record<string, unknown>>> => {
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > maximumBodyBytes)) {
    await response.body?.cancel();
    return fail();
  }
  const reader = response.body?.getReader();
  if (!reader) {
    return Object.freeze({});
  }
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    // eslint-disable-next-line no-constant-condition, @typescript-eslint/no-unnecessary-condition -- The stream reader terminates this bounded loop.
    while (true) {
      const part = await reader.read();
      if (part.done) {
        break;
      }
      size += part.value.byteLength;
      if (size > maximumBodyBytes) {
        await reader.cancel();
        return fail();
      }
      chunks.push(part.value);
    }
  } finally {
    reader.releaseLock();
  }
  if (size === 0 || !response.headers.get('content-type')?.includes('application/json')) {
    return Object.freeze({});
  }
  const bytes = Buffer.concat(chunks, size);
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes));
  } catch {
    return fail();
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return fail();
  }
  return Object.freeze(Object.fromEntries(Object.entries(value)));
};

/** The jar and responses cannot serialize; callers publish closed facts, never raw records. */
export const createCommonExperienceSession = (
  input: Readonly<{
    target: TargetConfig;
    clientId: string;
    signal?: AbortSignal;
    fetch?: typeof fetch;
  }>
): CommonExperienceSession => {
  const origin = new URL(input.target.coreUrl);
  const clientId = text(input.clientId, 256);
  if (
    !['http:', 'https:'].includes(origin.protocol) ||
    origin.username ||
    origin.password ||
    origin.search ||
    origin.hash
  ) {
    return fail();
  }
  const jar = new CookieJar();
  const controller = new AbortController();
  const requestFetch = input.fetch ?? fetch;
  let active = true;
  const admit = (): void => {
    if (!active || input.signal?.aborted) {
      fail();
    }
  };
  return Object.freeze({
    request: async (path: string, method: ExperienceMethod, body?: ExperienceBody) => {
      admit();
      if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
        return fail();
      }
      const endpoint = new URL(text(path), origin);
      if (
        endpoint.origin !== origin.origin ||
        endpoint.username ||
        endpoint.password ||
        endpoint.hash
      ) {
        return fail();
      }
      const headers = new Headers();
      const cookie = await jar.getCookieString(endpoint.href);
      if (cookie) {
        headers.set('cookie', cookie);
      }
      if (endpoint.pathname.startsWith('/api/experience')) {
        headers.set(input.target.label === 'oracle' ? 'logto-app-id' : 'aster-app-id', clientId);
      }
      const encoded =
        body === undefined
          ? undefined
          : body instanceof URLSearchParams
            ? body.toString()
            : typeof body === 'string'
              ? body
              : JSON.stringify(body);
      if (encoded !== undefined) {
        if (Buffer.byteLength(encoded) > maximumBodyBytes || method === 'GET') {
          return fail();
        }
        headers.set(
          'content-type',
          body instanceof URLSearchParams ? 'application/x-www-form-urlencoded' : 'application/json'
        );
      }
      const response = await requestFetch(endpoint, {
        method,
        headers,
        ...(encoded === undefined ? {} : { body: encoded }),
        redirect: 'manual',
        signal: AbortSignal.any([
          controller.signal,
          AbortSignal.timeout(10_000),
          ...(input.signal ? [input.signal] : []),
        ]),
      }).catch(fail);
      admit();
      const cookies = response.headers.getSetCookie();
      if (
        cookies.length > 32 ||
        cookies.some((cookieValue) => Buffer.byteLength(cookieValue) > 8192)
      ) {
        await response.body?.cancel();
        return fail();
      }
      for (const cookieValue of cookies) {
        await jar.setCookie(cookieValue, endpoint.href, { ignoreError: false }).catch(fail);
      }
      const record = await readCommonExperienceRecord(response);
      const location = response.headers.get('location') ?? undefined;
      if (location !== undefined) {
        text(location);
      }
      return Object.freeze({
        getStatus: () => {
          admit();
          return response.status;
        },
        getRecord: () => {
          admit();
          return record;
        },
        getLocation: () => {
          admit();
          return location;
        },
        toJSON: fail,
        [inspect.custom]: () => 'CommonExperienceResponse(<redacted>)',
      });
    },
    getCookieHeader: async () => {
      admit();
      return jar.getCookieString(origin.href);
    },
    close: () => {
      active = false;
      controller.abort();
    },
    toJSON: fail,
    [inspect.custom]: () => 'CommonExperienceSession(<redacted>)',
  });
};

/* eslint-enable complexity, no-await-in-loop, no-control-regex, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
