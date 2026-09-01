/* eslint-disable @silverhand/fp/no-mutating-methods, @silverhand/fp/no-mutation, @silverhand/fp/no-let, @typescript-eslint/ban-types, complexity, max-lines, no-control-regex -- The raw protocol boundary intentionally keeps credential storage, URL confinement, bounded transport state, and duplicate-preserving headers together so validation cannot be bypassed between helpers. */
import http, { type ClientRequest } from 'node:http';
import https from 'node:https';

import { CookieJar } from 'tough-cookie';

import { validateTargetConfig } from '../../config.js';
import type { TargetConfig } from '../../model.js';
import type { Phase1FixtureAllocationRole } from '../fixture-map.js';

export type RawProtocolHeaders = ReadonlyArray<readonly [string, string]>;

export type RawProtocolResponse = Readonly<{
  status: number;
  headers: RawProtocolHeaders;
  body: string;
}>;

export type ProtocolRequestOptions = Readonly<{
  method?: string;
  headers?: RawProtocolHeaders | Readonly<Record<string, string>>;
  body?: string;
  includeCookies?: boolean;
}>;

export type RawProtocolClientOptions = Readonly<{
  target: TargetConfig;
  fixture: Readonly<{
    public: Readonly<{
      allocations: ReadonlyArray<Readonly<{ role: Phase1FixtureAllocationRole }>>;
    }>;
  }>;
  allocationRole?: Phase1FixtureAllocationRole;
  store: MemoryProtocolSecretStore;
  signal: AbortSignal;
}>;

const safeOperationPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const absoluteUrlPattern = /^[A-Za-z][A-Za-z0-9+.-]*:/u;
const namespaceProbePath = 'aster-namespace-probe';
const maximumRawResponseBytes = 8 * 1024 * 1024;
const maximumCredentialGraphDepth = 32;
const forbiddenCallerHeaderNames = new Set([
  'host',
  ':authority',
  'cookie',
  'proxy-authorization',
  'proxy-connection',
  'connection',
  'upgrade',
  'forwarded',
  'transfer-encoding',
  'te',
  'trailer',
  'keep-alive',
  'proxy-authenticate',
]);

type PreparedProtocolRequest = Readonly<{
  operation: string;
  url: string;
}>;

export class ProtocolClientError extends Error {
  readonly operation: string;
  readonly status: number | undefined;

  override get name(): string {
    return 'ProtocolClientError';
  }

  constructor(operation: string, status?: number) {
    const diagnosticOperation = safeOperationPattern.test(operation)
      ? operation
      : 'invalid-operation';
    super(
      status === undefined
        ? `Protocol client operation failed: ${diagnosticOperation}`
        : `Protocol client operation failed: ${diagnosticOperation} (HTTP ${status})`
    );
    this.operation = diagnosticOperation;
    this.status = status;
    this.stack = this.message;
  }
}

const requireText = (value: unknown, failure: string): string => {
  if (typeof value !== 'string' || value.length === 0 || /[\u0000-\u001F\u007F]/u.test(value)) {
    throw new TypeError(failure);
  }

  return value;
};

const requireOperation = (value: unknown): string => {
  const operation = requireText(value, 'Invalid protocol operation');

  if (!safeOperationPattern.test(operation)) {
    throw new TypeError('Invalid protocol operation');
  }

  return operation;
};

const requireRelativeRequestPath = (value: unknown): string => {
  const path = requireText(value, 'Invalid protocol request path');

  if (
    path !== path.trim() ||
    path.startsWith('/') ||
    path.includes('\\') ||
    absoluteUrlPattern.test(path)
  ) {
    throw new TypeError('Invalid protocol request path');
  }
  const pathOnly = path.split(/[?#]/u, 1)[0] ?? '';

  for (const segment of pathOnly.split('/')) {
    let decoded: string;

    try {
      decoded = decodeURIComponent(segment);
    } catch {
      throw new TypeError('Invalid protocol request path');
    }
    if (decoded === '.' || decoded === '..' || decoded.includes('/') || decoded.includes('\\')) {
      throw new TypeError('Invalid protocol request path');
    }
  }

  return path;
};

const cookieName = (setCookie: string): string | undefined => {
  const separator = setCookie.indexOf('=');
  const name = separator < 1 ? '' : setCookie.slice(0, separator).trim();

  return /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u.test(name) ? name : undefined;
};

const cookieValue = (setCookie: string): string => {
  const pair = setCookie.split(';', 1)[0] ?? '';
  const separator = pair.indexOf('=');
  const value = separator < 0 ? '' : pair.slice(separator + 1).trim();

  return value.startsWith('"') && value.endsWith('"') ? value.slice(1, -1) : value;
};

const inspectCredentialGraph = (
  value: unknown,
  credentials: ReadonlySet<string>,
  ancestors: WeakSet<object>,
  depth: number
): void => {
  if (depth > maximumCredentialGraphDepth) {
    throw new TypeError('Protocol output contains credential material');
  }
  if (typeof value === 'string') {
    if (
      [...credentials].some((credential) => credential.length > 0 && value.includes(credential))
    ) {
      throw new TypeError('Protocol output contains credential material');
    }

    return;
  }
  if (value === null || value === undefined || ['number', 'boolean'].includes(typeof value)) {
    return;
  }
  if (typeof value !== 'object' || ancestors.has(value)) {
    throw new TypeError('Protocol output contains credential material');
  }
  const prototype: unknown = Object.getPrototypeOf(value);

  if (
    (Array.isArray(value) && prototype !== Array.prototype) ||
    (!Array.isArray(value) && prototype !== Object.prototype && prototype !== null)
  ) {
    throw new TypeError('Protocol output contains credential material');
  }
  ancestors.add(value);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') {
      throw new TypeError('Protocol output contains credential material');
    }
    inspectCredentialGraph(key, credentials, ancestors, depth + 1);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);

    if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
      throw new TypeError('Protocol output contains credential material');
    }
    inspectCredentialGraph(descriptor.value, credentials, ancestors, depth + 1);
  }
  ancestors.delete(value);
};

export class MemoryProtocolSecretStore {
  readonly #cookies = new CookieJar(undefined, { allowSpecialUseDomain: true });
  readonly #tokens = new Map<string, string>();
  readonly #credentials = new Set<string>();

  registerSecret(value: string): void {
    const credential = requireText(value, 'Invalid protocol secret');
    this.#credentials.add(credential);
  }

  assertNoCredentialMaterial(value: unknown): void {
    inspectCredentialGraph(value, this.#credentials, new WeakSet(), 0);
  }

  setCookie(setCookie: string, url: URL): void {
    const value = requireText(setCookie, 'Invalid protocol cookie');

    if (!cookieName(value)) {
      throw new TypeError('Invalid protocol cookie');
    }
    try {
      this.#cookies.setCookieSync(value, url.href);
      const credential = cookieValue(value);

      if (credential.length > 0) {
        this.registerSecret(credential);
      }
    } catch {
      throw new TypeError('Invalid protocol cookie');
    }
  }

  getCookieHeader(url: URL): string | undefined {
    let value: string;

    try {
      value = this.#cookies.getCookieStringSync(url.href);
    } catch {
      throw new TypeError('Invalid protocol cookie');
    }

    return value.length === 0 ? undefined : value;
  }

  setToken(name: string, value: string): void {
    const token = requireText(value, 'Invalid protocol token');
    this.registerSecret(token);
    this.#tokens.set(requireText(name, 'Invalid protocol token name'), token);
  }

  getToken(name: string): string | undefined {
    return this.#tokens.get(requireText(name, 'Invalid protocol token name'));
  }

  clearToken(name: string): void {
    this.#tokens.delete(requireText(name, 'Invalid protocol token name'));
  }

  toJSON(): never {
    throw new TypeError('Protocol secret store is not serializable');
  }
}

const isRawProtocolHeaders = (
  value: ProtocolRequestOptions['headers']
): value is RawProtocolHeaders => Array.isArray(value);

export const protocolHeaderPairs = (
  value: ProtocolRequestOptions['headers']
): Array<readonly [string, string]> => {
  const pairs =
    value === undefined
      ? []
      : isRawProtocolHeaders(value)
        ? value.map(([name, headerValue]) => [name, headerValue] as const)
        : Object.entries(value);

  if (
    pairs.some(([name]) => {
      const normalized = name.toLowerCase();

      return forbiddenCallerHeaderNames.has(normalized) || normalized.startsWith('x-forwarded-');
    })
  ) {
    throw new TypeError('Invalid protocol request headers');
  }

  return pairs;
};

const rawResponseHeaders = (rawHeaders: readonly string[]): RawProtocolHeaders =>
  Object.freeze(
    Array.from({ length: Math.floor(rawHeaders.length / 2) }, (_, index) =>
      Object.freeze([
        rawHeaders[index * 2]?.toLowerCase() ?? '',
        rawHeaders[index * 2 + 1] ?? '',
      ] as const)
    )
  );

export class OidcClient {
  readonly target: TargetConfig;
  readonly fixture: RawProtocolClientOptions['fixture'];
  readonly allocationRole: Phase1FixtureAllocationRole | undefined;
  readonly store: MemoryProtocolSecretStore;
  readonly signal: AbortSignal;

  constructor(options: RawProtocolClientOptions) {
    this.target = validateTargetConfig(options.target);
    this.fixture = options.fixture;
    this.allocationRole = options.allocationRole;
    this.store = options.store;
    this.signal = options.signal;
    const hasAllocation = this.fixture.public.allocations.some(
      ({ role }) => role === this.allocationRole
    );

    if (
      (this.allocationRole === undefined && this.fixture.public.allocations.length > 0) ||
      (this.allocationRole !== undefined && !hasAllocation)
    ) {
      throw new TypeError('Invalid protocol fixture allocation');
    }
  }

  async request(
    operation: string,
    path: string,
    options: ProtocolRequestOptions = {}
  ): Promise<RawProtocolResponse> {
    return this.sendPreparedRequest(this.prepareRequest(operation, path), options);
  }

  protected prepareRequest(operation: string, path: string): PreparedProtocolRequest {
    const safeOperation = requireOperation(operation);

    try {
      const safePath = requireRelativeRequestPath(path);
      const target = new URL(this.baseUrl());
      const namespace = new URL('.', this.resolve(namespaceProbePath));
      const resolved = this.resolve(safePath);

      if (
        namespace.origin !== target.origin ||
        namespace.protocol !== target.protocol ||
        namespace.username.length > 0 ||
        namespace.password.length > 0 ||
        !namespace.pathname.endsWith('/') ||
        namespace.search.length > 0 ||
        namespace.hash.length > 0 ||
        resolved.origin !== namespace.origin ||
        resolved.protocol !== namespace.protocol ||
        resolved.username.length > 0 ||
        resolved.password.length > 0 ||
        !resolved.pathname.startsWith(namespace.pathname)
      ) {
        throw new TypeError('Invalid protocol request path');
      }

      return Object.freeze({ operation: safeOperation, url: resolved.href });
    } catch {
      throw new ProtocolClientError(safeOperation);
    }
  }

  protected async sendPreparedRequest(
    prepared: PreparedProtocolRequest,
    options: ProtocolRequestOptions = {}
  ): Promise<RawProtocolResponse> {
    const safeOperation = prepared.operation;
    const url = new URL(prepared.url);
    const headers = (() => {
      try {
        const pairs = protocolHeaderPairs(options.headers);
        if (
          this.allocationRole === undefined &&
          pairs.some(([name]) => name.toLowerCase() === 'authorization')
        ) {
          throw new TypeError('Invalid public protocol request headers');
        }
        const cookie =
          this.allocationRole === undefined || options.includeCookies === false
            ? undefined
            : this.store.getCookieHeader(url);

        return Object.fromEntries([
          ...pairs,
          ...(cookie && !pairs.some(([name]) => name.toLowerCase() === 'cookie')
            ? ([['cookie', cookie]] as const)
            : []),
        ]);
      } catch {
        throw new ProtocolClientError(safeOperation);
      }
    })();
    const transport = url.protocol === 'https:' ? https : http;

    return new Promise<RawProtocolResponse>((resolve, reject) => {
      let settled = false;
      let request: ClientRequest | undefined;
      const fail = (status?: number) => {
        if (settled) {
          return;
        }
        settled = true;
        reject(new ProtocolClientError(safeOperation, status));
      };
      try {
        request = transport.request(
          url,
          {
            method: options.method ?? (options.body === undefined ? 'GET' : 'POST'),
            headers,
            signal: this.signal,
          },
          (response) => {
            const chunks: Uint8Array[] = [];
            let responseBytes = 0;

            response.on('data', (chunk: Uint8Array | string) => {
              const bytes = typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
              responseBytes += bytes.byteLength;
              if (responseBytes > maximumRawResponseBytes) {
                response.destroy();
                fail(response.statusCode);
                return;
              }
              chunks.push(bytes);
            });
            response.once('error', () => {
              fail();
            });
            response.once('aborted', () => {
              fail();
            });
            response.once('close', () => {
              if (!response.complete) {
                fail();
              }
            });
            response.once('end', () => {
              if (settled) {
                return;
              }
              const status = response.statusCode;

              if (status === undefined || status < 100 || status > 599) {
                fail();
                return;
              }
              const responseHeaders = rawResponseHeaders(response.rawHeaders);

              for (const [name, value] of responseHeaders) {
                if (name === 'set-cookie' && this.allocationRole !== undefined) {
                  try {
                    this.store.setCookie(value, url);
                  } catch {
                    fail(status);
                    return;
                  }
                }
              }
              settled = true;
              resolve(
                Object.freeze({
                  status,
                  headers: responseHeaders,
                  body: Buffer.concat(chunks).toString('utf8'),
                })
              );
            });
          }
        );

        request.once('error', () => {
          fail();
        });
        if (options.body === undefined) {
          request.end();
        } else {
          request.end(options.body);
        }
      } catch {
        try {
          request?.destroy();
        } catch {
          // The fixed rejection below is the only diagnostic crossing this boundary.
        }
        fail();
      }
    });
  }

  protected resolve(path: string): URL {
    return new URL(requireText(path, 'Invalid protocol request path'), this.baseUrl());
  }

  private baseUrl(): string {
    return this.allocationRole === 'admin' ? this.target.adminUrl : this.target.coreUrl;
  }
}

/* eslint-enable @silverhand/fp/no-mutating-methods, @silverhand/fp/no-mutation, @silverhand/fp/no-let, @typescript-eslint/ban-types, complexity, max-lines, no-control-regex */
