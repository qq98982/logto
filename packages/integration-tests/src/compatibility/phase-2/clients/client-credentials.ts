/* eslint-disable complexity, max-lines, no-await-in-loop, no-restricted-syntax, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unnecessary-condition, @typescript-eslint/no-unsafe-assignment, unicorn/no-useless-undefined -- The closed client bounds a streaming response, recursively sanitizes untrusted JSON, and preserves runtime checks beyond the static request type. */
import { createHash } from 'node:crypto';

import { base64url, createLocalJWKSet, jwtVerify, type JSONWebKeySet } from 'jose';

export type ClientCredentialsRequest = Readonly<{
  method: 'client_secret_basic' | 'client_secret_post';
  clientId: string;
  clientSecret: string;
  resource?: string;
  organizationId?: string;
  scope?: string;
}>;

export type SanitizedTokenObservation = Readonly<{
  status: number;
  headers: Readonly<Record<string, string>>;
  body: Readonly<Record<string, unknown>>;
  jwt?: Readonly<{
    header: Readonly<Record<string, unknown>>;
    claims: Readonly<Record<string, unknown>>;
    signatureSha256: string;
  }>;
}>;

export type ClientCredentialsRequestOptions = Readonly<{
  fetch?: typeof fetch;
  headers?: ReadonlyArray<readonly [string, string]>;
  maximumBodyBytes?: number;
  maximumHeaderBytes?: number;
  signal?: AbortSignal;
}>;

const requestKeys = new Set([
  'method',
  'clientId',
  'clientSecret',
  'resource',
  'organizationId',
  'scope',
]);
const optionKeys = new Set([
  'fetch',
  'headers',
  'maximumBodyBytes',
  'maximumHeaderBytes',
  'signal',
]);
const sensitiveFieldNames = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'client_secret',
  'clientsecret',
  'access_token',
  'accesstoken',
  'refresh_token',
  'refreshtoken',
  'id_token',
  'idtoken',
]);
const omittedResponseHeaders = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
]);
const compactTokenPattern = /\b[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/u;
const credentialLabelPattern = /\b(?:authorization|proxy-authorization|cookie|set-cookie)\s*:/iu;
const privateJwkMembers = new Set(['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']);
const defaultMaximumBodyBytes = 64 * 1024;
const defaultMaximumHeaderBytes = 16 * 1024;
const cancellationTimeoutMilliseconds = 100;
const maximumFieldBytes = 4096;
const invalidRequestMessage = 'Client credentials request rejected';
const requestFailureMessage = 'Client credentials request failed';
const responseFailureMessage = 'Client credentials response rejected';
const verificationFailureMessage = 'Client credentials JWT verification failed';

export class ClientCredentialsClientError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ClientCredentialsClientError';
    this.stack = this.message;
  }
}

const fail = (message: string): never => {
  throw new ClientCredentialsClientError(message);
};

const cancelSafely = async (value: unknown): Promise<void> => {
  try {
    if (typeof value !== 'object' || value === null) {
      return;
    }
    const cancel: unknown = Reflect.get(value, 'cancel');
    if (typeof cancel === 'function') {
      const cancellation = (async () => {
        try {
          await Promise.resolve(Reflect.apply(cancel, value, []));
        } catch {
          // Cancellation failures are intentionally contained.
        }
      })();
      const timeout = new Promise<void>((resolve) => {
        setTimeout(resolve, cancellationTimeoutMilliseconds);
      });
      await Promise.race([cancellation, timeout]);
    }
  } catch {
    // Cancellation is best-effort and must never replace the fixed public failure category.
  }
};

const assertBound = (value: unknown, fallback: number): number => {
  const resolved = value ?? fallback;

  if (
    typeof resolved !== 'number' ||
    !Number.isSafeInteger(resolved) ||
    resolved <= 0 ||
    resolved > 1024 * 1024
  ) {
    return fail(invalidRequestMessage);
  }

  return resolved;
};

type ResolvedRequestOptions = Readonly<{
  fetch: typeof fetch;
  headers: ReadonlyArray<readonly [string, string]>;
  maximumBodyBytes: number;
  maximumHeaderBytes: number;
  signal: AbortSignal | undefined;
}>;

const validateOptions = (options: ClientCredentialsRequestOptions): ResolvedRequestOptions => {
  try {
    if (typeof options !== 'object' || options === null || Array.isArray(options)) {
      return fail(invalidRequestMessage);
    }
    const prototype = Object.getPrototypeOf(options) as unknown;
    if (prototype !== Object.prototype && prototype !== null) {
      return fail(invalidRequestMessage);
    }
    const keys = Reflect.ownKeys(options);
    const descriptors = Object.getOwnPropertyDescriptors(options);
    if (
      keys.some((key) => typeof key !== 'string' || !optionKeys.has(key)) ||
      Object.values(descriptors).some(
        (descriptor) =>
          descriptor.get !== undefined || descriptor.set !== undefined || !descriptor.enumerable
      )
    ) {
      return fail(invalidRequestMessage);
    }
    const value = (key: keyof ClientCredentialsRequestOptions): unknown => {
      const descriptor = descriptors[key];
      if (descriptor === undefined) {
        return undefined;
      }
      return Object.hasOwn(descriptor, 'value')
        ? (descriptor.value as unknown)
        : fail(invalidRequestMessage);
    };
    const requestFetch = value('fetch');
    const headers = value('headers');
    const signal = value('signal');
    if (
      (requestFetch !== undefined && typeof requestFetch !== 'function') ||
      (headers !== undefined && !Array.isArray(headers)) ||
      (signal !== undefined && !(signal instanceof AbortSignal))
    ) {
      return fail(invalidRequestMessage);
    }

    return Object.freeze({
      fetch: (requestFetch ?? fetch) as typeof fetch,
      headers: (headers ?? []) as ReadonlyArray<readonly [string, string]>,
      maximumBodyBytes: assertBound(value('maximumBodyBytes'), defaultMaximumBodyBytes),
      maximumHeaderBytes: assertBound(value('maximumHeaderBytes'), defaultMaximumHeaderBytes),
      signal,
    });
  } catch (error: unknown) {
    if (error instanceof ClientCredentialsClientError) {
      throw error;
    }
    return fail(invalidRequestMessage);
  }
};

const assertRequestString = (value: unknown, allowEmpty = false): string => {
  if (typeof value !== 'string' || (!allowEmpty && value.length === 0)) {
    return fail(invalidRequestMessage);
  }
  if (Buffer.byteLength(value) > maximumFieldBytes || /\p{Cc}/u.test(value)) {
    return fail(invalidRequestMessage);
  }

  return value;
};

const assertClientSecret = (value: unknown): string => {
  const secret = assertRequestString(value);
  return /^[A-Za-z0-9]{32}$/u.test(secret) ? secret : fail(invalidRequestMessage);
};

const validateRequest = (request: ClientCredentialsRequest): ClientCredentialsRequest => {
  try {
    if (typeof request !== 'object' || request === null || Array.isArray(request)) {
      return fail(invalidRequestMessage);
    }
    const prototype = Object.getPrototypeOf(request) as unknown;
    if (prototype !== Object.prototype && prototype !== null) {
      return fail(invalidRequestMessage);
    }
    const keys = Reflect.ownKeys(request);
    const descriptors = Object.getOwnPropertyDescriptors(request);
    if (
      keys.some((key) => typeof key !== 'string' || !requestKeys.has(key)) ||
      Object.values(descriptors).some(
        (descriptor) =>
          descriptor.get !== undefined || descriptor.set !== undefined || !descriptor.enumerable
      )
    ) {
      return fail(invalidRequestMessage);
    }
    const value = (key: keyof ClientCredentialsRequest, required: boolean): unknown => {
      const descriptor = descriptors[key];
      if (descriptor === undefined) {
        return required ? fail(invalidRequestMessage) : undefined;
      }
      if (!Object.hasOwn(descriptor, 'value')) {
        return fail(invalidRequestMessage);
      }
      return descriptor.value as unknown;
    };
    const method = value('method', true);
    if (method !== 'client_secret_basic' && method !== 'client_secret_post') {
      return fail(invalidRequestMessage);
    }
    const clientId = assertRequestString(value('clientId', true));
    const clientSecret = assertClientSecret(value('clientSecret', true));
    const resource = value('resource', false);
    const organizationId = value('organizationId', false);
    const scope = value('scope', false);

    return Object.freeze({
      method,
      clientId,
      clientSecret,
      ...(resource === undefined ? {} : { resource: assertRequestString(resource, true) }),
      ...(organizationId === undefined
        ? {}
        : { organizationId: assertRequestString(organizationId, true) }),
      ...(scope === undefined ? {} : { scope: assertRequestString(scope, true) }),
    });
  } catch (error: unknown) {
    if (error instanceof ClientCredentialsClientError) {
      throw error;
    }
    return fail(invalidRequestMessage);
  }
};

const validateEndpoint = (endpoint: URL | string): URL => {
  try {
    const url = new URL(endpoint);

    if (
      (url.protocol !== 'http:' && url.protocol !== 'https:') ||
      url.username !== '' ||
      url.password !== '' ||
      url.search !== '' ||
      url.hash !== ''
    ) {
      return fail(invalidRequestMessage);
    }

    return url;
  } catch {
    return fail(invalidRequestMessage);
  }
};

const snapshotPublicJwks = (jwks: Readonly<JSONWebKeySet>): JSONWebKeySet => {
  const snapshot: unknown = (() => {
    try {
      return structuredClone(jwks) as unknown;
    } catch {
      return undefined;
    }
  })();
  if (
    typeof snapshot !== 'object' ||
    snapshot === null ||
    Array.isArray(snapshot) ||
    Reflect.ownKeys(snapshot).some((key) => key !== 'keys')
  ) {
    return fail(invalidRequestMessage);
  }
  const { keys } = snapshot as { keys?: unknown };
  if (!Array.isArray(keys) || keys.length === 0 || keys.length > 32) {
    return fail(invalidRequestMessage);
  }
  const candidates: readonly unknown[] = keys;
  for (const key of candidates) {
    if (
      typeof key !== 'object' ||
      key === null ||
      Array.isArray(key) ||
      Reflect.ownKeys(key).some(
        (member) => typeof member !== 'string' || privateJwkMembers.has(member)
      )
    ) {
      return fail(invalidRequestMessage);
    }
  }

  type Freezable = Record<PropertyKey, unknown> | unknown[];
  const seen = new WeakSet<Freezable>();
  const freeze = (value: unknown): void => {
    if (typeof value !== 'object' || value === null) {
      return;
    }
    const candidate = value as Freezable;
    if (seen.has(candidate)) {
      return;
    }
    seen.add(candidate);
    for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(candidate))) {
      if (Object.hasOwn(descriptor, 'value')) {
        freeze(descriptor.value);
      }
    }
    Object.freeze(candidate);
  };
  freeze(snapshot);

  return snapshot as JSONWebKeySet;
};

const requestToken = async (
  requestFetch: typeof fetch,
  endpoint: URL,
  prepared: ReturnType<typeof createRequest>,
  signal: AbortSignal | undefined
): Promise<Response> => {
  try {
    return await requestFetch(endpoint, {
      method: 'POST',
      body: prepared.body,
      headers: prepared.headers,
      redirect: 'manual',
      signal,
    });
  } catch {
    return fail(requestFailureMessage);
  }
};

type ResponseSnapshot = Readonly<{
  status: number;
  headers: Headers;
  body: ReadableStream<Uint8Array> | undefined;
}>;

const snapshotResponse = async (response: Response): Promise<ResponseSnapshot> => {
  // eslint-disable-next-line @silverhand/fp/no-let -- Capturing the body first lets a later accessor failure cancel the acquired stream.
  let body: ReadableStream<Uint8Array> | undefined;
  try {
    body = response.body ?? undefined;
    const { headers } = response;
    const { status } = response;
    if (
      !(headers instanceof Headers) ||
      !Number.isInteger(status) ||
      status < 100 ||
      status > 599 ||
      (body !== undefined &&
        (typeof body.getReader !== 'function' || typeof body.cancel !== 'function'))
    ) {
      return fail(responseFailureMessage);
    }
    return Object.freeze({ status, headers, body });
  } catch (error: unknown) {
    await cancelSafely(body);
    if (error instanceof ClientCredentialsClientError) {
      throw error;
    }
    return fail(responseFailureMessage);
  }
};

const projectResponseHeaders = async (
  response: ResponseSnapshot,
  maximumBytes: number,
  sensitiveValues: readonly string[]
): Promise<ProjectedHeaders> => {
  try {
    return projectHeaders(response.headers, maximumBytes, sensitiveValues);
  } catch (error: unknown) {
    await cancelSafely(response.body);
    throw error;
  }
};

const readBoundedBody = async (
  response: ResponseSnapshot,
  maximumBytes: number
): Promise<Uint8Array> => {
  try {
    const contentLength = response.headers.get('content-length');

    if (contentLength !== null) {
      const parsedLength = /^[0-9]+$/u.test(contentLength) ? Number(contentLength) : Number.NaN;

      if (!Number.isSafeInteger(parsedLength) || parsedLength < 0 || parsedLength > maximumBytes) {
        await cancelSafely(response.body);
        return fail(responseFailureMessage);
      }
    }
    if (response.body === undefined) {
      return new Uint8Array();
    }

    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    // eslint-disable-next-line @silverhand/fp/no-let -- The stream length is accumulated while enforcing the hard read bound.
    let length = 0;

    try {
      // eslint-disable-next-line no-constant-condition -- The reader's done flag is the loop terminator.
      while (true) {
        const { done, value } = await reader.read();

        if (done) {
          break;
        }
        length += value.byteLength;
        if (length > maximumBytes) {
          await cancelSafely(reader);
          return fail(responseFailureMessage);
        }
        chunks.push(value);
      }
    } catch {
      await cancelSafely(reader);
      return fail(responseFailureMessage);
    } finally {
      reader.releaseLock();
    }

    const body = new Uint8Array(length);
    // eslint-disable-next-line @silverhand/fp/no-let -- Each bounded chunk is copied into the final exact-size buffer.
    let offset = 0;

    for (const chunk of chunks) {
      body.set(chunk, offset);
      offset += chunk.byteLength;
    }

    return body;
  } catch (error: unknown) {
    await cancelSafely(response.body);
    if (error instanceof ClientCredentialsClientError) {
      throw error;
    }
    return fail(responseFailureMessage);
  }
};

const sanitizeString = (value: string, sensitiveValues: readonly string[]): string => {
  const normalized = value.toLowerCase();
  if (
    compactTokenPattern.test(value) ||
    credentialLabelPattern.test(value) ||
    sensitiveValues.some(
      (sensitiveValue) =>
        sensitiveValue.length > 0 && normalized.includes(sensitiveValue.toLowerCase())
    )
  ) {
    return '<redacted>';
  }

  return value;
};

const sanitizeValue = (value: unknown, sensitiveValues: readonly string[]): unknown => {
  if (typeof value === 'string') {
    return sanitizeString(value, sensitiveValues);
  }
  if (Array.isArray(value)) {
    return value.map((entry) => sanitizeValue(entry, sensitiveValues));
  }
  if (typeof value === 'object' && value !== null) {
    return Object.fromEntries(
      Object.entries(value)
        .filter(
          ([key]) =>
            !sensitiveFieldNames.has(key.toLowerCase()) &&
            sanitizeString(key, sensitiveValues) === key
        )
        .map(([key, entry]) => [key, sanitizeValue(entry, sensitiveValues)])
    );
  }

  return value;
};

const assertObservationSanitized = (
  observation: SanitizedTokenObservation,
  sensitiveValues: readonly string[]
): SanitizedTokenObservation => {
  const serialized = JSON.stringify(observation);
  const normalized = serialized.toLowerCase();
  if (
    sensitiveValues.some(
      (sensitiveValue) =>
        sensitiveValue.length > 0 && normalized.includes(sensitiveValue.toLowerCase())
    )
  ) {
    return fail(responseFailureMessage);
  }
  return observation;
};

type ProjectedHeaders = Readonly<{
  headers: Readonly<Record<string, string>>;
  sensitiveValues: readonly string[];
}>;

const credentialHeaderValues = (name: string, value: string): readonly string[] => {
  const values = [value];
  if (name === 'cookie' || name === 'set-cookie') {
    for (const quoted of value.matchAll(/"((?:\\.|[^"\\])*)"/gu)) {
      const logical = (quoted[1] ?? '').replaceAll(/\\(.)/gu, '$1');
      if (logical.length > 0) {
        values.push(logical);
      }
    }
    for (const match of value.matchAll(/(?:^|[;,]\s*)([^=;,\s]+)=([^;,]*)/gu)) {
      const pair = match[0].replace(/^[;,]\s*/u, '');
      const cookieValue = match[2] ?? '';
      const logicalCookieValue =
        cookieValue.length >= 2 && cookieValue.startsWith('"') && cookieValue.endsWith('"')
          ? cookieValue.slice(1, -1).replaceAll(/\\(.)/gu, '$1')
          : cookieValue;
      if (pair.length > 0) {
        values.push(pair);
      }
      if (cookieValue.length > 0) {
        values.push(cookieValue);
      }
      if (logicalCookieValue.length > 0 && logicalCookieValue !== cookieValue) {
        values.push(logicalCookieValue);
      }
    }
  } else {
    const credential = value.split(/\s+/u).slice(1).join(' ');
    if (credential.length > 0) {
      values.push(credential);
    }
  }
  return values;
};

const projectHeaders = (
  headers: Headers,
  maximumBytes: number,
  sensitiveValues: readonly string[]
): ProjectedHeaders => {
  const entries = [...headers.entries()];
  const bytes = entries.reduce(
    (total, [name, value]) => total + Buffer.byteLength(name) + Buffer.byteLength(value) + 4,
    0
  );
  if (bytes > maximumBytes) {
    return fail(responseFailureMessage);
  }
  const discoveredSensitiveValues = [
    ...sensitiveValues,
    ...entries.flatMap(([name, value]) =>
      omittedResponseHeaders.has(name.toLowerCase())
        ? credentialHeaderValues(name.toLowerCase(), value)
        : []
    ),
  ];
  const projected: Array<readonly [string, string]> = [];

  for (const [rawName, rawValue] of entries) {
    const name = rawName.toLowerCase();

    if (
      omittedResponseHeaders.has(name) ||
      sensitiveFieldNames.has(name) ||
      sanitizeString(name, discoveredSensitiveValues) !== name
    ) {
      continue;
    }
    const value = sanitizeString(rawValue, discoveredSensitiveValues);
    projected.push([name, value]);
  }

  projected.sort(([left], [right]) => left.localeCompare(right));
  return Object.freeze({
    headers: Object.freeze(Object.fromEntries(projected)),
    sensitiveValues: Object.freeze(discoveredSensitiveValues),
  });
};

const projectBody = (
  bytes: Uint8Array,
  sensitiveValues: readonly string[]
): Readonly<Record<string, unknown>> => {
  if (bytes.byteLength === 0) {
    return Object.freeze({});
  }

  try {
    const text = new TextDecoder('utf8', { fatal: true }).decode(bytes);
    const parsed: unknown = JSON.parse(text);
    const sanitized = sanitizeValue(parsed, sensitiveValues);

    if (typeof sanitized === 'object' && sanitized !== null && !Array.isArray(sanitized)) {
      return Object.freeze(sanitized as Record<string, unknown>);
    }

    return Object.freeze({ value: sanitized });
  } catch (error: unknown) {
    if (error instanceof SyntaxError) {
      return Object.freeze({ text: '<redacted>' });
    }
    if (error instanceof TypeError) {
      return fail(responseFailureMessage);
    }

    return fail(responseFailureMessage);
  }
};

const encodeOauthBasicComponent = (value: string): string => {
  const encoded = new URLSearchParams([['value', value]]).toString();
  return encoded.slice('value='.length);
};

const createRequestUnchecked = (
  request: ClientCredentialsRequest,
  additionalHeaders: ReadonlyArray<readonly [string, string]>
): Readonly<{ body: URLSearchParams; headers: Headers; authorization: string | undefined }> => {
  if (!Array.isArray(additionalHeaders)) {
    return fail(invalidRequestMessage);
  }
  const validatedHeaders = additionalHeaders.map((entry) => {
    if (!Array.isArray(entry) || Object.getPrototypeOf(entry) !== Array.prototype) {
      return fail(invalidRequestMessage);
    }
    const keys = Reflect.ownKeys(entry);
    const descriptors = Object.getOwnPropertyDescriptors(entry) as unknown as Record<
      PropertyKey,
      PropertyDescriptor
    >;
    const nameDescriptor = descriptors[0];
    const valueDescriptor = descriptors[1];
    const lengthDescriptor = descriptors.length;
    if (
      keys.some((key) => key !== '0' && key !== '1' && key !== 'length') ||
      nameDescriptor === undefined ||
      valueDescriptor === undefined ||
      lengthDescriptor === undefined ||
      !Object.hasOwn(nameDescriptor, 'value') ||
      !Object.hasOwn(valueDescriptor, 'value') ||
      lengthDescriptor.value !== 2 ||
      typeof nameDescriptor.value !== 'string' ||
      typeof valueDescriptor.value !== 'string'
    ) {
      return fail(invalidRequestMessage);
    }
    const name = nameDescriptor.value;
    const { value } = valueDescriptor;
    if (
      /\p{Cc}/u.test(name) ||
      /\p{Cc}/u.test(value) ||
      Buffer.byteLength(name) > maximumFieldBytes ||
      Buffer.byteLength(value) > maximumFieldBytes ||
      omittedResponseHeaders.has(name.toLowerCase())
    ) {
      return fail(invalidRequestMessage);
    }
    return [name, value] as [string, string];
  });

  const body = new URLSearchParams({ grant_type: 'client_credentials' });

  if (request.resource !== undefined) {
    body.append('resource', request.resource);
  }
  if (request.organizationId !== undefined) {
    body.append('organization_id', request.organizationId);
  }
  if (request.scope !== undefined) {
    body.append('scope', request.scope);
  }

  const headers = (() => {
    try {
      const value = new Headers(validatedHeaders);
      value.set('content-type', 'application/x-www-form-urlencoded');
      return value;
    } catch {
      return fail(invalidRequestMessage);
    }
  })();

  if (request.method === 'client_secret_post') {
    body.append('client_id', request.clientId);
    body.append('client_secret', request.clientSecret);
    return Object.freeze({ authorization: undefined, body, headers });
  }

  const authorization = `Basic ${Buffer.from(
    `${encodeOauthBasicComponent(request.clientId)}:${encodeOauthBasicComponent(
      request.clientSecret
    )}`,
    'utf8'
  ).toString('base64')}`;
  headers.set('authorization', authorization);

  return Object.freeze({ authorization, body, headers });
};

const createRequest = (
  request: ClientCredentialsRequest,
  additionalHeaders: ReadonlyArray<readonly [string, string]>
): ReturnType<typeof createRequestUnchecked> => {
  try {
    return createRequestUnchecked(request, additionalHeaders);
  } catch (error: unknown) {
    if (error instanceof ClientCredentialsClientError) {
      throw error;
    }
    return fail(invalidRequestMessage);
  }
};

const observeClientCredentialsTokenUnchecked = async (
  endpoint: URL | string,
  jwks: Readonly<JSONWebKeySet>,
  untrustedRequest: ClientCredentialsRequest,
  options: ClientCredentialsRequestOptions = {}
): Promise<SanitizedTokenObservation> => {
  const request = validateRequest(untrustedRequest);
  const tokenEndpoint = validateEndpoint(endpoint);
  const pinnedJwks = snapshotPublicJwks(jwks);
  const resolvedOptions = validateOptions(options);
  const prepared = createRequest(request, resolvedOptions.headers);
  const sensitiveValues = [
    request.clientSecret,
    ...(prepared.authorization === undefined
      ? []
      : credentialHeaderValues('authorization', prepared.authorization)),
  ];
  const rawResponse = await requestToken(
    resolvedOptions.fetch,
    tokenEndpoint,
    prepared,
    resolvedOptions.signal
  );
  const response = await snapshotResponse(rawResponse);
  const projectedHeaders = await projectResponseHeaders(
    response,
    resolvedOptions.maximumHeaderBytes,
    sensitiveValues
  );
  const bodyBytes = await readBoundedBody(response, resolvedOptions.maximumBodyBytes);
  const body = projectBody(bodyBytes, projectedHeaders.sensitiveValues);
  const rawBody = (() => {
    try {
      return JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bodyBytes)) as unknown;
    } catch {
      return undefined;
    }
  })();

  if (response.status < 200 || response.status >= 300) {
    return assertObservationSanitized(
      Object.freeze({ status: response.status, headers: projectedHeaders.headers, body }),
      projectedHeaders.sensitiveValues
    );
  }
  if (typeof rawBody !== 'object' || rawBody === null || Array.isArray(rawBody)) {
    return fail(responseFailureMessage);
  }
  const compactJwt = Reflect.get(rawBody, 'access_token');

  if (typeof compactJwt !== 'string' || compactJwt.split('.').length !== 3) {
    return fail(responseFailureMessage);
  }

  try {
    const verified = await jwtVerify(compactJwt, createLocalJWKSet(pinnedJwks));
    const signature = compactJwt.split('.')[2];

    if (!signature) {
      return fail(verificationFailureMessage);
    }

    const header = sanitizeValue(verified.protectedHeader, projectedHeaders.sensitiveValues);
    const claims = sanitizeValue(verified.payload, projectedHeaders.sensitiveValues);
    if (
      typeof header !== 'object' ||
      header === null ||
      Array.isArray(header) ||
      typeof claims !== 'object' ||
      claims === null ||
      Array.isArray(claims)
    ) {
      return fail(verificationFailureMessage);
    }

    return assertObservationSanitized(
      Object.freeze({
        status: response.status,
        headers: projectedHeaders.headers,
        body,
        jwt: Object.freeze({
          header: Object.freeze(header as Record<string, unknown>),
          claims: Object.freeze(claims as Record<string, unknown>),
          signatureSha256: createHash('sha256').update(base64url.decode(signature)).digest('hex'),
        }),
      }),
      projectedHeaders.sensitiveValues
    );
  } catch (error: unknown) {
    if (error instanceof ClientCredentialsClientError) {
      throw error;
    }

    return fail(verificationFailureMessage);
  }
};

export const observeClientCredentialsToken = async (
  endpoint: URL | string,
  jwks: Readonly<JSONWebKeySet>,
  request: ClientCredentialsRequest,
  options: ClientCredentialsRequestOptions = {}
): Promise<SanitizedTokenObservation> => {
  try {
    return await observeClientCredentialsTokenUnchecked(endpoint, jwks, request, options);
  } catch (error: unknown) {
    if (error instanceof ClientCredentialsClientError) {
      throw error;
    }
    return fail(responseFailureMessage);
  }
};
/* eslint-enable complexity, max-lines, no-await-in-loop, no-restricted-syntax, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unnecessary-condition, @typescript-eslint/no-unsafe-assignment, unicorn/no-useless-undefined */
