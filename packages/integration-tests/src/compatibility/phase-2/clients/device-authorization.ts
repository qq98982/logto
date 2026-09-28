/* eslint-disable complexity, max-lines, max-params, no-await-in-loop, no-control-regex, no-restricted-syntax, @typescript-eslint/no-unnecessary-condition, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- This boundary owns a short-lived secret store, cookie jar, and bounded hostile HTTP surfaces. */
import { types as nodeTypes } from 'node:util';

import { Cookie, CookieJar } from 'tough-cookie';

import { validateTargetConfig } from '../../config.js';
import type { TargetConfig } from '../../model.js';

import { containsCompactJwt } from './client-credentials.js';

export type DeviceAuthorizationFieldName =
  | 'client_id'
  | 'client_secret'
  | 'resource'
  | 'scope'
  | 'organization_id'
  | 'ui_locales';

export type DeviceAuthorizationRequest =
  | Readonly<{
      encoding: 'form';
      fields: ReadonlyArray<readonly [DeviceAuthorizationFieldName, string]>;
    }>
  | Readonly<{
      encoding: 'json';
      fields: Readonly<Partial<Record<DeviceAuthorizationFieldName, string>>>;
    }>
  | Readonly<{
      encoding: 'raw';
      mediaType: string;
      body: string;
      sensitiveFragments?: readonly string[];
    }>;

export type DeviceAuthorizationSecretValue =
  | string
  | Readonly<{ stored: 'device-code' | 'user-code' | 'xsrf' }>;

export type DeviceAuthorizationClientProof =
  | Readonly<{ method: 'public'; clientId: string }>
  | Readonly<{ method: 'basic' | 'post'; clientId: string; clientSecret: string }>;

export type DeviceTokenPollingRequest = Readonly<{
  proof: DeviceAuthorizationClientProof;
  deviceCode?: DeviceAuthorizationSecretValue;
}>;

export type DeviceVerificationRequest =
  | Readonly<{
      method: 'GET';
      path: '/device' | '/oidc/device';
      userCode?: DeviceAuthorizationSecretValue;
    }>
  | Readonly<{
      method: 'POST';
      path: '/device' | '/oidc/device';
      fields: Readonly<{
        xsrf?: DeviceAuthorizationSecretValue;
        user_code?: DeviceAuthorizationSecretValue;
        confirm?: string;
        abort?: string;
      }>;
    }>;

export type DeviceAuthorizationUrlProjection = Readonly<{
  origin: string;
  path: string;
  queryKeys: readonly string[];
}>;

export type DeviceAuthorizationCookieProjection = Readonly<{
  name: string;
  options: readonly string[];
}>;

export type DeviceAuthorizationChallengeProjection = Readonly<{
  scheme: string;
  parameters: Readonly<Record<string, string>>;
}>;

export type DeviceAuthorizationProjection = Readonly<{
  status: number;
  contentType: string | undefined;
  headers: Readonly<Record<string, string>>;
  keys: readonly string[];
  cookies: readonly DeviceAuthorizationCookieProjection[];
  challenge: DeviceAuthorizationChallengeProjection | undefined;
  location: DeviceAuthorizationUrlProjection | undefined;
  oauthError: Readonly<{ category: string | undefined; description: string | undefined }>;
  userCodeShape:
    | Readonly<{
        length: number;
        groups: readonly number[];
        separator: string | undefined;
        matchesReferencePattern: boolean;
      }>
    | undefined;
  deviceCodeShape: Readonly<{ length: number }> | undefined;
  expiresIn: number | undefined;
  interval: number | undefined;
  verificationUri: DeviceAuthorizationUrlProjection | undefined;
  verificationUriComplete: DeviceAuthorizationUrlProjection | undefined;
  experience:
    | Readonly<{
        title: string | undefined;
        formAction: DeviceAuthorizationUrlProjection | undefined;
        inputNames: readonly string[];
        autoSubmit: boolean;
      }>
    | undefined;
}>;

export type DeviceAuthorizationTransportOptions = Readonly<{
  target: TargetConfig;
  fetch?: typeof fetch;
  maximumBodyBytes?: number;
  maximumHeaderBytes?: number;
  maximumRequestBodyBytes?: number;
  maximumRequestHeaderBytes?: number;
  maximumRequestUrlBytes?: number;
  maximumSensitiveVariants?: number;
  timeoutMs?: number;
}>;

export type DeviceAuthorizationTransportLease = Readonly<{
  requestAuthorization(request: DeviceAuthorizationRequest): Promise<DeviceAuthorizationProjection>;
  requestVerification(request: DeviceVerificationRequest): Promise<DeviceAuthorizationProjection>;
  pollToken(request: DeviceTokenPollingRequest): Promise<DeviceAuthorizationProjection>;
  clear(): void;
  toJSON(): never;
}>;

type TransportState = {
  active: boolean;
  operationActive: boolean;
  deviceCode?: string;
  userCode?: string;
  codesExpireAt?: number;
  xsrf?: string;
  xsrfCookieIdentity?: string;
  xsrfExpireAt?: number;
  cookies: CookieJar;
  controllers: Set<AbortController>;
};

type ResponseLimits = Readonly<{ body: number; headers: number }>;
type RequestLimits = Readonly<{ body: number; headers: number; url: number }>;
type DeviceResponseOperation = 'authorization' | 'verification' | 'token';
type SensitiveRegistry = Readonly<{
  values: Set<string>;
  maximum: number;
  stage: string;
}>;

const diagnostic = 'Invalid Phase 2 device authorization transport';
const authorizationFields = new Set<DeviceAuthorizationFieldName>([
  'client_id',
  'client_secret',
  'resource',
  'scope',
  'organization_id',
  'ui_locales',
]);
const verificationFieldNames = new Set(['xsrf', 'user_code', 'confirm', 'abort']);
const optionKeys = new Set([
  'target',
  'fetch',
  'maximumBodyBytes',
  'maximumHeaderBytes',
  'maximumRequestBodyBytes',
  'maximumRequestHeaderBytes',
  'maximumRequestUrlBytes',
  'maximumSensitiveVariants',
  'timeoutMs',
]);
const selectedResponseHeaders = new Set([
  'access-control-allow-origin',
  'access-control-expose-headers',
  'cache-control',
  'pragma',
  'referrer-policy',
  'x-content-type-options',
]);
const cookieNamePattern = /^[A-Za-z0-9!#$%&'*+.^_|~-]{1,128}$/u;
const fieldNamePattern = /^[A-Za-z][A-Za-z0-9_.~-]{0,127}$/u;
const mediaTypePattern =
  /^[A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9!#$&^_.+-]+(?:\s*;\s*[A-Za-z0-9!#$&^_.+-]+=[A-Za-z0-9!#$&^_.+"'~:-]+)*$/u;
const defaultMaximumBodyBytes = 64 * 1024;
const defaultMaximumHeaderBytes = 16 * 1024;
const maximumRequestBodyBytes = 16 * 1024;
const maximumRequestHeaderBytes = 16 * 1024;
const maximumRequestUrlBytes = 8192;
const maximumFieldBytes = 4096;
const maximumTimeoutMs = 60_000;
const maximumSensitiveVariants = 512;

const fail = (stage: string): never => {
  throw new TypeError(`${diagnostic} (${stage})`);
};

const encodeOauthBasicComponent = (value: string): string => {
  const encoded = new URLSearchParams([['value', value]]).toString();
  return encoded.slice('value='.length);
};

const registerSensitiveValue = (registry: SensitiveRegistry, value: string): void => {
  if (value.length === 0) {
    return;
  }
  const variants = [
    value,
    encodeOauthBasicComponent(value),
    (() => {
      try {
        return encodeURIComponent(value);
      } catch {
        return value;
      }
    })(),
    Buffer.from(value, 'utf8').toString('base64'),
    Buffer.from(value, 'utf8').toString('base64url'),
  ];
  const additions = new Set<string>();
  for (const variant of variants) {
    if (variant.length === 0 || variant.length > 64 * 1024) {
      fail(registry.stage);
    }
    if (!registry.values.has(variant)) {
      additions.add(variant);
    }
  }
  if (registry.values.size + additions.size > registry.maximum) {
    fail(registry.stage);
  }
  for (const variant of additions) {
    registry.values.add(variant);
  }
};

const isPlainRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  !nodeTypes.isProxy(value) &&
  Object.getPrototypeOf(value) === Object.prototype;

const hasOnlyKeys = (value: Record<string, unknown>, allowed: ReadonlySet<string>): boolean =>
  Reflect.ownKeys(value).every((key) => typeof key === 'string' && allowed.has(key));

const snapshotDataRecord = (
  value: unknown,
  allowed: ReadonlySet<string>,
  stage: string
): Readonly<Record<string, unknown>> => {
  if (!isPlainRecord(value)) {
    return fail(stage);
  }
  const keys = Reflect.ownKeys(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (keys.some((key) => typeof key !== 'string' || !allowed.has(key))) {
    return fail(stage);
  }
  const snapshot: Record<string, unknown> = {};
  for (const key of keys) {
    if (typeof key !== 'string') {
      return fail(stage);
    }
    const descriptor = descriptors[key];
    if (
      descriptor === undefined ||
      !Object.hasOwn(descriptor, 'value') ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined ||
      !descriptor.enumerable
    ) {
      return fail(stage);
    }
    snapshot[key] = descriptor.value as unknown;
  }
  return Object.freeze(snapshot);
};

const snapshotArray = (value: unknown, maximum: number, stage: string): readonly unknown[] => {
  if (
    !Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Array.prototype
  ) {
    return fail(stage);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value) as unknown as Record<
    PropertyKey,
    PropertyDescriptor
  >;
  const lengthDescriptor = descriptors.length;
  const length: unknown =
    lengthDescriptor !== undefined && Object.hasOwn(lengthDescriptor, 'value')
      ? (lengthDescriptor.value as unknown)
      : undefined;
  if (
    typeof length !== 'number' ||
    !Number.isSafeInteger(length) ||
    length < 0 ||
    length > maximum
  ) {
    return fail(stage);
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== length + 1 ||
    keys.some((key) => key !== 'length' && (typeof key !== 'string' || !/^\d+$/u.test(key)))
  ) {
    return fail(stage);
  }
  const snapshot: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (
      descriptor === undefined ||
      !Object.hasOwn(descriptor, 'value') ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined ||
      !descriptor.enumerable
    ) {
      return fail(stage);
    }
    snapshot.push(descriptor.value as unknown);
  }
  return Object.freeze(snapshot);
};

const fixedFailure = <Value>(stage: string, use: () => Value): Value => {
  try {
    return use();
  } catch {
    return fail(stage);
  }
};

const boundedString = (
  value: unknown,
  stage: string,
  maximum = maximumFieldBytes,
  allowEmpty = false
): string =>
  typeof value === 'string' &&
  (allowEmpty || value.length > 0) &&
  Buffer.byteLength(value) <= maximum &&
  !/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/u.test(value)
    ? value
    : fail(stage);

const boundedInteger = (
  value: unknown,
  fallback: number,
  minimum: number,
  maximum: number,
  stage: string
): number => {
  const selected = value ?? fallback;
  return Number.isSafeInteger(selected) &&
    Number(selected) >= minimum &&
    Number(selected) <= maximum
    ? Number(selected)
    : fail(stage);
};

const assertRequestBounds = (
  url: URL,
  headers: Headers,
  body: string | URLSearchParams | undefined,
  limits: RequestLimits,
  stage: string
): void => {
  if (Buffer.byteLength(url.href) > limits.url) {
    fail(stage);
  }
  let headerBytes = 0;
  for (const [name, value] of headers) {
    headerBytes += Buffer.byteLength(name) + Buffer.byteLength(value) + 4;
    if (headerBytes > limits.headers) {
      fail(stage);
    }
  }
  if (body !== undefined && Buffer.byteLength(String(body)) > limits.body) {
    fail(stage);
  }
};

const assertActive = (state: TransportState): void => {
  if (!state.active) {
    fail('cleared');
  }
};

const pruneExpiredState = (state: TransportState): void => {
  const now = Date.now();
  if (state.codesExpireAt !== undefined && state.codesExpireAt <= now) {
    state.deviceCode = undefined;
    state.userCode = undefined;
    state.codesExpireAt = undefined;
  }
  if (state.xsrfExpireAt !== undefined && state.xsrfExpireAt <= now) {
    state.xsrf = undefined;
    state.xsrfCookieIdentity = undefined;
    state.xsrfExpireAt = undefined;
  }
};

const cookieIdentity = (cookie: Cookie): string =>
  `${cookie.domain ?? ''}\n${cookie.path ?? ''}\n${cookie.key}`;

const createSensitiveRegistry = (
  state: TransportState,
  maximum: number,
  stage: string
): SensitiveRegistry => {
  pruneExpiredState(state);
  const registry: SensitiveRegistry = { values: new Set(), maximum, stage };
  for (const value of [state.deviceCode, state.userCode, state.xsrf]) {
    if (value !== undefined) {
      registerSensitiveValue(registry, value);
    }
  }
  const serialized = state.cookies.serializeSync();
  if (serialized === undefined || !Array.isArray(serialized.cookies)) {
    return fail(stage);
  }
  const now = Date.now();
  for (const rawCookie of serialized.cookies) {
    const cookie = Cookie.fromJSON(rawCookie);
    if (cookie === undefined) {
      return fail(stage);
    }
    const expireAt = cookie.expiryTime();
    if (expireAt === undefined) {
      return fail(stage);
    }
    if (expireAt > now) {
      registerSensitiveValue(registry, cookie.value);
    }
  }
  return registry;
};

const assertAvailable = (state: TransportState): void => {
  assertActive(state);
  pruneExpiredState(state);
  if (state.operationActive) {
    fail('concurrent');
  }
};

const beginRequest = (
  state: TransportState,
  timeoutMs: number
): Readonly<{ controller: AbortController; signal: AbortSignal }> => {
  assertAvailable(state);
  const controller = new AbortController();
  state.operationActive = true;
  state.controllers.add(controller);
  return Object.freeze({
    controller,
    signal: AbortSignal.any([controller.signal, AbortSignal.timeout(timeoutMs)]),
  });
};

const clearState = (state: TransportState): void => {
  state.deviceCode = undefined;
  state.userCode = undefined;
  state.codesExpireAt = undefined;
  state.xsrf = undefined;
  state.xsrfCookieIdentity = undefined;
  state.xsrfExpireAt = undefined;
  state.cookies.removeAllCookiesSync();
  for (const controller of state.controllers) {
    controller.abort();
  }
  state.controllers.clear();
  state.operationActive = false;
  state.active = false;
};

const snapshotState = (state: TransportState): TransportState => ({
  active: state.active,
  operationActive: state.operationActive,
  deviceCode: state.deviceCode,
  userCode: state.userCode,
  codesExpireAt: state.codesExpireAt,
  xsrf: state.xsrf,
  xsrfCookieIdentity: state.xsrfCookieIdentity,
  xsrfExpireAt: state.xsrfExpireAt,
  cookies: state.cookies.cloneSync() ?? fail('state'),
  controllers: state.controllers,
});

const finishProjection = (
  state: TransportState,
  next: TransportState,
  projection: DeviceAuthorizationProjection,
  registry: SensitiveRegistry,
  stage: string
): DeviceAuthorizationProjection => {
  const serialized = JSON.stringify(projection);
  const normalized = serialized.toLowerCase();
  if (
    containsCompactJwt(serialized) ||
    [...registry.values].some(
      (sensitive) => sensitive.length > 0 && normalized.includes(sensitive.toLowerCase())
    )
  ) {
    return fail(stage);
  }
  assertActive(state);
  state.deviceCode = next.deviceCode;
  state.userCode = next.userCode;
  state.codesExpireAt = next.codesExpireAt;
  state.xsrf = next.xsrf;
  state.xsrfCookieIdentity = next.xsrfCookieIdentity;
  state.xsrfExpireAt = next.xsrfExpireAt;
  state.cookies = next.cookies;
  return projection;
};

const safePublicString = (
  value: unknown,
  sensitiveValues: ReadonlySet<string>,
  stage: string,
  maximum = 1024
): string | undefined => {
  if (value === undefined || value === null) {
    return undefined;
  }
  const text = boundedString(value, stage, maximum, true);
  const normalized = text.toLowerCase();
  if (
    [...sensitiveValues].some(
      (sensitive) => sensitive.length > 0 && normalized.includes(sensitive.toLowerCase())
    ) ||
    containsCompactJwt(text) ||
    /\b(?:basic|bearer)\s+[A-Za-z0-9._~+/-]+=*/iu.test(text)
  ) {
    return fail(stage);
  }
  return text;
};

const cancelResponseBodySafely = async (
  body: ReadableStream<Uint8Array> | undefined
): Promise<void> => {
  if (body === undefined) {
    return;
  }
  try {
    await body.cancel();
  } catch {
    // Cancellation is best effort and must not replace the fixed public diagnostic.
  }
};

const readBoundedBody = async (
  response: Response,
  maximum: number,
  stage: string
): Promise<Uint8Array> => {
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > maximum)) {
    await response.body?.cancel();
    return fail(stage);
  }
  if (!response.body) {
    return new Uint8Array();
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    // eslint-disable-next-line no-constant-condition -- The reader's done flag terminates the loop.
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      length += value.byteLength;
      if (length > maximum) {
        await reader.cancel();
        return fail(stage);
      }
      chunks.push(value);
    }
  } catch {
    try {
      await reader.cancel();
    } catch {
      // Cancellation is best effort after a failed hostile stream read.
    }
    return fail(stage);
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
};

const normalizedContentType = (headers: Headers, stage: string): string | undefined => {
  const raw = headers.get('content-type');
  if (raw === null) {
    return undefined;
  }
  const value = raw.split(';', 1)[0]?.trim().toLowerCase();
  if (!value || Buffer.byteLength(value) > 128 || !mediaTypePattern.test(value)) {
    return fail(stage);
  }
  return value;
};

const projectHeaders = (
  headers: Headers,
  maximum: number,
  sensitiveValues: ReadonlySet<string>,
  suppressPublicStrings: boolean,
  stage: string
): Readonly<Record<string, string>> => {
  let total = 0;
  const selected: Array<readonly [string, string]> = [];
  for (const [rawName, rawValue] of headers) {
    const name = rawName.toLowerCase();
    total += Buffer.byteLength(name) + Buffer.byteLength(rawValue) + 4;
    if (total > maximum || ['authorization', 'proxy-authorization', 'cookie'].includes(name)) {
      return fail(stage);
    }
    if (!suppressPublicStrings && selectedResponseHeaders.has(name)) {
      const value = safePublicString(rawValue, sensitiveValues, stage, maximumFieldBytes);
      if (value === undefined) {
        return fail(stage);
      }
      selected.push([name, value]);
    }
  }
  selected.sort(([left], [right]) => left.localeCompare(right));
  return Object.freeze(Object.fromEntries(selected));
};

const responseSetCookies = (headers: Headers): readonly string[] => {
  const getSetCookie = headers.getSetCookie.bind(headers);
  return getSetCookie();
};

const mergeCookies = (
  state: TransportState,
  headers: Headers,
  requestUrl: URL,
  registry: SensitiveRegistry,
  stage: string
): readonly DeviceAuthorizationCookieProjection[] => {
  const projections: DeviceAuthorizationCookieProjection[] = [];
  for (const raw of responseSetCookies(headers)) {
    if (Buffer.byteLength(raw) > 8192) {
      return fail(stage);
    }
    const parsed = Cookie.parse(raw);
    const [, ...attributes] = raw.split(';').map((part) => part.trim());
    if (
      parsed === undefined ||
      !cookieNamePattern.test(parsed.key) ||
      Buffer.byteLength(parsed.value) > maximumFieldBytes ||
      /[\u0000-\u001F\u007F;]/u.test(parsed.value)
    ) {
      return fail(stage);
    }
    const options = attributes.map((attribute) => {
      const option = attribute.split('=', 1)[0]?.toLowerCase() ?? '';
      return cookieNamePattern.test(option) ? option : fail(stage);
    });
    if (new Set(options).size !== options.length) {
      return fail(stage);
    }
    options.sort();
    registerSensitiveValue(registry, parsed.value);
    let accepted: Cookie | undefined;
    try {
      accepted = state.cookies.setCookieSync(raw, requestUrl.href);
    } catch {
      return fail(stage);
    }
    if (accepted === undefined) {
      return fail(stage);
    }
    if (parsed.key.endsWith('_device_flow_xsrf')) {
      const identity = cookieIdentity(accepted);
      const expireAt = accepted.expiryTime();
      if (expireAt === undefined) {
        return fail(stage);
      }
      if (accepted.value.length > 0 && expireAt > Date.now()) {
        state.xsrf = accepted.value;
        state.xsrfCookieIdentity = identity;
        state.xsrfExpireAt = expireAt;
      } else if (state.xsrfCookieIdentity === identity) {
        state.xsrf = undefined;
        state.xsrfCookieIdentity = undefined;
        state.xsrfExpireAt = undefined;
      }
    }
    const serialized = state.cookies.serializeSync();
    if (
      serialized === undefined ||
      !Array.isArray(serialized.cookies) ||
      serialized.cookies.length > 16
    ) {
      return fail(stage);
    }
    projections.push(Object.freeze({ name: parsed.key, options: Object.freeze(options) }));
  }
  projections.sort(({ name: left }, { name: right }) => left.localeCompare(right));
  return Object.freeze(projections);
};

const projectUrl = (
  value: unknown,
  base: URL,
  stage: string
): DeviceAuthorizationUrlProjection | undefined => {
  if (value === undefined || value === null) {
    return undefined;
  }
  const raw = boundedString(value, stage, 8192);
  let url: URL;
  try {
    url = new URL(raw, base);
  } catch {
    return fail(stage);
  }
  if (
    !['http:', 'https:'].includes(url.protocol) ||
    url.username.length > 0 ||
    url.password.length > 0 ||
    url.hash.length > 0
  ) {
    return fail(stage);
  }
  const queryKeys = [...new Set(url.searchParams.keys())];
  if (queryKeys.some((key) => !fieldNamePattern.test(key))) {
    return fail(stage);
  }
  queryKeys.sort();
  return Object.freeze({
    origin: url.origin,
    path: url.pathname,
    queryKeys: Object.freeze(queryKeys),
  });
};

const numberField = (value: unknown, stage: string): number | undefined => {
  if (value === undefined) {
    return undefined;
  }
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= 86_400
    ? value
    : fail(stage);
};

const positiveExpiryField = (value: unknown, stage: string): number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value > 0 && value <= 86_400
    ? value
    : fail(stage);

const userCodeShape = (
  value: string | undefined
): DeviceAuthorizationProjection['userCodeShape'] => {
  if (value === undefined) {
    return undefined;
  }
  const groups = value.split('-').map((group) => [...group].length);
  return Object.freeze({
    length: [...value].length,
    groups: Object.freeze(groups),
    separator: value.includes('-') ? '-' : undefined,
    matchesReferencePattern: /^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/u.test(value),
  });
};

const emptyExperience = undefined;
const challengeTokenPattern = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u;
const challengeParameterNames = new Set(['realm', 'error', 'error_description', 'scope']);
const challengeParameterPattern =
  /\s*([\w!#$%&'*+.^`|~-]+)\s*=\s*(?:"((?:\\.|[^"\\])*)"|([\w!#$%&'*+.^`|~-]+))\s*(?:,|$)/gy;

const projectChallenge = (
  headers: Headers,
  base: URL,
  sensitiveValues: ReadonlySet<string>,
  suppressPublicStrings: boolean,
  stage: string
): DeviceAuthorizationChallengeProjection | undefined => {
  const raw = headers.get('www-authenticate');
  if (raw === null || suppressPublicStrings) {
    return undefined;
  }
  const challenge = boundedString(raw, stage, maximumFieldBytes);
  if (/[\u0000-\u001F\u007F]/u.test(challenge)) {
    return fail(stage);
  }
  const separator = challenge.search(/[ \t]/u);
  const rawScheme = separator < 0 ? challenge : challenge.slice(0, separator);
  if (!challengeTokenPattern.test(rawScheme)) {
    return fail(stage);
  }
  const scheme = safePublicString(rawScheme.toLowerCase(), sensitiveValues, stage, 64);
  if (scheme === undefined) {
    return fail(stage);
  }
  const remainder = separator < 0 ? '' : challenge.slice(separator).trim();
  const parameters: Record<string, string> = {};
  let offset = 0;
  while (offset < remainder.length) {
    challengeParameterPattern.lastIndex = offset;
    const match = challengeParameterPattern.exec(remainder);
    if (match === null || match.index !== offset) {
      return fail(stage);
    }
    const name = match[1]?.toLowerCase();
    if (
      name === undefined ||
      !challengeParameterNames.has(name) ||
      Object.hasOwn(parameters, name)
    ) {
      return fail(stage);
    }
    const rawValue = match[2] === undefined ? match[3] : match[2].replaceAll(/\\(.)/gu, '$1');
    const value = safePublicString(rawValue, sensitiveValues, stage, 1024);
    if (value === undefined) {
      return fail(stage);
    }
    const expectedRealm = new URL('/oidc', base).href;
    parameters[name] = name === 'realm' && value === expectedRealm ? '<target-issuer>' : value;
    offset = challengeParameterPattern.lastIndex;
  }
  return Object.freeze({ scheme, parameters: Object.freeze(parameters) });
};

const suppressResponseStrings = (
  projection: DeviceAuthorizationProjection
): DeviceAuthorizationProjection =>
  Object.freeze({
    status: projection.status,
    contentType: undefined,
    headers: Object.freeze({}),
    keys: Object.freeze([]),
    cookies: Object.freeze([]),
    challenge: undefined,
    location: undefined,
    oauthError: Object.freeze({ category: undefined, description: undefined }),
    userCodeShape:
      projection.userCodeShape === undefined
        ? undefined
        : Object.freeze({
            length: projection.userCodeShape.length,
            groups: projection.userCodeShape.groups,
            separator: undefined,
            matchesReferencePattern: projection.userCodeShape.matchesReferencePattern,
          }),
    deviceCodeShape: projection.deviceCodeShape,
    expiresIn: projection.expiresIn,
    interval: projection.interval,
    verificationUri: undefined,
    verificationUriComplete: undefined,
    experience: undefined,
  });

const projectRedirectError = (
  rawLocation: string | undefined,
  base: URL,
  sensitiveValues: ReadonlySet<string>,
  stage: string
): Readonly<{ category: string | undefined; description: string | undefined }> => {
  if (rawLocation === undefined) {
    return Object.freeze({ category: undefined, description: undefined });
  }
  let location: URL;
  try {
    location = new URL(rawLocation, base);
  } catch {
    return fail(stage);
  }
  return Object.freeze({
    category: safePublicString(location.searchParams.get('error'), sensitiveValues, stage, 256),
    description: safePublicString(
      location.searchParams.get('error_description'),
      sensitiveValues,
      stage,
      2048
    ),
  });
};

const projectExperience = (
  body: string,
  base: URL,
  sensitiveValues: ReadonlySet<string>,
  stage: string
): NonNullable<DeviceAuthorizationProjection['experience']> => {
  const titleMatch = /<title\b[^>]*>([^<]*)<\/title>/iu.exec(body)?.[1]?.trim();
  const action = /<form\b[^>]*\baction=["']([^"']+)["']/iu.exec(body)?.[1];
  const inputNames = [...body.matchAll(/<input\b[^>]*\bname=["']([^"']+)["']/giu)].map((match) =>
    boundedString(match[1], stage, 128)
  );
  if (inputNames.length > 32 || inputNames.some((name) => !fieldNamePattern.test(name))) {
    return fail(stage);
  }
  inputNames.sort();
  return Object.freeze({
    title: safePublicString(titleMatch, sensitiveValues, stage, 256),
    formAction: projectUrl(action, base, stage),
    inputNames: Object.freeze(inputNames),
    autoSubmit: /\bsubmit\s*\(\s*\)/iu.test(body),
  });
};

const projectResponseUnchecked = async (
  response: Response,
  base: URL,
  requestUrl: URL,
  state: TransportState,
  limits: ResponseLimits,
  requestSensitiveValues: readonly string[],
  maximumSensitiveValues: number,
  suppressPublicStrings: boolean,
  operation: DeviceResponseOperation,
  stage: string
): Promise<DeviceAuthorizationProjection> => {
  if (response.redirected || response.status < 100 || response.status > 599) {
    await response.body?.cancel();
    return fail(stage);
  }
  assertActive(state);
  const next = snapshotState(state);
  const registry = createSensitiveRegistry(next, maximumSensitiveValues, stage);
  for (const sensitive of requestSensitiveValues) {
    registerSensitiveValue(registry, sensitive);
  }
  const cookies = mergeCookies(next, response.headers, requestUrl, registry, stage);
  const headers = projectHeaders(
    response.headers,
    limits.headers,
    registry.values,
    suppressPublicStrings,
    stage
  );
  const contentType = normalizedContentType(response.headers, stage);
  const challenge = projectChallenge(
    response.headers,
    base,
    registry.values,
    suppressPublicStrings,
    stage
  );
  const rawLocation = response.headers.get('location') ?? undefined;
  const location = projectUrl(rawLocation, base, stage);
  const bytes = await readBoundedBody(response, limits.body, stage);
  const bodyText = new TextDecoder('utf8', { fatal: true }).decode(bytes);
  const successfulAuthorization =
    operation === 'authorization' && response.status >= 200 && response.status < 300;
  if (contentType !== 'application/json') {
    if (successfulAuthorization) {
      return fail(stage);
    }
    if (
      (bodyText.length > 0 && contentType === undefined) ||
      (contentType !== undefined && !['text/html', 'text/plain'].includes(contentType))
    ) {
      return fail(stage);
    }
    if (contentType === 'text/plain' && !suppressPublicStrings) {
      safePublicString(bodyText, registry.values, stage, limits.body);
    }
    const projection: DeviceAuthorizationProjection = Object.freeze({
      status: response.status,
      contentType,
      headers,
      keys: Object.freeze([]),
      cookies,
      challenge,
      location,
      oauthError: suppressPublicStrings
        ? Object.freeze({ category: undefined, description: undefined })
        : projectRedirectError(rawLocation, base, registry.values, stage),
      userCodeShape: undefined,
      deviceCodeShape: undefined,
      expiresIn: undefined,
      interval: undefined,
      verificationUri: undefined,
      verificationUriComplete: undefined,
      experience:
        contentType === 'text/html' && !suppressPublicStrings
          ? projectExperience(bodyText, base, registry.values, stage)
          : emptyExperience,
    });
    return finishProjection(
      state,
      next,
      suppressPublicStrings ? suppressResponseStrings(projection) : projection,
      registry,
      stage
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(bodyText) as unknown;
  } catch {
    return fail(stage);
  }
  if (!isPlainRecord(parsed)) {
    return fail(stage);
  }
  const deviceCode =
    parsed.device_code === undefined
      ? undefined
      : boundedString(parsed.device_code, stage, maximumFieldBytes);
  const userCode =
    parsed.user_code === undefined
      ? undefined
      : boundedString(parsed.user_code, stage, maximumFieldBytes);
  const expiresIn = successfulAuthorization
    ? positiveExpiryField(parsed.expires_in, stage)
    : numberField(parsed.expires_in, stage);
  if (successfulAuthorization && (deviceCode === undefined || userCode === undefined)) {
    return fail(stage);
  }
  if (deviceCode !== undefined) {
    registerSensitiveValue(registry, deviceCode);
  }
  if (userCode !== undefined) {
    registerSensitiveValue(registry, userCode);
  }
  if (successfulAuthorization && deviceCode !== undefined && userCode !== undefined) {
    if (expiresIn === undefined) {
      return fail(stage);
    }
    next.deviceCode = deviceCode;
    next.userCode = userCode;
    next.codesExpireAt = Date.now() + expiresIn * 1000;
  }
  for (const tokenField of ['access_token', 'refresh_token', 'id_token'] as const) {
    if (parsed[tokenField] !== undefined) {
      registerSensitiveValue(registry, boundedString(parsed[tokenField], stage, 16 * 1024));
    }
  }
  const keys = Object.keys(parsed).sort();
  if (keys.length > 32 || keys.some((key) => !fieldNamePattern.test(key))) {
    return fail(stage);
  }
  const projection = Object.freeze({
    status: response.status,
    contentType,
    headers,
    keys: Object.freeze(keys),
    cookies,
    challenge,
    location,
    oauthError: suppressPublicStrings
      ? Object.freeze({ category: undefined, description: undefined })
      : parsed.error === undefined && parsed.error_description === undefined
        ? projectRedirectError(rawLocation, base, registry.values, stage)
        : Object.freeze({
            category: safePublicString(parsed.error, registry.values, stage, 256),
            description: safePublicString(parsed.error_description, registry.values, stage, 2048),
          }),
    userCodeShape: userCodeShape(userCode),
    deviceCodeShape:
      deviceCode === undefined ? undefined : Object.freeze({ length: [...deviceCode].length }),
    expiresIn,
    interval: numberField(parsed.interval, stage),
    verificationUri: projectUrl(parsed.verification_uri, base, stage),
    verificationUriComplete: projectUrl(parsed.verification_uri_complete, base, stage),
    experience: emptyExperience,
  });
  return finishProjection(
    state,
    next,
    suppressPublicStrings ? suppressResponseStrings(projection) : projection,
    registry,
    stage
  );
};

const projectResponse = async (
  response: Response,
  base: URL,
  requestUrl: URL,
  state: TransportState,
  limits: ResponseLimits,
  requestSensitiveValues: readonly string[],
  maximumSensitiveValues: number,
  suppressPublicStrings: boolean,
  operation: DeviceResponseOperation,
  stage: string
): Promise<DeviceAuthorizationProjection> => {
  try {
    return await projectResponseUnchecked(
      response,
      base,
      requestUrl,
      state,
      limits,
      requestSensitiveValues,
      maximumSensitiveValues,
      suppressPublicStrings,
      operation,
      stage
    );
  } catch {
    await cancelResponseBodySafely(response.body ?? undefined);
    return fail(stage);
  }
};

const prepareAuthorization = (
  request: DeviceAuthorizationRequest
): Readonly<{
  body: BodyInit;
  contentType: string;
  sensitiveValues: readonly string[];
  suppressPublicStrings: boolean;
}> => {
  const input = snapshotDataRecord(
    request,
    new Set(['encoding', 'fields', 'mediaType', 'body', 'sensitiveFragments']),
    'authorization-request'
  );
  const { encoding } = input;
  if (!['form', 'json', 'raw'].includes(String(encoding))) {
    return fail('authorization-request');
  }
  if (encoding === 'raw') {
    if (!hasOnlyKeys(input, new Set(['encoding', 'mediaType', 'body', 'sensitiveFragments']))) {
      return fail('authorization-request');
    }
    const mediaType = boundedString(input.mediaType, 'authorization-request', 256);
    const body = boundedString(input.body, 'authorization-request', maximumRequestBodyBytes, true);
    if (!mediaTypePattern.test(mediaType)) {
      return fail('authorization-request');
    }
    const fragments =
      input.sensitiveFragments === undefined
        ? Object.freeze([])
        : snapshotArray(input.sensitiveFragments, 32, 'authorization-request');
    const sensitiveValues = [body];
    for (const fragment of fragments) {
      sensitiveValues.push(boundedString(fragment, 'authorization-request', maximumFieldBytes));
    }
    return Object.freeze({
      body,
      contentType: mediaType,
      sensitiveValues: Object.freeze(sensitiveValues),
      suppressPublicStrings: true,
    });
  }
  if (!hasOnlyKeys(input, new Set(['encoding', 'fields']))) {
    return fail('authorization-request');
  }
  const entries: Array<readonly [DeviceAuthorizationFieldName, string]> = [];
  if (encoding === 'form') {
    const fields = snapshotArray(input.fields, 16, 'authorization-request');
    for (const field of fields) {
      const candidate = snapshotArray(field, 2, 'authorization-request');
      if (candidate.length !== 2) {
        return fail('authorization-request');
      }
      const name = candidate[0];
      const value = candidate[1];
      if (
        typeof name !== 'string' ||
        !authorizationFields.has(name as DeviceAuthorizationFieldName)
      ) {
        return fail('authorization-request');
      }
      entries.push([
        name as DeviceAuthorizationFieldName,
        boundedString(value, 'authorization-request', maximumFieldBytes, true),
      ]);
    }
  } else {
    const fields = snapshotDataRecord(input.fields, authorizationFields, 'authorization-request');
    for (const name of authorizationFields) {
      if (Object.hasOwn(fields, name)) {
        entries.push([
          name,
          boundedString(fields[name], 'authorization-request', maximumFieldBytes, true),
        ]);
      }
    }
  }
  const sensitiveValues = entries
    .filter(([name]) => name === 'client_secret')
    .map(([, value]) => value);
  if (encoding === 'form') {
    const body = new URLSearchParams();
    for (const [name, value] of entries) {
      body.append(name, value);
    }
    if (Buffer.byteLength(body.toString()) > maximumRequestBodyBytes) {
      return fail('authorization-request');
    }
    return Object.freeze({
      body,
      contentType: 'application/x-www-form-urlencoded',
      sensitiveValues: Object.freeze(sensitiveValues),
      suppressPublicStrings: false,
    });
  }
  const body = JSON.stringify(Object.fromEntries(entries));
  if (Buffer.byteLength(body) > maximumRequestBodyBytes) {
    return fail('authorization-request');
  }
  return Object.freeze({
    body,
    contentType: 'application/json',
    sensitiveValues: Object.freeze(sensitiveValues),
    suppressPublicStrings: false,
  });
};

const resolveSecretValue = (
  value: DeviceAuthorizationSecretValue,
  expected: 'device-code' | 'user-code' | 'xsrf',
  state: TransportState,
  stage: string
): string => {
  if (typeof value === 'string') {
    const literal = boundedString(value, stage, maximumFieldBytes, true);
    return literal;
  }
  const reference = snapshotDataRecord(value, new Set(['stored']), stage);
  if (reference.stored !== expected) {
    return fail(stage);
  }
  const stored =
    expected === 'device-code'
      ? state.deviceCode
      : expected === 'user-code'
        ? state.userCode
        : state.xsrf;
  return stored ?? fail(stage);
};

const cookieHeader = (state: TransportState, url: URL, stage: string): string | undefined => {
  try {
    const value = state.cookies.getCookieStringSync(url.href);
    return value.length === 0 ? undefined : value;
  } catch {
    return fail(stage);
  }
};

const prepareVerification = (
  request: DeviceVerificationRequest,
  base: URL,
  state: TransportState
): Readonly<{
  url: URL;
  method: 'GET' | 'POST';
  body?: URLSearchParams;
  sensitiveValues: readonly string[];
}> => {
  const stage = 'verification-request';
  const input = snapshotDataRecord(
    request,
    new Set(['method', 'path', 'userCode', 'fields']),
    stage
  );
  const { method } = input;
  const { path } = input;
  if (
    !['GET', 'POST'].includes(String(method)) ||
    !['/device', '/oidc/device'].includes(String(path))
  ) {
    return fail(stage);
  }
  const requestMethod = method as 'GET' | 'POST';
  const url = new URL(String(path), base);
  if (requestMethod === 'GET') {
    if (!hasOnlyKeys(input, new Set(['method', 'path', 'userCode']))) {
      return fail(stage);
    }
    const sensitiveValues: string[] = [];
    if (input.userCode !== undefined) {
      const value = resolveSecretValue(
        input.userCode as DeviceAuthorizationSecretValue,
        'user-code',
        state,
        stage
      );
      url.searchParams.set('user_code', value);
      sensitiveValues.push(value);
    }
    return Object.freeze({
      url,
      method: requestMethod,
      sensitiveValues: Object.freeze(sensitiveValues),
    });
  }
  if (!hasOnlyKeys(input, new Set(['method', 'path', 'fields'])) || input.fields === undefined) {
    return fail(stage);
  }
  const fields = snapshotDataRecord(input.fields, verificationFieldNames, stage);
  const body = new URLSearchParams();
  const sensitiveValues: string[] = [];
  if (fields.xsrf !== undefined) {
    const value = resolveSecretValue(
      fields.xsrf as DeviceAuthorizationSecretValue,
      'xsrf',
      state,
      stage
    );
    body.set('xsrf', value);
    sensitiveValues.push(value);
  }
  if (fields.user_code !== undefined) {
    const value = resolveSecretValue(
      fields.user_code as DeviceAuthorizationSecretValue,
      'user-code',
      state,
      stage
    );
    body.set('user_code', value);
    sensitiveValues.push(value);
  }
  for (const field of ['confirm', 'abort'] as const) {
    const value = fields[field];
    if (value !== undefined) {
      body.set(field, boundedString(value, stage, 256, true));
    }
  }
  return Object.freeze({
    url,
    method: requestMethod,
    body,
    sensitiveValues: Object.freeze(sensitiveValues),
  });
};

const prepareTokenPoll = (
  request: DeviceTokenPollingRequest,
  state: TransportState
): Readonly<{
  body: URLSearchParams;
  authorization?: string;
  sensitiveValues: readonly string[];
}> => {
  const stage = 'token-request';
  const input = snapshotDataRecord(request, new Set(['proof', 'deviceCode']), stage);
  if (input.proof === undefined) {
    return fail(stage);
  }
  const proofInput = snapshotDataRecord(
    input.proof,
    new Set(['method', 'clientId', 'clientSecret']),
    stage
  );
  const { method } = proofInput;
  if (!['public', 'basic', 'post'].includes(String(method))) {
    return fail(stage);
  }
  const expectedProofKeys =
    method === 'public'
      ? new Set(['method', 'clientId'])
      : new Set(['method', 'clientId', 'clientSecret']);
  if (!hasOnlyKeys(proofInput, expectedProofKeys)) {
    return fail(stage);
  }
  const clientId = boundedString(proofInput.clientId, stage, maximumFieldBytes);
  const deviceCode =
    input.deviceCode === undefined
      ? resolveSecretValue({ stored: 'device-code' }, 'device-code', state, stage)
      : resolveSecretValue(
          input.deviceCode as DeviceAuthorizationSecretValue,
          'device-code',
          state,
          stage
        );
  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
    device_code: deviceCode,
  });
  const sensitiveValues = [deviceCode];
  if (method === 'public') {
    body.set('client_id', clientId);
    return Object.freeze({ body, sensitiveValues: Object.freeze(sensitiveValues) });
  }
  const clientSecret = boundedString(proofInput.clientSecret, stage, maximumFieldBytes);
  const encodedClientId = encodeOauthBasicComponent(clientId);
  const encodedClientSecret = encodeOauthBasicComponent(clientSecret);
  sensitiveValues.push(clientSecret, encodedClientSecret);
  if (method === 'post') {
    body.set('client_id', clientId);
    body.set('client_secret', clientSecret);
    return Object.freeze({ body, sensitiveValues: Object.freeze(sensitiveValues) });
  }
  const payload = Buffer.from(`${encodedClientId}:${encodedClientSecret}`, 'utf8').toString(
    'base64'
  );
  const authorization = `Basic ${payload}`;
  sensitiveValues.push(payload, authorization);
  return Object.freeze({
    body,
    authorization,
    sensitiveValues: Object.freeze(sensitiveValues),
  });
};

export const createDeviceAuthorizationTransportLease = (
  options: DeviceAuthorizationTransportOptions
): DeviceAuthorizationTransportLease => {
  const input = fixedFailure('options', () => snapshotDataRecord(options, optionKeys, 'options'));
  const target = fixedFailure('options', () =>
    validateTargetConfig(
      snapshotDataRecord(input.target, new Set(['label', 'coreUrl', 'adminUrl']), 'options')
    )
  );
  const requestFetchInput = input.fetch ?? fetch;
  if (typeof requestFetchInput !== 'function') {
    return fail('options');
  }
  const requestFetch = requestFetchInput as typeof fetch;
  const limits = Object.freeze({
    body: boundedInteger(
      input.maximumBodyBytes,
      defaultMaximumBodyBytes,
      1,
      defaultMaximumBodyBytes,
      'options'
    ),
    headers: boundedInteger(
      input.maximumHeaderBytes,
      defaultMaximumHeaderBytes,
      1,
      defaultMaximumHeaderBytes,
      'options'
    ),
  });
  const requestLimits = Object.freeze({
    body: boundedInteger(
      input.maximumRequestBodyBytes,
      maximumRequestBodyBytes,
      1,
      maximumRequestBodyBytes,
      'options'
    ),
    headers: boundedInteger(
      input.maximumRequestHeaderBytes,
      maximumRequestHeaderBytes,
      1,
      maximumRequestHeaderBytes,
      'options'
    ),
    url: boundedInteger(
      input.maximumRequestUrlBytes,
      maximumRequestUrlBytes,
      1,
      maximumRequestUrlBytes,
      'options'
    ),
  });
  const sensitiveVariantLimit = boundedInteger(
    input.maximumSensitiveVariants,
    maximumSensitiveVariants,
    1,
    maximumSensitiveVariants,
    'options'
  );
  const timeoutMs = boundedInteger(input.timeoutMs, 10_000, 1, maximumTimeoutMs, 'options');
  const base = new URL(target.coreUrl);
  const state: TransportState = {
    active: true,
    operationActive: false,
    cookies: new CookieJar(undefined, { allowSpecialUseDomain: true }),
    controllers: new Set(),
  };
  const lease: DeviceAuthorizationTransportLease = Object.freeze({
    requestAuthorization: async (
      request: DeviceAuthorizationRequest
    ): Promise<DeviceAuthorizationProjection> => {
      assertAvailable(state);
      const prepared = fixedFailure('authorization-request', () => prepareAuthorization(request));
      const url = new URL('/oidc/device/auth', base);
      const headers = new Headers({ 'content-type': prepared.contentType });
      fixedFailure('authorization-request', () => {
        assertRequestBounds(
          url,
          headers,
          prepared.body as string | URLSearchParams,
          requestLimits,
          'authorization-request'
        );
      });
      const control = beginRequest(state, timeoutMs);
      try {
        let response: Response;
        try {
          response = await requestFetch(url, {
            method: 'POST',
            headers,
            body: prepared.body,
            redirect: 'manual',
            signal: control.signal,
          });
        } catch {
          return fail('authorization-request');
        }
        try {
          return await projectResponse(
            response,
            base,
            url,
            state,
            limits,
            prepared.sensitiveValues,
            sensitiveVariantLimit,
            prepared.suppressPublicStrings,
            'authorization',
            'authorization-response'
          );
        } catch {
          return fail('authorization-response');
        }
      } finally {
        state.controllers.delete(control.controller);
        state.operationActive = false;
      }
    },
    requestVerification: async (
      request: DeviceVerificationRequest
    ): Promise<DeviceAuthorizationProjection> => {
      assertAvailable(state);
      const prepared = fixedFailure('verification-request', () =>
        prepareVerification(request, base, state)
      );
      const headers = new Headers();
      const cookies = cookieHeader(state, prepared.url, 'verification-request');
      if (cookies !== undefined) {
        headers.set('cookie', cookies);
      }
      if (prepared.method === 'POST') {
        headers.set('content-type', 'application/x-www-form-urlencoded');
      }
      fixedFailure('verification-request', () => {
        assertRequestBounds(
          prepared.url,
          headers,
          prepared.body,
          requestLimits,
          'verification-request'
        );
      });
      const control = beginRequest(state, timeoutMs);
      try {
        let response: Response;
        try {
          response = await requestFetch(prepared.url, {
            method: prepared.method,
            headers,
            ...(prepared.body === undefined ? {} : { body: prepared.body }),
            redirect: 'manual',
            signal: control.signal,
          });
        } catch {
          return fail('verification-request');
        }
        try {
          return await projectResponse(
            response,
            base,
            prepared.url,
            state,
            limits,
            prepared.sensitiveValues,
            sensitiveVariantLimit,
            false,
            'verification',
            'verification-response'
          );
        } catch {
          return fail('verification-response');
        }
      } finally {
        state.controllers.delete(control.controller);
        state.operationActive = false;
      }
    },
    pollToken: async (
      request: DeviceTokenPollingRequest
    ): Promise<DeviceAuthorizationProjection> => {
      assertAvailable(state);
      const prepared = fixedFailure('token-request', () => prepareTokenPoll(request, state));
      const headers = new Headers({ 'content-type': 'application/x-www-form-urlencoded' });
      if (prepared.authorization !== undefined) {
        headers.set('authorization', prepared.authorization);
      }
      const url = new URL('/oidc/token', base);
      fixedFailure('token-request', () => {
        assertRequestBounds(url, headers, prepared.body, requestLimits, 'token-request');
      });
      const control = beginRequest(state, timeoutMs);
      try {
        let response: Response;
        try {
          response = await requestFetch(url, {
            method: 'POST',
            headers,
            body: prepared.body,
            redirect: 'manual',
            signal: control.signal,
          });
        } catch {
          return fail('token-request');
        }
        try {
          return await projectResponse(
            response,
            base,
            url,
            state,
            limits,
            prepared.sensitiveValues,
            sensitiveVariantLimit,
            false,
            'token',
            'token-response'
          );
        } catch {
          return fail('token-response');
        }
      } finally {
        state.controllers.delete(control.controller);
        state.operationActive = false;
      }
    },
    clear: () => {
      clearState(state);
    },
    toJSON: (): never => fail('lease'),
  });
  return lease;
};

/* eslint-enable complexity, max-lines, max-params, no-await-in-loop, no-control-regex, no-restricted-syntax, @typescript-eslint/no-unnecessary-condition, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
