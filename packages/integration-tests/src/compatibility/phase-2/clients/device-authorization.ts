/* eslint-disable complexity, max-lines, max-params, no-await-in-loop, no-control-regex, no-restricted-syntax, unicorn/prefer-switch, @typescript-eslint/no-unnecessary-condition, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- This boundary owns a short-lived secret store, cookie jar, and bounded hostile HTTP surfaces. */
import { types as nodeTypes } from 'node:util';

import { Cookie, CookieJar } from 'tough-cookie';

import { validateTargetConfig } from '../../config.js';
import type { TargetConfig } from '../../model.js';
import {
  assertDeviceAuthorizationEvidenceIsSanitized,
  publishDeviceAuthorizationProjection,
  publishDeviceLifecycleProjection,
  type DeviceAuthorizationChallengeProjection,
  type DeviceAuthorizationCookieProjection,
  type DeviceAuthorizationProjection,
  type DeviceAuthorizationUrlProjection,
  type DeviceLifecycleKind,
  type DeviceLifecycleProjection,
} from '../projections/device-authorization.js';

import { containsCompactJwt } from './client-credentials.js';

export type DeviceAuthorizationFieldName =
  | 'client_id'
  | 'client_secret'
  | 'resource'
  | 'scope'
  | 'organization_id'
  | 'ui_locales'
  | 'request_uri';

export type DeviceAuthorizationTransportControl = Readonly<{
  query?: ReadonlyArray<readonly [DeviceAuthorizationFieldName, string]>;
  proof?: Readonly<{ method: 'basic'; clientId: string; clientSecret: string }>;
}>;

export type DeviceAuthorizationRequest = (
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
    }>
) &
  Readonly<{ transport?: DeviceAuthorizationTransportControl }>;

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
  | Readonly<{ method: 'FOLLOW_PROJECTED_LOCATION' }>
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

export type {
  DeviceAuthorizationChallengeProjection,
  DeviceAuthorizationCookieProjection,
  DeviceAuthorizationProjection,
  DeviceAuthorizationUrlProjection,
  DeviceLifecycleProjection,
} from '../projections/device-authorization.js';

export type DeviceLifecycleRequest =
  | Readonly<{ kind: 'verification-success'; method: 'GET' }>
  | Readonly<{ kind: 'experience-open'; method: 'PUT' }>
  | Readonly<{
      kind: 'password-verification';
      method: 'POST';
      username: string;
      password: string;
    }>
  | Readonly<{ kind: 'identification'; method: 'POST' }>
  | Readonly<{ kind: 'experience-submit'; method: 'POST' }>
  | Readonly<{ kind: 'consent-read'; method: 'GET' }>
  | Readonly<{ kind: 'consent-write'; method: 'POST' }>
  | Readonly<{ kind: 'resume'; method: 'GET' }>
  | Readonly<{
      kind: 'refresh';
      method: 'POST';
      proof: DeviceAuthorizationClientProof;
      scope?: string;
      resource?: string;
      organizationId?: string;
    }>
  | Readonly<{
      kind: 'userinfo';
      method: 'GET';
      expectedSubjectId: string;
    }>
  | Readonly<{
      kind: 'introspection' | 'revocation';
      method: 'POST';
      proof: DeviceAuthorizationClientProof;
      token: 'access' | 'refresh';
      hint?: 'access_token' | 'refresh_token';
      expectedSubjectId?: string;
      expectedClientId?: string;
    }>
  | Readonly<{
      kind: 'logout-open';
      method: 'GET';
      clientId: string;
      postLogoutRedirectUri?: string;
      state?: string;
    }>
  | Readonly<{ kind: 'logout-confirm'; method: 'POST'; confirm: boolean }>
  | Readonly<{ kind: 'oidc-discovery' | 'oauth-discovery'; method: 'GET' }>;

export type DeviceCredentialLease = Readonly<{
  getAccessToken(): string | undefined;
  getRefreshToken(): string | undefined;
  getIdToken(): string | undefined;
  getPreviousRefreshToken(): string | undefined;
  toJSON(): never;
}>;

export type DeviceVerificationXsrfLease = Readonly<{
  getXsrf(): string;
  toJSON(): never;
}>;

export type DeviceVerificationUserCodeLease = Readonly<{
  getUserCode(): string;
  getXsrf(): string;
  toJSON(): never;
}>;

export type DeviceCodeLease = Readonly<{
  getDeviceCode(): string;
  toJSON(): never;
}>;

export type DeviceAuthorizationSecretLease = Readonly<{
  getDeviceCode(): string;
  getUserCode(): string;
  getXsrf(): string;
  toJSON(): never;
}>;

export type DeviceEvidenceSecretLease = Readonly<{
  getDeviceCode(): string;
  getUserCode(): string;
  getAuditXsrf(): string;
  getAccessToken(): string | undefined;
  getRefreshToken(): string | undefined;
  getIdToken(): string | undefined;
  toJSON(): never;
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
  requestLifecycle(request: DeviceLifecycleRequest): Promise<DeviceLifecycleProjection>;
  withCredentialLease<Result>(
    use: (lease: DeviceCredentialLease) => Result | Promise<Result>
  ): Promise<Result>;
  withVerificationXsrfLease<Result>(
    use: (lease: DeviceVerificationXsrfLease) => Result | Promise<Result>
  ): Promise<Result>;
  withVerificationUserCodeLease<Result>(
    use: (lease: DeviceVerificationUserCodeLease) => Result | Promise<Result>
  ): Promise<Result>;
  withDeviceCodeLease<Result>(
    use: (lease: DeviceCodeLease) => Result | Promise<Result>
  ): Promise<Result>;
  withAuthorizationSecretLease?<Result>(
    use: (lease: DeviceAuthorizationSecretLease) => Result | Promise<Result>
  ): Promise<Result>;
  withEvidenceSecretLease?<Result>(
    use: (lease: DeviceEvidenceSecretLease) => Result | Promise<Result>
  ): Promise<Result>;
  clear(): void;
  toJSON(): never;
}>;

type TransportState = {
  targetLabel: 'oracle' | 'candidate';
  active: boolean;
  operationActive: boolean;
  deviceCode?: string;
  userCode?: string;
  codesExpireAt?: number;
  xsrf?: string;
  auditXsrf?: string;
  auditXsrfExpireAt?: number;
  xsrfCookieIdentity?: string;
  xsrfExpireAt?: number;
  verificationId?: string;
  verificationFollowUrl?: string;
  resumeUrl?: string;
  resumeStage?: 'after-experience-submit' | 'after-consent-write';
  logoutXsrf?: string;
  logoutAction?: string;
  logoutRedirectUri?: string;
  logoutState?: string;
  accessToken?: string;
  refreshToken?: string;
  previousRefreshToken?: string;
  idToken?: string;
  accessExpireAt?: number;
  credentialLeaseActive: boolean;
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
  'request_uri',
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
const sensitiveResponseKeyPattern =
  /^(?:authorization|proxy.?authorization|cookie|set.?cookie|password|client.?secret|access.?token|refresh.?token|id.?token|device.?code|user.?code|xsrf|verification.?id|redirect.?to)$/iu;
const referenceCookieNameMappings = new Map<string, string>([
  ['_logto', '_aster'],
  ['_logto.sig', '_aster.sig'],
  ['_logto_device_flow_xsrf', '_aster_device_flow_xsrf'],
  ['_logto_device_flow_xsrf.sig', '_aster_device_flow_xsrf.sig'],
] as const);
const referenceProductCookiePattern = /^_logto/u;

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
    state.auditXsrf = undefined;
    state.auditXsrfExpireAt = undefined;
  }
  if (state.xsrfExpireAt !== undefined && state.xsrfExpireAt <= now) {
    state.xsrf = undefined;
    state.xsrfCookieIdentity = undefined;
    state.xsrfExpireAt = undefined;
  }
  if (state.auditXsrfExpireAt !== undefined && state.auditXsrfExpireAt <= now) {
    state.auditXsrf = undefined;
    state.auditXsrfExpireAt = undefined;
  }
  if (state.accessExpireAt !== undefined && state.accessExpireAt <= now) {
    state.accessToken = undefined;
    state.accessExpireAt = undefined;
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
  for (const value of [
    state.deviceCode,
    state.userCode,
    state.xsrf,
    state.auditXsrf,
    state.verificationId,
    state.verificationFollowUrl,
    state.resumeUrl,
    state.logoutXsrf,
    state.accessToken,
    state.refreshToken,
    state.previousRefreshToken,
    state.idToken,
  ]) {
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
  if (state.operationActive || state.credentialLeaseActive) {
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
  state.auditXsrf = undefined;
  state.auditXsrfExpireAt = undefined;
  state.xsrfCookieIdentity = undefined;
  state.xsrfExpireAt = undefined;
  state.verificationId = undefined;
  state.verificationFollowUrl = undefined;
  state.resumeUrl = undefined;
  state.resumeStage = undefined;
  state.logoutXsrf = undefined;
  state.logoutAction = undefined;
  state.logoutRedirectUri = undefined;
  state.logoutState = undefined;
  state.accessToken = undefined;
  state.refreshToken = undefined;
  state.previousRefreshToken = undefined;
  state.idToken = undefined;
  state.accessExpireAt = undefined;
  state.credentialLeaseActive = false;
  state.cookies.removeAllCookiesSync();
  for (const controller of state.controllers) {
    controller.abort();
  }
  state.controllers.clear();
  state.operationActive = false;
  state.active = false;
};

const snapshotState = (state: TransportState): TransportState => ({
  targetLabel: state.targetLabel,
  active: state.active,
  operationActive: state.operationActive,
  deviceCode: state.deviceCode,
  userCode: state.userCode,
  codesExpireAt: state.codesExpireAt,
  xsrf: state.xsrf,
  auditXsrf: state.auditXsrf,
  auditXsrfExpireAt: state.auditXsrfExpireAt,
  xsrfCookieIdentity: state.xsrfCookieIdentity,
  xsrfExpireAt: state.xsrfExpireAt,
  verificationId: state.verificationId,
  verificationFollowUrl: state.verificationFollowUrl,
  resumeUrl: state.resumeUrl,
  resumeStage: state.resumeStage,
  logoutXsrf: state.logoutXsrf,
  logoutAction: state.logoutAction,
  logoutRedirectUri: state.logoutRedirectUri,
  logoutState: state.logoutState,
  accessToken: state.accessToken,
  refreshToken: state.refreshToken,
  previousRefreshToken: state.previousRefreshToken,
  idToken: state.idToken,
  accessExpireAt: state.accessExpireAt,
  credentialLeaseActive: state.credentialLeaseActive,
  cookies: state.cookies.cloneSync() ?? fail('state'),
  controllers: state.controllers,
});

const assertProjectedStringsAreSanitized = (
  projection: DeviceAuthorizationProjection | DeviceLifecycleProjection,
  registry: SensitiveRegistry,
  stage: string
): void => {
  const projectedStrings: string[] = [];
  JSON.stringify(projection, (_key, value: unknown) => {
    if (typeof value === 'string') {
      if (projectedStrings.length >= 512 || Buffer.byteLength(value) > 64 * 1024) {
        fail(stage);
      }
      projectedStrings.push(value);
    }
    return value;
  });
  if (
    projectedStrings.some(
      (value) =>
        containsCompactJwt(value) ||
        [...registry.values].some(
          (sensitive) =>
            sensitive.length > 0 && value.toLowerCase().includes(sensitive.toLowerCase())
        )
    )
  ) {
    fail(stage);
  }
};

const finishProjection = (
  state: TransportState,
  next: TransportState,
  projection: DeviceAuthorizationProjection,
  registry: SensitiveRegistry,
  stage: string
): DeviceAuthorizationProjection => {
  assertProjectedStringsAreSanitized(projection, registry, stage);
  assertActive(state);
  state.deviceCode = next.deviceCode;
  state.userCode = next.userCode;
  state.codesExpireAt = next.codesExpireAt;
  state.xsrf = next.xsrf;
  state.auditXsrf = next.auditXsrf;
  state.auditXsrfExpireAt = next.auditXsrfExpireAt;
  state.xsrfCookieIdentity = next.xsrfCookieIdentity;
  state.xsrfExpireAt = next.xsrfExpireAt;
  state.verificationId = next.verificationId;
  state.verificationFollowUrl = next.verificationFollowUrl;
  state.resumeUrl = next.resumeUrl;
  state.resumeStage = next.resumeStage;
  state.logoutXsrf = next.logoutXsrf;
  state.logoutAction = next.logoutAction;
  state.logoutRedirectUri = next.logoutRedirectUri;
  state.logoutState = next.logoutState;
  state.accessToken = next.accessToken;
  state.refreshToken = next.refreshToken;
  state.previousRefreshToken = next.previousRefreshToken;
  state.idToken = next.idToken;
  state.accessExpireAt = next.accessExpireAt;
  state.cookies = next.cookies;
  return publishDeviceAuthorizationProjection(projection);
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
    const mappedReferenceName = referenceCookieNameMappings.get(parsed.key);
    if (
      (state.targetLabel === 'candidate' && parsed.key.startsWith('_logto')) ||
      (state.targetLabel === 'oracle' &&
        parsed.key.startsWith('_logto') &&
        mappedReferenceName === undefined)
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
        state.auditXsrf = undefined;
        state.auditXsrfExpireAt = undefined;
        state.xsrfCookieIdentity = identity;
        state.xsrfExpireAt = expireAt;
      } else if (state.xsrfCookieIdentity === identity) {
        state.auditXsrf = state.xsrf;
        state.auditXsrfExpireAt = state.xsrfExpireAt;
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
    projections.push(
      Object.freeze({
        name: state.targetLabel === 'oracle' ? (mappedReferenceName ?? parsed.key) : parsed.key,
        options: Object.freeze(options),
        clearing:
          accepted.value.length === 0 ||
          (accepted.expiryTime() ?? Number.POSITIVE_INFINITY) <= Date.now(),
      })
    );
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
    url.origin !== base.origin ||
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
    originCategory: 'issuer',
    path: url.pathname,
    queryKeys: Object.freeze(queryKeys),
  });
};

const projectClientLogoutUrl = (
  value: unknown,
  redirectUri: string | undefined,
  state: string | undefined,
  stage: string
): DeviceAuthorizationUrlProjection | undefined => {
  if (value === undefined || value === null) {
    return undefined;
  }
  const expected = redirectUri === undefined ? fail(stage) : new URL(redirectUri);
  if (state !== undefined) {
    expected.searchParams.set('state', state);
  }
  const raw = boundedString(value, stage, 8192);
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return fail(stage);
  }
  if (
    !['http:', 'https:'].includes(url.protocol) ||
    url.username.length > 0 ||
    url.password.length > 0 ||
    url.hash.length > 0 ||
    url.href !== expected.href
  ) {
    return fail(stage);
  }
  const queryKeys = [...new Set(url.searchParams.keys())];
  if (queryKeys.some((key) => !fieldNamePattern.test(key))) {
    return fail(stage);
  }
  queryKeys.sort();
  return Object.freeze({
    originCategory: 'client',
    path: url.pathname,
    queryKeys: Object.freeze(queryKeys),
  });
};

const projectLogoutUrl = (
  value: unknown,
  redirectUri: string | undefined,
  state: string | undefined,
  base: URL,
  stage: string
): DeviceAuthorizationUrlProjection | undefined => {
  if (redirectUri !== undefined) {
    return projectClientLogoutUrl(value, redirectUri, state, stage);
  }
  if (state !== undefined) {
    return fail(stage);
  }
  const projection = projectUrl(value, base, stage);
  if (
    projection !== undefined &&
    (projection.path !== '/oidc/session/end/success' || projection.queryKeys.length > 0)
  ) {
    return fail(stage);
  }
  return projection;
};

const projectLifecycleRedirect = (
  redirect: URL,
  base: URL,
  stage: string
): DeviceAuthorizationUrlProjection => {
  const projection = projectUrl(redirect.href, base, stage) ?? fail(stage);
  const match = /^\/oidc\/(device|auth)\/([A-Za-z0-9_-]{43})$/u.exec(projection.path);
  if (projection.queryKeys.length === 0 && match !== null) {
    return Object.freeze({
      ...projection,
      path: `/oidc/${match[1]}/<interaction-uid>`,
    });
  }
  return projection;
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
            separator: projection.userCodeShape.separator,
            matchesReferencePattern: projection.userCodeShape.matchesReferencePattern,
          }),
    deviceCodeShape: projection.deviceCodeShape,
    expiresIn: projection.expiresIn,
    interval: projection.interval,
    tokenType: projection.tokenType,
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
  if (operation === 'verification') {
    if (next.verificationFollowUrl === requestUrl.href) {
      next.verificationFollowUrl = undefined;
    }
    if (rawLocation !== undefined) {
      const follow = new URL(rawLocation, base);
      if (follow.origin === base.origin && !follow.username && !follow.password && !follow.hash) {
        next.verificationFollowUrl = follow.href;
      }
    }
  }
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
      tokenType: undefined,
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
  const responseTokens: Partial<Record<'access_token' | 'refresh_token' | 'id_token', string>> = {};
  for (const tokenField of ['access_token', 'refresh_token', 'id_token'] as const) {
    if (parsed[tokenField] !== undefined) {
      const token = boundedString(parsed[tokenField], stage, 16 * 1024);
      registerSensitiveValue(registry, token);
      responseTokens[tokenField] = token;
    }
  }
  if (
    operation === 'token' &&
    response.status >= 200 &&
    response.status < 300 &&
    (Object.keys(responseTokens).length > 0 || parsed.token_type !== undefined)
  ) {
    const accessToken = responseTokens.access_token ?? fail(stage);
    const refreshToken = responseTokens.refresh_token;
    const idToken = responseTokens.id_token;
    const tokenExpiresIn = positiveExpiryField(parsed.expires_in, stage);
    const issuedTokens = [accessToken, refreshToken, idToken].filter(
      (token): token is string => token !== undefined
    );
    if (parsed.token_type !== 'Bearer' || new Set(issuedTokens).size !== issuedTokens.length) {
      return fail(stage);
    }
    next.accessToken = accessToken;
    next.refreshToken = refreshToken;
    next.previousRefreshToken = undefined;
    next.idToken = idToken;
    next.accessExpireAt = Date.now() + tokenExpiresIn * 1000;
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
    tokenType:
      parsed.token_type === undefined
        ? undefined
        : boundedString(parsed.token_type, stage, maximumFieldBytes) === 'Bearer'
          ? 'Bearer'
          : fail(stage),
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
  query: ReadonlyArray<readonly [DeviceAuthorizationFieldName, string]>;
  authorization: string | undefined;
  sensitiveValues: readonly string[];
  suppressPublicStrings: boolean;
}> => {
  const input = snapshotDataRecord(
    request,
    new Set(['encoding', 'fields', 'mediaType', 'body', 'sensitiveFragments', 'transport']),
    'authorization-request'
  );
  const transport: Readonly<Record<string, unknown>> =
    input.transport === undefined
      ? Object.freeze({})
      : snapshotDataRecord(input.transport, new Set(['query', 'proof']), 'authorization-request');
  const query: Array<readonly [DeviceAuthorizationFieldName, string]> = [];
  if (transport.query !== undefined) {
    for (const rawEntry of snapshotArray(transport.query, 16, 'authorization-request')) {
      const entry = snapshotArray(rawEntry, 2, 'authorization-request');
      if (
        entry.length !== 2 ||
        typeof entry[0] !== 'string' ||
        !authorizationFields.has(entry[0] as DeviceAuthorizationFieldName)
      ) {
        return fail('authorization-request');
      }
      query.push([
        entry[0] as DeviceAuthorizationFieldName,
        boundedString(entry[1], 'authorization-request', maximumFieldBytes, true),
      ]);
    }
  }
  let authorization: string | undefined;
  const controlSensitiveValues: string[] = query
    .filter(([name]) => name === 'client_secret')
    .map(([, value]) => value);
  if (transport.proof !== undefined) {
    const proof = snapshotDataRecord(
      transport.proof,
      new Set(['method', 'clientId', 'clientSecret']),
      'authorization-request'
    );
    if (proof.method !== 'basic') {
      return fail('authorization-request');
    }
    const clientId = boundedString(proof.clientId, 'authorization-request', maximumFieldBytes);
    const clientSecret = boundedString(
      proof.clientSecret,
      'authorization-request',
      maximumFieldBytes,
      true
    );
    const encoded = Buffer.from(
      `${encodeOauthBasicComponent(clientId)}:${encodeOauthBasicComponent(clientSecret)}`
    ).toString('base64');
    authorization = `Basic ${encoded}`;
    controlSensitiveValues.push(clientSecret, authorization, encoded);
  }
  const { encoding } = input;
  if (!['form', 'json', 'raw'].includes(String(encoding))) {
    return fail('authorization-request');
  }
  if (encoding === 'raw') {
    if (
      !hasOnlyKeys(
        input,
        new Set(['encoding', 'mediaType', 'body', 'sensitiveFragments', 'transport'])
      )
    ) {
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
    const sensitiveValues = [body, ...controlSensitiveValues];
    for (const fragment of fragments) {
      sensitiveValues.push(boundedString(fragment, 'authorization-request', maximumFieldBytes));
    }
    return Object.freeze({
      body,
      contentType: mediaType,
      query: Object.freeze(query),
      authorization,
      sensitiveValues: Object.freeze(sensitiveValues),
      suppressPublicStrings: true,
    });
  }
  if (!hasOnlyKeys(input, new Set(['encoding', 'fields', 'transport']))) {
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
    .map(([, value]) => value)
    .concat(controlSensitiveValues);
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
      query: Object.freeze(query),
      authorization,
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
    query: Object.freeze(query),
    authorization,
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
  if (method === 'FOLLOW_PROJECTED_LOCATION') {
    if (!hasOnlyKeys(input, new Set(['method']))) {
      return fail(stage);
    }
    const userCode = state.userCode ?? fail(stage);
    const url = localStoredUrl(state.verificationFollowUrl, base, stage);
    const queryKeys = [...url.searchParams.keys()];
    if (
      url.pathname !== '/oidc/device' ||
      queryKeys.length !== 1 ||
      queryKeys[0] !== 'user_code' ||
      url.searchParams.getAll('user_code').length !== 1 ||
      url.searchParams.get('user_code') !== userCode
    ) {
      return fail(stage);
    }
    return Object.freeze({
      url,
      method: 'GET',
      sensitiveValues: Object.freeze([userCode]),
    });
  }
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

type PreparedLifecycleRequest = Readonly<{
  kind: DeviceLifecycleKind;
  method: 'GET' | 'POST' | 'PUT';
  url: URL;
  headers: Headers;
  body?: string | URLSearchParams;
  sensitiveValues: readonly string[];
  expectedSubjectId?: string;
  expectedClientId?: string;
  introspectionCredentialKind?: 'access' | 'refresh';
  logoutRedirectUri?: string;
  logoutState?: string;
}>;

const applyClientProof = (
  proof: unknown,
  form: URLSearchParams,
  headers: Headers,
  sensitiveValues: string[],
  stage: string
): void => {
  const source = snapshotDataRecord(proof, new Set(['method', 'clientId', 'clientSecret']), stage);
  const { method } = source;
  const expectedKeys =
    method === 'public'
      ? new Set(['method', 'clientId'])
      : new Set(['method', 'clientId', 'clientSecret']);
  if (!['public', 'basic', 'post'].includes(String(method)) || !hasOnlyKeys(source, expectedKeys)) {
    fail(stage);
  }
  const clientId = boundedString(source.clientId, stage, maximumFieldBytes);
  if (method === 'public') {
    form.set('client_id', clientId);
    return;
  }
  const clientSecret = boundedString(source.clientSecret, stage, maximumFieldBytes);
  sensitiveValues.push(clientSecret);
  if (method === 'post') {
    form.set('client_id', clientId);
    form.set('client_secret', clientSecret);
    return;
  }
  const encodedClientId = encodeOauthBasicComponent(clientId);
  const encodedClientSecret = encodeOauthBasicComponent(clientSecret);
  const payload = Buffer.from(`${encodedClientId}:${encodedClientSecret}`, 'utf8').toString(
    'base64'
  );
  const authorization = `Basic ${payload}`;
  sensitiveValues.push(encodedClientSecret, payload, authorization);
  headers.set('authorization', authorization);
};

const localStoredUrl = (value: string | undefined, base: URL, stage: string): URL => {
  const raw = value ?? fail(stage);
  let url: URL;
  try {
    url = new URL(raw, base);
  } catch {
    return fail(stage);
  }
  if (url.origin !== base.origin || url.username || url.password || url.hash) {
    return fail(stage);
  }
  return url;
};

const prepareLifecycleRequest = (
  request: DeviceLifecycleRequest,
  base: URL,
  state: TransportState
): PreparedLifecycleRequest => {
  const stage = 'lifecycle-request';
  const input = snapshotDataRecord(
    request,
    new Set([
      'kind',
      'method',
      'username',
      'password',
      'proof',
      'scope',
      'resource',
      'organizationId',
      'token',
      'hint',
      'clientId',
      'postLogoutRedirectUri',
      'state',
      'confirm',
      'expectedSubjectId',
      'expectedClientId',
    ]),
    stage
  );
  const kind = input.kind as DeviceLifecycleKind;
  const { method } = input;
  const headers = new Headers();
  const sensitiveValues: string[] = [];
  let url: URL;
  let body: string | URLSearchParams | undefined;
  let expectedSubjectId: string | undefined;
  let expectedClientId: string | undefined;
  let logoutRedirectUri: string | undefined;
  let logoutState: string | undefined;
  const exact = (keys: readonly string[]): void => {
    if (!hasOnlyKeys(input, new Set(['kind', 'method', ...keys]))) {
      fail(stage);
    }
  };
  const json = (value: Readonly<Record<string, unknown>>): void => {
    headers.set('content-type', 'application/json');
    body = JSON.stringify(value);
  };
  if (kind === 'verification-success') {
    exact([]);
    if (method !== 'GET') {
      fail(stage);
    }
    url = new URL('/device/success', base);
  } else if (kind === 'experience-open') {
    exact([]);
    if (method !== 'PUT') {
      fail(stage);
    }
    url = new URL('/api/experience', base);
    json({ interactionEvent: 'SignIn' });
  } else if (kind === 'password-verification') {
    exact(['username', 'password']);
    if (method !== 'POST') {
      fail(stage);
    }
    const username = boundedString(input.username, stage, maximumFieldBytes);
    const password = boundedString(input.password, stage, 256);
    sensitiveValues.push(password);
    url = new URL('/api/experience/verification/password', base);
    json({ identifier: { type: 'username', value: username }, password });
  } else if (kind === 'identification') {
    exact([]);
    if (method !== 'POST') {
      fail(stage);
    }
    const verificationId = state.verificationId ?? fail(stage);
    sensitiveValues.push(verificationId);
    url = new URL('/api/experience/identification', base);
    json({ verificationId });
  } else if (kind === 'experience-submit') {
    exact([]);
    if (method !== 'POST') {
      fail(stage);
    }
    url = new URL('/api/experience/submit', base);
  } else if (kind === 'consent-read') {
    exact([]);
    if (method !== 'GET') {
      fail(stage);
    }
    url = new URL('/api/interaction/consent', base);
  } else if (kind === 'consent-write') {
    exact([]);
    if (method !== 'POST') {
      fail(stage);
    }
    url = new URL('/api/interaction/consent', base);
    json({});
  } else if (kind === 'resume') {
    exact([]);
    if (method !== 'GET') {
      fail(stage);
    }
    url = localStoredUrl(state.resumeUrl, base, stage);
    sensitiveValues.push(state.resumeUrl ?? fail(stage));
  } else if (kind === 'refresh') {
    exact(['proof', 'scope', 'resource', 'organizationId']);
    if (method !== 'POST') {
      fail(stage);
    }
    const refreshToken = state.refreshToken ?? fail(stage);
    const form = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken });
    sensitiveValues.push(refreshToken);
    applyClientProof(input.proof, form, headers, sensitiveValues, stage);
    for (const [inputName, wireName] of [
      ['scope', 'scope'],
      ['resource', 'resource'],
      ['organizationId', 'organization_id'],
    ] as const) {
      if (input[inputName] !== undefined) {
        form.set(wireName, boundedString(input[inputName], stage, maximumFieldBytes));
      }
    }
    headers.set('content-type', 'application/x-www-form-urlencoded');
    url = new URL('/oidc/token', base);
    body = form;
  } else if (kind === 'userinfo') {
    exact(['expectedSubjectId']);
    if (method !== 'GET') {
      fail(stage);
    }
    expectedSubjectId = boundedString(input.expectedSubjectId, stage, maximumFieldBytes);
    sensitiveValues.push(expectedSubjectId);
    const accessToken = state.accessToken ?? fail(stage);
    const authorization = `Bearer ${accessToken}`;
    headers.set('authorization', authorization);
    sensitiveValues.push(accessToken, authorization);
    url = new URL('/oidc/me', base);
  } else if (kind === 'introspection' || kind === 'revocation') {
    exact(['proof', 'token', 'hint', 'expectedSubjectId', 'expectedClientId']);
    if (method !== 'POST' || !['access', 'refresh'].includes(String(input.token))) {
      fail(stage);
    }
    const token = input.token === 'access' ? state.accessToken : state.refreshToken;
    const credential = token ?? fail(stage);
    const form = new URLSearchParams({ token: credential });
    sensitiveValues.push(credential);
    if (input.hint !== undefined) {
      if (!['access_token', 'refresh_token'].includes(String(input.hint))) {
        fail(stage);
      }
      form.set('token_type_hint', String(input.hint));
    }
    applyClientProof(input.proof, form, headers, sensitiveValues, stage);
    if (kind === 'introspection') {
      expectedSubjectId = boundedString(input.expectedSubjectId, stage, maximumFieldBytes);
      expectedClientId = boundedString(input.expectedClientId, stage, maximumFieldBytes);
      sensitiveValues.push(expectedSubjectId, expectedClientId);
    } else if (input.expectedSubjectId !== undefined || input.expectedClientId !== undefined) {
      fail(stage);
    }
    headers.set('content-type', 'application/x-www-form-urlencoded');
    url = new URL(`/oidc/token/${kind}`, base);
    body = form;
  } else if (kind === 'logout-open') {
    exact(['clientId', 'postLogoutRedirectUri', 'state']);
    if (method !== 'GET') {
      fail(stage);
    }
    url = new URL('/oidc/session/end', base);
    url.searchParams.set('client_id', boundedString(input.clientId, stage, maximumFieldBytes));
    if (state.idToken !== undefined) {
      url.searchParams.set('id_token_hint', state.idToken);
      sensitiveValues.push(state.idToken);
    }
    if (input.postLogoutRedirectUri !== undefined) {
      const redirect = boundedString(input.postLogoutRedirectUri, stage, 8192);
      const parsed = new URL(redirect);
      if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) {
        fail(stage);
      }
      if (parsed.hash.length > 0) {
        fail(stage);
      }
      logoutRedirectUri = parsed.href;
      url.searchParams.set('post_logout_redirect_uri', redirect);
    }
    if (input.state !== undefined) {
      logoutState = boundedString(input.state, stage, maximumFieldBytes);
      url.searchParams.set('state', logoutState);
    }
  } else if (kind === 'logout-confirm') {
    exact(['confirm']);
    if (method !== 'POST' || typeof input.confirm !== 'boolean') {
      fail(stage);
    }
    url = localStoredUrl(state.logoutAction, base, stage);
    const xsrf = state.logoutXsrf ?? fail(stage);
    const form = new URLSearchParams({ xsrf });
    if (input.confirm) {
      form.set('logout', 'yes');
    }
    headers.set('content-type', 'application/x-www-form-urlencoded');
    sensitiveValues.push(xsrf);
    body = form;
  } else if (kind === 'oidc-discovery' || kind === 'oauth-discovery') {
    exact([]);
    if (method !== 'GET') {
      fail(stage);
    }
    url = new URL(
      kind === 'oidc-discovery'
        ? '/oidc/.well-known/openid-configuration'
        : '/oidc/.well-known/oauth-authorization-server',
      base
    );
  } else {
    return fail(stage);
  }
  const browserKinds = new Set<DeviceLifecycleKind>([
    'verification-success',
    'experience-open',
    'password-verification',
    'identification',
    'experience-submit',
    'consent-read',
    'consent-write',
    'resume',
    'logout-open',
    'logout-confirm',
  ]);
  if (browserKinds.has(kind)) {
    const cookies = cookieHeader(state, url, stage);
    if (cookies !== undefined) {
      headers.set('cookie', cookies);
    }
  }
  return Object.freeze({
    kind,
    method: method as 'GET' | 'POST' | 'PUT',
    url,
    headers,
    ...(body === undefined ? {} : { body }),
    sensitiveValues: Object.freeze(sensitiveValues),
    ...(expectedSubjectId === undefined ? {} : { expectedSubjectId }),
    ...(expectedClientId === undefined ? {} : { expectedClientId }),
    ...(kind === 'introspection'
      ? { introspectionCredentialKind: input.token as 'access' | 'refresh' }
      : {}),
    ...(logoutRedirectUri === undefined ? {} : { logoutRedirectUri }),
    ...(logoutState === undefined ? {} : { logoutState }),
  });
};

const lifecycleStatuses: Readonly<Record<DeviceLifecycleKind, ReadonlySet<number>>> = Object.freeze(
  {
    'verification-success': new Set([200]),
    'experience-open': new Set([204]),
    'password-verification': new Set([200]),
    identification: new Set([204]),
    'experience-submit': new Set([200]),
    'consent-read': new Set([200]),
    'consent-write': new Set([200]),
    resume: new Set([302, 303]),
    refresh: new Set([200, 400, 401]),
    userinfo: new Set([200, 401]),
    introspection: new Set([200, 400, 401]),
    revocation: new Set([200, 400, 401]),
    'logout-open': new Set([200, 302, 303]),
    'logout-confirm': new Set([303]),
    'oidc-discovery': new Set([200]),
    'oauth-discovery': new Set([200]),
  }
);

const jsonObject = (text: string, stage: string): Record<string, unknown> => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    return fail(stage);
  }
  const source = isPlainRecord(parsed) ? parsed : fail(stage);
  const keys = Object.keys(source);
  if (keys.length > 128 || keys.some((key) => !fieldNamePattern.test(key))) {
    return fail(stage);
  }
  return source;
};

const markerFacts = (marker: string): Readonly<Record<string, unknown>> =>
  Object.freeze({ marker });

const htmlInputValue = (body: string, name: string): string | undefined => {
  const escaped = name.replaceAll(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  return (
    new RegExp(`<input\\b[^>]*\\bname=["']${escaped}["'][^>]*\\bvalue=["']([^"']+)["']`, 'iu').exec(
      body
    )?.[1] ??
    new RegExp(`<input\\b[^>]*\\bvalue=["']([^"']+)["'][^>]*\\bname=["']${escaped}["']`, 'iu').exec(
      body
    )?.[1]
  );
};

const commitLifecycleState = (state: TransportState, next: TransportState): void => {
  assertActive(state);
  for (const key of [
    'deviceCode',
    'userCode',
    'codesExpireAt',
    'xsrf',
    'xsrfCookieIdentity',
    'xsrfExpireAt',
    'verificationId',
    'verificationFollowUrl',
    'resumeUrl',
    'resumeStage',
    'logoutXsrf',
    'logoutAction',
    'logoutRedirectUri',
    'logoutState',
    'accessToken',
    'refreshToken',
    'previousRefreshToken',
    'idToken',
    'accessExpireAt',
  ] as const) {
    state[key] = next[key] as never;
  }
  state.cookies = next.cookies;
};

const projectLifecycleResponse = async (
  response: Response,
  prepared: PreparedLifecycleRequest,
  base: URL,
  state: TransportState,
  limits: ResponseLimits,
  maximumSensitiveValues: number
): Promise<DeviceLifecycleProjection> => {
  const stage = 'lifecycle-response';
  if (response.redirected || !lifecycleStatuses[prepared.kind].has(response.status)) {
    await cancelResponseBodySafely(response.body ?? undefined);
    return fail(stage);
  }
  const next = snapshotState(state);
  const registry = createSensitiveRegistry(next, maximumSensitiveValues, stage);
  for (const sensitive of prepared.sensitiveValues) {
    registerSensitiveValue(registry, sensitive);
  }
  const cookies = mergeCookies(next, response.headers, prepared.url, registry, stage);
  const headers = projectHeaders(response.headers, limits.headers, registry.values, false, stage);
  const contentType = normalizedContentType(response.headers, stage);
  const challenge = projectChallenge(response.headers, base, registry.values, false, stage);
  const rawLocation = response.headers.get('location') ?? undefined;
  const location =
    prepared.kind === 'logout-open' || prepared.kind === 'logout-confirm'
      ? projectLogoutUrl(
          rawLocation,
          prepared.kind === 'logout-open' ? prepared.logoutRedirectUri : next.logoutRedirectUri,
          prepared.kind === 'logout-open' ? prepared.logoutState : next.logoutState,
          base,
          stage
        )
      : projectUrl(rawLocation, base, stage);
  const bytes = await readBoundedBody(response, limits.body, stage);
  const bodyText = new TextDecoder('utf8', { fatal: true }).decode(bytes);
  const parsed = contentType === 'application/json' ? jsonObject(bodyText, stage) : undefined;
  if (
    parsed === undefined &&
    bodyText.length > 0 &&
    contentType !== 'text/html' &&
    contentType !== 'text/plain'
  ) {
    return fail(stage);
  }
  let facts: Readonly<Record<string, unknown>>;
  const { kind } = prepared;
  if (kind === 'password-verification') {
    const verificationId = boundedString(parsed?.verificationId, stage, maximumFieldBytes);
    registerSensitiveValue(registry, verificationId);
    next.verificationId = verificationId;
    facts = markerFacts('password-verified');
  } else if (kind === 'experience-submit' || kind === 'consent-write') {
    const redirectTo = boundedString(parsed?.redirectTo, stage, 8192);
    const redirect = localStoredUrl(redirectTo, base, stage);
    registerSensitiveValue(registry, redirectTo);
    next.resumeUrl = redirect.href;
    next.resumeStage =
      kind === 'experience-submit' ? 'after-experience-submit' : 'after-consent-write';
    facts = Object.freeze({
      marker: kind === 'experience-submit' ? 'experience-submitted' : 'consent-recorded',
      redirect: projectLifecycleRedirect(redirect, base, stage),
    });
  } else if (kind === 'refresh' && response.status === 200) {
    const accessToken = boundedString(parsed?.access_token, stage, 16 * 1024);
    const refreshToken = boundedString(parsed?.refresh_token, stage, 16 * 1024);
    const issuedIdToken =
      parsed?.id_token === undefined ? undefined : boundedString(parsed.id_token, stage, 16 * 1024);
    const expiresIn = positiveExpiryField(parsed?.expires_in, stage);
    const previousRefreshToken = next.refreshToken ?? fail(stage);
    if (
      parsed?.token_type !== 'Bearer' ||
      accessToken === refreshToken ||
      refreshToken === previousRefreshToken ||
      (issuedIdToken !== undefined &&
        new Set([accessToken, refreshToken, issuedIdToken]).size !== 3)
    ) {
      return fail(stage);
    }
    for (const token of [accessToken, refreshToken, issuedIdToken]) {
      if (token !== undefined) {
        registerSensitiveValue(registry, token);
      }
    }
    next.previousRefreshToken = previousRefreshToken;
    next.accessToken = accessToken;
    next.refreshToken = refreshToken;
    if (issuedIdToken !== undefined) {
      next.idToken = issuedIdToken;
    }
    next.accessExpireAt = Date.now() + expiresIn * 1000;
    const { scope } = parsed;
    facts = Object.freeze({
      marker: 'tokens-refreshed',
      tokenType: 'Bearer',
      expiresIn,
      refreshRotated: true,
      idTokenIssued: issuedIdToken !== undefined,
      ...(scope === undefined
        ? {}
        : {
            scopes: Object.freeze(
              scope === '' ? [] : boundedString(scope, stage, maximumFieldBytes).split(' ').sort()
            ),
          }),
    });
  } else if (kind === 'userinfo' && response.status === 200) {
    if (Object.keys(parsed ?? {}).some((key) => sensitiveResponseKeyPattern.test(key))) {
      return fail(stage);
    }
    const subject = boundedString(parsed?.sub, stage, maximumFieldBytes);
    if (subject !== prepared.expectedSubjectId) {
      return fail(stage);
    }
    registerSensitiveValue(registry, subject);
    facts = Object.freeze({
      marker: 'userinfo',
      subject: '<subject>',
      keys: Object.freeze(Object.keys(parsed ?? {}).sort()),
      ...(typeof parsed?.email_verified === 'boolean'
        ? { emailVerified: parsed.email_verified }
        : {}),
      ...(typeof parsed?.phone_number_verified === 'boolean'
        ? { phoneNumberVerified: parsed.phone_number_verified }
        : {}),
    });
  } else if (kind === 'introspection' && response.status === 200) {
    if (typeof parsed?.active !== 'boolean') {
      return fail(stage);
    }
    if (parsed.active) {
      const credentialKind = prepared.introspectionCredentialKind ?? fail(stage);
      const allowedKeys = new Set(
        credentialKind === 'access'
          ? ['active', 'sub', 'client_id', 'exp', 'iat', 'iss', 'scope', 'token_type']
          : ['active', 'sub', 'client_id', 'exp', 'iat', 'iss', 'scope']
      );
      const keys = Object.keys(parsed);
      const subject = boundedString(parsed.sub, stage, maximumFieldBytes);
      const clientId = boundedString(parsed.client_id, stage, maximumFieldBytes);
      const issuer = boundedString(parsed.iss, stage, 8192);
      const issuedAt = parsed.iat;
      const expiresAt = parsed.exp;
      const nowSeconds = Math.floor(Date.now() / 1000);
      const scope = boundedString(parsed.scope, stage, maximumFieldBytes);
      const tokenType = parsed.token_type;
      if (
        keys.some((key) => !allowedKeys.has(key)) ||
        subject !== prepared.expectedSubjectId ||
        clientId !== prepared.expectedClientId ||
        issuer !== new URL('/oidc', base).href.replace(/\/$/u, '') ||
        !Number.isSafeInteger(issuedAt) ||
        !Number.isSafeInteger(expiresAt) ||
        Number(issuedAt) > nowSeconds + 1 ||
        Number(expiresAt) <= nowSeconds ||
        Number(expiresAt) <= Number(issuedAt) ||
        Number(expiresAt) - Number(issuedAt) > (credentialKind === 'access' ? 86_400 : 1_209_600) ||
        (tokenType !== undefined && tokenType !== 'Bearer')
      ) {
        return fail(stage);
      }
      registerSensitiveValue(registry, subject);
      registerSensitiveValue(registry, clientId);
      facts = Object.freeze({
        marker: 'introspection',
        active: true,
        credentialKind,
        subject: '<subject>',
        clientId: '<client>',
        issuer: '<target-issuer>',
        issuedAt: '<issued-at>',
        lifetimeSeconds: Number(expiresAt) - Number(issuedAt),
        scopes: Object.freeze(scope.split(' ').sort()),
        ...(tokenType === undefined ? {} : { tokenType }),
      });
    } else {
      if (Object.keys(parsed).length !== 1) {
        return fail(stage);
      }
      facts = Object.freeze({ marker: 'introspection', active: false });
    }
  } else if (kind === 'revocation' && response.status === 200) {
    if (bodyText.length > 0) {
      return fail(stage);
    }
    facts = markerFacts('revoked');
  } else if (kind === 'logout-open' && response.status === 200) {
    if (contentType !== 'text/html') {
      return fail(stage);
    }
    const experience = projectExperience(bodyText, base, registry.values, stage);
    const xsrf = boundedString(htmlInputValue(bodyText, 'xsrf'), stage, maximumFieldBytes);
    const action = experience.formAction ?? fail(stage);
    const actionUrl = new URL(action.path, base);
    registerSensitiveValue(registry, xsrf);
    next.logoutXsrf = xsrf;
    next.logoutAction = actionUrl.href;
    next.logoutRedirectUri = prepared.logoutRedirectUri;
    next.logoutState = prepared.logoutState;
    facts = Object.freeze({
      marker: 'logout-confirmation',
      title: experience.title,
      formAction: experience.formAction,
      inputNames: experience.inputNames,
    });
  } else if (kind === 'logout-open' && [302, 303].includes(response.status)) {
    if (location === undefined) {
      return fail(stage);
    }
    facts = markerFacts('logout-finished');
    next.logoutRedirectUri = undefined;
    next.logoutState = undefined;
  } else if (kind === 'oidc-discovery' || kind === 'oauth-discovery') {
    const issuer = boundedString(parsed?.issuer, stage, 8192);
    if (issuer !== new URL('/oidc', base).href.replace(/\/$/u, '')) {
      return fail(stage);
    }
    if (
      state.targetLabel === 'oracle' &&
      (parsed?.backchannel_logout_session_supported !== true ||
        parsed.backchannel_logout_supported !== true ||
        parsed.pushed_authorization_request_endpoint !== `${issuer}/request` ||
        JSON.stringify(parsed.token_endpoint_auth_signing_alg_values_supported) !==
          JSON.stringify(['HS256', 'RS256', 'PS256', 'ES256', 'Ed25519', 'EdDSA']))
    ) {
      return fail(stage);
    }
    const endpointPaths = Object.freeze({
      authorization_endpoint: '/oidc/auth',
      token_endpoint: '/oidc/token',
      jwks_uri: '/oidc/jwks',
      userinfo_endpoint: '/oidc/me',
      device_authorization_endpoint: '/oidc/device/auth',
      introspection_endpoint: '/oidc/token/introspection',
      revocation_endpoint: '/oidc/token/revocation',
      end_session_endpoint: '/oidc/session/end',
    });
    const endpoints: Record<string, DeviceAuthorizationUrlProjection> = {};
    for (const [name, path] of Object.entries(endpointPaths)) {
      const endpoint = projectUrl(parsed?.[name], base, stage) ?? fail(stage);
      if (
        endpoint.originCategory !== 'issuer' ||
        endpoint.path !== path ||
        endpoint.queryKeys.length > 0
      ) {
        return fail(stage);
      }
      endpoints[name] = endpoint;
    }
    facts = Object.freeze({
      marker: kind,
      issuer: '<target-issuer>',
      endpoints: Object.freeze(endpoints),
      keys: Object.freeze(Object.keys(parsed ?? {}).sort()),
    });
  } else if (
    (kind === 'refresh' ||
      kind === 'userinfo' ||
      kind === 'introspection' ||
      kind === 'revocation') &&
    response.status >= 400
  ) {
    facts = markerFacts('oauth-error');
  } else if (kind === 'verification-success') {
    if (contentType !== 'text/html') {
      return fail(stage);
    }
    if (!/<div\s+id=["']app["'][^>]*>/iu.test(bodyText)) {
      return fail(stage);
    }
    facts = Object.freeze({
      marker: 'device-success',
      shell: 'experience-app',
    });
  } else if (kind === 'consent-read') {
    if (parsed?.redirectUri !== undefined) {
      return fail(stage);
    }
    const missingOidcScopes = parsed?.missingOIDCScope ?? [];
    const missingResourceScopes = parsed?.missingResourceScopes ?? [];
    if (
      !Array.isArray(missingOidcScopes) ||
      missingOidcScopes.some((scope) => typeof scope !== 'string') ||
      !Array.isArray(missingResourceScopes)
    ) {
      return fail(stage);
    }
    const projectedMissingOidcScopes = (missingOidcScopes as unknown[])
      .map((scope) => boundedString(scope, stage, maximumFieldBytes))
      .sort((left, right) => left.localeCompare(right));
    facts = Object.freeze({
      marker: 'consent-presented',
      redirectUriAbsent: true,
      missingOidcScopes: Object.freeze(projectedMissingOidcScopes),
      missingResourceScopeCount: missingResourceScopes.length,
    });
  } else if (kind === 'resume') {
    const resumeStage = next.resumeStage ?? fail(stage);
    if (
      (resumeStage === 'after-experience-submit' &&
        (response.status !== 303 ||
          location?.originCategory !== 'issuer' ||
          location.path !== '/consent' ||
          location.queryKeys.length !== 1 ||
          location.queryKeys[0] !== 'app_id')) ||
      (resumeStage === 'after-consent-write' &&
        (response.status !== 302 ||
          location?.originCategory !== 'issuer' ||
          location.path !== '/device/success' ||
          location.queryKeys.length > 0))
    ) {
      return fail(stage);
    }
    next.resumeUrl = undefined;
    next.resumeStage = undefined;
    facts = Object.freeze(
      resumeStage === 'after-experience-submit'
        ? { marker: 'consent-redirect', stage: resumeStage }
        : { marker: 'device-success-redirect', stage: resumeStage }
    );
  } else if (kind === 'logout-confirm') {
    if (location === undefined) {
      return fail(stage);
    }
    facts = markerFacts('logout-finished');
    next.logoutRedirectUri = undefined;
    next.logoutState = undefined;
  } else {
    facts = markerFacts(
      kind === 'experience-open'
        ? 'experience-opened'
        : kind === 'identification'
          ? 'subject-identified'
          : kind
    );
  }
  const oauthError =
    parsed?.error === undefined && parsed?.error_description === undefined
      ? projectRedirectError(rawLocation, base, registry.values, stage)
      : Object.freeze({
          category: safePublicString(parsed.error, registry.values, stage, 256),
          description: safePublicString(parsed.error_description, registry.values, stage, 2048),
        });
  const projection = publishDeviceLifecycleProjection(
    Object.freeze({
      kind,
      status: response.status,
      contentType,
      headers,
      cookies,
      challenge,
      location,
      oauthError,
      facts,
    }) as DeviceLifecycleProjection
  );
  assertProjectedStringsAreSanitized(projection, registry, stage);
  commitLifecycleState(state, next);
  return projection;
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
    targetLabel: target.label,
    active: true,
    operationActive: false,
    credentialLeaseActive: false,
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
      for (const [name, value] of prepared.query) {
        url.searchParams.append(name, value);
      }
      const headers = new Headers({ 'content-type': prepared.contentType });
      if (prepared.authorization !== undefined) {
        headers.set('authorization', prepared.authorization);
      }
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
    requestLifecycle: async (
      request: DeviceLifecycleRequest
    ): Promise<DeviceLifecycleProjection> => {
      assertAvailable(state);
      const prepared = fixedFailure('lifecycle-request', () =>
        prepareLifecycleRequest(request, base, state)
      );
      fixedFailure('lifecycle-request', () => {
        assertRequestBounds(
          prepared.url,
          prepared.headers,
          prepared.body,
          requestLimits,
          'lifecycle-request'
        );
      });
      const control = beginRequest(state, timeoutMs);
      try {
        let response: Response;
        try {
          response = await requestFetch(prepared.url, {
            method: prepared.method,
            headers: prepared.headers,
            ...(prepared.body === undefined ? {} : { body: prepared.body }),
            redirect: 'manual',
            signal: control.signal,
          });
        } catch {
          return fail('lifecycle-request');
        }
        try {
          return await projectLifecycleResponse(
            response,
            prepared,
            base,
            state,
            limits,
            sensitiveVariantLimit
          );
        } catch {
          await cancelResponseBodySafely(response.body ?? undefined);
          return fail('lifecycle-response');
        }
      } finally {
        state.controllers.delete(control.controller);
        state.operationActive = false;
      }
    },
    withCredentialLease: async <Result>(
      use: (lease: DeviceCredentialLease) => Result | Promise<Result>
    ): Promise<Result> => {
      assertAvailable(state);
      if (typeof use !== 'function') {
        return fail('credential-lease');
      }
      const { accessToken, refreshToken, idToken } = state;
      const { previousRefreshToken } = state;
      if (accessToken === undefined && refreshToken === undefined && idToken === undefined) {
        return fail('credential-lease');
      }
      const registry: SensitiveRegistry = {
        values: new Set(),
        maximum: sensitiveVariantLimit,
        stage: 'credential-lease',
      };
      for (const token of [accessToken, refreshToken, idToken, previousRefreshToken]) {
        if (token !== undefined) {
          registerSensitiveValue(registry, token);
        }
      }
      let valid = true;
      state.credentialLeaseActive = true;
      const read = (
        value: string | undefined,
        current: () => string | undefined
      ): string | undefined => {
        assertActive(state);
        pruneExpiredState(state);
        if (!valid || (value !== undefined && current() !== value)) {
          return fail('credential-lease');
        }
        return value;
      };
      const credentialLease: DeviceCredentialLease = Object.freeze({
        getAccessToken: () => read(accessToken, () => state.accessToken),
        getRefreshToken: () => read(refreshToken, () => state.refreshToken),
        getIdToken: () => read(idToken, () => state.idToken),
        getPreviousRefreshToken: () => read(previousRefreshToken, () => state.previousRefreshToken),
        toJSON: (): never => fail('credential-lease'),
      });
      try {
        let result: Result;
        try {
          result = await use(credentialLease);
        } catch {
          return fail('credential-lease');
        }
        assertActive(state);
        pruneExpiredState(state);
        if (
          state.accessToken !== accessToken ||
          state.refreshToken !== refreshToken ||
          state.idToken !== idToken
        ) {
          return fail('credential-lease');
        }
        fixedFailure('credential-lease', () => {
          assertDeviceAuthorizationEvidenceIsSanitized(result);
        });
        let serialized: string;
        try {
          serialized = JSON.stringify(result) ?? '';
        } catch {
          return fail('credential-lease');
        }
        const normalized = serialized.toLowerCase();
        if (
          containsCompactJwt(serialized) ||
          [...registry.values].some(
            (sensitive) => sensitive.length > 0 && normalized.includes(sensitive.toLowerCase())
          )
        ) {
          return fail('credential-lease');
        }
        return result;
      } finally {
        valid = false;
        state.credentialLeaseActive = false;
      }
    },
    withVerificationXsrfLease: async <Result>(
      use: (xsrfLease: DeviceVerificationXsrfLease) => Result | Promise<Result>
    ): Promise<Result> => {
      assertAvailable(state);
      if (typeof use !== 'function') {
        return fail('xsrf-lease');
      }
      const xsrf = state.xsrf ?? fail('xsrf-lease');
      const registry: SensitiveRegistry = {
        values: new Set(),
        maximum: sensitiveVariantLimit,
        stage: 'xsrf-lease',
      };
      registerSensitiveValue(registry, xsrf);
      let valid = true;
      state.credentialLeaseActive = true;
      const scopedLease: DeviceVerificationXsrfLease = Object.freeze({
        getXsrf: () => {
          assertActive(state);
          pruneExpiredState(state);
          if (!valid || state.xsrf !== xsrf) {
            return fail('xsrf-lease');
          }
          return xsrf;
        },
        toJSON: (): never => fail('xsrf-lease'),
      });
      try {
        let result: Result;
        try {
          result = await use(scopedLease);
        } catch {
          return fail('xsrf-lease');
        }
        assertActive(state);
        pruneExpiredState(state);
        if (state.xsrf !== xsrf) {
          return fail('xsrf-lease');
        }
        fixedFailure('xsrf-lease', () => {
          assertDeviceAuthorizationEvidenceIsSanitized(result);
        });
        let serialized: string;
        try {
          serialized = JSON.stringify(result) ?? '';
        } catch {
          return fail('xsrf-lease');
        }
        const normalized = serialized.toLowerCase();
        if (
          [...registry.values].some(
            (sensitive) => sensitive.length > 0 && normalized.includes(sensitive.toLowerCase())
          )
        ) {
          return fail('xsrf-lease');
        }
        return result;
      } finally {
        valid = false;
        state.credentialLeaseActive = false;
      }
    },
    withVerificationUserCodeLease: async <Result>(
      use: (userCodeLease: DeviceVerificationUserCodeLease) => Result | Promise<Result>
    ): Promise<Result> => {
      assertAvailable(state);
      if (typeof use !== 'function') {
        return fail('user-code-lease');
      }
      const userCode = state.userCode ?? fail('user-code-lease');
      const xsrf = state.xsrf ?? fail('user-code-lease');
      const registry: SensitiveRegistry = {
        values: new Set(),
        maximum: sensitiveVariantLimit,
        stage: 'user-code-lease',
      };
      registerSensitiveValue(registry, userCode);
      registerSensitiveValue(registry, xsrf);
      let valid = true;
      state.credentialLeaseActive = true;
      const read = (value: string, current: string | undefined): string => {
        assertActive(state);
        pruneExpiredState(state);
        if (!valid || current !== value) {
          return fail('user-code-lease');
        }
        return value;
      };
      const scopedLease: DeviceVerificationUserCodeLease = Object.freeze({
        getUserCode: () => read(userCode, state.userCode),
        getXsrf: () => read(xsrf, state.xsrf),
        toJSON: (): never => fail('user-code-lease'),
      });
      try {
        let result: Result;
        try {
          result = await use(scopedLease);
        } catch {
          return fail('user-code-lease');
        }
        assertActive(state);
        pruneExpiredState(state);
        if (state.userCode !== userCode || state.xsrf !== xsrf) {
          return fail('user-code-lease');
        }
        fixedFailure('user-code-lease', () => {
          assertDeviceAuthorizationEvidenceIsSanitized(result);
        });
        const serialized = fixedFailure('user-code-lease', () => JSON.stringify(result) ?? '');
        const normalized = serialized.toLowerCase();
        if (
          [...registry.values].some(
            (sensitive) => sensitive.length > 0 && normalized.includes(sensitive.toLowerCase())
          )
        ) {
          return fail('user-code-lease');
        }
        return result;
      } finally {
        valid = false;
        state.credentialLeaseActive = false;
      }
    },
    withDeviceCodeLease: async <Result>(
      use: (deviceCodeLease: DeviceCodeLease) => Result | Promise<Result>
    ): Promise<Result> => {
      assertAvailable(state);
      if (typeof use !== 'function') {
        return fail('device-code-lease');
      }
      const deviceCode = state.deviceCode ?? fail('device-code-lease');
      const registry: SensitiveRegistry = {
        values: new Set(),
        maximum: sensitiveVariantLimit,
        stage: 'device-code-lease',
      };
      registerSensitiveValue(registry, deviceCode);
      let valid = true;
      state.credentialLeaseActive = true;
      const scopedLease: DeviceCodeLease = Object.freeze({
        getDeviceCode: () => {
          assertActive(state);
          pruneExpiredState(state);
          if (!valid || state.deviceCode !== deviceCode) {
            return fail('device-code-lease');
          }
          return deviceCode;
        },
        toJSON: (): never => fail('device-code-lease'),
      });
      try {
        let result: Result;
        try {
          result = await use(scopedLease);
        } catch {
          return fail('device-code-lease');
        }
        assertActive(state);
        pruneExpiredState(state);
        if (state.deviceCode !== deviceCode) {
          return fail('device-code-lease');
        }
        fixedFailure('device-code-lease', () => {
          assertDeviceAuthorizationEvidenceIsSanitized(result);
        });
        const serialized = fixedFailure('device-code-lease', () => JSON.stringify(result) ?? '');
        if (
          [...registry.values].some(
            (sensitive) =>
              sensitive.length > 0 && serialized.toLowerCase().includes(sensitive.toLowerCase())
          )
        ) {
          return fail('device-code-lease');
        }
        return result;
      } finally {
        valid = false;
        state.credentialLeaseActive = false;
      }
    },
    withAuthorizationSecretLease: async <Result>(
      use: (secretLease: DeviceAuthorizationSecretLease) => Result | Promise<Result>
    ): Promise<Result> => {
      assertAvailable(state);
      if (typeof use !== 'function') {
        return fail('authorization-secret-lease');
      }
      const deviceCode = state.deviceCode ?? fail('authorization-secret-lease');
      const userCode = state.userCode ?? fail('authorization-secret-lease');
      const xsrf = state.xsrf ?? fail('authorization-secret-lease');
      const registry: SensitiveRegistry = {
        values: new Set(),
        maximum: sensitiveVariantLimit,
        stage: 'authorization-secret-lease',
      };
      for (const secret of [deviceCode, userCode, xsrf]) {
        registerSensitiveValue(registry, secret);
      }
      let valid = true;
      state.credentialLeaseActive = true;
      const read = (value: string, current: string | undefined): string => {
        assertActive(state);
        pruneExpiredState(state);
        if (!valid || current !== value) {
          return fail('authorization-secret-lease');
        }
        return value;
      };
      const scopedLease: DeviceAuthorizationSecretLease = Object.freeze({
        getDeviceCode: () => read(deviceCode, state.deviceCode),
        getUserCode: () => read(userCode, state.userCode),
        getXsrf: () => read(xsrf, state.xsrf),
        toJSON: (): never => fail('authorization-secret-lease'),
      });
      try {
        let result: Result;
        try {
          result = await use(scopedLease);
        } catch {
          return fail('authorization-secret-lease');
        }
        assertActive(state);
        pruneExpiredState(state);
        if (state.deviceCode !== deviceCode || state.userCode !== userCode || state.xsrf !== xsrf) {
          return fail('authorization-secret-lease');
        }
        fixedFailure('authorization-secret-lease', () => {
          assertDeviceAuthorizationEvidenceIsSanitized(result);
        });
        const serialized = fixedFailure(
          'authorization-secret-lease',
          () => JSON.stringify(result) ?? ''
        ).toLowerCase();
        if (
          [...registry.values].some(
            (sensitive) => sensitive.length > 0 && serialized.includes(sensitive.toLowerCase())
          )
        ) {
          return fail('authorization-secret-lease');
        }
        return result;
      } finally {
        valid = false;
        state.credentialLeaseActive = false;
      }
    },
    withEvidenceSecretLease: async <Result>(
      use: (evidenceLease: DeviceEvidenceSecretLease) => Result | Promise<Result>
    ): Promise<Result> => {
      assertAvailable(state);
      if (typeof use !== 'function') {
        return fail('evidence-secret-lease');
      }
      const deviceCode = state.deviceCode ?? fail('evidence-secret-lease');
      const userCode = state.userCode ?? fail('evidence-secret-lease');
      const auditXsrf = state.auditXsrf ?? fail('evidence-secret-lease');
      const { accessToken, refreshToken, idToken } = state;
      const registry: SensitiveRegistry = {
        values: new Set(),
        maximum: sensitiveVariantLimit,
        stage: 'evidence-secret-lease',
      };
      for (const secret of [deviceCode, userCode, auditXsrf, accessToken, refreshToken, idToken]) {
        if (secret !== undefined) {
          registerSensitiveValue(registry, secret);
        }
      }
      let valid = true;
      state.credentialLeaseActive = true;
      const read = (value: string | undefined, current: string | undefined) => {
        assertActive(state);
        pruneExpiredState(state);
        if (!valid || current !== value) {
          return fail('evidence-secret-lease');
        }
        return value;
      };
      const scopedLease: DeviceEvidenceSecretLease = Object.freeze({
        getDeviceCode: () => read(deviceCode, state.deviceCode) ?? fail('evidence-secret-lease'),
        getUserCode: () => read(userCode, state.userCode) ?? fail('evidence-secret-lease'),
        getAuditXsrf: () => read(auditXsrf, state.auditXsrf) ?? fail('evidence-secret-lease'),
        getAccessToken: () => read(accessToken, state.accessToken),
        getRefreshToken: () => read(refreshToken, state.refreshToken),
        getIdToken: () => read(idToken, state.idToken),
        toJSON: (): never => fail('evidence-secret-lease'),
      });
      try {
        let result: Result;
        try {
          result = await use(scopedLease);
        } catch {
          return fail('evidence-secret-lease');
        }
        assertActive(state);
        pruneExpiredState(state);
        fixedFailure('evidence-secret-lease', () => {
          assertDeviceAuthorizationEvidenceIsSanitized(result);
        });
        const serialized = fixedFailure(
          'evidence-secret-lease',
          () => JSON.stringify(result) ?? ''
        ).toLowerCase();
        if (
          [...registry.values].some(
            (sensitive) => sensitive.length > 0 && serialized.includes(sensitive.toLowerCase())
          )
        ) {
          return fail('evidence-secret-lease');
        }
        return result;
      } finally {
        valid = false;
        state.credentialLeaseActive = false;
      }
    },
    clear: () => {
      clearState(state);
    },
    toJSON: (): never => fail('lease'),
  });
  return lease;
};

/* eslint-enable complexity, max-lines, max-params, no-await-in-loop, no-control-regex, no-restricted-syntax, unicorn/prefer-switch, @typescript-eslint/no-unnecessary-condition, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
