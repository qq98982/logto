import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const suiteCommit = '0dc0e3a21ec411e92c808e5b2e2258592c22b594';
const configPlanName = 'oidcc-config-certification-test-plan';
const configTestName = 'oidcc-discovery-endpoint-verification';
const basicPlanName = 'oidcc-basic-certification-test-plan';
const alias = 'aster-phase1';
const configDescription = 'Aster phase 1 Config certification';
const basicDescription = 'Aster phase 1 Basic certification';
const maximumInputBytes = 65_536;
const maximumResponseBytes = 65_536;
const requestTimeoutMs = 40_000;
const terminalTimeoutMs = 220_000;
const basicModuleTimeoutMs = 300_000;
const basicTerminalTimeoutMs = 10_800_000;
const waitStateTimeoutMs = 30_000;
const diagnostic = 'Invalid official OIDF Config plan run';
const basicDiagnostic = 'Invalid official OIDF Basic plan run';
const planIdPattern = /^[A-Za-z0-9]{13}$/u;
const testIdPattern = /^[A-Za-z0-9]{15}$/u;
const expectedInputKeys = Object.freeze(['schemaVersion', 'suite', 'target', 'planId', 'variant']);
const expectedSuiteKeys = Object.freeze(['commit']);
const expectedTargetKeys = Object.freeze(['discoveryUrl', 'suiteBaseUrl', 'alias']);
const expectedVariantKeys = Object.freeze(['clientRegistration', 'serverMetadata']);
const expectedBasicTargetKeys = Object.freeze([
  'issuer',
  'discoveryUrl',
  'suiteBaseUrl',
  'alias',
  'callbackUri',
]);
const expectedBasicVariantKeys = Object.freeze([
  'clientRegistration',
  'serverMetadata',
  'responseType',
  'responseMode',
  'clientAuthTypes',
]);
const basicSecretPaths = Object.freeze({
  password: '/run/aster-secrets/phase1-user',
  basic1: '/run/aster-secrets/oidf-basic-1',
  basic2: '/run/aster-secrets/oidf-basic-2',
  post1: '/run/aster-secrets/oidf-post-1',
  publicMap: '/run/aster-secrets/oidf-conformance-public.json',
});
const browserResponseStatuses = Object.freeze([
  200,
  201,
  204,
  301,
  302,
  303,
  307,
  308,
  ...Array.from({ length: 100 }, (_, index) => 400 + index),
]);

// The pinned plan declares 38 entries; static_client removes the exact three entries annotated
// not-applicable for static registration, leaving this ordered 35-module API manifest.
const basicModuleNames = Object.freeze([
  'oidcc-server',
  'oidcc-response-type-missing',
  'oidcc-userinfo-get',
  'oidcc-userinfo-post-header',
  'oidcc-userinfo-post-body',
  'oidcc-ensure-request-without-nonce-succeeds-for-code-flow',
  'oidcc-scope-profile',
  'oidcc-scope-email',
  'oidcc-scope-address',
  'oidcc-scope-phone',
  'oidcc-scope-all',
  'oidcc-alternate-happy-flow',
  'oidcc-display-page',
  'oidcc-display-popup',
  'oidcc-prompt-login',
  'oidcc-prompt-none-not-logged-in',
  'oidcc-prompt-none-logged-in',
  'oidcc-max-age-1',
  'oidcc-max-age-10000',
  'oidcc-ensure-request-with-unknown-parameter-succeeds',
  'oidcc-id-token-hint',
  'oidcc-login-hint',
  'oidcc-ui-locales',
  'oidcc-claims-locales',
  'oidcc-ensure-request-with-acr-values-succeeds',
  'oidcc-codereuse',
  'oidcc-codereuse-30seconds',
  'oidcc-ensure-registered-redirect-uri',
  'oidcc-ensure-post-request-succeeds',
  'oidcc-server-client-secret-post',
  'oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported',
  'oidcc-claims-essential',
  'oidcc-ensure-request-object-with-redirect-uri',
  'oidcc-refresh-token',
  'oidcc-ensure-request-with-valid-pkce-succeeds',
]);

export const oidfBasicPlanManifest = Object.freeze(
  basicModuleNames.map((testModule) =>
    Object.freeze({
      testModule,
      variant: Object.freeze({
        response_type: 'code',
        client_auth_type:
          testModule === 'oidcc-server-client-secret-post'
            ? 'client_secret_post'
            : 'client_secret_basic',
        response_mode: 'default',
      }),
    })
  )
);

const invalid = () => new TypeError(diagnostic);
class BasicRunError extends TypeError {
  constructor(category, module) {
    super(basicDiagnostic);
    this.name = 'BasicRunError';
    this.category = category;
    this.module = module;
  }
}
const invalidBasic = (category = 'input', module) => new BasicRunError(category, module);
const isRecord = (value) =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype;
const hasExactKeys = (value, expected) => {
  const keys = Object.keys(value);
  return keys.length === expected.length && keys.every((key) => expected.includes(key));
};
const exactObject = (value, expected) =>
  isRecord(value) &&
  hasExactKeys(value, Object.keys(expected)) &&
  Object.entries(expected).every(([key, expectedValue]) => value[key] === expectedValue);

const decodeUtf8 = (bytes) => {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw invalid();
  }
};

const parseJson = (bytes) => {
  try {
    const source = decodeUtf8(bytes);
    if (source.length === 0 || source.charCodeAt(0) === 0xfeff) throw invalid();
    return JSON.parse(source);
  } catch {
    throw invalid();
  }
};

const requireHttpsUrl = (value, originOnly) => {
  if (typeof value !== 'string' || value.length < 1 || value.length > 2048) throw invalid();
  let url;
  try {
    url = new URL(value);
  } catch {
    throw invalid();
  }
  if (
    url.protocol !== 'https:' ||
    url.username !== '' ||
    url.password !== '' ||
    url.hash !== '' ||
    (originOnly && (url.pathname !== '/' || url.search !== ''))
  ) {
    throw invalid();
  }
  return originOnly ? url.origin : url.href;
};

const parseInput = (input) => {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  if (!(bytes instanceof Uint8Array) || bytes.byteLength < 1 || bytes.byteLength > maximumInputBytes) {
    throw invalid();
  }
  const value = parseJson(bytes);
  if (
    !isRecord(value) ||
    !hasExactKeys(value, expectedInputKeys) ||
    value.schemaVersion !== 1 ||
    !isRecord(value.suite) ||
    !hasExactKeys(value.suite, expectedSuiteKeys) ||
    value.suite.commit !== suiteCommit ||
    !isRecord(value.target) ||
    !hasExactKeys(value.target, expectedTargetKeys) ||
    value.target.alias !== alias ||
    value.planId !== configPlanName ||
    !isRecord(value.variant) ||
    !hasExactKeys(value.variant, expectedVariantKeys) ||
    value.variant.clientRegistration !== 'static_client' ||
    value.variant.serverMetadata !== 'discovery'
  ) {
    throw invalid();
  }
  return {
    discoveryUrl: requireHttpsUrl(value.target.discoveryUrl, false),
    suiteBaseUrl: requireHttpsUrl(value.target.suiteBaseUrl, true),
    variant: { ...value.variant },
  };
};

const requireBasicHttpsUrl = (value, originOnly, category = 'input') => {
  try {
    return requireHttpsUrl(value, originOnly);
  } catch {
    throw invalidBasic(category);
  }
};

const parseBasicInput = (input) => {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  if (!(bytes instanceof Uint8Array) || bytes.byteLength < 1 || bytes.byteLength > maximumInputBytes) {
    throw invalidBasic();
  }
  let value;
  try {
    value = parseJson(bytes);
  } catch {
    throw invalidBasic();
  }
  if (
    !isRecord(value) ||
    !hasExactKeys(value, expectedInputKeys) ||
    value.schemaVersion !== 1 ||
    !isRecord(value.suite) ||
    !hasExactKeys(value.suite, expectedSuiteKeys) ||
    value.suite.commit !== suiteCommit ||
    !isRecord(value.target) ||
    !hasExactKeys(value.target, expectedBasicTargetKeys) ||
    value.target.alias !== alias ||
    value.planId !== basicPlanName ||
    !isRecord(value.variant) ||
    !hasExactKeys(value.variant, expectedBasicVariantKeys) ||
    value.variant.clientRegistration !== 'static_client' ||
    value.variant.serverMetadata !== 'discovery' ||
    value.variant.responseType !== 'code' ||
    value.variant.responseMode !== 'default' ||
    !Array.isArray(value.variant.clientAuthTypes) ||
    value.variant.clientAuthTypes.length !== 2 ||
    value.variant.clientAuthTypes[0] !== 'client_secret_basic' ||
    value.variant.clientAuthTypes[1] !== 'client_secret_post'
  ) {
    throw invalidBasic();
  }
  const issuer = requireBasicHttpsUrl(value.target.issuer, false);
  const discoveryUrl = requireBasicHttpsUrl(value.target.discoveryUrl, false);
  const suiteBaseUrl = requireBasicHttpsUrl(value.target.suiteBaseUrl, true);
  const callbackUri = requireBasicHttpsUrl(value.target.callbackUri, false);
  const issuerUrl = new URL(issuer);
  const discovery = new URL(discoveryUrl);
  const callback = new URL(callbackUri);

  if (
    issuerUrl.pathname !== '/oidc' ||
    issuerUrl.search !== '' ||
    discovery.origin !== issuerUrl.origin ||
    discovery.pathname !== '/oidc/.well-known/openid-configuration' ||
    discovery.search !== '' ||
    callback.origin !== suiteBaseUrl ||
    callback.pathname !== `/test/a/${alias}/callback` ||
    callback.search !== ''
  ) {
    throw invalidBasic();
  }

  return Object.freeze({
    issuer,
    issuerOrigin: issuerUrl.origin,
    discoveryUrl,
    suiteBaseUrl,
    callbackUri,
    variant: Object.freeze({
      clientRegistration: 'static_client',
      serverMetadata: 'discovery',
      responseType: 'code',
      responseMode: 'default',
      clientAuthTypes: Object.freeze(['client_secret_basic', 'client_secret_post']),
    }),
  });
};

const readResponseBytes = async (response, maximumBytes) => {
  const contentLength = response.headers.get('content-length');
  if (contentLength !== null) {
    if (!/^[0-9]+$/u.test(contentLength) || Number(contentLength) > maximumBytes) throw invalid();
  }
  if (!response.body) throw invalid();
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) throw invalid();
      total += value.byteLength;
      if (total > maximumBytes) throw invalid();
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
};

const requestJson = async ({
  fetchImplementation,
  now,
  setTimer,
  clearTimer,
  perRequestTimeout,
  deadline,
  responseBytes,
  url,
  init,
  expectedStatus,
}) => {
  const remaining = deadline - now();
  if (!Number.isFinite(remaining) || remaining <= 0) throw invalid();
  const controller = new AbortController();
  const timer = setTimer(() => controller.abort(), Math.min(perRequestTimeout, remaining));
  try {
    const response = await fetchImplementation(url, { ...init, signal: controller.signal });
    if (!(response instanceof Response) || response.status !== expectedStatus) throw invalid();
    return parseJson(await readResponseBytes(response, responseBytes));
  } catch {
    throw invalid();
  } finally {
    clearTimer(timer);
  }
};

const decodeBasicJson = (bytes, category, module) => {
  try {
    return parseJson(bytes);
  } catch {
    throw invalidBasic(category, module);
  }
};

const readBasicResponseBytes = async (response, maximumBytes, category, module) => {
  const contentLength = response.headers.get('content-length');
  if (
    contentLength !== null &&
    (!/^[0-9]+$/u.test(contentLength) || Number(contentLength) > maximumBytes)
  ) {
    throw invalidBasic(category, module);
  }
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) throw invalidBasic(category, module);
      total += value.byteLength;
      if (total > maximumBytes) throw invalidBasic(category, module);
      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof BasicRunError) throw error;
    throw invalidBasic(category, module);
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
};

const basicRequestBytes = async ({
  fetchImplementation,
  now,
  setTimer,
  clearTimer,
  perRequestTimeout,
  deadline,
  responseBytes,
  url,
  init,
  expectedStatuses,
  category,
  module,
}) => {
  const remaining = deadline - now();
  if (!Number.isFinite(remaining) || remaining <= 0) {
    throw invalidBasic('timeout', module);
  }
  const controller = new AbortController();
  const timer = setTimer(() => controller.abort(), Math.min(perRequestTimeout, remaining));
  try {
    const response = await fetchImplementation(url, { ...init, signal: controller.signal });
    if (!(response instanceof Response) || !expectedStatuses.includes(response.status)) {
      throw invalidBasic(category, module);
    }
    const bytes = await readBasicResponseBytes(response, responseBytes, category, module);
    return Object.freeze({ status: response.status, headers: response.headers, bytes });
  } catch (error) {
    if (error instanceof BasicRunError) throw error;
    throw invalidBasic(category, module);
  } finally {
    clearTimer(timer);
  }
};

const basicRequestJson = async (options) => {
  const response = await basicRequestBytes(options);
  return decodeBasicJson(response.bytes, options.category, options.module);
};

const readPrivateText = (readSecret, secretPath, minimumBytes, maximumBytes) => {
  let bytes;
  try {
    bytes = readSecret(secretPath);
  } catch {
    throw invalidBasic('secret');
  }
  if (
    !(bytes instanceof Uint8Array) ||
    bytes.byteLength < minimumBytes ||
    bytes.byteLength > maximumBytes
  ) {
    throw invalidBasic('secret');
  }
  let value;
  try {
    value = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw invalidBasic('secret');
  }
  if (!/^[!-~]+$/u.test(value)) throw invalidBasic('secret');
  return value;
};

const readBasicSecrets = (readSecret) => {
  if (typeof readSecret !== 'function') throw invalidBasic('secret');
  const password = readPrivateText(readSecret, basicSecretPaths.password, 12, 256);
  const basic1 = readPrivateText(readSecret, basicSecretPaths.basic1, 12, 256);
  const basic2 = readPrivateText(readSecret, basicSecretPaths.basic2, 12, 256);
  const post1 = readPrivateText(readSecret, basicSecretPaths.post1, 12, 256);
  const secretValues = [password, basic1, basic2, post1];
  if (new Set(secretValues).size !== secretValues.length) throw invalidBasic('secret');

  let publicMapBytes;
  try {
    publicMapBytes = readSecret(basicSecretPaths.publicMap);
  } catch {
    throw invalidBasic('secret');
  }
  if (
    !(publicMapBytes instanceof Uint8Array) ||
    publicMapBytes.byteLength < 2 ||
    publicMapBytes.byteLength > 65_536
  ) {
    throw invalidBasic('secret');
  }
  const publicMap = decodeBasicJson(publicMapBytes, 'secret');
  if (
    !isRecord(publicMap) ||
    publicMap.schemaVersion !== 1 ||
    publicMap.recipe !== 'oidfConformance' ||
    !Array.isArray(publicMap.allocations) ||
    publicMap.allocations.length !== 1 ||
    !isRecord(publicMap.allocations[0]) ||
    typeof publicMap.allocations[0].allocationId !== 'string' ||
    publicMap.allocations[0].allocationId.length < 1 ||
    publicMap.allocations[0].allocationId.length > 1024
  ) {
    throw invalidBasic('secret');
  }
  const allocationId = publicMap.allocations[0].allocationId;
  const username = `phase1_user_a_${crypto
    .createHash('sha256')
    .update(allocationId, 'utf8')
    .digest('hex')
    .slice(0, 16)}`;

  return Object.freeze({ password, basic1, basic2, post1, username });
};

const basicPlanApiVariant = Object.freeze({
  server_metadata: 'discovery',
  client_registration: 'static_client',
});

const requireBasicPlanResponse = (value) => {
  if (
    !isRecord(value) ||
    value.name !== basicPlanName ||
    typeof value.id !== 'string' ||
    !planIdPattern.test(value.id) ||
    !Array.isArray(value.modules) ||
    value.modules.length !== oidfBasicPlanManifest.length
  ) {
    throw invalidBasic('plan-manifest');
  }
  for (const [index, expected] of oidfBasicPlanManifest.entries()) {
    const module = value.modules[index];
    if (
      !isRecord(module) ||
      module.testModule !== expected.testModule ||
      !exactObject(module.variant, expected.variant) ||
      !Array.isArray(module.instances) ||
      module.instances.length !== 0
    ) {
      throw invalidBasic('plan-manifest', expected.testModule);
    }
  }
  return value.id;
};

class MemoryCookieJar {
  constructor(now = Date.now) {
    this.cookies = new Map();
    this.now = now;
  }

  store(url, headers) {
    const values =
      typeof headers.getSetCookie === 'function'
        ? headers.getSetCookie()
        : headers.get('set-cookie')
          ? [headers.get('set-cookie')]
          : [];
    for (const source of values) {
      if (typeof source !== 'string') continue;
      const parts = source.split(';');
      const pair = parts.shift();
      const separator = pair?.indexOf('=') ?? -1;
      if (separator < 1) continue;
      const name = pair.slice(0, separator).trim();
      const value = pair.slice(separator + 1).trim();
      if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u.test(name)) continue;
      let domain = url.hostname.toLowerCase();
      let hostOnly = true;
      let cookiePath = this.defaultPath(url.pathname);
      let secure = false;
      let expired = false;
      let expiresAt = null;
      let maxAgeSeen = false;
      let valid = true;
      for (const attributeSource of parts) {
        const attribute = attributeSource.trim();
        const equals = attribute.indexOf('=');
        const key = (equals < 0 ? attribute : attribute.slice(0, equals)).toLowerCase();
        const attributeValue = equals < 0 ? '' : attribute.slice(equals + 1).trim();
        if (key === 'domain') {
          const candidate = attributeValue.replace(/^\./u, '').toLowerCase();
          if (
            candidate.length === 0 ||
            (url.hostname.toLowerCase() !== candidate &&
              !url.hostname.toLowerCase().endsWith(`.${candidate}`))
          ) {
            valid = false;
            break;
          }
          domain = candidate;
          hostOnly = false;
        } else if (key === 'path' && attributeValue.startsWith('/')) {
          cookiePath = attributeValue;
        } else if (key === 'secure') {
          secure = true;
        } else if (key === 'max-age' && /^-?[0-9]+$/u.test(attributeValue)) {
          maxAgeSeen = true;
          const seconds = Number(attributeValue);
          expired = seconds <= 0;
          const candidate = this.now() + seconds * 1000;
          expiresAt = expired || !Number.isFinite(candidate) ? null : candidate;
        } else if (key === 'expires' && !maxAgeSeen) {
          const expiry = Date.parse(attributeValue);
          if (Number.isFinite(expiry)) {
            expired = expiry <= this.now();
            expiresAt = expired ? null : expiry;
          }
        }
      }
      if (!valid) continue;
      const key = `${domain}\u0000${cookiePath}\u0000${name}`;
      if (expired || value.length === 0) {
        this.cookies.delete(key);
      } else {
        this.cookies.set(
          key,
          Object.freeze({ name, value, domain, hostOnly, path: cookiePath, secure, expiresAt })
        );
      }
    }
  }

  header(url) {
    const current = this.now();
    const available = [];
    for (const [key, cookie] of this.cookies) {
      if (cookie.expiresAt !== null && cookie.expiresAt <= current) {
        this.cookies.delete(key);
      } else {
        available.push(cookie);
      }
    }
    return available
      .filter((cookie) => {
        const host = url.hostname.toLowerCase();
        const domainMatches = cookie.hostOnly
          ? host === cookie.domain
          : host === cookie.domain || host.endsWith(`.${cookie.domain}`);
        return (
          domainMatches &&
          (!cookie.secure || url.protocol === 'https:') &&
          this.pathMatches(url.pathname, cookie.path)
        );
      })
      .sort((left, right) => right.path.length - left.path.length)
      .map(({ name, value }) => `${name}=${value}`)
      .join('; ');
  }

  defaultPath(pathname) {
    if (!pathname.startsWith('/') || pathname === '/') return '/';
    const lastSlash = pathname.lastIndexOf('/');
    return lastSlash <= 0 ? '/' : pathname.slice(0, lastSlash);
  }

  pathMatches(requestPath, cookiePath) {
    return (
      requestPath === cookiePath ||
      requestPath.startsWith(cookiePath.endsWith('/') ? cookiePath : `${cookiePath}/`)
    );
  }
}

const requireAllowedNavigationUrl = (value, config, category, module) => {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw invalidBasic(category, module);
  }
  if (
    url.protocol !== 'https:' ||
    url.username !== '' ||
    url.password !== '' ||
    url.hash !== '' ||
    ![config.issuerOrigin, config.suiteBaseUrl].includes(url.origin)
  ) {
    throw invalidBasic(category, module);
  }
  return url;
};

const requestWithCookieJar = async ({
  fetchImplementation,
  now,
  setTimer,
  clearTimer,
  perRequestTimeout,
  deadline,
  responseBytes,
  cookieJar,
  url,
  method,
  headers = {},
  body,
  category,
  module,
}) => {
  const cookie = cookieJar.header(url);
  const requestHeaders = { ...headers, ...(cookie && { cookie }) };
  const response = await basicRequestBytes({
    fetchImplementation,
    now,
    setTimer,
    clearTimer,
    perRequestTimeout,
    deadline,
    responseBytes,
    url: url.href,
    init: {
      method,
      redirect: 'manual',
      credentials: 'omit',
      headers: requestHeaders,
      ...(body !== undefined && { body }),
    },
    expectedStatuses: browserResponseStatuses,
    category,
    module,
  });
  cookieJar.store(url, response.headers);
  return response;
};

const requireEmptyResponse = (response, expectedStatus, category, module) => {
  if (response.status !== expectedStatus || response.bytes.byteLength !== 0) {
    throw invalidBasic(category, module);
  }
};

const requireJsonResponse = (response, expectedStatus, category, module) => {
  if (response.status !== expectedStatus || response.bytes.byteLength === 0) {
    throw invalidBasic(category, module);
  }
  return decodeBasicJson(response.bytes, category, module);
};

const applicationIdFromUiUrl = (url, module) => {
  const values = url.searchParams.getAll('app_id');
  if (
    values.length !== 1 ||
    !['oidf-basic-1', 'oidf-basic-2', 'oidf-post-1'].includes(values[0])
  ) {
    throw invalidBasic('browser-flow', module);
  }
  return values[0];
};

const experienceHeaders = (applicationId) => ({
  accept: 'application/json',
  'content-type': 'application/json',
  'aster-app-id': applicationId,
});

const performExperienceLogin = async (uiUrl, context) => {
  const applicationId = applicationIdFromUiUrl(uiUrl, context.module);
  const endpoint = (pathname) => new URL(pathname, context.config.issuerOrigin);
  const request = (url, method, headers, body) =>
    requestWithCookieJar({ ...context, url, method, headers, body, category: 'browser-flow' });
  requireEmptyResponse(
    await request(
      endpoint('/api/experience'),
      'PUT',
      experienceHeaders(applicationId),
      JSON.stringify({ interactionEvent: 'SignIn' })
    ),
    204,
    'browser-flow',
    context.module
  );
  const passwordBody = requireJsonResponse(
    await request(
      endpoint('/api/experience/verification/password'),
      'POST',
      experienceHeaders(applicationId),
      JSON.stringify({
        identifier: { type: 'username', value: context.secrets.username },
        password: context.secrets.password,
      })
    ),
    200,
    'browser-flow',
    context.module
  );
  if (
    !isRecord(passwordBody) ||
    typeof passwordBody.verificationId !== 'string' ||
    passwordBody.verificationId.length < 1 ||
    passwordBody.verificationId.length > 2048
  ) {
    throw invalidBasic('browser-flow', context.module);
  }
  requireEmptyResponse(
    await request(
      endpoint('/api/experience/identification'),
      'POST',
      experienceHeaders(applicationId),
      JSON.stringify({ verificationId: passwordBody.verificationId })
    ),
    204,
    'browser-flow',
    context.module
  );
  const submitBody = requireJsonResponse(
    await request(
      endpoint('/api/experience/submit'),
      'POST',
      { accept: 'application/json', 'aster-app-id': applicationId },
      undefined
    ),
    200,
    'browser-flow',
    context.module
  );
  if (!isRecord(submitBody) || typeof submitBody.redirectTo !== 'string') {
    throw invalidBasic('browser-flow', context.module);
  }
  const resumeUrl = requireAllowedNavigationUrl(
    submitBody.redirectTo,
    context.config,
    'browser-flow',
    context.module
  );
  if (resumeUrl.origin !== context.config.issuerOrigin || !resumeUrl.pathname.startsWith('/oidc/auth/')) {
    throw invalidBasic('browser-flow', context.module);
  }
  return Object.freeze({
    url: resumeUrl,
    method: 'GET',
    response: await request(resumeUrl, 'GET', { accept: 'text/html,application/xhtml+xml' }),
  });
};

const performConsent = async (uiUrl, context) => {
  const applicationId = applicationIdFromUiUrl(uiUrl, context.module);
  const consentUrl = new URL('/api/interaction/consent', context.config.issuerOrigin);
  const request = (method, headers, body) =>
    requestWithCookieJar({
      ...context,
      url: consentUrl,
      method,
      headers,
      body,
      category: 'browser-flow',
    });
  requireJsonResponse(
    await request('GET', { accept: 'application/json', 'aster-app-id': applicationId }),
    200,
    'browser-flow',
    context.module
  );
  const consentBody = requireJsonResponse(
    await request(
      'POST',
      {
        accept: 'application/json',
        'content-type': 'application/json;charset=utf-8',
        'aster-app-id': applicationId,
      },
      '{}'
    ),
    200,
    'browser-flow',
    context.module
  );
  if (!isRecord(consentBody) || typeof consentBody.redirectTo !== 'string') {
    throw invalidBasic('browser-flow', context.module);
  }
  const resumeUrl = requireAllowedNavigationUrl(
    consentBody.redirectTo,
    context.config,
    'browser-flow',
    context.module
  );
  if (resumeUrl.origin !== context.config.issuerOrigin || !resumeUrl.pathname.startsWith('/oidc/auth/')) {
    throw invalidBasic('browser-flow', context.module);
  }
  return Object.freeze({
    url: resumeUrl,
    method: 'GET',
    response: await requestWithCookieJar({
      ...context,
      url: resumeUrl,
      method: 'GET',
      headers: { accept: 'text/html,application/xhtml+xml' },
      category: 'browser-flow',
    }),
  });
};

const redirectTarget = (response, currentUrl, config, module) => {
  const location = response.headers.get('location');
  if (typeof location !== 'string' || location.length < 1 || location.length > 4096) {
    throw invalidBasic('browser-flow', module);
  }
  let absolute;
  try {
    absolute = new URL(location, currentUrl);
  } catch {
    throw invalidBasic('browser-flow', module);
  }
  return requireAllowedNavigationUrl(absolute.href, config, 'browser-flow', module);
};

const driveDeclaredBrowserUrl = async (declaration, context) => {
  let currentUrl = requireAllowedNavigationUrl(
    declaration.url,
    context.config,
    'browser-flow',
    context.module
  );
  let method = declaration.method;
  let body;
  let headers = { accept: 'text/html,application/xhtml+xml' };
  if (method === 'POST') {
    body = currentUrl.searchParams.toString();
    currentUrl = new URL(currentUrl.href);
    currentUrl.search = '';
    headers = {
      accept: 'text/html,application/xhtml+xml',
      'content-type': 'application/x-www-form-urlencoded',
    };
  }
  let pending;
  for (let step = 0; step < 32; step += 1) {
    const response =
      pending?.response ??
      (await requestWithCookieJar({
        ...context,
        url: currentUrl,
        method,
        headers,
        body,
        category: 'browser-flow',
      }));
    pending = undefined;
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const nextUrl = redirectTarget(response, currentUrl, context.config, context.module);
      if (nextUrl.origin === context.config.issuerOrigin && nextUrl.pathname === '/sign-in') {
        pending = await performExperienceLogin(nextUrl, context);
      } else if (nextUrl.origin === context.config.issuerOrigin && nextUrl.pathname === '/consent') {
        pending = await performConsent(nextUrl, context);
      } else {
        currentUrl = nextUrl;
        if (![307, 308].includes(response.status)) {
          method = 'GET';
          body = undefined;
          headers = { accept: 'text/html,application/xhtml+xml' };
        }
      }
      if (pending) {
        currentUrl = pending.url;
        method = pending.method;
        body = undefined;
        headers = { accept: 'text/html,application/xhtml+xml' };
      }
      continue;
    }
    if (
      (response.status >= 200 && response.status < 300) ||
      (response.status >= 400 && response.status < 500 && currentUrl.origin === context.config.issuerOrigin)
    ) {
      return;
    }
    throw invalidBasic('browser-flow', context.module);
  }
  throw invalidBasic('browser-flow', context.module);
};

const requireBrowserDeclarations = (value, expectedTestId, module) => {
  if (
    !isRecord(value) ||
    value.name !== module ||
    value.id !== expectedTestId ||
    !isRecord(value.browser) ||
    !Array.isArray(value.browser.urls) ||
    !Array.isArray(value.browser.urlsWithMethod) ||
    value.browser.urls.length !== value.browser.urlsWithMethod.length ||
    !Array.isArray(value.browser.browserApiRequests) ||
    value.browser.browserApiRequests.length !== 0 ||
    !Array.isArray(value.browser.uriInputRequests) ||
    value.browser.uriInputRequests.length !== 0
  ) {
    throw invalidBasic('browser-flow', module);
  }
  return Object.freeze(
    value.browser.urls.map((url, index) => {
      const withMethod = value.browser.urlsWithMethod[index];
      if (
        typeof url !== 'string' ||
        !isRecord(withMethod) ||
        !hasExactKeys(withMethod, ['url', 'method']) ||
        withMethod.url !== url ||
        !['GET', 'POST'].includes(withMethod.method)
      ) {
        throw invalidBasic('browser-flow', module);
      }
      return Object.freeze({ url, method: withMethod.method });
    })
  );
};

const markBrowserDeclarationVisited = async (declaration, testInstanceId, dependencies, module) => {
  const visitUrl = new URL(`/api/runner/browser/${testInstanceId}/visit`, dependencies.config.suiteBaseUrl);
  visitUrl.searchParams.set('url', declaration.url);
  const response = await basicRequestBytes({
    ...dependencies,
    url: visitUrl.href,
    init: {
      method: 'POST',
      redirect: 'error',
      credentials: 'omit',
      headers: { accept: 'application/json' },
    },
    expectedStatuses: [204],
    category: 'suite-api',
    module,
  });
  if (response.bytes.byteLength !== 0) throw invalidBasic('suite-api', module);
};

const requirePlanResponse = (value) => {
  if (
    !isRecord(value) ||
    value.name !== configPlanName ||
    typeof value.id !== 'string' ||
    !planIdPattern.test(value.id) ||
    !Array.isArray(value.modules) ||
    value.modules.length !== 1
  ) {
    throw invalid();
  }
  const module = value.modules[0];
  if (
    !isRecord(module) ||
    module.testModule !== configTestName ||
    !exactObject(module.variant, {
      server_metadata: 'discovery',
      client_registration: 'static_client',
    }) ||
    !Array.isArray(module.instances) ||
    module.instances.length !== 0
  ) {
    throw invalid();
  }
  return value.id;
};

const requireRunnerResponse = (value) => {
  if (
    !isRecord(value) ||
    value.name !== configTestName ||
    typeof value.id !== 'string' ||
    !testIdPattern.test(value.id)
  ) {
    throw invalid();
  }
  return value.id;
};

const requireInfoResponse = (value, expectedTestId, expectedPlanId) => {
  if (
    !isRecord(value) ||
    value.testId !== expectedTestId ||
    value.testName !== configTestName ||
    !exactObject(value.variant, {
      server_metadata: 'discovery',
      client_registration: 'static_client',
    }) ||
    value.planId !== expectedPlanId ||
    value.status !== 'FINISHED' ||
    value.result !== 'PASSED'
  ) {
    throw invalid();
  }
};

export const runOidfConfigPlan = async (input, dependencies = {}) => {
  try {
    const fetchImplementation = dependencies.fetch ?? globalThis.fetch;
    const now = dependencies.now ?? Date.now;
    const setTimer = dependencies.setTimer ?? globalThis.setTimeout;
    const clearTimer = dependencies.clearTimer ?? globalThis.clearTimeout;
    const perRequestTimeout = dependencies.requestTimeoutMs ?? requestTimeoutMs;
    const totalTimeout = dependencies.totalTimeoutMs ?? terminalTimeoutMs;
    const responseBytes = dependencies.maximumResponseBytes ?? maximumResponseBytes;
    if (
      typeof fetchImplementation !== 'function' ||
      typeof now !== 'function' ||
      typeof setTimer !== 'function' ||
      typeof clearTimer !== 'function' ||
      !Number.isSafeInteger(perRequestTimeout) ||
      perRequestTimeout < 1 ||
      perRequestTimeout > requestTimeoutMs ||
      !Number.isSafeInteger(totalTimeout) ||
      totalTimeout < 1 ||
      totalTimeout > terminalTimeoutMs ||
      !Number.isSafeInteger(responseBytes) ||
      responseBytes < 1 ||
      responseBytes > maximumResponseBytes
    ) {
      throw invalid();
    }
    const config = parseInput(input);
    const started = now();
    const deadline = started + totalTimeout;
    if (!Number.isFinite(started) || !Number.isFinite(deadline)) throw invalid();
    const planUrl = `${config.suiteBaseUrl}/api/plan?planName=${encodeURIComponent(configPlanName)}`;
    const planResponse = await requestJson({
      fetchImplementation,
      now,
      setTimer,
      clearTimer,
      perRequestTimeout,
      deadline,
      responseBytes,
      url: planUrl,
      init: {
        method: 'POST',
        redirect: 'error',
        credentials: 'omit',
        headers: { accept: 'application/json', 'content-type': 'application/json' },
        body: JSON.stringify({
          alias,
          description: configDescription,
          server: { discoveryUrl: config.discoveryUrl },
        }),
      },
      expectedStatus: 201,
    });
    const planInstanceId = requirePlanResponse(planResponse);
    const runnerUrl = `${config.suiteBaseUrl}/api/runner?test=${encodeURIComponent(
      configTestName
    )}&plan=${encodeURIComponent(planInstanceId)}`;
    const runnerResponse = await requestJson({
      fetchImplementation,
      now,
      setTimer,
      clearTimer,
      perRequestTimeout,
      deadline,
      responseBytes,
      url: runnerUrl,
      init: {
        method: 'POST',
        redirect: 'error',
        credentials: 'omit',
        headers: { accept: 'application/json', 'content-type': 'application/json' },
      },
      expectedStatus: 201,
    });
    const testInstanceId = requireRunnerResponse(runnerResponse);
    const waitUrl = `${config.suiteBaseUrl}/api/runner/${testInstanceId}/wait-state?states=FINISHED,INTERRUPTED&timeoutMs=${waitStateTimeoutMs}`;
    for (;;) {
      if (now() >= deadline) throw invalid();
      const waitResponse = await requestJson({
        fetchImplementation,
        now,
        setTimer,
        clearTimer,
        perRequestTimeout,
        deadline,
        responseBytes,
        url: waitUrl,
        init: {
          method: 'GET',
          redirect: 'error',
          credentials: 'omit',
          headers: { accept: 'application/json' },
        },
        expectedStatus: 200,
      });
      if (exactObject(waitResponse, { state: 'FINISHED' })) break;
      if (exactObject(waitResponse, { timeout: true })) continue;
      throw invalid();
    }
    const infoResponse = await requestJson({
      fetchImplementation,
      now,
      setTimer,
      clearTimer,
      perRequestTimeout,
      deadline,
      responseBytes,
      url: `${config.suiteBaseUrl}/api/info/${testInstanceId}?public=false`,
      init: {
        method: 'GET',
        redirect: 'error',
        credentials: 'omit',
        headers: { accept: 'application/json' },
      },
      expectedStatus: 200,
    });
    requireInfoResponse(infoResponse, testInstanceId, planInstanceId);
    return Object.freeze({
      schemaVersion: 1,
      kind: 'phase1-conformance-official-terminal',
      suiteCommit,
      planId: configPlanName,
      variant: Object.freeze({ ...config.variant }),
      status: 'PASSED',
      resultId: planInstanceId,
      result: Object.freeze({ outcome: 'passed', moduleCount: 1, passedModuleCount: 1 }),
    });
  } catch {
    throw invalid();
  }
};

const requireBasicRunnerResponse = (value, module) => {
  if (
    !isRecord(value) ||
    value.name !== module ||
    typeof value.id !== 'string' ||
    !testIdPattern.test(value.id)
  ) {
    throw invalidBasic('suite-api', module);
  }
  return value.id;
};

const combinedBasicVariant = (moduleVariant) =>
  Object.freeze({ ...basicPlanApiVariant, ...moduleVariant });

const requireBasicInfoResponse = (value, expectedTestId, expectedPlanId, manifestEntry) => {
  if (
    !isRecord(value) ||
    value.testId !== expectedTestId ||
    value.testName !== manifestEntry.testModule ||
    !exactObject(value.variant, combinedBasicVariant(manifestEntry.variant)) ||
    value.planId !== expectedPlanId ||
    value.status !== 'FINISHED' ||
    value.result !== 'PASSED'
  ) {
    throw invalidBasic('module-result', manifestEntry.testModule);
  }
};

const cancelBasicModule = async (testId, dependencies) => {
  const controller = new AbortController();
  const timer = dependencies.setTimer(() => controller.abort(), dependencies.perRequestTimeout);
  try {
    await dependencies.fetchImplementation(`${dependencies.config.suiteBaseUrl}/api/runner/${testId}`, {
      method: 'DELETE',
      redirect: 'error',
      credentials: 'omit',
      headers: { accept: 'application/json' },
      signal: controller.signal,
    });
  } catch {
    // Cancellation is best-effort and must not replace the bounded failure category.
  } finally {
    dependencies.clearTimer(timer);
  }
};

const runBasicModule = async (manifestEntry, planInstanceId, dependencies) => {
  const module = manifestEntry.testModule;
  const moduleStarted = dependencies.now();
  const moduleDeadline = Math.min(
    dependencies.totalDeadline,
    moduleStarted + dependencies.moduleTimeout
  );
  if (!Number.isFinite(moduleStarted) || moduleStarted >= moduleDeadline) {
    throw invalidBasic('timeout', module);
  }
  const runnerUrl = new URL('/api/runner', dependencies.config.suiteBaseUrl);
  runnerUrl.searchParams.set('test', module);
  runnerUrl.searchParams.set('plan', planInstanceId);
  // The pinned suite's own run-test-plan.py passes each plan entry variant here. This is how
  // repeated module classes are disambiguated while the plan-selected values still take priority.
  runnerUrl.searchParams.set('variant', JSON.stringify(manifestEntry.variant));
  let testInstanceId;
  try {
    const runnerResponse = await basicRequestJson({
      ...dependencies,
      deadline: moduleDeadline,
      url: runnerUrl.href,
      init: {
        method: 'POST',
        redirect: 'error',
        credentials: 'omit',
        headers: { accept: 'application/json', 'content-type': 'application/json' },
      },
      expectedStatuses: [201],
      category: 'suite-api',
      module,
    });
    testInstanceId = requireBasicRunnerResponse(runnerResponse, module);
    const cookieJar = new MemoryCookieJar(dependencies.now);
    let interactionStarted = false;
    for (;;) {
      if (dependencies.now() >= moduleDeadline) throw invalidBasic('timeout', module);
      const waitUrl = new URL(
        `/api/runner/${testInstanceId}/wait-state`,
        dependencies.config.suiteBaseUrl
      );
      waitUrl.searchParams.set(
        'states',
        interactionStarted ? 'FINISHED,INTERRUPTED' : 'WAITING,FINISHED,INTERRUPTED'
      );
      waitUrl.searchParams.set('timeoutMs', String(waitStateTimeoutMs));
      const waitResponse = await basicRequestJson({
        ...dependencies,
        deadline: moduleDeadline,
        url: waitUrl.href,
        init: {
          method: 'GET',
          redirect: 'error',
          credentials: 'omit',
          headers: { accept: 'application/json' },
        },
        expectedStatuses: [200],
        category: 'suite-api',
        module,
      });
      const waitTimedOut = exactObject(waitResponse, { timeout: true });
      if (waitTimedOut && !interactionStarted) continue;
      if (exactObject(waitResponse, { state: 'INTERRUPTED' })) {
        throw invalidBasic('module-result', module);
      }
      if (exactObject(waitResponse, { state: 'FINISHED' })) break;
      if (!exactObject(waitResponse, { state: 'WAITING' }) && !(waitTimedOut && interactionStarted)) {
        throw invalidBasic('suite-api', module);
      }
      interactionStarted = true;
      const runnerStatus = await basicRequestJson({
        ...dependencies,
        deadline: moduleDeadline,
        url: `${dependencies.config.suiteBaseUrl}/api/runner/${testInstanceId}`,
        init: {
          method: 'GET',
          redirect: 'error',
          credentials: 'omit',
          headers: { accept: 'application/json' },
        },
        expectedStatuses: [200],
        category: 'suite-api',
        module,
      });
      const declarations = requireBrowserDeclarations(runnerStatus, testInstanceId, module);
      for (const declaration of declarations) {
        await markBrowserDeclarationVisited(declaration, testInstanceId, {
          ...dependencies,
          deadline: moduleDeadline,
        }, module);
        await driveDeclaredBrowserUrl(declaration, {
          ...dependencies,
          deadline: moduleDeadline,
          cookieJar,
          module,
        });
      }
    }
    const infoResponse = await basicRequestJson({
      ...dependencies,
      deadline: moduleDeadline,
      url: `${dependencies.config.suiteBaseUrl}/api/info/${testInstanceId}?public=false`,
      init: {
        method: 'GET',
        redirect: 'error',
        credentials: 'omit',
        headers: { accept: 'application/json' },
      },
      expectedStatuses: [200],
      category: 'suite-api',
      module,
    });
    requireBasicInfoResponse(infoResponse, testInstanceId, planInstanceId, manifestEntry);
  } catch (error) {
    if (testInstanceId) await cancelBasicModule(testInstanceId, dependencies);
    if (error instanceof BasicRunError) {
      throw invalidBasic(error.category, error.module ?? module);
    }
    throw invalidBasic('suite-api', module);
  }
};

export const runOidfBasicPlan = async (input, dependencies = {}) => {
  try {
    const fetchImplementation = dependencies.fetch ?? globalThis.fetch;
    const readSecret = dependencies.readSecret ?? ((secretPath) => fs.readFileSync(secretPath));
    const now = dependencies.now ?? Date.now;
    const setTimer = dependencies.setTimer ?? globalThis.setTimeout;
    const clearTimer = dependencies.clearTimer ?? globalThis.clearTimeout;
    const perRequestTimeout = dependencies.requestTimeoutMs ?? requestTimeoutMs;
    const moduleTimeout = dependencies.moduleTimeoutMs ?? basicModuleTimeoutMs;
    const totalTimeout = dependencies.totalTimeoutMs ?? basicTerminalTimeoutMs;
    const responseBytes = dependencies.maximumResponseBytes ?? maximumResponseBytes;
    if (
      typeof fetchImplementation !== 'function' ||
      typeof readSecret !== 'function' ||
      typeof now !== 'function' ||
      typeof setTimer !== 'function' ||
      typeof clearTimer !== 'function' ||
      !Number.isSafeInteger(perRequestTimeout) ||
      perRequestTimeout < 1 ||
      perRequestTimeout > requestTimeoutMs ||
      !Number.isSafeInteger(moduleTimeout) ||
      moduleTimeout < 1 ||
      moduleTimeout > basicModuleTimeoutMs ||
      !Number.isSafeInteger(totalTimeout) ||
      totalTimeout < 1 ||
      totalTimeout > basicTerminalTimeoutMs ||
      !Number.isSafeInteger(responseBytes) ||
      responseBytes < 1 ||
      responseBytes > maximumResponseBytes
    ) {
      throw invalidBasic();
    }
    const config = parseBasicInput(input);
    const secrets = readBasicSecrets(readSecret);
    const started = now();
    const totalDeadline = started + totalTimeout;
    if (!Number.isFinite(started) || !Number.isFinite(totalDeadline)) throw invalidBasic();
    const planUrl = new URL('/api/plan', config.suiteBaseUrl);
    planUrl.searchParams.set('planName', basicPlanName);
    planUrl.searchParams.set('variant', JSON.stringify(basicPlanApiVariant));
    const planResponse = await basicRequestJson({
      fetchImplementation,
      now,
      setTimer,
      clearTimer,
      perRequestTimeout,
      deadline: totalDeadline,
      responseBytes,
      url: planUrl.href,
      init: {
        method: 'POST',
        redirect: 'error',
        credentials: 'omit',
        headers: { accept: 'application/json', 'content-type': 'application/json' },
        body: JSON.stringify({
          alias,
          description: basicDescription,
          server: { discoveryUrl: config.discoveryUrl },
          client: { client_id: 'oidf-basic-1', client_secret: secrets.basic1 },
          client2: { client_id: 'oidf-basic-2', client_secret: secrets.basic2 },
          client_secret_post: { client_id: 'oidf-post-1', client_secret: secrets.post1 },
          browser: [],
        }),
      },
      expectedStatuses: [201],
      category: 'suite-api',
    });
    const planInstanceId = requireBasicPlanResponse(planResponse);
    const runtimeDependencies = Object.freeze({
      fetchImplementation,
      now,
      setTimer,
      clearTimer,
      perRequestTimeout,
      moduleTimeout,
      totalDeadline,
      responseBytes,
      config,
      secrets,
    });
    for (const manifestEntry of oidfBasicPlanManifest) {
      await runBasicModule(manifestEntry, planInstanceId, runtimeDependencies);
    }
    return Object.freeze({
      schemaVersion: 1,
      kind: 'phase1-conformance-official-terminal',
      suiteCommit,
      planId: basicPlanName,
      variant: config.variant,
      status: 'PASSED',
      resultId: planInstanceId,
      result: Object.freeze({
        outcome: 'passed',
        moduleCount: oidfBasicPlanManifest.length,
        passedModuleCount: oidfBasicPlanManifest.length,
      }),
    });
  } catch (error) {
    if (error instanceof BasicRunError) throw error;
    throw invalidBasic();
  }
};

const basicFailureTerminal = (error) =>
  Object.freeze({
    schemaVersion: 1,
    kind: 'phase1-conformance-official-failure-terminal',
    suiteCommit,
    planId: basicPlanName,
    module: error.module ?? null,
    status: 'FAILED',
    result: 'FAILED',
    failureCategory: error.category,
  });

const main = async () => {
  const args = process.argv.slice(2);
  if (args.length === 2 && args[0] === '--plan-id' && args[1] === basicPlanName) {
    try {
      const terminal = await runOidfBasicPlan(fs.readFileSync(0));
      process.stdout.write(JSON.stringify(terminal));
    } catch (error) {
      process.stdout.write(
        JSON.stringify(
          basicFailureTerminal(
            error instanceof BasicRunError ? error : invalidBasic('input')
          )
        )
      );
      process.exitCode = 1;
    }
    return;
  }
  try {
    if (args.length !== 2 || args[0] !== '--plan-id' || args[1] !== configPlanName) throw invalid();
    const terminal = await runOidfConfigPlan(fs.readFileSync(0));
    process.stdout.write(JSON.stringify(terminal));
  } catch {
    process.exitCode = 1;
  }
};

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  await main();
}
