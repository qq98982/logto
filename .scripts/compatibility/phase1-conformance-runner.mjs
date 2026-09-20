import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  awaitScreenshotReview,
  beginScreenshotHandoff,
  consumeScreenshotResponse,
  createScreenshotBinding,
  requireScreenshotCookies,
  screenshotConditionMappings,
  verifyModuleAudits,
  writeModuleAudit,
} from './phase1-screenshot-handoff.mjs';

const suiteCommit = '0dc0e3a21ec411e92c808e5b2e2258592c22b594';
const configPlanName = 'oidcc-config-certification-test-plan';
const configTestName = 'oidcc-discovery-endpoint-verification';
const basicPlanName = 'oidcc-basic-certification-test-plan';
const alias = 'aster-phase1';
const configDescription = 'Aster phase 1 Config certification';
const basicDescription = 'Aster phase 1 Basic certification';
const mandatoryScreenshotModules = Object.freeze([
  'oidcc-prompt-login',
  'oidcc-max-age-1',
  'oidcc-ensure-registered-redirect-uri',
]);
const maximumInputBytes = 65_536;
const maximumResponseBytes = 65_536;
const maximumConditionLogBytes = 16_777_216;
const maximumImageUploadResponseBytes = 1_048_576;
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
      let httpOnly = false;
      let sameSite = 'Lax';
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
        } else if (key === 'httponly') {
          httpOnly = true;
        } else if (key === 'samesite') {
          const normalized = attributeValue.toLowerCase();
          if (normalized === 'strict') sameSite = 'Strict';
          else if (normalized === 'lax') sameSite = 'Lax';
          else if (normalized === 'none') sameSite = 'None';
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
      if (sameSite === 'None' && !secure) continue;
      const key = `${domain}\u0000${cookiePath}\u0000${name}`;
      if (expired || value.length === 0) {
        this.cookies.delete(key);
      } else {
        this.cookies.set(
          key,
          Object.freeze({
            name,
            value,
            domain,
            hostOnly,
            path: cookiePath,
            expiresAt,
            httpOnly,
            secure,
            sameSite,
          })
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

  issuerCookies(url) {
    const host = url.hostname.toLowerCase();
    const current = this.now();
    const cookies = [];
    for (const [key, cookie] of this.cookies) {
      if (cookie.expiresAt !== null && cookie.expiresAt <= current) {
        this.cookies.delete(key);
        continue;
      }
      const domainMatches = cookie.hostOnly
        ? host === cookie.domain
        : host === cookie.domain || host.endsWith(`.${cookie.domain}`);
      if (!domainMatches) continue;
      cookies.push(
        Object.freeze({
          name: cookie.name,
          value: cookie.value,
          domain: cookie.hostOnly ? cookie.domain : `.${cookie.domain}`,
          path: cookie.path,
          expires: cookie.expiresAt === null ? -1 : cookie.expiresAt / 1000,
          httpOnly: cookie.httpOnly,
          secure: cookie.secure,
          sameSite: cookie.sameSite,
        })
      );
    }
    return Object.freeze(
      cookies.toSorted((left, right) =>
        `${left.domain}\u0000${left.path}\u0000${left.name}`.localeCompare(
          `${right.domain}\u0000${right.path}\u0000${right.name}`
        )
      )
    );
  }

  replaceIssuerCookies(url, values) {
    const cookies = requireScreenshotCookies(values);
    const host = url.hostname.toLowerCase();
    const current = this.now();
    for (const [key, cookie] of this.cookies) {
      const domainMatches = cookie.hostOnly
        ? host === cookie.domain
        : host === cookie.domain || host.endsWith(`.${cookie.domain}`);
      if (domainMatches) this.cookies.delete(key);
    }
    for (const cookie of cookies) {
      const hostOnly = !cookie.domain.startsWith('.');
      const domain = cookie.domain.replace(/^\./u, '').toLowerCase();
      const domainMatches = hostOnly
        ? host === domain
        : host === domain || host.endsWith(`.${domain}`);
      const expiresAt = cookie.expires === -1 ? null : Math.floor(cookie.expires * 1000);
      if (
        !domainMatches ||
        (expiresAt !== null && expiresAt <= current) ||
        (cookie.sameSite === 'None' && !cookie.secure)
      ) {
        throw invalidBasic('screenshot-handoff');
      }
      const key = `${domain}\u0000${cookie.path}\u0000${cookie.name}`;
      this.cookies.set(
        key,
        Object.freeze({
          name: cookie.name,
          value: cookie.value,
          domain,
          hostOnly,
          path: cookie.path,
          expiresAt,
          httpOnly: cookie.httpOnly,
          secure: cookie.secure,
          sameSite: cookie.sameSite,
        })
      );
    }
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
  if (
    absolute.hash &&
    absolute.origin === config.suiteBaseUrl &&
    absolute.pathname === new URL(config.callbackUri).pathname
  ) {
    const hash = absolute.hash;
    absolute.hash = '';
    requireAllowedNavigationUrl(absolute.href, config, 'browser-flow', module);
    absolute.hash = hash;
    return absolute;
  }
  return requireAllowedNavigationUrl(absolute.href, config, 'browser-flow', module);
};

const implicitSubmissionUrl = (response, config, module) => {
  if (
    response.status !== 200 ||
    !/^text\/html(?:\s*;|$)/iu.test(response.headers.get('content-type') ?? '')
  ) {
    throw invalidBasic('browser-flow', module);
  }
  let html;
  try {
    html = new TextDecoder('utf-8', { fatal: true }).decode(response.bytes);
  } catch {
    throw invalidBasic('browser-flow', module);
  }
  const submissions = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script\s*>/giu)].flatMap(
    ([, script]) => [...script.matchAll(/\bxhr\.open\(\s*'POST'\s*,\s*("(?:\\.|[^"\\])*")\s*,\s*true\s*\)/gu)]
  );
  if (submissions.length !== 1) throw invalidBasic('browser-flow', module);
  let value;
  try {
    value = JSON.parse(submissions[0][1]);
  } catch {
    throw invalidBasic('browser-flow', module);
  }
  if (typeof value !== 'string') throw invalidBasic('browser-flow', module);
  const url = requireAllowedNavigationUrl(value, config, 'browser-flow', module);
  if (
    url.href !== value ||
    url.origin !== config.suiteBaseUrl ||
    !/^\/test\/a\/aster-phase1\/implicit\/[A-Za-z0-9]{20}$/u.test(url.pathname) ||
    url.search !== ''
  ) {
    throw invalidBasic('browser-flow', module);
  }
  return url;
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
  let callbackHash = '';
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
  let screenshotEvidence = null;
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
        if (context.screenshot?.mapping.captureKind === 'second-sign-in') {
          if (screenshotEvidence !== null) {
            throw invalidBasic('screenshot-condition', context.module);
          }
          screenshotEvidence = await captureAndReviewScreenshot(nextUrl, context);
        }
        pending = await performExperienceLogin(nextUrl, context);
      } else if (nextUrl.origin === context.config.issuerOrigin && nextUrl.pathname === '/consent') {
        pending = await performConsent(nextUrl, context);
      } else {
        callbackHash = nextUrl.hash;
        nextUrl.hash = '';
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
      currentUrl.origin === context.config.suiteBaseUrl &&
      currentUrl.pathname === new URL(context.config.callbackUri).pathname
    ) {
      const submissionUrl = implicitSubmissionUrl(response, context.config, context.module);
      requireEmptyResponse(
        await requestWithCookieJar({
          ...context,
          url: submissionUrl,
          method: 'POST',
          headers: { accept: '*/*', 'content-type': 'text/plain' },
          body: callbackHash,
          category: 'browser-flow',
        }),
        204,
        'browser-flow',
        context.module
      );
      if (
        context.screenshot &&
        screenshotEvidence === null &&
        (context.screenshot.mapping.captureKind !== 'ui-error' ||
          mandatoryScreenshotModules.includes(context.module))
      ) {
        throw invalidBasic('screenshot-condition', context.module);
      }
      return Object.freeze({
        screenshotEvidence,
        callbackPlaceholder:
          screenshotEvidence === null ? context.screenshot : null,
      });
    }
    if (
      (response.status >= 200 && response.status < 300) ||
      (response.status >= 400 && response.status < 500 && currentUrl.origin === context.config.issuerOrigin)
    ) {
      if (context.screenshot) {
        if (
          context.screenshot.mapping.captureKind !== 'ui-error' ||
          currentUrl.origin !== context.config.issuerOrigin ||
          currentUrl.pathname === '/oidc/auth' ||
          currentUrl.pathname.startsWith('/oidc/auth/') ||
          screenshotEvidence !== null
        ) {
          throw invalidBasic('screenshot-condition', context.module);
        }
        screenshotEvidence = await captureAndReviewScreenshot(currentUrl, context);
      }
      return Object.freeze({ screenshotEvidence, callbackPlaceholder: null });
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
  if (
    !Number.isSafeInteger(value.browser.uploadsRequired) ||
    value.browser.uploadsRequired < 0
  ) {
    throw invalidBasic('suite-api', module);
  }
  const declarations = value.browser.urls.map((url, index) => {
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
    });
  return Object.freeze({
    declarations: Object.freeze(declarations),
    uploadsRequired: value.browser.uploadsRequired,
  });
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
    value.status !== 'FINISHED'
  ) {
    throw invalidBasic('module-result', manifestEntry.testModule);
  }
  if (
    !['PASSED', 'REVIEW'].includes(value.result) ||
    (mandatoryScreenshotModules.includes(manifestEntry.testModule) && value.result !== 'REVIEW')
  ) {
    throw invalidBasic('module-result', manifestEntry.testModule);
  }
  return value.result;
};

const requireCleanConditionLog = (conditionLog, module) => {
  if (conditionLog.entries.some(({ result }) => result === 'FAILURE' || result === 'WARNING')) {
    throw invalidBasic('condition-log', module);
  }
};

const fetchBasicConditionLog = async (testId, dependencies, module, deferFindings = false) => {
  const response = await basicRequestBytes({
    ...dependencies,
    responseBytes: maximumConditionLogBytes,
    url: `${dependencies.config.suiteBaseUrl}/api/log/${testId}?public=false`,
    init: {
      method: 'GET',
      redirect: 'error',
      credentials: 'omit',
      headers: { accept: 'application/json' },
    },
    expectedStatuses: [200],
    category: 'condition-log',
    module,
  });
  const entries = decodeBasicJson(response.bytes, 'condition-log', module);
  if (!Array.isArray(entries)) throw invalidBasic('condition-log', module);
  for (const entry of entries) {
    if (
      !isRecord(entry) ||
      entry.testId !== testId ||
      typeof entry.src !== 'string' ||
      entry.src.length < 1 ||
      entry.src.length > 256 ||
      (entry.result !== undefined && typeof entry.result !== 'string')
    ) {
      throw invalidBasic('condition-log', module);
    }
  }
  const conditionLog = Object.freeze({
    entries: Object.freeze(entries),
    sha256: crypto.createHash('sha256').update(response.bytes).digest('hex'),
  });
  if (!deferFindings) requireCleanConditionLog(conditionLog, module);
  return conditionLog;
};

const auditStatusValues = new Set([
  'NOT_YET_CREATED', 'CREATED', 'CONFIGURED', 'RUNNING', 'WAITING', 'INTERRUPTED', 'FINISHED',
]);
const auditResultValues = new Set(['PASSED', 'FAILED', 'WARNING', 'REVIEW', 'SKIPPED', 'UNKNOWN']);
const auditConditionValues = new Set([
  ...auditStatusValues, ...auditResultValues, 'FAILURE', 'INFO', 'SUCCESS',
]);

const conditionLedger = (conditionLog, module) => conditionLog.entries.map((entry) => {
  const resultPresent = Object.hasOwn(entry, 'result');
  if (
    (entry._id !== undefined && (typeof entry._id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/u.test(entry._id))) ||
    (entry.src !== '-START-BLOCK-' &&
      !/^[A-Za-z0-9_][A-Za-z0-9_. -]{0,255}$/u.test(entry.src)) ||
    (resultPresent && !auditConditionValues.has(entry.result)) ||
    (Object.hasOwn(entry, 'requirements') && (
      !Array.isArray(entry.requirements) || entry.requirements.length > 256 ||
      entry.requirements.some((value) => typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value))
    )) ||
    (Object.hasOwn(entry, 'upload') && (typeof entry.upload !== 'string' || !/^[A-Za-z0-9]{10}$/u.test(entry.upload))) ||
    (Object.hasOwn(entry, 'image_no_longer_required') && typeof entry.image_no_longer_required !== 'boolean')
  ) throw invalidBasic('module-audit', module);
  let imageSha256;
  if (Object.hasOwn(entry, 'img')) {
    const match = typeof entry.img === 'string' && /^data:image\/(?:png|jpeg);base64,([A-Za-z0-9+/]+={0,2})$/u.exec(entry.img);
    if (!match) throw invalidBasic('module-audit', module);
    const bytes = Buffer.from(match[1], 'base64');
    if (bytes.byteLength < 1 || bytes.byteLength > 512_000 || bytes.toString('base64') !== match[1]) {
      throw invalidBasic('module-audit', module);
    }
    imageSha256 = crypto.createHash('sha256').update(bytes).digest('hex');
  }
  return Object.freeze({
    _id: entry._id ?? null,
    testId: entry.testId,
    src: entry.src,
    resultPresent,
    result: resultPresent ? entry.result : null,
    ...(Object.hasOwn(entry, 'requirements') && { requirements: [...entry.requirements] }),
    ...(Object.hasOwn(entry, 'upload') && { upload: entry.upload }),
    ...(Object.hasOwn(entry, 'image_no_longer_required') && { image_no_longer_required: entry.image_no_longer_required }),
    ...(imageSha256 !== undefined && { imageSha256 }),
  });
});

const persistBasicModuleAudit = ({
  root, planInstanceId, testId, manifestEntry, info, infoSha256, conditionLog, screenshotEvidence,
  failureCategory = null,
}) => {
  const module = manifestEntry.testModule;
  if (
    !isRecord(info) || info.testId !== testId || info.testName !== module ||
    info.planId !== planInstanceId || !auditStatusValues.has(info.status) ||
    !auditResultValues.has(info.result) ||
    !exactObject(info.variant, combinedBasicVariant(manifestEntry.variant))
  ) throw invalidBasic('module-audit', module);
  try {
    return writeModuleAudit(root, {
      schemaVersion: 1,
      kind: 'phase1-conformance-module-audit',
      suiteCommit,
      planName: basicPlanName,
      planInstanceId,
      moduleName: module,
      testId,
      info: {
        testId: info.testId, testName: info.testName, status: info.status, result: info.result,
        variant: { ...info.variant }, planId: info.planId,
      },
      infoSha256,
      conditionLogSha256: conditionLog.sha256,
      conditionCount: conditionLog.entries.length,
      conditions: conditionLedger(conditionLog, module),
      captureId: screenshotEvidence?.captureId ?? null,
      review: screenshotEvidence === null ? null : {
        placeholderId: screenshotEvidence.placeholderId,
        conditionId: screenshotEvidence.conditionId,
        imageSha256: screenshotEvidence.imageSha256,
        reviewRecordSha256: screenshotEvidence.reviewRecordSha256,
        reviewer: screenshotEvidence.reviewer,
        decision: 'APPROVE',
      },
      accepted: failureCategory === null,
      failureCategory,
    });
  } catch {
    throw invalidBasic('module-audit', module);
  }
};

const requireScreenshotPlaceholder = (conditionLog, testId, module) => {
  const mapping = screenshotConditionMappings[module];
  if (!mapping) throw invalidBasic('screenshot-condition', module);
  const reviews = conditionLog.entries.filter(({ result }) => result === 'REVIEW');
  if (reviews.length !== 1) throw invalidBasic('condition-log', module);
  const entry = reviews[0];
  if (
    entry.testId !== testId ||
    entry.src !== mapping.conditionId ||
    entry.msg !== mapping.message ||
    typeof entry._id !== 'string' ||
    entry._id.length < 1 ||
    entry._id.length > 128 ||
    typeof entry.upload !== 'string' ||
    !/^[A-Za-z0-9]{10}$/u.test(entry.upload) ||
    entry.img !== undefined
  ) {
    throw invalidBasic('screenshot-condition', module);
  }
  return Object.freeze({
    mapping,
    placeholderId: entry.upload,
    logEntryId: entry._id,
  });
};

const requireScreenshotUploadResponse = (
  value,
  expected,
  testId,
  module,
  imageDataUrl
) => {
  if (
    !isRecord(value) ||
    value._id !== expected.logEntryId ||
    value.testId !== testId ||
    value.src !== expected.mapping.conditionId ||
    value.msg !== expected.mapping.message ||
    value.result !== 'REVIEW' ||
    value.img !== imageDataUrl ||
    Object.hasOwn(value, 'upload')
  ) {
    throw invalidBasic('screenshot-upload', module);
  }
};

const captureAndReviewScreenshot = async (captureUrl, context) => {
  const screenshot = context.screenshot;
  if (!screenshot) throw invalidBasic('screenshot-handoff', context.module);
  const remaining = context.deadline - context.now();
  const createdAt = context.wallClock();
  if (
    !Number.isFinite(remaining) ||
    remaining <= 0 ||
    !Number.isSafeInteger(createdAt) ||
    createdAt < 0 ||
    typeof context.screenshotIpcRoot !== 'string'
  ) {
    throw invalidBasic('screenshot-handoff', context.module);
  }
  const deadline = createdAt + Math.floor(remaining);
  if (!Number.isSafeInteger(deadline) || deadline <= createdAt) {
    throw invalidBasic('screenshot-handoff', context.module);
  }
  let handoff;
  try {
    const binding = createScreenshotBinding({
      schemaVersion: 1,
      suiteCommit,
      planName: basicPlanName,
      planInstanceId: context.planInstanceId,
      moduleName: context.module,
      testId: context.testInstanceId,
      placeholderId: screenshot.placeholderId,
      conditionId: screenshot.mapping.conditionId,
      captureId: crypto.randomBytes(16).toString('hex'),
      captureKind: screenshot.mapping.captureKind,
      createdAt,
      deadline,
    });
    handoff = await beginScreenshotHandoff({
      root: context.screenshotIpcRoot,
      binding,
      url: captureUrl.href,
      issuerOrigin: context.config.issuerOrigin,
      cookies: context.cookieJar.issuerCookies(new URL(context.config.issuerOrigin)),
    });
    try {
      context.cookieJar.replaceIssuerCookies(
        new URL(context.config.issuerOrigin),
        handoff.cookies
      );
    } finally {
      consumeScreenshotResponse(handoff);
    }
    const imageDataUrl = `data:image/png;base64,${handoff.imageBytes.toString('base64')}`;
    const uploadResponse = await basicRequestBytes({
      ...context,
      responseBytes: maximumImageUploadResponseBytes,
      url: `${context.config.suiteBaseUrl}/api/log/${context.testInstanceId}/images/${screenshot.placeholderId}`,
      init: {
        method: 'POST',
        redirect: 'error',
        credentials: 'omit',
        headers: { accept: 'application/json', 'content-type': 'text/plain;charset=UTF-8' },
        body: imageDataUrl,
      },
      expectedStatuses: [200],
      category: 'screenshot-upload',
      module: context.module,
    });
    requireScreenshotUploadResponse(
      decodeBasicJson(uploadResponse.bytes, 'screenshot-upload', context.module),
      screenshot,
      context.testInstanceId,
      context.module,
      imageDataUrl
    );
    const review = await awaitScreenshotReview(handoff);
    return Object.freeze({
      placeholderId: screenshot.placeholderId,
      conditionId: screenshot.mapping.conditionId,
      imageSha256: handoff.imageSha256,
      reviewRecordSha256: review.reviewRecordSha256,
      reviewer: review.reviewer,
      decision: 'APPROVE',
      captureId: handoff.binding.captureId,
      logEntryId: screenshot.logEntryId,
      imageDataUrl,
    });
  } catch (error) {
    if (error instanceof BasicRunError) throw error;
    throw invalidBasic('screenshot-handoff', context.module);
  }
};

const validateFinalConditionLog = (
  conditionLog,
  officialResult,
  screenshotEvidence,
  callbackPlaceholder,
  testId,
  module
) => {
  requireCleanConditionLog(conditionLog, module);
  const reviews = conditionLog.entries.filter(({ result }) => result === 'REVIEW');
  if (officialResult === 'PASSED') {
    if (screenshotEvidence !== null) {
      throw invalidBasic('condition-log', module);
    }
    if (callbackPlaceholder === null) {
      if (reviews.length !== 0) throw invalidBasic('condition-log', module);
      return;
    }
    const mapping = screenshotConditionMappings[module];
    const review = reviews[0];
    // A successful protocol callback can retire only its own optional UI-error placeholder.
    if (
      mapping?.captureKind !== 'ui-error' ||
      reviews.length !== 1 ||
      review.testId !== testId ||
      review._id !== callbackPlaceholder.logEntryId ||
      review.src !== mapping.conditionId ||
      review.msg !== mapping.message ||
      review.image_no_longer_required !== true ||
      Object.hasOwn(review, 'img') ||
      Object.hasOwn(review, 'upload')
    ) {
      throw invalidBasic('condition-log', module);
    }
    return;
  }
  const mapping = screenshotConditionMappings[module];
  if (!mapping || screenshotEvidence === null || reviews.length !== 1) {
    throw invalidBasic('condition-log', module);
  }
  const review = reviews[0];
  if (
    review.testId !== testId ||
    review._id !== screenshotEvidence.logEntryId ||
    review.src !== mapping.conditionId ||
    review.msg !== mapping.message ||
    review.img !== screenshotEvidence.imageDataUrl ||
    Object.hasOwn(review, 'upload')
  ) {
    throw invalidBasic('condition-log', module);
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
  let screenshotEvidence = null;
  let callbackPlaceholder = null;
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
      const browserStatus = requireBrowserDeclarations(runnerStatus, testInstanceId, module);
      const { declarations, uploadsRequired } = browserStatus;
      // WAITING can be observed before the suite queues its browser declaration.
      if (
        !waitTimedOut &&
        uploadsRequired > 0 &&
        declarations.length === 0
      ) {
        continue;
      }
      let pendingScreenshot = null;
      if (uploadsRequired > 0) {
        if (
          uploadsRequired !== 1 ||
          declarations.length !== 1 ||
          screenshotEvidence !== null ||
          callbackPlaceholder !== null ||
          !screenshotConditionMappings[module]
        ) {
          throw invalidBasic('screenshot-condition', module);
        }
        pendingScreenshot = requireScreenshotPlaceholder(
          await fetchBasicConditionLog(testInstanceId, {
            ...dependencies,
            deadline: moduleDeadline,
          }, module),
          testInstanceId,
          module
        );
      }
      if (waitTimedOut && declarations.length === 0 && uploadsRequired > 0) {
        throw invalidBasic('screenshot-condition', module);
      }
      for (const declaration of declarations) {
        await markBrowserDeclarationVisited(declaration, testInstanceId, {
          ...dependencies,
          deadline: moduleDeadline,
        }, module);
        const browserResult = await driveDeclaredBrowserUrl(declaration, {
          ...dependencies,
          deadline: moduleDeadline,
          cookieJar,
          module,
          planInstanceId,
          testInstanceId,
          screenshot: pendingScreenshot,
        });
        if (browserResult.screenshotEvidence !== null) {
          if (screenshotEvidence !== null) throw invalidBasic('screenshot-condition', module);
          screenshotEvidence = browserResult.screenshotEvidence;
        }
        if (browserResult.callbackPlaceholder !== null) {
          if (callbackPlaceholder !== null) throw invalidBasic('screenshot-condition', module);
          callbackPlaceholder = browserResult.callbackPlaceholder;
        }
      }
      if (
        pendingScreenshot !== null &&
        screenshotEvidence === null &&
        callbackPlaceholder === null
      ) {
        throw invalidBasic('screenshot-condition', module);
      }
    }
    const infoResponseBytes = await basicRequestBytes({
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
    const infoResponse = decodeBasicJson(infoResponseBytes.bytes, 'suite-api', module);
    const infoSha256 = crypto.createHash('sha256').update(infoResponseBytes.bytes).digest('hex');
    let officialResult;
    let infoError;
    try {
      officialResult = requireBasicInfoResponse(infoResponse, testInstanceId, planInstanceId, manifestEntry);
    } catch (error) {
      infoError = error;
    }
    let conditionLog;
    try {
      conditionLog = await fetchBasicConditionLog(
        testInstanceId,
        { ...dependencies, deadline: moduleDeadline },
        module,
        true
      );
    } catch (error) {
      throw infoError ?? error;
    }
    const auditInput = {
      root: dependencies.screenshotIpcRoot,
      planInstanceId,
      testId: testInstanceId,
      manifestEntry,
      info: infoResponse,
      infoSha256,
      conditionLog,
      screenshotEvidence,
    };
    try {
      if (infoError) throw infoError;
      validateFinalConditionLog(
        conditionLog, officialResult, screenshotEvidence, callbackPlaceholder, testInstanceId, module
      );
    } catch (error) {
      try {
        persistBasicModuleAudit({
          ...auditInput,
          failureCategory: error instanceof BasicRunError ? error.category : 'module-result',
        });
      } catch {
        // Preserve the original failure if malformed evidence cannot be retained safely.
      }
      throw error;
    }
    const audit = persistBasicModuleAudit(auditInput);
    return Object.freeze({
      summary: Object.freeze({
        testId: testInstanceId,
        testName: module,
        status: 'FINISHED',
        result: officialResult,
        conditionLogSha256: conditionLog.sha256,
        review:
          screenshotEvidence === null
            ? null
            : Object.freeze({
                placeholderId: screenshotEvidence.placeholderId,
                conditionId: screenshotEvidence.conditionId,
                imageSha256: screenshotEvidence.imageSha256,
                reviewRecordSha256: screenshotEvidence.reviewRecordSha256,
                reviewer: screenshotEvidence.reviewer,
                decision: 'APPROVE',
              }),
      }),
      captureId: screenshotEvidence?.captureId ?? null,
      reviewRecordSha256: screenshotEvidence?.reviewRecordSha256 ?? null,
      audit,
    });
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
    const wallClock = dependencies.wallClock ?? Date.now;
    const setTimer = dependencies.setTimer ?? globalThis.setTimeout;
    const clearTimer = dependencies.clearTimer ?? globalThis.clearTimeout;
    const perRequestTimeout = dependencies.requestTimeoutMs ?? requestTimeoutMs;
    const moduleTimeout = dependencies.moduleTimeoutMs ?? basicModuleTimeoutMs;
    const totalTimeout = dependencies.totalTimeoutMs ?? basicTerminalTimeoutMs;
    const responseBytes = dependencies.maximumResponseBytes ?? maximumResponseBytes;
    const screenshotIpcRoot =
      dependencies.screenshotIpcRoot ?? process.env.ASTER_PHASE1_SCREENSHOT_IPC_ROOT;
    if (
      typeof fetchImplementation !== 'function' ||
      typeof readSecret !== 'function' ||
      typeof now !== 'function' ||
      typeof wallClock !== 'function' ||
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
      responseBytes > maximumResponseBytes ||
      (screenshotIpcRoot !== undefined && typeof screenshotIpcRoot !== 'string')
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
      wallClock,
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
      wallClock,
      setTimer,
      clearTimer,
      perRequestTimeout,
      moduleTimeout,
      totalDeadline,
      responseBytes,
      config,
      secrets,
      screenshotIpcRoot,
    });
    const modules = [];
    const testIds = new Set();
    const captureIds = new Set();
    const reviewRecordIds = new Set();
    const audits = [];
    for (const manifestEntry of oidfBasicPlanManifest) {
      const completed = await runBasicModule(manifestEntry, planInstanceId, runtimeDependencies);
      if (
        completed.summary.testName !== manifestEntry.testModule ||
        testIds.has(completed.summary.testId)
      ) {
        throw invalidBasic('module-result', manifestEntry.testModule);
      }
      testIds.add(completed.summary.testId);
      if (completed.summary.review === null) {
        if (completed.captureId !== null || completed.reviewRecordSha256 !== null) {
          throw invalidBasic('screenshot-review', manifestEntry.testModule);
        }
      } else {
        if (
          completed.captureId === null ||
          completed.reviewRecordSha256 === null ||
          captureIds.has(completed.captureId) ||
          reviewRecordIds.has(completed.reviewRecordSha256)
        ) {
          throw invalidBasic('screenshot-review', manifestEntry.testModule);
        }
        captureIds.add(completed.captureId);
        reviewRecordIds.add(completed.reviewRecordSha256);
      }
      modules.push(completed.summary);
      audits.push(completed.audit);
    }
    if (modules.length !== oidfBasicPlanManifest.length || testIds.size !== modules.length) {
      throw invalidBasic('module-result');
    }
    const passedModuleCount = modules.filter(({ result }) => result === 'PASSED').length;
    const reviewedModuleCount = modules.filter(({ result }) => result === 'REVIEW').length;
    if (passedModuleCount + reviewedModuleCount !== oidfBasicPlanManifest.length) {
      throw invalidBasic('module-result');
    }
    try {
      verifyModuleAudits(screenshotIpcRoot, planInstanceId, audits);
    } catch {
      throw invalidBasic('module-audit');
    }
    return Object.freeze({
      schemaVersion: 1,
      kind: 'phase1-conformance-basic-terminal',
      suiteCommit,
      planId: basicPlanName,
      variant: config.variant,
      status: 'FINISHED',
      acceptance: 'ACCEPTED',
      resultId: planInstanceId,
      result: Object.freeze({
        outcome: 'accepted',
        moduleCount: oidfBasicPlanManifest.length,
        passedModuleCount,
        reviewedModuleCount,
        modules: Object.freeze(modules),
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
