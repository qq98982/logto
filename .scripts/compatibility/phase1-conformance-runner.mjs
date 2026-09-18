import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const suiteCommit = '0dc0e3a21ec411e92c808e5b2e2258592c22b594';
const planName = 'oidcc-config-certification-test-plan';
const testName = 'oidcc-discovery-endpoint-verification';
const alias = 'aster-phase1';
const description = 'Aster phase 1 Config certification';
const maximumInputBytes = 65_536;
const maximumResponseBytes = 65_536;
const requestTimeoutMs = 40_000;
const terminalTimeoutMs = 220_000;
const waitStateTimeoutMs = 30_000;
const diagnostic = 'Invalid official OIDF Config plan run';
const planIdPattern = /^[A-Za-z0-9]{13}$/u;
const testIdPattern = /^[A-Za-z0-9]{15}$/u;
const expectedInputKeys = Object.freeze(['schemaVersion', 'suite', 'target', 'planId', 'variant']);
const expectedSuiteKeys = Object.freeze(['commit']);
const expectedTargetKeys = Object.freeze(['discoveryUrl', 'suiteBaseUrl', 'alias']);
const expectedVariantKeys = Object.freeze(['clientRegistration', 'serverMetadata']);

const invalid = () => new TypeError(diagnostic);
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
    value.planId !== planName ||
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

const requirePlanResponse = (value) => {
  if (
    !isRecord(value) ||
    value.name !== planName ||
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
    module.testModule !== testName ||
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
    value.name !== testName ||
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
    value.testName !== testName ||
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
    const planUrl = `${config.suiteBaseUrl}/api/plan?planName=${encodeURIComponent(planName)}`;
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
          description,
          server: { discoveryUrl: config.discoveryUrl },
        }),
      },
      expectedStatus: 201,
    });
    const planInstanceId = requirePlanResponse(planResponse);
    const runnerUrl = `${config.suiteBaseUrl}/api/runner?test=${encodeURIComponent(
      testName
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
      planId: planName,
      variant: Object.freeze({ ...config.variant }),
      status: 'PASSED',
      resultId: planInstanceId,
      result: Object.freeze({ outcome: 'passed', moduleCount: 1, passedModuleCount: 1 }),
    });
  } catch {
    throw invalid();
  }
};

const main = async () => {
  try {
    const args = process.argv.slice(2);
    if (args.length !== 2 || args[0] !== '--plan-id' || args[1] !== planName) throw invalid();
    const terminal = await runOidfConfigPlan(fs.readFileSync(0));
    process.stdout.write(JSON.stringify(terminal));
  } catch {
    process.exitCode = 1;
  }
};

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  await main();
}
