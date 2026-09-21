/* eslint-disable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- This boundary test records the complete official suite exchange, including the closed Basic failure terminal, and mutates one response contract at a time. */
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { phase1ConformanceSuiteCommit } from './config.js';

const planName = 'oidcc-config-certification-test-plan';
const testName = 'oidcc-discovery-endpoint-verification';
const planInstanceId = 'PlanOpaque001';
const testInstanceId = 'TestOpaque00001';
const suiteBaseUrl = 'https://suite.example';
const runnerPath = path.resolve(
  process.cwd(),
  '../../.scripts/compatibility/phase1-conformance-runner.mjs'
);

type RunnerDependencies = Readonly<{
  fetch?: typeof fetch;
  now?: () => number;
  setTimer?: typeof setTimeout;
  clearTimer?: typeof clearTimeout;
  requestTimeoutMs?: number;
  totalTimeoutMs?: number;
  maximumResponseBytes?: number;
}>;

type RunnerModule = Readonly<{
  runOidfConfigPlan: (
    input: string | Uint8Array,
    dependencies?: RunnerDependencies
  ) => Promise<Readonly<Record<string, unknown>>>;
}>;

type FetchCall = Readonly<{ url: string; init: RequestInit | undefined }>;

const loadRunner = async (): Promise<RunnerModule> =>
  (await import(pathToFileURL(runnerPath).href)) as RunnerModule;

const validInput = () => ({
  schemaVersion: 1,
  suite: { commit: phase1ConformanceSuiteCommit },
  target: {
    discoveryUrl: 'https://server.example/oidc/.well-known/openid-configuration',
    suiteBaseUrl,
    alias: 'aster-phase1',
  },
  planId: planName,
  variant: { clientRegistration: 'static_client', serverMetadata: 'discovery' },
});

const jsonResponse = (body: unknown, status = 200): Response =>
  new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });

const successfulResponses = (): Response[] => [
  jsonResponse(
    {
      name: planName,
      id: planInstanceId,
      modules: [
        {
          testModule: testName,
          variant: { server_metadata: 'discovery', client_registration: 'static_client' },
          instances: [],
          clientSecret: 'do-not-copy',
        },
      ],
      owner: { token: 'do-not-copy' },
    },
    201
  ),
  jsonResponse(
    {
      name: testName,
      id: testInstanceId,
      url: 'https://suite.example/test/secret-location',
      accessToken: 'do-not-copy',
    },
    201
  ),
  jsonResponse({ state: 'FINISHED' }),
  jsonResponse({
    testId: testInstanceId,
    testName,
    variant: { server_metadata: 'discovery', client_registration: 'static_client' },
    planId: planInstanceId,
    status: 'FINISHED',
    result: 'PASSED',
    config: { client_secret: 'do-not-copy' },
    owner: { credential: 'do-not-copy' },
  }),
];

const createFetch = (responses: readonly Response[]) => {
  const calls: FetchCall[] = [];
  let index = 0;
  const fetchImplementation: typeof fetch = async (input, init) => {
    calls.push({ url: String(input), init });
    const response = responses[index];
    index += 1;
    if (!response) {
      throw new TypeError('unexpected fetch');
    }
    return response;
  };

  return { calls, fetchImplementation };
};

const neverCompletingFetch: typeof fetch = async (_input, init) =>
  new Promise((_resolve, reject) => {
    const rejectAbort = () => {
      reject(new DOMException('aborted', 'AbortError'));
    };
    if (init?.signal?.aborted) {
      rejectAbort();
    } else {
      init?.signal?.addEventListener('abort', rejectAbort, { once: true });
    }
  });

describe('official OIDF Config plan runner', () => {
  it('executes the exact HTTP sequence and emits one credential-free official terminal', async () => {
    const runner = await loadRunner();
    const { calls, fetchImplementation } = createFetch(successfulResponses());
    const terminal = await runner.runOidfConfigPlan(JSON.stringify(validInput()), {
      fetch: fetchImplementation,
    });

    expect(calls).toHaveLength(4);
    const planRequest = new URL(calls[0]!.url);
    expect(planRequest.origin + planRequest.pathname).toBe(`${suiteBaseUrl}/api/plan`);
    expect(planRequest.searchParams.get('planName')).toBe(planName);
    expect(planRequest.searchParams.get('variant')).toBeNull();
    expect(calls[0]!.init).toMatchObject({ method: 'POST', redirect: 'error' });
    expect(JSON.parse(String(calls[0]!.init?.body))).toEqual({
      alias: 'aster-phase1',
      description: 'Aster phase 1 Config certification',
      server: { discoveryUrl: validInput().target.discoveryUrl },
    });

    const testRequest = new URL(calls[1]!.url);
    expect(testRequest.origin + testRequest.pathname).toBe(`${suiteBaseUrl}/api/runner`);
    expect(testRequest.searchParams.get('test')).toBe(testName);
    expect(testRequest.searchParams.get('plan')).toBe(planInstanceId);
    expect(calls[1]!.init).toMatchObject({ method: 'POST', redirect: 'error' });
    expect(calls[1]!.init?.headers).toEqual({
      accept: 'application/json',
      'content-type': 'application/json',
    });
    expect(calls[1]!.init?.body).toBeUndefined();

    expect(calls[2]!.url).toBe(
      `${suiteBaseUrl}/api/runner/${testInstanceId}/wait-state?states=FINISHED,INTERRUPTED&timeoutMs=30000`
    );
    expect(calls[3]!.url).toBe(`${suiteBaseUrl}/api/info/${testInstanceId}?public=false`);
    expect(terminal).toEqual({
      schemaVersion: 1,
      kind: 'phase1-conformance-official-terminal',
      suiteCommit: phase1ConformanceSuiteCommit,
      planId: planName,
      variant: validInput().variant,
      status: 'PASSED',
      resultId: planInstanceId,
      result: { outcome: 'passed', moduleCount: 1, passedModuleCount: 1 },
    });
    expect(JSON.stringify(terminal)).not.toMatch(
      /TestOpaque|secret-location|do-not-copy|client_secret|owner|cookie|token|credential/iu
    );
  });

  it.each([
    ['wrong schema', { ...validInput(), schemaVersion: 2 }],
    ['wrong suite commit', { ...validInput(), suite: { commit: '1'.repeat(40) } }],
    ['wrong plan', { ...validInput(), planId: 'oidcc-basic-certification-test-plan' }],
    [
      'wrong variant',
      {
        ...validInput(),
        variant: { clientRegistration: 'dynamic_client', serverMetadata: 'discovery' },
      },
    ],
    ['wrong alias', { ...validInput(), target: { ...validInput().target, alias: 'other' } }],
    ['extra static clients', { ...validInput(), staticClients: [{ clientSecret: 'private' }] }],
    [
      'extra redirect',
      { ...validInput(), target: { ...validInput().target, callbackUri: 'https://callback' } },
    ],
  ] as const)('rejects %s before any HTTP request', async (_name, input) => {
    const runner = await loadRunner();
    let touched = false;

    await expect(
      runner.runOidfConfigPlan(JSON.stringify(input), {
        fetch: async () => {
          touched = true;
          return jsonResponse({});
        },
      })
    ).rejects.toThrow('Invalid official OIDF Config plan run');
    expect(touched).toBe(false);
  });

  it.each([
    ['wrong plan name', 0, { name: 'wrong', id: planInstanceId, modules: [] }, 201],
    [
      'wrong module',
      0,
      {
        name: planName,
        id: planInstanceId,
        modules: [{ testModule: 'wrong', variant: {}, instances: [] }],
      },
      201,
    ],
    [
      'nonempty module variant',
      0,
      {
        name: planName,
        id: planInstanceId,
        modules: [{ testModule: testName, variant: { changed: true }, instances: [] }],
      },
      201,
    ],
    [
      'preexisting module instance',
      0,
      {
        name: planName,
        id: planInstanceId,
        modules: [{ testModule: testName, variant: {}, instances: ['old'] }],
      },
      201,
    ],
    [
      'invalid plan id',
      0,
      {
        name: planName,
        id: '../not-opaque',
        modules: [{ testModule: testName, variant: {}, instances: [] }],
      },
      201,
    ],
    ['wrong runner name', 1, { name: 'wrong', id: testInstanceId }, 201],
    ['invalid test id', 1, { name: testName, id: '../not-opaque' }, 201],
    [
      'wrong info test id',
      3,
      {
        testId: 'OtherOpaque0001',
        testName,
        variant: { server_metadata: 'discovery', client_registration: 'static_client' },
        planId: planInstanceId,
        status: 'FINISHED',
        result: 'PASSED',
      },
      200,
    ],
    [
      'wrong info plan id',
      3,
      {
        testId: testInstanceId,
        testName,
        variant: { server_metadata: 'discovery', client_registration: 'static_client' },
        planId: 'OtherPlan0001',
        status: 'FINISHED',
        result: 'PASSED',
      },
      200,
    ],
  ] as const)('rejects %s', async (_name, responseIndex, body, status) => {
    const runner = await loadRunner();
    const responses = successfulResponses();
    responses[responseIndex] = jsonResponse(body, status);
    const { fetchImplementation } = createFetch(responses);

    await expect(
      runner.runOidfConfigPlan(JSON.stringify(validInput()), { fetch: fetchImplementation })
    ).rejects.toThrow('Invalid official OIDF Config plan run');
  });

  it.each(['WARNING', 'REVIEW', 'FAILED'] as const)('rejects %s result', async (result) => {
    const runner = await loadRunner();
    const responses = successfulResponses();
    responses[3] = jsonResponse({
      testId: testInstanceId,
      testName,
      variant: { server_metadata: 'discovery', client_registration: 'static_client' },
      planId: planInstanceId,
      status: 'FINISHED',
      result,
    });
    const { fetchImplementation } = createFetch(responses);

    await expect(
      runner.runOidfConfigPlan(JSON.stringify(validInput()), { fetch: fetchImplementation })
    ).rejects.toThrow('Invalid official OIDF Config plan run');
  });

  it('rejects INTERRUPTED and never requests final info', async () => {
    const runner = await loadRunner();
    const responses = successfulResponses();
    responses[2] = jsonResponse({ state: 'INTERRUPTED' });
    const { calls, fetchImplementation } = createFetch(responses);

    await expect(
      runner.runOidfConfigPlan(JSON.stringify(validInput()), { fetch: fetchImplementation })
    ).rejects.toThrow('Invalid official OIDF Config plan run');
    expect(calls).toHaveLength(3);
  });

  it('rejects non-FINISHED status', async () => {
    const runner = await loadRunner();
    const responses = successfulResponses();
    responses[3] = jsonResponse({
      testId: testInstanceId,
      testName,
      variant: { server_metadata: 'discovery', client_registration: 'static_client' },
      planId: planInstanceId,
      status: 'RUNNING',
      result: 'PASSED',
    });
    const { fetchImplementation } = createFetch(responses);

    await expect(
      runner.runOidfConfigPlan(JSON.stringify(validInput()), { fetch: fetchImplementation })
    ).rejects.toThrow('Invalid official OIDF Config plan run');
  });

  it.each([
    ['invalid JSON', '{'],
    ['oversized input', 'x'.repeat(65_537)],
  ] as const)('rejects %s without HTTP', async (_name, input) => {
    const runner = await loadRunner();
    let touched = false;

    await expect(
      runner.runOidfConfigPlan(input, {
        fetch: async () => {
          touched = true;
          return jsonResponse({});
        },
      })
    ).rejects.toThrow('Invalid official OIDF Config plan run');
    expect(touched).toBe(false);
  });

  it.each([
    ['invalid response JSON', jsonResponse('{', 201)],
    ['oversized response', jsonResponse('x'.repeat(65_537), 201)],
    ['wrong HTTP status', jsonResponse({}, 200)],
  ] as const)('rejects %s', async (_name, firstResponse) => {
    const runner = await loadRunner();
    const responses = successfulResponses();
    responses[0] = firstResponse;
    const { fetchImplementation } = createFetch(responses);

    await expect(
      runner.runOidfConfigPlan(JSON.stringify(validInput()), { fetch: fetchImplementation })
    ).rejects.toThrow('Invalid official OIDF Config plan run');
  });

  it('enforces the per-request HTTP timeout through the injected clock', async () => {
    const runner = await loadRunner();

    await expect(
      runner.runOidfConfigPlan(JSON.stringify(validInput()), {
        fetch: neverCompletingFetch,
        setTimer: ((callback: () => void) => {
          callback();
          return 1;
        }) as unknown as typeof setTimeout,
        clearTimer: (() => false) as unknown as typeof clearTimeout,
      })
    ).rejects.toThrow('Invalid official OIDF Config plan run');
  });

  it('repeats bounded long polls and fails at the 220 second terminal budget', async () => {
    const runner = await loadRunner();
    let now = 0;
    const responses = successfulResponses().slice(0, 2);
    const calls: FetchCall[] = [];
    const fetchImplementation: typeof fetch = async (input, init) => {
      calls.push({ url: String(input), init });
      const response = responses.shift();
      if (response) {
        return response;
      }
      now += 30_000;
      return jsonResponse({ timeout: true });
    };

    await expect(
      runner.runOidfConfigPlan(JSON.stringify(validInput()), {
        fetch: fetchImplementation,
        now: () => now,
      })
    ).rejects.toThrow('Invalid official OIDF Config plan run');
    expect(calls.filter(({ url }) => url.includes('/wait-state?')).length).toBeGreaterThan(1);
    expect(now).toBeGreaterThanOrEqual(220_000);
  });

  it('emits only the closed failure category for invalid Basic input in both entry points', () => {
    const driverPath = path.resolve(
      process.cwd(),
      '../../.scripts/compatibility/phase1-conformance-driver.sh'
    );
    const input = JSON.stringify({
      ...validInput(),
      planId: 'oidcc-basic-certification-test-plan',
    });
    const driver = spawnSync(driverPath, ['--plan-id', 'oidcc-basic-certification-test-plan'], {
      input,
      encoding: 'utf8',
      env: { PATH: '/tmp/path-hijack:/usr/bin:/bin' },
    });
    const direct = spawnSync(
      process.execPath,
      [runnerPath, '--plan-id', 'oidcc-basic-certification-test-plan'],
      { input, encoding: 'utf8' }
    );

    const expected = {
      schemaVersion: 1,
      kind: 'phase1-conformance-official-failure-terminal',
      suiteCommit: phase1ConformanceSuiteCommit,
      planId: 'oidcc-basic-certification-test-plan',
      module: null,
      status: 'FAILED',
      result: 'FAILED',
      failureCategory: 'input',
    };

    expect(driver).toMatchObject({ status: 1, stderr: '' });
    expect(direct).toMatchObject({ status: 1, stderr: '' });
    expect(JSON.parse(driver.stdout)).toEqual(expected);
    expect(JSON.parse(direct.stdout)).toEqual(expected);
    expect(driver.stdout).not.toMatch(/https?:|cookie|token|secret|password/iu);
  });
});

/* eslint-enable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
