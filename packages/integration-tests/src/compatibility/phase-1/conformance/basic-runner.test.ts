/* eslint-disable max-lines, complexity, unicorn/consistent-function-scoping, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- This boundary test records the exact Basic plan manifest, serial suite exchange, and one cohesive fake HTTP state machine. */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, copyFile, mkdtemp, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { phase1ConformanceSuiteCommit } from './config.js';

const planName = 'oidcc-basic-certification-test-plan';
const planInstanceId = 'Plan000000001';
const suiteBaseUrl = 'https://suite.example';
const runnerPath = path.resolve(
  process.cwd(),
  '../../.scripts/compatibility/phase1-conformance-runner.mjs'
);
const driverPath = path.resolve(
  process.cwd(),
  '../../.scripts/compatibility/phase1-conformance-driver.sh'
);
const basicVariant = Object.freeze({
  clientRegistration: 'static_client',
  serverMetadata: 'discovery',
  responseType: 'code',
  responseMode: 'default',
  clientAuthTypes: Object.freeze(['client_secret_basic', 'client_secret_post']),
});
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

const moduleVariant = (name: string) => ({
  response_type: 'code',
  client_auth_type:
    name === 'oidcc-server-client-secret-post' ? 'client_secret_post' : 'client_secret_basic',
  response_mode: 'default',
});
const expectedManifest = Object.freeze(
  basicModuleNames.map((testModule) =>
    Object.freeze({ testModule, variant: Object.freeze(moduleVariant(testModule)) })
  )
);

type BasicRunnerDependencies = Readonly<{
  fetch?: typeof fetch;
  readSecret?: (path: string) => Uint8Array;
  now?: () => number;
  setTimer?: typeof setTimeout;
  clearTimer?: typeof clearTimeout;
  requestTimeoutMs?: number;
  moduleTimeoutMs?: number;
  totalTimeoutMs?: number;
  maximumResponseBytes?: number;
}>;

type RunnerModule = Readonly<{
  oidfBasicPlanManifest: ReadonlyArray<Readonly<Record<string, unknown>>>;
  runOidfBasicPlan: (
    input: string | Uint8Array,
    dependencies?: BasicRunnerDependencies
  ) => Promise<Readonly<Record<string, unknown>>>;
}>;

const loadRunner = async (): Promise<RunnerModule> =>
  (await import(pathToFileURL(runnerPath).href)) as RunnerModule;

const validInput = () => ({
  schemaVersion: 1,
  suite: { commit: phase1ConformanceSuiteCommit },
  target: {
    issuer: 'https://server.example/oidc',
    discoveryUrl: 'https://server.example/oidc/.well-known/openid-configuration',
    suiteBaseUrl,
    alias: 'aster-phase1',
    callbackUri: 'https://suite.example/test/a/aster-phase1/callback',
  },
  planId: planName,
  variant: basicVariant,
});

const jsonResponse = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });

const readSecret = (secretPath: string): Uint8Array => {
  const values: Readonly<Record<string, string>> = {
    '/run/aster-secrets/phase1-user': 'user-secret-value',
    '/run/aster-secrets/oidf-basic-1': 'basic-one-secret',
    '/run/aster-secrets/oidf-basic-2': 'basic-two-secret',
    '/run/aster-secrets/oidf-post-1': 'post-one-secret',
    '/run/aster-secrets/oidf-conformance-public.json': JSON.stringify({
      schemaVersion: 1,
      recipe: 'oidfConformance',
      allocations: [{ allocationId: 'oidf-allocation-1' }],
    }),
  };
  const value = values[secretPath];

  if (!value) {
    throw new Error('unexpected secret path');
  }

  return new TextEncoder().encode(value);
};

describe('official OIDF Basic plan runner input and manifest', () => {
  it('accepts Basic through the shell driver plan allowlist', async () => {
    const root = await mkdtemp('/var/tmp/henry-build/oidf-basic-driver-');
    const copiedDriver = path.join(root, 'phase1-conformance-driver.sh');
    const copiedRunner = path.join(root, 'phase1-conformance-runner.mjs');

    try {
      await copyFile(driverPath, copiedDriver);
      await chmod(copiedDriver, 0o755);
      await writeFile(
        copiedRunner,
        'process.stdout.write(JSON.stringify(process.argv.slice(2)));\n',
        { mode: 0o644 }
      );
      const result = spawnSync(copiedDriver, ['--plan-id', planName], {
        input: '{}',
        encoding: 'utf8',
        env: { PATH: '/usr/bin:/bin' },
      });

      expect(result.status).toBe(0);
      expect(result.stderr).toBe('');
      expect(JSON.parse(result.stdout)).toEqual(['--plan-id', planName]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('exports the exact ordered 35-module static-client manifest', async () => {
    const runner = await loadRunner();

    expect(runner.oidfBasicPlanManifest).toEqual(expectedManifest);
    expect(runner.oidfBasicPlanManifest).toHaveLength(35);
    expect(JSON.stringify(runner.oidfBasicPlanManifest)).not.toMatch(
      /oidcc-idtoken-signature|oidcc-idtoken-unsigned|oidcc-request-uri-unsigned/iu
    );
  });

  it.each([
    ['wrong alias', { ...validInput(), target: { ...validInput().target, alias: 'other' } }],
    [
      'wrong callback alias',
      {
        ...validInput(),
        target: {
          ...validInput().target,
          callbackUri: 'https://suite.example/test/a/other/callback',
        },
      },
    ],
    [
      'wrong variant',
      {
        ...validInput(),
        variant: { ...basicVariant, clientAuthTypes: ['client_secret_basic'] },
      },
    ],
  ] as const)('rejects %s before reading secrets or using HTTP', async (_name, input) => {
    const runner = await loadRunner();
    let secretTouched = false;
    let httpTouched = false;

    await expect(
      runner.runOidfBasicPlan(JSON.stringify(input), {
        readSecret: () => {
          secretTouched = true;
          return new Uint8Array();
        },
        fetch: async () => {
          httpTouched = true;
          return jsonResponse({});
        },
      })
    ).rejects.toThrow('Invalid official OIDF Basic plan run');
    expect(secretTouched).toBe(false);
    expect(httpTouched).toBe(false);
  });

  it('rejects a reordered or variant-mutated live plan manifest before running modules', async () => {
    const runner = await loadRunner();
    const modules = expectedManifest.map(({ testModule, variant }) => ({
      testModule,
      variant,
      instances: [],
    }));
    const first = modules[0]!;
    modules[0] = modules[1]!;
    modules[1] = first;
    let calls = 0;

    await expect(
      runner.runOidfBasicPlan(JSON.stringify(validInput()), {
        readSecret,
        fetch: async () => {
          calls += 1;
          return jsonResponse({ name: planName, id: planInstanceId, modules }, 201);
        },
      })
    ).rejects.toThrow('Invalid official OIDF Basic plan run');
    expect(calls).toBe(1);
  });

  it('runs the exact 35 modules serially and accepts only 35 PASSED results', async () => {
    const runner = await loadRunner();
    const calls: Array<Readonly<{ url: URL; init: RequestInit | undefined }>> = [];
    const tests = new Map<string, Readonly<{ name: string; variant: Record<string, string> }>>();
    let nextTest = 0;
    const fetchImplementation: typeof fetch = async (input, init) => {
      const url = new URL(String(input));
      calls.push({ url, init });
      if (url.pathname === '/api/plan') {
        return jsonResponse(
          {
            name: planName,
            id: planInstanceId,
            modules: expectedManifest.map(({ testModule, variant }) => ({
              testModule,
              variant,
              instances: [],
            })),
          },
          201
        );
      }
      if (url.pathname === '/api/runner' && init?.method === 'POST') {
        const manifestEntry = expectedManifest[nextTest];
        if (!manifestEntry) {
          throw new Error('unexpected module');
        }
        const id = `T${String(nextTest).padStart(14, '0')}`;
        tests.set(id, { name: manifestEntry.testModule, variant: manifestEntry.variant });
        nextTest += 1;
        return jsonResponse({ name: manifestEntry.testModule, id }, 201);
      }
      const wait = /^\/api\/runner\/([A-Za-z0-9]{15})\/wait-state$/u.exec(url.pathname);
      if (wait) {
        return jsonResponse({ state: 'FINISHED' });
      }
      const info = /^\/api\/info\/([A-Za-z0-9]{15})$/u.exec(url.pathname);
      if (info) {
        const test = tests.get(info[1]!);
        if (!test) {
          throw new Error('unknown test');
        }
        return jsonResponse({
          testId: info[1],
          testName: test.name,
          variant: {
            ...test.variant,
            server_metadata: 'discovery',
            client_registration: 'static_client',
          },
          planId: planInstanceId,
          status: 'FINISHED',
          result: 'PASSED',
        });
      }
      throw new Error(`unexpected request ${url.pathname}`);
    };

    const terminal = await runner.runOidfBasicPlan(JSON.stringify(validInput()), {
      readSecret,
      fetch: fetchImplementation,
    });

    expect(nextTest).toBe(35);
    expect(calls).toHaveLength(106);
    const planCall = calls[0]!;
    expect(planCall.url.searchParams.get('planName')).toBe(planName);
    expect(JSON.parse(planCall.url.searchParams.get('variant') ?? '')).toEqual({
      server_metadata: 'discovery',
      client_registration: 'static_client',
    });
    expect(JSON.parse(String(planCall.init?.body))).toEqual({
      alias: 'aster-phase1',
      description: 'Aster phase 1 Basic certification',
      server: { discoveryUrl: validInput().target.discoveryUrl },
      client: { client_id: 'oidf-basic-1', client_secret: 'basic-one-secret' },
      client2: { client_id: 'oidf-basic-2', client_secret: 'basic-two-secret' },
      client_secret_post: { client_id: 'oidf-post-1', client_secret: 'post-one-secret' },
      browser: [],
    });
    const runnerCalls = calls.filter(({ url }) => url.pathname === '/api/runner');
    expect(runnerCalls.map(({ url }) => url.searchParams.get('test'))).toEqual(basicModuleNames);
    expect(runnerCalls.map(({ url }) => JSON.parse(url.searchParams.get('variant') ?? ''))).toEqual(
      expectedManifest.map(({ variant }) => variant)
    );
    expect(calls.some(({ url }) => url.pathname.startsWith('/api/log'))).toBe(false);
    expect(terminal).toEqual({
      schemaVersion: 1,
      kind: 'phase1-conformance-official-terminal',
      suiteCommit: phase1ConformanceSuiteCommit,
      planId: planName,
      variant: basicVariant,
      status: 'PASSED',
      resultId: planInstanceId,
      result: { outcome: 'passed', moduleCount: 35, passedModuleCount: 35 },
    });
    expect(JSON.stringify(terminal)).not.toMatch(
      /user-secret-value|basic-one-secret|basic-two-secret|post-one-secret|suite_session=|https?:/iu
    );
  });

  it('drives declared browser URLs with one module cookie jar and response-led Experience state', async () => {
    const runner = await loadRunner();
    const tests = new Map<string, Readonly<{ name: string; variant: Record<string, string> }>>();
    const navigation: string[] = [];
    let nextTest = 0;
    let firstWait = 0;
    let virtualNow = 0;
    const visited = new Set<string>();
    const waitStates: string[] = [];
    const redirectResponse = (
      location: string,
      status: 302 | 303,
      cookies: readonly string[] = []
    ): Response => {
      const headers = new Headers({ location });

      for (const cookie of cookies) {
        headers.append('set-cookie', cookie);
      }

      return new Response(null, { status, headers });
    };
    const requestHeaders = (init: RequestInit | undefined) => new Headers(init?.headers);
    const fetchImplementation: typeof fetch = async (input, init) => {
      const url = new URL(String(input));
      const method = init?.method ?? 'GET';
      const headers = requestHeaders(init);
      navigation.push(`${method} ${url.origin}${url.pathname}${url.search}`);
      if (url.origin === suiteBaseUrl && url.pathname === '/api/plan') {
        return jsonResponse(
          {
            name: planName,
            id: planInstanceId,
            modules: expectedManifest.map(({ testModule, variant }) => ({
              testModule,
              variant,
              instances: [],
            })),
          },
          201
        );
      }
      if (url.origin === suiteBaseUrl && url.pathname === '/api/runner' && method === 'POST') {
        const manifestEntry = expectedManifest[nextTest];
        if (!manifestEntry) {
          throw new Error('unexpected module');
        }
        const id = nextTest === 0 ? 'B00000000000001' : `T${String(nextTest).padStart(14, '0')}`;
        tests.set(id, { name: manifestEntry.testModule, variant: manifestEntry.variant });
        nextTest += 1;
        return jsonResponse({ name: manifestEntry.testModule, id }, 201);
      }
      if (
        url.origin === suiteBaseUrl &&
        url.pathname === '/api/runner/B00000000000001/wait-state'
      ) {
        firstWait += 1;
        waitStates.push(url.searchParams.get('states') ?? '');
        return jsonResponse(
          firstWait === 1
            ? { state: 'WAITING' }
            : firstWait === 2
              ? { timeout: true }
              : { state: 'FINISHED' }
        );
      }
      if (url.origin === suiteBaseUrl && url.pathname.endsWith('/wait-state')) {
        return jsonResponse({ state: 'FINISHED' });
      }
      if (url.origin === suiteBaseUrl && url.pathname === '/api/runner/B00000000000001') {
        const declarations = [
          { url: 'https://suite.example/browser/start-one', method: 'GET' },
          { url: 'https://suite.example/browser/start-two?phase=2', method: 'POST' },
          { url: 'https://suite.example/browser/start-three', method: 'GET' },
        ].filter(({ url: declared }) => !visited.has(declared));
        return jsonResponse({
          name: 'oidcc-server',
          id: 'B00000000000001',
          browser: {
            urls: declarations.map(({ url: declared }) => declared),
            urlsWithMethod: declarations,
            browserApiRequests: [],
            uriInputRequests: [],
          },
        });
      }
      if (url.origin === suiteBaseUrl && url.pathname.startsWith('/api/info/')) {
        const id = url.pathname.slice('/api/info/'.length);
        const test = tests.get(id);
        if (!test) {
          throw new Error('unknown test');
        }
        return jsonResponse({
          testId: id,
          testName: test.name,
          variant: {
            ...test.variant,
            server_metadata: 'discovery',
            client_registration: 'static_client',
          },
          planId: planInstanceId,
          status: 'FINISHED',
          result: 'PASSED',
        });
      }
      if (
        url.origin === suiteBaseUrl &&
        url.pathname === '/api/runner/browser/B00000000000001/visit' &&
        method === 'POST'
      ) {
        const declared = url.searchParams.get('url');
        if (!declared) {
          throw new Error('missing visited URL');
        }
        visited.add(declared);
        return new Response(null, { status: 204 });
      }
      if (url.origin === suiteBaseUrl && url.pathname === '/browser/start-one') {
        expect(method).toBe('GET');
        expect(headers.get('cookie')).toBeNull();
        return redirectResponse('https://server.example/oidc/auth/authorize-one', 302, [
          'suite_session=alpha; Max-Age=60; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; Secure; HttpOnly',
          'bad_cookie=discard-me; Domain=evil.example; Path=/; Secure',
        ]);
      }
      if (url.origin === 'https://server.example' && url.pathname === '/oidc/auth/authorize-one') {
        expect(headers.get('cookie')).toBeNull();
        return redirectResponse('/sign-in?app_id=oidf-basic-1', 303, [
          '_aster=interaction-one; Path=/; Secure; HttpOnly',
        ]);
      }
      if (url.origin === 'https://server.example' && url.pathname === '/api/experience') {
        expect(method).toBe('PUT');
        expect(headers.get('aster-app-id')).toBe('oidf-basic-1');
        expect(headers.get('content-type')).toBe('application/json');
        expect(headers.get('cookie')).toContain('_aster=interaction-one');
        expect(JSON.parse(String(init?.body))).toEqual({ interactionEvent: 'SignIn' });
        return new Response(null, {
          status: 204,
          headers: { 'set-cookie': '_aster.sig=interaction-signature; Path=/; Secure; HttpOnly' },
        });
      }
      if (
        url.origin === 'https://server.example' &&
        url.pathname === '/api/experience/verification/password'
      ) {
        const expectedUsername = `phase1_user_a_${createHash('sha256')
          .update('oidf-allocation-1')
          .digest('hex')
          .slice(0, 16)}`;
        expect(method).toBe('POST');
        expect(headers.get('cookie')).toContain('_aster.sig=interaction-signature');
        expect(JSON.parse(String(init?.body))).toEqual({
          identifier: { type: 'username', value: expectedUsername },
          password: 'user-secret-value',
        });
        return jsonResponse({ verificationId: 'verification-private' });
      }
      if (
        url.origin === 'https://server.example' &&
        url.pathname === '/api/experience/identification'
      ) {
        expect(JSON.parse(String(init?.body))).toEqual({ verificationId: 'verification-private' });
        return new Response(null, { status: 204 });
      }
      if (url.origin === 'https://server.example' && url.pathname === '/api/experience/submit') {
        expect(method).toBe('POST');
        expect(init?.body).toBeUndefined();
        expect(headers.get('content-type')).toBeNull();
        return jsonResponse({ redirectTo: 'https://server.example/oidc/auth/login-resume' });
      }
      if (url.origin === 'https://server.example' && url.pathname === '/oidc/auth/login-resume') {
        return redirectResponse('/consent?app_id=oidf-basic-1', 303, [
          '_aster_session=session-one; Path=/; Secure; HttpOnly',
          'expiring=discard-me; Max-Age=1; Path=/; Secure; HttpOnly',
        ]);
      }
      if (
        url.origin === 'https://server.example' &&
        url.pathname === '/api/interaction/consent' &&
        method === 'GET'
      ) {
        expect(url.search).toBe('');
        expect(init?.body).toBeUndefined();
        expect(headers.get('aster-app-id')).toBe('oidf-basic-1');
        expect(headers.get('cookie')).toContain('_aster_session=session-one');
        return jsonResponse({ application: { id: 'oidf-basic-1' } });
      }
      if (
        url.origin === 'https://server.example' &&
        url.pathname === '/api/interaction/consent' &&
        method === 'POST'
      ) {
        expect(headers.get('content-type')).toBe('application/json;charset=utf-8');
        expect(init?.body).toBe('{}');
        return jsonResponse({ redirectTo: 'https://server.example/oidc/auth/consent-resume' });
      }
      if (url.origin === 'https://server.example' && url.pathname === '/oidc/auth/consent-resume') {
        return redirectResponse(
          'https://suite.example/test/a/aster-phase1/callback?code=private-code&state=state-one',
          303
        );
      }
      if (
        url.origin === suiteBaseUrl &&
        url.pathname === '/test/a/aster-phase1/callback' &&
        url.searchParams.get('state') === 'state-one'
      ) {
        expect(headers.get('cookie')).toContain('suite_session=alpha');
        expect(headers.get('cookie')).not.toContain('_aster');
        expect(headers.get('cookie')).not.toContain('bad_cookie');
        virtualNow = 2000;
        return new Response('complete', { status: 200 });
      }
      if (url.origin === suiteBaseUrl && url.pathname === '/browser/start-two') {
        expect(method).toBe('POST');
        expect(url.search).toBe('');
        expect(init?.body).toBe('phase=2');
        expect(headers.get('content-type')).toBe('application/x-www-form-urlencoded');
        expect(headers.get('cookie')).toContain('suite_session=alpha');
        return redirectResponse('https://server.example/oidc/auth/prompt-none', 302);
      }
      if (url.origin === 'https://server.example' && url.pathname === '/oidc/auth/prompt-none') {
        expect(headers.get('cookie')).toContain('_aster_session=session-one');
        expect(headers.get('cookie')).not.toContain('expiring=discard-me');
        return redirectResponse(
          'https://suite.example/test/a/aster-phase1/callback?error=login_required&state=state-two',
          303
        );
      }
      if (
        url.origin === suiteBaseUrl &&
        url.pathname === '/test/a/aster-phase1/callback' &&
        url.searchParams.get('state') === 'state-two'
      ) {
        expect(headers.get('cookie')).toContain('suite_session=alpha');
        return new Response('complete', { status: 200 });
      }
      if (url.origin === suiteBaseUrl && url.pathname === '/browser/start-three') {
        expect(method).toBe('GET');
        return redirectResponse('https://server.example/oidc/auth/invalid-redirect', 302);
      }
      if (
        url.origin === 'https://server.example' &&
        url.pathname === '/oidc/auth/invalid-redirect'
      ) {
        return new Response('invalid redirect', { status: 400 });
      }
      throw new Error(`unexpected request ${method} ${url.href}`);
    };

    const terminal = await runner.runOidfBasicPlan(JSON.stringify(validInput()), {
      readSecret,
      fetch: fetchImplementation,
      now: () => virtualNow,
    });

    expect(firstWait).toBe(3);
    expect(waitStates).toEqual([
      'WAITING,FINISHED,INTERRUPTED',
      'FINISHED,INTERRUPTED',
      'FINISHED,INTERRUPTED',
    ]);
    expect(nextTest).toBe(35);
    expect(navigation.some((entry) => entry.includes('/sign-in'))).toBe(false);
    expect(navigation.some((entry) => entry.includes('/consent?'))).toBe(false);
    expect(navigation.some((entry) => entry.includes('/api/log'))).toBe(false);
    expect(visited).toEqual(
      new Set([
        'https://suite.example/browser/start-one',
        'https://suite.example/browser/start-two?phase=2',
        'https://suite.example/browser/start-three',
      ])
    );
    expect(terminal).toMatchObject({
      status: 'PASSED',
      result: { moduleCount: 35, passedModuleCount: 35 },
    });
  });

  it('keeps the request deadline active while reading a response body', async () => {
    const runner = await loadRunner();
    const fetchImplementation: typeof fetch = async (_input, init) =>
      new Response(
        new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(new TextEncoder().encode('{'));
            init?.signal?.addEventListener(
              'abort',
              () => {
                controller.error(new Error('aborted'));
              },
              { once: true }
            );
          },
        }),
        { status: 201, headers: { 'content-type': 'application/json' } }
      );

    await expect(
      runner.runOidfBasicPlan(JSON.stringify(validInput()), {
        readSecret,
        fetch: fetchImplementation,
        requestTimeoutMs: 10,
        moduleTimeoutMs: 100,
        totalTimeoutMs: 100,
      })
    ).rejects.toThrow('Invalid official OIDF Basic plan run');
  });

  it('cancels an interrupted module without requesting raw logs', async () => {
    const runner = await loadRunner();
    const requests: string[] = [];
    const fetchImplementation: typeof fetch = async (input, init) => {
      const url = new URL(String(input));
      requests.push(`${init?.method ?? 'GET'} ${url.pathname}`);
      if (url.pathname === '/api/plan') {
        return jsonResponse(
          {
            name: planName,
            id: planInstanceId,
            modules: expectedManifest.map(({ testModule, variant }) => ({
              testModule,
              variant,
              instances: [],
            })),
          },
          201
        );
      }
      if (url.pathname === '/api/runner' && init?.method === 'POST') {
        return jsonResponse({ name: 'oidcc-server', id: 'I00000000000001' }, 201);
      }
      if (url.pathname === '/api/runner/I00000000000001/wait-state') {
        return jsonResponse({ state: 'INTERRUPTED' });
      }
      if (url.pathname === '/api/runner/I00000000000001' && init?.method === 'DELETE') {
        return jsonResponse({ name: 'oidcc-server', id: 'I00000000000001' });
      }
      throw new Error(`unexpected request ${url.pathname}`);
    };

    await expect(
      runner.runOidfBasicPlan(JSON.stringify(validInput()), {
        readSecret,
        fetch: fetchImplementation,
      })
    ).rejects.toThrow('Invalid official OIDF Basic plan run');
    expect(requests).toContain('DELETE /api/runner/I00000000000001');
    expect(requests.some((request) => request.includes('/api/log'))).toBe(false);
  });
});

/* eslint-enable max-lines, complexity, unicorn/consistent-function-scoping, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
