/* eslint-disable max-lines, complexity, unicorn/consistent-function-scoping, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- This boundary test records the exact Basic plan manifest, serial suite exchange, and one cohesive fake HTTP state machine. */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  access,
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  stat,
  writeFile,
} from 'node:fs/promises';
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
const screenshotHandoffPath = path.resolve(
  process.cwd(),
  '../../.scripts/compatibility/phase1-screenshot-handoff.mjs'
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
  wallClock?: () => number;
  setTimer?: typeof setTimeout;
  clearTimer?: typeof clearTimeout;
  requestTimeoutMs?: number;
  moduleTimeoutMs?: number;
  totalTimeoutMs?: number;
  maximumResponseBytes?: number;
  screenshotIpcRoot?: string;
}>;

type RunnerModule = Readonly<{
  oidfBasicPlanManifest: ReadonlyArray<Readonly<Record<string, unknown>>>;
  runOidfBasicPlan: (
    input: string | Uint8Array,
    dependencies?: BasicRunnerDependencies
  ) => Promise<Readonly<Record<string, unknown>>>;
}>;

type ScreenshotBinding = Readonly<Record<string, unknown>>;
type ScreenshotHandoff = Readonly<{
  binding: ScreenshotBinding;
  captureDirectory: string;
  responseFile: string;
  imageBytes: Uint8Array;
  imageSha256: string;
  imageBytesLength: number;
  renderedUrl: string;
  cookies: ReadonlyArray<Readonly<Record<string, unknown>>>;
}>;
type ScreenshotHandoffModule = Readonly<{
  createScreenshotBinding: (value: Record<string, unknown>) => ScreenshotBinding;
  beginScreenshotHandoff: (input: Readonly<Record<string, unknown>>) => Promise<ScreenshotHandoff>;
  consumeScreenshotResponse: (handoff: ScreenshotHandoff) => void;
  awaitScreenshotReview: (
    handoff: ScreenshotHandoff
  ) => Promise<Readonly<{ reviewer: string; reviewRecordSha256: string }>>;
}>;

const loadRunner = async (): Promise<RunnerModule> => {
  const runner = (await import(pathToFileURL(runnerPath).href)) as RunnerModule;
  return {
    ...runner,
    runOidfBasicPlan: async (input, dependencies = {}) => {
      if (dependencies.screenshotIpcRoot) {
        return runner.runOidfBasicPlan(input, dependencies);
      }
      await mkdir(screenshotEvidenceParent, { recursive: true, mode: 0o700 });
      const root = await mkdtemp(`${screenshotEvidenceParent}/run.`);
      try {
        return await runner.runOidfBasicPlan(input, { ...dependencies, screenshotIpcRoot: root });
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  };
};

const loadScreenshotHandoff = async (): Promise<ScreenshotHandoffModule> =>
  (await import(pathToFileURL(screenshotHandoffPath).href)) as ScreenshotHandoffModule;

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

const renderedImplicitCallback = (submissionUrl: string): Response =>
  new Response(
    `<html><script>var xhr = new XMLHttpRequest(); xhr.open('POST', ${JSON.stringify(submissionUrl)}, true); xhr.setRequestHeader('Content-type', 'text/plain'); xhr.send(window.location.hash);</script></html>`,
    { status: 200, headers: { 'content-type': 'text/html;charset=UTF-8' } }
  );

const screenshotEvidenceParent = '/var/tmp/henry-build/aster-phase1-screenshot-evidence';
const testPng = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=',
  'base64'
);

const waitForPrivateFile = async (file: string, attempt = 0): Promise<void> => {
  try {
    await access(file);
  } catch {
    if (attempt >= 199) {
      throw new Error(`timed out waiting for ${file}`);
    }
    await new Promise<void>((resolve) => {
      setTimeout(resolve, 20);
    });
    return waitForPrivateFile(file, attempt + 1);
  }
};

const writePrivateAtomic = async (file: string, value: string | Uint8Array): Promise<void> => {
  const temporary = `${file}.tmp`;
  await writeFile(temporary, value, { mode: 0o600 });
  await chmod(temporary, 0o600);
  await rename(temporary, file);
};

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

const requiredScreenshotNames: readonly string[] = [
  'oidcc-prompt-login',
  'oidcc-max-age-1',
  'oidcc-ensure-registered-redirect-uri',
];
const redirectErrorDeclaration = Object.freeze({
  url: 'https://server.example/oidc/auth?client_id=oidf-basic-1&redirect_uri=https%3A%2F%2Fsuite.example%2Fcallback%2Funregistered&state=original%2Bstate',
  method: 'GET',
});

// Supply the three mandatory suite/browser/IPC exchanges in otherwise focused plan fixtures.
const runWithRequiredScreenshots = async (
  runner: RunnerModule,
  dependencies: BasicRunnerDependencies & { fetch: typeof fetch },
  excludedModules: readonly string[] = [],
  errorDeclaration: Readonly<{ url: string; method: string }> = redirectErrorDeclaration
) => {
  await mkdir(screenshotEvidenceParent, { recursive: true, mode: 0o700 });
  const root =
    dependencies.screenshotIpcRoot ?? (await mkdtemp(`${screenshotEvidenceParent}/run.`));
  const workers: Array<Promise<void>> = [];
  const workerFailures: unknown[] = [];
  let active:
    | {
        id: string;
        name: string;
        logins: number;
        errorPage: boolean;
        image?: string;
        entry: Record<string, unknown>;
      }
    | undefined;
  const fetchImplementation: typeof fetch = async (input, init) => {
    const url = new URL(String(input));
    const method = init?.method ?? 'GET';
    if (url.pathname === '/api/runner' && method === 'POST') {
      const response = await dependencies.fetch(input, init);
      const module = (await response.clone().json()) as { id: string; name: string };
      active = undefined;
      if (requiredScreenshotNames.includes(module.name) && !excludedModules.includes(module.name)) {
        const errorPage = module.name === 'oidcc-ensure-registered-redirect-uri';
        active = {
          ...module,
          logins: 0,
          errorPage,
          entry: {
            _id: `entry-${module.id}`,
            testId: module.id,
            src: errorPage ? 'ExpectRedirectUriErrorPage' : 'ExpectSecondLoginPage',
            msg: errorPage
              ? 'Show redirect URI error page'
              : 'The server must ask the user to login for a second time; a screenshot of this must be uploaded.',
            result: 'REVIEW',
          },
        };
      }
      return response;
    }
    if (!active) {
      return dependencies.fetch(input, init);
    }
    const state = active;
    const placeholderId = `P${String(basicModuleNames.indexOf(state.name)).padStart(9, '0')}`;
    const redirect = (location: string) =>
      new Response(null, { status: 302, headers: { location } });
    if (url.pathname === `/api/runner/${state.id}/wait-state`) {
      const finished = state.errorPage ? Boolean(state.image) : state.logins === 2;
      return jsonResponse(
        finished
          ? { state: 'FINISHED' }
          : state.logins === 0
            ? { state: 'WAITING' }
            : { timeout: true }
      );
    }
    if (url.pathname === `/api/runner/${state.id}` && method === 'GET') {
      const declared = state.errorPage
        ? errorDeclaration.url
        : `https://server.example/oidc/auth/required-${state.logins}`;
      return jsonResponse({
        id: state.id,
        name: state.name,
        browser: {
          urls: [declared],
          urlsWithMethod: [
            { url: declared, method: state.errorPage ? errorDeclaration.method : 'GET' },
          ],
          browserApiRequests: [],
          uriInputRequests: [],
          uploadsRequired: state.errorPage || state.logins === 1 ? 1 : 0,
        },
      });
    }
    if (url.pathname === `/api/runner/browser/${state.id}/visit`) {
      return new Response(null, { status: 204 });
    }
    if (state.errorPage && url.origin === 'https://server.example') {
      throw new Error('redirect-error navigation must belong exclusively to the capture worker');
    }
    if (url.pathname.startsWith('/oidc/auth/required-')) {
      return redirect(state.errorPage ? '/error/required' : '/sign-in?app_id=oidf-basic-1');
    }
    if (url.pathname === '/error/required') {
      return new Response('<html>Invalid redirect URI</html>', { status: 400 });
    }
    if (url.pathname === '/api/experience' || url.pathname === '/api/experience/identification') {
      return new Response(null, { status: 204 });
    }
    if (url.pathname === '/api/experience/verification/password') {
      return jsonResponse({ verificationId: 'verification-required' });
    }
    if (url.pathname === '/api/experience/submit') {
      return jsonResponse({ redirectTo: 'https://server.example/oidc/auth/resume-required' });
    }
    if (url.pathname === '/oidc/auth/resume-required') {
      return redirect(`${suiteBaseUrl}/test/a/aster-phase1/callback?code=required`);
    }
    if (url.pathname === '/test/a/aster-phase1/callback') {
      return renderedImplicitCallback(
        `${suiteBaseUrl}/test/a/aster-phase1/implicit/Required123456789012`
      );
    }
    if (url.pathname === '/test/a/aster-phase1/implicit/Required123456789012') {
      state.logins += 1;
      return new Response(null, { status: 204 });
    }
    if (url.pathname === `/api/log/${state.id}`) {
      if (!state.image) {
        const directory = path.join(root, planInstanceId, state.id, placeholderId);
        const worker = (async () => {
          await waitForPrivateFile(path.join(directory, 'capture-request.json'));
          const request = JSON.parse(
            await readFile(path.join(directory, 'capture-request.json'), 'utf8')
          ) as Record<string, unknown>;
          const { url: renderedUrl, issuerOrigin: _origin, cookies, ...binding } = request;
          if (state.errorPage) {
            expect(renderedUrl).toBe(errorDeclaration.url);
          }
          expect(binding).toMatchObject({
            testId: state.id,
            moduleName: state.name,
            placeholderId,
          });
          const imageSha256 = createHash('sha256').update(testPng).digest('hex');
          await writePrivateAtomic(path.join(directory, 'capture.png'), testPng);
          await writePrivateAtomic(
            path.join(directory, 'capture-response.json'),
            JSON.stringify({
              ...binding,
              result: 'CAPTURED',
              renderedUrl,
              imageFile: 'capture.png',
              imageSha256,
              imageBytes: testPng.byteLength,
              observedCondition: true,
              cookies,
            })
          );
          await waitForPrivateFile(path.join(directory, 'review-request.json'));
          await writePrivateAtomic(
            path.join(directory, 'manual-review.json'),
            JSON.stringify({
              ...binding,
              imageSha256,
              reviewer: `sol-fixture-${state.id}`,
              review: 'APPROVE',
              reviewedAt: Date.now(),
            })
          );
        })();
        workers.push(
          (async () => {
            try {
              await worker;
            } catch (error: unknown) {
              workerFailures.push(error);
            }
          })()
        );
      }
      return jsonResponse([
        { ...state.entry, ...(state.image ? { img: state.image } : { upload: placeholderId }) },
      ]);
    }
    if (url.pathname === `/api/log/${state.id}/images/${placeholderId}` && method === 'POST') {
      state.image = String(init?.body);
      return jsonResponse({ ...state.entry, img: state.image });
    }
    if (url.pathname === `/api/info/${state.id}`) {
      return jsonResponse({
        testId: state.id,
        testName: state.name,
        planId: planInstanceId,
        status: 'FINISHED',
        result: 'REVIEW',
        variant: {
          ...moduleVariant(state.name),
          server_metadata: 'discovery',
          client_registration: 'static_client',
        },
      });
    }
    return dependencies.fetch(input, init);
  };
  try {
    const terminal = await runner.runOidfBasicPlan(JSON.stringify(validInput()), {
      ...dependencies,
      moduleTimeoutMs: dependencies.moduleTimeoutMs ?? 4000,
      screenshotIpcRoot: root,
      fetch: fetchImplementation,
    });
    await Promise.all(workers);
    if (workerFailures.length > 0) {
      throw workerFailures[0];
    }
    return terminal;
  } finally {
    await Promise.allSettled(workers);
    if (!dependencies.screenshotIpcRoot) {
      await rm(root, { recursive: true, force: true });
    }
  }
};

const firstModuleEvidenceExchange = (
  scenario: Readonly<{
    uploadsRequired?: unknown;
    secondDeclaration?: boolean;
    finalResult?: string;
    infoOverrides?: Readonly<Record<string, unknown>>;
  }>
) => {
  const testId = 'E00000000000001';
  const declaredUrl = 'https://suite.example/browser/second-authorization';
  const requests: string[] = [];
  let waits = 0;
  let statusPolls = 0;
  let visited = false;
  const fetchImplementation: typeof fetch = async (input, init) => {
    const url = new URL(String(input));
    const method = init?.method ?? 'GET';
    requests.push(`${method} ${url.pathname}`);
    if (url.pathname === '/api/plan' && method === 'POST') {
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
    if (url.pathname === '/api/runner' && method === 'POST') {
      return jsonResponse({ name: 'oidcc-server', id: testId }, 201);
    }
    if (url.pathname === `/api/runner/${testId}/wait-state`) {
      waits += 1;
      return jsonResponse(
        waits === 1
          ? { state: 'WAITING' }
          : scenario.finalResult
            ? { state: 'FINISHED' }
            : { timeout: true }
      );
    }
    if (url.pathname === `/api/runner/${testId}` && method === 'GET') {
      statusPolls += 1;
      const declarations =
        scenario.secondDeclaration && statusPolls > 1 && !visited
          ? [{ url: declaredUrl, method: 'GET' }]
          : [];
      return jsonResponse({
        name: 'oidcc-server',
        id: testId,
        browser: {
          urls: declarations.map(({ url: value }) => value),
          urlsWithMethod: declarations,
          browserApiRequests: [],
          uriInputRequests: [],
          uploadsRequired: scenario.uploadsRequired,
        },
      });
    }
    if (url.pathname === `/api/runner/browser/${testId}/visit` && method === 'POST') {
      visited = true;
      return new Response(null, { status: 204 });
    }
    if (url.pathname === '/browser/second-authorization' && method === 'GET') {
      return new Response('<html>Second authorization</html>', {
        headers: { 'content-type': 'text/html' },
      });
    }
    if (url.pathname === `/api/info/${testId}` && method === 'GET') {
      return jsonResponse({
        testId,
        testName: 'oidcc-server',
        variant: {
          ...expectedManifest[0]!.variant,
          server_metadata: 'discovery',
          client_registration: 'static_client',
        },
        planId: planInstanceId,
        status: 'FINISHED',
        result: scenario.finalResult,
        ...scenario.infoOverrides,
      });
    }
    if (url.pathname === `/api/runner/${testId}` && method === 'DELETE') {
      return jsonResponse({ name: 'oidcc-server', id: testId });
    }
    throw new Error('unexpected fake suite request');
  };
  return { fetchImplementation, requests };
};

const callbackPlaceholderExchange = (
  scenario: Readonly<{
    moduleName?: string;
    initialQueueDelay?: boolean;
    finalResult?: string;
    finalEntry?: Readonly<Record<string, unknown>>;
    extraResult?: string;
    missingFinalEntry?: boolean;
    skipCallback?: boolean;
    authenticate?: boolean;
    finishWithoutBrowser?: boolean;
  }> = {}
) => {
  const moduleName = scenario.moduleName ?? 'oidcc-response-type-missing';
  const testId = `C${String(basicModuleNames.indexOf(moduleName)).padStart(14, '0')}`;
  const placeholder = {
    _id: '507f1f77bcf86cd799439031',
    testId,
    src:
      moduleName === 'oidcc-prompt-login' || moduleName === 'oidcc-max-age-1'
        ? 'ExpectSecondLoginPage'
        : moduleName === 'oidcc-response-type-missing'
          ? 'ExpectResponseTypeMissingErrorPage'
          : 'ExpectRedirectUriErrorPage',
    msg:
      moduleName === 'oidcc-prompt-login' || moduleName === 'oidcc-max-age-1'
        ? 'The server must ask the user to login for a second time; a screenshot of this must be uploaded.'
        : moduleName === 'oidcc-response-type-missing'
          ? 'Upload a screenshot of the error page showing a missing response type error.'
          : 'Show redirect URI error page',
    result: 'REVIEW',
  };
  const completedPlaceholder = {
    ...placeholder,
    image_no_longer_required: true,
    ...scenario.finalEntry,
  };
  const requests: string[] = [];
  const startedModules: string[] = [];
  let callbackCompleted = false;
  let waits = 0;
  let statusPolls = 0;
  const finalLog = [
    ...(scenario.missingFinalEntry ? [] : [completedPlaceholder]),
    {
      testId,
      src: scenario.authenticate
        ? 'CheckIdTokenSignature'
        : 'CheckErrorFromAuthorizationEndpointErrorInvalidRequestOrUnsupportedResponseType',
      result: 'SUCCESS',
    },
    ...(scenario.extraResult
      ? [{ testId, src: 'UnrelatedCondition', result: scenario.extraResult }]
      : []),
    {
      testId,
      src: moduleName,
      result: 'FINISHED',
      testmodule_result: scenario.finalResult ?? 'PASSED',
    },
  ];
  const fetchImplementation: typeof fetch = async (input, init) => {
    const url = new URL(String(input));
    const method = init?.method ?? 'GET';
    requests.push(`${method} ${url.pathname}`);
    if (url.pathname === '/api/plan') {
      return jsonResponse(
        {
          name: planName,
          id: planInstanceId,
          modules: expectedManifest.map((entry) => ({ ...entry, instances: [] })),
        },
        201
      );
    }
    if (url.pathname === '/api/runner' && method === 'POST') {
      const entry = expectedManifest[startedModules.length];
      if (!entry) {
        throw new Error('unexpected module');
      }
      const id = `C${String(startedModules.length).padStart(14, '0')}`;
      startedModules.push(entry.testModule);
      return jsonResponse({ name: entry.testModule, id }, 201);
    }
    if (url.pathname.endsWith('/wait-state')) {
      if (
        url.pathname !== `/api/runner/${testId}/wait-state` ||
        callbackCompleted ||
        scenario.finishWithoutBrowser
      ) {
        return jsonResponse({ state: 'FINISHED' });
      }
      waits += 1;
      if (waits > 2) {
        throw new Error('unexpected wait before callback completion');
      }
      return jsonResponse(waits === 1 ? { state: 'WAITING' } : { timeout: true });
    }
    if (url.pathname === `/api/runner/${testId}` && method === 'GET') {
      statusPolls += 1;
      const declarations =
        scenario.initialQueueDelay && statusPolls === 1
          ? []
          : [{ url: 'https://server.example/oidc/auth', method: 'GET' }];
      return jsonResponse({
        id: testId,
        name: moduleName,
        browser: {
          urls: declarations.map(({ url: declared }) => declared),
          urlsWithMethod: declarations,
          browserApiRequests: [],
          uriInputRequests: [],
          uploadsRequired: 1,
        },
      });
    }
    if (url.pathname === `/api/runner/browser/${testId}/visit`) {
      return new Response(null, { status: 204 });
    }
    if (url.origin === 'https://server.example' && url.pathname === '/oidc/auth') {
      if (scenario.skipCallback) {
        return new Response('invalid request', { status: 400 });
      }
      return new Response(null, {
        status: 302,
        headers: {
          location: scenario.authenticate
            ? '/sign-in?app_id=oidf-basic-1'
            : `${suiteBaseUrl}/test/a/aster-phase1/callback?error=invalid_request`,
        },
      });
    }
    if (url.pathname === '/api/experience' || url.pathname === '/api/experience/identification') {
      return new Response(null, { status: 204 });
    }
    if (url.pathname === '/api/experience/verification/password') {
      return jsonResponse({ verificationId: 'optional-authentication' });
    }
    if (url.pathname === '/api/experience/submit') {
      return jsonResponse({ redirectTo: 'https://server.example/oidc/auth/optional-login' });
    }
    if (url.pathname === '/oidc/auth/optional-login') {
      return new Response(null, {
        status: 302,
        headers: { location: '/consent?app_id=oidf-basic-1' },
      });
    }
    if (url.pathname === '/api/interaction/consent') {
      return jsonResponse(
        method === 'GET'
          ? { application: { id: 'oidf-basic-1' } }
          : { redirectTo: 'https://server.example/oidc/auth/optional-consent' }
      );
    }
    if (url.pathname === '/oidc/auth/optional-consent') {
      return new Response(null, {
        status: 302,
        headers: { location: `${suiteBaseUrl}/test/a/aster-phase1/callback?code=optional` },
      });
    }
    if (url.pathname === '/test/a/aster-phase1/callback') {
      return renderedImplicitCallback(
        `${suiteBaseUrl}/test/a/aster-phase1/implicit/AbCdEfGhIjKlMnOpQrSt`
      );
    }
    if (url.pathname === '/test/a/aster-phase1/implicit/AbCdEfGhIjKlMnOpQrSt') {
      if (method !== 'POST' || init?.body !== '') {
        throw new Error('invalid callback submission');
      }
      callbackCompleted = true;
      return new Response(null, { status: 204 });
    }
    const info = /^\/api\/info\/C([0-9]{14})$/u.exec(url.pathname);
    if (info) {
      const entry = expectedManifest[Number(info[1])]!;
      return jsonResponse({
        testId: `C${info[1]}`,
        testName: entry.testModule,
        variant: {
          ...entry.variant,
          server_metadata: 'discovery',
          client_registration: 'static_client',
        },
        planId: planInstanceId,
        status: 'FINISHED',
        result: entry.testModule === moduleName ? (scenario.finalResult ?? 'PASSED') : 'PASSED',
      });
    }
    const log = /^\/api\/log\/(C[0-9]{14})$/u.exec(url.pathname);
    if (log) {
      if (log[1] === testId) {
        return jsonResponse(
          callbackCompleted ? finalLog : [{ ...placeholder, upload: 'Optional01' }]
        );
      }
      return jsonResponse([{ testId: log[1], src: 'CheckIdToken', result: 'SUCCESS' }]);
    }
    if (url.pathname === `/api/runner/${testId}` && method === 'DELETE') {
      return jsonResponse({ id: testId, name: moduleName });
    }
    throw new Error('unexpected callback-placeholder exchange');
  };
  return { fetchImplementation, requests, startedModules, finalLog, testId };
};

describe('official OIDF Basic plan runner input and manifest', () => {
  it('retains all 35 private ordered ledgers with original byte hashes and no sensitive payloads', async () => {
    const runner = await loadRunner();
    await mkdir(screenshotEvidenceParent, { recursive: true, mode: 0o700 });
    const root = await mkdtemp(`${screenshotEvidenceParent}/run.`);
    const exchange = callbackPlaceholderExchange();
    const hashes = new Map<string, string>();
    const payloadCanary = 'private-payload-not-for-audit';
    const fetchImplementation: typeof fetch = async (input, init) => {
      const url = new URL(String(input));
      const response = await exchange.fetchImplementation(input, init);
      if (
        !url.pathname.startsWith('/api/info/') &&
        !/^\/api\/log\/[A-Za-z0-9]+$/u.test(url.pathname)
      ) {
        return response;
      }
      const parsed = (await response.json()) as
        | Record<string, unknown>
        | Array<Record<string, unknown>>;
      const value = Array.isArray(parsed)
        ? [
            {
              _id: 'block-start',
              testId: url.pathname.split('/').at(-1),
              src: '-START-BLOCK-',
              msg: payloadCanary,
            },
            ...parsed.map((row) => ({
              ...row,
              data: payloadCanary,
              env: { token: payloadCanary },
            })),
            {
              _id: 'metadata-row',
              testId: url.pathname.split('/').at(-1),
              src: 'AuditMetadata',
              requirements: ['OIDCC-3.1.2.1'],
              msg: payloadCanary,
              cookies: payloadCanary,
            },
          ]
        : { ...parsed, configuration: { client_secret: payloadCanary }, tokens: payloadCanary };
      const bytes = `${JSON.stringify(value, null, 2)}\n`;
      hashes.set(url.pathname, createHash('sha256').update(bytes).digest('hex'));
      return new Response(bytes, {
        status: response.status,
        headers: { 'content-type': 'application/json' },
      });
    };
    try {
      const terminal = await runWithRequiredScreenshots(runner, {
        readSecret,
        fetch: fetchImplementation,
        screenshotIpcRoot: root,
      });
      const result = terminal.result as { modules: Array<Record<string, unknown>> };
      const audits = await Promise.all(
        result.modules.map(async (summary) => {
          const directory = path.join(root, planInstanceId, String(summary.testId));
          const file = path.join(directory, 'module-audit.json');
          const source = await readFile(file, 'utf8');
          const audit = JSON.parse(source) as {
            conditions: Array<Record<string, unknown>>;
            conditionCount: number;
            review: unknown;
            info: Record<string, unknown>;
          };
          const [directoryStat, fileStat] = await Promise.all([stat(directory), stat(file)]);
          expect(directoryStat.mode % 0o1000).toBe(0o700);
          expect(fileStat.mode % 0o1000).toBe(0o600);
          expect(fileStat.uid).toBe(process.getuid?.());
          expect(source).not.toContain(payloadCanary);
          expect(source).not.toMatch(
            /"(?:msg|img|payload|env|cookies|tokens|client_secret)"|data:image/iu
          );
          expect(audit).toMatchObject({
            suiteCommit: phase1ConformanceSuiteCommit,
            planName,
            planInstanceId,
            moduleName: summary.testName,
            testId: summary.testId,
            accepted: true,
            failureCategory: null,
            conditionLogSha256: summary.conditionLogSha256,
            review: summary.review,
            info: {
              testId: summary.testId,
              testName: summary.testName,
              status: 'FINISHED',
              result: summary.result,
              planId: planInstanceId,
            },
          });
          expect(Object.keys(audit.info).sort()).toEqual([
            'planId',
            'result',
            'status',
            'testId',
            'testName',
            'variant',
          ]);
          expect(audit.conditionCount).toBe(audit.conditions.length);
          if (audit.review) {
            expect(audit.conditions[0]?.imageSha256).toBe(
              (audit.review as Record<string, unknown>).imageSha256
            );
            expect(audit).toMatchObject({
              captureId: expect.stringMatching(/^[a-f0-9]{32}$/u) as unknown,
            });
          }
          return audit;
        })
      );
      expect(audits).toHaveLength(35);
      expect(audits[1]).toMatchObject({
        infoSha256: hashes.get(`/api/info/${exchange.testId}`),
        conditionLogSha256: hashes.get(`/api/log/${exchange.testId}`),
        conditionCount: 5,
      });
      expect(audits[1]?.conditions.map(({ src }) => src)).toEqual([
        '-START-BLOCK-',
        'ExpectResponseTypeMissingErrorPage',
        'CheckErrorFromAuthorizationEndpointErrorInvalidRequestOrUnsupportedResponseType',
        'oidcc-response-type-missing',
        'AuditMetadata',
      ]);
      expect(audits[1]?.conditions[1]).toMatchObject({
        resultPresent: true,
        result: 'REVIEW',
        image_no_longer_required: true,
      });
      expect(audits[1]?.conditions[4]).toEqual({
        _id: 'metadata-row',
        testId: exchange.testId,
        src: 'AuditMetadata',
        resultPresent: false,
        result: null,
        requirements: ['OIDCC-3.1.2.1'],
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('rejects unknown leading-punctuation sources instead of treating them as suite block markers', async () => {
    const runner = await loadRunner();
    const exchange = callbackPlaceholderExchange();
    const fetchImplementation: typeof fetch = async (input, init) => {
      if (new URL(String(input)).pathname === '/api/log/C00000000000000') {
        return jsonResponse([
          { _id: 'bad-marker', testId: 'C00000000000000', src: '-UNKNOWN-BLOCK-' },
        ]);
      }
      return exchange.fetchImplementation(input, init);
    };
    await expect(
      runner.runOidfBasicPlan(JSON.stringify(validInput()), {
        readSecret,
        fetch: fetchImplementation,
      })
    ).rejects.toMatchObject({ category: 'module-audit', module: 'oidcc-server' });
  });

  it.each(['missing', 'modified', 'wrong permissions'] as const)(
    'rejects final acceptance when an earlier audit is %s',
    async (mutation) => {
      const runner = await loadRunner();
      await mkdir(screenshotEvidenceParent, { recursive: true, mode: 0o700 });
      const root = await mkdtemp(`${screenshotEvidenceParent}/run.`);
      const exchange = callbackPlaceholderExchange();
      const file = path.join(root, planInstanceId, 'C00000000000000', 'module-audit.json');
      const fetchImplementation: typeof fetch = async (input, init) => {
        const url = new URL(String(input));
        if (url.pathname === '/api/info/C00000000000034') {
          if (mutation === 'missing') {
            await rm(file);
          } else if (mutation === 'modified') {
            await writeFile(file, '{}', { mode: 0o600 });
          } else {
            await chmod(file, 0o644);
          }
        }
        return exchange.fetchImplementation(input, init);
      };
      try {
        await expect(
          runWithRequiredScreenshots(runner, {
            readSecret,
            fetch: fetchImplementation,
            screenshotIpcRoot: root,
          })
        ).rejects.toMatchObject({ category: 'module-audit' });
        expect(exchange.startedModules).toHaveLength(35);
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
  );

  it.each(requiredScreenshotNames)(
    'rejects mandatory %s reporting PASSED without capture proof',
    async (moduleName) => {
      const runner = await loadRunner();
      const exchange = callbackPlaceholderExchange({ moduleName, finishWithoutBrowser: true });
      await expect(
        runWithRequiredScreenshots(
          runner,
          {
            readSecret,
            fetch: exchange.fetchImplementation,
          },
          [moduleName]
        )
      ).rejects.toMatchObject({ category: 'module-result', module: moduleName });
      expect(exchange.requests).toContain(`GET /api/info/${exchange.testId}`);
    }
  );

  it.each(requiredScreenshotNames)(
    'rejects mandatory %s reporting REVIEW without capture proof',
    async (moduleName) => {
      const runner = await loadRunner();
      const exchange = callbackPlaceholderExchange({
        moduleName,
        finishWithoutBrowser: true,
        finalResult: 'REVIEW',
      });
      await expect(
        runWithRequiredScreenshots(
          runner,
          {
            readSecret,
            fetch: exchange.fetchImplementation,
          },
          [moduleName]
        )
      ).rejects.toMatchObject({ category: 'condition-log', module: moduleName });
    }
  );

  it.each(['oidcc-response-type-missing', 'oidcc-ensure-request-object-with-redirect-uri'])(
    'allows %s to authenticate and consent before its callback retires the optional placeholder',
    async (moduleName) => {
      const runner = await loadRunner();
      const exchange = callbackPlaceholderExchange({ moduleName, authenticate: true });
      const terminal = await runWithRequiredScreenshots(runner, {
        readSecret,
        fetch: exchange.fetchImplementation,
      });
      expect(terminal).toMatchObject({
        status: 'FINISHED',
        acceptance: 'ACCEPTED',
        result: { moduleCount: 35, passedModuleCount: 32, reviewedModuleCount: 3 },
      });
      expect(exchange.requests).toContain('POST /api/experience/verification/password');
      expect(exchange.requests).toContain('POST /api/interaction/consent');
      expect(exchange.requests).toContain(
        'POST /test/a/aster-phase1/implicit/AbCdEfGhIjKlMnOpQrSt'
      );
      expect(
        exchange.requests.some((request) => request.includes(`/api/log/${exchange.testId}/images/`))
      ).toBe(false);
    }
  );

  it('never retires the registered-redirect placeholder through a successful callback', async () => {
    const runner = await loadRunner();
    const moduleName = 'oidcc-ensure-registered-redirect-uri';
    const exchange = callbackPlaceholderExchange({ moduleName });
    await expect(
      runWithRequiredScreenshots(runner, { readSecret, fetch: exchange.fetchImplementation }, [
        moduleName,
      ])
    ).rejects.toMatchObject({ category: 'screenshot-handoff', module: moduleName });
    expect(exchange.requests).not.toContain('GET /oidc/auth');
    expect(exchange.requests).not.toContain('GET /test/a/aster-phase1/callback');
  });

  it('hands the untouched registered-redirect GET to capture without a driver prefetch', async () => {
    const runner = await loadRunner();
    const exchange = callbackPlaceholderExchange();
    const terminal = await runWithRequiredScreenshots(runner, {
      readSecret,
      fetch: exchange.fetchImplementation,
    });
    expect(terminal).toMatchObject({
      acceptance: 'ACCEPTED',
    });
    const result = terminal.result as { modules: Array<Record<string, unknown>> };
    expect(result.modules[27]).toMatchObject({
      testName: 'oidcc-ensure-registered-redirect-uri',
      result: 'REVIEW',
      review: { conditionId: 'ExpectRedirectUriErrorPage' },
    });
  });

  it.each([
    { ...redirectErrorDeclaration, method: 'POST' },
    { ...redirectErrorDeclaration, url: 'https://server.example/oidc/auth/previous' },
    { ...redirectErrorDeclaration, url: `${suiteBaseUrl}/test/a/aster-phase1/callback` },
  ])(
    'rejects a non-first-GET registered-redirect declaration before handoff',
    async (declaration) => {
      const runner = await loadRunner();
      const exchange = callbackPlaceholderExchange();
      await expect(
        runWithRequiredScreenshots(
          runner,
          { readSecret, fetch: exchange.fetchImplementation },
          [],
          declaration
        )
      ).rejects.toMatchObject({
        category: 'screenshot-condition',
        module: 'oidcc-ensure-registered-redirect-uri',
      });
    }
  );

  it.each([false, true])(
    'accepts all 35 modules when the callback retires its optional placeholder (initial queue delay: %s)',
    async (initialQueueDelay) => {
      const runner = await loadRunner();
      const exchange = callbackPlaceholderExchange({ initialQueueDelay });
      const terminal = await runWithRequiredScreenshots(runner, {
        readSecret,
        fetch: exchange.fetchImplementation,
      });
      const result = terminal.result as {
        modules: ReadonlyArray<Readonly<Record<string, unknown>>>;
      };
      expect(exchange.startedModules).toEqual(basicModuleNames);
      expect(terminal).toMatchObject({
        status: 'FINISHED',
        acceptance: 'ACCEPTED',
        result: { moduleCount: 35, passedModuleCount: 32, reviewedModuleCount: 3 },
      });
      expect(result.modules[1]).toEqual({
        testId: exchange.testId,
        testName: 'oidcc-response-type-missing',
        status: 'FINISHED',
        result: 'PASSED',
        conditionLogSha256: createHash('sha256')
          .update(JSON.stringify(exchange.finalLog))
          .digest('hex'),
        review: null,
      });
      expect(exchange.requests).toContain(
        'POST /test/a/aster-phase1/implicit/AbCdEfGhIjKlMnOpQrSt'
      );
      expect(exchange.requests.some((request) => request.includes('/images/'))).toBe(false);
    }
  );

  it.each([
    ['missing flag', { finalEntry: { image_no_longer_required: undefined } }],
    ['false flag', { finalEntry: { image_no_longer_required: false } }],
    ['string flag', { finalEntry: { image_no_longer_required: 'true' } }],
    ['wrong entry', { finalEntry: { _id: 'different-entry' } }],
    ['wrong condition', { finalEntry: { src: 'ExpectRedirectUriErrorPage' } }],
    ['wrong message', { finalEntry: { msg: 'different condition' } }],
    ['wrong test', { finalEntry: { testId: 'C99999999999999' } }],
    ['remaining upload', { finalEntry: { upload: 'Optional01' } }],
    ['image present', { finalEntry: { img: null } }],
    ['missing entry', { missingFinalEntry: true }],
    ['unrelated REVIEW', { extraResult: 'REVIEW' }],
    ['hidden FAILURE', { extraResult: 'FAILURE' }],
    ['hidden WARNING', { extraResult: 'WARNING' }],
    ['official REVIEW', { finalResult: 'REVIEW' }],
  ] as const)('rejects callback-retired placeholder with %s', async (_name, scenario) => {
    const runner = await loadRunner();
    const exchange = callbackPlaceholderExchange(scenario);
    await expect(
      runner.runOidfBasicPlan(JSON.stringify(validInput()), {
        readSecret,
        fetch: exchange.fetchImplementation,
      })
    ).rejects.toMatchObject({ category: 'condition-log', module: 'oidcc-response-type-missing' });
    expect(exchange.startedModules).toHaveLength(2);
    expect(exchange.requests).toContain(`DELETE /api/runner/${exchange.testId}`);
  });

  it('requires a second-sign-in capture even if the callback would retire its placeholder', async () => {
    const runner = await loadRunner();
    const exchange = callbackPlaceholderExchange({ moduleName: 'oidcc-prompt-login' });
    await expect(
      runner.runOidfBasicPlan(JSON.stringify(validInput()), {
        readSecret,
        fetch: exchange.fetchImplementation,
      })
    ).rejects.toMatchObject({ category: 'screenshot-condition', module: 'oidcc-prompt-login' });
    expect(exchange.requests).not.toContain(`GET /api/info/${exchange.testId}`);
  });

  it('does not retire an optional placeholder without completing the actual callback', async () => {
    const runner = await loadRunner();
    const exchange = callbackPlaceholderExchange({ skipCallback: true });
    await expect(
      runner.runOidfBasicPlan(JSON.stringify(validInput()), {
        readSecret,
        fetch: exchange.fetchImplementation,
      })
    ).rejects.toMatchObject({
      category: 'screenshot-condition',
      module: 'oidcc-response-type-missing',
    });
    expect(exchange.requests).not.toContain(`GET /api/info/${exchange.testId}`);
  });

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

  it('accepts identical PNG bytes only through distinct bound captures and review records', async () => {
    const handoffModule = await loadScreenshotHandoff();
    await mkdir(screenshotEvidenceParent, { recursive: true, mode: 0o700 });
    await chmod(screenshotEvidenceParent, 0o700);
    const root = await mkdtemp(`${screenshotEvidenceParent}/run.`);
    await chmod(root, 0o700);
    const imageSha256 = createHash('sha256').update(testPng).digest('hex');

    const perform = async (sequence: number) => {
      const createdAt = Date.now();
      const binding = handoffModule.createScreenshotBinding({
        schemaVersion: 1,
        suiteCommit: phase1ConformanceSuiteCommit,
        planName,
        planInstanceId,
        moduleName: sequence === 1 ? 'oidcc-prompt-login' : 'oidcc-max-age-1',
        testId: `S${String(sequence).padStart(14, '0')}`,
        placeholderId: sequence === 1 ? 'CaptureA01' : 'CaptureB02',
        conditionId: 'ExpectSecondLoginPage',
        captureId: String(sequence).padStart(32, '0'),
        captureKind: 'second-sign-in',
        createdAt,
        deadline: createdAt + 10_000,
      });
      const captureDirectory = path.join(
        root,
        String(binding.planInstanceId),
        String(binding.testId),
        String(binding.placeholderId)
      );
      const requestFile = path.join(captureDirectory, 'capture-request.json');
      const responseFile = path.join(captureDirectory, 'capture-response.json');
      const reviewRequestFile = path.join(captureDirectory, 'review-request.json');
      const manualReviewFile = path.join(captureDirectory, 'manual-review.json');
      const worker = (async () => {
        await waitForPrivateFile(requestFile);
        const request = JSON.parse(await readFile(requestFile, 'utf8')) as Record<string, unknown>;
        const { url: _url, issuerOrigin: _issuerOrigin, cookies: _cookies, ...common } = request;
        await writePrivateAtomic(path.join(captureDirectory, 'capture.png'), testPng);
        await writePrivateAtomic(
          responseFile,
          JSON.stringify({
            ...common,
            result: 'CAPTURED',
            renderedUrl: request.url,
            imageFile: 'capture.png',
            imageSha256,
            imageBytes: testPng.byteLength,
            observedCondition: true,
            cookies: [],
          })
        );
        await waitForPrivateFile(reviewRequestFile);
        const review = {
          ...common,
          imageSha256,
          reviewer: `sol-session-${sequence}`,
          review: 'APPROVE',
          reviewedAt: Date.now(),
        };
        const source = JSON.stringify(review);
        await writePrivateAtomic(manualReviewFile, source);
        return source;
      })();
      const handoff = await handoffModule.beginScreenshotHandoff({
        root,
        binding,
        url: 'https://server.example/sign-in?app_id=oidf-basic-1',
        issuerOrigin: 'https://server.example',
        cookies: [],
      });
      handoffModule.consumeScreenshotResponse(handoff);
      const review = await handoffModule.awaitScreenshotReview(handoff);
      const source = await worker;
      expect(review.reviewRecordSha256).toBe(createHash('sha256').update(source).digest('hex'));
      return { handoff, review };
    };

    try {
      const [first, second] = await Promise.all([perform(1), perform(2)]);
      expect(first.handoff.imageSha256).toBe(second.handoff.imageSha256);
      expect(first.handoff.binding.captureId).not.toBe(second.handoff.binding.captureId);
      expect(first.review.reviewRecordSha256).not.toBe(second.review.reviewRecordSha256);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('rejects a stale independently reviewed record', async () => {
    const handoffModule = await loadScreenshotHandoff();
    await mkdir(screenshotEvidenceParent, { recursive: true, mode: 0o700 });
    await chmod(screenshotEvidenceParent, 0o700);
    const root = await mkdtemp(`${screenshotEvidenceParent}/run.`);
    await chmod(root, 0o700);
    const createdAt = Date.now();
    const binding = handoffModule.createScreenshotBinding({
      schemaVersion: 1,
      suiteCommit: phase1ConformanceSuiteCommit,
      planName,
      planInstanceId,
      moduleName: 'oidcc-prompt-login',
      testId: 'S00000000000003',
      placeholderId: 'CaptureC03',
      conditionId: 'ExpectSecondLoginPage',
      captureId: '00000000000000000000000000000003',
      captureKind: 'second-sign-in',
      createdAt,
      deadline: createdAt + 10_000,
    });
    const captureDirectory = path.join(
      root,
      String(binding.planInstanceId),
      String(binding.testId),
      String(binding.placeholderId)
    );
    const requestFile = path.join(captureDirectory, 'capture-request.json');
    const responseFile = path.join(captureDirectory, 'capture-response.json');
    const reviewRequestFile = path.join(captureDirectory, 'review-request.json');
    const imageSha256 = createHash('sha256').update(testPng).digest('hex');
    const worker = (async () => {
      await waitForPrivateFile(requestFile);
      const request = JSON.parse(await readFile(requestFile, 'utf8')) as Record<string, unknown>;
      const { url: _url, issuerOrigin: _issuerOrigin, cookies: _cookies, ...common } = request;
      await writePrivateAtomic(path.join(captureDirectory, 'capture.png'), testPng);
      await writePrivateAtomic(
        responseFile,
        JSON.stringify({
          ...common,
          result: 'CAPTURED',
          renderedUrl: request.url,
          imageFile: 'capture.png',
          imageSha256,
          imageBytes: testPng.byteLength,
          observedCondition: true,
          cookies: [],
        })
      );
      await waitForPrivateFile(reviewRequestFile);
      await writePrivateAtomic(
        path.join(captureDirectory, 'manual-review.json'),
        JSON.stringify({
          ...common,
          imageSha256,
          reviewer: 'sol-session-stale',
          review: 'APPROVE',
          reviewedAt: createdAt - 1,
        })
      );
    })();

    try {
      const handoff = await handoffModule.beginScreenshotHandoff({
        root,
        binding,
        url: 'https://server.example/sign-in?app_id=oidf-basic-1',
        issuerOrigin: 'https://server.example',
        cookies: [],
      });
      handoffModule.consumeScreenshotResponse(handoff);
      await expect(handoffModule.awaitScreenshotReview(handoff)).rejects.toThrow(
        'Invalid phase 1 screenshot handoff'
      );
      await worker;
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('captures and independently approves the real second sign-in before credentials', async () => {
    const runner = await loadRunner();
    await mkdir(screenshotEvidenceParent, { recursive: true, mode: 0o700 });
    await chmod(screenshotEvidenceParent, 0o700);
    const screenshotIpcRoot = await mkdtemp(`${screenshotEvidenceParent}/run.`);
    await chmod(screenshotIpcRoot, 0o700);
    const promptIndex = basicModuleNames.indexOf('oidcc-prompt-login');
    const promptId = `R${String(promptIndex).padStart(14, '0')}`;
    const placeholderId = 'AbCdEf1234';
    const logEntryId = '507f1f77bcf86cd799439011';
    const promptMessage =
      'The server must ask the user to login for a second time; a screenshot of this must be uploaded.';
    const captureDirectory = path.join(screenshotIpcRoot, planInstanceId, promptId, placeholderId);
    const captureRequestFile = path.join(captureDirectory, 'capture-request.json');
    const captureResponseFile = path.join(captureDirectory, 'capture-response.json');
    const reviewRequestFile = path.join(captureDirectory, 'review-request.json');
    const manualReviewFile = path.join(captureDirectory, 'manual-review.json');
    const imageFile = path.join(captureDirectory, 'capture.png');
    const imageSha256 = createHash('sha256').update(testPng).digest('hex');
    const tests = new Map<string, Readonly<{ name: string; variant: Record<string, string> }>>();
    let nextTest = 0;
    let promptWaits = 0;
    let promptStatusPolls = 0;
    let currentLogin: 'first' | 'second' = 'first';
    let secondLoginCompleted = false;
    let secondAuthorizationCookie = '';
    let uploadedEntry: Readonly<Record<string, unknown>> | undefined;
    let reviewSource = '';

    const worker = (async () => {
      await waitForPrivateFile(captureRequestFile);
      const request = JSON.parse(await readFile(captureRequestFile, 'utf8')) as Record<
        string,
        unknown
      >;
      expect(request).toMatchObject({
        schemaVersion: 1,
        suiteCommit: phase1ConformanceSuiteCommit,
        planName,
        planInstanceId,
        moduleName: 'oidcc-prompt-login',
        testId: promptId,
        placeholderId,
        conditionId: 'ExpectSecondLoginPage',
        captureKind: 'second-sign-in',
        issuerOrigin: 'https://server.example',
      });
      expect(request.url).toBe('https://server.example/sign-in?app_id=oidf-basic-1');
      const requestCookies = request.cookies as Array<Record<string, unknown>>;
      expect(requestCookies.every(({ domain }) => domain === 'server.example')).toBe(true);
      expect(
        requestCookies.some(({ name, httpOnly }) => name === '_aster' && httpOnly === true)
      ).toBe(true);
      expect(
        requestCookies.some(({ name, sameSite }) => name === '_aster' && sameSite === 'Strict')
      ).toBe(true);
      expect(requestCookies.some(({ name }) => name === 'suite_session')).toBe(false);
      const { url: _url, issuerOrigin: _issuerOrigin, cookies: _cookies, ...binding } = request;
      const responseCookies = [
        {
          name: '_aster',
          value: 'rendered-second',
          domain: 'server.example',
          path: '/',
          expires: -1,
          httpOnly: true,
          secure: true,
          sameSite: 'Strict',
        },
        {
          name: '_aster_session',
          value: 'session-one',
          domain: 'server.example',
          path: '/',
          expires: -1,
          httpOnly: true,
          secure: true,
          sameSite: 'None',
        },
      ];
      await writePrivateAtomic(`${imageFile}`, testPng);
      await writePrivateAtomic(
        captureResponseFile,
        JSON.stringify({
          ...binding,
          result: 'CAPTURED',
          renderedUrl: request.url,
          imageFile: 'capture.png',
          imageSha256,
          imageBytes: testPng.byteLength,
          observedCondition: true,
          cookies: responseCookies,
        })
      );
      await waitForPrivateFile(reviewRequestFile);
      const reviewRequest = JSON.parse(await readFile(reviewRequestFile, 'utf8')) as Record<
        string,
        unknown
      >;
      expect(reviewRequest).toEqual({
        ...binding,
        imageFile: 'capture.png',
        imageSha256,
        imageBytes: testPng.byteLength,
      });
      const manualReview = {
        ...binding,
        imageSha256,
        reviewer: 'sol-session-basic-001',
        review: 'APPROVE',
        reviewedAt: Date.now(),
      };
      reviewSource = JSON.stringify(manualReview);
      await writePrivateAtomic(manualReviewFile, reviewSource);
      return request;
    })();

    const redirectResponse = (location: string, cookies: readonly string[] = []): Response => {
      const headers = new Headers({ location });
      for (const cookie of cookies) {
        headers.append('set-cookie', cookie);
      }
      return new Response(null, { status: 302, headers });
    };
    const initialReviewEntry = () => ({
      _id: logEntryId,
      testId: promptId,
      src: 'ExpectSecondLoginPage',
      msg: promptMessage,
      result: 'REVIEW',
      upload: placeholderId,
    });
    const fetchImplementation: typeof fetch = async (input, init) => {
      const url = new URL(String(input));
      const method = init?.method ?? 'GET';
      const headers = new Headers(init?.headers);
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
        const id = `R${String(nextTest).padStart(14, '0')}`;
        tests.set(id, { name: manifestEntry.testModule, variant: manifestEntry.variant });
        nextTest += 1;
        return jsonResponse({ name: manifestEntry.testModule, id }, 201);
      }
      const wait = /^\/api\/runner\/([A-Za-z0-9]{15})\/wait-state$/u.exec(url.pathname);
      if (wait) {
        if (wait[1] !== promptId) {
          return jsonResponse({ state: 'FINISHED' });
        }
        promptWaits += 1;
        if (promptWaits === 1) {
          return jsonResponse({ state: 'WAITING' });
        }
        if (promptWaits === 2) {
          return jsonResponse({ timeout: true });
        }
        expect(secondLoginCompleted).toBe(true);
        return jsonResponse({ state: 'FINISHED' });
      }
      if (url.origin === suiteBaseUrl && url.pathname === `/api/runner/${promptId}`) {
        promptStatusPolls += 1;
        const second = promptStatusPolls === 2;
        return jsonResponse({
          name: 'oidcc-prompt-login',
          id: promptId,
          browser: {
            urls: [`https://suite.example/browser/prompt-${second ? 'second' : 'first'}`],
            urlsWithMethod: [
              {
                url: `https://suite.example/browser/prompt-${second ? 'second' : 'first'}`,
                method: 'GET',
              },
            ],
            browserApiRequests: [],
            uriInputRequests: [],
            uploadsRequired: second ? 1 : 0,
          },
        });
      }
      if (
        url.origin === suiteBaseUrl &&
        url.pathname === `/api/runner/browser/${promptId}/visit` &&
        method === 'POST'
      ) {
        return new Response(null, { status: 204 });
      }
      if (url.origin === suiteBaseUrl && url.pathname === '/browser/prompt-first') {
        return redirectResponse('https://server.example/oidc/auth/prompt-first', [
          'suite_session=alpha; Path=/; Secure; HttpOnly; SameSite=Lax',
        ]);
      }
      if (url.origin === suiteBaseUrl && url.pathname === '/browser/prompt-second') {
        return redirectResponse('https://server.example/oidc/auth/prompt-second');
      }
      if (url.origin === 'https://server.example' && url.pathname === '/oidc/auth/prompt-first') {
        currentLogin = 'first';
        return redirectResponse('/sign-in?app_id=oidf-basic-1', [
          '_aster=interaction-first; Path=/; Secure; HttpOnly; SameSite=Strict',
        ]);
      }
      if (url.origin === 'https://server.example' && url.pathname === '/oidc/auth/prompt-second') {
        secondAuthorizationCookie = headers.get('cookie') ?? '';
        currentLogin = 'second';
        return redirectResponse('/sign-in?app_id=oidf-basic-1', [
          '_aster=interaction-second; Path=/; Secure; HttpOnly; SameSite=Strict',
        ]);
      }
      if (url.origin === 'https://server.example' && url.pathname === '/api/experience') {
        if (currentLogin === 'second') {
          expect(uploadedEntry).toBeDefined();
          expect(headers.get('cookie')).toContain('_aster=rendered-second');
          expect(headers.get('cookie')).not.toContain('_aster=interaction-second');
        }
        return new Response(null, { status: 204 });
      }
      if (
        url.origin === 'https://server.example' &&
        url.pathname === '/api/experience/verification/password'
      ) {
        return jsonResponse({ verificationId: `verification-${currentLogin}` });
      }
      if (
        url.origin === 'https://server.example' &&
        url.pathname === '/api/experience/identification'
      ) {
        return new Response(null, { status: 204 });
      }
      if (url.origin === 'https://server.example' && url.pathname === '/api/experience/submit') {
        return jsonResponse({
          redirectTo: `https://server.example/oidc/auth/resume-${currentLogin}`,
        });
      }
      if (url.origin === 'https://server.example' && url.pathname === '/oidc/auth/resume-first') {
        return redirectResponse('https://suite.example/test/a/aster-phase1/callback?state=first', [
          '_aster_session=session-one; Path=/; Secure; HttpOnly; SameSite=None',
        ]);
      }
      if (url.origin === 'https://server.example' && url.pathname === '/oidc/auth/resume-second') {
        return redirectResponse('https://suite.example/test/a/aster-phase1/callback?state=second');
      }
      if (url.origin === suiteBaseUrl && url.pathname === '/test/a/aster-phase1/callback') {
        expect(headers.get('cookie')).toContain('suite_session=alpha');
        return renderedImplicitCallback(
          url.searchParams.get('state') === 'first'
            ? 'https://suite.example/test/a/aster-phase1/implicit/AbCdEfGhIjKlMnOpQrSt'
            : 'https://suite.example/test/a/aster-phase1/implicit/0123456789abcdefghij'
        );
      }
      if (
        url.origin === suiteBaseUrl &&
        url.pathname.startsWith('/test/a/aster-phase1/implicit/')
      ) {
        if (url.pathname.endsWith('/0123456789abcdefghij')) {
          secondLoginCompleted = true;
        }
        return new Response(null, { status: 204 });
      }
      const upload = new RegExp(`^/api/log/${promptId}/images/(${placeholderId})$`, 'u').exec(
        url.pathname
      );
      if (url.origin === suiteBaseUrl && upload && method === 'POST') {
        const imageData = String(init?.body);
        expect(
          createHash('sha256')
            .update(Buffer.from(imageData.split(',')[1]!, 'base64'))
            .digest('hex')
        ).toBe(imageSha256);
        uploadedEntry = {
          _id: logEntryId,
          testId: promptId,
          src: 'ExpectSecondLoginPage',
          msg: promptMessage,
          result: 'REVIEW',
          img: imageData,
          updatedAt: Date.now(),
        };
        return jsonResponse(uploadedEntry);
      }
      const info = /^\/api\/info\/([A-Za-z0-9]{15})$/u.exec(url.pathname);
      if (url.origin === suiteBaseUrl && info) {
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
          result: info[1] === promptId ? 'REVIEW' : 'PASSED',
        });
      }
      const log = /^\/api\/log\/([A-Za-z0-9]{15})$/u.exec(url.pathname);
      if (url.origin === suiteBaseUrl && log) {
        if (log[1] !== promptId) {
          return jsonResponse([]);
        }
        return jsonResponse([uploadedEntry ?? initialReviewEntry()]);
      }
      throw new Error(`unexpected request ${method} ${url.href}`);
    };

    try {
      const terminal = await runWithRequiredScreenshots(
        runner,
        {
          readSecret,
          fetch: fetchImplementation,
          screenshotIpcRoot,
        },
        ['oidcc-prompt-login']
      );
      await worker;
      expect(nextTest).toBe(35);
      expect(promptStatusPolls).toBe(2);
      expect(secondAuthorizationCookie).toContain('_aster_session=session-one');
      expect(terminal).toMatchObject({
        kind: 'phase1-conformance-basic-terminal',
        status: 'FINISHED',
        acceptance: 'ACCEPTED',
        result: {
          outcome: 'accepted',
          moduleCount: 35,
          passedModuleCount: 32,
          reviewedModuleCount: 3,
        },
      });
      const terminalResult = terminal.result as Readonly<{
        modules: ReadonlyArray<Readonly<Record<string, unknown>>>;
      }>;
      expect(terminalResult.modules[promptIndex]).toEqual({
        testId: promptId,
        testName: 'oidcc-prompt-login',
        status: 'FINISHED',
        result: 'REVIEW',
        conditionLogSha256: createHash('sha256')
          .update(JSON.stringify([uploadedEntry]))
          .digest('hex'),
        review: {
          placeholderId,
          conditionId: 'ExpectSecondLoginPage',
          imageSha256,
          reviewRecordSha256: createHash('sha256').update(reviewSource).digest('hex'),
          reviewer: 'sol-session-basic-001',
          decision: 'APPROVE',
        },
      });
      expect(JSON.stringify(terminal)).not.toMatch(
        /https?:|suite_session|rendered-second|captureId/iu
      );
      await expect(access(captureRequestFile)).rejects.toThrow();
      await expect(access(captureResponseFile)).rejects.toThrow();
      await expect(access(imageFile)).resolves.toBeUndefined();
      await expect(access(reviewRequestFile)).resolves.toBeUndefined();
      await expect(access(manualReviewFile)).resolves.toBeUndefined();
    } finally {
      await rm(screenshotIpcRoot, { recursive: true, force: true });
    }
  });

  it.each([false, true])(
    'reports a required screenshot after browser declarations finish (second declaration: %s)',
    async (secondDeclaration) => {
      const runner = await loadRunner();
      const { fetchImplementation, requests } = firstModuleEvidenceExchange({
        uploadsRequired: 1,
        secondDeclaration,
      });
      await expect(
        runner.runOidfBasicPlan(JSON.stringify(validInput()), {
          readSecret,
          fetch: fetchImplementation,
        })
      ).rejects.toMatchObject({
        category: 'screenshot-condition',
        module: 'oidcc-server',
        message: 'Invalid official OIDF Basic plan run',
      });
      expect(requests.filter((request) => request === 'POST /api/runner')).toHaveLength(1);
      expect(requests).toContain('DELETE /api/runner/E00000000000001');
      expect(
        requests.filter((request) => request === 'GET /api/runner/E00000000000001')
      ).toHaveLength(2);
      expect(
        requests.some((request) => request.includes('/api/log') || request.includes('/images'))
      ).toBe(false);
      expect(requests).not.toContain('POST /api/runner/browser/E00000000000001/visit');
    }
  );

  it.each([undefined, null, -1, 0.5, '1', true, Number.MAX_SAFE_INTEGER + 1])(
    'rejects malformed suite uploadsRequired %s',
    async (uploadsRequired) => {
      const runner = await loadRunner();
      const { fetchImplementation, requests } = firstModuleEvidenceExchange({ uploadsRequired });
      await expect(
        runner.runOidfBasicPlan(JSON.stringify(validInput()), {
          readSecret,
          fetch: fetchImplementation,
        })
      ).rejects.toMatchObject({ category: 'suite-api', module: 'oidcc-server' });
      expect(requests).toContain('DELETE /api/runner/E00000000000001');
      expect(requests.some((request) => request.includes('/api/log'))).toBe(false);
    }
  );

  it('classifies a matching FINISHED/REVIEW after a completed image upload without accepting it', async () => {
    const runner = await loadRunner();
    const { fetchImplementation, requests } = firstModuleEvidenceExchange({
      uploadsRequired: 0,
      finalResult: 'REVIEW',
    });
    await expect(
      runner.runOidfBasicPlan(JSON.stringify(validInput()), {
        readSecret,
        fetch: fetchImplementation,
      })
    ).rejects.toMatchObject({ category: 'condition-log', module: 'oidcc-server' });
    expect(requests).toContain('GET /api/info/E00000000000001');
    expect(requests.filter((request) => request === 'POST /api/runner')).toHaveLength(1);
    expect(requests.includes('GET /api/log/E00000000000001')).toBe(true);
  });

  it.each([
    ['FAILED', {}],
    ['WARNING', {}],
    ['REVIEW', { testId: 'different' }],
    ['REVIEW', { status: 'WAITING' }],
    ['REVIEW', { planId: 'different' }],
    ['REVIEW', { variant: {} }],
    ['REVIEW', { testName: 'different' }],
  ] as const)(
    'keeps %s with mismatched or invalid info as module-result',
    async (finalResult, infoOverrides) => {
      const runner = await loadRunner();
      const { fetchImplementation } = firstModuleEvidenceExchange({
        uploadsRequired: 0,
        finalResult,
        infoOverrides,
      });
      await expect(
        runner.runOidfBasicPlan(JSON.stringify(validInput()), {
          readSecret,
          fetch: fetchImplementation,
        })
      ).rejects.toMatchObject({ category: 'module-result', module: 'oidcc-server' });
    }
  );

  it.each(['FAILURE', 'WARNING', 'REVIEW'] as const)(
    'rejects a hidden %s condition even when official module status is PASSED',
    async (result) => {
      const runner = await loadRunner();
      const testId = 'L00000000000001';
      await mkdir(screenshotEvidenceParent, { recursive: true, mode: 0o700 });
      const root = await mkdtemp(`${screenshotEvidenceParent}/run.`);
      const fetchImplementation: typeof fetch = async (input, init) => {
        const url = new URL(String(input));
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
          return jsonResponse({ name: 'oidcc-server', id: testId }, 201);
        }
        if (url.pathname === `/api/runner/${testId}/wait-state`) {
          return jsonResponse({ state: 'FINISHED' });
        }
        if (url.pathname === `/api/info/${testId}`) {
          return jsonResponse({
            testId,
            testName: 'oidcc-server',
            variant: {
              ...expectedManifest[0]!.variant,
              server_metadata: 'discovery',
              client_registration: 'static_client',
            },
            planId: planInstanceId,
            status: 'FINISHED',
            result: 'PASSED',
          });
        }
        if (url.pathname === `/api/log/${testId}`) {
          return jsonResponse([
            { _id: 'before', testId, src: 'Start' },
            {
              _id: '507f1f77bcf86cd799439012',
              testId,
              src: 'UnexpectedCondition',
              msg: 'must not be accepted',
              result,
              ...(result === 'REVIEW' && { upload: 'OtherAb123' }),
            },
            { _id: 'after', testId, src: 'CheckOtherCondition', result: 'SUCCESS' },
          ]);
        }
        if (url.pathname === `/api/runner/${testId}` && init?.method === 'DELETE') {
          return jsonResponse({ name: 'oidcc-server', id: testId });
        }
        throw new Error(`unexpected request ${url.pathname}`);
      };

      try {
        await expect(
          runner.runOidfBasicPlan(JSON.stringify(validInput()), {
            readSecret,
            fetch: fetchImplementation,
            screenshotIpcRoot: root,
          })
        ).rejects.toMatchObject({ category: 'condition-log', module: 'oidcc-server' });
        const audit = JSON.parse(
          await readFile(path.join(root, planInstanceId, testId, 'module-audit.json'), 'utf8')
        ) as {
          conditions: Array<Record<string, unknown>>;
        };
        expect(audit).toMatchObject({
          accepted: false,
          failureCategory: 'condition-log',
          conditionCount: 3,
          info: { status: 'FINISHED', result: 'PASSED' },
        });
        expect(audit.conditions.map((entry) => entry._id)).toEqual([
          'before',
          '507f1f77bcf86cd799439012',
          'after',
        ]);
        expect(audit.conditions.map((entry) => entry.result)).toEqual([null, result, 'SUCCESS']);
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
  );

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

  it('runs the exact 35 modules serially with three mandatory reviewed captures', async () => {
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
      const log = /^\/api\/log\/([A-Za-z0-9]{15})$/u.exec(url.pathname);
      if (log) {
        expect(tests.has(log[1]!)).toBe(true);
        return jsonResponse([]);
      }
      throw new Error(`unexpected request ${url.pathname}`);
    };

    const terminal = await runWithRequiredScreenshots(runner, {
      readSecret,
      fetch: fetchImplementation,
    });

    expect(nextTest).toBe(35);
    expect(calls).toHaveLength(132);
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
    expect(calls.filter(({ url }) => url.pathname.startsWith('/api/log/'))).toHaveLength(32);
    expect(terminal).toEqual({
      schemaVersion: 1,
      kind: 'phase1-conformance-basic-terminal',
      suiteCommit: phase1ConformanceSuiteCommit,
      planId: planName,
      variant: basicVariant,
      status: 'FINISHED',
      acceptance: 'ACCEPTED',
      resultId: planInstanceId,
      result: {
        outcome: 'accepted',
        moduleCount: 35,
        passedModuleCount: 32,
        reviewedModuleCount: 3,
        modules: expectedManifest.map(({ testModule }, index) => ({
          testId: `T${String(index).padStart(14, '0')}`,
          testName: testModule,
          status: 'FINISHED',
          result: requiredScreenshotNames.includes(testModule) ? 'REVIEW' : 'PASSED',
          conditionLogSha256: requiredScreenshotNames.includes(testModule)
            ? (expect.stringMatching(/^[a-f0-9]{64}$/u) as unknown)
            : createHash('sha256').update('[]').digest('hex'),
          review: requiredScreenshotNames.includes(testModule)
            ? {
                placeholderId: `P${String(index).padStart(9, '0')}`,
                conditionId:
                  testModule === 'oidcc-ensure-registered-redirect-uri'
                    ? 'ExpectRedirectUriErrorPage'
                    : 'ExpectSecondLoginPage',
                imageSha256: createHash('sha256').update(testPng).digest('hex'),
                reviewRecordSha256: expect.stringMatching(/^[a-f0-9]{64}$/u) as unknown,
                reviewer: `sol-fixture-T${String(index).padStart(14, '0')}`,
                decision: 'APPROVE',
              }
            : null,
        })),
      },
    });
    expect(JSON.stringify(terminal)).not.toMatch(
      /user-secret-value|basic-one-secret|basic-two-secret|post-one-secret|suite_session=|https?:/iu
    );
  });

  it('submits an empty callback fragment before the first module finishes', async () => {
    const runner = await loadRunner();
    const requests: string[] = [];
    const tests = new Map<string, Readonly<{ name: string; variant: Record<string, string> }>>();
    let nextTest = 0;
    let firstFinished = false;
    let waits = 0;
    const declaredUrl = 'https://suite.example/browser/finish-on-callback';
    const firstId = 'B00000000000001';
    const fetchImplementation: typeof fetch = async (input, init) => {
      const url = new URL(String(input));
      const method = init?.method ?? 'GET';
      requests.push(`${method} ${url.pathname}`);
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
      if (url.pathname === '/api/runner' && method === 'POST') {
        const manifestEntry = expectedManifest[nextTest];
        if (!manifestEntry) {
          throw new Error('unexpected module');
        }
        const id = nextTest === 0 ? firstId : `T${String(nextTest).padStart(14, '0')}`;
        tests.set(id, { name: manifestEntry.testModule, variant: manifestEntry.variant });
        nextTest += 1;
        return jsonResponse({ name: manifestEntry.testModule, id }, 201);
      }
      if (url.pathname === `/api/runner/${firstId}/wait-state`) {
        waits += 1;
        if (waits > 2 && !firstFinished) {
          throw new Error('callback fragment not submitted');
        }
        return jsonResponse({ state: firstFinished ? 'FINISHED' : 'WAITING' });
      }
      if (url.pathname.endsWith('/wait-state')) {
        return jsonResponse({ state: 'FINISHED' });
      }
      if (url.pathname === `/api/runner/${firstId}` && method === 'GET') {
        return jsonResponse({
          name: 'oidcc-server',
          id: firstId,
          browser: {
            urls: [declaredUrl],
            urlsWithMethod: [{ url: declaredUrl, method: 'GET' }],
            browserApiRequests: [],
            uriInputRequests: [],
            uploadsRequired: 0,
          },
        });
      }
      if (url.pathname === `/api/runner/browser/${firstId}/visit` && method === 'POST') {
        expect(url.searchParams.get('url')).toBe(declaredUrl);
        return new Response(null, { status: 204 });
      }
      if (url.pathname === '/browser/finish-on-callback') {
        expect(method).toBe('GET');
        return new Response(null, {
          status: 302,
          headers: { location: 'https://suite.example/test/a/aster-phase1/callback?code=done' },
        });
      }
      if (url.pathname === '/test/a/aster-phase1/callback') {
        expect(firstFinished).toBe(false);
        return renderedImplicitCallback(
          'https://suite.example/test/a/aster-phase1/implicit/AbCdEfGhIjKlMnOpQrSt'
        );
      }
      if (url.pathname === '/test/a/aster-phase1/implicit/AbCdEfGhIjKlMnOpQrSt') {
        expect(method).toBe('POST');
        expect(new Headers(init?.headers).get('content-type')).toBe('text/plain');
        expect(init?.body).toBe('');
        firstFinished = true;
        return new Response(null, { status: 204 });
      }
      if (url.pathname.startsWith('/api/info/')) {
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
      if (url.pathname.startsWith('/api/log/')) {
        return jsonResponse([]);
      }
      if (url.pathname === `/api/runner/${firstId}` && method === 'DELETE') {
        return jsonResponse({ name: 'oidcc-server', id: firstId });
      }
      throw new Error(`unexpected request ${method} ${url.href}`);
    };

    const terminal = await runWithRequiredScreenshots(runner, {
      readSecret,
      fetch: fetchImplementation,
    });

    expect(requests.indexOf(`POST /api/runner/browser/${firstId}/visit`)).toBeLessThan(
      requests.indexOf('GET /test/a/aster-phase1/callback')
    );
    expect(requests.indexOf('GET /test/a/aster-phase1/callback')).toBeLessThan(
      requests.indexOf('POST /test/a/aster-phase1/implicit/AbCdEfGhIjKlMnOpQrSt')
    );
    expect(firstFinished).toBe(true);
    expect(nextTest).toBe(35);
    expect(terminal).toMatchObject({
      status: 'FINISHED',
      acceptance: 'ACCEPTED',
      result: { moduleCount: 35, passedModuleCount: 32, reviewedModuleCount: 3 },
    });
  });

  it('rejects a suite visit 404 before driving the declared browser URL', async () => {
    const runner = await loadRunner();
    const requests: string[] = [];
    const testId = 'B00000000000001';
    const declaredUrl = 'https://suite.example/browser/start-one';
    const fetchImplementation: typeof fetch = async (input, init) => {
      const url = new URL(String(input));
      const method = init?.method ?? 'GET';
      requests.push(`${method} ${url.pathname}`);
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
      if (url.pathname === '/api/runner' && method === 'POST') {
        return jsonResponse({ name: 'oidcc-server', id: testId }, 201);
      }
      if (url.pathname === `/api/runner/${testId}/wait-state`) {
        return jsonResponse({ state: 'WAITING' });
      }
      if (url.pathname === `/api/runner/${testId}` && method === 'GET') {
        return jsonResponse({
          name: 'oidcc-server',
          id: testId,
          browser: {
            urls: [declaredUrl],
            urlsWithMethod: [{ url: declaredUrl, method: 'GET' }],
            browserApiRequests: [],
            uriInputRequests: [],
            uploadsRequired: 0,
          },
        });
      }
      if (url.pathname === `/api/runner/browser/${testId}/visit` && method === 'POST') {
        return jsonResponse({ error: 'test is no longer running' }, 404);
      }
      if (url.pathname === `/api/runner/${testId}` && method === 'DELETE') {
        return jsonResponse({ name: 'oidcc-server', id: testId });
      }
      throw new Error(`unexpected request ${method} ${url.href}`);
    };

    await expect(
      runner.runOidfBasicPlan(JSON.stringify(validInput()), {
        readSecret,
        fetch: fetchImplementation,
      })
    ).rejects.toMatchObject({ category: 'suite-api', module: 'oidcc-server' });
    expect(requests).toContain(`POST /api/runner/browser/${testId}/visit`);
    expect(requests).toContain(`DELETE /api/runner/${testId}`);
    expect(requests).not.toContain('GET /browser/start-one');
  });

  it.each([
    [
      'missing submit URL',
      () => new Response('<html>complete</html>', { headers: { 'content-type': 'text/html' } }),
      204,
    ],
    [
      'submit marker outside script',
      () =>
        new Response(
          `<html><p>xhr.open('POST', "https://suite.example/test/a/aster-phase1/implicit/AbCdEfGhIjKlMnOpQrSt", true)</p></html>`,
          { headers: { 'content-type': 'text/html' } }
        ),
      204,
    ],
    [
      'wrong origin',
      () =>
        renderedImplicitCallback(
          'https://server.example/test/a/aster-phase1/implicit/AbCdEfGhIjKlMnOpQrSt'
        ),
      204,
    ],
    [
      'wrong alias',
      () =>
        renderedImplicitCallback(
          'https://suite.example/test/a/other/implicit/AbCdEfGhIjKlMnOpQrSt'
        ),
      204,
    ],
    [
      'wrong token length',
      () =>
        renderedImplicitCallback('https://suite.example/test/a/aster-phase1/implicit/too-short'),
      204,
    ],
    [
      'userinfo',
      () =>
        renderedImplicitCallback(
          'https://user@suite.example/test/a/aster-phase1/implicit/AbCdEfGhIjKlMnOpQrSt'
        ),
      204,
    ],
    [
      'unexpected query',
      () =>
        renderedImplicitCallback(
          'https://suite.example/test/a/aster-phase1/implicit/AbCdEfGhIjKlMnOpQrSt?extra=1'
        ),
      204,
    ],
    [
      'unexpected fragment',
      () =>
        renderedImplicitCallback(
          'https://suite.example/test/a/aster-phase1/implicit/AbCdEfGhIjKlMnOpQrSt#hash'
        ),
      204,
    ],
    [
      'duplicate submit URLs',
      () =>
        new Response(
          `<script>xhr.open('POST', "https://suite.example/test/a/aster-phase1/implicit/AbCdEfGhIjKlMnOpQrSt", true); xhr.open('POST', "https://suite.example/test/a/aster-phase1/implicit/0123456789abcdefghij", true);</script>`,
          { headers: { 'content-type': 'text/html' } }
        ),
      204,
    ],
    [
      'non-204 submit response',
      () =>
        renderedImplicitCallback(
          'https://suite.example/test/a/aster-phase1/implicit/AbCdEfGhIjKlMnOpQrSt'
        ),
      200,
    ],
  ] as const)(
    'rejects %s from the callback page without accepting the module',
    async (_reason, callbackPage, submissionStatus) => {
      const runner = await loadRunner();
      const requests: string[] = [];
      const testId = 'B00000000000001';
      const declaredUrl = 'https://suite.example/browser/start-one';
      const fetchImplementation: typeof fetch = async (input, init) => {
        const url = new URL(String(input));
        const method = init?.method ?? 'GET';
        requests.push(`${method} ${url.pathname}`);
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
        if (url.pathname === '/api/runner' && method === 'POST') {
          return jsonResponse({ name: 'oidcc-server', id: testId }, 201);
        }
        if (url.pathname === `/api/runner/${testId}/wait-state`) {
          return jsonResponse({ state: 'WAITING' });
        }
        if (url.pathname === `/api/runner/${testId}` && method === 'GET') {
          return jsonResponse({
            name: 'oidcc-server',
            id: testId,
            browser: {
              urls: [declaredUrl],
              urlsWithMethod: [{ url: declaredUrl, method: 'GET' }],
              browserApiRequests: [],
              uriInputRequests: [],
              uploadsRequired: 0,
            },
          });
        }
        if (url.pathname === `/api/runner/browser/${testId}/visit` && method === 'POST') {
          return new Response(null, { status: 204 });
        }
        if (url.pathname === '/browser/start-one') {
          return new Response(null, {
            status: 302,
            headers: { location: 'https://suite.example/test/a/aster-phase1/callback?code=done' },
          });
        }
        if (url.pathname === '/test/a/aster-phase1/callback') {
          return callbackPage();
        }
        if (url.pathname === '/test/a/aster-phase1/implicit/AbCdEfGhIjKlMnOpQrSt') {
          return new Response(null, { status: submissionStatus });
        }
        if (url.pathname === `/api/runner/${testId}` && method === 'DELETE') {
          return jsonResponse({ name: 'oidcc-server', id: testId });
        }
        throw new Error(`unexpected request ${method} ${url.href}`);
      };

      await expect(
        runner.runOidfBasicPlan(JSON.stringify(validInput()), {
          readSecret,
          fetch: fetchImplementation,
        })
      ).rejects.toMatchObject({ category: 'browser-flow', module: 'oidcc-server' });
      expect(requests).toContain('GET /test/a/aster-phase1/callback');
      expect(requests).toContain(`DELETE /api/runner/${testId}`);
      expect(
        requests.filter((request) => request.startsWith('POST /test/a/aster-phase1/implicit/'))
      ).toHaveLength(submissionStatus === 200 ? 1 : 0);
    }
  );

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
            uploadsRequired: 0,
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
      if (url.origin === suiteBaseUrl && url.pathname.startsWith('/api/log/')) {
        return jsonResponse([]);
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
        expect(visited.has('https://suite.example/browser/start-one')).toBe(true);
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
        return renderedImplicitCallback(
          'https://suite.example/test/a/aster-phase1/implicit/AbCdEfGhIjKlMnOpQrSt'
        );
      }
      if (url.pathname === '/test/a/aster-phase1/implicit/AbCdEfGhIjKlMnOpQrSt') {
        expect(method).toBe('POST');
        expect(headers.get('content-type')).toBe('text/plain');
        expect(headers.get('cookie')).toContain('suite_session=alpha');
        expect(init?.body).toBe('');
        virtualNow = 2000;
        return new Response(null, { status: 204 });
      }
      if (url.origin === suiteBaseUrl && url.pathname === '/browser/start-two') {
        expect(visited.has('https://suite.example/browser/start-two?phase=2')).toBe(true);
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
          'https://suite.example/test/a/aster-phase1/callback?error=login_required&state=state-two#fragment=value',
          303
        );
      }
      if (
        url.origin === suiteBaseUrl &&
        url.pathname === '/test/a/aster-phase1/callback' &&
        url.searchParams.get('state') === 'state-two'
      ) {
        expect(url.hash).toBe('');
        expect(headers.get('cookie')).toContain('suite_session=alpha');
        return renderedImplicitCallback(
          'https://suite.example/test/a/aster-phase1/implicit/0123456789abcdefghij'
        );
      }
      if (url.pathname === '/test/a/aster-phase1/implicit/0123456789abcdefghij') {
        expect(method).toBe('POST');
        expect(headers.get('content-type')).toBe('text/plain');
        expect(init?.body).toBe('#fragment=value');
        return new Response(null, { status: 204 });
      }
      if (url.origin === suiteBaseUrl && url.pathname === '/browser/start-three') {
        expect(visited.has('https://suite.example/browser/start-three')).toBe(true);
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

    const terminal = await runWithRequiredScreenshots(runner, {
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
    expect(navigation.filter((entry) => entry.includes('/api/log/'))).toHaveLength(32);
    expect(visited).toEqual(
      new Set([
        'https://suite.example/browser/start-one',
        'https://suite.example/browser/start-two?phase=2',
        'https://suite.example/browser/start-three',
      ])
    );
    expect(terminal).toMatchObject({
      status: 'FINISHED',
      acceptance: 'ACCEPTED',
      result: { moduleCount: 35, passedModuleCount: 32, reviewedModuleCount: 3 },
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
