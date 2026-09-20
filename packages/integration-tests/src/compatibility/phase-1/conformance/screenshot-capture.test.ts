/* eslint-disable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, max-lines, max-params, no-await-in-loop, no-promise-executor-return -- This isolated process fixture creates private PKI and IPC trees and exercises adversarial HTTPS responses before recording child-process output. */
import { execFile, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { createServer } from 'node:https';
import { createRequire } from 'node:module';
import path from 'node:path';
import { promisify } from 'node:util';

const executeFile = promisify(execFile);
const repositoryRoot = path.resolve(process.cwd(), '../..');
const helperPath = path.join(
  repositoryRoot,
  '.scripts/compatibility/phase1-screenshot-capture.mjs'
);
const playwrightModule = createRequire(import.meta.url).resolve('@playwright/test');
const browserRoot = '/var/tmp/henry-build/aster-playwright-browsers';
const issuerHost = 'aster-server.aster-phase1-conformance.svc.cluster.local';
const suiteCommit = '0dc0e3a21ec411e92c808e5b2e2258592c22b594';
const planName = 'oidcc-basic-certification-test-plan';
const pngSignature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

type CaptureKind = 'second-sign-in' | 'ui-error';

type Binding = Readonly<{
  schemaVersion: 1;
  suiteCommit: string;
  planName: string;
  planInstanceId: string;
  moduleName: string;
  testId: string;
  placeholderId: string;
  conditionId: string;
  captureId: string;
  captureKind: CaptureKind;
  createdAt: number;
  deadline: number;
}>;

type Cookie = Readonly<{
  name: string;
  value: string;
  domain: string;
  path: string;
  expires: number;
  httpOnly: boolean;
  secure: boolean;
  sameSite: 'Strict' | 'Lax' | 'None';
}>;

const waitForFile = async (file: string, deadline: number): Promise<void> => {
  for (;;) {
    try {
      await stat(file);
      return;
    } catch (error: unknown) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT' || Date.now() >= deadline) {
        throw error;
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
};

const createPki = async (
  root: string
): Promise<Readonly<{ ca: string; cert: string; key: string }>> => {
  const ca = path.join(root, 'root-ca.crt');
  const caKey = path.join(root, 'root-ca.key');
  const cert = path.join(root, 'issuer.crt');
  const key = path.join(root, 'issuer.key');
  const request = path.join(root, 'issuer.csr');
  const extension = path.join(root, 'issuer.ext');

  await executeFile('/usr/bin/openssl', [
    'req',
    '-x509',
    '-newkey',
    'rsa:2048',
    '-nodes',
    '-sha256',
    '-days',
    '1',
    '-subj',
    '/CN=Aster screenshot test root',
    '-keyout',
    caKey,
    '-out',
    ca,
  ]);
  await executeFile('/usr/bin/openssl', [
    'req',
    '-newkey',
    'rsa:2048',
    '-nodes',
    '-sha256',
    '-subj',
    `/CN=${issuerHost}`,
    '-keyout',
    key,
    '-out',
    request,
  ]);
  await writeFile(
    extension,
    [
      `subjectAltName=DNS:${issuerHost}`,
      'basicConstraints=critical,CA:FALSE',
      'keyUsage=critical,digitalSignature,keyEncipherment',
      'extendedKeyUsage=serverAuth',
      '',
    ].join('\n'),
    { mode: 0o600 }
  );
  await executeFile('/usr/bin/openssl', [
    'x509',
    '-req',
    '-sha256',
    '-days',
    '1',
    '-in',
    request,
    '-CA',
    ca,
    '-CAkey',
    caKey,
    '-CAcreateserial',
    '-extfile',
    extension,
    '-out',
    cert,
  ]);
  await Promise.all([chmod(ca, 0o444), chmod(cert, 0o444), chmod(key, 0o600)]);

  return Object.freeze({ ca, cert, key });
};

const binding = (
  captureKind: CaptureKind,
  conditionId: string,
  testId: string,
  placeholderId: string,
  captureId: string,
  deadline: number
): Binding =>
  Object.freeze({
    schemaVersion: 1,
    suiteCommit,
    planName,
    planInstanceId: 'BasicPlan0001',
    moduleName:
      captureKind === 'second-sign-in'
        ? 'oidcc-prompt-login'
        : 'oidcc-ensure-registered-redirect-uri',
    testId,
    placeholderId,
    conditionId,
    captureId,
    captureKind,
    createdAt: Date.now(),
    deadline,
  });

const writeRequest = async (
  root: string,
  value: Binding,
  issuerOrigin: string,
  pathname: string,
  cookies: readonly Cookie[]
): Promise<string> => {
  const directory = path.join(root, value.planInstanceId, value.testId, value.placeholderId);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  for (const current of [
    path.join(root, value.planInstanceId),
    path.join(root, value.planInstanceId, value.testId),
    directory,
  ]) {
    await chmod(current, 0o700);
  }
  await writeFile(
    path.join(directory, 'capture-request.json'),
    JSON.stringify({ ...value, url: `${issuerOrigin}${pathname}`, issuerOrigin, cookies }),
    { flag: 'wx', mode: 0o600 }
  );

  return directory;
};

describe('phase 1 screenshot capture helper', () => {
  it.each(['blank', 'prefilled'] as const)(
    'captures only blank credentials before sign-in (%s identifier)',
    async (identifierState) => {
      const root = await mkdtemp('/var/tmp/henry-build/aster-screenshot-capture-test.');
      await chmod(root, 0o700);
      const ipcRoot = path.join(root, 'ipc');
      const pkiRoot = path.join(root, 'pki');
      await Promise.all([mkdir(ipcRoot, { mode: 0o700 }), mkdir(pkiRoot, { mode: 0o700 })]);
      const pki = await createPki(pkiRoot);
      const requests: string[] = [];
      const server = createServer(
        { cert: await readFile(pki.cert), key: await readFile(pki.key) },
        (request, response) => {
          requests.push(`${request.method ?? ''} ${request.url ?? ''}`);
          if (request.url === '/asset.css') {
            response.writeHead(200, { 'content-type': 'text/css' });
            response.end('body{font-family:sans-serif}');
            return;
          }
          const cookie = request.headers.cookie ?? '';
          if (!cookie.includes('_interaction=private-cookie-value')) {
            response.writeHead(403, { 'content-type': 'text/plain' });
            response.end('missing session');
            return;
          }
          response.setHeader(
            'set-cookie',
            'updated=session-value; Path=/; HttpOnly; Secure; SameSite=Strict'
          );
          response.setHeader('content-type', 'text/html; charset=utf-8');
          if (request.url?.startsWith('/sign-in')) {
            const identifierValue =
              identifierState === 'prefilled' ? 'private-identifier-sentinel' : '';
            response.end(
              `<!doctype html><html><head><link rel="stylesheet" href="/asset.css"><script>window.asterSsr={surface:'experience'}</script></head><body><main><h1>Sign in</h1><form><label>Username<input name="identifier" type="text" autocomplete="username" value="${identifierValue}"></label><label>Password<input name="password" type="password" autocomplete="current-password"></label><button type="submit">Sign in</button></form></main></body></html>`
            );
            return;
          }
          response.end(
            `<!doctype html><html><head><link rel="stylesheet" href="/asset.css"><script>window.asterSsr={surface:'experience'}</script></head><body><main><h1>Request is invalid</h1><p>redirect_uri did not match any registered redirect URI.</p></main></body></html>`
          );
        }
      );
      await new Promise<void>((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', resolve);
      });
      const address = server.address();
      if (!address || typeof address === 'string') {
        throw new Error('missing HTTPS fixture address');
      }
      const issuerOrigin = `https://${issuerHost}:${address.port}`;
      const helperDeadline = Date.now() + 90_000;
      const child = spawn(
        process.execPath,
        [
          helperPath,
          '--issuer-origin',
          issuerOrigin,
          '--root-ca-file',
          pki.ca,
          '--certificate-file',
          pki.cert,
          '--playwright-module',
          playwrightModule,
          '--deadline',
          String(helperDeadline),
        ],
        {
          cwd: repositoryRoot,
          env: {
            HOME: root,
            PATH: '/usr/bin:/bin',
            PLAYWRIGHT_BROWSERS_PATH: browserRoot,
            ASTER_PHASE1_SCREENSHOT_IPC_ROOT: ipcRoot,
          },
          stdio: ['ignore', 'pipe', 'pipe'],
        }
      );
      const childExit = new Promise<
        Readonly<{ code: number | undefined; signal: NodeJS.Signals | undefined }>
      >((resolve) => {
        child.once('exit', (code, signal) => {
          resolve(Object.freeze({ code: code ?? undefined, signal: signal ?? undefined }));
        });
      });
      const killTimer = setTimeout(() => child.kill('SIGKILL'), 75_000);
      let stdout = '';
      let stderr = '';
      child.stdout.setEncoding('utf8');
      child.stderr.setEncoding('utf8');
      child.stdout.on('data', (value: string) => {
        stdout += value;
      });
      child.stderr.on('data', (value: string) => {
        stderr += value;
      });
      const cookies = Object.freeze([
        Object.freeze({
          name: '_interaction',
          value: 'private-cookie-value',
          domain: issuerHost,
          path: '/',
          expires: -1,
          httpOnly: true,
          secure: true,
          sameSite: 'Lax' as const,
        }),
        Object.freeze({
          name: '_oidc',
          value: 'path-scoped-oidc-cookie',
          domain: issuerHost,
          path: '/oidc',
          expires: -1,
          httpOnly: true,
          secure: true,
          sameSite: 'Lax' as const,
        }),
        Object.freeze({
          name: '_interaction_resume',
          value: 'path-scoped-resume-cookie',
          domain: issuerHost,
          path: '/oidc/auth/syntheticUID',
          expires: -1,
          httpOnly: true,
          secure: true,
          sameSite: 'Strict' as const,
        }),
      ]);

      try {
        const first = binding(
          'second-sign-in',
          'ExpectSecondLoginPage',
          'PromptLogin0001',
          'Prompt0001',
          '1'.repeat(32),
          Date.now() + 60_000
        );
        const firstDirectory = await writeRequest(
          ipcRoot,
          first,
          issuerOrigin,
          '/sign-in?app_id=oidf-basic-1',
          cookies
        );
        const firstResponseFile = path.join(firstDirectory, 'capture-response.json');
        if (identifierState === 'prefilled') {
          expect(await childExit).toEqual({ code: 1, signal: undefined });
          expect(requests).toContain('GET /sign-in?app_id=oidf-basic-1');
          expect(await readdir(firstDirectory)).toEqual(['capture-request.json']);
          expect(stderr).toBe(
            `phase 1 screenshot capture ready: ${ipcRoot}\nphase 1 screenshot capture failed\n`
          );
          return;
        }
        await waitForFile(firstResponseFile, first.deadline);
        const firstResponse = JSON.parse(await readFile(firstResponseFile, 'utf8')) as Record<
          string,
          unknown
        >;
        const firstImage = await readFile(path.join(firstDirectory, 'capture.png'));

        expect(Object.keys(firstResponse)).toEqual([
          'schemaVersion',
          'suiteCommit',
          'planName',
          'planInstanceId',
          'moduleName',
          'testId',
          'placeholderId',
          'conditionId',
          'captureId',
          'captureKind',
          'createdAt',
          'deadline',
          'result',
          'renderedUrl',
          'imageFile',
          'imageSha256',
          'imageBytes',
          'observedCondition',
          'cookies',
        ]);
        expect(firstResponse).toMatchObject({
          ...first,
          result: 'CAPTURED',
          renderedUrl: `${issuerOrigin}/sign-in?app_id=oidf-basic-1`,
          imageFile: 'capture.png',
          imageBytes: firstImage.byteLength,
          observedCondition: true,
        });
        expect(firstImage.subarray(0, 8)).toEqual(pngSignature);
        expect(firstImage.byteLength).toBeLessThanOrEqual(512_000);
        expect(firstResponse.imageSha256).toBe(
          createHash('sha256').update(firstImage).digest('hex')
        );
        expect(firstResponse.cookies).toEqual(
          expect.arrayContaining([
            ...cookies,
            {
              name: 'updated',
              value: 'session-value',
              domain: issuerHost,
              path: '/',
              expires: -1,
              httpOnly: true,
              secure: true,
              sameSite: 'Strict',
            },
          ])
        );
        await writeFile(
          path.join(path.dirname(firstDirectory), 'module-audit.json'),
          `{}${' '.repeat(131_071)}`,
          {
            mode: 0o600,
          }
        );
        await new Promise((resolve) => setTimeout(resolve, 300));

        const second = binding(
          'ui-error',
          'ExpectRedirectUriErrorPage',
          'RedirectError01',
          'Redirect01',
          '2'.repeat(32),
          Date.now() + 60_000
        );
        const secondDirectory = await writeRequest(
          ipcRoot,
          { ...second, moduleName: 'oidcc-ensure-request-object-with-redirect-uri' },
          issuerOrigin,
          '/authorization-error',
          cookies
        );
        const secondResponseFile = path.join(secondDirectory, 'capture-response.json');
        await waitForFile(secondResponseFile, second.deadline);
        const secondResponse = JSON.parse(await readFile(secondResponseFile, 'utf8')) as Record<
          string,
          unknown
        >;
        const secondImage = await readFile(path.join(secondDirectory, 'capture.png'));

        expect(secondResponse).toMatchObject({
          ...second,
          moduleName: 'oidcc-ensure-request-object-with-redirect-uri',
          result: 'CAPTURED',
          renderedUrl: `${issuerOrigin}/authorization-error`,
          imageFile: 'capture.png',
          imageBytes: secondImage.byteLength,
          observedCondition: true,
        });
        expect(secondResponse.imageSha256).not.toBe(firstResponse.imageSha256);
        expect(requests).toEqual(
          expect.arrayContaining([
            'GET /sign-in?app_id=oidf-basic-1',
            'GET /authorization-error',
            'GET /asset.css',
          ])
        );
      } finally {
        if (child.exitCode === null && child.signalCode === null) {
          child.kill('SIGTERM');
        }
        const exit = await childExit;
        clearTimeout(killTimer);
        await new Promise<void>((resolve) =>
          server.close(() => {
            resolve();
          })
        );
        await rm(root, { recursive: true, force: true });
        expect(exit).toEqual({ code: identifierState === 'prefilled' ? 1 : 0, signal: undefined });
        expect(stdout).toBe('');
        expect(stderr).toContain(`phase 1 screenshot capture ready: ${ipcRoot}\n`);
        expect(stderr).not.toMatch(
          /private-cookie-value|session-value|authorization-error|private-identifier-sentinel/iu
        );
      }
    },
    120_000
  );

  it.each([
    'valid',
    'request-object',
    'same-origin-redirect',
    'registered-callback',
    'unregistered-callback',
    'wrong-status',
    'wrong-type',
    'wrong-code',
    'wrong-issuer',
    'missing-field',
    'extra-field',
    'duplicate-field',
    'location-header',
    'refresh-header',
    'set-cookie-header',
    'wrong-module',
    'wrong-condition',
    'wrong-kind',
    'resume-path',
  ] as const)(
    'allows only the first verified redirect-error document: %s',
    async (scenario) => {
      const root = await mkdtemp('/var/tmp/henry-build/aster-screenshot-capture-test.');
      const ipcRoot = path.join(root, 'ipc');
      await mkdir(ipcRoot, { mode: 0o700 });
      const pki = await createPki(root);
      const tlsOptions = { cert: await readFile(pki.cert), key: await readFile(pki.key) };
      const callbacks: string[] = [];
      const authorizations: Array<
        Readonly<{
          method: string | undefined;
          url: string | undefined;
          cookie: string | undefined;
        }>
      > = [];
      const callbackServer = createServer(tlsOptions, (request, response) => {
        callbacks.push(request.url ?? '');
        response.end('unexpected callback');
      });
      await new Promise<void>((resolve) => callbackServer.listen(0, '127.0.0.1', resolve));
      const callbackAddress = callbackServer.address();
      if (!callbackAddress || typeof callbackAddress === 'string') {
        throw new Error('fixture address');
      }
      const callbackOrigin = `https://${issuerHost}:${callbackAddress.port}`;
      let issuerOrigin = '';
      const server = createServer(tlsOptions, (request, response) => {
        if (!request.url?.startsWith('/oidc/auth?')) {
          callbacks.push(request.url ?? '');
          response.end('unexpected navigation');
          return;
        }
        authorizations.push({
          method: request.method,
          url: request.url,
          cookie: request.headers.cookie,
        });
        const value: Record<string, string> = {
          code: 'oidc.invalid_redirect_uri',
          message: "`redirect_uri` did not match any of the client's registered `redirect_uris`.",
          error: 'invalid_redirect_uri',
          error_description:
            "redirect_uri did not match any of the client's registered redirect_uris",
          iss: `${issuerOrigin}/oidc`,
        };
        if (
          scenario === 'same-origin-redirect' ||
          scenario === 'registered-callback' ||
          scenario === 'unregistered-callback'
        ) {
          const location =
            scenario === 'same-origin-redirect'
              ? `${issuerOrigin}/unexpected`
              : `${callbackOrigin}/test/a/aster-phase1/callback${scenario === 'unregistered-callback' ? '/Unregistered' : ''}`;
          response.writeHead(scenario === 'same-origin-redirect' ? 307 : 302, { location });
          response.end();
          return;
        }
        if (scenario === 'wrong-code') {
          value.error = 'invalid_request';
        }
        if (scenario === 'wrong-issuer') {
          value.iss = `${callbackOrigin}/oidc`;
        }
        if (scenario === 'missing-field') {
          Reflect.deleteProperty(value, 'message');
        }
        if (scenario === 'extra-field') {
          value.code_value = 'private-field-sentinel';
        }
        if (scenario === 'location-header') {
          response.setHeader('location', `${callbackOrigin}/callback`);
        }
        if (scenario === 'refresh-header') {
          response.setHeader('refresh', `0;url=${callbackOrigin}/callback`);
        }
        if (scenario === 'set-cookie-header') {
          response.setHeader('set-cookie', 'unexpected=private-cookie-sentinel; Secure');
        }
        response.writeHead(scenario === 'wrong-status' ? 200 : 400, {
          'content-type':
            scenario === 'wrong-type'
              ? 'text/html; charset=utf-8'
              : 'application/json; charset=utf-8',
        });
        const body = JSON.stringify(value);
        response.end(
          scenario === 'duplicate-field'
            ? body.replace('{', '{"code":"private-field-sentinel",')
            : body
        );
      });
      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
      const address = server.address();
      if (!address || typeof address === 'string') {
        throw new Error('fixture address');
      }
      issuerOrigin = `https://${issuerHost}:${address.port}`;
      const currentBinding = binding(
        'ui-error',
        'ExpectRedirectUriErrorPage',
        'RedirectError01',
        'Redirect01',
        '3'.repeat(32),
        Date.now() + 15_000
      );
      const requestBinding = {
        ...currentBinding,
        moduleName:
          scenario === 'wrong-module'
            ? 'oidcc-response-type-missing'
            : scenario === 'request-object'
              ? 'oidcc-ensure-request-object-with-redirect-uri'
              : currentBinding.moduleName,
        conditionId:
          scenario === 'wrong-condition'
            ? 'ExpectResponseTypeMissingErrorPage'
            : currentBinding.conditionId,
        captureKind:
          scenario === 'wrong-kind' ? ('second-sign-in' as const) : currentBinding.captureKind,
      };
      const pathname = `${scenario === 'resume-path' ? '/oidc/auth/syntheticUID' : '/oidc/auth'}?client_id=fixture&redirect_uri=${encodeURIComponent(`${callbackOrigin}/callback/Unregistered`)}&state=fixture%2Bstate`;
      const cookie: Cookie = {
        name: '_aster',
        value: 'path-cookie-sentinel',
        domain: issuerHost,
        path: '/oidc',
        expires: -1,
        httpOnly: true,
        secure: true,
        sameSite: 'Lax',
      };
      const directory = await writeRequest(ipcRoot, requestBinding, issuerOrigin, pathname, [
        cookie,
      ]);
      const child = spawn(
        process.execPath,
        [
          helperPath,
          '--issuer-origin',
          issuerOrigin,
          '--root-ca-file',
          pki.ca,
          '--certificate-file',
          pki.cert,
          '--playwright-module',
          playwrightModule,
          '--deadline',
          String(Date.now() + 30_000),
        ],
        {
          cwd: repositoryRoot,
          env: {
            PATH: '/usr/bin:/bin',
            HOME: root,
            PLAYWRIGHT_BROWSERS_PATH: browserRoot,
            ASTER_PHASE1_SCREENSHOT_IPC_ROOT: ipcRoot,
          },
          stdio: ['ignore', 'pipe', 'pipe'],
        }
      );
      const exit = new Promise<number | undefined>((resolve) =>
        child.once('exit', (code) => {
          resolve(code ?? undefined);
        })
      );
      const killTimer = setTimeout(() => child.kill('SIGKILL'), 25_000);
      let stdout = '';
      let stderr = '';
      child.stdout.setEncoding('utf8');
      child.stderr.setEncoding('utf8');
      child.stdout.on('data', (data: string) => {
        stdout += data;
      });
      child.stderr.on('data', (data: string) => {
        stderr += data;
      });
      try {
        if (scenario === 'valid' || scenario === 'request-object') {
          await waitForFile(path.join(directory, 'capture-response.json'), currentBinding.deadline);
          const result = JSON.parse(
            await readFile(path.join(directory, 'capture-response.json'), 'utf8')
          ) as Record<string, unknown>;
          const png = await readFile(path.join(directory, 'capture.png'));
          expect(result).toMatchObject({
            ...currentBinding,
            moduleName: requestBinding.moduleName,
            observedCondition: true,
            renderedUrl: `${issuerOrigin}${pathname}`,
            cookies: [cookie],
            result: 'CAPTURED',
          });
          expect(png.subarray(0, 8)).toEqual(pngSignature);
          expect(png.length).toBeLessThanOrEqual(512_000);
          expect(result.imageSha256).toBe(createHash('sha256').update(png).digest('hex'));
          child.kill('SIGTERM');
          expect(await exit).toBe(0);
        } else {
          expect(await exit).toBe(1);
          expect(await readdir(directory)).toEqual(['capture-request.json']);
        }
        expect(stderr).toContain(`phase 1 screenshot capture ready: ${ipcRoot}\n`);
        const rejectedBeforeNavigation = [
          'wrong-module',
          'wrong-condition',
          'wrong-kind',
          'resume-path',
        ].includes(scenario);
        expect(authorizations).toEqual(
          rejectedBeforeNavigation
            ? []
            : [{ method: 'GET', url: pathname, cookie: '_aster=path-cookie-sentinel' }]
        );
        expect(callbacks).toEqual([]);
        expect(stdout).toBe('');
        expect(stderr).not.toMatch(
          /path-cookie-sentinel|private-field-sentinel|private-cookie-sentinel|fixture%2Bstate/u
        );
      } finally {
        if (child.exitCode === null && child.signalCode === null) {
          child.kill('SIGTERM');
        }
        await exit;
        clearTimeout(killTimer);
        server.closeAllConnections();
        callbackServer.closeAllConnections();
        await Promise.all([
          new Promise<void>((resolve) =>
            server.close(() => {
              resolve();
            })
          ),
          new Promise<void>((resolve) =>
            callbackServer.close(() => {
              resolve();
            })
          ),
        ]);
        await rm(root, { recursive: true, force: true });
      }
    },
    40_000
  );
});

/* eslint-enable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, max-lines, max-params, no-await-in-loop, no-promise-executor-return */
