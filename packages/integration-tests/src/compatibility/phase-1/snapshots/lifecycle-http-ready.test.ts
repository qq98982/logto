import { execFile } from 'node:child_process';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer, type Server } from 'node:http';
import path from 'node:path';
import { promisify } from 'node:util';

const repositoryRoot = path.resolve(process.cwd(), '../..');
const runnerPath = path.join(repositoryRoot, '.scripts/compatibility/run-phase1.sh');
const executeFile = promisify(execFile);
const temporaryRoots = new Set<string>();
const maximumResponseChars = 65_536;

afterEach(async () => {
  await Promise.all(
    [...temporaryRoots].map(async (root) => rm(root, { recursive: true, force: true }))
  );
  temporaryRoots.clear();
});

const listen = async (server: Server): Promise<number> => {
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();

  if (typeof address !== 'object' || address === null) {
    throw new TypeError('HTTP readiness fixture failed to bind');
  }

  return address.port;
};

const close = async (server: Server): Promise<void> =>
  new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });

const writeHarness = async (root: string, deadlineSeconds = 2): Promise<string> => {
  const source = await readFile(runnerPath, 'utf8');
  const start = source.indexOf('http_ready()');
  const end = source.indexOf('\n\nfor core_port', start);

  expect(start).toBeGreaterThan(0);
  expect(end).toBeGreaterThan(start);
  const scriptPath = path.join(root, 'verify-http-ready.sh');
  const functions = source.slice(start, end);
  const harness = `#!/usr/bin/env bash
set -euo pipefail
HTTP_READY_DEADLINE_SECONDS=${deadlineSeconds}
HTTP_READY_MAX_RESPONSE_CHARS=${maximumResponseChars}
HTTP_READY_READ_CHARS=4096
${functions}
http_ready "$1" "$2" 'issuer'
`;
  await writeFile(scriptPath, harness, { mode: 0o700 });
  await chmod(scriptPath, 0o700);

  return scriptPath;
};

describe('Phase 1 lifecycle HTTP readiness boundary', () => {
  it('recognizes compact JSON only through the exact localhost port', async () => {
    const root = await mkdtemp('/var/tmp/henry-build/phase1-http-ready-test-');
    temporaryRoots.add(root);
    const scriptPath = await writeHarness(root);
    const server = createServer((request, response) => {
      const address = server.address();
      const correctHost =
        typeof address === 'object' &&
        address !== null &&
        request.headers.host === `localhost:${address.port}`;
      const body = correctHost ? '{"issuer":"http://localhost"}' : '{}';

      response.writeHead(correctHost ? 200 : 404, {
        Connection: 'close',
        'Content-Length': Buffer.byteLength(body),
        'Content-Type': 'application/json',
      });
      response.end(body);
    });
    const port = await listen(server);

    try {
      await expect(
        executeFile('/bin/bash', [scriptPath, String(port), '/ready'], { timeout: 10_000 })
      ).resolves.toMatchObject({ stderr: '' });
    } finally {
      await close(server);
    }
  });

  it('retries one incomplete response within the total deadline', async () => {
    const root = await mkdtemp('/var/tmp/henry-build/phase1-http-ready-retry-test-');
    temporaryRoots.add(root);
    const scriptPath = await writeHarness(root, 4);
    // eslint-disable-next-line @silverhand/fp/no-let -- The socket fixture counts retry attempts.
    let requestCount = 0;
    const server = createServer((_request, response) => {
      // eslint-disable-next-line @silverhand/fp/no-mutation -- Each accepted fixture request advances the bounded retry state.
      requestCount += 1;
      response.writeHead(200, {
        Connection: 'close',
        'Content-Type': 'application/json',
      });
      response.write('{"issuer":"http://localhost"}');
      if (requestCount > 1) {
        response.end();
      }
    });
    const port = await listen(server);

    try {
      await expect(
        executeFile('/bin/bash', [scriptPath, String(port), '/retry'], { timeout: 5000 })
      ).resolves.toMatchObject({ stderr: '' });
      expect(requestCount).toBe(2);
    } finally {
      await close(server);
    }
  });

  it('rejects incomplete oversized and misleading non-200 responses', async () => {
    const root = await mkdtemp('/var/tmp/henry-build/phase1-http-ready-bound-test-');
    temporaryRoots.add(root);
    const scriptPath = await writeHarness(root);
    const server = createServer((request, response) => {
      if (request.url === '/slow') {
        response.writeHead(200, { 'Content-Type': 'application/json' });
        response.write('{"issuer":"http://localhost"}\n');
        return;
      }
      if (request.url === '/misleading') {
        const body = '{"issuer":"contains 200 but is unavailable"}';

        response.writeHead(503, {
          Connection: 'close',
          'Content-Length': Buffer.byteLength(body),
          'Content-Type': 'application/json',
        });
        response.end(body);
        return;
      }
      const body = `{"issuer":"${'x'.repeat(maximumResponseChars)}"}`;

      response.writeHead(200, {
        Connection: 'close',
        'Content-Length': Buffer.byteLength(body),
        'Content-Type': 'application/json',
      });
      response.end(body);
    });
    const port = await listen(server);

    try {
      await expect(
        executeFile('/bin/bash', [scriptPath, String(port), '/slow'], { timeout: 5000 })
      ).rejects.toMatchObject({ code: 1, killed: false, signal: null });
      await expect(
        executeFile('/bin/bash', [scriptPath, String(port), '/large'], { timeout: 5000 })
      ).rejects.toMatchObject({ code: 1, killed: false, signal: null });
      await expect(
        executeFile('/bin/bash', [scriptPath, String(port), '/misleading'], { timeout: 5000 })
      ).rejects.toMatchObject({ code: 1, killed: false, signal: null });
    } finally {
      await close(server);
    }
  });
});
