/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The isolated TLS fixture owns one optional server handle so finally can close it after failures. */
import { execFileSync } from 'node:child_process';
import { access, chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import https from 'node:https';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const buildRoot = '/var/tmp/henry-build';
const repositoryRoot = path.resolve(process.cwd(), '../..');
const observerPath = path.join(repositoryRoot, '.scripts/compatibility/phase2-fetch-observer.mjs');

const request = async (
  port: number,
  ca: string,
  pathname: string,
  options: Readonly<{ method?: string; headers?: Record<string, string>; body?: string }> = {}
) =>
  new Promise<Readonly<{ status: number; body: string; location?: string }>>((resolve, reject) => {
    const call = https.request(
      {
        host: '127.0.0.1',
        port,
        path: pathname,
        method: options.method ?? 'GET',
        headers: { host: 'fetch-observer.aster.test:8443', ...options.headers },
        ca,
        servername: 'fetch-observer.aster.test',
      },
      (response) => {
        const chunks: Uint8Array[] = [];
        response.on('data', (chunk: Uint8Array) => chunks.push(chunk));
        response.on('end', () => {
          resolve({
            status: response.statusCode ?? 0,
            body: Buffer.concat(chunks).toString('utf8'),
            ...(response.headers.location ? { location: response.headers.location } : {}),
          });
        });
      }
    );
    call.once('error', reject);
    call.end(options.body);
  });

test('bounded HTTPS observer serves fixed routes and writes only sanitized ordered receipts', async () => {
  const root = await mkdtemp(path.join(buildRoot, 'aster-fetch-observer-test-'));
  let observer: { address: { port: number }; close(): Promise<void> } | undefined;
  try {
    await chmod(root, 0o700);
    const key = path.join(root, 'key.pem');
    const cert = path.join(root, 'cert.pem');
    const receipts = path.join(root, 'receipts.ndjson');
    await writeFile(receipts, '', { mode: 0o600 });
    execFileSync(
      '/usr/bin/openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-days',
        '1',
        '-subj',
        '/CN=fetch-observer.aster.test',
        '-addext',
        'subjectAltName=DNS:fetch-observer.aster.test',
        '-keyout',
        key,
        '-out',
        cert,
      ],
      { stdio: 'ignore' }
    );
    await chmod(key, 0o600);
    const { startFetchObserver } = (await import(pathToFileURL(observerPath).href)) as {
      startFetchObserver(input: Record<string, unknown>): Promise<{
        address: { port: number };
        close(): Promise<void>;
      }>;
    };
    await chmod(receipts, 0o640);
    await expect(
      startFetchObserver({
        address: '127.0.0.1',
        port: 0,
        certificateFile: cert,
        privateKeyFile: key,
        receiptFile: receipts,
      })
    ).rejects.toThrow('observer receipt file invalid');
    await chmod(receipts, 0o600);
    await writeFile(receipts, 'occupied\n');
    await expect(
      startFetchObserver({
        address: '127.0.0.1',
        port: 0,
        certificateFile: cert,
        privateKeyFile: key,
        receiptFile: receipts,
      })
    ).rejects.toThrow('observer receipt file not empty');
    await writeFile(receipts, '');
    observer = await startFetchObserver({
      address: '127.0.0.1',
      port: 0,
      certificateFile: cert,
      privateKeyFile: key,
      receiptFile: receipts,
    });
    const observerPort = observer.address.port;
    const ca = await readFile(cert, 'utf8');
    expect(await request(observerPort, ca, '/text')).toEqual({
      status: 200,
      body: 'bounded-text',
    });
    expect(
      await request(observerPort, ca, '/post', {
        method: 'POST',
        headers: { 'x-aster-probe': 'bounded-header' },
        body: 'bounded-body',
      })
    ).toMatchObject({ status: 201 });
    expect(await request(observerPort, ca, '/redirect')).toEqual({
      status: 302,
      body: '',
      location: '/final',
    });
    expect(await request(observerPort, ca, '/final')).toEqual({
      status: 200,
      body: 'redirected',
    });
    await expect(request(observerPort, ca, '/reset-connection')).rejects.toThrow();
    const unavailable = await request(observerPort, ca, '/receipts');
    expect(unavailable).toMatchObject({ status: 404 });
    const query = await request(observerPort, ca, '/text?unexpected=1');
    expect(query).toMatchObject({ status: 400 });
    const wrongHost = await request(observerPort, ca, '/text', {
      headers: { host: 'other.example:8443' },
    });
    expect(wrongHost).toMatchObject({ status: 400 });
    await Promise.all(Array.from({ length: 60 }, async () => request(observerPort, ca, '/text')));
    await expect(request(observerPort, ca, '/text')).resolves.toMatchObject({
      status: 503,
    });
    await expect(request(observerPort, ca, '/text')).resolves.toMatchObject({
      status: 503,
    });
    const receiptText = await readFile(receipts, 'utf8');
    const lines = receiptText
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line));
    expect(lines).toHaveLength(64);
    expect(lines.slice(0, 4)).toEqual([
      { method: 'GET', path: '/text', headerMatches: true, bodyMatches: true },
      { method: 'POST', path: '/post', headerMatches: true, bodyMatches: true },
      { method: 'GET', path: '/redirect', headerMatches: true, bodyMatches: true },
      { method: 'GET', path: '/final', headerMatches: true, bodyMatches: true },
    ]);
    expect(JSON.stringify(lines)).not.toContain('bounded-body');
  } finally {
    try {
      await observer?.close();
    } finally {
      await rm(root, { force: true, recursive: true });
    }
  }
  await expect(access(root)).rejects.toThrow();
});

/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
