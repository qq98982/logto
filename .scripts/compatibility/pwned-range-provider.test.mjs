import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { get } from 'node:https';
import net from 'node:net';
import path from 'node:path';
import { test } from 'node:test';
import { promisify } from 'node:util';

const execute = promisify(execFile);
const script = new URL('./pwned-range-provider.mjs', import.meta.url).pathname;
const prefix = 'ABCDE';
const suffix = '0123456789ABCDEF0123456789ABCDEF012';

const allocatePort = async () =>
  new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (typeof address !== 'object' || address === null) {
        server.close(() => reject(new Error('port allocation failed')));
        return;
      }
      server.close((error) => (error ? reject(error) : resolve(address.port)));
    });
  });

const requestRange = async (port) =>
  new Promise((resolve, reject) => {
    const request = get(
      {
        hostname: '127.0.0.1',
        port,
        path: `/range/${prefix}`,
        servername: 'api.pwnedpasswords.com',
        headers: { host: 'api.pwnedpasswords.com', 'add-padding': 'true', 'user-agent': 'node' },
        rejectUnauthorized: false,
      },
      (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () =>
          resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString('utf8') })
        );
      }
    );
    request.once('error', reject);
  });

const waitForRequest = async (port) => {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    try {
      return await requestRange(port);
    } catch (error) {
      if (attempt === 39 || error.code !== 'ECONNREFUSED') {
        throw error;
      }
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
  }
  throw new Error('provider did not start');
};

test('serves exact range counts and resets the controlled transport', async () => {
  const root = await mkdtemp('/var/tmp/henry-build/pwned-range-provider-test-');
  const key = path.join(root, 'server.key');
  const certificate = path.join(root, 'server.pem');
  try {
    await execute('/usr/bin/openssl', [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-sha256',
      '-subj', '/CN=api.pwnedpasswords.com', '-keyout', key, '-out', certificate,
    ]);
    await Promise.all([chmod(root, 0o700), chmod(key, 0o400), chmod(certificate, 0o444)]);
    for (const mode of ['count-zero', 'count-one', 'transport-reset']) {
      const configuration = path.join(root, `${mode}.json`);
      const receipt = path.join(root, `${mode}.ndjson`);
      const port = await allocatePort();
      await Promise.all([
        writeFile(configuration, `${JSON.stringify({ prefix, suffix, responseMode: mode })}\n`, {
          mode: 0o600,
        }),
        writeFile(receipt, '', { mode: 0o600 }),
      ]);
      const child = spawn(process.execPath, [script], {
        env: {
          PATH: process.env.PATH,
          ASTER_PWNED_CERTIFICATE_FILE: certificate,
          ASTER_PWNED_PRIVATE_KEY_FILE: key,
          ASTER_PWNED_CONFIGURATION_FILE: configuration,
          ASTER_PWNED_RECEIPT_FILE: receipt,
          ASTER_PWNED_LISTEN_HOST: '127.0.0.1',
          ASTER_PWNED_LISTEN_PORT: String(port),
        },
        stdio: 'ignore',
      });
      try {
        if (mode === 'transport-reset') {
          await assert.rejects(waitForRequest(port), (error) => error.code === 'ECONNRESET');
        } else {
          const response = await waitForRequest(port);
          assert.equal(response.status, 200);
          assert.equal(response.body, `${suffix}:${mode === 'count-one' ? 1 : 0}\r\n`);
        }
        const facts = (await readFile(receipt, 'utf8')).trim().split('\n').map(JSON.parse);
        assert.deepEqual(facts, [{
          methodGet: true,
          originMatches: true,
          pathShapeMatches: true,
          prefixMatches: true,
          addPaddingPresent: true,
          userAgentProduct: 'node',
          status: mode === 'transport-reset' ? 0 : 200,
        }]);
      } finally {
        child.kill('SIGTERM');
        await new Promise((resolve) => child.once('exit', resolve));
      }
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
