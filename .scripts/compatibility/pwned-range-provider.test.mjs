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
const differentSuffix = `1${suffix.slice(1)}`;
let fixtureIndex = 0;

const allocatePort = async () => new Promise((resolve, reject) => {
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

const requestRange = async ({ addPadding, pathPrefix, port }) => new Promise((resolve, reject) => {
  const request = get({
    hostname: '127.0.0.1', port, path: `/range/${pathPrefix}`,
    servername: 'api.pwnedpasswords.com', rejectUnauthorized: false,
    headers: {
      host: 'api.pwnedpasswords.com',
      ...(addPadding ? { 'add-padding': 'true' } : {}),
      'user-agent': 'node',
    },
  }, (response) => {
    const chunks = [];
    response.on('data', (chunk) => chunks.push(chunk));
    response.on('end', () => resolve({
      status: response.statusCode,
      body: Buffer.concat(chunks).toString('utf8'),
    }));
  });
  request.once('error', reject);
});

const waitForRequest = async (input) => {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    try {
      return await requestRange(input);
    } catch (error) {
      if (attempt === 39 || error.code !== 'ECONNREFUSED') throw error;
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
  }
  throw new Error('provider did not start');
};

const withProvider = async ({ certificate, key, mode, root }, use) => {
  fixtureIndex += 1;
  const configuration = path.join(root, `${mode}-${fixtureIndex}.json`);
  const receipt = path.join(root, `${mode}-${fixtureIndex}.ndjson`);
  const port = await allocatePort();
  await Promise.all([
    writeFile(configuration, `${JSON.stringify({ prefix, suffix, responseMode: mode })}\n`, { mode: 0o600 }),
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
    await use({ port, receipt });
  } finally {
    if (child.exitCode === null) child.kill('SIGTERM');
    if (child.exitCode === null) await new Promise((resolve) => child.once('exit', resolve));
  }
};

const createCertificate = async (root) => {
  const key = path.join(root, 'server.key');
  const certificate = path.join(root, 'server.pem');
  await execute('/usr/bin/openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-sha256',
    '-subj', '/CN=api.pwnedpasswords.com', '-keyout', key, '-out', certificate,
  ]);
  await Promise.all([chmod(root, 0o700), chmod(key, 0o600), chmod(certificate, 0o600)]);
  return { certificate, key };
};

test('serves clear, compromised, and reset outcomes for both selected request dialects', async () => {
  const root = await mkdtemp('/var/tmp/henry-build/pwned-range-provider-test-');
  try {
    const tls = await createCertificate(root);
    for (const dialect of [
      { name: 'reference', pathPrefix: prefix.toLowerCase(), addPadding: false },
      { name: 'candidate', pathPrefix: prefix, addPadding: true },
    ]) {
      for (const mode of ['count-zero', 'count-one', 'transport-reset']) {
        await withProvider({ ...tls, mode, root }, async ({ port, receipt }) => {
          const input = { addPadding: dialect.addPadding, pathPrefix: dialect.pathPrefix, port };
          if (mode === 'transport-reset') {
            await assert.rejects(waitForRequest(input), (error) => error.code === 'ECONNRESET');
          } else {
            const response = await waitForRequest(input);
            assert.equal(response.status, 200);
            assert.equal(response.body, mode === 'count-one'
              ? `${suffix}:1\r\n`
              : `${differentSuffix}:1\r\n`);
            if (mode === 'count-zero') assert.equal(response.body.includes(suffix), false);
          }
          const facts = (await readFile(receipt, 'utf8')).trim().split('\n').map(JSON.parse);
          assert.deepEqual(facts, [{
            methodGet: true,
            originMatches: true,
            pathShapeMatches: true,
            prefixMatches: true,
            addPaddingPresent: dialect.addPadding,
            userAgentProduct: 'node',
            status: mode === 'transport-reset' ? 0 : 200,
          }], dialect.name);
        });
      }
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('rejects a different range prefix without consuming the configured response', async () => {
  const root = await mkdtemp('/var/tmp/henry-build/pwned-range-provider-prefix-');
  try {
    const tls = await createCertificate(root);
    await withProvider({ ...tls, mode: 'count-one', root }, async ({ port, receipt }) => {
      const rejected = await waitForRequest({ addPadding: false, pathPrefix: 'ABCDF', port });
      assert.equal(rejected.status, 400);
      assert.equal(rejected.body, '');
      const accepted = await requestRange({ addPadding: false, pathPrefix: prefix.toLowerCase(), port });
      assert.equal(accepted.status, 200);
      assert.equal(accepted.body, `${suffix}:1\r\n`);
      const facts = (await readFile(receipt, 'utf8')).trim().split('\n').map(JSON.parse);
      assert.deepEqual(facts.map(({ prefixMatches, status }) => ({ prefixMatches, status })), [
        { prefixMatches: false, status: 400 },
        { prefixMatches: true, status: 200 },
      ]);
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
