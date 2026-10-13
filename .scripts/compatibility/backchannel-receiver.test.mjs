import assert from 'node:assert/strict';
import { chmod, lstat, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import https from 'node:https';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = await mkdtemp('/var/tmp/henry-build/bc-');
try {
const script = fileURLToPath(new URL('./backchannel-receiver.mjs', import.meta.url));
const key = `${root}/tls.key`;
const certificate = `${root}/tls.pem`;
const openssl = spawn('openssl', [
  'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
  '-subj', '/CN=backchannel.aster.test',
  '-addext', 'subjectAltName=DNS:backchannel.aster.test',
  '-keyout', key, '-out', certificate,
], { stdio: 'ignore' });
assert.equal((await once(openssl, 'exit'))[0], 0);
await chmod(key, 0o600);
await chmod(certificate, 0o600);

const waitForSocket = async (socket) => {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const ready = await lstat(socket).then((state) => state.isSocket(), () => false);
    if (ready) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error('receiver socket unavailable');
};
const request = async (ca, token) => new Promise((resolve, reject) => {
  const body = new URLSearchParams({ logout_token: token }).toString();
  const client = https.request({
    hostname: '127.0.0.1', port: 8443, path: '/backchannel-logout', method: 'POST',
    servername: 'backchannel.aster.test', ca,
    headers: {
      host: 'backchannel.aster.test:8443',
      'content-type': 'application/x-www-form-urlencoded',
      'content-length': Buffer.byteLength(body),
    },
  }, (response) => {
    response.resume();
    response.once('end', () => resolve(response.statusCode));
  });
  client.once('error', reject);
  client.end(body);
});
const consume = async (socket) => new Promise((resolve, reject) => {
  const client = net.createConnection(socket);
  client.setEncoding('utf8');
  let body = '';
  client.once('error', reject);
  client.on('data', (chunk) => { body += chunk; });
  client.once('end', () => resolve(body));
  client.once('connect', () => client.end('CONSUME\n'));
});
const run = async (configuredStatus) => {
  const suffix = String(configuredStatus);
  const receipt = `${root}/receipt-${suffix}.ndjson`;
  const socket = `${root}/consume-${suffix}.sock`;
  await writeFile(receipt, '', { mode: 0o600 });
  const child = spawn(process.execPath, [script], {
    detached: true,
    stdio: 'ignore',
    env: {
      ...process.env,
      ASTER_BACKCHANNEL_RECEIPT_FILE: receipt,
      ASTER_BACKCHANNEL_CERTIFICATE_FILE: certificate,
      ASTER_BACKCHANNEL_PRIVATE_KEY_FILE: key,
      ASTER_BACKCHANNEL_CONSUME_SOCKET: socket,
      ASTER_BACKCHANNEL_RESPONSE_STATUS: suffix,
    },
  });
  try {
    await waitForSocket(socket);
    const ca = await readFile(certificate);
    const token = `owned-token.${suffix}.signature`;
    assert.equal(await request(ca, token), configuredStatus);
    assert.equal(await consume(socket), `${token}\n`);
    assert.equal(await consume(socket), 'EMPTY\n');
    process.kill(-child.pid, 'SIGTERM');
    const [code, signal] = await once(child, 'exit');
    assert.equal(code, 0);
    assert.equal(signal, null);
    await assert.rejects(lstat(socket), { code: 'ENOENT' });
    const lines = (await readFile(receipt, 'utf8')).trim().split('\n');
    assert.equal(lines.length, 1);
    assert.equal(JSON.parse(lines[0]).status, configuredStatus);
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      process.kill(-child.pid, 'SIGKILL');
      await once(child, 'exit');
    }
  }
};

  await test('closes owned HTTPS and IPC listeners after delivering each logout token once', {
    timeout: 10_000,
  }, async () => {
    await run(204);
    await run(503);
  });
} finally {
  await rm(root, { recursive: true, force: true });
}
