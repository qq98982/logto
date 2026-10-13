import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import test from 'node:test';
import { promisify } from 'node:util';

const execute = promisify(execFile);
const carrier = new URL('./h5-https-carrier.mjs', import.meta.url).pathname;
const pki = new URL('./generate-h5-pki.sh', import.meta.url).pathname;

const waitForHttps = async (ca) => {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      return await new Promise((resolve, reject) => {
        const request = https.get('https://localhost:3361/readyz', { ca, timeout: 500 }, resolve);
        request.once('error', reject);
        request.once('timeout', () => request.destroy(new Error('timeout')));
      });
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
  }
  throw new Error('carrier did not become ready');
};

test('serves the Oracle production password authority through the fixed HTTPS carrier', async () => {
  const root = await mkdtemp('/var/tmp/henry-build/password-carrier-test.');
  const requests = [];
  const upstream = http.createServer((request, response) => {
    requests.push({
      path: request.url,
      forwardedHost: request.headers['x-forwarded-host'],
      forwardedProto: request.headers['x-forwarded-proto'],
    });
    response.writeHead(200, { 'content-type': 'text/plain' });
    response.end('ready');
  });
  let child;
  try {
    await execute(pki, ['generate', root]);
    await new Promise((resolve, reject) => {
      upstream.once('error', reject);
      upstream.listen(3363, '127.0.0.1', resolve);
    });
    child = spawn(process.execPath, [
      carrier,
      '3361',
      '3363',
      `${root}/h5-loopback-server.pem`,
      `${root}/h5-loopback-server.key`,
    ], { stdio: 'ignore' });
    const ca = await readFile(`${root}/h5-loopback-ca.pem`);
    const response = await waitForHttps(ca);
    const body = await new Promise((resolve, reject) => {
      let value = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { value += chunk; });
      response.once('end', () => resolve(value));
      response.once('error', reject);
    });
    assert.equal(response.statusCode, 200);
    assert.equal(body, 'ready');
    assert.deepEqual(requests, [{
      path: '/readyz',
      forwardedHost: 'localhost:3361',
      forwardedProto: 'https',
    }]);
  } finally {
    if (child?.exitCode === null) child.kill('SIGTERM');
    if (child) await new Promise((resolve) => child.once('exit', resolve));
    await new Promise((resolve) => upstream.close(resolve));
    await rm(root, { recursive: true, force: true });
  }
});

test('admits only the two H5 listeners and the Oracle password listener', async () => {
  const root = await mkdtemp('/var/tmp/henry-build/password-carrier-admission.');
  try {
    await execute(pki, ['generate', root]);
    const certificate = `${root}/h5-loopback-server.pem`;
    const privateKey = `${root}/h5-loopback-server.key`;
    for (const port of ['3351', '3352', '3361']) {
      const child = spawn(process.execPath, [carrier, port, '3363', certificate, privateKey], {
        stdio: 'ignore',
      });
      await new Promise((resolve) => setTimeout(resolve, 30));
      assert.equal(child.exitCode, null);
      child.kill('SIGTERM');
      await new Promise((resolve) => child.once('exit', resolve));
    }
    for (const port of ['3350', '3353', '3360', '3362', '65535']) {
      await assert.rejects(execute(process.execPath, [carrier, port, '3363', certificate, privateKey]));
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
